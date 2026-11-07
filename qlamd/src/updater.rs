//! Signature feed updater (`qlamd update`).
//!
//! Runs from qlam-update.service as the unprivileged `qlam` user in a
//! sandbox, since it parses data straight off the internet. It only ever
//! writes into /var/lib/qlam/feeds; the root daemon notices the new
//! state.json and reloads.
//!
//! Feeds:
//!   - abuse.ch (CC0), all three with the user's free Auth-Key (see
//!     `config::abusech_key`); without one, the current lists are kept and
//!     the app asks for a key:
//!       - MalwareBazaar: SHA-256 of malware samples. Only samples of Linux
//!         file types attributed to a named family are imported.
//!       - ThreatFox: indicators of compromise; only file hashes of Linux
//!         malware families (Malpedia `elf.*` and script platforms), at
//!         high confidence.
//!     Both: a full export on first run and monthly, the recent export
//!     (48 hours) merged in daily.
//!       - URLhaus: URLs that served malware in the last 30 days, replaced
//!         daily, for the download-origin check (engine/origin.rs).
//!   - YARA Forge core, reduced to rules for Linux executables (see
//!     `select_feed_rules`); rules that yara-x can't compile are dropped
//!     individually.
//!
//! Each feed is written to a temporary file and renamed into place, so a
//! failed or interrupted update leaves the previous version intact.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{abusech_key, feeds_dir};
use crate::engine::hashdb::Builder;
use crate::engine::origin::url_key;
use crate::engine::yara::{check_source, select_feed_rules};
use crate::engine::URL_LIST;
use crate::store::now;

const UA: &str = concat!("qlam/", env!("CARGO_PKG_VERSION"), " (+https://github.com/berk-kucuk/QLAM)");

const FULL_EVERY: i64 = 30 * 24 * 3600;

/// One abuse.ch dataset, fetched from
/// `https://<host>/v2/files/exports/<auth-key>/<file>` (the key has to be
/// in the path).
struct AbuseFeed {
    id: Feed,
    name: &'static str,
    host: &'static str,
    /// List file written to the feeds directory.
    list: &'static str,
    /// Full dump (a zip with one CSV), rebuilt from monthly; the recent
    /// export is merged into the list in between. None: the recent export
    /// is the whole list, replaced each time.
    full: Option<&'static str>,
    recent: &'static str,
    /// Bumped whenever `row` changes what it keeps, forcing a full rebuild.
    filter_version: u32,
    /// A list smaller than this is a broken export, not good news.
    min_entries: usize,
    row: fn(&Columns, &[String], &mut Builder),
}

#[derive(Clone, Copy)]
enum Feed {
    MalwareBazaar,
    ThreatFox,
    UrlHaus,
}

const ABUSE_FEEDS: &[AbuseFeed] = &[
    AbuseFeed {
        id: Feed::MalwareBazaar,
        name: "MalwareBazaar",
        host: "mb-api.abuse.ch",
        list: "malwarebazaar.qlh",
        full: Some("full.csv.zip"),
        recent: "recent.csv",
        filter_version: 2,
        min_entries: 1000,
        row: malwarebazaar_row,
    },
    AbuseFeed {
        id: Feed::ThreatFox,
        name: "ThreatFox",
        host: "threatfox-api.abuse.ch",
        list: "threatfox.qlh",
        full: Some("full.csv.zip"),
        recent: "recent.csv",
        filter_version: 1,
        min_entries: 50,
        row: threatfox_row,
    },
    AbuseFeed {
        id: Feed::UrlHaus,
        name: "URLhaus",
        host: "urlhaus-api.abuse.ch",
        list: URL_LIST,
        full: None,
        recent: "recent.csv",
        filter_version: 1,
        min_entries: 100,
        row: urlhaus_row,
    },
];

/// Bumped whenever `select_feed_rules` changes, forcing a re-download.
const FORGE_FILTER_VERSION: u32 = 2;

const FORGE_API: &str = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest";
const FORGE_ASSET: &str = "yara-forge-rules-core.zip";
const FORGE_FILE: &str = "yara-forge-core.yar";

pub const STATE_FILE: &str = "state.json";
/// Written while an update runs, removed when it ends: what it's doing, for
/// the app to show. Holds the updater's pid, so a crashed run's leftover
/// file isn't mistaken for a running one.
pub const PROGRESS_FILE: &str = "progress.json";

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Progress {
    pub pid: u32,
    pub started_at: i64,
    /// "MalwareBazaar", "ThreatFox", "URLhaus", "YARA Forge".
    pub feed: String,
    /// "full list", "recent additions", "rules".
    pub stage: String,
    pub bytes: u64,
}

impl Progress {
    /// The running update's progress, if one is running.
    pub fn load() -> Option<Progress> {
        let p: Progress = serde_json::from_slice(&std::fs::read(feeds_dir().join(PROGRESS_FILE)).ok()?).ok()?;
        std::path::Path::new(&format!("/proc/{}", p.pid)).exists().then_some(p)
    }
}

/// The updater's own progress, written at most once a second.
static PROGRESS: std::sync::Mutex<Option<(Progress, std::time::Instant)>> = std::sync::Mutex::new(None);

fn progress(feed: &str, stage: &str) {
    let mut g = PROGRESS.lock().unwrap_or_else(|p| p.into_inner());
    let started_at = g.as_ref().map(|(p, _)| p.started_at).unwrap_or_else(now);
    let p = Progress { pid: std::process::id(), started_at, feed: feed.into(), stage: stage.into(), bytes: 0 };
    let _ = write_atomic(&feeds_dir().join(PROGRESS_FILE), &serde_json::to_vec(&p).unwrap_or_default());
    *g = Some((p, std::time::Instant::now()));
}

fn progress_bytes(bytes: u64) {
    let mut g = PROGRESS.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((p, at)) = g.as_mut() {
        if at.elapsed() >= Duration::from_secs(1) {
            p.bytes = bytes;
            let _ = write_atomic(&feeds_dir().join(PROGRESS_FILE), &serde_json::to_vec(&*p).unwrap_or_default());
            *at = std::time::Instant::now();
        }
    }
}

/// State of one abuse.ch list.
#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ListState {
    pub full_at: i64,
    pub updated_at: i64,
    pub entries: usize,
    /// `filter_version` the list was built with.
    pub filter: u32,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FeedState {
    pub updated_at: i64,
    pub malwarebazaar: ListState,
    pub threatfox: ListState,
    pub urlhaus: ListState,
    /// "ok", "missing" (no Auth-Key set) or "rejected" (abuse.ch refused it).
    pub abusech_key: String,
    pub yara_forge_tag: String,
    pub yara_forge_rules: usize,
    pub yara_forge_dropped: usize,
    /// FORGE_FILTER_VERSION the current rule file was built with.
    pub yara_forge_filter: u32,
    pub errors: Vec<String>,
}

impl FeedState {
    pub fn load() -> FeedState {
        std::fs::read(feeds_dir().join(STATE_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn list(&mut self, feed: Feed) -> &mut ListState {
        match feed {
            Feed::MalwareBazaar => &mut self.malwarebazaar,
            Feed::ThreatFox => &mut self.threatfox,
            Feed::UrlHaus => &mut self.urlhaus,
        }
    }
}

pub fn run() -> i32 {
    let dir = feeds_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        log::error!("{}: {e}", dir.display());
        return 1;
    }
    let mut state = FeedState::load();
    state.errors.clear();
    progress("", "starting");

    update_abusech(&dir, &mut state);
    if let Err(e) = update_yara_forge(&dir, &mut state) {
        log::error!("YARA Forge: {e}");
        state.errors.push(format!("YARA Forge: {e}"));
    }

    state.updated_at = now();
    let _ = std::fs::remove_file(dir.join(PROGRESS_FILE));
    match serde_json::to_vec_pretty(&state) {
        Ok(json) => {
            if let Err(e) = write_atomic(&dir.join(STATE_FILE), &json) {
                log::error!("state: {e}");
                return 1;
            }
        }
        Err(e) => {
            log::error!("state: {e}");
            return 1;
        }
    }
    if state.errors.is_empty() { 0 } else { 2 }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15 * 60)))
        .user_agent(UA)
        .https_only(true)
        .build()
        .into()
}

// ── abuse.ch ─────────────────────────────────────────────────────────────

fn update_abusech(dir: &Path, state: &mut FeedState) {
    let Some(key) = abusech_key() else {
        // Not a failure of the update: the lists stay as they are and the
        // app shows how to get a key.
        log::warn!("abuse.ch: no Auth-Key set; keeping the current lists");
        state.abusech_key = "missing".into();
        return;
    };
    state.abusech_key = "ok".into();
    let agent = agent();
    for feed in ABUSE_FEEDS {
        match update_list(&agent, feed, dir, state.list(feed.id), &key) {
            Ok(()) => {}
            Err(e) if is_auth_denied(&e) => {
                log::error!("{}: abuse.ch did not accept the Auth-Key", feed.name);
                state.abusech_key = "rejected".into();
                state.errors.push("abuse.ch did not accept the Auth-Key".into());
                // The same key for every feed: asking again only adds load.
                return;
            }
            Err(e) => {
                // The key is part of the URL; never let it reach a log line or
                // state.json, which every user can read.
                let msg = e.to_string().replace(&key, "<auth-key>");
                log::error!("{}: {msg}", feed.name);
                state.errors.push(format!("{}: {msg}", feed.name));
            }
        }
    }
}

fn is_auth_denied(e: &io::Error) -> bool {
    matches!(
        e.get_ref().and_then(|i| i.downcast_ref::<ureq::Error>()),
        Some(ureq::Error::StatusCode(401 | 403))
    )
}

fn update_list(agent: &ureq::Agent, feed: &AbuseFeed, dir: &Path, st: &mut ListState, key: &str) -> io::Result<()> {
    let url = |file: &str| format!("https://{}/v2/files/exports/{key}/{file}", feed.host);
    let target = dir.join(feed.list);
    let mut builder = Builder::default();

    let full = feed.full.filter(|_| !target.exists() || st.filter != feed.filter_version || now() - st.full_at > FULL_EVERY);
    let mut have_full = false;
    if let Some(file) = full {
        log::info!("{}: downloading full export", feed.name);
        progress(feed.name, "full list");
        let tmp = dir.join(format!(".{}.zip.part", feed.list));
        let res = download_to(agent, &url(file), &tmp, 1024 * 1024 * 1024).and_then(|_| {
            let mut zip = zip::ZipArchive::new(File::open(&tmp)?).map_err(io::Error::other)?;
            if zip.is_empty() {
                return Err(io::Error::other("empty archive"));
            }
            let entry = zip.by_index(0).map_err(io::Error::other)?;
            // Cap decompressed size: a zip bomb must not fill the disk/RAM.
            parse_csv(BufReader::new(entry.take(8 * 1024 * 1024 * 1024)), feed.row, &mut builder)
        });
        let _ = std::fs::remove_file(&tmp);
        match res {
            Ok(()) => {
                st.full_at = now();
                have_full = true;
            }
            Err(e) if is_auth_denied(&e) || !target.exists() => return Err(e),
            // The full dump is big and its download can break off. The list
            // there is still good: bring it up to date with the small recent
            // export now, and try the full dump again next time (full_at is
            // left as it was).
            Err(e) => {
                log::warn!(
                    "{}: full export failed ({}); adding the recent export to the current list instead",
                    feed.name,
                    e.to_string().replace(key, "<auth-key>")
                );
                builder = Builder::default();
            }
        }
    }
    if !have_full {
        if feed.full.is_some() {
            builder.read_file(&target)?;
        }
        let before = builder.len();
        progress(feed.name, "recent additions");
        let body = get(agent, &url(feed.recent), 200 * 1024 * 1024)?;
        parse_csv(BufReader::new(&body[..]), feed.row, &mut builder)?;
        log::info!("{}: {} entries from the recent export", feed.name, builder.len() - before);
    }

    if builder.len() < feed.min_entries {
        return Err(io::Error::other(format!("only {} entries parsed; keeping the previous list", builder.len())));
    }
    let mut out = Vec::new();
    let count = builder.write(&mut out)?;
    write_atomic(&target, &out)?;
    st.updated_at = now();
    st.entries = count;
    st.filter = feed.filter_version;
    log::info!("{}: {count} entries", feed.name);
    Ok(())
}

/// Column positions, from the export's header comment (`# "a","b",...`),
/// with the documented positions as fallback.
#[derive(Default)]
struct Columns(HashMap<String, usize>);

impl Columns {
    fn get(&self, name: &str, fallback: usize) -> usize {
        self.0.get(name).copied().unwrap_or(fallback)
    }
}

/// Parse an abuse.ch CSV export, handing each data row to `row`. Rows are
/// read as bytes and decoded lossily: one bad byte must not end the feed.
fn parse_csv(mut reader: impl BufRead, row: fn(&Columns, &[String], &mut Builder), builder: &mut Builder) -> io::Result<()> {
    let mut cols = Columns::default();
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end_matches(['\r', '\n']);
        if let Some(comment) = text.strip_prefix('#') {
            let names = split_csv(comment);
            let is_header = names.len() >= 3
                && names.iter().all(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'));
            if is_header {
                cols = Columns(names.into_iter().enumerate().map(|(i, n)| (n, i)).collect());
            }
            continue;
        }
        if text.trim().is_empty() {
            continue;
        }
        row(&cols, &split_csv(text), builder);
    }
}

/// One CSV line into fields: quoted fields with doubled quotes inside, and
/// the spaces abuse.ch puts after separators.
fn split_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.next_if(|c| *c == ' ' || *c == '\t').is_some() {}
        let mut field = String::new();
        if chars.next_if_eq(&'"').is_some() {
            while let Some(c) = chars.next() {
                if c == '"' {
                    if chars.next_if_eq(&'"').is_some() {
                        field.push('"');
                    } else {
                        break;
                    }
                } else {
                    field.push(c);
                }
            }
            // Anything between the closing quote and the separator.
            while chars.next_if(|c| *c != ',').is_some() {}
        } else {
            while let Some(c) = chars.next_if(|c| *c != ',') {
                field.push(c);
            }
            field = field.trim().to_string();
        }
        fields.push(field);
        if chars.next().is_none() {
            return fields;
        }
    }
}

/// A family name fit for a detection name, or None for "no family".
fn family(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 64 || raw.eq_ignore_ascii_case("n/a") {
        return None;
    }
    let lower = raw.to_ascii_lowercase();
    if lower.contains("unknown") || lower.contains("unidentified") {
        return None;
    }
    let name: String = raw.chars().filter(|c| c.is_ascii_alphanumeric() || "._-".contains(*c)).collect();
    (!name.is_empty()).then_some(name)
}

/// MalwareBazaar file types that can run on Linux. Windows executables,
/// WSH scripts and Office documents are most of the feed but can't harm this
/// system; leaving them out cuts the list (and its memory) by about 80%.
const LINUX_TYPES: &[&str] = &["elf", "sh", "bash", "zsh", "ksh", "py", "pl", "php", "jar", "deb", "rpm"];

/// Only rows of a Linux file type (LINUX_TYPES) with a family signature.
fn malwarebazaar_row(cols: &Columns, f: &[String], b: &mut Builder) {
    let get = |name, fallback| f.get(cols.get(name, fallback)).map(String::as_str).unwrap_or("");
    let ftype = get("file_type_guess", 6).to_ascii_lowercase();
    if !LINUX_TYPES.contains(&ftype.as_str()) {
        return;
    }
    if let Some(fam) = family(get("signature", 8)) {
        b.add(&get("sha256_hash", 1).to_ascii_lowercase(), &fam);
    }
}

/// Malpedia platforms (the part of `fk_malware` before the dot) whose
/// malware can run on Linux.
const THREATFOX_PLATFORMS: &[&str] = &["elf", "sh", "py", "php", "jar", "pl"];
/// ThreatFox confidence (0-100) below which an indicator isn't imported: a
/// hash match may be acted on, so only well-established ones count.
const THREATFOX_MIN_CONFIDENCE: u32 = 75;

fn threatfox_row(cols: &Columns, f: &[String], b: &mut Builder) {
    let get = |name, fallback| f.get(cols.get(name, fallback)).map(String::as_str).unwrap_or("");
    if get("ioc_type", 3) != "sha256_hash" {
        return;
    }
    let malware = get("fk_malware", 5);
    let platform = malware.split('.').next().unwrap_or("");
    if !THREATFOX_PLATFORMS.contains(&platform) {
        return;
    }
    if get("confidence_level", 9).parse::<u32>().is_ok_and(|c| c < THREATFOX_MIN_CONFIDENCE) {
        return;
    }
    if let Some(fam) = family(get("malware_printable", 7)) {
        b.add(&get("ioc_value", 2).to_ascii_lowercase(), &fam);
    }
}

/// URLs that distributed malware, keyed by `url_key`, labelled with the
/// family tag when there is one. URLhaus tags mix families ("Mozi") with
/// file traits ("elf", "32-bit", "mips"); family tags are the capitalised
/// ones.
fn urlhaus_row(cols: &Columns, f: &[String], b: &mut Builder) {
    let get = |name, fallback| f.get(cols.get(name, fallback)).map(String::as_str).unwrap_or("");
    let threat = get("threat", 5);
    if !threat.is_empty() && threat != "malware_download" {
        return;
    }
    let Some(key) = url_key(get("url", 2)) else { return };
    let tag = get("tags", 6)
        .split(',')
        .map(str::trim)
        .find(|t| t.starts_with(|c: char| c.is_ascii_uppercase()))
        .and_then(family)
        .unwrap_or_default();
    b.add(&key, &tag);
}

// ── YARA Forge ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

fn update_yara_forge(dir: &Path, state: &mut FeedState) -> io::Result<()> {
    progress("YARA Forge", "rules");
    let agent = agent();
    let target = dir.join(FORGE_FILE);
    let body = get(&agent, FORGE_API, 1024 * 1024)?;
    let release: Release = serde_json::from_slice(&body).map_err(io::Error::other)?;
    if release.tag_name == state.yara_forge_tag && state.yara_forge_filter == FORGE_FILTER_VERSION && target.exists() {
        log::info!("YARA Forge: {} is current", release.tag_name);
        return Ok(());
    }
    let url = release
        .assets
        .iter()
        .find(|a| a.name == FORGE_ASSET)
        .map(|a| a.browser_download_url.clone())
        .ok_or_else(|| io::Error::other(format!("{FORGE_ASSET} missing from release {}", release.tag_name)))?;
    if !url.starts_with("https://github.com/YARAHQ/yara-forge/releases/download/") {
        return Err(io::Error::other(format!("unexpected download URL {url}")));
    }

    log::info!("YARA Forge: downloading {}", release.tag_name);
    let zipped = get(&agent, &url, 64 * 1024 * 1024)?;
    let mut zip = zip::ZipArchive::new(io::Cursor::new(zipped)).map_err(io::Error::other)?;
    let mut source = String::new();
    for i in 0..zip.len() {
        let entry = zip.by_index(i).map_err(io::Error::other)?;
        if entry.name().ends_with(".yar") {
            entry.take(256 * 1024 * 1024).read_to_string(&mut source)?;
            break;
        }
    }
    if source.is_empty() {
        return Err(io::Error::other("no .yar file in the archive"));
    }

    let (clean, kept, dropped) = keep_compilable(&source);
    if kept == 0 {
        return Err(io::Error::other("no rule compiled; keeping previous rules"));
    }
    write_atomic(&target, clean.as_bytes())?;
    state.yara_forge_tag = release.tag_name;
    state.yara_forge_rules = kept;
    state.yara_forge_dropped = dropped;
    state.yara_forge_filter = FORGE_FILTER_VERSION;
    log::info!("YARA Forge: {kept} rules kept, {dropped} not for Linux executables or incompatible");
    Ok(())
}

/// Select the feed rules Qlam uses (see `select_feed_rules`), then compile;
/// if the selection doesn't compile as a whole, keep the rules that compile
/// on their own. Returns (source, kept, dropped).
fn keep_compilable(src: &str) -> (String, usize, usize) {
    let sel = select_feed_rules(src);
    let whole = format!("{}{}", sel.imports, sel.rules.concat());
    if check_source(&whole).is_ok() {
        return (whole, sel.rules.len(), sel.dropped);
    }
    let mut out = sel.imports.clone();
    let (mut kept, mut dropped) = (0, sel.dropped);
    for rule in sel.rules {
        if check_source(&format!("{}{rule}", sel.imports)).is_ok() {
            out.push_str(rule);
            out.push('\n');
            kept += 1;
        } else {
            dropped += 1;
        }
    }
    (out, kept, dropped)
}

// ── HTTP / files ─────────────────────────────────────────────────────────

fn get(agent: &ureq::Agent, url: &str, limit: u64) -> io::Result<Vec<u8>> {
    let mut resp = agent.get(url).call().map_err(io::Error::other)?;
    resp.body_mut().with_config().limit(limit).read_to_vec().map_err(io::Error::other)
}

/// Download `url` to `dest`. A connection that breaks off is resumed where
/// it stopped (HTTP Range): the full exports are hundreds of megabytes, and
/// on 2026-11-07 the connection broke every 30-45 seconds, each time
/// further along. So resuming goes on as long as attempts make progress;
/// STALLED_TRIES in a row without any, or MAX_TRIES in all, give up.
fn download_to(agent: &ureq::Agent, url: &str, dest: &Path, limit: u64) -> io::Result<()> {
    use std::io::{Seek, SeekFrom};
    const STALLED_TRIES: u64 = 5;
    const MAX_TRIES: u64 = 100;
    let mut f = File::create(dest)?;
    let mut have: u64 = 0;
    let mut last = io::Error::other("download failed");
    let mut stalled = 0;
    let mut before = 0;
    for attempt in 0..MAX_TRIES {
        if attempt > 0 {
            stalled = if have > before { 0 } else { stalled + 1 };
            if stalled >= STALLED_TRIES {
                break;
            }
            log::info!("download broke off at {} MB ({last}); resuming (attempt {})", have >> 20, attempt + 1);
            // Back off only when nothing is getting through.
            std::thread::sleep(Duration::from_secs(1 + 5 * stalled));
        }
        before = have;
        let mut req = agent.get(url);
        if have > 0 {
            req = req.header("Range", format!("bytes={have}-"));
        }
        let resp = match req.call() {
            Ok(r) => r,
            // An answer from the server (401, 404, 410...) won't change by
            // asking again.
            Err(e @ ureq::Error::StatusCode(416)) if have > 0 => {
                log::debug!("{e}: already complete");
                break;
            }
            Err(e @ ureq::Error::StatusCode(_)) => return Err(io::Error::other(e)),
            Err(e) => {
                last = io::Error::other(e);
                continue;
            }
        };
        if have > 0 && resp.status().as_u16() != 206 {
            // The server ignored the range and sends everything again.
            have = 0;
            f.set_len(0)?;
            f.seek(SeekFrom::Start(0))?;
        }
        let mut reader = resp.into_body().into_with_config().limit(limit.saturating_sub(have)).reader();
        let mut buf = vec![0u8; 256 * 1024];
        let done = loop {
            match reader.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    f.write_all(&buf[..n])?;
                    have += n as u64;
                    progress_bytes(have);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => break Err(e),
            }
        };
        match done {
            Ok(()) => return f.sync_all(),
            Err(e) => last = e,
        }
    }
    // Stalled, out of attempts, or the server says there's nothing left to send
    // (416). Only whole if the zip's directory at its end is there.
    f.sync_all()?;
    if have > 0 && zip::ZipArchive::new(&f).is_ok() { Ok(()) } else { Err(last) }
}

fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("part");
    let res = (|| {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(csv: &str, row: fn(&Columns, &[String], &mut Builder)) -> crate::engine::hashdb::HashDb {
        let mut b = Builder::default();
        parse_csv(BufReader::new(csv.as_bytes()), row, &mut b).unwrap();
        b.build()
    }

    #[test]
    fn splits_csv() {
        assert_eq!(split_csv(r#""a", "b,c" ,d, "e""q""#), ["a", "b,c", "d", "e\"q"]);
        assert_eq!(split_csv("x,,y"), ["x", "", "y"]);
        assert_eq!(split_csv(r#""""#), [""]);
    }

    #[test]
    fn malwarebazaar_keeps_attributed_linux_samples() {
        let csv = concat!(
            "# comment\n",
            // Attributed, but a Windows executable: can't run here.
            "\"2026-09-29 19:30:00\", \"e34d9ea96e37934b805bdd0a8821411555409a7e16f43b109d5d14de7adb1d8b\", \"m\", \"s\", \"anon\", \"inv.exe\", \"exe\", \"application/x-dosexec\", \"AgentTesla\", \"n/a\", \"n/a\", \"n/a\", \"x\", \"y\"\n",
            // Attributed shell script.
            "\"2026-09-29 19:31:00\", \"f34d9ea96e37934b805bdd0a8821411555409a7e16f43b109d5d14de7adb1d8b\", \"m\", \"s\", \"anon\", \"x.sh\", \"sh\", \"text/x-shellscript\", \"Mirai\", \"n/a\", \"n/a\", \"n/a\", \"x\", \"y\"\n",
            // A file name with a quote and separator in it doesn't shift the columns.
            "\"2026-09-29 19:33:37\", \"c34d9ea96e37934b805bdd0a8821411555409a7e16f43b109d5d14de7adb1d8b\", \"m\", \"s\", \"abuse_ch\", \"bot\"\",.mips\", \"elf\", \"application/x-executable\", \"Mirai\", \"n/a\", \"n/a\", \"n/a\", \"x\", \"y\"\n",
            "\"2026-09-29 19:33:37\", \"d34d9ea96e37934b805bdd0a8821411555409a7e16f43b109d5d14de7adb1d8b\", \"m\", \"s\", \"anon\", \"setup.exe\", \"exe\", \"application/x-dosexec\", \"n/a\", \"n/a\", \"n/a\", \"n/a\", \"x\", \"y\"\n",
        );
        let db = parse(csv, malwarebazaar_row);
        assert_eq!(db.len(), 2);
        assert_eq!(db.lookup_hex("c34d9ea96e37934b805bdd0a8821411555409a7e16f43b109d5d14de7adb1d8b"), Some("Mirai"));
        assert_eq!(db.lookup_hex("f34d9ea96e37934b805bdd0a8821411555409a7e16f43b109d5d14de7adb1d8b"), Some("Mirai"));
        assert_eq!(db.lookup_hex("e34d9ea96e37934b805bdd0a8821411555409a7e16f43b109d5d14de7adb1d8b"), None);
    }

    #[test]
    fn columns_follow_the_header() {
        // Same data, columns reordered: the header decides.
        let csv = concat!(
            "# \"signature\",\"file_type_guess\",\"sha256_hash\"\n",
            "\"Gafgyt\", \"elf\", \"A34d9ea96e37934b805bdd0a8821411555409a7e16f43b109d5d14de7adb1d8b\"\n",
        );
        let db = parse(csv, malwarebazaar_row);
        assert_eq!(db.lookup_hex("a34d9ea96e37934b805bdd0a8821411555409a7e16f43b109d5d14de7adb1d8b"), Some("Gafgyt"));
    }

    #[test]
    fn threatfox_keeps_confident_linux_hashes() {
        let h = |c: char| c.to_string().repeat(64);
        let csv = format!(concat!(
            "# \"first_seen_utc\",\"ioc_id\",\"ioc_value\",\"ioc_type\",\"threat_type\",\"fk_malware\",\"malware_alias\",\"malware_printable\",\"last_seen_utc\",\"confidence_level\",\"reference\",\"tags\",\"anonymous\",\"reporter\"\n",
            "\"2026-11-01 10:00:00\", \"1\", \"{a}\", \"sha256_hash\", \"payload\", \"elf.mirai\", \"\", \"Mirai\", \"\", \"100\", \"\", \"\", \"0\", \"r\"\n",
            "\"2026-11-01 10:00:00\", \"2\", \"{b}\", \"sha256_hash\", \"payload\", \"win.agent_tesla\", \"\", \"Agent Tesla\", \"\", \"100\", \"\", \"\", \"0\", \"r\"\n",
            "\"2026-11-01 10:00:00\", \"3\", \"{c}\", \"sha256_hash\", \"payload\", \"elf.mozi\", \"\", \"Mozi\", \"\", \"50\", \"\", \"\", \"0\", \"r\"\n",
            "\"2026-11-01 10:00:00\", \"4\", \"1.2.3.4:80\", \"ip:port\", \"botnet_cc\", \"elf.mirai\", \"\", \"Mirai\", \"\", \"100\", \"\", \"\", \"0\", \"r\"\n",
            "\"2026-11-01 10:00:00\", \"5\", \"{d}\", \"sha256_hash\", \"payload\", \"elf.unknown\", \"\", \"Unknown malware\", \"\", \"100\", \"\", \"\", \"0\", \"r\"\n",
        ), a = h('a'), b = h('b'), c = h('c'), d = h('d'));
        let db = parse(&csv, threatfox_row);
        assert_eq!(db.len(), 1);
        assert_eq!(db.lookup_hex(&h('a')), Some("Mirai"));
    }

    #[test]
    fn urlhaus_keys_urls_with_family_tags() {
        let csv = concat!(
            "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n",
            "\"1\",\"2026-11-01 10:00:00\",\"http://1.2.3.4:8080/bins/mozi.m\",\"online\",\"\",\"malware_download\",\"32-bit,elf,mips,Mozi\",\"https://urlhaus.abuse.ch/url/1/\",\"r\"\n",
            "\"2\",\"2026-11-01 10:00:00\",\"https://Example.org/x.sh\",\"offline\",\"\",\"malware_download\",\"sh\",\"https://urlhaus.abuse.ch/url/2/\",\"r\"\n",
        );
        let db = parse(csv, urlhaus_row);
        assert_eq!(db.len(), 2);
        assert_eq!(db.lookup_hex(&url_key("http://1.2.3.4:8080/bins/mozi.m").unwrap()), Some("Mozi"));
        assert_eq!(db.lookup_hex(&url_key("https://example.org/x.sh").unwrap()), Some(""));
    }

    /// A server that cuts the first response off halfway, like the full
    /// export download did (2026-11-07), then honours the Range request.
    #[test]
    fn broken_downloads_resume() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        let body: Vec<u8> = {
            let mut w = zip::ZipWriter::new(io::Cursor::new(Vec::new()));
            w.start_file("full.csv", zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored)).unwrap();
            w.write_all(&vec![b'x'; 300_000]).unwrap();
            w.finish().unwrap().into_inner()
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = body.clone();
        let server = std::thread::spawn(move || {
            let mut ranges = Vec::new();
            for (n, conn) in listener.incoming().take(2).enumerate() {
                let mut conn = conn.unwrap();
                let mut from = 0usize;
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("range: bytes=") {
                        from = v.trim().trim_end_matches('-').parse().unwrap();
                    }
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                }
                ranges.push(from);
                let rest = &served[from..];
                if n == 0 {
                    // Promise everything, send half, hang up.
                    write!(conn, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", rest.len()).unwrap();
                    conn.write_all(&rest[..rest.len() / 2]).unwrap();
                } else {
                    write!(conn, "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\n\r\n", rest.len()).unwrap();
                    conn.write_all(rest).unwrap();
                }
            }
            ranges
        });
        let agent: ureq::Agent = ureq::Agent::config_builder().build().into();
        let dest = std::env::temp_dir().join(format!("qlam-dl-{}.zip", std::process::id()));
        download_to(&agent, &format!("http://127.0.0.1:{port}/full.csv.zip"), &dest, 10 << 20).unwrap();
        let ranges = server.join().unwrap();
        assert_eq!(ranges[0], 0);
        assert_eq!(ranges[1], body.len() / 2, "second request resumes where the first stopped");
        assert_eq!(std::fs::read(&dest).unwrap(), body);
        let _ = std::fs::remove_file(dest);
    }

    #[test]
    fn auth_key_errors() {
        assert!(is_auth_denied(&io::Error::other(ureq::Error::StatusCode(401))));
        assert!(!is_auth_denied(&io::Error::other(ureq::Error::StatusCode(410))));
        assert!(!is_auth_denied(&io::Error::other("401")));
        assert!(crate::config::valid_abusech_key("0123456789abcdef0123456789abcdef0123456789abcdef"));
        assert!(!crate::config::valid_abusech_key("0123456789abcdef/../../x"));
        assert!(!crate::config::valid_abusech_key("short"));
    }

    #[test]
    fn drops_only_broken_rules() {
        let src = "import \"elf\"\n\
            rule good { condition: uint32(0) == 0x464c457f }\n\
            rule bad { condition: uint32(0) == 0x464c457f and nosuchthing }\n\
            rule good2 { strings: $a = \"x\" condition: elf.type == elf.ET_EXEC and $a }\n\
            rule ELASTIC_Linux_Hacktool_Socat { condition: uint32(0) == 0x464c457f }\n\
            rule TRELLIX_ARC_Malw_Eicar { condition: true }\n";
        let (out, kept, dropped) = keep_compilable(src);
        assert_eq!((kept, dropped), (2, 3));
        assert!(out.contains("good2") && !out.contains("Eicar") && !out.contains("nosuchthing"));
        assert!(out.contains("good2") && !out.contains("nosuchthing") && !out.contains("Socat"));
    }
}
