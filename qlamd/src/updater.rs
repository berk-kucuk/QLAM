//! Signature feed updater (`qlamd update`).
//!
//! Runs from qlam-update.service as the unprivileged `qlam` user in a
//! sandbox, since it parses data straight off the internet. It only ever
//! writes into /var/lib/qlam/feeds; the root daemon notices the new
//! state.json and reloads.
//!
//! Feeds:
//!   - MalwareBazaar (abuse.ch, CC0): SHA-256 of malware samples. Only
//!     samples of Linux file types attributed to a named family are
//!     imported (see hashdb.rs).
//!     A full export on first run and monthly, the 48-hour export daily.
//!   - YARA Forge core, reduced to rules for Linux executables (see
//!     `select_feed_rules`); rules that yara-x can't compile are dropped
//!     individually.
//!
//! Each feed is written to a temporary file and renamed into place, so a
//! failed or interrupted update leaves the previous version intact.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::feeds_dir;
use crate::engine::hashdb::Builder;
use crate::engine::yara::{check_source, select_feed_rules};
use crate::store::now;

const UA: &str = concat!("qlam/", env!("CARGO_PKG_VERSION"), " (+https://github.com/berk-kucuk/QLAM)");

const MB_FULL_URL: &str = "https://bazaar.abuse.ch/export/csv/full/";
const MB_RECENT_URL: &str = "https://bazaar.abuse.ch/export/csv/recent/";
const MB_FULL_EVERY: i64 = 30 * 24 * 3600;

/// MalwareBazaar file types that can run on Linux. Windows executables,
/// WSH scripts and Office documents are most of the feed but can't harm this
/// system; leaving them out cuts the list (and its memory) by about 80%.
const LINUX_TYPES: &[&str] = &["elf", "sh", "bash", "zsh", "ksh", "py", "pl", "php", "jar", "deb", "rpm"];

/// Bumped whenever the selection above changes, forcing a full re-import.
const MB_FILTER_VERSION: u32 = 2;

/// Bumped whenever `select_feed_rules` changes, forcing a re-download.
const FORGE_FILTER_VERSION: u32 = 2;
const MB_FILE: &str = "malwarebazaar.qlh";

const FORGE_API: &str = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest";
const FORGE_ASSET: &str = "yara-forge-rules-core.zip";
const FORGE_FILE: &str = "yara-forge-core.yar";

pub const STATE_FILE: &str = "state.json";

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FeedState {
    pub updated_at: i64,
    pub malwarebazaar_full_at: i64,
    pub malwarebazaar_at: i64,
    pub malwarebazaar_hashes: usize,
    /// MB_FILTER_VERSION the current list was built with.
    pub malwarebazaar_filter: u32,
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
}

pub fn run() -> i32 {
    let dir = feeds_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        log::error!("{}: {e}", dir.display());
        return 1;
    }
    let mut state = FeedState::load();
    state.errors.clear();

    if let Err(e) = update_malwarebazaar(&dir, &mut state) {
        log::error!("MalwareBazaar: {e}");
        state.errors.push(format!("MalwareBazaar: {e}"));
    }
    if let Err(e) = update_yara_forge(&dir, &mut state) {
        log::error!("YARA Forge: {e}");
        state.errors.push(format!("YARA Forge: {e}"));
    }

    state.updated_at = now();
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

// ── MalwareBazaar ────────────────────────────────────────────────────────

fn update_malwarebazaar(dir: &Path, state: &mut FeedState) -> io::Result<()> {
    let agent = agent();
    let target = dir.join(MB_FILE);
    let mut builder = Builder::default();

    let full = !target.exists()
        || state.malwarebazaar_filter != MB_FILTER_VERSION
        || now() - state.malwarebazaar_full_at > MB_FULL_EVERY;
    if full {
        log::info!("MalwareBazaar: downloading full export");
        let tmp = dir.join(".malwarebazaar-full.zip.part");
        let res = download_to(&agent, MB_FULL_URL, &tmp, 1024 * 1024 * 1024).and_then(|_| {
            let mut zip = zip::ZipArchive::new(File::open(&tmp)?).map_err(io::Error::other)?;
            if zip.is_empty() {
                return Err(io::Error::other("empty archive"));
            }
            let entry = zip.by_index(0).map_err(io::Error::other)?;
            // Cap decompressed size: a zip bomb must not fill the disk/RAM.
            parse_mb_csv(BufReader::new(entry.take(8 * 1024 * 1024 * 1024)), &mut builder)
        });
        let _ = std::fs::remove_file(&tmp);
        res?;
        state.malwarebazaar_full_at = now();
        state.malwarebazaar_filter = MB_FILTER_VERSION;
    } else {
        builder.read_file(&target)?;
        let before = builder.len();
        let body = get(&agent, MB_RECENT_URL, 100 * 1024 * 1024)?;
        parse_mb_csv(BufReader::new(&body[..]), &mut builder)?;
        log::info!("MalwareBazaar: {} new entries", builder.len() - before);
    }

    // A feed that suddenly shrinks to nothing is broken, not good news.
    if builder.len() < 1000 {
        return Err(io::Error::other(format!("only {} hashes parsed; keeping previous list", builder.len())));
    }
    let mut out = Vec::new();
    let count = builder.write(&mut out)?;
    write_atomic(&target, &out)?;
    state.malwarebazaar_at = now();
    state.malwarebazaar_hashes = count;
    log::info!("MalwareBazaar: {count} attributed hashes");
    Ok(())
}

/// `"first_seen","sha256","md5","sha1","reporter","file_name","file_type",
/// "mime","signature",...` — only rows of a Linux file type (LINUX_TYPES)
/// with a family signature are kept.
fn parse_mb_csv(reader: impl BufRead, builder: &mut Builder) -> io::Result<()> {
    for line in reader.lines() {
        let line = line?;
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split("\",").map(|f| f.trim().trim_matches('"').trim()).collect();
        let (Some(sha), Some(ftype), Some(sig)) = (fields.get(1), fields.get(6), fields.get(8)) else { continue };
        if !LINUX_TYPES.contains(&ftype.to_ascii_lowercase().as_str()) {
            continue;
        }
        if sig.is_empty() || sig.eq_ignore_ascii_case("n/a") || sig.len() > 64 {
            continue;
        }
        let family: String = sig.chars().filter(|c| c.is_ascii_alphanumeric() || "._-".contains(*c)).collect();
        if !family.is_empty() {
            builder.add(&sha.to_ascii_lowercase(), &family);
        }
    }
    Ok(())
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

fn download_to(agent: &ureq::Agent, url: &str, dest: &Path, limit: u64) -> io::Result<()> {
    let resp = agent.get(url).call().map_err(io::Error::other)?;
    let mut reader = resp.into_body().into_with_config().limit(limit).reader();
    let mut f = File::create(dest)?;
    io::copy(&mut reader, &mut f)?;
    f.sync_all()
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

    #[test]
    fn csv_keeps_attributed_linux_samples() {
        let csv = concat!(
            "# comment\n",
            // Attributed, but a Windows executable: can't run here.
            "\"2026-09-29 19:30:00\", \"e34d9ea96e37934b805bdd0a8821411555409a7e16f43b109d5d14de7adb1d8b\", \"m\", \"s\", \"anon\", \"inv.exe\", \"exe\", \"application/x-dosexec\", \"AgentTesla\", \"n/a\", \"n/a\", \"n/a\", \"x\", \"y\"\n",
            // Attributed shell script.
            "\"2026-09-29 19:31:00\", \"f34d9ea96e37934b805bdd0a8821411555409a7e16f43b109d5d14de7adb1d8b\", \"m\", \"s\", \"anon\", \"x.sh\", \"sh\", \"text/x-shellscript\", \"Mirai\", \"n/a\", \"n/a\", \"n/a\", \"x\", \"y\"\n",
            "\"2026-09-29 19:33:37\", \"c34d9ea96e37934b805bdd0a8821411555409a7e16f43b109d5d14de7adb1d8b\", \"m\", \"s\", \"abuse_ch\", \"bot.mips\", \"elf\", \"application/x-executable\", \"Mirai\", \"n/a\", \"n/a\", \"n/a\", \"x\", \"y\"\n",
            "\"2026-09-29 19:33:37\", \"d34d9ea96e37934b805bdd0a8821411555409a7e16f43b109d5d14de7adb1d8b\", \"m\", \"s\", \"anon\", \"setup.exe\", \"exe\", \"application/x-dosexec\", \"n/a\", \"n/a\", \"n/a\", \"n/a\", \"x\", \"y\"\n",
        );
        let mut b = Builder::default();
        parse_mb_csv(BufReader::new(csv.as_bytes()), &mut b).unwrap();
        let db = b.build();
        assert_eq!(db.len(), 2);
        assert_eq!(db.lookup_hex("c34d9ea96e37934b805bdd0a8821411555409a7e16f43b109d5d14de7adb1d8b"), Some("Mirai"));
        assert_eq!(db.lookup_hex("f34d9ea96e37934b805bdd0a8821411555409a7e16f43b109d5d14de7adb1d8b"), Some("Mirai"));
        assert_eq!(db.lookup_hex("e34d9ea96e37934b805bdd0a8821411555409a7e16f43b109d5d14de7adb1d8b"), None);
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
