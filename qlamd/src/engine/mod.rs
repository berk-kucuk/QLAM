//! Detection engines and the verdict they produce together.
//!
//! Two kinds of "malicious" are kept apart on purpose:
//!   - confirmed: the file is byte-for-byte a known sample (SHA-256 match) or
//!     a rule explicitly marked `qlam_confirmed` (the EICAR test file). Only
//!     these may be acted on automatically (exec blocking, and quarantine when
//!     the admin enables it) — a hash match cannot be a pattern false positive.
//!   - pattern matches (YARA, ClamAV), a download from a URL that URLhaus
//!     lists, and known samples found *inside* an archive: reported as
//!     warnings for the user to decide on, never acted on by themselves. (An
//!     archive is not what gets executed, and malware feeds sometimes list
//!     legitimate libraries that end up in wheels and jars.)
//!
//! Order matters for cost: the allowlist and the hash list are a SHA-256 plus a
//! lookup, the origin check one getxattr, YARA a pass over the bytes, an
//! archive a pass over each member, and ClamAV a round-trip to clamd.

pub mod archive;
pub mod clamd;
pub mod goodware;
pub mod hashdb;
pub mod origin;
pub mod yara;

use std::io;
use std::os::fd::BorrowedFd;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::store::Store;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub severity: Severity,
    /// Exact identification rather than a pattern match; see the module docs.
    pub confirmed: bool,
    /// Detection name, e.g. "Qlam.Linux.Miner.XMRig". Empty when clean.
    pub name: String,
    /// Which engine produced it: "hash", "yara", "clamav", "urlhaus", or
    /// "archive:<engine>" for a finding about a file inside an archive.
    pub engine: String,
    pub sha256: String,
}

impl Verdict {
    pub fn clean(sha256: String) -> Verdict {
        Verdict { severity: Severity::Clean, confirmed: false, name: String::new(), engine: String::new(), sha256 }
    }

    fn found(m: Match, engine: &str, sha256: &str) -> Verdict {
        Verdict { severity: m.severity, confirmed: m.confirmed, name: m.name, engine: engine.into(), sha256: sha256.into() }
    }

    /// Stronger than `other`: higher severity, then confirmed over not.
    fn beats(&self, other: &Verdict) -> bool {
        (self.severity, self.confirmed) > (other.severity, other.confirmed)
    }

    pub fn is_malicious(&self) -> bool {
        self.severity == Severity::Malicious
    }

    /// Eligible for automatic action (blocking, auto-quarantine).
    pub fn is_confirmed(&self) -> bool {
        self.confirmed && self.severity == Severity::Malicious
    }
}

/// One engine's opinion.
pub struct Match {
    pub severity: Severity,
    pub confirmed: bool,
    pub name: String,
}

/// Files this small carry no useful identity: a known-bad list that contains
/// the hash of an empty or near-empty file would otherwise flag every such
/// file on the system.
const MIN_HASH_MATCH_SIZE: usize = 64;

/// Text joining a detection name and the archive member it was found in.
/// The app splits on it to explain the finding.
pub const IN_ARCHIVE: &str = " in archive member ";

/// Signature sets that are swapped atomically when the feeds change.
pub struct Signatures {
    pub hashes: hashdb::HashDb,
    /// URLhaus malware-distribution URLs, keyed by `origin::url_key`.
    pub urls: hashdb::HashDb,
    pub yara: yara::YaraRules,
    pub known_good: goodware::KnownGood,
    pub generation: u64,
}

impl Signatures {
    pub fn load(generation: u64) -> Signatures {
        Signatures {
            hashes: hashdb::HashDb::load_feeds(),
            urls: hashdb::HashDb::load_file(&crate::config::feeds_dir().join(URL_LIST)),
            yara: yara::YaraRules::load_default(),
            known_good: goodware::KnownGood::load(),
            generation,
        }
    }
}

/// File name of the URLhaus list in the feeds directory.
pub const URL_LIST: &str = "urlhaus.qlu";

pub struct Engine {
    sigs: ArcSwap<Signatures>,
    clamd: clamd::Clamd,
    pip: goodware::PipRecords,
    store: Arc<Store>,
}

impl Engine {
    pub fn new(clamd_socket: &str, store: Arc<Store>) -> Engine {
        Engine {
            sigs: ArcSwap::from_pointee(Signatures::load(1)),
            clamd: clamd::Clamd::new(clamd_socket),
            pip: goodware::PipRecords::default(),
            store,
        }
    }

    pub fn signatures(&self) -> Arc<Signatures> {
        self.sigs.load_full()
    }

    pub fn reload(&self) {
        let next = self.sigs.load().generation + 1;
        self.sigs.store(Arc::new(Signatures::load(next)));
    }

    pub fn clamd_available(&self) -> bool {
        self.clamd.available()
    }

    /// Scan an open file found at `path`. `buf` is a per-worker buffer reused
    /// between calls so the hot path does not allocate per file. With
    /// `archives`, archives are opened and their members checked too.
    pub fn scan_fd(
        &self,
        fd: BorrowedFd<'_>,
        path: &Path,
        max_size: u64,
        archives: Option<&archive::Limits>,
        buf: &mut Vec<u8>,
    ) -> io::Result<Verdict> {
        crate::fsutil::read_from_start(fd, buf, max_size)?;
        let sha256 = hex::encode(Sha256::digest(&buf[..]));

        // The user said "I trust this file": nothing overrides that. A
        // per-user decision only covers files that user owns.
        let owner = crate::fsutil::fstat(fd).ok().map(|st| st.st_uid);
        if self.store.is_allowlisted_for(owner, &sha256) {
            return Ok(Verdict::clean(sha256));
        }

        let sigs = self.sigs.load();
        if sigs.known_good.contains(&sha256) {
            return Ok(Verdict::clean(sha256));
        }
        if buf.len() >= MIN_HASH_MATCH_SIZE {
            if let Some(family) = sigs.hashes.lookup_hex(&sha256).filter(|_| !self.pip.verified(path, &sha256)) {
                let m = Match { severity: Severity::Malicious, confirmed: true, name: format!("{family} (known sample)") };
                return Ok(Verdict::found(m, "hash", &sha256));
            }
        }

        let mut best = Verdict::clean(sha256.clone());
        if let Some(m) = origin_match(&sigs, fd) {
            best = Verdict::found(m, "urlhaus", &sha256);
        }
        if let Some(m) = sigs.yara.scan(buf) {
            let v = Verdict::found(m, "yara", &sha256);
            if v.is_confirmed() {
                return Ok(v);
            }
            if v.beats(&best) {
                best = v;
            }
        }
        if let Some(limits) = archives.filter(|_| best.severity < Severity::Malicious) {
            if archive::detect(buf).is_some() {
                let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                if let Some(v) = self.scan_members(&sigs, buf, &name, owner, limits, &sha256) {
                    if v.beats(&best) {
                        best = v;
                    }
                }
            }
        }
        if let Some(m) = self.clamd.scan_fd(fd) {
            let v = Verdict::found(m, "clamav", &sha256);
            if v.beats(&best) {
                best = v;
            }
        }
        Ok(best)
    }

    /// The strongest finding among the members of the archive in `data`.
    /// `sha256` is the archive's own: the finding is about the archive file,
    /// which is what the user can quarantine or trust.
    fn scan_members(
        &self,
        sigs: &Signatures,
        data: &[u8],
        name: &str,
        owner: Option<u32>,
        limits: &archive::Limits,
        sha256: &str,
    ) -> Option<Verdict> {
        let mut best: Option<(Match, String, &'static str)> = None;
        let walked = archive::walk(data, name, limits, &mut |member, bytes| {
            let sha = hex::encode(Sha256::digest(bytes));
            if sigs.known_good.contains(&sha) || self.store.is_allowlisted_for(owner, &sha) {
                return archive::Flow::Continue;
            }
            if bytes.len() >= MIN_HASH_MATCH_SIZE {
                if let Some(family) = sigs.hashes.lookup_hex(&sha) {
                    let m = Match { severity: Severity::Malicious, confirmed: false, name: format!("{family} (known sample)") };
                    best = Some((m, member.to_string(), "hash"));
                    return archive::Flow::Stop;
                }
            }
            if let Some(m) = sigs.yara.scan(bytes) {
                let stronger = best.as_ref().is_none_or(|(b, _, _)| m.severity > b.severity);
                if stronger {
                    let stop = m.severity == Severity::Malicious;
                    best = Some((Match { confirmed: false, ..m }, member.to_string(), "yara"));
                    if stop {
                        return archive::Flow::Stop;
                    }
                }
            }
            archive::Flow::Continue
        });
        if walked.incomplete || walked.skipped > 0 {
            log::debug!("{name}: {} archive members checked, {} skipped, complete: {}", walked.members, walked.skipped, !walked.incomplete);
        }
        let (m, member, engine) = best?;
        Some(Verdict {
            severity: m.severity,
            confirmed: false,
            name: format!("{}{IN_ARCHIVE}{member}", m.name),
            engine: format!("archive:{engine}"),
            sha256: sha256.to_string(),
        })
    }

    /// For files on-access protection doesn't read (not runnable): only the
    /// download-origin check, which costs one getxattr. The file is read only
    /// when its origin matches, for the hash the finding needs.
    pub fn scan_origin(&self, fd: BorrowedFd<'_>, max_size: u64, buf: &mut Vec<u8>) -> io::Result<Option<Verdict>> {
        let sigs = self.sigs.load();
        let Some(m) = origin_match(&sigs, fd) else { return Ok(None) };
        crate::fsutil::read_from_start(fd, buf, max_size)?;
        let sha256 = hex::encode(Sha256::digest(&buf[..]));
        let owner = crate::fsutil::fstat(fd).ok().map(|st| st.st_uid);
        if self.store.is_allowlisted_for(owner, &sha256) || sigs.known_good.contains(&sha256) {
            return Ok(None);
        }
        Ok(Some(Verdict::found(m, "urlhaus", &sha256)))
    }
}

fn origin_match(sigs: &Signatures, fd: BorrowedFd<'_>) -> Option<Match> {
    if sigs.urls.len() == 0 {
        return None;
    }
    let url = origin::origin_url(fd)?;
    let tag = sigs.urls.lookup_hex(&origin::url_key(&url)?)?;
    let name = if tag.is_empty() || tag == "Unknown" {
        "URLhaus.MalwareDownload".to_string()
    } else {
        format!("URLhaus.MalwareDownload.{tag}")
    };
    Some(Match { severity: Severity::Malicious, confirmed: false, name })
}
