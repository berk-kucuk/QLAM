//! Detection engines and the verdict they produce together.
//!
//! Two kinds of "malicious" are kept apart on purpose:
//!   - confirmed: the file is byte-for-byte a known sample (SHA-256 match) or
//!     a rule explicitly marked `qlam_confirmed` (the EICAR test file). Only
//!     these may be acted on automatically (exec blocking, and quarantine when
//!     the admin enables it) — a hash match cannot be a pattern false positive.
//!   - pattern matches (YARA, ClamAV): reported as warnings for the user to
//!     decide on, never acted on by themselves.
//!
//! Order matters for cost: the allowlist and the hash list are a SHA-256 plus a
//! lookup, YARA is a pass over the bytes, and ClamAV is a round-trip to clamd.

pub mod clamd;
pub mod goodware;
pub mod hashdb;
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
    /// Which engine produced it: "hash", "yara", "clamav".
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

/// Signature sets that are swapped atomically when the feeds change.
pub struct Signatures {
    pub hashes: hashdb::HashDb,
    pub yara: yara::YaraRules,
    pub known_good: goodware::KnownGood,
    pub generation: u64,
}

impl Signatures {
    pub fn load(generation: u64) -> Signatures {
        Signatures {
            hashes: hashdb::HashDb::load_feeds(),
            yara: yara::YaraRules::load_default(),
            known_good: goodware::KnownGood::load(),
            generation,
        }
    }
}

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
    /// between calls so the hot path does not allocate per file.
    pub fn scan_fd(&self, fd: BorrowedFd<'_>, path: &Path, max_size: u64, buf: &mut Vec<u8>) -> io::Result<Verdict> {
        crate::fsutil::read_from_start(fd, buf, max_size)?;
        let sha256 = hex::encode(Sha256::digest(&buf[..]));

        // The user said "I trust this file": nothing overrides that.
        if self.store.is_allowlisted(&sha256) {
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
        if let Some(m) = sigs.yara.scan(buf) {
            best = Verdict::found(m, "yara", &sha256);
            if best.is_confirmed() {
                return Ok(best);
            }
        }
        if let Some(m) = self.clamd.scan_fd(fd) {
            if m.severity > best.severity {
                best = Verdict::found(m, "clamav", &sha256);
            }
        }
        Ok(best)
    }
}
