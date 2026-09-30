//! Known-good evidence that overrides a hash match.
//!
//! Malware feeds are not clean: honeypot collectors upload *every* file an
//! intruder dropped, including the legitimate libraries shipped alongside the
//! bot. MalwareBazaar lists the official PyPI build of cryptography's
//! `_rust.abi3.so` as "Mirai", for example. Two defences:
//!
//!   1. A known-good list (`known-good*.txt`: bundled, and from feeds) of
//!      hashes verified to be legitimate builds. Listed files are clean,
//!      whatever any engine says.
//!   2. Package-manager records: a file inside a Python environment whose
//!      hash equals the one pip recorded in `*.dist-info/RECORD` at install
//!      time is the file pip installed, so a feed's hash match on it is taken
//!      to be collateral. This trades a little evasion resistance (malware
//!      could forge a RECORD entry) for not calling users' virtualenvs
//!      infected; pattern engines still see such files.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::config::{feeds_dir, BUNDLED_RULES_DIR};

pub struct KnownGood {
    hashes: HashSet<String>,
}

impl KnownGood {
    pub fn load() -> KnownGood {
        let mut hashes = HashSet::new();
        let dev = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/rules"));
        for dir in [PathBuf::from(BUNDLED_RULES_DIR), dev, feeds_dir()] {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for p in rd.flatten().map(|e| e.path()) {
                let is_list = p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("known-good") && n.ends_with(".txt"));
                if !is_list {
                    continue;
                }
                if let Ok(text) = std::fs::read_to_string(&p) {
                    for line in text.lines() {
                        let h = line.split('#').next().unwrap_or("").trim().to_ascii_lowercase();
                        if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
                            hashes.insert(h);
                        }
                    }
                }
            }
        }
        KnownGood { hashes }
    }

    pub fn contains(&self, sha256_hex: &str) -> bool {
        self.hashes.contains(sha256_hex)
    }
}

type Records = Arc<HashMap<String, String>>;

/// pip RECORD lookups, cached per site-packages directory and refreshed when
/// the directory changes (a package installed or removed).
#[derive(Default)]
pub struct PipRecords {
    cache: Mutex<HashMap<PathBuf, (Option<SystemTime>, Records)>>,
}

impl PipRecords {
    /// True if `path` sits in a site-packages directory and pip recorded
    /// exactly this content for it.
    pub fn verified(&self, path: &Path, sha256_hex: &str) -> bool {
        let Some(sp) = path
            .ancestors()
            .find(|a| a.file_name().is_some_and(|n| n == "site-packages" || n == "dist-packages"))
        else {
            return false;
        };
        let Ok(rel) = path.strip_prefix(sp) else { return false };
        let Some(rel) = rel.to_str() else { return false };
        let Ok(raw) = hex::decode(sha256_hex) else { return false };
        let want = format!("sha256={}", b64url_nopad(&raw));
        self.records(sp).get(rel).is_some_and(|h| *h == want)
    }

    fn records(&self, sp: &Path) -> Records {
        let mtime = std::fs::metadata(sp).and_then(|m| m.modified()).ok();
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((m, r)) = cache.get(sp) {
            if *m == mtime {
                return r.clone();
            }
        }
        let r: Records = Arc::new(load_records(sp));
        if cache.len() > 256 {
            cache.clear();
        }
        cache.insert(sp.to_path_buf(), (mtime, r.clone()));
        r
    }
}

fn load_records(sp: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(rd) = std::fs::read_dir(sp) else { return out };
    for e in rd.flatten() {
        let name = e.file_name();
        if !name.to_string_lossy().ends_with(".dist-info") {
            continue;
        }
        let record = e.path().join("RECORD");
        let Ok(meta) = std::fs::symlink_metadata(&record) else { continue };
        if !meta.is_file() || meta.len() > 16 * 1024 * 1024 {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&record) else { continue };
        for line in text.lines() {
            // path,sha256=<urlsafe base64, no padding>,size — paths containing
            // commas are quoted; those are rare enough to skip.
            let mut parts = line.rsplitn(3, ',');
            let (_size, hash, path) = (parts.next(), parts.next(), parts.next());
            if let (Some(hash), Some(path)) = (hash, path) {
                if hash.starts_with("sha256=") && !path.starts_with('"') {
                    out.insert(path.to_string(), hash.to_string());
                }
            }
        }
    }
    out
}

fn b64url_nopad(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len() * 4 / 3 + 3);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..chunk.len() + 1 {
            out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_matches_pip() {
        // sha256("") as pip writes it.
        let h = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
        assert_eq!(b64url_nopad(&h), "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
    }

    #[test]
    fn verifies_pip_installed_file() {
        let root = std::env::temp_dir().join(format!("qlam-pip-{}", std::process::id()));
        let sp = root.join("lib/python3.14/site-packages");
        std::fs::create_dir_all(sp.join("pkg")).unwrap();
        std::fs::create_dir_all(sp.join("pkg-1.0.dist-info")).unwrap();
        std::fs::write(sp.join("pkg/mod.so"), b"").unwrap();
        std::fs::write(
            sp.join("pkg-1.0.dist-info/RECORD"),
            "pkg/mod.so,sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU,0\npkg-1.0.dist-info/RECORD,,\n",
        )
        .unwrap();
        let p = PipRecords::default();
        let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(p.verified(&sp.join("pkg/mod.so"), empty));
        assert!(!p.verified(&sp.join("pkg/mod.so"), &"a".repeat(64)));
        assert!(!p.verified(&root.join("mod.so"), empty));
        let _ = std::fs::remove_dir_all(root);
    }
}
