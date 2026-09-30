//! Known-malware SHA-256 set, with the malware family of each hash.
//!
//! A hash match is the one detection Qlam may act on automatically, so the
//! updater only imports samples that a feed attributes to a named family: an
//! unattributed upload is more likely to be a mistake (a clean installer
//! someone was unsure about) than a family sample is.
//!
//! File format (`*.qlh`, written by the updater, little endian):
//!   "QLHASH01" | u32 name count | names as (u16 len, utf-8) |
//!   u64 record count | records of (32-byte hash, u16 name index),
//!   sorted by hash, no duplicates.

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;

use crate::config::feeds_dir;

const MAGIC: &[u8; 8] = b"QLHASH01";
const RECORD: usize = 34;

#[derive(Default)]
pub struct HashDb {
    hashes: Vec<[u8; 32]>,
    family: Vec<u16>,
    names: Vec<String>,
}

impl HashDb {
    pub fn load_feeds() -> HashDb {
        let mut builder = Builder::default();
        if let Ok(dir) = std::fs::read_dir(feeds_dir()) {
            for path in dir.flatten().map(|e| e.path()) {
                if path.extension().is_some_and(|e| e == "qlh") {
                    if let Err(e) = builder.read_file(&path) {
                        log::warn!("{}: {e}", path.display());
                    }
                }
            }
        }
        let db = builder.build();
        log::info!("hash list: {} known-malware hashes", db.len());
        db
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Family name if the hash is known.
    pub fn lookup_hex(&self, sha256_hex: &str) -> Option<&str> {
        let mut key = [0u8; 32];
        hex::decode_to_slice(sha256_hex, &mut key).ok()?;
        let i = self.hashes.binary_search(&key).ok()?;
        Some(self.names.get(self.family[i] as usize).map(String::as_str).unwrap_or("Unknown"))
    }
}

/// Collects (hash, family) pairs from feeds and writes/builds the sorted set.
#[derive(Default)]
pub struct Builder {
    entries: Vec<([u8; 32], u16)>,
    names: Vec<String>,
    name_idx: HashMap<String, u16>,
}

impl Builder {
    pub fn add(&mut self, sha256_hex: &str, family: &str) -> bool {
        let mut h = [0u8; 32];
        if sha256_hex.len() != 64 || hex::decode_to_slice(sha256_hex, &mut h).is_err() {
            return false;
        }
        let idx = self.intern(family);
        self.entries.push((h, idx));
        true
    }

    fn intern(&mut self, name: &str) -> u16 {
        if let Some(i) = self.name_idx.get(name) {
            return *i;
        }
        // Name table is u16-indexed; past that, lump into the last slot.
        if self.names.len() >= u16::MAX as usize {
            return u16::MAX - 1;
        }
        let i = self.names.len() as u16;
        self.names.push(name.to_string());
        self.name_idx.insert(name.to_string(), i);
        i
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn read_file(&mut self, path: &Path) -> io::Result<()> {
        let data = std::fs::read(path)?;
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "corrupt hash list");
        if data.len() < 8 || &data[..8] != MAGIC {
            return Err(bad());
        }
        let mut off = 8;
        let mut take = |n: usize| -> io::Result<&[u8]> {
            let s = data.get(off..off + n).ok_or_else(bad)?;
            off += n;
            Ok(s)
        };
        let name_count = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
        let mut names = Vec::with_capacity(name_count.min(65535));
        for _ in 0..name_count {
            let len = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
            names.push(String::from_utf8_lossy(take(len)?).into_owned());
        }
        let count = u64::from_le_bytes(take(8)?.try_into().unwrap()) as usize;
        let records = take(count.checked_mul(RECORD).ok_or_else(bad)?)?;
        let records = records.to_vec();
        for r in records.chunks_exact(RECORD) {
            let idx = u16::from_le_bytes([r[32], r[33]]) as usize;
            let name = names.get(idx).cloned().unwrap_or_else(|| "Unknown".into());
            let fam = self.intern(&name);
            self.entries.push((r[..32].try_into().unwrap(), fam));
        }
        Ok(())
    }

    fn sorted(mut self) -> Self {
        self.entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        self.entries.dedup_by(|a, b| a.0 == b.0);
        self
    }

    pub fn build(self) -> HashDb {
        let s = self.sorted();
        let (hashes, family) = s.entries.into_iter().unzip();
        HashDb { hashes, family, names: s.names }
    }

    pub fn write(self, out: &mut impl Write) -> io::Result<usize> {
        let s = self.sorted();
        out.write_all(MAGIC)?;
        out.write_all(&(s.names.len() as u32).to_le_bytes())?;
        for n in &s.names {
            let b = &n.as_bytes()[..n.len().min(u16::MAX as usize)];
            out.write_all(&(b.len() as u16).to_le_bytes())?;
            out.write_all(b)?;
        }
        out.write_all(&(s.entries.len() as u64).to_le_bytes())?;
        for (h, f) in &s.entries {
            out.write_all(h)?;
            out.write_all(&f.to_le_bytes())?;
        }
        Ok(s.entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut b = Builder::default();
        let h1 = "a".repeat(64);
        let h2 = "0".repeat(63) + "1";
        assert!(b.add(&h1, "Mirai"));
        assert!(b.add(&h2, "XMRig"));
        assert!(b.add(&h1, "Mirai"));
        assert!(!b.add("xyz", "Bad"));
        let mut buf = Vec::new();
        assert_eq!(b.write(&mut buf).unwrap(), 2);

        let path = std::env::temp_dir().join(format!("qlam-hash-{}.qlh", std::process::id()));
        std::fs::write(&path, &buf).unwrap();
        let mut r = Builder::default();
        r.read_file(&path).unwrap();
        let db = r.build();
        assert_eq!(db.lookup_hex(&h1), Some("Mirai"));
        assert_eq!(db.lookup_hex(&h2), Some("XMRig"));
        assert_eq!(db.lookup_hex(&"b".repeat(64)), None);
        let _ = std::fs::remove_file(path);
    }
}
