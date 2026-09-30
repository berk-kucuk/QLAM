//! Root-owned quarantine in /var/lib/qlam/quarantine.
//!
//! Samples are stored XOR-encoded with a random per-file key, so the store
//! never holds a runnable (or re-detectable) copy of the malware. Nothing
//! here ever writes into a user-controlled path as root:
//!   - removal re-checks that the directory entry is still the inode we
//!     scanned before unlinking it, so swapping in a symlink or another file
//!     after detection can't redirect the unlink;
//!   - restore writes into a descriptor the *client* opened with its own
//!     permissions.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::config::quarantine_dir;
use crate::engine::Verdict;
use crate::fsutil::{fstat, read_from_start};
use crate::store::{now, QuarantineItem, Store};

const MAGIC: &[u8; 8] = b"QLAMQ1\0\0";
const KEY_LEN: usize = 32;
/// Anything bigger is left in place (mode 000) instead of copied.
const MAX_QUARANTINE_SIZE: u64 = 2 * 1024 * 1024 * 1024;

pub struct Outcome {
    pub item: Option<QuarantineItem>,
    /// Original directory entry was removed.
    pub removed: bool,
}

impl Outcome {
    pub fn describe(&self) -> &'static str {
        match (&self.item, self.removed) {
            (Some(_), true) => "moved to quarantine",
            (Some(_), false) => "copied to quarantine; original could not be removed and was made unreadable",
            (None, true) => "removed (could not be stored in quarantine)",
            (None, false) => "could not be quarantined; access was revoked",
        }
    }
}

fn store_path(id: &str) -> PathBuf {
    quarantine_dir().join(format!("{id}.qlq"))
}

pub fn ensure_dir() -> io::Result<()> {
    let dir = quarantine_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
}

/// Quarantine the file open on `fd`, found at `path`.
pub fn quarantine(store: &Store, fd: BorrowedFd<'_>, path: &Path, verdict: &Verdict) -> Outcome {
    let st = match fstat(fd) {
        Ok(st) => st,
        Err(e) => {
            log::error!("quarantine {}: fstat: {e}", path.display());
            return Outcome { item: None, removed: false };
        }
    };

    let item = match copy_to_store(fd, path, &st, verdict) {
        Ok(item) => match store.quarantine_add(&item) {
            Ok(()) => Some(item),
            Err(e) => {
                log::error!("quarantine index: {e}");
                let _ = std::fs::remove_file(store_path(&item.id));
                None
            }
        },
        Err(e) => {
            log::error!("quarantine {}: {e}", path.display());
            None
        }
    };

    // Revoke access first: this also covers other hard links to the same
    // inode, which unlinking this one name would not.
    unsafe { libc::fchmod(fd.as_raw_fd(), 0) };

    // Only remove the original once a copy is safely stored — unless it could
    // not be stored at all, in which case it stays in place, mode 000.
    let removed = item.is_some() && unlink_if_same(path, &st).is_ok();
    Outcome { item, removed }
}

fn copy_to_store(fd: BorrowedFd<'_>, path: &Path, st: &libc::stat, verdict: &Verdict) -> io::Result<QuarantineItem> {
    if st.st_size as u64 > MAX_QUARANTINE_SIZE {
        return Err(io::Error::new(io::ErrorKind::FileTooLarge, "too large to quarantine"));
    }
    let mut data = Vec::with_capacity(st.st_size as usize);
    read_from_start(fd, &mut data, MAX_QUARANTINE_SIZE)?;
    let sha256 = hex::encode(Sha256::digest(&data));

    let mut key = [0u8; KEY_LEN];
    getrandom::fill(&mut key).map_err(|e| io::Error::other(e.to_string()))?;
    xor(&mut data, &key);

    let id = uuid::Uuid::new_v4().to_string();
    let dest = store_path(&id);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&dest)?;
    let res = f.write_all(MAGIC).and_then(|_| f.write_all(&key)).and_then(|_| f.write_all(&data)).and_then(|_| f.sync_all());
    if let Err(e) = res {
        let _ = std::fs::remove_file(&dest);
        return Err(e);
    }

    Ok(QuarantineItem {
        id,
        ts: now(),
        original_path: path.to_string_lossy().into_owned(),
        sha256,
        size: st.st_size,
        uid: st.st_uid,
        gid: st.st_gid,
        mode: st.st_mode & 0o7777,
        detection: verdict.name.clone(),
        engine: verdict.engine.clone(),
    })
}

/// Unlink `path` only if it still names the inode described by `st`.
fn unlink_if_same(path: &Path, st: &libc::stat) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| io::Error::other("no parent"))?;
    let name = path.file_name().ok_or_else(|| io::Error::other("no file name"))?;
    let cparent = CString::new(parent.as_os_str().as_bytes())?;
    let cname = CString::new(name.as_bytes())?;
    unsafe {
        let dfd = libc::open(cparent.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        if dfd < 0 {
            return Err(io::Error::last_os_error());
        }
        let dir = OwnedFd::from_raw_fd(dfd);
        let mut now_st: libc::stat = std::mem::zeroed();
        if libc::fstatat(dir.as_raw_fd(), cname.as_ptr(), &mut now_st, libc::AT_SYMLINK_NOFOLLOW) != 0 {
            return Err(io::Error::last_os_error());
        }
        if now_st.st_dev != st.st_dev || now_st.st_ino != st.st_ino {
            return Err(io::Error::other("file was replaced after detection"));
        }
        if libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Decode a quarantined sample into `out` (a descriptor the client opened),
/// then drop it from quarantine and allowlist its hash so on-access scanning
/// doesn't take it straight back.
pub fn restore(store: &Store, item: &QuarantineItem, out: OwnedFd) -> io::Result<()> {
    let data = load(item)?;
    let mut out = File::from(out);
    out.write_all(&data)?;
    out.sync_all()?;
    store.allowlist_add(&item.sha256, &format!("restored from quarantine: {}", item.original_path));
    delete(store, item)
}

pub fn delete(store: &Store, item: &QuarantineItem) -> io::Result<()> {
    match std::fs::remove_file(store_path(&item.id)) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    store.quarantine_remove(&item.id);
    Ok(())
}

fn load(item: &QuarantineItem) -> io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    File::open(store_path(&item.id))?.read_to_end(&mut raw)?;
    if raw.len() < MAGIC.len() + KEY_LEN || &raw[..MAGIC.len()] != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a Qlam quarantine file"));
    }
    let key: [u8; KEY_LEN] = raw[MAGIC.len()..MAGIC.len() + KEY_LEN].try_into().unwrap();
    let mut data = raw.split_off(MAGIC.len() + KEY_LEN);
    xor(&mut data, &key);
    if hex::encode(Sha256::digest(&data)) != item.sha256 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "quarantine file is corrupt"));
    }
    Ok(data)
}

fn xor(data: &mut [u8], key: &[u8; KEY_LEN]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % KEY_LEN];
    }
}
