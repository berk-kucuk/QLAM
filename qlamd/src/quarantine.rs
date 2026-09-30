//! Root-owned quarantine in /var/lib/qlam/quarantine.
//!
//! Samples are stored XOR-encoded with a random per-file key, so the store
//! never holds a runnable (or re-detectable) copy of the malware. Nothing is
//! ever deleted outright: a file leaves its folder only once an intact copy
//! is stored, and a failed quarantine leaves it exactly as it was. Nothing
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
use crate::fsutil::fstat;
use crate::store::{now, QuarantineItem, Store};

const MAGIC: &[u8; 8] = b"QLAMQ1\0\0";
const KEY_LEN: usize = 32;
/// Files are copied through a buffer this size, never loaded whole.
const CHUNK: usize = 1 << 20;
/// Bigger files are reported but can't be quarantined.
const MAX_QUARANTINE_SIZE: u64 = 1 << 30;

fn store_path(id: &str) -> PathBuf {
    quarantine_dir().join(format!("{id}.qlq"))
}

pub fn ensure_dir() -> io::Result<()> {
    let dir = quarantine_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
}

/// Move the file open on `fd`, found at `path`, into quarantine.
///
/// All or nothing. The encoded copy is written and synced and its index row
/// added before the original is removed; if the content isn't `expect_sha256`
/// (the file changed since it was scanned), or the original can't be removed,
/// the copy and the row are dropped again. On any error the user's file is
/// exactly as it was — never half-quarantined, never made unreadable.
pub fn quarantine(
    store: &Store,
    fd: BorrowedFd<'_>,
    path: &Path,
    verdict: &Verdict,
    expect_sha256: &str,
) -> io::Result<QuarantineItem> {
    let st = fstat(fd)?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(io::Error::other("not a regular file"));
    }
    let item = copy_to_store(fd, path, &st, verdict)?;
    let undo = |item: &QuarantineItem| {
        let _ = std::fs::remove_file(store_path(&item.id));
    };
    if item.sha256 != expect_sha256 {
        undo(&item);
        return Err(io::Error::other("the file has changed since it was scanned; scan it again"));
    }
    if let Err(e) = store.quarantine_add(&item) {
        undo(&item);
        return Err(io::Error::other(format!("quarantine index: {e}")));
    }
    if let Err(e) = unlink_if_same(path, &st) {
        store.quarantine_remove(&item.id);
        undo(&item);
        return Err(e);
    }
    // Other hard links to the same inode still hold the content. It is safely
    // stored now, so make those names unreadable too.
    if st.st_nlink > 1 {
        unsafe { libc::fchmod(fd.as_raw_fd(), 0) };
    }
    Ok(item)
}

fn copy_to_store(fd: BorrowedFd<'_>, path: &Path, st: &libc::stat, verdict: &Verdict) -> io::Result<QuarantineItem> {
    if st.st_size as u64 > MAX_QUARANTINE_SIZE {
        return Err(io::Error::new(io::ErrorKind::FileTooLarge, "too large to quarantine"));
    }
    let mut key = [0u8; KEY_LEN];
    getrandom::fill(&mut key).map_err(|e| io::Error::other(e.to_string()))?;

    let id = uuid::Uuid::new_v4().to_string();
    let dest = store_path(&id);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&dest)?;
    let copied = (|| -> io::Result<(String, u64)> {
        f.write_all(MAGIC)?;
        f.write_all(&key)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        let mut off: u64 = 0;
        loop {
            let n = pread(fd, &mut buf, off)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            xor(&mut buf[..n], &key, off);
            f.write_all(&buf[..n])?;
            off += n as u64;
            if off > MAX_QUARANTINE_SIZE {
                return Err(io::Error::new(io::ErrorKind::FileTooLarge, "too large to quarantine"));
            }
        }
        f.sync_all()?;
        Ok((hex::encode(hasher.finalize()), off))
    })();
    let (sha256, size) = match copied {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_file(&dest);
            return Err(e);
        }
    };

    Ok(QuarantineItem {
        id,
        ts: now(),
        original_path: path.to_string_lossy().into_owned(),
        sha256,
        size: size as i64,
        uid: st.st_uid,
        gid: st.st_gid,
        mode: st.st_mode & 0o7777,
        detection: verdict.name.clone(),
        engine: verdict.engine.clone(),
    })
}

fn pread(fd: BorrowedFd<'_>, buf: &mut [u8], off: u64) -> io::Result<usize> {
    loop {
        let n = unsafe { libc::pread(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), off as libc::off_t) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
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
///
/// The stored copy is verified in full before a single byte is written, so a
/// damaged quarantine file never ends up in the user's folder.
pub fn restore(store: &Store, item: &QuarantineItem, out: OwnedFd) -> io::Result<()> {
    let (mut src, key) = open_sample(item)?;
    let mut hasher = Sha256::new();
    decode(&mut src, &key, |chunk| {
        hasher.update(chunk);
        Ok(())
    })?;
    if hex::encode(hasher.finalize()) != item.sha256 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "quarantine file is corrupt"));
    }
    let (mut src, key) = open_sample(item)?;
    let mut out = File::from(out);
    decode(&mut src, &key, |chunk| out.write_all(chunk))?;
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

/// Open a stored sample and read its header; returns the file positioned at
/// the encoded content, and the key.
fn open_sample(item: &QuarantineItem) -> io::Result<(File, [u8; KEY_LEN])> {
    let mut f = File::open(store_path(&item.id))?;
    let mut head = [0u8; MAGIC.len() + KEY_LEN];
    f.read_exact(&mut head)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not a Qlam quarantine file"))?;
    if &head[..MAGIC.len()] != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a Qlam quarantine file"));
    }
    Ok((f, head[MAGIC.len()..].try_into().unwrap()))
}

/// Stream the decoded content through `sink`, a chunk at a time.
fn decode(src: &mut File, key: &[u8; KEY_LEN], mut sink: impl FnMut(&[u8]) -> io::Result<()>) -> io::Result<()> {
    let mut buf = vec![0u8; CHUNK];
    let mut off: u64 = 0;
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        xor(&mut buf[..n], key, off);
        sink(&buf[..n])?;
        off += n as u64;
    }
}

/// XOR with the key, for a chunk that starts `offset` bytes into the file.
fn xor(data: &mut [u8], key: &[u8; KEY_LEN], offset: u64) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[((offset + i as u64) % KEY_LEN as u64) as usize];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Severity;
    use std::os::fd::AsFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn sha(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    fn verdict(sha256: &str) -> Verdict {
        Verdict { severity: Severity::Malicious, confirmed: true, name: "Test".into(), engine: "hash".into(), sha256: sha256.into() }
    }

    fn stored_samples() -> usize {
        std::fs::read_dir(quarantine_dir()).map(|d| d.count()).unwrap_or(0)
    }

    /// One test, because quarantine_dir() comes from a process-wide variable.
    #[test]
    fn quarantine_is_all_or_nothing() {
        let root = std::env::temp_dir().join(format!("qlam-quarantine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::env::set_var("QLAM_STATE_DIR", root.join("state"));
        ensure_dir().unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let store = Store::in_memory();

        // A file larger than one copy chunk, moved and restored intact.
        let data: Vec<u8> = (0..3 * CHUNK + 123).map(|i| (i * 7 % 251) as u8).collect();
        let p = home.join("sample.bin");
        std::fs::write(&p, &data).unwrap();
        let f = File::open(&p).unwrap();
        let item = quarantine(&store, f.as_fd(), &p, &verdict(&sha(&data)), &sha(&data)).unwrap();
        drop(f);
        assert!(!p.exists(), "original removed");
        assert_eq!(item.size as usize, data.len());
        assert_eq!(stored_samples(), 1);
        let raw = std::fs::read(store_path(&item.id)).unwrap();
        assert!(!raw.windows(64).any(|w| w == &data[..64]), "stored encoded, not as-is");
        let out = home.join("restored.bin");
        restore(&store, &item, File::create(&out).unwrap().into()).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), data);
        assert_eq!(stored_samples(), 0);
        assert!(store.quarantine_list(None).is_empty());

        // Content no longer what was scanned: nothing happens.
        let p = home.join("changed.bin");
        std::fs::write(&p, b"new content").unwrap();
        std::fs::set_permissions(&p, PermissionsExt::from_mode(0o640)).unwrap();
        let f = File::open(&p).unwrap();
        let err = quarantine(&store, f.as_fd(), &p, &verdict("x"), &sha(b"old content")).unwrap_err();
        assert!(err.to_string().contains("changed"), "{err}");
        assert_eq!(std::fs::read(&p).unwrap(), b"new content");
        assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o640, "mode untouched");
        assert_eq!(stored_samples(), 0);
        assert!(store.quarantine_list(None).is_empty());

        // Original can't be removed (read-only folder): everything undone.
        let ro = home.join("readonly");
        std::fs::create_dir(&ro).unwrap();
        let p = ro.join("stuck.bin");
        std::fs::write(&p, b"stuck").unwrap();
        std::fs::set_permissions(&ro, PermissionsExt::from_mode(0o555)).unwrap();
        let f = File::open(&p).unwrap();
        let res = quarantine(&store, f.as_fd(), &p, &verdict("x"), &sha(b"stuck"));
        std::fs::set_permissions(&ro, PermissionsExt::from_mode(0o755)).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            // (root ignores the folder's permissions)
            assert!(res.is_err());
            assert_eq!(std::fs::read(&p).unwrap(), b"stuck");
            assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o644);
            assert_eq!(stored_samples(), 0);
            assert!(store.quarantine_list(None).is_empty());
        }

        // Other hard links lose access once the content is safely stored.
        let p = home.join("linked.bin");
        let twin = home.join("twin.bin");
        std::fs::write(&p, b"linked").unwrap();
        std::fs::hard_link(&p, &twin).unwrap();
        let f = File::open(&p).unwrap();
        quarantine(&store, f.as_fd(), &p, &verdict("x"), &sha(b"linked")).unwrap();
        assert!(!p.exists());
        assert_eq!(std::fs::metadata(&twin).unwrap().mode() & 0o777, 0);

        let _ = std::fs::remove_dir_all(&root);
    }
}
