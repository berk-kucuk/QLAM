//! Small descriptor-level helpers shared by the scanners.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub fn fstat(fd: BorrowedFd<'_>) -> io::Result<libc::stat> {
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd.as_raw_fd(), &mut st) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(st)
    }
}

/// A file only root could have put where it is: under /usr, owned by root,
/// writable by no one else, in a directory owned by root that no one else can
/// write either. Qlam never blocks or quarantines such a file on its own
/// (audit QL2): a non-root attacker cannot place one there, a root attacker
/// can switch Qlam off anyway — but a poisoned or mistaken feed listing the
/// hash of /usr/bin/sudo would otherwise stop it from running on the whole
/// system. It is still reported.
pub fn is_system_file(fd: BorrowedFd<'_>, path: &Path) -> bool {
    let Ok(st) = fstat(fd) else { return false };
    if st.st_uid != 0 || st.st_mode & 0o022 != 0 || !path.starts_with("/usr/") {
        return false;
    }
    let Some(parent) = path.parent() else { return false };
    match std::fs::metadata(parent) {
        Ok(m) => m.uid() == 0 && m.mode() & 0o022 == 0,
        Err(_) => false,
    }
}

/// Read the whole file with pread (no shared offset, no mmap: a file
/// truncated under a mapping raises SIGBUS, which any user could use to kill
/// the daemon). Fails with FileTooLarge past `max` instead of returning a
/// prefix that would then be called clean.
pub fn read_from_start(fd: BorrowedFd<'_>, out: &mut Vec<u8>, max: u64) -> io::Result<()> {
    out.clear();
    let mut off: u64 = 0;
    loop {
        if out.capacity() - out.len() < 64 * 1024 {
            out.reserve(1 << 20);
        }
        let spare = out.capacity() - out.len();
        let n = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                out.as_mut_ptr().add(out.len()).cast(),
                spare,
                off as libc::off_t,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Ok(());
        }
        unsafe { out.set_len(out.len() + n as usize) };
        off += n as u64;
        if off > max {
            return Err(io::Error::new(io::ErrorKind::FileTooLarge, "file exceeds size limit"));
        }
    }
}

/// Path a descriptor refers to, as the kernel reports it.
pub fn fd_path(fd: BorrowedFd<'_>) -> Option<PathBuf> {
    let link = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok()?;
    let s = link.to_string_lossy();
    // Unlinked-but-open files read back as "/path (deleted)".
    match s.strip_suffix(" (deleted)") {
        Some(p) => Some(PathBuf::from(p)),
        None => Some(link),
    }
}

/// "name[pid]" for event records; best effort.
pub fn process_label(pid: i32) -> String {
    if pid <= 0 {
        return String::new();
    }
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
    format!("{}[{pid}]", comm.trim())
}

/// Real uid of a process; None if it is gone.
pub fn process_uid(pid: i32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|u| u.parse().ok())
}

/// How much disk time a thread may take.
#[derive(Clone, Copy)]
pub enum IoPriority {
    /// Only when no one else wants the disk.
    Idle,
    /// Lowest of the normal class: still makes progress under load.
    Low,
}

/// Lower this thread's I/O and CPU priority (both are per-thread on Linux).
pub fn lower_priority(io: IoPriority, nice: i32) {
    const IOPRIO_WHO_PROCESS: libc::c_long = 1;
    const IOPRIO_CLASS_SHIFT: libc::c_long = 13;
    let value = match io {
        IoPriority::Idle => 3 << IOPRIO_CLASS_SHIFT,
        IoPriority::Low => (2 << IOPRIO_CLASS_SHIFT) | 7,
    };
    unsafe {
        libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0 as libc::c_long, value);
        libc::setpriority(libc::PRIO_PROCESS, 0, nice);
    }
}

/// Give back a scan buffer's memory after a large file, so one big file
/// doesn't keep tens of megabytes allocated for good.
pub fn trim_buffer(buf: &mut Vec<u8>) {
    const KEEP: usize = 1 << 20;
    if buf.capacity() > 8 * KEEP {
        buf.clear();
        buf.shrink_to(KEEP);
    }
}

#[cfg(test)]
mod system_file_tests {
    use super::*;
    use std::fs::File;
    use std::os::fd::AsFd;

    #[test]
    fn root_owned_usr_binary_is_a_system_file() {
        let p = Path::new("/usr/bin/sh");
        if let Ok(f) = File::open(p) {
            let real = std::fs::canonicalize(p).unwrap();
            assert!(is_system_file(f.as_fd(), &real));
        }
    }

    #[test]
    fn user_files_are_not() {
        let dir = std::env::temp_dir().join(format!("qlam-sysfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x");
        std::fs::write(&p, b"x").unwrap();
        let f = File::open(&p).unwrap();
        assert!(!is_system_file(f.as_fd(), &p));
        // A path that only claims to be under /usr does not help either:
        // the file is not root's.
        assert!(!is_system_file(f.as_fd(), Path::new("/usr/bin/x")));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
