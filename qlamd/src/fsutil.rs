//! Small descriptor-level helpers shared by the scanners.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::PathBuf;

pub fn fstat(fd: BorrowedFd<'_>) -> io::Result<libc::stat> {
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd.as_raw_fd(), &mut st) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(st)
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
