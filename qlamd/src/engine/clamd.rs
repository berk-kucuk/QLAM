//! Optional ClamAV engine through clamd.
//!
//! Files are handed over with zFILDES (the descriptor is passed over the unix
//! socket), not by path: clamd runs as the unprivileged `clamav` user and can't
//! open files in users' homes, and a path could be swapped between our check
//! and clamd's open anyway.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use super::{Match, Severity};

pub struct Clamd {
    socket: PathBuf,
}

impl Clamd {
    pub fn new(socket: &str) -> Clamd {
        Clamd { socket: PathBuf::from(socket) }
    }

    pub fn available(&self) -> bool {
        let Ok(mut s) = self.connect() else { return false };
        s.write_all(b"zPING\0").is_ok() && read_reply(&mut s).is_some_and(|r| r == "PONG")
    }

    fn connect(&self) -> std::io::Result<UnixStream> {
        let s = UnixStream::connect(&self.socket)?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        s.set_write_timeout(Some(Duration::from_secs(2)))?;
        Ok(s)
    }

    /// None when clean, when clamd isn't running, or on any protocol error:
    /// ClamAV is an extra layer, never the only one.
    pub fn scan_fd(&self, fd: BorrowedFd<'_>) -> Option<Match> {
        let mut s = self.connect().ok()?;
        // The descriptor shares our file offset, which the hash pass left at
        // EOF.
        unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) };
        s.write_all(b"zFILDES\0").ok()?;
        send_fd(&s, fd).ok()?;
        let reply = read_reply(&mut s)?;
        // "fd[10]: Eicar-Test-Signature FOUND" / "fd[10]: OK"
        let verdict = reply.rsplit_once(": ").map(|(_, v)| v)?;
        let name = verdict.strip_suffix(" FOUND")?.trim();
        // Heuristics.* (encrypted archives, broken executables, phishing
        // guesses) misfire on ordinary files too often to show a user at all.
        // PUA.* is an opinion about wanted software, so at most a warning.
        if name.starts_with("Heuristics.") {
            return None;
        }
        let severity = if name.starts_with("PUA.") { Severity::Suspicious } else { Severity::Malicious };
        Some(Match { severity, confirmed: false, name: format!("ClamAV.{name}") })
    }
}

fn read_reply(s: &mut UnixStream) -> Option<String> {
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        match s.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == 0 => break,
            Ok(_) => {
                buf.push(byte[0]);
                if buf.len() > 4096 {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
    String::from_utf8(buf).ok()
}

fn send_fd(sock: &UnixStream, fd: BorrowedFd<'_>) -> std::io::Result<()> {
    let raw = fd.as_raw_fd();
    let mut data = [0u8; 1];
    let mut iov = libc::iovec { iov_base: data.as_mut_ptr().cast(), iov_len: 1 };
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut cbuf = vec![0u8; space];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>(), raw);
        if libc::sendmsg(sock.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
