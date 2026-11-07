//! Reading processes from /proc, for the behaviour monitor and the rootkit
//! checks. Everything here is best effort: a process can exit between any
//! two reads, so every function returns None rather than failing.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

/// PF_KTHREAD in /proc/<pid>/stat flags.
const PF_KTHREAD: u64 = 0x0020_0000;

/// Process ids as /proc lists them.
pub fn pids() -> Vec<i32> {
    let Ok(rd) = std::fs::read_dir("/proc") else { return Vec::new() };
    rd.flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect()
}

#[derive(Debug, Clone)]
pub struct Stat {
    pub comm: String,
    pub kernel_thread: bool,
    /// User + system CPU time, in clock ticks.
    pub cpu_ticks: u64,
    /// Start time since boot, in clock ticks: with the pid, identifies a
    /// process across pid reuse.
    pub start: u64,
}

pub fn stat(pid: i32) -> Option<Stat> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_stat(&s)
}

fn parse_stat(s: &str) -> Option<Stat> {
    // "pid (comm) state ppid ..." — comm may itself contain spaces and ')'.
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    let comm = s.get(open + 1..close)?.to_string();
    let rest: Vec<&str> = s.get(close + 2..)?.split_whitespace().collect();
    // rest[0] is field 3 (state).
    let field = |n: usize| rest.get(n - 3).and_then(|v| v.parse::<u64>().ok());
    Some(Stat {
        comm,
        kernel_thread: field(9)? & PF_KTHREAD != 0,
        cpu_ticks: field(14)? + field(15)?,
        start: field(22)?,
    })
}

/// (real uid, thread group id) from /proc/<pid>/status.
pub fn status_ids(pid: i32) -> Option<(u32, i32)> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut uid = None;
    let mut tgid = None;
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("Uid:") {
            uid = v.split_whitespace().next().and_then(|u| u.parse().ok());
        } else if let Some(v) = line.strip_prefix("Tgid:") {
            tgid = v.trim().parse().ok();
        }
    }
    Some((uid?, tgid?))
}

/// The executable, as the kernel reports it ("/x (deleted)", "/memfd:name
/// (deleted)"). Needs ptrace-read access to the process.
pub fn exe(pid: i32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| p.to_string_lossy().into_owned())
}

/// argv[0].
pub fn argv0(pid: i32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let first = raw.split(|b| *b == 0).next()?;
    Some(String::from_utf8_lossy(first).into_owned())
}

/// Socket inode an open descriptor refers to.
pub fn fd_socket(pid: i32, fd: i32) -> Option<u64> {
    socket_inode(&std::fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?)
}

/// Inodes of every socket the process has open.
pub fn sockets(pid: i32) -> HashSet<u64> {
    let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { return HashSet::new() };
    rd.flatten().filter_map(|e| socket_inode(&std::fs::read_link(e.path()).ok()?)).collect()
}

fn socket_inode(link: &Path) -> Option<u64> {
    link.to_str()?.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

/// An established TCP connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conn {
    pub remote: IpAddr,
    pub port: u16,
    pub inode: u64,
}

/// Established TCP connections in the network namespace of `pid`. (The
/// daemon runs in its own, empty one, so /proc/net would show nothing.)
pub fn tcp_established(pid: i32) -> Vec<Conn> {
    let mut out = Vec::new();
    for (file, v6) in [("tcp", false), ("tcp6", true)] {
        if let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/net/{file}")) {
            out.extend(s.lines().skip(1).filter_map(|l| parse_tcp_line(l, v6)));
        }
    }
    out
}

fn parse_tcp_line(line: &str, v6: bool) -> Option<Conn> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.get(3)? != &"01" {
        return None; // not ESTABLISHED
    }
    let (addr, port) = f.get(2)?.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let remote = if v6 { IpAddr::V6(parse_v6(addr)?) } else { IpAddr::V4(parse_v4(addr)?) };
    Some(Conn { remote, port, inode: f.get(9)?.parse().ok()? })
}

/// /proc/net/tcp writes addresses as host-order (little-endian) words.
fn parse_v4(hex: &str) -> Option<Ipv4Addr> {
    Some(Ipv4Addr::from(u32::from_str_radix(hex, 16).ok()?.swap_bytes()))
}

fn parse_v6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for w in 0..4 {
        let word = u32::from_str_radix(&hex[w * 8..w * 8 + 8], 16).ok()?.swap_bytes();
        bytes[w * 4..w * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    Some(Ipv6Addr::from(bytes))
}

/// An address on the internet rather than this machine or the local
/// network (where a game server, a NAS or a phone over adb lives).
pub fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast()
                // 100.64.0.0/10, carrier-grade NAT and Tailscale.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(&IpAddr::V4(v4));
            }
            let seg0 = v6.segments()[0];
            !(v6.is_loopback() || v6.is_unspecified() || (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80)
        }
    }
}

/// The highest pid the kernel may have handed out lately.
pub fn pid_horizon(listed: &[i32]) -> i32 {
    let read = |p: &str| std::fs::read_to_string(p).ok().and_then(|s| s.trim().parse::<i32>().ok());
    let last = read("/proc/sys/kernel/ns_last_pid").unwrap_or(0);
    let max = read("/proc/sys/kernel/pid_max").unwrap_or(4_194_304);
    listed.iter().copied().max().unwrap_or(0).max(last).saturating_add(64).min(max)
}

pub fn proc_path(pid: i32) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stat_with_awkward_names() {
        let line = "4242 (evil) (x) S 1 4242 4242 0 -1 4194560 10 0 0 0 150 50 0 0 20 0 1 0 98765 1000 100 18446744073709551615";
        let s = parse_stat(line).unwrap();
        assert_eq!(s.comm, "evil) (x");
        assert_eq!(s.cpu_ticks, 200);
        assert_eq!(s.start, 98765);
        assert!(!s.kernel_thread);
        let kthread = "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 2 0 0";
        assert!(parse_stat(kthread).unwrap().kernel_thread);
    }

    #[test]
    fn parses_tcp_lines() {
        let v4 = "   1: 0100A8C0:C350 22B8D9B9:0D05 01 00000000:00000000 00:00000000 00000000  1000        0 123456 1 0000000000000000 20 4 30 10 -1";
        let c = parse_tcp_line(v4, false).unwrap();
        assert_eq!(c.remote, IpAddr::V4(Ipv4Addr::new(185, 217, 184, 34)));
        assert_eq!(c.port, 3333);
        assert_eq!(c.inode, 123456);
        let listen = "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999 1";
        assert_eq!(parse_tcp_line(listen, false), None);
        let v6 = "   0: 00000000000000000000000001000000:1F90 0000000000000000FFFF00000100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 777 1";
        let c = parse_tcp_line(v6, true).unwrap();
        assert_eq!(c.remote, IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!is_public(&c.remote));
    }

    #[test]
    fn public_addresses() {
        for (ip, public) in [("8.8.8.8", true), ("192.168.1.5", false), ("10.0.0.1", false), ("100.101.1.1", false),
                             ("127.0.0.1", false), ("2001:4860::8888", true), ("fd00::1", false), ("fe80::1", false)] {
            assert_eq!(is_public(&ip.parse().unwrap()), public, "{ip}");
        }
    }

    #[test]
    fn reads_own_process() {
        let me = std::process::id() as i32;
        assert!(pids().contains(&me));
        let st = stat(me).unwrap();
        assert!(!st.kernel_thread);
        assert_eq!(status_ids(me).unwrap().1, me);
        assert!(exe(me).is_some());
    }
}
