//! Behaviour monitor: what running programs do, not what their files
//! contain.
//!
//! Every TICK the monitor walks /proc and looks for things malware does
//! and ordinary programs almost never do:
//!   - running from memory only (a memfd), or from a file that was deleted
//!     out of a user-writable location after it started;
//!   - running from a hidden folder in /tmp, /var/tmp or /dev/shm;
//!   - a userland process calling itself "[kworker/0:1]" to pass as a
//!     kernel thread in `ps`;
//!   - a shell whose input and output are a network connection to the
//!     internet: a reverse shell;
//!   - a program from a user-writable location connected to a mining-pool
//!     port on the internet, and (worse) also burning CPU: a cryptominer.
//!
//! Whenever there is a program file to look at (even a deleted or
//! memory-only one, through /proc/<pid>/exe), it is also scanned like any
//! other file, so a known sample is named as such.
//!
//! Cost: one pass over /proc every 10 seconds (a few reads per process);
//! sockets only every minute and only for programs that run from a
//! user-writable place. No process is ever stopped or touched: findings
//! are reported like any other, and the user decides. Polling misses
//! programs that live for a few seconds, which is accepted: what this is
//! for (miners, backdoors, reverse shells) stays running.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::os::fd::AsFd;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Scope;
use crate::daemon::Daemon;
use crate::engine::{archive, Severity};
use crate::guard::{Observation, Trigger};
use crate::procfs;

const TICK: Duration = Duration::from_secs(10);
/// Sockets are looked at every this many ticks.
const NET_EVERY: u32 = 6;
/// CPU share (of one core, over a minute) above which a miner is "mining".
const BUSY_SHARE: f64 = 0.5;

/// Ports of the usual mining pools (stratum). 4444 and 5555 are also used
/// by other things, which is why a connection alone is only a notice.
const POOL_PORTS: &[u16] = &[3333, 4444, 5555, 7777, 10128, 10343, 14433, 14444, 20580, 45560, 45700];

const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "fish", "busybox", "tcsh", "csh"];

/// memfd executables that are normal: container runtimes re-executing
/// themselves from memory (CVE-2019-5736 hardening).
const MEMFD_OK: &[&str] = &["/memfd:runc_cloned", "/memfd:crun", "/memfd:youki"];

/// One process, as seen over time.
struct Seen {
    start: u64,
    cpu: u64,
    cpu_at: Instant,
    /// CPU share of one core since the previous network pass.
    share: f64,
    reported: HashSet<&'static str>,
}

pub fn spawn(d: Arc<Daemon>) {
    std::thread::Builder::new()
        .name("behavior".into())
        .spawn(move || {
            crate::fsutil::lower_priority(crate::fsutil::IoPriority::Idle, 19);
            let mut m = Monitor { seen: HashMap::new(), tick: 0, buf: Vec::new(), me: std::process::id() as i32 };
            loop {
                std::thread::sleep(TICK);
                if d.config().behavior_monitor {
                    m.pass(&d);
                } else {
                    m.seen.clear();
                }
            }
        })
        .expect("spawn behavior monitor");
}

struct Monitor {
    seen: HashMap<i32, Seen>,
    tick: u32,
    buf: Vec<u8>,
    me: i32,
}

/// What the monitor makes of one process.
#[derive(Debug, PartialEq)]
pub struct Suspicion {
    pub name: &'static str,
    pub severity: &'static str,
    pub detail: String,
}

impl Monitor {
    fn pass(&mut self, d: &Daemon) {
        self.tick = self.tick.wrapping_add(1);
        let net = self.tick % NET_EVERY == 0;
        let scope = d.scope();
        let pids = procfs::pids();
        let alive: HashSet<i32> = pids.iter().copied().collect();
        self.seen.retain(|pid, _| alive.contains(pid));

        for pid in pids {
            if pid == self.me {
                continue;
            }
            let Some(st) = procfs::stat(pid) else { continue };
            if st.kernel_thread {
                continue;
            }
            let Some(exe) = procfs::exe(pid) else { continue };
            let now = Instant::now();
            let seen = self.seen.entry(pid).or_insert_with(|| Seen {
                start: st.start,
                cpu: st.cpu_ticks,
                cpu_at: now,
                share: 0.0,
                reported: HashSet::new(),
            });
            if seen.start != st.start {
                // The pid was reused by a new process.
                *seen = Seen { start: st.start, cpu: st.cpu_ticks, cpu_at: now, share: 0.0, reported: HashSet::new() };
            }
            if net {
                let secs = now.duration_since(seen.cpu_at).as_secs_f64();
                if secs > 0.0 {
                    seen.share = st.cpu_ticks.saturating_sub(seen.cpu) as f64 / clock_ticks() / secs;
                }
                seen.cpu = st.cpu_ticks;
                seen.cpu_at = now;
            }

            let mut found = Vec::new();
            found.extend(judge_exe(&exe, &scope));
            if let Some(argv0) = procfs::argv0(pid) {
                found.extend(judge_name(&argv0, &st.comm));
            }
            if SHELLS.contains(&st.comm.as_str()) {
                found.extend(reverse_shell(pid));
            }
            if net && runs_from_user_space(&exe, &scope) {
                found.extend(miner(pid, seen.share));
            }

            let fresh: Vec<Suspicion> = found.into_iter().filter(|s| seen.reported.insert(s.name)).collect();
            if fresh.is_empty() {
                continue;
            }
            let uid = procfs::status_ids(pid).map(|(u, _)| u).unwrap_or(0);
            let shown = exe.trim_end_matches(" (deleted)").to_string();
            // The program itself, whatever it is, gets a proper scan too.
            self.scan_exe(d, pid, &shown);
            for s in fresh {
                log::warn!("behaviour: pid {pid} ({}): {} — {}", st.comm, s.name, s.detail);
                d.guard.report_observation(Observation {
                    path: shown.clone().into(),
                    uid,
                    pid,
                    kind: "behavior",
                    engine: "behavior",
                    name: s.name,
                    detail: &s.detail,
                    severity: s.severity,
                });
            }
        }
    }

    /// Scan the program a process runs, through /proc/<pid>/exe, which
    /// works for deleted and memory-only programs too.
    fn scan_exe(&mut self, d: &Daemon, pid: i32, shown: &str) {
        let Ok(file) = File::open(format!("/proc/{pid}/exe")) else { return };
        let path = Path::new(shown);
        if let Ok(v) = d.guard.engine.scan_fd(file.as_fd(), path, 100 << 20, Some(&archive::Limits::ON_ACCESS), &mut self.buf) {
            if v.severity != Severity::Clean {
                d.guard.handle(file.as_fd(), path, &v, Trigger::Exec { pid, blocked: false });
            }
        }
        crate::fsutil::trim_buffer(&mut self.buf);
    }
}

/// One pass of the checks that need no history (`qlamd check-system`):
/// (pid, comm, suspicion) for every process this caller can inspect.
pub fn check_once(scope: &Scope) -> Vec<(i32, String, Suspicion)> {
    let mut out = Vec::new();
    for pid in procfs::pids() {
        let Some(st) = procfs::stat(pid) else { continue };
        if st.kernel_thread {
            continue;
        }
        let Some(exe) = procfs::exe(pid) else { continue };
        let mut found: Vec<Suspicion> = judge_exe(&exe, scope).into_iter().collect();
        found.extend(procfs::argv0(pid).and_then(|a| judge_name(&a, &st.comm)));
        if SHELLS.contains(&st.comm.as_str()) {
            found.extend(reverse_shell(pid));
        }
        if runs_from_user_space(&exe, scope) {
            found.extend(miner(pid, 0.0));
        }
        out.extend(found.into_iter().map(|s| (pid, st.comm.clone(), s)));
    }
    out
}

fn clock_ticks() -> f64 {
    let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if t > 0 { t as f64 } else { 100.0 }
}

/// Where the program runs from.
pub fn judge_exe(exe: &str, scope: &Scope) -> Option<Suspicion> {
    if exe.starts_with("/memfd:") {
        if MEMFD_OK.iter().any(|ok| exe.starts_with(ok)) {
            return None;
        }
        return Some(Suspicion {
            name: "Qlam.Behavior.FilelessExecution",
            severity: "suspicious",
            detail: format!("runs from memory only ({}), with no program file on disk", exe.trim_end_matches(" (deleted)")),
        });
    }
    if let Some(path) = exe.strip_suffix(" (deleted)") {
        // After an update the old program file is gone but a new one sits
        // at the same path: normal. Gone without a replacement, from a
        // place users write to: a program that removed its own traces.
        let p = Path::new(path);
        if scope.contains(p) && !p.exists() {
            return Some(Suspicion {
                name: "Qlam.Behavior.DeletedExecutable",
                severity: "suspicious",
                detail: format!("keeps running after its program file {path} was deleted"),
            });
        }
        return None;
    }
    let p = Path::new(exe);
    let temp = ["/tmp", "/var/tmp", "/dev/shm"].iter().find(|t| p.starts_with(t))?;
    let hidden = p
        .strip_prefix(temp)
        .ok()?
        .components()
        .any(|c| c.as_os_str().to_str().is_some_and(|s| s.starts_with('.') && !s.starts_with(".mount_")));
    if *temp == "/dev/shm" || hidden {
        return Some(Suspicion {
            name: "Qlam.Behavior.HiddenTempProgram",
            severity: "suspicious",
            detail: format!("runs from {exe}, a hidden or memory-backed temporary location"),
        });
    }
    None
}

/// A userland process named like a kernel thread.
pub fn judge_name(argv0: &str, comm: &str) -> Option<Suspicion> {
    const KTHREADS: &[&str] =
        &["kworker", "ksoftirqd", "kthreadd", "kswapd", "migration", "rcu_sched", "rcu_preempt", "watchdog", "kblockd", "jbd2"];
    let looks_kernel = |s: &str| {
        let s = s.trim();
        let inner = s.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(s);
        KTHREADS.iter().any(|k| inner.starts_with(k)) && (s.starts_with('[') || inner.contains('/'))
    };
    if looks_kernel(argv0) || looks_kernel(comm) {
        return Some(Suspicion {
            name: "Qlam.Behavior.KernelThreadMasquerade",
            severity: "malicious",
            detail: format!("calls itself \"{}\" to pass as a kernel thread, but is a normal program", argv0.trim()),
        });
    }
    None
}

/// A shell whose standard input and output are an internet connection.
fn reverse_shell(pid: i32) -> Option<Suspicion> {
    let (Some(i), Some(o)) = (procfs::fd_socket(pid, 0), procfs::fd_socket(pid, 1)) else { return None };
    let conns = procfs::tcp_established(pid);
    let c = conns.iter().find(|c| (c.inode == i || c.inode == o) && procfs::is_public(&c.remote))?;
    Some(Suspicion {
        name: "Qlam.Behavior.ReverseShell",
        severity: "malicious",
        detail: format!("is a shell whose input and output are a connection to {}:{}, so whoever is there controls it", c.remote, c.port),
    })
}

fn runs_from_user_space(exe: &str, scope: &Scope) -> bool {
    exe.starts_with("/memfd:") || scope.contains(Path::new(exe.trim_end_matches(" (deleted)")))
}

/// Connected to a mining pool port on the internet; mining if also busy.
fn miner(pid: i32, share: f64) -> Option<Suspicion> {
    let mine = procfs::sockets(pid);
    if mine.is_empty() {
        return None;
    }
    let conns = procfs::tcp_established(pid);
    let c = conns.iter().find(|c| mine.contains(&c.inode) && POOL_PORTS.contains(&c.port) && procfs::is_public(&c.remote))?;
    Some(if share >= BUSY_SHARE {
        Suspicion {
            name: "Qlam.Behavior.CryptoMiner",
            severity: "malicious",
            detail: format!(
                "uses {:.0}% of a CPU core while connected to {}:{}, a mining pool port",
                share * 100.0,
                c.remote,
                c.port
            ),
        }
    } else {
        Suspicion {
            name: "Qlam.Behavior.MiningPoolConnection",
            severity: "suspicious",
            detail: format!("is connected to {}:{}, a port mining pools use", c.remote, c.port),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn scope() -> Scope {
        Scope::new(&Config::default())
    }

    #[test]
    fn judges_where_programs_run_from() {
        let s = scope();
        assert_eq!(judge_exe("/memfd:x (deleted)", &s).unwrap().name, "Qlam.Behavior.FilelessExecution");
        assert_eq!(judge_exe("/memfd:runc_cloned:/proc/self/exe (deleted)", &s), None);
        assert_eq!(judge_exe("/tmp/.ICE-unix/.x/kdevtmpfsi", &s).unwrap().name, "Qlam.Behavior.HiddenTempProgram");
        assert_eq!(judge_exe("/dev/shm/x", &s).unwrap().name, "Qlam.Behavior.HiddenTempProgram");
        // AppImages run from a FUSE mount under /tmp/.mount_*.
        assert_eq!(judge_exe("/tmp/.mount_ObsidiXyz/obsidian", &s), None);
        assert_eq!(judge_exe("/tmp/build/a.out", &s), None);
        // Deleted and not replaced, in a user location: suspicious.
        assert_eq!(
            judge_exe("/home/nobody-qlam-test/.cache/x (deleted)", &s).unwrap().name,
            "Qlam.Behavior.DeletedExecutable"
        );
        // Replaced by an update (the path exists again), or a system path.
        assert_eq!(judge_exe("/tmp (deleted)", &s), None);
        assert_eq!(judge_exe("/usr/bin/nonexistent-qlam (deleted)", &s), None);
        assert_eq!(judge_exe("/usr/bin/bash", &s), None);
    }

    /// What one pass costs on this machine (`cargo test -- --ignored`).
    #[test]
    #[ignore]
    fn pass_cost() {
        let s = scope();
        let t = std::time::Instant::now();
        for _ in 0..20 {
            check_once(&s);
        }
        eprintln!("one pass over {} processes: {:?}", procfs::pids().len(), t.elapsed() / 20);
    }

    #[test]
    fn judges_names() {
        assert_eq!(judge_name("[kworker/0:2]", "kworker/0:2").unwrap().severity, "malicious");
        assert!(judge_name("[kswapd0]", "x").is_some());
        assert!(judge_name("/usr/bin/python3", "kworker/1:0").is_some());
        assert_eq!(judge_name("/usr/bin/watchdog-client", "watchdog-client"), None);
        assert_eq!(judge_name("kworker-exporter", "kworker-exporte"), None);
        assert_eq!(judge_name("[celery worker]", "celery"), None);
    }
}
