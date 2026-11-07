//! System-level rootkit checks, run with every quick, home and scheduled
//! scan.
//!
//! A rootkit's job is to hide, so these look for the seams hiding leaves:
//!   - /etc/ld.so.preload: a library injected into every program. The
//!     classic userland rootkit (libprocesshider, Azazel, Jynx) installs
//!     itself here; legitimate uses are rare.
//!   - processes the kernel knows but `/proc` doesn't list: a rootkit
//!     hooking directory listing hides its process from `ps`, but the
//!     process still answers when asked for by number.
//!   - kernel modules in /sys/module that /proc/modules doesn't list (or the
//!     other way round): a module unlinking itself from one list.
//!
//! The process and module checks compare two views taken at slightly
//! different times, so anything found is confirmed by looking again: a
//! process starting or a module loading in between is not a rootkit.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use crate::procfs;

pub struct Finding {
    pub path: PathBuf,
    pub name: &'static str,
    pub detail: String,
    /// "malicious" or "suspicious".
    pub severity: &'static str,
    /// The process the finding is about, if any.
    pub pid: i32,
}

pub fn check() -> Vec<Finding> {
    let mut out = preload();
    out.extend(hidden_processes());
    out.extend(hidden_modules());
    out
}

// ── ld.so.preload ────────────────────────────────────────────────────────

const PRELOAD: &str = "/etc/ld.so.preload";

fn preload() -> Vec<Finding> {
    let Ok(text) = std::fs::read_to_string(PRELOAD) else { return Vec::new() };
    preload_entries(&text)
        .into_iter()
        .map(|lib| Finding {
            path: PRELOAD.into(),
            name: "Qlam.Rootkit.LdSoPreload",
            detail: format!("{lib} is loaded into every program on this computer"),
            severity: "suspicious",
            pid: 0,
        })
        .collect()
}

fn preload_entries(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .flat_map(|l| l.split_whitespace())
        .map(str::to_string)
        .collect()
}

// ── Hidden processes ─────────────────────────────────────────────────────

fn hidden_processes() -> Vec<Finding> {
    let listed: HashSet<i32> = procfs::pids().into_iter().collect();
    let horizon = procfs::pid_horizon(&listed.iter().copied().collect::<Vec<_>>());
    let candidates: Vec<i32> = (1..=horizon)
        .filter(|pid| !listed.contains(pid))
        // Threads answer to their id too but are never listed: only a
        // thread group leader is a process.
        .filter(|pid| procfs::status_ids(*pid).is_some_and(|(_, tgid)| tgid == *pid))
        .collect();
    if candidates.is_empty() {
        return Vec::new();
    }
    // Whatever was born after the listing shows up in a fresh one.
    std::thread::sleep(Duration::from_millis(200));
    let relisted: HashSet<i32> = procfs::pids().into_iter().collect();
    candidates
        .into_iter()
        .filter(|pid| !relisted.contains(pid))
        .filter_map(|pid| {
            let (uid, tgid) = procfs::status_ids(pid)?;
            (tgid == pid).then_some(())?;
            let comm = procfs::stat(pid).map(|s| s.comm).unwrap_or_default();
            let exe = procfs::exe(pid).unwrap_or_else(|| "unknown program".into());
            Some(Finding {
                path: procfs::proc_path(pid),
                name: "Qlam.Rootkit.HiddenProcess",
                detail: format!("process {pid} ({comm}, {exe}, user {uid}) runs but is hidden from the process list"),
                severity: "malicious",
                pid,
            })
        })
        .collect()
}

// ── Hidden kernel modules ────────────────────────────────────────────────

fn proc_modules() -> Option<HashSet<String>> {
    let text = std::fs::read_to_string("/proc/modules").ok()?;
    Some(text.lines().filter_map(|l| l.split_whitespace().next()).map(str::to_string).collect())
}

/// Loadable modules in sysfs: built-in ones have a directory too, but no
/// `initstate`.
fn sys_modules() -> Option<HashSet<String>> {
    let rd = std::fs::read_dir("/sys/module").ok()?;
    Some(
        rd.flatten()
            .filter(|e| e.path().join("initstate").exists())
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .collect(),
    )
}

fn hidden_modules() -> Vec<Finding> {
    let diff = || -> Option<(Vec<String>, Vec<String>)> {
        let (p, s) = (proc_modules()?, sys_modules()?);
        Some((s.difference(&p).cloned().collect(), p.difference(&s).cloned().collect()))
    };
    let Some((first_a, first_b)) = diff() else { return Vec::new() };
    if first_a.is_empty() && first_b.is_empty() {
        return Vec::new();
    }
    // A module loading or unloading between the two reads differs once;
    // a hidden one differs every time.
    std::thread::sleep(Duration::from_millis(500));
    let Some((again_a, again_b)) = diff() else { return Vec::new() };
    let mut out = Vec::new();
    for m in first_a.iter().filter(|m| again_a.contains(m)) {
        out.push(module_finding(m, "is loaded but missing from the module list (/proc/modules)"));
    }
    for m in first_b.iter().filter(|m| again_b.contains(m)) {
        out.push(module_finding(m, "is loaded but missing from /sys/module"));
    }
    out
}

fn module_finding(name: &str, how: &str) -> Finding {
    Finding {
        path: PathBuf::from(format!("/sys/module/{name}")),
        name: "Qlam.Rootkit.HiddenModule",
        detail: format!("kernel module {name} {how}"),
        severity: "malicious",
        pid: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_preload_entries() {
        assert_eq!(preload_entries("# comment\n/lib/libx.so  /lib/liby.so\n\n  /usr/lib/libz.so # why\n"),
                   ["/lib/libx.so", "/lib/liby.so", "/usr/lib/libz.so"]);
        assert!(preload_entries("# nothing\n\n").is_empty());
    }

    #[test]
    fn this_system_hides_nothing() {
        // Runs against the real machine: no false alarm on a clean system.
        // (As a normal user some processes can't be inspected; the checks
        // must still not invent anything.)
        let found: Vec<String> =
            hidden_processes().into_iter().chain(hidden_modules()).map(|f| f.detail).collect();
        assert!(found.is_empty(), "{found:?}");
    }
}
