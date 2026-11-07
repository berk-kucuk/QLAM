//! Scheduled scans.
//!
//! Real-time protection only sees files as they are written or run; a
//! scheduled scan also catches what arrived while it was off, and what the
//! signatures learned to recognise since. The default is a weekly quick scan
//! of every user (downloads, desktop, startup entries, temp folders, and the
//! persistence checks), which takes seconds to minutes.
//!
//! The daemon decides when, not a systemd timer: it already knows whether a
//! scan is running and owns the scan history users see. A due scan waits
//! until the system has been up for a while, no other scan is running, and
//! the computer is on mains power — unless it is a full period overdue, so a
//! laptop that never sits on its charger still gets scanned.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::daemon::Daemon;
use crate::scanner::User;
use crate::store::now;

const TICK: Duration = Duration::from_secs(5 * 60);
/// Leave the start of a session to the user.
const SETTLE: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Frequency {
    Off,
    Daily,
    Weekly,
}

impl Frequency {
    pub fn parse(s: &str) -> Option<Frequency> {
        match s {
            "off" => Some(Frequency::Off),
            "daily" => Some(Frequency::Daily),
            "weekly" => Some(Frequency::Weekly),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Frequency::Off => "off",
            Frequency::Daily => "daily",
            Frequency::Weekly => "weekly",
        }
    }

    fn period(self) -> Option<i64> {
        match self {
            Frequency::Off => None,
            Frequency::Daily => Some(24 * 3600),
            Frequency::Weekly => Some(7 * 24 * 3600),
        }
    }
}

/// What a scheduled scan covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Depth {
    Quick,
    Home,
}

impl Depth {
    pub fn parse(s: &str) -> Option<Depth> {
        match s {
            "quick" => Some(Depth::Quick),
            "home" => Some(Depth::Home),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Depth::Quick => "quick",
            Depth::Home => "home",
        }
    }
}

/// For the app: the schedule and when it runs.
#[derive(Debug, Serialize)]
pub struct ScheduleStatus {
    pub frequency: Frequency,
    pub depth: Depth,
    pub last: i64,
    /// 0 when off.
    pub next: i64,
}

const LAST_KEY: &str = "schedule_last";

pub fn status(d: &Daemon) -> ScheduleStatus {
    let cfg = d.config();
    let last = last_run(d);
    let next = match cfg.scheduled_scan.period() {
        None => 0,
        Some(p) => (last + p).max(d.started_at + SETTLE.as_secs() as i64),
    };
    ScheduleStatus { frequency: cfg.scheduled_scan, depth: cfg.scheduled_scan_depth, last, next }
}

fn last_run(d: &Daemon) -> i64 {
    match d.guard.store.setting(LAST_KEY).and_then(|v| v.parse().ok()) {
        Some(t) => t,
        None => {
            // First start: count from now, rather than scanning everyone the
            // moment Qlam is installed.
            let t = now();
            d.guard.store.set_setting(LAST_KEY, &t.to_string());
            t
        }
    }
}

pub fn spawn(d: Arc<Daemon>) {
    std::thread::Builder::new()
        .name("schedule".into())
        .spawn(move || {
            let started = Instant::now();
            loop {
                std::thread::sleep(TICK);
                if started.elapsed() < SETTLE {
                    continue;
                }
                let cfg = d.config();
                let Some(period) = cfg.scheduled_scan.period() else { continue };
                let overdue = now() - last_run(&d);
                if overdue < period || d.scanner.busy() {
                    continue;
                }
                if on_battery() && overdue < 2 * period {
                    continue;
                }
                run(&d, cfg.scheduled_scan_depth);
            }
        })
        .expect("spawn scheduler");
}

/// Scan every regular user, one after another.
fn run(d: &Daemon, depth: Depth) {
    // Recorded first: a scan that crashes the daemon must not run again on
    // every restart.
    d.guard.store.set_setting(LAST_KEY, &now().to_string());
    let users = regular_users();
    log::info!("scheduled {} scan of {} user(s)", depth.as_str(), users.len());
    let scope = d.scope();
    let mut shared_done = false;
    for user in users {
        let mut targets = match depth {
            Depth::Quick => user.quick_targets(),
            Depth::Home => vec![user.home.clone()],
        };
        // /tmp, /var/tmp and /dev/shm are everyone's: scan them once.
        let shared = |p: &PathBuf| !p.starts_with(&user.home);
        if shared_done {
            targets.retain(|p| !shared(p));
        }
        shared_done |= targets.iter().any(shared);
        // Same rule as an interactive scan: only what's in scope, and of a
        // home only the user's own (user-dirs.dirs is theirs to edit).
        let targets: Vec<PathBuf> = targets
            .iter()
            .filter_map(|t| std::fs::canonicalize(t).ok())
            .filter(|t| scope.contains(t))
            .filter(|t| crate::daemon::home_owner(t).is_none_or(|o| o == user.uid))
            .collect();
        d.scanner.run(user, "scheduled", targets, scope.clone(), true);
    }
}

/// Accounts that log in: uid in the regular range, a home directory that
/// exists, a real shell.
fn regular_users() -> Vec<User> {
    let mut out = Vec::new();
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    unsafe { libc::setpwent() };
    loop {
        let r = unsafe { libc::getpwent_r(&mut pw, buf.as_mut_ptr(), buf.len(), &mut res) };
        if r != 0 || res.is_null() {
            break;
        }
        let shell = unsafe { std::ffi::CStr::from_ptr(pw.pw_shell) }.to_string_lossy();
        if !(1000..60000).contains(&pw.pw_uid) || shell.ends_with("nologin") || shell.ends_with("/false") {
            continue;
        }
        if let Some(user) = User::lookup(pw.pw_uid).filter(|u| u.home.is_dir()) {
            if !out.iter().any(|u: &User| u.uid == user.uid) {
                out.push(user);
            }
        }
    }
    unsafe { libc::endpwent() };
    out
}

/// True when the machine runs on battery: it has a mains supply and none is
/// online. Desktops (no mains supply listed) count as plugged in.
pub fn on_battery() -> bool {
    let Ok(dir) = std::fs::read_dir("/sys/class/power_supply") else { return false };
    let mut mains = false;
    for entry in dir.flatten() {
        let p = entry.path();
        if std::fs::read_to_string(p.join("type")).is_ok_and(|t| t.trim() == "Mains") {
            mains = true;
            if std::fs::read_to_string(p.join("online")).is_ok_and(|o| o.trim() == "1") {
                return false;
            }
        }
    }
    mains
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_settings() {
        for f in [Frequency::Off, Frequency::Daily, Frequency::Weekly] {
            assert_eq!(Frequency::parse(f.as_str()), Some(f));
        }
        for d in [Depth::Quick, Depth::Home] {
            assert_eq!(Depth::parse(d.as_str()), Some(d));
        }
        assert_eq!(Frequency::parse("hourly"), None);
        assert_eq!(Depth::parse("everything"), None);
    }

    #[test]
    fn finds_this_user() {
        // Whoever runs the tests is a regular user unless it's root or CI.
        let uid = unsafe { libc::getuid() };
        if (1000..60000).contains(&uid) {
            assert!(regular_users().iter().any(|u| u.uid == uid));
        }
    }
}
