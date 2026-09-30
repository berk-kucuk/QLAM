//! What happens after a detection, shared by on-access and on-demand scanning.
//!
//! Qlam's policy is warn first. The only automatic actions are:
//!   - denying execution of a *confirmed* detection (an exact known-malware
//!     hash), which changes nothing on disk;
//!   - quarantining confirmed detections, only if the admin turned
//!     auto-quarantine on (off by default).
//!
//! Everything else — pattern matches, heuristics, persistence findings — is a
//! warning, and the user decides: quarantine it, or trust it.
//!
//! On top of that, a safety brake: if automatic actions suddenly spike (a bad
//! signature update is the likely cause, not an outbreak on a desktop), they
//! pause and the user is told, instead of Qlam blocking half the system.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;

use crate::engine::{Engine, Severity, Verdict};
use crate::fsutil;
use crate::quarantine;
use crate::store::{now, Event, Store};

/// More automatic actions than this within `BRAKE_WINDOW` pauses them.
const BRAKE_LIMIT: usize = 10;
const BRAKE_WINDOW: Duration = Duration::from_secs(10 * 60);
const BRAKE_PAUSE: Duration = Duration::from_secs(60 * 60);

/// Messages for the D-Bus side to turn into signals.
#[derive(Debug, Clone)]
pub enum Notice {
    Threat(Event),
    StatusChanged,
    ScanProgress { id: String, files: u64, detections: u64 },
    ScanFinished { id: String },
}

#[derive(Debug, Clone, Copy)]
pub enum Trigger {
    /// Execution was attempted; `blocked` says whether we denied it.
    Exec { pid: i32, blocked: bool },
    /// File was just written.
    Write { pid: i32 },
    /// On-demand scan.
    Scan,
}

#[derive(Default)]
struct Brake {
    recent: VecDeque<Instant>,
    paused_until: Option<Instant>,
}

pub struct Guard {
    pub engine: Engine,
    pub store: Arc<Store>,
    pub notices: Sender<Notice>,
    pub auto_quarantine: AtomicBool,
    brake: Mutex<Brake>,
    /// Hashes already reported by on-access scanning, so a file that is run
    /// or rewritten repeatedly produces one alert, not one per access.
    reported: Mutex<HashMap<String, u64>>,
}

impl Guard {
    pub fn new(engine: Engine, store: Arc<Store>, notices: Sender<Notice>, auto_quarantine: bool) -> Guard {
        Guard {
            engine,
            store,
            notices,
            auto_quarantine: AtomicBool::new(auto_quarantine),
            brake: Mutex::new(Brake::default()),
            reported: Mutex::new(HashMap::new()),
        }
    }

    pub fn notify(&self, n: Notice) {
        let _ = self.notices.try_send(n);
    }

    // ── Safety brake ─────────────────────────────────────────────────────

    /// Whether automatic actions are currently allowed.
    pub fn may_act(&self) -> bool {
        let mut b = self.brake.lock().unwrap_or_else(|p| p.into_inner());
        match b.paused_until {
            Some(t) if Instant::now() < t => false,
            Some(_) => {
                b.paused_until = None;
                b.recent.clear();
                true
            }
            None => true,
        }
    }

    pub fn actions_paused(&self) -> bool {
        !self.may_act()
    }

    /// Count an automatic action; trips the brake when they spike.
    pub fn record_action(&self) {
        let tripped = {
            let mut b = self.brake.lock().unwrap_or_else(|p| p.into_inner());
            let now = Instant::now();
            b.recent.push_back(now);
            while b.recent.front().is_some_and(|t| now.duration_since(*t) > BRAKE_WINDOW) {
                b.recent.pop_front();
            }
            if b.recent.len() > BRAKE_LIMIT && b.paused_until.is_none() {
                b.paused_until = Some(now + BRAKE_PAUSE);
                true
            } else {
                false
            }
        };
        if tripped {
            log::error!("unusually many automatic actions; pausing them for an hour");
            let mut ev = Event {
                ts: now(),
                kind: "safety-pause".into(),
                severity: "info".into(),
                detection: "Qlam.SafetyPause".into(),
                action: "Automatic blocking paused for 1 hour after an unusual number of detections. \
                         Detections are still reported. This usually means a faulty signature update."
                    .into(),
                ..Default::default()
            };
            ev.id = self.store.add_event(&ev);
            self.notify(Notice::Threat(ev));
            self.notify(Notice::StatusChanged);
        }
    }

    // ── Detections ───────────────────────────────────────────────────────

    /// Record (and, for confirmed detections, act on) a non-clean verdict for
    /// the file open on `fd`.
    pub fn handle(&self, fd: BorrowedFd<'_>, path: &Path, verdict: &Verdict, trigger: Trigger) -> Option<Event> {
        if verdict.severity == Severity::Clean {
            return None;
        }
        if !matches!(trigger, Trigger::Scan) && !self.first_report(&verdict.sha256) {
            return None;
        }

        let (pid, blocked) = match trigger {
            Trigger::Exec { pid, blocked } => (pid, blocked),
            Trigger::Write { pid } => (pid, false),
            Trigger::Scan => (0, false),
        };
        let mut ev = Event {
            ts: now(),
            path: path.to_string_lossy().into_owned(),
            uid: fsutil::fstat(fd).map(|s| s.st_uid).unwrap_or(0),
            severity: if verdict.is_malicious() { "malicious" } else { "suspicious" }.into(),
            confirmed: verdict.is_confirmed(),
            detection: verdict.name.clone(),
            engine: verdict.engine.clone(),
            sha256: verdict.sha256.clone(),
            process: fsutil::process_label(pid),
            ..Default::default()
        };
        // Attribute exec attempts to the user who ran it, when that's not root.
        if let Trigger::Exec { pid, .. } = trigger {
            if let Some(uid) = fsutil::process_uid(pid).filter(|u| *u != 0) {
                ev.uid = uid;
            }
        }

        let mut action = Vec::new();
        if blocked {
            action.push("execution blocked".to_string());
        }
        let auto_q = verdict.is_confirmed() && self.auto_quarantine.load(Ordering::Relaxed) && self.may_act();
        if auto_q {
            self.record_action();
            match quarantine::quarantine(&self.store, fd, path, verdict, &verdict.sha256) {
                Ok(_) => {
                    action.push("moved to quarantine".into());
                    ev.kind = "quarantined".into();
                    ev.resolution = "quarantined".into();
                }
                Err(e) => {
                    action.push(format!("could not be quarantined ({e}); the file was left as it was"));
                    ev.kind = "warning".into();
                }
            }
        } else {
            action.push("no changes made; review in Qlam".into());
            ev.kind = if blocked {
                "blocked"
            } else if verdict.is_malicious() {
                "warning"
            } else {
                "suspicious"
            }
            .into();
        }
        if blocked && ev.kind == "quarantined" {
            ev.kind = "blocked".into();
        }
        ev.action = action.join(", ");

        log::warn!("{}: {} [{}] -> {}", ev.path, ev.detection, ev.engine, ev.action);
        ev.id = self.store.add_event(&ev);
        self.notify(Notice::Threat(ev.clone()));
        Some(ev)
    }

    /// Record a finding that isn't about a file's content, e.g. a persistence
    /// entry in a config file. Always a warning; skipped if the user already
    /// said to trust it.
    pub fn report_finding(&self, path: &Path, uid: u32, name: &str, detail: &str) -> Option<Event> {
        let path_s = path.to_string_lossy().into_owned();
        if self.store.is_allowlisted(&finding_key(&path_s, name)) {
            return None;
        }
        let mut ev = Event {
            ts: now(),
            kind: "persistence".into(),
            path: path_s,
            uid,
            severity: "suspicious".into(),
            detection: name.into(),
            engine: "persistence".into(),
            action: format!("no changes made: {detail}"),
            ..Default::default()
        };
        log::warn!("{}: {} ({detail})", ev.path, ev.detection);
        ev.id = self.store.add_event(&ev);
        self.notify(Notice::Threat(ev.clone()));
        Some(ev)
    }

    // ── User decisions ───────────────────────────────────────────────────

    /// Quarantine the file an event is about, at the user's request. The file
    /// must still have the content that was detected: whatever sits at that
    /// path now may be something else entirely.
    pub fn quarantine_event(&self, ev: &Event) -> io::Result<()> {
        if ev.sha256.is_empty() {
            return Err(io::Error::other("this finding is not about a file's content"));
        }
        let file = File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(&ev.path)?;
        // Content is checked against ev.sha256 by quarantine() itself, on the
        // very bytes it stores.
        let verdict = Verdict {
            severity: if ev.severity == "malicious" { Severity::Malicious } else { Severity::Suspicious },
            confirmed: ev.confirmed,
            name: ev.detection.clone(),
            engine: ev.engine.clone(),
            sha256: ev.sha256.clone(),
        };
        quarantine::quarantine(&self.store, file.as_fd(), Path::new(&ev.path), &verdict, &ev.sha256)?;
        self.store.resolve(ev, "quarantined");
        let mut done = ev.clone();
        done.ts = now();
        done.kind = "quarantined".into();
        done.resolution = "quarantined".into();
        done.action = "moved to quarantine at the user's request".into();
        done.id = self.store.add_event(&done);
        self.notify(Notice::Threat(done));
        Ok(())
    }

    /// "I trust this": never flag this content (or this persistence entry)
    /// again.
    pub fn trust_event(&self, ev: &Event) {
        let key = if ev.sha256.is_empty() { finding_key(&ev.path, &ev.detection) } else { ev.sha256.clone() };
        self.store.allowlist_add(&key, &format!("trusted by user: {} ({})", ev.path, ev.detection));
        self.store.resolve(ev, "trusted");
        self.notify(Notice::StatusChanged);
        self.reported.lock().unwrap_or_else(|p| p.into_inner()).remove(&ev.sha256);
    }

    fn first_report(&self, sha256: &str) -> bool {
        let generation = self.engine.signatures().generation;
        let mut r = self.reported.lock().unwrap_or_else(|p| p.into_inner());
        if r.len() > 10_000 {
            r.clear();
        }
        r.insert(sha256.to_string(), generation) != Some(generation)
    }
}

/// Allowlist key for a content-less finding.
fn finding_key(path: &str, name: &str) -> String {
    format!("finding:{name}:{path}")
}
