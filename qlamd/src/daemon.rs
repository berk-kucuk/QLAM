//! Daemon state shared between the D-Bus service and the workers.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde_json::json;

use crate::config::{feeds_dir, Config, Scope};
use crate::guard::{Guard, Notice};
use crate::realtime::Realtime;
use crate::scanner::Scanner;
use crate::store::now;
use crate::updater::{FeedState, STATE_FILE};

pub struct Daemon {
    /// Development instance on the session bus: no real-time protection.
    pub session: bool,
    cfg: Mutex<Config>,
    pub guard: Arc<Guard>,
    pub scanner: Arc<Scanner>,
    realtime: Mutex<Option<Realtime>>,
    realtime_error: Mutex<String>,
}

/// Runtime overrides persisted in the settings table.
const BOOL_SETTINGS: &[&str] = &["realtime", "block_exec", "auto_quarantine"];

impl Daemon {
    pub fn new(mut cfg: Config, guard: Arc<Guard>, session: bool) -> Arc<Daemon> {
        for key in BOOL_SETTINGS {
            if let Some(v) = guard.store.setting(key).and_then(|v| v.parse::<bool>().ok()) {
                set_cfg_bool(&mut cfg, key, v);
            }
        }
        if session {
            cfg.realtime = false;
        }
        guard.auto_quarantine.store(cfg.auto_quarantine, Ordering::Relaxed);
        Arc::new(Daemon {
            session,
            scanner: Arc::new(Scanner::new(guard.clone())),
            guard,
            cfg: Mutex::new(cfg),
            realtime: Mutex::new(None),
            realtime_error: Mutex::new(String::new()),
        })
    }

    pub fn config(&self) -> Config {
        self.cfg.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn scope(&self) -> Scope {
        Scope::new(&self.config())
    }

    /// Start or stop on-access protection to match the configuration.
    pub fn apply_realtime(&self) {
        let cfg = self.config();
        let mut rt = self.realtime.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(r) = rt.take() {
            r.stop();
        }
        let mut err = self.realtime_error.lock().unwrap_or_else(|p| p.into_inner());
        err.clear();
        if cfg.realtime {
            match Realtime::start(&cfg, self.guard.clone()) {
                Ok(r) => *rt = Some(r),
                Err(e) => {
                    log::error!("real-time protection failed to start: {e}");
                    *err = e.to_string();
                }
            }
        }
        drop((rt, err));
        self.guard.notify(Notice::StatusChanged);
    }

    pub fn set_option(&self, key: &str, value: bool) -> Result<(), String> {
        if !BOOL_SETTINGS.contains(&key) {
            return Err(format!("unknown option {key}"));
        }
        if self.session && key == "realtime" && value {
            return Err("real-time protection needs the system service".into());
        }
        {
            let mut cfg = self.cfg.lock().unwrap_or_else(|p| p.into_inner());
            set_cfg_bool(&mut cfg, key, value);
        }
        self.guard.store.set_setting(key, &value.to_string());
        log::info!("option {key} = {value}");
        match key {
            "auto_quarantine" => {
                self.guard.auto_quarantine.store(value, Ordering::Relaxed);
                self.guard.notify(Notice::StatusChanged);
            }
            _ => self.apply_realtime(),
        }
        Ok(())
    }

    pub fn stop(&self) {
        if let Some(r) = self.realtime.lock().unwrap_or_else(|p| p.into_inner()).take() {
            r.stop();
        }
    }

    /// Close findings whose file no longer exists: a temporary file that was
    /// deleted, a download the user removed. Nothing is left to decide about,
    /// and keeping them "open" would only nag. Cheap: one lstat per open
    /// finding, and there are few.
    pub fn sweep_gone(&self) {
        let store = &self.guard.store;
        for path in store.open_paths() {
            let gone = matches!(std::fs::symlink_metadata(&path), Err(e) if e.kind() == std::io::ErrorKind::NotFound);
            if gone {
                store.resolve_path(&path, "gone");
            }
        }
    }

    pub fn status_json(&self, uid: u32) -> String {
        self.sweep_gone();
        let cfg = self.config();
        let user = (uid != 0).then_some(uid);
        let store = &self.guard.store;
        let sigs = self.guard.engine.signatures();
        let rt = self.realtime.lock().unwrap_or_else(|p| p.into_inner());
        let stats = rt.as_ref().map(|r| {
            json!({
                "exec_checked": r.stats.exec_checked.load(Ordering::Relaxed),
                "exec_blocked": r.stats.exec_blocked.load(Ordering::Relaxed),
                "exec_overflow": r.stats.exec_overflow.load(Ordering::Relaxed),
                "writes_scanned": r.stats.writes_scanned.load(Ordering::Relaxed),
                "writes_dropped": r.stats.dropped.load(Ordering::Relaxed),
            })
        });
        let last_scan = store.scans(user, 1).into_iter().next();
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "session": self.session,
            "realtime": {
                "enabled": cfg.realtime,
                "active": rt.is_some(),
                "error": *self.realtime_error.lock().unwrap_or_else(|p| p.into_inner()),
                "block_exec": cfg.block_exec,
                "auto_quarantine": cfg.auto_quarantine,
                "actions_paused": self.guard.actions_paused(),
                "stats": stats,
            },
            "engines": {
                "hashes": sigs.hashes.len(),
                "yara_rules": sigs.yara.len(),
                "clamav": self.guard.engine.clamd_available(),
            },
            "feeds": FeedState::load(),
            "user": {
                "uid": uid,
                "threats_30d": store.threat_count(user, now() - 30 * 24 * 3600),
                "open_findings": store.open_count(user),
                "quarantined": store.quarantine_list(user).len(),
                "last_scan": last_scan,
                "running_scans": self.scanner.running_for(uid),
            },
            "scope": cfg.scope,
        })
        .to_string()
    }

    /// Reload signatures whenever the updater publishes a new state.json.
    pub fn watch_feeds(self: &Arc<Self>) {
        let me = self.clone();
        std::thread::Builder::new()
            .name("feed-watch".into())
            .spawn(move || {
                let path = feeds_dir().join(STATE_FILE);
                let mut last = mtime(&path);
                loop {
                    std::thread::sleep(Duration::from_secs(30));
                    let m = mtime(&path);
                    if m != last {
                        last = m;
                        log::info!("feeds changed; reloading signatures");
                        me.guard.engine.reload();
                        me.guard.notify(Notice::StatusChanged);
                    }
                }
            })
            .expect("spawn feed watcher");
    }
}

fn set_cfg_bool(cfg: &mut Config, key: &str, v: bool) {
    match key {
        "realtime" => cfg.realtime = v,
        "block_exec" => cfg.block_exec = v,
        "auto_quarantine" => cfg.auto_quarantine = v,
        _ => {}
    }
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// The uid owning the home directory `path` lies in (/home/<name>/... or
/// /root/...), if it lies in one.
pub fn home_owner(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let mut comps = path.components();
    comps.next()?; // "/"
    let top = comps.next()?.as_os_str().to_str()?;
    let home: PathBuf = match top {
        "root" => PathBuf::from("/root"),
        "home" => Path::new("/home").join(comps.next()?.as_os_str()),
        _ => return None,
    };
    std::fs::metadata(home).ok().map(|m| m.uid())
}
