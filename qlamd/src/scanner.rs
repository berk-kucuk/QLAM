//! On-demand scans, run as background jobs and reported over D-Bus.

use std::collections::HashMap;
use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::Scope;
use crate::engine::{archive, Severity};
use crate::guard::{Guard, Notice, Observation, Trigger};
use crate::persistence;
use crate::rootkit;
use crate::store::{now, ScanRecord};

/// On-demand scans look at bigger files than on-access does, but each file
/// is read into memory, so not much bigger.
const ONDEMAND_MAX_SIZE: u64 = 100 * 1024 * 1024;

pub struct User {
    pub uid: u32,
    pub name: String,
    pub home: PathBuf,
}

impl User {
    pub fn lookup(uid: u32) -> Option<User> {
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0 as libc::c_char; 16 * 1024];
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        let r = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut res) };
        if r != 0 || res.is_null() {
            return None;
        }
        let cstr = |p: *const libc::c_char| unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned();
        Some(User { uid, name: cstr(pw.pw_name), home: PathBuf::from(cstr(pw.pw_dir)) })
    }

    /// Localised XDG directory (e.g. "İndirilenler"), falling back to the
    /// English default.
    fn xdg_dir(&self, key: &str, default: &str) -> PathBuf {
        let conf = self.home.join(".config/user-dirs.dirs");
        if let Ok(text) = std::fs::read_to_string(conf) {
            for line in text.lines() {
                if let Some(v) = line.strip_prefix(key).and_then(|r| r.strip_prefix('=')) {
                    let v = v.trim().trim_matches('"');
                    let v = v.replacen("$HOME", &self.home.to_string_lossy(), 1);
                    // This file belongs to the user and is read by root, so
                    // it may only point INSIDE the user's own home. Anything
                    // else ("/root", another home, "/etc") falls back to the
                    // default instead of becoming a root scan target.
                    if v.starts_with('/') {
                        let cand = PathBuf::from(&v);
                        let home = std::fs::canonicalize(&self.home).unwrap_or_else(|_| self.home.clone());
                        if let Ok(real) = std::fs::canonicalize(&cand) {
                            if real.starts_with(&home) {
                                return real;
                            }
                        }
                    }
                }
            }
        }
        self.home.join(default)
    }

    /// Where a quick scan looks: where downloads land, where user-level
    /// malware installs itself, and the shared temp directories.
    pub fn quick_targets(&self) -> Vec<PathBuf> {
        let h = &self.home;
        vec![
            self.xdg_dir("XDG_DOWNLOAD_DIR", "Downloads"),
            self.xdg_dir("XDG_DESKTOP_DIR", "Desktop"),
            h.join(".local/bin"),
            h.join(".local/share/applications"),
            h.join(".config/autostart"),
            h.join(".config/systemd/user"),
            PathBuf::from("/tmp"),
            PathBuf::from("/var/tmp"),
            PathBuf::from("/dev/shm"),
        ]
    }
}

struct Progress {
    files: u64,
    detections: u64,
    suspicious: u64,
    errors: u64,
}

pub struct Scanner {
    guard: Arc<Guard>,
    /// Running jobs: id -> (owner uid, cancel flag).
    jobs: Mutex<HashMap<String, (u32, Arc<AtomicBool>)>>,
}

impl Scanner {
    pub fn new(guard: Arc<Guard>) -> Scanner {
        Scanner { guard, jobs: Mutex::new(HashMap::new()) }
    }

    /// Running job ids visible to `uid` (root sees all).
    pub fn running_for(&self, uid: u32) -> Vec<String> {
        let jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        jobs.iter().filter(|(_, (owner, _))| uid == 0 || *owner == uid).map(|(id, _)| id.clone()).collect()
    }

    /// Cancel a job owned by `uid` (root may cancel any).
    pub fn cancel(&self, id: &str, uid: u32) -> bool {
        match self.jobs.lock().unwrap_or_else(|p| p.into_inner()).get(id) {
            Some((owner, flag)) if uid == 0 || *owner == uid => {
                flag.store(true, Ordering::Relaxed);
                true
            }
            _ => false,
        }
    }

    /// Start a scan job. `targets` must already be authorised and resolved;
    /// `persistence_home` adds the persistence checks for that user.
    pub fn start(self: &Arc<Self>, user: User, kind: &str, targets: Vec<PathBuf>, scope: Scope, persistence_home: bool) -> String {
        let (rec, cancel) = self.register(&user, kind, &targets);
        let id = rec.id.clone();
        let me = self.clone();
        std::thread::Builder::new()
            .name(format!("scan-{}", &id[..8]))
            .spawn(move || me.run_job(rec, cancel, user, targets, scope, persistence_home))
            .expect("spawn scan thread");
        id
    }

    /// Run a scan job on the calling thread (scheduled scans, which run one
    /// user after another). Returns the finished record.
    pub fn run(&self, user: User, kind: &str, targets: Vec<PathBuf>, scope: Scope, persistence_home: bool) -> ScanRecord {
        let (rec, cancel) = self.register(&user, kind, &targets);
        self.run_job(rec, cancel, user, targets, scope, persistence_home)
    }

    /// Any scan running, whoever started it.
    pub fn busy(&self) -> bool {
        !self.jobs.lock().unwrap_or_else(|p| p.into_inner()).is_empty()
    }

    fn register(&self, user: &User, kind: &str, targets: &[PathBuf]) -> (ScanRecord, Arc<AtomicBool>) {
        let id = uuid::Uuid::new_v4().to_string();
        let cancel = Arc::new(AtomicBool::new(false));
        self.jobs.lock().unwrap_or_else(|p| p.into_inner()).insert(id.clone(), (user.uid, cancel.clone()));
        let rec = ScanRecord {
            id,
            uid: user.uid,
            kind: kind.into(),
            targets: targets.iter().map(|p| p.to_string_lossy().into_owned()).collect(),
            started: now(),
            finished: 0,
            files: 0,
            detections: 0,
            suspicious: 0,
            errors: 0,
            status: "running".into(),
        };
        self.guard.store.scan_save(&rec);
        (rec, cancel)
    }

    fn run_job(
        &self,
        mut rec: ScanRecord,
        cancel: Arc<AtomicBool>,
        user: User,
        targets: Vec<PathBuf>,
        scope: Scope,
        persistence_home: bool,
    ) -> ScanRecord {
        // The user asked for this scan, so it keeps going under load, but it
        // yields to everything else.
        crate::fsutil::lower_priority(crate::fsutil::IoPriority::Low, 10);
        let mut prog = Progress { files: 0, detections: 0, suspicious: 0, errors: 0 };
        if persistence_home {
            for f in persistence::check_home(&user.home, Some(&user.name)) {
                if self.guard.report_finding(&f.path, user.uid, f.name, &f.detail).is_some() {
                    prog.suspicious += 1;
                }
            }
            // System-wide signs of a rootkit concern everyone on the
            // computer, so each user's scan reports them to that user.
            for f in rootkit::check() {
                let o = Observation {
                    path: f.path,
                    uid: user.uid,
                    pid: f.pid,
                    kind: "rootkit",
                    engine: "rootkit",
                    name: f.name,
                    detail: &f.detail,
                    severity: f.severity,
                };
                if self.guard.report_observation(o).is_some() {
                    if f.severity == "malicious" {
                        prog.detections += 1;
                    } else {
                        prog.suspicious += 1;
                    }
                }
            }
        }
        let mut walker = Walker { scanner: self, id: &rec.id, scope: &scope, cancel: &cancel, buf: Vec::new(), last: Instant::now(), prog };
        for t in &targets {
            walker.walk(t);
        }
        let prog = walker.prog;

        rec.finished = now();
        rec.files = prog.files as i64;
        rec.detections = prog.detections as i64;
        rec.suspicious = prog.suspicious as i64;
        rec.errors = prog.errors as i64;
        rec.status = if cancel.load(Ordering::Relaxed) { "cancelled" } else { "finished" }.into();
        self.guard.store.scan_save(&rec);
        self.jobs.lock().unwrap_or_else(|p| p.into_inner()).remove(&rec.id);
        log::info!("scan {} ({}) {}: {} files, {} detections", rec.id, rec.kind, rec.status, rec.files, rec.detections);
        self.guard.notify(Notice::ScanFinished { id: rec.id.clone() });
        rec
    }
}

struct Walker<'a> {
    scanner: &'a Scanner,
    id: &'a str,
    scope: &'a Scope,
    cancel: &'a AtomicBool,
    buf: Vec<u8>,
    last: Instant,
    prog: Progress,
}

impl Walker<'_> {
    fn walk(&mut self, root: &Path) {
        // Iterative, and never following symlinks: a link into /etc or another
        // user's home must not extend the scan beyond what was authorised.
        let mut stack = vec![root.to_path_buf()];
        while let Some(path) = stack.pop() {
            if self.cancel.load(Ordering::Relaxed) {
                return;
            }
            if !self.scope.contains(&path) {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
            if meta.is_dir() {
                match std::fs::read_dir(&path) {
                    Ok(rd) => stack.extend(rd.flatten().map(|e| e.path())),
                    Err(_) => self.prog.errors += 1,
                }
            } else if meta.is_file() && meta.size() > 0 {
                self.scan_file(&path);
            }
        }
    }

    fn scan_file(&mut self, path: &Path) {
        // O_NONBLOCK: a FIFO swapped in after the lstat must not hang the scan.
        let file = match File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(path)
        {
            Ok(f) => f,
            Err(_) => {
                self.prog.errors += 1;
                return;
            }
        };
        if !file.metadata().is_ok_and(|m| m.is_file()) {
            return;
        }
        self.prog.files += 1;
        let guard = &self.scanner.guard;
        match guard.engine.scan_fd(file.as_fd(), path, ONDEMAND_MAX_SIZE, Some(&archive::Limits::ON_DEMAND), &mut self.buf) {
            Ok(v) if v.severity != Severity::Clean => {
                if v.is_malicious() {
                    self.prog.detections += 1;
                } else {
                    self.prog.suspicious += 1;
                }
                guard.handle(file.as_fd(), path, &v, Trigger::Scan);
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::FileTooLarge => {}
            Err(_) => self.prog.errors += 1,
        }
        crate::fsutil::trim_buffer(&mut self.buf);
        if self.last.elapsed() >= Duration::from_millis(250) {
            self.last = Instant::now();
            guard.notify(Notice::ScanProgress {
                id: self.id.to_string(),
                files: self.prog.files,
                detections: self.prog.detections,
            });
        }
    }
}
