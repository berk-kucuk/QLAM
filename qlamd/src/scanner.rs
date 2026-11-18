//! On-demand scans, run as background jobs and reported over D-Bus.

use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
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

/// What [`walk_fds`] hands to its caller.
enum Visit<'p> {
    /// A regular, non-empty file, already open (no symlink followed to it).
    File(File, &'p Path),
    /// Something under the root could not be listed or opened.
    Error,
}

/// Walk `root` by file descriptor, never by path.
///
/// The daemon runs as root and a user may ask it to scan their own tree.
/// Opening `a/b/c` by its full path resolves `a` and `b` again at every step,
/// so swapping `a` for a symlink to `/root` while the scan runs walked root's
/// files on the user's behalf (O_NOFOLLOW only guards the LAST component).
/// Here the root is opened with no symlink anywhere on its path (openat2
/// RESOLVE_NO_SYMLINKS), and every entry below it relative to its parent's
/// open descriptor with O_NOFOLLOW: once a directory is open, renaming or
/// replacing anything above it changes nothing about what is read. Symlinks
/// are never followed. Entries are visited in name order.
fn walk_fds(root: &Path, cancel: &AtomicBool, keep: &dyn Fn(&Path) -> bool,
            visit: &mut dyn FnMut(Visit<'_>)) {
    if !keep(root) {
        return;
    }
    let dir = match open_root(root, libc::O_RDONLY | libc::O_DIRECTORY) {
        Ok(fd) => fd,
        Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => {
            // A single file was asked for.
            match open_root(root, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY) {
                Ok(fd) => {
                    let file = File::from(fd);
                    if file.metadata().is_ok_and(|m| m.is_file() && m.len() > 0) {
                        visit(Visit::File(file, root));
                    }
                }
                Err(_) => visit(Visit::Error),
            }
            return;
        }
        Err(_) => {
            visit(Visit::Error);
            return;
        }
    };
    let mut stack: Vec<(Rc<OwnedFd>, OsString, PathBuf)> = Vec::new();
    push_entries(Rc::new(dir), root, &mut stack, visit);
    while let Some((parent, name, path)) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        if !keep(&path) {
            continue;
        }
        let Ok(st) = fstatat_nofollow(&parent, &name) else { continue };
        match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => match openat_nofollow(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY) {
                Ok(fd) => push_entries(Rc::new(fd), &path, &mut stack, visit),
                Err(_) => visit(Visit::Error),
            },
            libc::S_IFREG if st.st_size > 0 => {
                // O_NONBLOCK: a FIFO swapped in after the stat must not hang the scan.
                match openat_nofollow(&parent, &name, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY) {
                    Ok(fd) => visit(Visit::File(File::from(fd), &path)),
                    Err(_) => visit(Visit::Error),
                }
            }
            _ => {}
        }
    }
}

/// Queue a directory's entries, in reverse name order so they pop in order.
fn push_entries(dir: Rc<OwnedFd>, path: &Path, stack: &mut Vec<(Rc<OwnedFd>, OsString, PathBuf)>,
                visit: &mut dyn FnMut(Visit<'_>)) {
    match list_dir(&dir) {
        Ok(mut names) => {
            names.sort();
            for name in names.into_iter().rev() {
                let child = path.join(&name);
                stack.push((Rc::clone(&dir), name, child));
            }
        }
        Err(_) => visit(Visit::Error),
    }
}

fn cstring(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

/// Open with no symlink anywhere on the path (openat2, Linux 5.6+).
fn open_root(path: &Path, flags: i32) -> io::Result<OwnedFd> {
    let c = cstring(path.as_os_str().as_bytes())?;
    // SAFETY: open_how is plain data; all-zero is a valid "no options" value.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (flags | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_NO_SYMLINKS;
    // SAFETY: c and how outlive the call; the size matches the struct passed.
    let fd = unsafe {
        libc::syscall(libc::SYS_openat2, libc::AT_FDCWD, c.as_ptr(), &how as *const libc::open_how,
                      std::mem::size_of::<libc::open_how>())
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel just returned this descriptor; nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn openat_nofollow(dir: &OwnedFd, name: &OsStr, flags: i32) -> io::Result<OwnedFd> {
    let c = cstring(name.as_bytes())?;
    // SAFETY: dir is an open descriptor, c a NUL-terminated name.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel just returned this descriptor; nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fstatat_nofollow(dir: &OwnedFd, name: &OsStr) -> io::Result<libc::stat> {
    let c = cstring(name.as_bytes())?;
    // SAFETY: zeroed stat is valid storage for the kernel to fill.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: dir is open, c NUL-terminated, st writable.
    if unsafe { libc::fstatat(dir.as_raw_fd(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

/// The names in an open directory (not "." or "..").
fn list_dir(dir: &OwnedFd) -> io::Result<Vec<OsString>> {
    // fdopendir takes ownership of the descriptor it gets: give it a duplicate.
    // SAFETY: dir is an open descriptor.
    let dup = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: dup is a fresh descriptor this function owns.
    let d = unsafe { libc::fdopendir(dup) };
    if d.is_null() {
        let e = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so dup is still ours to close.
        unsafe { libc::close(dup) };
        return Err(e);
    }
    let mut names = Vec::new();
    let result = loop {
        // SAFETY: errno is thread-local; reset it to tell end-of-directory from an error.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: d is a valid DIR* until closedir below.
        let ent = unsafe { libc::readdir(d) };
        if ent.is_null() {
            let e = io::Error::last_os_error();
            break if e.raw_os_error() == Some(0) { Ok(()) } else { Err(e) };
        }
        // SAFETY: d_name is NUL-terminated within the entry readdir returned.
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(OsStr::from_bytes(name).to_os_string());
        }
    };
    // SAFETY: d came from fdopendir and is closed exactly once.
    unsafe { libc::closedir(d) };
    result.map(|()| names)
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
        let (scope, cancel) = (self.scope, self.cancel);
        walk_fds(root, cancel, &|p: &Path| scope.contains(p), &mut |visit| match visit {
            Visit::File(file, path) => self.scan_open(file, path),
            Visit::Error => self.prog.errors += 1,
        });
    }

    fn scan_open(&mut self, file: File, path: &Path) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("qlam-walk-{tag}-{}-{}", std::process::id(),
                                                       now()));
            fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Every path walk_fds hands over, and the contents it can read through
    /// the descriptor — what a scan would actually see.
    fn walk(root: &Path, mut on_file: impl FnMut(&Path)) -> (Vec<(PathBuf, String)>, u64) {
        let cancel = AtomicBool::new(false);
        let mut seen = Vec::new();
        let mut errors = 0;
        walk_fds(root, &cancel, &|_| true, &mut |v| match v {
            Visit::File(mut f, p) => {
                let mut s = String::new();
                io::Read::read_to_string(&mut f, &mut s).unwrap();
                seen.push((p.to_path_buf(), s));
                on_file(p);
            }
            Visit::Error => errors += 1,
        });
        (seen, errors)
    }

    #[test]
    fn a_directory_swapped_for_a_symlink_mid_scan_is_not_followed() {
        // root/a/0.txt is scanned first (name order). At that moment root/a is
        // renamed and replaced by a link to `outside`; root/a/inner is still
        // to come. Opened relative to a's descriptor it is the real inner;
        // opened by path ("root/a/inner") it would be outside/inner.
        let t = TempDir::new("swap");
        let (root, outside) = (t.0.join("root"), t.0.join("outside"));
        fs::create_dir_all(root.join("a/inner")).unwrap();
        fs::write(root.join("a/0.txt"), "first").unwrap();
        fs::write(root.join("a/inner/mine.txt"), "mine").unwrap();
        fs::create_dir_all(outside.join("inner")).unwrap();
        fs::write(outside.join("inner/secret.txt"), "SECRET").unwrap();
        let mut swapped = false;
        let (seen, _) = walk(&root, |p| {
            if !swapped && p.ends_with("a/0.txt") {
                fs::rename(root.join("a"), root.join("a_real")).unwrap();
                symlink(&outside, root.join("a")).unwrap();
                swapped = true;
            }
        });
        assert!(swapped);
        assert!(seen.iter().all(|(_, s)| s != "SECRET"), "read outside the authorised tree: {seen:?}");
        assert!(seen.iter().any(|(_, s)| s == "mine"));
    }

    #[test]
    fn symlinks_inside_the_tree_are_never_followed() {
        let t = TempDir::new("links");
        let (root, outside) = (t.0.join("root"), t.0.join("outside"));
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.txt"), "SECRET").unwrap();
        fs::write(root.join("ok.txt"), "ok").unwrap();
        symlink(&outside, root.join("dirlink")).unwrap();
        symlink(outside.join("secret.txt"), root.join("filelink")).unwrap();
        let (seen, _) = walk(&root, |_| {});
        let texts: Vec<&str> = seen.iter().map(|(_, s)| s.as_str()).collect();
        assert_eq!(texts, ["ok"]);
    }

    #[test]
    fn a_root_reached_through_a_symlink_is_refused() {
        let t = TempDir::new("root");
        let real = t.0.join("real");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("f.txt"), "x").unwrap();
        symlink(&real, t.0.join("link")).unwrap();
        let (seen, errors) = walk(&t.0.join("link/."), |_| {});
        assert!(seen.is_empty());
        assert_eq!(errors, 1);
    }

    #[test]
    fn plain_trees_and_single_files_are_scanned() {
        let t = TempDir::new("plain");
        fs::create_dir_all(t.0.join("d/e")).unwrap();
        fs::write(t.0.join("d/e/f.txt"), "f").unwrap();
        fs::write(t.0.join("d/g.txt"), "g").unwrap();
        fs::write(t.0.join("d/empty"), "").unwrap();
        let (seen, errors) = walk(&t.0.join("d"), |_| {});
        let texts: Vec<&str> = seen.iter().map(|(_, s)| s.as_str()).collect();
        assert_eq!((texts, errors), (vec!["f", "g"], 0));
        let (one, _) = walk(&t.0.join("d/g.txt"), |_| {});
        assert_eq!(one.len(), 1);
    }
}
