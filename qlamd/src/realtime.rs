//! On-access protection with fanotify.
//!
//! Two event types, on every filesystem that holds a scope location:
//!   - FAN_OPEN_EXEC_PERM: the kernel holds an exec until we answer. Only
//!     confirmed detections (exact known-malware hashes) are ever denied;
//!     everything else is allowed and, if it matched a pattern, reported.
//!   - FAN_CLOSE_WRITE: a file was just written (a finished download, an
//!     extracted archive, a dropped script). Scanned in the background so the
//!     user is warned before anyone runs it. Scripts need this path:
//!     `bash x.sh` opens x.sh as data, it is never exec'd.
//!
//! Marks are per filesystem, so events for system paths arrive too; those are
//! answered immediately after a path-prefix check. Anything that goes wrong
//! answers "allow": an antivirus that wedges every exec on the machine is
//! worse than one that misses a file. A watchdog allows any exec left
//! unanswered past a short deadline, and if the daemon dies the kernel
//! releases pending events on its own.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::fmt::Display;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, unbounded, Receiver, Sender, TrySendError};

use crate::config::{Config, Scope};
use crate::engine::{Severity, Verdict};
use crate::fsutil;
use crate::guard::{Guard, Trigger};
use crate::supervise::{fatal, spawn_critical};

/// Filesystems never marked: pseudo filesystems, and FUSE (root usually
/// can't read other users' FUSE mounts, and blocking exec on a FUSE mount
/// whose server is the process being exec'd can deadlock).
const SKIP_FSTYPES: &[&str] = &[
    "proc", "sysfs", "cgroup", "cgroup2", "devpts", "devtmpfs", "mqueue", "debugfs", "tracefs",
    "securityfs", "pstore", "bpf", "configfs", "fusectl", "binfmt_misc", "autofs", "hugetlbfs",
    "efivarfs", "nsfs", "rpc_pipefs", "ramfs", "squashfs",
];

/// Same path written again within this window is not rescanned; editors and
/// downloaders close a file many times in a burst.
const WRITE_DEBOUNCE: Duration = Duration::from_secs(2);

/// An exec still unanswered after this long is allowed by the watchdog. While
/// an exec permission event is pending the process is frozen in the kernel,
/// so a stuck scan (or a bug here) must never be able to freeze the machine
/// — including the shell someone would use to stop this daemon.
const EXEC_DEADLINE: Duration = Duration::from_secs(3);

#[derive(Default)]
pub struct Stats {
    pub exec_checked: AtomicU64,
    pub exec_blocked: AtomicU64,
    pub writes_scanned: AtomicU64,
    pub dropped: AtomicU64,
}

// ── Verdict cache ────────────────────────────────────────────────────────

/// Keyed by inode identity plus size, mtime and ctime. A user can fake mtime
/// but not ctime, so any content change produces a new key.
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct FileKey {
    dev: u64,
    ino: u64,
    size: i64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl FileKey {
    fn of(st: &libc::stat) -> FileKey {
        FileKey {
            dev: st.st_dev,
            ino: st.st_ino,
            size: st.st_size,
            mtime: (st.st_mtime, st.st_mtime_nsec),
            ctime: (st.st_ctime, st.st_ctime_nsec),
        }
    }
}

/// Cached outcome: severity and whether it was a confirmed detection.
type Cached = (Severity, bool);

struct Cache {
    map: Mutex<HashMap<FileKey, (u64, Cached)>>,
}

impl Cache {
    fn get(&self, k: &FileKey, generation: u64) -> Option<Cached> {
        let m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        m.get(k).filter(|(g, _)| *g == generation).map(|(_, s)| *s)
    }

    fn put(&self, k: FileKey, generation: u64, s: Cached) {
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        if m.len() > 100_000 {
            m.clear();
        }
        m.insert(k, (generation, s));
    }
}

// ── Plumbing ─────────────────────────────────────────────────────────────

struct Job {
    fd: OwnedFd,
    pid: i32,
    path: PathBuf,
    /// Pending-exec ticket; 0 for notification (write) events.
    ticket: u64,
}

/// Exec events waiting for an answer, so the watchdog can find overdue ones.
/// An entry's descriptor stays open (owned by its Job) until the entry is
/// removed, so the watchdog can never answer for a reused descriptor number.
#[derive(Default)]
struct Pending {
    next: AtomicU64,
    map: Mutex<HashMap<u64, (RawFd, Instant)>>,
}

struct Shared {
    fan: OwnedFd,
    guard: Arc<Guard>,
    cache: Cache,
    stats: Arc<Stats>,
    pending: Pending,
    max_size: u64,
    block_exec: bool,
}

impl Shared {
    fn register(&self, fd: RawFd) -> u64 {
        let t = self.pending.next.fetch_add(1, Ordering::Relaxed) + 1;
        self.pending.map.lock().unwrap_or_else(|p| p.into_inner()).insert(t, (fd, Instant::now()));
        t
    }

    /// Answer a pending exec exactly once. Returns false if the watchdog
    /// already allowed it.
    fn answer(&self, ticket: u64, allow: bool) -> bool {
        let mut map = self.pending.map.lock().unwrap_or_else(|p| p.into_inner());
        match map.remove(&ticket) {
            Some((fd, _)) => {
                self.respond(fd, allow);
                true
            }
            None => false,
        }
    }

    fn respond(&self, event_fd: RawFd, allow: bool) {
        let resp = libc::fanotify_response {
            fd: event_fd,
            response: if allow { libc::FAN_ALLOW } else { libc::FAN_DENY },
        };
        let n = unsafe {
            libc::write(
                self.fan.as_raw_fd(),
                (&resp as *const libc::fanotify_response).cast(),
                std::mem::size_of::<libc::fanotify_response>(),
            )
        };
        if n < 0 {
            log::error!("fanotify response: {}", io::Error::last_os_error());
        }
    }

    /// Verdict for an open file, from cache when possible. None on read error
    /// or when the file is over the size limit (treated as allowed).
    fn verdict(&self, fd: BorrowedFd<'_>, path: &Path, buf: &mut Vec<u8>) -> Option<(Cached, Option<Verdict>)> {
        let st = fsutil::fstat(fd).ok()?;
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG || st.st_size as u64 > self.max_size {
            return None;
        }
        let key = FileKey::of(&st);
        let generation = self.guard.engine.signatures().generation;
        if let Some(c) = self.cache.get(&key, generation) {
            return Some((c, None));
        }
        match self.guard.engine.scan_fd(fd, path, self.max_size, buf) {
            Ok(v) => {
                let c = (v.severity, v.is_confirmed());
                self.cache.put(key, generation, c);
                Some((c, Some(v)))
            }
            Err(e) => {
                log::debug!("scan: {e}");
                None
            }
        }
    }
}

pub struct Realtime {
    stop: OwnedFd,
    /// Set before an orderly stop, so the exec-path threads ending is not
    /// mistaken for a failure.
    stopping: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    pub stats: Arc<Stats>,
}

impl Realtime {
    pub fn start(cfg: &Config, guard: Arc<Guard>) -> io::Result<Realtime> {
        let flags = libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | libc::FAN_UNLIMITED_QUEUE | libc::FAN_UNLIMITED_MARKS;
        let raw = unsafe { libc::fanotify_init(flags, (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fan = unsafe { OwnedFd::from_raw_fd(raw) };
        let stop = eventfd()?;
        let scope = Scope::new(cfg);
        let mask = if cfg.block_exec {
            libc::FAN_OPEN_EXEC_PERM | libc::FAN_CLOSE_WRITE
        } else {
            libc::FAN_CLOSE_WRITE
        };

        let mut marked = HashSet::new();
        mark_mounts(fan.as_fd(), &scope, mask, &mut marked);
        if marked.is_empty() {
            return Err(io::Error::other("no filesystem in scope could be marked"));
        }

        let stats = Arc::new(Stats::default());
        let shared = Arc::new(Shared {
            fan,
            guard,
            cache: Cache { map: Mutex::new(HashMap::new()) },
            stats: stats.clone(),
            pending: Pending::default(),
            max_size: cfg.max_file_size(),
            block_exec: cfg.block_exec,
        });

        let (exec_tx, exec_rx) = unbounded::<Job>();
        let (bg_tx, bg_rx) = bounded::<Job>(4096);
        let stopping = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();

        // The reader, the exec workers and the watchdog are the exec path:
        // spawn_critical ends the process if one of them dies.
        for i in 0..cfg.exec_workers {
            let (s, rx) = (shared.clone(), exec_rx.clone());
            threads.push(spawn_critical(&format!("exec-{i}"), stopping.clone(), move || exec_worker(s, rx)));
        }
        for i in 0..cfg.background_workers {
            let (s, rx) = (shared.clone(), bg_rx.clone());
            threads.push(spawn(&format!("write-{i}"), move || write_worker(s, rx)));
        }
        {
            let s = shared.clone();
            let stop_fd = stop.as_raw_fd();
            let scope = scope.clone();
            threads.push(spawn_critical("fan-reader", stopping.clone(), move || {
                reader(s, scope, stop_fd, exec_tx, bg_tx)
            }));
        }
        {
            let s = shared.clone();
            let stop_fd = stop.as_raw_fd();
            threads.push(spawn("mount-watch", move || mount_watcher(s, scope, mask, marked, stop_fd)));
        }
        {
            let s = shared.clone();
            let stop_fd = stop.as_raw_fd();
            threads.push(spawn_critical("exec-watchdog", stopping.clone(), move || watchdog(s, stop_fd)));
        }
        log::info!("real-time protection on (blocking confirmed detections: {})", cfg.block_exec);
        Ok(Realtime { stop, stopping, threads, stats })
    }

    pub fn stop(self) {
        self.stopping.store(true, Ordering::SeqCst);
        let one: u64 = 1;
        unsafe { libc::write(self.stop.as_raw_fd(), (&one as *const u64).cast(), 8) };
        for t in self.threads {
            let _ = t.join();
        }
        log::info!("real-time protection off");
    }
}

fn spawn(name: &str, f: impl FnOnce() + Send + 'static) -> JoinHandle<()> {
    std::thread::Builder::new().name(name.into()).spawn(f).expect("spawn thread")
}

fn eventfd() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// ── Reader ───────────────────────────────────────────────────────────────

/// How the reader reacts to a failed poll() or read() on the fanotify fd.
#[derive(Debug, PartialEq, Eq)]
enum OnError {
    /// Try again at once.
    Retry,
    /// Out of a resource the workers will give back: pause briefly first.
    Backoff,
    /// A bug (bad descriptor, bad buffer): the reader cannot continue.
    Fatal,
}

fn classify(e: &io::Error) -> OnError {
    match e.raw_os_error() {
        // Out of descriptors or memory. The kernel could not create the
        // event's descriptor, answered that one event itself (a permission
        // event is denied, a notification dropped) and kept the rest queued.
        Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOBUFS) => OnError::Backoff,
        Some(libc::EBADF | libc::EFAULT | libc::EINVAL) => OnError::Fatal,
        // Everything else is about one event, and that event is gone: read()
        // also reports why the kernel could not open the event's file (EIO on
        // a failing disk, EACCES, ENXIO, ...). Never a reason to stop reading.
        _ => OnError::Retry,
    }
}

/// Pause after a resource error: long enough for workers to close
/// descriptors, short enough that queued execs barely notice.
const BACKOFF: Duration = Duration::from_millis(50);

/// Logs at most once per interval, counting what it held back.
struct Throttle {
    every: Duration,
    last: Option<Instant>,
    suppressed: u64,
}

impl Throttle {
    fn new(every: Duration) -> Throttle {
        Throttle { every, last: None, suppressed: 0 }
    }

    fn warn(&mut self, msg: impl Display) {
        if self.last.is_some_and(|t| t.elapsed() < self.every) {
            self.suppressed += 1;
            return;
        }
        if self.suppressed > 0 {
            log::warn!("{msg} ({} similar messages suppressed)", self.suppressed);
        } else {
            log::warn!("{msg}");
        }
        self.last = Some(Instant::now());
        self.suppressed = 0;
    }
}

/// The only thread reading the fanotify descriptor, so it must never stop
/// while protection is on: every error is retried, except the few that mean
/// the loop itself is broken, which end the process (see supervise.rs).
fn reader(s: Arc<Shared>, scope: Scope, stop_fd: RawFd, exec_tx: Sender<Job>, bg_tx: Sender<Job>) {
    let me = std::process::id() as i32;
    let meta_len = std::mem::size_of::<libc::fanotify_event_metadata>();
    let mut buf = vec![0u8; 256 * 1024];
    let mut recent: HashMap<PathBuf, Instant> = HashMap::new();
    let mut throttle = Throttle::new(Duration::from_secs(10));

    loop {
        let mut fds = [
            libc::pollfd { fd: s.fan.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: stop_fd, events: libc::POLLIN, revents: 0 },
        ];
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if r < 0 {
            let e = io::Error::last_os_error();
            match classify(&e) {
                OnError::Retry if e.kind() == io::ErrorKind::Interrupted => {}
                OnError::Fatal => fatal(&format!("fanotify poll: {e}")),
                _ => {
                    throttle.warn(format_args!("fanotify poll: {e}; retrying"));
                    std::thread::sleep(BACKOFF);
                }
            }
            continue;
        }
        if fds[1].revents != 0 {
            return;
        }
        let n = unsafe { libc::read(s.fan.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            match classify(&e) {
                OnError::Retry => {
                    if !matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock) {
                        throttle.warn(format_args!("fanotify read: {e}; event skipped"));
                    }
                }
                OnError::Backoff => {
                    throttle.warn(format_args!("fanotify read: {e}; pausing {BACKOFF:?}"));
                    std::thread::sleep(BACKOFF);
                }
                OnError::Fatal => fatal(&format!("fanotify read: {e}")),
            }
            continue;
        }

        let mut off = 0usize;
        let n = n as usize;
        while off + meta_len <= n {
            let m: libc::fanotify_event_metadata = unsafe { std::ptr::read_unaligned(buf[off..].as_ptr().cast()) };
            if m.event_len < meta_len as u32 || off + m.event_len as usize > n {
                break;
            }
            off += m.event_len as usize;
            if m.vers != libc::FANOTIFY_METADATA_VERSION {
                fatal(&format!("fanotify metadata version {} unsupported", m.vers));
            }
            if m.fd == libc::FAN_NOFD {
                if m.mask & libc::FAN_Q_OVERFLOW != 0 {
                    log::warn!("fanotify queue overflow; some writes were not scanned");
                }
                continue;
            }
            let fd = unsafe { OwnedFd::from_raw_fd(m.fd) };
            let is_perm = m.mask & libc::FAN_OPEN_EXEC_PERM != 0;

            // Our own reads never generate these, but keep it cheap and safe.
            if m.pid == me {
                if is_perm {
                    s.respond(fd.as_raw_fd(), true);
                }
                continue;
            }
            let path = match fsutil::fd_path(fd.as_fd()) {
                Some(p) if scope.contains(&p) => p,
                _ => {
                    if is_perm {
                        s.respond(fd.as_raw_fd(), true);
                    }
                    continue;
                }
            };

            if is_perm {
                // Unbounded on purpose: blocking here would stall every exec
                // on the machine, not just the ones in scope.
                let ticket = s.register(fd.as_raw_fd());
                if let Err(e) = exec_tx.send(Job { fd, pid: m.pid, path, ticket }) {
                    s.answer(e.0.ticket, true);
                }
            } else if m.mask & libc::FAN_CLOSE_WRITE != 0 {
                let now = Instant::now();
                if recent.get(&path).is_some_and(|t| now.duration_since(*t) < WRITE_DEBOUNCE) {
                    continue;
                }
                if recent.len() > 4096 {
                    recent.retain(|_, t| now.duration_since(*t) < WRITE_DEBOUNCE);
                }
                recent.insert(path.clone(), now);
                if let Err(TrySendError::Full(_)) = bg_tx.try_send(Job { fd, pid: m.pid, path, ticket: 0 }) {
                    s.stats.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

// ── Workers ──────────────────────────────────────────────────────────────

fn exec_worker(s: Arc<Shared>, rx: Receiver<Job>) {
    let mut buf = Vec::new();
    for job in rx {
        s.stats.exec_checked.fetch_add(1, Ordering::Relaxed);
        let result = s.verdict(job.fd.as_fd(), &job.path, &mut buf);
        // Only exact identifications are ever blocked; pattern matches run
        // and are reported. And not even those while the safety brake is on.
        let confirmed = matches!(result, Some(((Severity::Malicious, true), _)));
        let deny = confirmed && s.block_exec && s.guard.may_act();
        // Answer first; reporting can take a while and the process (or the
        // user waiting on it) shouldn't.
        let answered = s.answer(job.ticket, !deny);
        let deny = deny && answered;
        if deny {
            s.stats.exec_blocked.fetch_add(1, Ordering::Relaxed);
            s.guard.record_action();
        }
        report(&s, &job, result, Trigger::Exec { pid: job.pid, blocked: deny }, &mut buf);
    }
}

fn write_worker(s: Arc<Shared>, rx: Receiver<Job>) {
    // Background scans shouldn't compete with the user's foreground work.
    unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 10) };
    let mut buf = Vec::new();
    for job in rx {
        s.stats.writes_scanned.fetch_add(1, Ordering::Relaxed);
        let result = s.verdict(job.fd.as_fd(), &job.path, &mut buf);
        report(&s, &job, result, Trigger::Write { pid: job.pid }, &mut buf);
    }
}

fn report(s: &Shared, job: &Job, result: Option<(Cached, Option<Verdict>)>, trigger: Trigger, buf: &mut Vec<u8>) {
    let verdict = match result {
        None | Some(((Severity::Clean, _), _)) => return,
        Some((_, Some(v))) => v,
        // Cached non-clean verdict: rescan to get the name for the report.
        // Rare (the file was already handled), so the cost doesn't matter.
        Some((_, None)) => match s.guard.engine.scan_fd(job.fd.as_fd(), &job.path, s.max_size, buf) {
            Ok(v) if v.severity != Severity::Clean => v,
            _ => return,
        },
    };
    s.guard.handle(job.fd.as_fd(), &job.path, &verdict, trigger);
}

/// Allow any exec that has waited past the deadline.
fn watchdog(s: Arc<Shared>, stop_fd: RawFd) {
    loop {
        let mut pfd = libc::pollfd { fd: stop_fd, events: libc::POLLIN, revents: 0 };
        if unsafe { libc::poll(&mut pfd, 1, 250) } > 0 {
            return;
        }
        let mut map = s.pending.map.lock().unwrap_or_else(|p| p.into_inner());
        let overdue: Vec<u64> = map.iter().filter(|(_, (_, t))| t.elapsed() >= EXEC_DEADLINE).map(|(k, _)| *k).collect();
        for k in &overdue {
            if let Some((fd, _)) = map.remove(k) {
                s.respond(fd, true);
            }
        }
        drop(map);
        if !overdue.is_empty() {
            log::warn!("{} exec check(s) took longer than {:?}; allowed", overdue.len(), EXEC_DEADLINE);
        }
    }
}

// ── Marks ────────────────────────────────────────────────────────────────

struct Mount {
    mountpoint: PathBuf,
    fstype: String,
}

fn read_mounts() -> Vec<Mount> {
    let Ok(text) = std::fs::read_to_string("/proc/self/mountinfo") else { return Vec::new() };
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            let sep = fields.iter().position(|f| *f == "-")?;
            Some(Mount {
                mountpoint: PathBuf::from(unescape(fields.get(4)?)),
                fstype: fields.get(sep + 1)?.to_string(),
            })
        })
        .collect()
}

/// mountinfo escapes space, tab, newline and backslash as \ooo.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A mount is relevant if a scope root lives on it (it is an ancestor of the
/// root) or it is mounted somewhere inside a scope root.
fn relevant(m: &Mount, scope: &Scope) -> bool {
    if SKIP_FSTYPES.contains(&m.fstype.as_str()) || m.fstype.starts_with("fuse") {
        return false;
    }
    scope.roots().iter().any(|r| r.starts_with(&m.mountpoint) || m.mountpoint.starts_with(r))
}

fn mark_mounts(fan: BorrowedFd<'_>, scope: &Scope, mask: u64, marked: &mut HashSet<PathBuf>) {
    for m in read_mounts() {
        if marked.contains(&m.mountpoint) || !relevant(&m, scope) {
            continue;
        }
        match mark(fan, &m.mountpoint, mask) {
            Ok(kind) => {
                log::info!("watching {} ({}, {kind} mark)", m.mountpoint.display(), m.fstype);
                marked.insert(m.mountpoint);
            }
            Err(e) => log::warn!("cannot watch {}: {e}", m.mountpoint.display()),
        }
    }
}

/// Filesystem marks cover every mount of the filesystem, including bind
/// mounts inside flatpak/container namespaces. Some setups (btrfs subvolumes
/// on some kernels) refuse them; fall back to a mount mark.
fn mark(fan: BorrowedFd<'_>, path: &Path, mask: u64) -> io::Result<&'static str> {
    let c = CString::new(path.as_os_str().as_bytes())?;
    for (flag, kind) in [(libc::FAN_MARK_FILESYSTEM, "filesystem"), (libc::FAN_MARK_MOUNT, "mount")] {
        let r = unsafe { libc::fanotify_mark(fan.as_raw_fd(), libc::FAN_MARK_ADD | flag, mask, libc::AT_FDCWD, c.as_ptr()) };
        if r == 0 {
            return Ok(kind);
        }
    }
    Err(io::Error::last_os_error())
}

/// Mark filesystems mounted later: USB sticks under /run/media, and the
/// /run/user/UID tmpfs created at each login.
fn mount_watcher(s: Arc<Shared>, scope: Scope, mask: u64, mut marked: HashSet<PathBuf>, stop_fd: RawFd) {
    // Not on the exec path: if this stops, filesystems mounted later just go
    // unwatched. Say so instead of stopping silently.
    let f = match std::fs::File::open("/proc/self/mountinfo") {
        Ok(f) => f,
        Err(e) => {
            log::error!("mount watcher: {e}; filesystems mounted from now on will not be watched");
            return;
        }
    };
    loop {
        let mut fds = [
            libc::pollfd { fd: f.as_raw_fd(), events: libc::POLLPRI, revents: 0 },
            libc::pollfd { fd: stop_fd, events: libc::POLLIN, revents: 0 },
        ];
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            log::error!("mount watcher: {e}; filesystems mounted from now on will not be watched");
            return;
        }
        if fds[1].revents != 0 {
            return;
        }
        if fds[0].revents != 0 {
            // Forget unmounted paths so a later mount there is marked again.
            let current: HashSet<PathBuf> = read_mounts().into_iter().map(|m| m.mountpoint).collect();
            marked.retain(|p| current.contains(p));
            mark_mounts(s.fan.as_fd(), &scope, mask, &mut marked);
            // Re-arm: the change keeps being reported until this descriptor
            // has been read again from the start.
            unsafe { libc::lseek(f.as_raw_fd(), 0, libc::SEEK_SET) };
            let mut tmp = [0u8; 4096];
            while unsafe { libc::read(f.as_raw_fd(), tmp.as_mut_ptr().cast(), tmp.len()) } > 0 {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_errors_never_stop_the_reader_by_accident() {
        let e = |n| io::Error::from_raw_os_error(n);
        for n in [libc::EMFILE, libc::ENFILE, libc::ENOMEM, libc::ENOBUFS] {
            assert_eq!(classify(&e(n)), OnError::Backoff, "errno {n}");
        }
        // Per-event errors, including the open errors read() passes on.
        for n in [libc::EINTR, libc::EAGAIN, libc::EIO, libc::EACCES, libc::EPERM, libc::ENOENT, libc::ENXIO] {
            assert_eq!(classify(&e(n)), OnError::Retry, "errno {n}");
        }
        for n in [libc::EBADF, libc::EFAULT, libc::EINVAL] {
            assert_eq!(classify(&e(n)), OnError::Fatal, "errno {n}");
        }
    }

    #[test]
    fn unescapes_mountinfo() {
        assert_eq!(unescape(r"/run/media/u/My\040Disk"), "/run/media/u/My Disk");
        assert_eq!(unescape(r"/a\\b"), r"/a\\b");
        assert_eq!(unescape("/plain"), "/plain");
    }
}
