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
use std::fs::File;
use std::os::unix::fs::OpenOptionsExt;
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

/// Name prefixes of the shared-memory files Chromium and every Electron app
/// keep in /dev/shm. They back IPC and rendering buffers — whatever the app
/// is displaying, a web page or a chat that quotes the EICAR string — are
/// created and rewritten constantly, and are mapped, never executed. Their
/// writes are not scanned; an exec from one is still checked.
const BROWSER_SHM_PREFIXES: &[&str] = &[
    ".org.chromium.Chromium.",
    ".com.google.Chrome.",
    ".com.microsoft.Edge.",
    ".com.brave.Browser.",
    ".com.vivaldi.Vivaldi.",
    ".com.opera.Opera.",
];

fn is_browser_shm(path: &Path) -> bool {
    path.parent() == Some(Path::new("/dev/shm"))
        && path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| BROWSER_SHM_PREFIXES.iter().any(|p| n.starts_with(p)))
}

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
    /// Execs allowed unchecked because the exec queue was backed up.
    pub exec_overflow: AtomicU64,
    pub writes_scanned: AtomicU64,
    /// Written files not scanned because the write queue was full.
    pub dropped: AtomicU64,
}

/// How many exec checks may wait in the queue, each holding a descriptor.
/// Past this, new execs are allowed without a check: the descriptors must
/// never run out (the kernel then denies execs outright), and a backlog this
/// deep means the checks couldn't keep up anyway.
fn exec_backlog_limit() -> usize {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    let soft = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0 {
        lim.rlim_cur as usize
    } else {
        1024
    };
    (soft / 4).clamp(16, 4096)
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

/// An exec waiting for a verdict. It holds the event's descriptor, which the
/// answer to the kernel refers to.
struct Job {
    fd: OwnedFd,
    pid: i32,
    path: PathBuf,
    /// Pending-exec ticket, see [`Pending`].
    ticket: u64,
}

/// A written file waiting for a background scan. It holds the path and the
/// identity the file had when the write finished, not a descriptor: this
/// queue can be thousands deep during a burst of writes, and descriptors
/// parked in it used to exhaust the process's limit (2026-09-30).
struct WriteJob {
    path: PathBuf,
    key: FileKey,
    pid: i32,
}

/// Open a written file again for its background scan — but only if it is
/// still the file that was written: same inode, size, mtime and ctime.
/// Anything else (rewritten, replaced, deleted, swapped for a symlink) is
/// skipped; a rewrite produces a close-write event of its own.
fn reopen(path: &Path, key: &FileKey) -> Option<File> {
    let open = |extra: i32| {
        File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | extra)
            .open(path)
    };
    // O_NOATIME keeps scans from touching access times; only the owner or
    // CAP_FOWNER may use it, so fall back without it.
    let f = match open(libc::O_NOATIME) {
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => open(0),
        other => other,
    }
    .ok()?;
    let st = fsutil::fstat(f.as_fd()).ok()?;
    ((st.st_mode & libc::S_IFMT) == libc::S_IFREG && FileKey::of(&st) == *key).then_some(f)
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
    /// See [`exec_backlog_limit`].
    max_exec_backlog: usize,
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
            max_exec_backlog: exec_backlog_limit(),
        });

        let (exec_tx, exec_rx) = unbounded::<Job>();
        let (bg_tx, bg_rx) = bounded::<WriteJob>(4096);
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

/// Pause after a resource error when no reserve is left.
///
/// Deliberately short. Each read() that fails for lack of descriptors still
/// consumes one queued event (a notification is dropped, a permission event
/// denied). Execs queued behind those events have not been read yet, so the
/// watchdog cannot see them: with 2000 queued writes, a 50 ms pause would
/// hold such an exec for 100 s. Draining quickly means an exec may fail
/// during descriptor exhaustion, but it never hangs.
const BACKOFF: Duration = Duration::from_millis(2);

/// Descriptors the reader keeps in reserve.
const RESERVE_FDS: usize = 16;

/// Spare descriptors (on /dev/null) held back for when the table is full.
/// Releasing them lets the kernel hand over the next events normally instead
/// of refusing them; the reader closes most event descriptors within the same
/// batch, then takes the reserve back.
struct Reserve {
    fds: Vec<OwnedFd>,
}

impl Reserve {
    fn new() -> Reserve {
        let mut r = Reserve { fds: Vec::with_capacity(RESERVE_FDS) };
        r.refill();
        r
    }

    /// Top up; stops quietly when the table is full again.
    fn refill(&mut self) {
        while self.fds.len() < RESERVE_FDS {
            let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if fd < 0 {
                break;
            }
            self.fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
        }
    }

    /// Hand the spares back to the process. False if there were none.
    fn release(&mut self) -> bool {
        let had = !self.fds.is_empty();
        self.fds.clear();
        had
    }
}

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
fn reader(s: Arc<Shared>, scope: Scope, stop_fd: RawFd, exec_tx: Sender<Job>, bg_tx: Sender<WriteJob>) {
    let me = std::process::id() as i32;
    let meta_len = std::mem::size_of::<libc::fanotify_event_metadata>();
    let mut buf = vec![0u8; 256 * 1024];
    let mut recent: HashMap<PathBuf, Instant> = HashMap::new();
    let mut throttle = Throttle::new(Duration::from_secs(10));
    let mut overflow = Throttle::new(Duration::from_secs(10));
    let mut reserve = Reserve::new();

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
                    if reserve.release() {
                        throttle.warn(format_args!("fanotify read: {e}; using reserved descriptors"));
                    } else {
                        throttle.warn(format_args!(
                            "fanotify read: {e}; the kernel refuses events until descriptors are freed"
                        ));
                        std::thread::sleep(BACKOFF);
                    }
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
                // The queue is unbounded because blocking here would stall
                // every exec on the machine; its depth is capped here instead.
                if exec_tx.len() >= s.max_exec_backlog {
                    s.respond(fd.as_raw_fd(), true);
                    s.stats.exec_overflow.fetch_add(1, Ordering::Relaxed);
                    overflow.warn(format_args!(
                        "{} exec checks queued; allowing new execs unchecked until it drains",
                        s.max_exec_backlog
                    ));
                    continue;
                }
                let ticket = s.register(fd.as_raw_fd());
                if let Err(e) = exec_tx.send(Job { fd, pid: m.pid, path, ticket }) {
                    s.answer(e.0.ticket, true);
                }
            } else if m.mask & libc::FAN_CLOSE_WRITE != 0 {
                if is_browser_shm(&path) {
                    continue;
                }
                let now = Instant::now();
                if recent.get(&path).is_some_and(|t| now.duration_since(*t) < WRITE_DEBOUNCE) {
                    continue;
                }
                if recent.len() > 4096 {
                    recent.retain(|_, t| now.duration_since(*t) < WRITE_DEBOUNCE);
                }
                recent.insert(path.clone(), now);
                // Note what was written and let the descriptor go now (it
                // closes when `fd` drops at the end of this iteration).
                let Ok(st) = fsutil::fstat(fd.as_fd()) else { continue };
                if (st.st_mode & libc::S_IFMT) != libc::S_IFREG || st.st_size as u64 > s.max_size {
                    continue;
                }
                let job = WriteJob { path, key: FileKey::of(&st), pid: m.pid };
                if let Err(TrySendError::Full(_)) = bg_tx.try_send(job) {
                    s.stats.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        // This batch's descriptors are closed now; take the reserve back.
        if reserve.fds.len() < RESERVE_FDS {
            reserve.refill();
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
        let trigger = Trigger::Exec { pid: job.pid, blocked: deny };
        report(&s, job.fd.as_fd(), &job.path, result, trigger, &mut buf);
    }
}

fn write_worker(s: Arc<Shared>, rx: Receiver<WriteJob>) {
    // Background scans shouldn't compete with the user's foreground work.
    unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 10) };
    let mut buf = Vec::new();
    for job in rx {
        let Some(file) = reopen(&job.path, &job.key) else { continue };
        s.stats.writes_scanned.fetch_add(1, Ordering::Relaxed);
        let result = s.verdict(file.as_fd(), &job.path, &mut buf);
        report(&s, file.as_fd(), &job.path, result, Trigger::Write { pid: job.pid }, &mut buf);
    }
}

fn report(
    s: &Shared,
    fd: BorrowedFd<'_>,
    path: &Path,
    result: Option<(Cached, Option<Verdict>)>,
    trigger: Trigger,
    buf: &mut Vec<u8>,
) {
    let verdict = match result {
        None | Some(((Severity::Clean, _), _)) => return,
        Some((_, Some(v))) => v,
        // Cached non-clean verdict: rescan to get the name for the report.
        // Rare (the file was already handled), so the cost doesn't matter.
        Some((_, None)) => match s.guard.engine.scan_fd(fd, path, s.max_size, buf) {
            Ok(v) if v.severity != Severity::Clean => v,
            _ => return,
        },
    };
    s.guard.handle(fd, path, &verdict, trigger);
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
    use crate::supervise::testutil::{child_mode, run_child};
    use std::process::Command;

    fn set_nofile(n: u64) {
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        unsafe {
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim), 0);
            lim.rlim_cur = n.min(lim.rlim_max);
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &lim), 0);
        }
    }

    #[test]
    fn reserve_frees_room_when_the_table_is_full() {
        let code = run_child("realtime::tests::reserve_child", "reserve", &[], Duration::from_secs(20));
        assert_eq!(code, Some(0));
    }

    /// Child half: lowers the limit, so it runs in a process of its own.
    #[test]
    fn reserve_child() {
        if child_mode().as_deref() != Some("reserve") {
            return;
        }
        set_nofile(48);
        let mut reserve = Reserve::new();
        assert_eq!(reserve.fds.len(), RESERVE_FDS);
        let mut hog = Vec::new();
        while let Ok(f) = File::open("/dev/null") {
            hog.push(f);
        }
        assert!(File::open("/dev/null").is_err(), "table should be full");
        assert!(reserve.release());
        for _ in 0..RESERVE_FDS {
            hog.push(File::open("/dev/null").expect("room freed by the reserve"));
        }
        assert!(!reserve.release(), "nothing left to release");
        drop(hog.pop());
        reserve.refill();
        assert_eq!(reserve.fds.len(), 1, "refill takes what is free, no more");
    }

    /// The 2026-09-30 freeze, reproduced: a burst of writes under a tiny
    /// descriptor limit, then a completely full descriptor table while
    /// another process writes and runs programs. Execs must keep being
    /// answered within the deadline and the reader must survive.
    ///
    /// Needs root (fanotify permission events), and it marks "/", so every
    /// exec on the machine goes through the test while it runs; the child
    /// kills itself after 90 s whatever happens. Run it with:
    ///
    ///   sudo -E cargo test --release -- --ignored survives_descriptor_exhaustion
    #[test]
    #[ignore = "needs root; marks / with fanotify"]
    fn survives_descriptor_exhaustion() {
        assert_eq!(unsafe { libc::geteuid() }, 0, "run as root, see the comment above");
        let code = run_child("realtime::tests::stress_child", "stress", &["--ignored"], Duration::from_secs(120));
        assert_eq!(code, Some(0), "stress child failed or hung");
    }

    #[test]
    #[ignore = "child half of survives_descriptor_exhaustion"]
    fn stress_child() {
        if child_mode().as_deref() != Some("stress") {
            return;
        }
        // Kill switch: whatever happens, this process — and the fanotify
        // descriptor "/" is marked with — is gone within 90 s.
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_secs(90));
            eprintln!("stress test timed out");
            unsafe { libc::_exit(3) }
        });

        let dir = PathBuf::from(format!("/tmp/qlam-stress-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Bundled rules only: quick to load, and nothing here should match.
        std::env::set_var("QLAM_FEEDS_DIR", dir.join("no-feeds"));
        let prog = dir.join("true");
        std::fs::copy("/bin/true", &prog).unwrap();

        let cfg = Config {
            scope: vec![dir.to_string_lossy().into_owned()],
            exec_workers: 2,
            background_workers: 1,
            ..Config::default()
        };
        let store = Arc::new(crate::store::Store::in_memory());
        let (tx, _rx) = crossbeam_channel::bounded(16);
        let engine = crate::engine::Engine::new("/nonexistent/clamd.ctl", store.clone());
        let guard = Arc::new(Guard::new(engine, store, tx, false));

        set_nofile(64);
        let rt = Realtime::start(&cfg, guard).expect("start real-time protection");
        let stats = rt.stats.clone();
        let emfile = |e: &io::Error| e.raw_os_error() == Some(libc::EMFILE);

        // Phase 1: thousands of writes in this process under the limit of
        // 64, while programs inside and outside the watched directory run.
        let writer = {
            let dir = dir.clone();
            std::thread::spawn(move || {
                for i in 0..3000 {
                    let p = dir.join(format!("a{i}"));
                    loop {
                        match std::fs::write(&p, b"x") {
                            Ok(()) => break,
                            Err(e) if emfile(&e) => std::thread::sleep(Duration::from_millis(1)),
                            Err(e) => panic!("write {}: {e}", p.display()),
                        }
                    }
                }
            })
        };
        let mut runs = 0;
        while !writer.is_finished() || runs < 10 {
            for p in [Path::new("/bin/true"), prog.as_path()] {
                let t = Instant::now();
                match Command::new(p).status() {
                    Ok(_) => {
                        assert!(t.elapsed() < EXEC_DEADLINE, "exec of {} took {:?}", p.display(), t.elapsed());
                        runs += 1;
                    }
                    // Our own table was full for a moment; not the exec's fault.
                    Err(e) if emfile(&e) => {}
                    Err(e) => panic!("exec {}: {e}", p.display()),
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        writer.join().unwrap();

        // Phase 2: this process has no free descriptor at all while another
        // process writes 2000 watched files and runs programs. Its finishing
        // proves every exec was answered (allowed, or denied while no
        // descriptor could be made for it) instead of left waiting.
        std::fs::write(dir.join("go.tmp"), b"").unwrap();
        let script = "while [ ! -e go ]; do :; done; i=0; while [ $i -lt 2000 ]; do : > b$i; \
                      if [ $((i % 200)) -eq 0 ]; then /bin/true; ./true; fi; i=$((i+1)); done";
        let mut child = Command::new("/bin/sh").args(["-c", script]).current_dir(&dir).spawn().unwrap();
        let mut hog = Vec::new();
        while let Ok(f) = File::open("/dev/null") {
            hog.push(f);
        }
        std::fs::rename(dir.join("go.tmp"), dir.join("go")).unwrap(); // needs no descriptor
        let start = Instant::now();
        let status = loop {
            if let Some(st) = child.try_wait().unwrap() {
                break st;
            }
            assert!(start.elapsed() < Duration::from_secs(40), "writer process stuck: execs not answered");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(status.success(), "writer process: {status}");
        drop(hog);

        // Phase 3: the reader is still there and checking in-scope execs.
        let before = stats.exec_checked.load(Ordering::Relaxed);
        let t = Instant::now();
        assert!(Command::new(&prog).status().unwrap().success());
        assert!(t.elapsed() < EXEC_DEADLINE, "exec took {:?}", t.elapsed());
        assert!(stats.exec_checked.load(Ordering::Relaxed) > before, "exec not checked: reader gone?");

        rt.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

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
    fn write_jobs_reopen_only_the_file_that_was_written() {
        let dir = std::env::temp_dir().join(format!("qlam-reopen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("download.bin");
        std::fs::write(&path, b"first").unwrap();
        let key_of = |p: &Path| FileKey::of(&fsutil::fstat(File::open(p).unwrap().as_fd()).unwrap());
        let key = key_of(&path);

        assert!(reopen(&path, &key).is_some(), "unchanged file");

        // Rewritten after the event: ctime and size differ.
        std::thread::sleep(Duration::from_millis(10));
        std::fs::write(&path, b"second, longer").unwrap();
        assert!(reopen(&path, &key).is_none(), "rewritten file");

        // Replaced by a symlink to another file.
        let key = key_of(&path);
        let other = dir.join("other");
        std::fs::write(&other, b"x").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&other, &path).unwrap();
        assert!(reopen(&path, &key).is_none(), "symlink");

        // Gone.
        std::fs::remove_file(&path).unwrap();
        assert!(reopen(&path, &key).is_none(), "deleted file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn browser_shared_memory_is_recognised() {
        assert!(is_browser_shm(Path::new("/dev/shm/.org.chromium.Chromium.UmufvK")));
        assert!(is_browser_shm(Path::new("/dev/shm/.com.google.Chrome.a1b2c3")));
        // Only directly in /dev/shm, and only these names.
        assert!(!is_browser_shm(Path::new("/dev/shm/sub/.org.chromium.Chromium.x")));
        assert!(!is_browser_shm(Path::new("/tmp/.org.chromium.Chromium.x")));
        assert!(!is_browser_shm(Path::new("/dev/shm/payload")));
        assert!(!is_browser_shm(Path::new("/dev/shm/.org.chromium")));
    }

    #[test]
    fn unescapes_mountinfo() {
        assert_eq!(unescape(r"/run/media/u/My\040Disk"), "/run/media/u/My Disk");
        assert_eq!(unescape(r"/a\\b"), r"/a\\b");
        assert_eq!(unescape("/plain"), "/plain");
    }
}
