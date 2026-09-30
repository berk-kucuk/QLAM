//! qlamd — Qlam's antivirus daemon.
//!
//!   qlamd [daemon]      run the service (root, from qlamd.service)
//!   qlamd daemon --session
//!                       development: run as the current user on the session
//!                       bus, without real-time protection or polkit
//!   qlamd update        refresh signature feeds (qlam user, qlam-update.service)
//!   qlamd scan PATH...  scan paths in the foreground and print findings
//!                       (development aid; takes no action)

mod config;
mod daemon;
mod dbus;
mod engine;
mod fsutil;
mod guard;
mod logger;
mod persistence;
mod quarantine;
mod realtime;
mod scanner;
mod store;
mod supervise;
mod updater;

use std::os::fd::AsFd;
use std::path::PathBuf;
use std::sync::Arc;

fn main() {
    logger::init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        None | Some("daemon") => run_daemon(args.iter().any(|a| a == "--session")),
        Some("update") => updater::run(),
        Some("scan") => scan_foreground(&args[1..]),
        Some("--version") => {
            println!("qlamd {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Some(other) => {
            eprintln!("unknown command {other}; use daemon, update or scan");
            2
        }
    };
    std::process::exit(code);
}

fn run_daemon(session: bool) -> i32 {
    if !session && unsafe { libc::geteuid() } != 0 {
        log::error!("qlamd must run as root (fanotify and the quarantine need it)");
        return 1;
    }
    supervise::install_panic_hook();
    raise_nofile_limit();
    // Block the termination signals in every thread (threads inherit the
    // mask), so the main thread can wait for them with sigwait.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGHUP);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }

    let mut cfg = config::Config::load();
    if session {
        cfg.realtime = false;
    }
    let state = config::state_dir();
    if let Err(e) = std::fs::create_dir_all(&state) {
        log::error!("{}: {e}", state.display());
        return 1;
    }
    if let Err(e) = quarantine::ensure_dir() {
        log::error!("{}: {e}", config::quarantine_dir().display());
        return 1;
    }
    let store = match store::Store::open(&config::db_file()) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log::error!("{}: {e}", config::db_file().display());
            return 1;
        }
    };

    let (tx, rx) = crossbeam_channel::bounded(1024);
    let engine = engine::Engine::new(&cfg.clamd_socket, store.clone());
    let guard = Arc::new(guard::Guard::new(engine, store, tx, cfg.auto_quarantine));
    let d = daemon::Daemon::new(cfg, guard, session);
    d.apply_realtime();
    d.watch_feeds();

    let _conn = match dbus::serve(d.clone(), rx, session) {
        Ok(c) => c,
        Err(e) => {
            log::error!("D-Bus: {e}");
            d.stop();
            return 1;
        }
    };
    log::info!("qlamd {} ready", env!("CARGO_PKG_VERSION"));

    loop {
        let mut sig: libc::c_int = 0;
        unsafe { libc::sigwait(&set, &mut sig) };
        if sig == libc::SIGHUP {
            log::info!("SIGHUP: reloading signatures");
            d.guard.engine.reload();
            continue;
        }
        break;
    }
    log::info!("shutting down");
    d.stop();
    0
}

/// Raise the soft open-file limit to the hard limit.
///
/// Every fanotify event arrives as an open descriptor in this process, and
/// the systemd default soft limit is 1024. A burst of file activity (a
/// browser starting, an archive being unpacked) must not exhaust it: when
/// the kernel cannot create an event's descriptor it denies that exec.
/// qlamd.service also sets LimitNOFILE; this covers setups that override it.
fn raise_nofile_limit() {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return;
        }
        if lim.rlim_cur < lim.rlim_max {
            let want = libc::rlimit { rlim_cur: lim.rlim_max, rlim_max: lim.rlim_max };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &want) == 0 {
                lim = want;
            }
        }
    }
    log::info!("open file limit: {}", lim.rlim_cur);
}

/// Scan paths and print findings. Never quarantines or blocks anything.
fn scan_foreground(paths: &[String]) -> i32 {
    let store = Arc::new(store::Store::in_memory());
    let engine = engine::Engine::new(&config::Config::default().clamd_socket, store);
    let mut buf = Vec::new();
    let (mut files, mut hits) = (0u64, 0u64);
    let mut stack: Vec<PathBuf> = paths.iter().map(Into::into).collect();
    while let Some(p) = stack.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&p) else { continue };
        if meta.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&p) {
                stack.extend(rd.flatten().map(|e| e.path()));
            }
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        let Ok(f) = std::fs::File::open(&p) else { continue };
        files += 1;
        if let Ok(v) = engine.scan_fd(f.as_fd(), &p, 256 << 20, &mut buf) {
            if v.severity != engine::Severity::Clean {
                hits += 1;
                let tag = if v.is_confirmed() { "confirmed" } else { "pattern" };
                println!("{:?}/{tag}\t{}\t[{}]\t{}", v.severity, v.name, v.engine, p.display());
            }
        }
    }
    eprintln!("{files} files scanned, {hits} findings");
    if hits > 0 { 1 } else { 0 }
}
