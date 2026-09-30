//! Minimal logger: syslog-style "<N>" priority prefixes when stderr goes to
//! the journal (so journalctl shows real levels), plain text otherwise.
//! Level from QLAM_LOG (error, warn, info, debug); default info.

use std::io::Write;

use log::{Level, LevelFilter, Log, Metadata, Record};

struct Logger {
    journal: bool,
}

impl Log for Logger {
    fn enabled(&self, m: &Metadata<'_>) -> bool {
        m.level() <= log::max_level()
    }

    fn log(&self, r: &Record<'_>) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let mut err = std::io::stderr().lock();
        let _ = if self.journal {
            let prio = match r.level() {
                Level::Error => 3,
                Level::Warn => 4,
                Level::Info => 6,
                Level::Debug | Level::Trace => 7,
            };
            writeln!(err, "<{prio}>{}", r.args())
        } else {
            writeln!(err, "{:5} {}", r.level(), r.args())
        };
    }

    fn flush(&self) {}
}

/// JOURNAL_STREAM is inherited by children whose stderr may point elsewhere,
/// so it only counts if it names the device:inode stderr is actually on.
fn stderr_is_journal() -> bool {
    let Some(v) = std::env::var_os("JOURNAL_STREAM") else { return false };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(2, &mut st) } != 0 {
        return false;
    }
    v.to_string_lossy() == format!("{}:{}", st.st_dev, st.st_ino)
}

pub fn init() {
    let level = match std::env::var("QLAM_LOG").as_deref() {
        Ok("error") => LevelFilter::Error,
        Ok("warn") => LevelFilter::Warn,
        Ok("debug") => LevelFilter::Debug,
        Ok("trace") => LevelFilter::Trace,
        _ => LevelFilter::Info,
    };
    let journal = stderr_is_journal();
    if log::set_logger(Box::leak(Box::new(Logger { journal }))).is_ok() {
        log::set_max_level(level);
    }
}
