//! Keeping the exec path from being stranded.
//!
//! While a FAN_OPEN_EXEC_PERM event is unanswered, the process that called
//! execve() sleeps in the kernel. The kernel only gives up on our answers when
//! the fanotify descriptor is closed, which in practice means when the whole
//! process exits. So a thread on the exec path that dies while the rest of the
//! daemon lives on is the worst possible failure: every exec on every marked
//! filesystem waits forever, including the ones needed to recover (a shell,
//! systemctl, the shutdown sequence).
//!
//! The rule here: if a thread the exec path depends on ends unexpectedly — it
//! returns or panics while protection is still meant to be running — the
//! process exits at once. The kernel then allows every pending event, and
//! systemd (Restart=always) brings the daemon back.

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

/// Exit status after a fatal internal error (EX_SOFTWARE).
pub const FATAL_EXIT: i32 = 70;

/// Log and leave immediately.
///
/// `_exit` rather than `abort` or `exit`: an abort writes a core dump first,
/// and the kernel only closes our descriptors (and so releases pending execs)
/// once that is done — seconds, for a process holding ~1 GB of signatures.
/// `exit` runs atexit handlers that could block on a lock another thread holds.
pub fn fatal(msg: &str) -> ! {
    log::error!("fatal: {msg}; exiting so the kernel releases pending exec checks");
    unsafe { libc::_exit(FATAL_EXIT) }
}

/// Make every panic, on any thread, end the process through [`fatal`].
///
/// Release builds use panic=abort, which would also end the process, but via
/// a core dump (see [`fatal`] for why that is too slow). Installed by the
/// daemon only; tools and tests keep the default hook.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("unnamed");
        fatal(&format!("thread '{name}' panicked: {info}"));
    }));
}

/// Spawn a thread the exec path depends on. If it ends — normally or by
/// panicking — while `stopping` is unset, the process exits via [`fatal`].
pub fn spawn_critical(
    name: &str,
    stopping: Arc<AtomicBool>,
    f: impl FnOnce() + Send + 'static,
) -> JoinHandle<()> {
    let label = name.to_string();
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let outcome = std::panic::catch_unwind(AssertUnwindSafe(f));
            if stopping.load(Ordering::SeqCst) {
                return;
            }
            match outcome {
                Ok(()) => fatal(&format!("{label} thread stopped unexpectedly")),
                Err(p) => {
                    let why = p
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| p.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "unknown panic".into());
                    fatal(&format!("{label} thread panicked: {why}"))
                }
            }
        })
        .expect("spawn thread")
}

/// Helpers for tests that must run in a process of their own: anything that
/// ends the process on purpose, or changes process-wide limits.
#[cfg(test)]
pub mod testutil {
    use std::process::Command;
    use std::time::{Duration, Instant};

    const CHILD: &str = "QLAM_TEST_CHILD";

    /// In a child started by [`run_child`], the mode it was given.
    pub fn child_mode() -> Option<String> {
        std::env::var(CHILD).ok()
    }

    /// Re-run this test binary for one test (`extra` is passed to the test
    /// harness, e.g. `--ignored`) with `mode` in the environment. Returns the
    /// exit code, or None if the child had to be killed after `timeout`.
    pub fn run_child(test: &str, mode: &str, extra: &[&str], timeout: Duration) -> Option<i32> {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .args(extra)
            .env(CHILD, mode)
            .spawn()
            .unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status.code();
            }
            if start.elapsed() > timeout {
                let _ = child.kill();
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::{child_mode, run_child};
    use super::*;
    use std::time::Duration;

    const CHILD_TEST: &str = "supervise::tests::critical_child";

    fn run(mode: &str) -> Option<i32> {
        run_child(CHILD_TEST, mode, &[], Duration::from_secs(20))
    }

    /// Child side: start a critical thread that dies in the requested way,
    /// then outlive it. Reaching the end means the process was not ended.
    #[test]
    fn critical_child() {
        let Some(mode) = child_mode() else { return };
        let stopping = Arc::new(AtomicBool::new(mode == "stopping"));
        let t = spawn_critical("reader", stopping, move || {
            if mode == "panic" {
                panic!("simulated reader failure");
            }
        });
        let _ = t.join();
        std::thread::sleep(Duration::from_secs(2));
    }

    #[test]
    fn process_exits_when_critical_thread_returns() {
        assert_eq!(run("return"), Some(FATAL_EXIT));
    }

    #[test]
    fn process_exits_when_critical_thread_panics() {
        assert_eq!(run("panic"), Some(FATAL_EXIT));
    }

    #[test]
    fn orderly_stop_is_not_fatal() {
        assert_eq!(run("stopping"), Some(0));
    }
}
