//! System bus API: org.maze.Qlam1 at /org/maze/Qlam1.
//!
//! Complex values travel as JSON strings: the GUI is PyQt/QtDBus, where
//! nested D-Bus types are painful and JSON is one call.
//!
//! Signals are broadcast to every process on the system bus, so they carry
//! ids and counts only — never paths or detection details. Clients fetch
//! those through the uid-filtered methods.
//!
//! Every caller is identified by uid through the bus daemon. Reads are scoped
//! to the caller's own files and events (root sees everything); anything that
//! changes state goes through polkit (actions in org.maze.qlam.policy).

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;

use crossbeam_channel::Receiver;
use zbus::message::Header;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::Value;
use zbus::{fdo, interface, Connection};

use crate::daemon::{home_owner, Daemon};
use crate::guard::Notice;
use crate::quarantine;
use crate::scanner::User;
use crate::store::Event;

pub const BUS_NAME: &str = "org.maze.Qlam1";
pub const PATH: &str = "/org/maze/Qlam1";

pub struct Service {
    d: Arc<Daemon>,
}

/// Session-bus development instance: only the user themselves can reach it,
/// and there is no polkit agent relationship to check against.
static SESSION: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn err(e: impl std::fmt::Display) -> fdo::Error {
    fdo::Error::Failed(e.to_string())
}

async fn caller_uid(conn: &Connection, hdr: &Header<'_>) -> fdo::Result<u32> {
    let sender = hdr.sender().ok_or_else(|| fdo::Error::AccessDenied("no sender".into()))?;
    let proxy = fdo::DBusProxy::new(conn).await?;
    proxy.get_connection_unix_user(sender.clone().into()).await
}

/// Resolve the caller and check `action` with polkit (root is always allowed).
/// Polkit may show an authentication dialog, so this can take a while.
async fn authorize(conn: &Connection, hdr: &Header<'_>, action: &str) -> fdo::Result<u32> {
    let uid = caller_uid(conn, hdr).await?;
    if uid == 0 || SESSION.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(uid);
    }
    let sender = hdr.sender().ok_or_else(|| fdo::Error::AccessDenied("no sender".into()))?;
    let mut subject: HashMap<&str, Value<'_>> = HashMap::new();
    subject.insert("name", Value::from(sender.as_str()));
    let details: HashMap<&str, &str> = HashMap::new();
    const ALLOW_USER_INTERACTION: u32 = 1;
    let reply = conn
        .call_method(
            Some("org.freedesktop.PolicyKit1"),
            "/org/freedesktop/PolicyKit1/Authority",
            Some("org.freedesktop.PolicyKit1.Authority"),
            "CheckAuthorization",
            &(("system-bus-name", subject), action, details, ALLOW_USER_INTERACTION, ""),
        )
        .await?;
    let (authorized, _challenge, _details): (bool, bool, HashMap<String, String>) = reply.body().deserialize()?;
    if authorized {
        Ok(uid)
    } else {
        Err(fdo::Error::AccessDenied(format!("not authorized for {action}")))
    }
}

/// Owner check for an event or quarantine item. Root may act on anything.
fn owns(uid: u32, owner: u32) -> fdo::Result<()> {
    if uid == 0 || uid == owner {
        Ok(())
    } else {
        Err(fdo::Error::AccessDenied("this belongs to another user".into()))
    }
}

fn user_filter(uid: u32) -> Option<u32> {
    (uid != 0).then_some(uid)
}

impl Service {
    /// Event ids travel as strings: QtDBus marshals Python ints as int32.
    fn event_for(&self, uid: u32, id: &str) -> fdo::Result<Event> {
        let id: i64 = id.parse().map_err(|_| err("bad event id"))?;
        let ev = self.d.guard.store.event(id).ok_or_else(|| err("no such event"))?;
        owns(uid, ev.uid)?;
        Ok(ev)
    }
}

#[interface(name = "org.maze.Qlam1")]
impl Service {
    // ── Reads ────────────────────────────────────────────────────────────

    async fn status(&self, #[zbus(header)] hdr: Header<'_>, #[zbus(connection)] conn: &Connection) -> fdo::Result<String> {
        let uid = caller_uid(conn, &hdr).await?;
        Ok(self.d.status_json(uid))
    }

    async fn events(&self, limit: u32, #[zbus(header)] hdr: Header<'_>, #[zbus(connection)] conn: &Connection) -> fdo::Result<String> {
        let uid = caller_uid(conn, &hdr).await?;
        self.d.sweep_gone();
        let evs = self.d.guard.store.events(user_filter(uid), limit.min(1000));
        serde_json::to_string(&evs).map_err(err)
    }

    async fn scans(&self, limit: u32, #[zbus(header)] hdr: Header<'_>, #[zbus(connection)] conn: &Connection) -> fdo::Result<String> {
        let uid = caller_uid(conn, &hdr).await?;
        serde_json::to_string(&self.d.guard.store.scans(user_filter(uid), limit.min(500))).map_err(err)
    }

    async fn quarantine(&self, #[zbus(header)] hdr: Header<'_>, #[zbus(connection)] conn: &Connection) -> fdo::Result<String> {
        let uid = caller_uid(conn, &hdr).await?;
        serde_json::to_string(&self.d.guard.store.quarantine_list(user_filter(uid))).map_err(err)
    }

    // ── Scans ────────────────────────────────────────────────────────────

    /// kind: "quick" (downloads, desktop, autostart, temp dirs + persistence
    /// checks), "home" (whole home + persistence checks) or "custom" (paths).
    async fn start_scan(
        &self,
        kind: String,
        paths: Vec<String>,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<String> {
        let uid = authorize(conn, &hdr, "org.maze.qlam.scan").await?;
        let user = User::lookup(uid).ok_or_else(|| err("unknown user"))?;
        let scope = self.d.scope();
        let (targets, persistence) = match kind.as_str() {
            "quick" => (user.quick_targets(), true),
            "home" => (vec![user.home.clone()], true),
            "custom" => {
                let mut out = Vec::new();
                let mut needs_admin = false;
                for p in &paths {
                    // Resolve symlinks as root *before* judging the path, so a
                    // link into someone else's home is judged by its target.
                    let real = std::fs::canonicalize(p).map_err(|e| err(format!("{p}: {e}")))?;
                    if !scope.contains(&real) {
                        return Err(err(format!("{} is outside the protected locations", real.display())));
                    }
                    if home_owner(&real).is_some_and(|owner| owner != uid) {
                        needs_admin = true;
                    }
                    out.push(real);
                }
                if out.is_empty() {
                    return Err(err("no paths given"));
                }
                if needs_admin {
                    authorize(conn, &hdr, "org.maze.qlam.scan-any").await?;
                }
                (out, false)
            }
            _ => return Err(err(format!("unknown scan kind {kind}"))),
        };
        let targets: Vec<PathBuf> = targets.into_iter().filter(|t| t.exists()).collect();
        Ok(self.d.scanner.start(user, &kind, targets, scope, persistence))
    }

    async fn cancel_scan(&self, id: String, #[zbus(header)] hdr: Header<'_>, #[zbus(connection)] conn: &Connection) -> fdo::Result<bool> {
        let uid = caller_uid(conn, &hdr).await?;
        Ok(self.d.scanner.cancel(&id, uid))
    }

    // ── Decisions on warnings ────────────────────────────────────────────

    /// Move the file an event is about into quarantine.
    async fn quarantine_event(&self, event_id: &str, #[zbus(header)] hdr: Header<'_>, #[zbus(connection)] conn: &Connection) -> fdo::Result<()> {
        let uid = authorize(conn, &hdr, "org.maze.qlam.quarantine").await?;
        let ev = self.event_for(uid, event_id)?;
        self.d.guard.quarantine_event(&ev).map_err(err)
    }

    /// "This is a false alarm / I trust this file": never flag it again.
    async fn trust_event(&self, event_id: &str, #[zbus(header)] hdr: Header<'_>, #[zbus(connection)] conn: &Connection) -> fdo::Result<()> {
        let uid = authorize(conn, &hdr, "org.maze.qlam.trust").await?;
        let ev = self.event_for(uid, event_id)?;
        self.d.guard.trust_event(&ev);
        Ok(())
    }

    /// Restore a quarantined file into `fd`, which the client opened for
    /// writing with its own permissions (usually at the original path).
    async fn restore_quarantine(
        &self,
        id: String,
        fd: zbus::zvariant::OwnedFd,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<()> {
        let uid = authorize(conn, &hdr, "org.maze.qlam.restore").await?;
        let item = self.d.guard.store.quarantine_get(&id).ok_or_else(|| err("no such quarantine item"))?;
        owns(uid, item.uid)?;
        let fd: OwnedFd = fd.into();
        // Only ever write into a regular file: a pipe or socket could block
        // this call indefinitely.
        let st = crate::fsutil::fstat(std::os::fd::AsFd::as_fd(&fd)).map_err(err)?;
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(err("restore target must be a regular file"));
        }
        quarantine::restore(&self.d.guard.store, &item, fd).map_err(err)?;
        log::info!("restored {} for uid {uid}", item.original_path);
        Ok(())
    }

    async fn delete_quarantine(&self, id: String, #[zbus(header)] hdr: Header<'_>, #[zbus(connection)] conn: &Connection) -> fdo::Result<()> {
        let uid = authorize(conn, &hdr, "org.maze.qlam.quarantine").await?;
        let item = self.d.guard.store.quarantine_get(&id).ok_or_else(|| err("no such quarantine item"))?;
        owns(uid, item.uid)?;
        quarantine::delete(&self.d.guard.store, &item).map_err(err)
    }

    // ── Administration ───────────────────────────────────────────────────

    /// name: "realtime", "block_exec" or "auto_quarantine".
    async fn set_option(&self, name: String, value: bool, #[zbus(header)] hdr: Header<'_>, #[zbus(connection)] conn: &Connection) -> fdo::Result<()> {
        authorize(conn, &hdr, "org.maze.qlam.configure").await?;
        let d = self.d.clone();
        // Restarting real-time protection joins threads; keep that off the
        // bus executor.
        std::thread::spawn(move || d.set_option(&name, value)).join().map_err(|_| err("internal error"))?.map_err(err)
    }

    async fn update_signatures(&self, #[zbus(header)] hdr: Header<'_>, #[zbus(connection)] conn: &Connection) -> fdo::Result<()> {
        authorize(conn, &hdr, "org.maze.qlam.update").await?;
        conn.call_method(
            Some("org.freedesktop.systemd1"),
            "/org/freedesktop/systemd1",
            Some("org.freedesktop.systemd1.Manager"),
            "StartUnit",
            &("qlam-update.service", "replace"),
        )
        .await?;
        Ok(())
    }

    // ── Signals ──────────────────────────────────────────────────────────

    /// A new event for `uid`; fetch it with Events().
    #[zbus(signal)]
    async fn threat_detected(emitter: &SignalEmitter<'_>, event_id: i64, uid: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn status_changed(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn scan_progress(emitter: &SignalEmitter<'_>, id: &str, files: u64, detections: u64) -> zbus::Result<()>;

    /// Fetch the result with Scans().
    #[zbus(signal)]
    async fn scan_finished(emitter: &SignalEmitter<'_>, id: &str) -> zbus::Result<()>;
}

/// Connect to the system bus, claim the name and serve until the process
/// exits. Notices from the workers are forwarded as signals.
pub fn serve(d: Arc<Daemon>, notices: Receiver<Notice>, session: bool) -> zbus::Result<zbus::blocking::Connection> {
    SESSION.store(session, std::sync::atomic::Ordering::Relaxed);
    let builder = if session {
        zbus::blocking::connection::Builder::session()?
    } else {
        zbus::blocking::connection::Builder::system()?
    };
    let conn = builder
        .name(BUS_NAME)?
        .serve_at(PATH, Service { d })?
        .build()?;

    let inner = conn.inner().clone();
    std::thread::Builder::new()
        .name("dbus-signals".into())
        .spawn(move || {
            let emitter = match SignalEmitter::new(&inner, PATH) {
                Ok(e) => e,
                Err(e) => {
                    log::error!("signal emitter: {e}");
                    return;
                }
            };
            for n in notices {
                let r = zbus::block_on(async {
                    match &n {
                        Notice::Threat(ev) => Service::threat_detected(&emitter, ev.id, ev.uid).await,
                        Notice::StatusChanged => Service::status_changed(&emitter).await,
                        Notice::ScanProgress { id, files, detections } => {
                            Service::scan_progress(&emitter, id, *files, *detections).await
                        }
                        Notice::ScanFinished { id } => Service::scan_finished(&emitter, id).await,
                    }
                });
                if let Err(e) = r {
                    log::debug!("signal: {e}");
                }
            }
        })
        .expect("spawn signal thread");
    Ok(conn)
}
