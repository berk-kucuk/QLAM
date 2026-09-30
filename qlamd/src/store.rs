//! Persistent state: detection events, quarantine index, scan history,
//! allowlist and runtime settings, in one SQLite database under
//! /var/lib/qlam (root-only, so none of it is user-editable input).

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Event {
    pub id: i64,
    pub ts: i64,
    /// "blocked", "quarantined", "warning", "suspicious", "persistence",
    /// "safety-pause".
    pub kind: String,
    pub path: String,
    /// Owner of the file (or of the process, for exec events).
    pub uid: u32,
    pub severity: String,
    /// Exact identification (hash match), not a pattern match.
    pub confirmed: bool,
    pub detection: String,
    pub engine: String,
    pub sha256: String,
    /// Process that triggered it, when known ("firefox[1234]").
    pub process: String,
    /// What was done, in words, e.g. "execution blocked, moved to quarantine".
    pub action: String,
    /// How it was settled: "" (open), "quarantined" or "trusted" by the
    /// user, or "gone" when the file no longer exists.
    pub resolution: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct QuarantineItem {
    pub id: String,
    pub ts: i64,
    pub original_path: String,
    pub sha256: String,
    pub size: i64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub detection: String,
    pub engine: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanRecord {
    pub id: String,
    pub uid: u32,
    pub kind: String,
    pub targets: Vec<String>,
    pub started: i64,
    pub finished: i64,
    pub files: i64,
    pub detections: i64,
    pub suspicious: i64,
    pub errors: i64,
    /// "running", "finished", "cancelled", "failed".
    pub status: String,
}

pub struct Store {
    db: Mutex<Connection>,
    allow: RwLock<HashSet<String>>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL, kind TEXT NOT NULL, path TEXT NOT NULL, uid INTEGER NOT NULL,
    severity TEXT NOT NULL, confirmed INTEGER NOT NULL, detection TEXT NOT NULL, engine TEXT NOT NULL,
    sha256 TEXT NOT NULL, process TEXT NOT NULL, action TEXT NOT NULL,
    resolution TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS events_uid_ts ON events(uid, ts);
CREATE TABLE IF NOT EXISTS quarantine (
    id TEXT PRIMARY KEY, ts INTEGER NOT NULL, original_path TEXT NOT NULL,
    sha256 TEXT NOT NULL, size INTEGER NOT NULL, uid INTEGER NOT NULL,
    gid INTEGER NOT NULL, mode INTEGER NOT NULL, detection TEXT NOT NULL, engine TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY, uid INTEGER NOT NULL, kind TEXT NOT NULL, targets TEXT NOT NULL,
    started INTEGER NOT NULL, finished INTEGER NOT NULL, files INTEGER NOT NULL,
    detections INTEGER NOT NULL, suspicious INTEGER NOT NULL, errors INTEGER NOT NULL,
    status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS allowlist (sha256 TEXT PRIMARY KEY, ts INTEGER NOT NULL, note TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

/// Events older than this are pruned at startup.
const EVENT_RETENTION_SECS: i64 = 180 * 24 * 3600;

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Store> {
        let db = Connection::open(path)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "NORMAL")?;
        db.execute_batch(SCHEMA)?;
        // Databases created before the resolution column existed.
        let _ = db.execute("ALTER TABLE events ADD COLUMN resolution TEXT NOT NULL DEFAULT ''", []);
        db.execute("DELETE FROM events WHERE ts < ?1", params![now() - EVENT_RETENTION_SECS])?;
        // A scan still "running" at startup died with the previous process.
        db.execute("UPDATE scans SET status = 'failed' WHERE status = 'running'", [])?;
        let allow = {
            let mut stmt = db.prepare("SELECT sha256 FROM allowlist")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            rows.collect::<Result<HashSet<_>, _>>()?
        };
        Ok(Store { db: Mutex::new(db), allow: RwLock::new(allow) })
    }

    pub fn in_memory() -> Store {
        let db = Connection::open_in_memory().expect("sqlite in memory");
        db.execute_batch(SCHEMA).expect("schema");
        Store { db: Mutex::new(db), allow: RwLock::new(HashSet::new()) }
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|p| p.into_inner())
    }

    // ── Allowlist ────────────────────────────────────────────────────────

    pub fn is_allowlisted(&self, sha256: &str) -> bool {
        self.allow.read().unwrap_or_else(|p| p.into_inner()).contains(sha256)
    }

    pub fn allowlist_add(&self, sha256: &str, note: &str) {
        let r = self.conn().execute(
            "INSERT OR REPLACE INTO allowlist (sha256, ts, note) VALUES (?1, ?2, ?3)",
            params![sha256, now(), note],
        );
        if let Err(e) = r {
            log::error!("allowlist: {e}");
        }
        self.allow.write().unwrap_or_else(|p| p.into_inner()).insert(sha256.to_string());
    }

    // ── Events ───────────────────────────────────────────────────────────

    pub fn add_event(&self, e: &Event) -> i64 {
        let db = self.conn();
        let r = db.execute(
            "INSERT INTO events (ts, kind, path, uid, severity, confirmed, detection, engine, sha256, process, action)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![e.ts, e.kind, e.path, e.uid, e.severity, e.confirmed, e.detection, e.engine, e.sha256, e.process, e.action],
        );
        match r {
            Ok(_) => db.last_insert_rowid(),
            Err(err) => {
                log::error!("event insert: {err}");
                0
            }
        }
    }

    /// `uid = None` lists everyone's events (admin view).
    pub fn events(&self, uid: Option<u32>, limit: u32) -> Vec<Event> {
        let db = self.conn();
        let sql = format!("SELECT {EVENT_COLS} FROM events WHERE (?1 IS NULL OR uid = ?1) ORDER BY id DESC LIMIT ?2");
        let Ok(mut stmt) = db.prepare(&sql) else { return Vec::new() };
        let rows = stmt.query_map(params![uid, limit], row_to_event);
        rows.map(|it| it.flatten().collect()).unwrap_or_default()
    }

    pub fn event(&self, id: i64) -> Option<Event> {
        let sql = format!("SELECT {EVENT_COLS} FROM events WHERE id = ?1");
        self.conn().query_row(&sql, params![id], row_to_event).optional().ok().flatten()
    }

    pub fn threat_count(&self, uid: Option<u32>, since: i64) -> i64 {
        self.conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE (?1 IS NULL OR uid = ?1) AND ts >= ?2
                 AND severity = 'malicious'",
                params![uid, since],
                |r| r.get(0),
            )
            .unwrap_or(0)
    }

    /// Findings the user hasn't settled yet (one per file and detection).
    pub fn open_count(&self, uid: Option<u32>) -> i64 {
        self.conn()
            .query_row(
                "SELECT COUNT(*) FROM (SELECT DISTINCT path, detection FROM events
                 WHERE (?1 IS NULL OR uid = ?1) AND resolution = ''
                 AND kind IN ('blocked', 'warning', 'suspicious', 'persistence'))",
                params![uid],
                |r| r.get(0),
            )
            .unwrap_or(0)
    }

    /// Settle every open finding about the same content (or, for content-less
    /// findings, the same path and detection) as `ev`.
    pub fn resolve(&self, ev: &Event, resolution: &str) {
        let r = if ev.sha256.is_empty() {
            self.conn().execute(
                "UPDATE events SET resolution = ?1 WHERE resolution = '' AND path = ?2 AND detection = ?3",
                params![resolution, ev.path, ev.detection],
            )
        } else {
            self.conn().execute(
                "UPDATE events SET resolution = ?1 WHERE resolution = '' AND sha256 = ?2",
                params![resolution, ev.sha256],
            )
        };
        if let Err(e) = r {
            log::error!("resolve: {e}");
        }
    }

    /// Paths of open findings, one per path.
    pub fn open_paths(&self) -> Vec<String> {
        let db = self.conn();
        let Ok(mut stmt) = db.prepare(
            "SELECT DISTINCT path FROM events WHERE resolution = ''
             AND kind IN ('blocked', 'warning', 'suspicious', 'persistence')",
        ) else {
            return Vec::new();
        };
        let rows = stmt.query_map([], |r| r.get::<_, String>(0));
        rows.map(|it| it.flatten().collect()).unwrap_or_default()
    }

    /// Settle every open finding about `path` as `resolution`.
    pub fn resolve_path(&self, path: &str, resolution: &str) {
        let r = self.conn().execute(
            "UPDATE events SET resolution = ?1 WHERE resolution = '' AND path = ?2",
            params![resolution, path],
        );
        if let Err(e) = r {
            log::error!("resolve: {e}");
        }
    }

    // ── Quarantine ───────────────────────────────────────────────────────

    pub fn quarantine_add(&self, q: &QuarantineItem) -> rusqlite::Result<()> {
        self.conn().execute(
            "INSERT INTO quarantine (id, ts, original_path, sha256, size, uid, gid, mode, detection, engine)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![q.id, q.ts, q.original_path, q.sha256, q.size, q.uid, q.gid, q.mode, q.detection, q.engine],
        )?;
        Ok(())
    }

    pub fn quarantine_list(&self, uid: Option<u32>) -> Vec<QuarantineItem> {
        let db = self.conn();
        let Ok(mut stmt) = db.prepare(
            "SELECT id, ts, original_path, sha256, size, uid, gid, mode, detection, engine
             FROM quarantine WHERE (?1 IS NULL OR uid = ?1) ORDER BY ts DESC",
        ) else {
            return Vec::new();
        };
        let rows = stmt.query_map(params![uid], row_to_quarantine);
        rows.map(|it| it.flatten().collect()).unwrap_or_default()
    }

    pub fn quarantine_get(&self, id: &str) -> Option<QuarantineItem> {
        self.conn()
            .query_row(
                "SELECT id, ts, original_path, sha256, size, uid, gid, mode, detection, engine
                 FROM quarantine WHERE id = ?1",
                params![id],
                row_to_quarantine,
            )
            .optional()
            .ok()
            .flatten()
    }

    pub fn quarantine_remove(&self, id: &str) {
        let _ = self.conn().execute("DELETE FROM quarantine WHERE id = ?1", params![id]);
    }

    // ── Scans ────────────────────────────────────────────────────────────

    pub fn scan_save(&self, s: &ScanRecord) {
        let targets = serde_json::to_string(&s.targets).unwrap_or_default();
        let r = self.conn().execute(
            "INSERT OR REPLACE INTO scans (id, uid, kind, targets, started, finished, files, detections, suspicious, errors, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![s.id, s.uid, s.kind, targets, s.started, s.finished, s.files, s.detections, s.suspicious, s.errors, s.status],
        );
        if let Err(e) = r {
            log::error!("scan save: {e}");
        }
    }

    pub fn scans(&self, uid: Option<u32>, limit: u32) -> Vec<ScanRecord> {
        let db = self.conn();
        let Ok(mut stmt) = db.prepare(
            "SELECT id, uid, kind, targets, started, finished, files, detections, suspicious, errors, status
             FROM scans WHERE (?1 IS NULL OR uid = ?1) ORDER BY started DESC LIMIT ?2",
        ) else {
            return Vec::new();
        };
        let rows = stmt.query_map(params![uid, limit], |r| {
            let targets: String = r.get(3)?;
            Ok(ScanRecord {
                id: r.get(0)?,
                uid: r.get(1)?,
                kind: r.get(2)?,
                targets: serde_json::from_str(&targets).unwrap_or_default(),
                started: r.get(4)?,
                finished: r.get(5)?,
                files: r.get(6)?,
                detections: r.get(7)?,
                suspicious: r.get(8)?,
                errors: r.get(9)?,
                status: r.get(10)?,
            })
        });
        rows.map(|it| it.flatten().collect()).unwrap_or_default()
    }

    // ── Settings ─────────────────────────────────────────────────────────

    pub fn setting(&self, key: &str) -> Option<String> {
        self.conn()
            .query_row("SELECT value FROM settings WHERE key = ?1", params![key], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
    }

    pub fn set_setting(&self, key: &str, value: &str) {
        let _ = self.conn().execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        );
    }
}

const EVENT_COLS: &str =
    "id, ts, kind, path, uid, severity, confirmed, detection, engine, sha256, process, action, resolution";

fn row_to_event(r: &rusqlite::Row<'_>) -> rusqlite::Result<Event> {
    Ok(Event {
        id: r.get(0)?,
        ts: r.get(1)?,
        kind: r.get(2)?,
        path: r.get(3)?,
        uid: r.get(4)?,
        severity: r.get(5)?,
        confirmed: r.get(6)?,
        detection: r.get(7)?,
        engine: r.get(8)?,
        sha256: r.get(9)?,
        process: r.get(10)?,
        action: r.get(11)?,
        resolution: r.get(12)?,
    })
}

fn row_to_quarantine(r: &rusqlite::Row<'_>) -> rusqlite::Result<QuarantineItem> {
    Ok(QuarantineItem {
        id: r.get(0)?,
        ts: r.get(1)?,
        original_path: r.get(2)?,
        sha256: r.get(3)?,
        size: r.get(4)?,
        uid: r.get(5)?,
        gid: r.get(6)?,
        mode: r.get(7)?,
        detection: r.get(8)?,
        engine: r.get(9)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(path: &str, kind: &str) -> Event {
        Event { ts: now(), kind: kind.into(), path: path.into(), severity: "suspicious".into(), ..Default::default() }
    }

    #[test]
    fn findings_about_a_path_can_be_settled_together() {
        let s = Store::in_memory();
        s.add_event(&finding("/tmp/a", "warning"));
        s.add_event(&finding("/tmp/a", "suspicious"));
        s.add_event(&finding("/tmp/b", "warning"));
        s.add_event(&finding("/tmp/c", "quarantined")); // not a finding to decide on
        let mut open = s.open_paths();
        open.sort();
        assert_eq!(open, ["/tmp/a", "/tmp/b"]);

        s.resolve_path("/tmp/a", "gone");
        assert_eq!(s.open_paths(), ["/tmp/b"]);
        assert_eq!(s.open_count(None), 1);
        assert!(s.events(None, 10).iter().filter(|e| e.path == "/tmp/a").all(|e| e.resolution == "gone"));
    }
}
