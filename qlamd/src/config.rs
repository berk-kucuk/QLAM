//! Daemon configuration: admin defaults from /etc/qlam/qlamd.toml, with
//! runtime overrides (set over D-Bus) persisted in the state database.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::schedule::{Depth, Frequency};

pub const CONFIG_FILE: &str = "/etc/qlam/qlamd.toml";
/// Rules and lists shipped with Qlam; QLAM_RULES_DIR overrides it for
/// development and tests.
pub fn bundled_rules_dir() -> PathBuf {
    std::env::var_os("QLAM_RULES_DIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/usr/share/qlam/rules"))
}

/// State directory (/var/lib/qlam). QLAM_STATE_DIR overrides it for
/// development; the systemd unit never sets it.
pub fn state_dir() -> PathBuf {
    std::env::var_os("QLAM_STATE_DIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/var/lib/qlam"))
}

pub fn quarantine_dir() -> PathBuf {
    state_dir().join("quarantine")
}

pub fn db_file() -> PathBuf {
    state_dir().join("qlam.db")
}

/// Feed directory; QLAM_FEEDS_DIR overrides it independently.
pub fn feeds_dir() -> PathBuf {
    std::env::var_os("QLAM_FEEDS_DIR").map(PathBuf::from).unwrap_or_else(|| state_dir().join("feeds"))
}

/// abuse.ch Auth-Key for the MalwareBazaar exports. abuse.ch made the key
/// mandatory (the keyless export URLs answer 410 Gone since late 2026). It
/// lives in the state directory, not /etc: the daemon writes it (from the
/// app, after polkit) and /etc is read-only to it. root:qlam 0640, so the
/// updater can read it and other users can't.
pub fn abusech_key_file() -> PathBuf {
    state_dir().join("abusech.key")
}

/// Keys are opaque tokens; this only keeps the value safe to put in a URL
/// path.
pub fn valid_abusech_key(key: &str) -> bool {
    (16..=128).contains(&key.len()) && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn abusech_key() -> Option<String> {
    let key = std::fs::read_to_string(abusech_key_file()).ok()?;
    let key = key.trim();
    valid_abusech_key(key).then(|| key.to_string())
}

/// Store the key, or remove it when `key` is empty.
pub fn save_abusech_key(key: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let path = abusech_key_file();
    if key.is_empty() {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    if !valid_abusech_key(key) {
        return Err(std::io::Error::other("this doesn't look like an abuse.ch Auth-Key"));
    }
    let tmp = path.with_extension("part");
    let _ = std::fs::remove_file(&tmp);
    let res = (|| {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o640).open(&tmp)?;
        // The session-bus development instance runs as the user and can't
        // (and needn't) hand the file to the qlam group.
        if unsafe { libc::geteuid() } == 0 {
            let gid = qlam_gid().ok_or_else(|| std::io::Error::other("no qlam group"))?;
            std::os::unix::fs::fchown(&f, Some(0), Some(gid))?;
        }
        f.write_all(key.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        std::fs::rename(&tmp, &path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

fn qlam_gid() -> Option<u32> {
    let grp = unsafe { libc::getgrnam(c"qlam".as_ptr()) };
    (!grp.is_null()).then(|| unsafe { (*grp).gr_gid })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// On-access protection (fanotify). Off means on-demand scans only.
    pub realtime: bool,
    /// Deny execution of *confirmed* detections (exact known-malware hash).
    /// Pattern matches are never blocked, only reported. Off by default:
    /// blocking needs fanotify permission events, which make every program
    /// start on the watched filesystems wait for Qlam's answer. Without it,
    /// executed files are still scanned and reported, just not stopped.
    pub block_exec: bool,
    /// Also move confirmed detections to quarantine without asking. Off by
    /// default: Qlam warns and the user decides.
    pub auto_quarantine: bool,
    /// Files larger than this are not scanned on access.
    pub max_file_size_mb: u64,
    /// Locations a user can write to. Everything outside is left alone:
    /// malware has to be written somewhere the user can write before it can
    /// run, and system directories are pacman's business.
    pub scope: Vec<String>,
    /// Path prefixes never scanned on access.
    pub exclude: Vec<String>,
    /// clamd socket. ClamAV is an optional extra engine: it costs ~1 GB of
    /// RAM, so it is only used when the admin runs clamav-daemon.
    pub clamd_socket: String,
    /// Worker threads for exec-time decisions.
    pub exec_workers: usize,
    /// Worker threads for post-write background scans.
    pub background_workers: usize,
    /// Watch running programs for what malware does (behavior.rs).
    pub behavior_monitor: bool,
    /// Scheduled scan of every user: "off", "daily" or "weekly".
    pub scheduled_scan: Frequency,
    /// What it covers: "quick" (downloads, desktop, startup entries, temp
    /// folders) or "home" (the whole home folder).
    pub scheduled_scan_depth: Depth,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            realtime: true,
            block_exec: false,
            auto_quarantine: false,
            max_file_size_mb: 50,
            scope: vec![
                "/home".into(),
                "/root".into(),
                "/tmp".into(),
                "/var/tmp".into(),
                "/dev/shm".into(),
                "/run/user".into(),
                "/run/media".into(),
                "/media".into(),
                "/mnt".into(),
            ],
            exclude: vec![state_dir().to_string_lossy().into_owned()],
            clamd_socket: "/run/clamav/clamd.ctl".into(),
            exec_workers: 2,
            background_workers: 1,
            behavior_monitor: true,
            scheduled_scan: Frequency::Weekly,
            scheduled_scan_depth: Depth::Quick,
        }
    }
}

impl Config {
    pub fn load() -> Config {
        Self::load_from(Path::new(CONFIG_FILE))
    }

    pub fn load_from(path: &Path) -> Config {
        let mut cfg = match std::fs::read_to_string(path) {
            Ok(text) => match toml::from_str::<Config>(&text) {
                Ok(c) => c,
                Err(e) => {
                    log::error!("{}: {e}; using defaults", path.display());
                    Config::default()
                }
            },
            Err(_) => Config::default(),
        };
        // The state directory holds live samples; scanning it on access would
        // re-detect every quarantined file forever.
        let state = state_dir().to_string_lossy().into_owned();
        if !cfg.exclude.contains(&state) {
            cfg.exclude.push(state);
        }
        cfg.exec_workers = cfg.exec_workers.clamp(1, 32);
        cfg.background_workers = cfg.background_workers.clamp(1, 16);
        cfg
    }

    pub fn max_file_size(&self) -> u64 {
        self.max_file_size_mb.saturating_mul(1024 * 1024)
    }
}

/// Fast path-prefix matcher for the scope and exclusion lists.
#[derive(Debug, Clone)]
pub struct Scope {
    include: Vec<PathBuf>,
    exclude: Vec<PathBuf>,
}

impl Scope {
    pub fn new(cfg: &Config) -> Scope {
        Scope {
            include: cfg.scope.iter().map(PathBuf::from).collect(),
            exclude: cfg.exclude.iter().map(PathBuf::from).collect(),
        }
    }

    pub fn roots(&self) -> &[PathBuf] {
        &self.include
    }

    /// `Path::starts_with` compares whole components, so /home2 never matches
    /// /home.
    pub fn contains(&self, path: &Path) -> bool {
        self.include.iter().any(|r| path.starts_with(r))
            && !self.exclude.iter().any(|e| path.starts_with(e))
    }
}
