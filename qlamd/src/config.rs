//! Daemon configuration: admin defaults from /etc/qlam/qlamd.toml, with
//! runtime overrides (set over D-Bus) persisted in the state database.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const CONFIG_FILE: &str = "/etc/qlam/qlamd.toml";
pub const BUNDLED_RULES_DIR: &str = "/usr/share/qlam/rules";

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// On-access protection (fanotify). Off means on-demand scans only.
    pub realtime: bool,
    /// Deny execution of *confirmed* detections (exact known-malware hash).
    /// Pattern matches are never blocked, only reported.
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
}

impl Default for Config {
    fn default() -> Self {
        Config {
            realtime: true,
            block_exec: true,
            auto_quarantine: false,
            max_file_size_mb: 100,
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
            exec_workers: 4,
            background_workers: 2,
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
