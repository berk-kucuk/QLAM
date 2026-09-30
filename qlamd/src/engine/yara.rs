//! YARA rules through yara-x (memory-safe, which matters in a root daemon that
//! parses attacker-controlled files).
//!
//! Severity comes from rule metadata:
//!   - `qlam_severity = "malicious" | "suspicious"` on Qlam's bundled rules,
//!     plus `qlam_confirmed = true` on the few rules that identify a file
//!     exactly (the EICAR test file) rather than by pattern;
//!   - YARA Forge's `score` (0-100) on feed rules: 90 and up is malicious,
//!     70 and up suspicious; lower-scored and unscored feed rules are
//!     ignored, since they are the ones that fire on legitimate files.

use std::path::{Path, PathBuf};
use std::time::Duration;

use yara_x::{Compiler, MetaValue, Rules, Scanner};

use super::{Match, Severity};
use crate::config::{feeds_dir, BUNDLED_RULES_DIR};

const SCAN_TIMEOUT: Duration = Duration::from_secs(5);

/// Namespace prefix of the rules shipped with Qlam.
const BUNDLED_PREFIX: &str = "qlam_";

pub struct YaraRules {
    rules: Option<Rules>,
    count: usize,
}

impl YaraRules {
    pub fn load_default() -> YaraRules {
        let mut files: Vec<(PathBuf, bool)> = rule_files(Path::new(BUNDLED_RULES_DIR)).into_iter().map(|p| (p, true)).collect();
        // Development fallback: rules next to the source tree.
        if files.is_empty() {
            let dev = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/rules"));
            files.extend(rule_files(dev).into_iter().map(|p| (p, true)));
        }
        files.extend(rule_files(&feeds_dir()).into_iter().map(|p| (p, false)));
        Self::load_files(&files)
    }

    /// `(path, bundled)`: only bundled files may carry `qlam_confirmed`, and
    /// that is decided by where the file came from, never by its name.
    pub fn load_files(files: &[(PathBuf, bool)]) -> YaraRules {
        let mut compiler = Compiler::new();
        let mut loaded = 0;
        for (path, bundled) in files {
            let Ok(src) = std::fs::read_to_string(path) else { continue };
            // One broken feed file must not take the bundled rules down with
            // it, so each file is test-compiled on its own first.
            if let Err(e) = check_source(&src) {
                log::warn!("yara: skipping {}: {e}", path.display());
                continue;
            }
            let prefix = if *bundled { BUNDLED_PREFIX } else { "feed_" };
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("rules").replace(['-', '.'], "_");
            let ns = format!("{prefix}{stem}");
            compiler.new_namespace(&ns);
            match compiler.add_source(src.as_str()) {
                Ok(_) => loaded += 1,
                Err(e) => log::warn!("yara: {}: {e}", path.display()),
            }
        }
        let rules = compiler.build();
        let count = rules.iter().count();
        log::info!("yara: {count} rules from {loaded} files");
        YaraRules { rules: (count > 0).then_some(rules), count }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    /// Strongest match, if any.
    pub fn scan(&self, data: &[u8]) -> Option<Match> {
        let rules = self.rules.as_ref()?;
        let mut scanner = Scanner::new(rules);
        scanner.set_timeout(SCAN_TIMEOUT);
        let results = match scanner.scan(data) {
            Ok(r) => r,
            Err(e) => {
                log::debug!("yara scan: {e}");
                return None;
            }
        };
        let mut best: Option<Match> = None;
        for rule in results.matching_rules() {
            if !rule.namespace().starts_with(BUNDLED_PREFIX) && is_test_file_rule(rule.identifier()) {
                continue;
            }
            let mut severity = None;
            let mut confirmed = false;
            let mut score = None;
            let mut name = None;
            for (key, value) in rule.metadata() {
                match (key, value) {
                    ("qlam_severity", MetaValue::String(s)) => {
                        severity = match s {
                            "malicious" => Some(Severity::Malicious),
                            "suspicious" => Some(Severity::Suspicious),
                            _ => None,
                        }
                    }
                    ("qlam_name", MetaValue::String(s)) => name = Some(s.to_string()),
                    ("qlam_confirmed", MetaValue::Bool(b)) => confirmed = b,
                    ("score", MetaValue::Integer(i)) => score = Some(i),
                    _ => {}
                }
            }
            let severity = match (severity, score) {
                (Some(s), _) => s,
                (None, Some(s)) if s >= 90 => Severity::Malicious,
                (None, Some(s)) if s >= 70 => Severity::Suspicious,
                // Low scores are hunting rules, and a rule with no score gives
                // us nothing to judge its false-positive rate by.
                _ => continue,
            };
            let name = name.unwrap_or_else(|| format!("YARA.{}", rule.identifier()));
            // Only Qlam's own curated rules may claim an exact identification.
            let confirmed = confirmed && rule.namespace().starts_with(BUNDLED_PREFIX);
            let better = match &best {
                None => true,
                Some(b) => (severity, confirmed) > (b.severity, b.confirmed),
            };
            if better {
                best = Some(Match { severity, confirmed, name });
            }
        }
        best
    }
}

/// Feed rules for anti-malware test files (EICAR) match the test string
/// anywhere in a file, so they fire on documentation, chat caches and browser
/// memory that merely mention it — seen on 2026-09-30 in Chromium shared
/// memory. The bundled Qlam_Test_EICAR rule covers the real test file (the
/// string at offset 0 of a tiny file), so feed ones are ignored.
pub fn is_test_file_rule(identifier: &str) -> bool {
    identifier.to_ascii_lowercase().contains("eicar")
}

pub fn check_source(src: &str) -> Result<(), String> {
    let mut c = Compiler::new();
    c.add_source(src).map(|_| ()).map_err(|e| e.to_string())
}

fn rule_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut v: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "yar" || e == "yara"))
        .collect();
    v.sort();
    v
}
