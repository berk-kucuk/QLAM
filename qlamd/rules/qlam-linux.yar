/*
 * Qlam bundled rules — Linux threats seen in user-writable locations.
 *
 * Every rule sets:
 *   qlam_severity  "malicious"  → warning, shown prominently
 *                  "suspicious" → low-key notice
 *   qlam_name      detection name shown to the user
 *
 * Pattern rules are never acted on automatically; only `qlam_confirmed = true`
 * (reserved for exact identifications such as EICAR) may block execution.
 * Never set it on a pattern rule.
 *
 * Keep these conservative: a false warning on a user's own file costs their
 * trust in every later warning. When in doubt, a rule is "suspicious".
 */

import "elf"

private rule is_elf
{
    condition:
        uint32(0) == 0x464c457f
}

// Script rules require an interpreter line. Without it they match source
// code, notes and rule files (this one included) that merely contain the
// commands they look for.
private rule is_script
{
    condition:
        uint16(0) == 0x2123   // "#!"
}

rule Qlam_Test_EICAR
{
    meta:
        qlam_severity = "malicious"
        qlam_name = "Qlam.Test.EICAR"
        qlam_confirmed = true
        description = "EICAR anti-malware test file"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar at 0 and filesize < 256
}

rule Qlam_Linux_Miner_XMRig
{
    meta:
        qlam_severity = "suspicious"
        qlam_name = "Qlam.PUA.Linux.Miner.XMRig"
        description = "XMRig cryptocurrency miner. Legitimate if you installed it yourself; commonly dropped by intruders."
    strings:
        $a1 = "xmrig" ascii nocase
        $a2 = "donate-level" ascii
        $a3 = "randomx" ascii nocase
        $s1 = "stratum+tcp://" ascii
        $s2 = "stratum+ssl://" ascii
        $s3 = "cryptonight" ascii nocase
    condition:
        is_elf and filesize < 20MB and 2 of ($a*) and 1 of ($s*)
}

rule Qlam_Linux_Miner_Dropper_Script
{
    meta:
        qlam_severity = "malicious"
        qlam_name = "Qlam.Linux.Miner.Dropper"
        description = "Shell script that fetches and launches a miner while hiding it and removing competitors"
    strings:
        $fetch1 = /(curl|wget)[^\n]{1,200}(xmrig|kinsing|kdevtmpfsi|\.x86_64|xmr)/ nocase
        $pool = /(stratum\+(tcp|ssl)|pool\.(supportxmr|minexmr|hashvault)|xmrpool|nanopool\.org|c3pool)/ nocase
        $kill1 = /pkill\s+-9?\s*-?f?\s*(xmrig|kinsing|kdevtmpfsi|minerd|cryptonight)/ nocase
        $kill2 = "chattr -i" ascii
        $hide1 = "history -c" ascii
        $hide2 = /\/(tmp|var\/tmp|dev\/shm)\/\.[a-z0-9]{1,16}/ ascii
    condition:
        is_script and filesize < 1MB and ($fetch1 or $pool) and ($kill1 or $kill2) and 1 of ($hide*)
}

rule Qlam_Linux_Mirai
{
    meta:
        qlam_severity = "malicious"
        qlam_name = "Qlam.Linux.Botnet.Mirai"
        description = "Mirai-family IoT botnet"
    strings:
        $m1 = "/bin/busybox MIRAI" ascii
        $m2 = "MIRAI: applet not found" ascii
        $s1 = "TSource Engine Query" ascii
        $s2 = "/dev/watchdog" ascii
        $s3 = "/dev/misc/watchdog" ascii
        $s4 = "/bin/busybox ECCHI" ascii
        $s5 = "/proc/net/tcp" ascii
    condition:
        is_elf and filesize < 5MB and (1 of ($m*) or ($s1 and $s2 and $s3 and ($s4 or $s5)))
}

rule Qlam_Linux_Gafgyt
{
    meta:
        qlam_severity = "malicious"
        qlam_name = "Qlam.Linux.Botnet.Gafgyt"
        description = "Gafgyt/Bashlite IoT botnet"
    strings:
        $c1 = "PONG!" ascii
        $c2 = "GETLOCALIP" ascii
        $c3 = "KILLATTK" ascii
        $c4 = "LOLNOGTFO" ascii
        $c5 = "HTTPFLOOD" ascii
        $c6 = "UDPRAW" ascii
        $c7 = "STD" ascii fullword
    condition:
        is_elf and filesize < 5MB and 4 of them
}

rule Qlam_Linux_Preload_Rootkit
{
    meta:
        qlam_severity = "malicious"
        qlam_name = "Qlam.Linux.Rootkit.LdPreload"
        description = "Userland rootkit that hides processes/files by hooking readdir and installs itself through ld.so.preload"
    strings:
        $preload = "/etc/ld.so.preload" ascii
        $h1 = "readdir64" ascii
        $h2 = "readdir" ascii fullword
        $dl = "dlsym" ascii
        $hide1 = "process_to_filter" ascii
        $hide2 = /\/proc\/(self|%d)\/(stat|cmdline)/ ascii
        $hide3 = "hide" ascii nocase
    condition:
        is_elf and filesize < 2MB and elf.type == elf.ET_DYN
        and $dl and 1 of ($h*)
        and ($hide1 or ($preload and $hide2 and $hide3))
}

rule Qlam_Linux_ReverseShell_Script
{
    meta:
        qlam_severity = "suspicious"
        qlam_name = "Qlam.Linux.HackTool.ReverseShell"
        description = "Script that opens an interactive reverse shell. Common in pentest material; malicious when found in a startup file."
    strings:
        $r1 = /(bash|sh)\s+-i\s*>&\s*\/dev\/tcp\/[0-9a-zA-Z.\-]{1,64}\/[0-9]{1,5}/
        $r2 = /nc(at)?\s+(-[a-z]+\s+)*[0-9a-zA-Z.\-]{1,64}\s+[0-9]{1,5}\s+-e\s+\/bin\/(ba)?sh/
        $r3 = /socket\.socket\([^)]*\)[^\n]{0,200}\n[^\n]{0,200}connect\(\([^)]*\)\)[\s\S]{0,400}(pty\.spawn|subprocess\.call\(\[?["']\/bin\/(ba)?sh)/
        $r4 = /mkfifo\s+\/tmp\/[a-z0-9]{1,16};\s*(cat|nc)[^\n]{0,80}\/bin\/(ba)?sh/
    condition:
        // Documentation, notes, pentest tool data (nmap .nse) and source code
        // mention these commands all the time and must not be flagged.
        is_script and filesize < 512KB and any of them
}

rule Qlam_Linux_Downloader_Pipe_Shell_Hidden
{
    meta:
        qlam_severity = "suspicious"
        qlam_name = "Qlam.Linux.Downloader.PipeToShell"
        description = "Downloads and runs code from a raw IP or paste site, with output silenced"
    strings:
        $d1 = /(curl|wget)\s+[^\n|]{0,64}https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[^\n|]{0,120}\|\s*(ba)?sh/
        $d2 = /(curl|wget)\s+[^\n|]{0,64}https?:\/\/(pastebin\.com\/raw|transfer\.sh|temp\.sh|[a-z0-9]+\.ngrok[a-z.-]*)[^\n|]{0,120}\|\s*(ba)?sh/
        $d3 = /echo\s+[A-Za-z0-9+\/=]{40,}\s*\|\s*base64\s+-d\s*\|\s*(ba)?sh/
    condition:
        is_script and filesize < 1MB and any of them
}

rule Qlam_PHP_Webshell_Generic
{
    meta:
        qlam_severity = "suspicious"
        qlam_name = "Qlam.PHP.Webshell.Generic"
        description = "PHP that evaluates request input directly"
    strings:
        $php = "<?php" nocase
        $e1 = /(eval|assert|system|passthru|shell_exec|exec|popen)\s*\(\s*(base64_decode\s*\(\s*)?\$_(POST|GET|REQUEST|COOKIE|SERVER\[['"]HTTP_)/ nocase
        $e2 = /preg_replace\s*\(\s*['"]\/[^'"]*\/e['"]\s*,\s*\$_(POST|GET|REQUEST)/ nocase
    condition:
        // The PHP must open the file: payload strings quoted inside other
        // programs (scanners, WAF tests) are not webshells.
        filesize < 1MB and $php in (0..256) and any of ($e*)
}

rule Qlam_Linux_Ransom_Note_Encryptor
{
    meta:
        qlam_severity = "malicious"
        qlam_name = "Qlam.Linux.Ransomware.Generic"
        description = "ELF that walks the filesystem, encrypts files and drops a ransom note"
    strings:
        $n1 = /(your|all) files (have been|are) encrypted/ nocase
        $n2 = /(bitcoin|btc|monero|xmr) (wallet|address)/ nocase
        $n3 = "README" ascii
        $c1 = "EVP_EncryptInit" ascii
        $c2 = "chacha20" ascii nocase
        $c3 = "Salsa20" ascii
        $c4 = "crypto/aes" ascii
        $w1 = "opendir" ascii fullword
        $w2 = "readdir" ascii
        $w3 = "filepath.Walk" ascii
        $w4 = "WalkDir" ascii
    condition:
        is_elf and filesize < 30MB and $n1 and ($n2 or $n3) and 1 of ($c*) and 1 of ($w*)
}

// ── IoT and server botnets ──────────────────────────────────────────────

rule Qlam_Linux_Tsunami_Kaiten
{
    meta:
        qlam_severity = "malicious"
        qlam_name = "Qlam.Linux.Botnet.Tsunami"
        description = "Tsunami/Kaiten IRC flooding bot"
    strings:
        $k1 = "Kaiten wa goraku" ascii
        $n1 = "NOTICE %s :" ascii
        $c1 = "GETSPOOFS" ascii
        $c2 = "KILLALL" ascii fullword
        $c3 = "TSUNAMI" ascii fullword
        $c4 = "UNKNOWN" ascii fullword
        $c5 = "SPOOFS" ascii fullword
    condition:
        is_elf and filesize < 5MB and ($k1 or ($n1 and $c1 and 2 of ($c2, $c3, $c4, $c5)))
}

rule Qlam_Linux_XorDDoS
{
    meta:
        qlam_severity = "malicious"
        qlam_name = "Qlam.Linux.Botnet.XorDDoS"
        description = "XorDDoS DDoS bot (XOR-encrypted configuration, cron and init persistence)"
    strings:
        $key = "BB2FA36AAA9541F0" ascii
        $p1 = "/var/run/gcc.pid" ascii
        $p2 = "/lib/libudev.so" ascii
        $p3 = "/etc/cron.hourly/gcc.sh" ascii
        $p4 = "/etc/cron.hourly/cron.sh" ascii
    condition:
        is_elf and filesize < 5MB and ($key or 2 of ($p*))
}

rule Qlam_Linux_Mozi
{
    meta:
        qlam_severity = "malicious"
        qlam_name = "Qlam.Linux.Botnet.Mozi"
        description = "Mozi peer-to-peer IoT botnet (DHT-based, Mirai/Gafgyt code)"
    strings:
        $cfg1 = "[ss]" ascii
        $cfg2 = "[hp]" ascii
        $cfg3 = "[dip]" ascii
        $cfg4 = "[idp]" ascii
        $dht1 = "dht.transmissionbt.com" ascii
        $dht2 = "router.bittorrent.com" ascii
        $dht3 = "router.utorrent.com" ascii
    condition:
        // DHT bootstrap hosts alone are any torrent client; the bracketed
        // configuration keys are Mozi's.
        is_elf and filesize < 2MB and 3 of ($cfg*) and 1 of ($dht*)
}

rule Qlam_Linux_BPFDoor
{
    meta:
        qlam_severity = "malicious"
        qlam_name = "Qlam.Linux.Backdoor.BPFDoor"
        description = "BPFDoor passive backdoor: waits for a magic packet through a BPF filter, disguised as a system daemon"
    strings:
        $f1 = "/var/run/haldrund.pid" ascii
        $f2 = "/dev/shm/kdmtmpflush" ascii
        $f3 = "/var/run/kdevrund.pid" ascii
        $m1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii
        $m2 = "avahi-daemon: chroot helper" ascii
        $m3 = "dbus-daemon --system" ascii
        $m4 = "qmgr -l -t fifo -u" ascii
    condition:
        // The masquerade names are only suspicious together: one binary
        // posing as several system daemons.
        is_elf and filesize < 5MB and (1 of ($f*) or ($m1 and 1 of ($m2, $m3, $m4)) or 3 of ($m*))
}

rule Qlam_Linux_Bot_Loader_Script
{
    meta:
        qlam_severity = "malicious"
        qlam_name = "Qlam.Linux.Downloader.BotLoader"
        description = "Loader that fetches the same bot for many CPU architectures and runs each one (Mirai/Gafgyt style bins.sh)"
    strings:
        $dl = /(wget|curl|tftp|ftpget)[^\n]{0,120}[\/ ](mips|mpsl|mipsel|arm[4-7]?|x86|x86_64|i[3-6]86|ppc|sh4|m68k|spc|sparc|arc)(\s|;|$)/
        $chmod = /chmod\s+(777|\+x|755)/
    condition:
        // These loaders often have no #! line, so it's the repetition that
        // marks them: three or more architecture downloads in a small file
        // that starts with them. Real ones are a few KB of nothing else;
        // source code and notes that quote such lines (Qlam's own tests
        // were flagged inside its source tarball, 2026-11-08) are bigger
        // and start with something else.
        filesize < 8KB and not is_elf and #dl >= 3 and $chmod and @dl[1] < 512
}

// ── Cryptojacking and cloud attacks ─────────────────────────────────────

rule Qlam_Linux_Kinsing_Dropper
{
    meta:
        qlam_severity = "malicious"
        qlam_name = "Qlam.Linux.Miner.Kinsing"
        description = "Kinsing dropper script: installs the kdevtmpfsi miner and the kinsing backdoor"
    strings:
        $k1 = "kdevtmpfsi" ascii
        $k2 = "kinsing" ascii
        $dl = /(curl|wget|\$WGET|\$CURL)\s/
        $x = /chmod\s+(\+x|777|755)/
    condition:
        is_script and filesize < 512KB and $k1 and $k2 and $dl and $x
}

rule Qlam_Linux_TeamTNT_Script
{
    meta:
        qlam_severity = "malicious"
        qlam_name = "Qlam.Linux.Miner.TeamTNT"
        description = "TeamTNT script: cloud credential theft, miners and container escape tooling"
    strings:
        $t = "teamtnt" ascii nocase
        $dl = /(curl|wget)\s/
    condition:
        is_script and filesize < 1MB and $t and $dl
}

rule Qlam_Linux_Cloud_Credential_Stealer_Script
{
    meta:
        qlam_severity = "suspicious"
        qlam_name = "Qlam.Linux.Stealer.CloudCredentials"
        description = "Script that collects cloud and container credentials and uploads them"
    strings:
        $c1 = ".aws/credentials" ascii
        $c2 = ".docker/config.json" ascii
        $c3 = ".kube/config" ascii
        $c4 = "application_default_credentials.json" ascii
        $c5 = "169.254.169.254/latest/meta-data/iam/security-credentials" ascii
        $c6 = ".git-credentials" ascii
        $up1 = /curl[^\n]{0,160}\s(-F|--form)\s*["']?[A-Za-z0-9_\-]{0,32}=@/
        $up2 = /curl[^\n]{0,160}\s(--data-binary|--data|-d)\s*["']?@/
        $up3 = /curl[^\n]{0,160}\s(-T|--upload-file)\s/
        $up4 = /wget[^\n]{0,160}--post-file/
    condition:
        is_script and filesize < 1MB and 2 of ($c*) and 1 of ($up*)
}

rule Qlam_Linux_Miner_Config
{
    meta:
        qlam_severity = "suspicious"
        qlam_name = "Qlam.PUA.Linux.Miner.Config"
        description = "XMRig-style miner configuration. Legitimate if you set up mining yourself."
    strings:
        $d = "\"donate-level\"" ascii
        $p = "\"pools\"" ascii
        $u1 = "stratum+" ascii
        $u2 = /"url"\s*:\s*"[a-z0-9.\-]{3,64}:(3333|4444|5555|7777|10128|14444|45700)"/
    condition:
        uint8(0) == 0x7B and filesize < 64KB and $d and $p and 1 of ($u*)
}

// ── Backdoors and persistence ───────────────────────────────────────────

rule Qlam_Linux_SSH_Key_Lockin_Script
{
    meta:
        qlam_severity = "malicious"
        qlam_name = "Qlam.Linux.Backdoor.SshKeyInjector"
        description = "Script that adds an SSH key to authorized_keys and makes the file immutable so it can't be removed"
    strings:
        $add = /(echo|printf)\s+["']?ssh-(rsa|ed25519|dss|ecdsa-sha2-nistp256)\s+AAAA[A-Za-z0-9+\/=]{60,}[^\n]{0,200}>>?\s*[^\n]{0,80}authorized_keys/
        $lock = /chattr\s+[+-]?[ai]{1,2}\s+[^\n]{0,80}(authorized_keys|\.ssh)/
    condition:
        is_script and filesize < 1MB and $add and $lock
}

rule Qlam_Perl_ShellBot
{
    meta:
        qlam_severity = "malicious"
        qlam_name = "Qlam.Perl.Backdoor.ShellBot"
        description = "Perl IRC bot (ShellBot) that runs commands and floods on order"
    strings:
        $irc = "PRIVMSG" ascii
        $sock = "IO::Socket::INET" ascii
        $v1 = "@adms" ascii
        $v2 = "@canais" ascii
        $v3 = "$servidor" ascii
        $v4 = "$processo" ascii
        $v5 = "@hostauth" ascii
    condition:
        is_script and filesize < 512KB and $irc and $sock and 2 of ($v*)
}

rule Qlam_PHP_Webshell_Known
{
    meta:
        qlam_severity = "malicious"
        qlam_name = "Qlam.PHP.Webshell.Known"
        description = "Well-known PHP webshell (WSO/FilesMan, b374k, c99, r57)"
    strings:
        $php = "<?" ascii
        $wso1 = "FilesMan" ascii
        $wso2 = "$default_action" ascii
        $b374k = "b374k" ascii nocase
        $c99 = "c99shell" ascii nocase
        $r57 = "r57shell" ascii nocase
    condition:
        filesize < 2MB and $php in (0..1024) and (($wso1 and $wso2) or $b374k or $c99 or $r57)
}

rule Qlam_Linux_LKM_Rootkit_Known
{
    meta:
        qlam_severity = "malicious"
        qlam_name = "Qlam.Linux.Rootkit.LKM"
        description = "Known kernel-module rootkit (Diamorphine, Reptile)"
    strings:
        $d1 = "diamorphine_secret" ascii
        $d2 = "diamorphine" ascii fullword
        $r1 = "reptile_cmd" ascii
        $r2 = "/reptile/" ascii
        $khook = "khook_" ascii
    condition:
        is_elf and elf.type == elf.ET_REL and filesize < 5MB
        and ($d1 or ($d2 and $khook) or ($r1 and ($r2 or $khook)))
}

rule Qlam_Linux_LKM_Rootkit_Generic
{
    meta:
        qlam_severity = "suspicious"
        qlam_name = "Qlam.Linux.Rootkit.LKM.Generic"
        description = "Kernel module that finds the system call table and hides things. Some security and debugging modules do the first; few have a reason to hide."
    strings:
        $k1 = "kallsyms_lookup_name" ascii
        $s1 = "sys_call_table" ascii
        $s2 = "__x64_sys_getdents64" ascii
        $s3 = "__x64_sys_kill" ascii
        $h1 = "hide_pid" ascii nocase
        $h2 = "hide_module" ascii nocase
        $h3 = "module_hide" ascii nocase
        $h4 = "hidden_pids" ascii nocase
        $h5 = "hide_file" ascii nocase
    condition:
        is_elf and elf.type == elf.ET_REL and filesize < 5MB and $k1 and 1 of ($s*) and 1 of ($h*)
}

// ── Offensive tools ─────────────────────────────────────────────────────

rule Qlam_Linux_HackTool_Sliver
{
    meta:
        qlam_severity = "suspicious"
        qlam_name = "Qlam.Linux.HackTool.Sliver"
        description = "Sliver command-and-control framework (implant or tooling). Expected on a penetration tester's machine; otherwise an intrusion."
    strings:
        $s1 = "github.com/bishopfox/sliver/protobuf/sliverpb" ascii
        $s2 = "sliverpb.Envelope" ascii
        $s3 = "bishopfox/sliver" ascii
    condition:
        is_elf and filesize < 64MB and 2 of them
}

rule Qlam_Linux_HackTool_Mimipenguin
{
    meta:
        qlam_severity = "suspicious"
        qlam_name = "Qlam.Linux.HackTool.Mimipenguin"
        description = "mimipenguin: dumps login passwords from the memory of running processes"
    strings:
        $m = "mimipenguin" ascii nocase
        $t1 = "gnome-keyring-daemon" ascii
        $t2 = "/etc/shadow" ascii
        $t3 = "vsftpd" ascii
        $t4 = "sshd:" ascii
    condition:
        (is_script or is_elf) and filesize < 5MB and $m and 2 of ($t*)
}
