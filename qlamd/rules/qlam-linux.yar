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
        filesize < 1MB and ($fetch1 or $pool) and ($kill1 or $kill2) and 1 of ($hide*)
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
        // A script (shebang) or a tiny dropped one-liner. Documentation,
        // pentest tool data (nmap .nse) and notes mention these commands all
        // the time and must not be flagged.
        any of them and (uint16(0) == 0x2123 or filesize < 2KB)
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
        filesize < 1MB and any of them
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
