/*
 * Qlam heuristics — traits of Linux executables that malware shares.
 *
 * None of these is a detection. Each rule sets
 *   qlam_heur   points the trait is worth
 *   qlam_trait  how it is described to the user
 * and the engine adds up the points of every trait a file shows. Only at
 * HEUR_THRESHOLD (60, see engine/yara.rs) is the file reported, and then
 * always as "suspicious": a heuristic never blocks, quarantines or calls
 * anything malware. A named rule that matches the file wins over the sum.
 *
 * Scores are set so no single trait reaches the threshold on its own:
 * legitimate software is packed, static, or reads /proc/self/exe often
 * enough. Malware tends to do several such things at once. The engine also
 * wants one strong trait (HEUR_MIN_STRONG points) among them: weak,
 * text-based traits alone never add up to a report.
 *
 * Tuned against every ELF on a desktop (2026-11-07): Qualcomm firmware
 * split into header-only files, anti-cheat libraries (BattlEye) that are
 * packed on purpose, and big programs that embed a JavaScript bundle (and
 * so every string imaginable) must stay clean.
 *
 * The rules apply to ELF files only (they are compiled in their own
 * namespace, so `is_elf` is defined again here).
 */

import "elf"
import "math"

private rule is_elf
{
    condition:
        uint32(0) == 0x464c457f
}

/// A program, not a library: anti-cheat and DRM libraries are packed and
/// self-modifying by design.
private rule is_program
{
    condition:
        is_elf and (elf.type == elf.ET_EXEC or
            (elf.type == elf.ET_DYN and for any s in elf.segments : (s.type == elf.PT_INTERP)))
}

/// Small enough for its strings to mean something: big programs that
/// embed scripts or resources contain every string a trait looks for.
private rule is_small
{
    condition:
        filesize < 8MB
}

private rule is_go_or_rust
{
    // Static and stripped is normal for these toolchains.
    strings:
        $go1 = "Go build ID:" ascii
        $go2 = "runtime.gopanic" ascii
        $rs1 = "/rustc/" ascii
        $rs2 = "rust_panic" ascii
    condition:
        any of them
}

rule Qlam_Heur_Packed_No_Sections
{
    meta:
        qlam_heur = 40
        qlam_trait = "packed or encrypted"
    condition:
        is_program and filesize > 4KB and elf.sections.len() == 0
        and math.entropy(0, filesize) >= 7.2
}

rule Qlam_Heur_UPX_Modified
{
    meta:
        qlam_heur = 40
        qlam_trait = "packed with a modified UPX, so it can't be unpacked"
    strings:
        $magic = "UPX!" ascii
        $info = "$Info: This file is packed with the UPX" ascii
    condition:
        // IoT bots strip UPX's notice and corrupt its header to defeat
        // `upx -d`; honest UPX use leaves the notice in.
        is_elf and filesize < 10MB and $magic and not $info
        and elf.sections.len() <= 3
}

rule Qlam_Heur_UPX
{
    meta:
        qlam_heur = 20
        qlam_trait = "UPX-packed"
    strings:
        $info = "$Info: This file is packed with the UPX" ascii
    condition:
        is_elf and $info
}

rule Qlam_Heur_RWX_Segment
{
    meta:
        qlam_heur = 25
        qlam_trait = "code that is writable and executable at once"
    condition:
        is_program and for any s in elf.segments : (
            s.type == elf.PT_LOAD and s.flags & elf.PF_W != 0 and s.flags & elf.PF_X != 0
        )
}

rule Qlam_Heur_Tiny_Loader
{
    meta:
        qlam_heur = 50
        qlam_trait = "a tiny program with no structure, like a shellcode loader"
    condition:
        // msfvenom-style stagers are a few hundred bytes, all of it code.
        // Firmware split into parts keeps a header-only part whose
        // segments point past its end: not a program.
        is_program and filesize < 1KB and elf.sections.len() == 0
        and for any s in elf.segments : (
            s.type == elf.PT_LOAD and s.flags & elf.PF_X != 0
            and s.file_size > 0 and s.offset + s.file_size <= filesize
        )
}

rule Qlam_Heur_Kernel_Thread_Name
{
    meta:
        qlam_heur = 40
        qlam_trait = "carries a kernel thread's name to hide as one"
    strings:
        $k = /\[(kworker|ksoftirqd|kthreadd|kswapd[0-9]?|migration|rcu_sched|rcu_preempt|watchdogd?|kblockd|jbd2)[\/0-9:A-Za-z\-]{0,24}\]/ ascii
    condition:
        is_elf and $k
}

rule Qlam_Heur_Wipes_Traces
{
    meta:
        qlam_heur = 25
        qlam_trait = "erases shell history or login records"
    strings:
        $h1 = "HISTFILE=/dev/null" ascii
        $h2 = "unset HISTFILE" ascii
        $h3 = "history -c" ascii
        $l1 = "/var/log/wtmp" ascii
        $l2 = "/var/log/lastlog" ascii
        $l3 = "/var/log/auth.log" ascii
        $l4 = "/var/log/secure" ascii
    condition:
        // Login tools name the log files too; it's the history wiping
        // together with them that tells.
        is_elf and is_small and 1 of ($h*) and 1 of ($l*)
}

rule Qlam_Heur_Disables_Security
{
    meta:
        qlam_heur = 30
        qlam_trait = "turns off the firewall or other protections"
    strings:
        $s1 = "iptables -F" ascii
        $s2 = "ufw disable" ascii
        $s3 = "setenforce 0" ascii
        $s4 = "systemctl stop firewalld" ascii
        $s5 = "systemctl disable apparmor" ascii
        $s6 = "randomize_va_space" ascii
        $s7 = "nmi_watchdog" ascii
    condition:
        is_elf and is_small and 2 of them
}

rule Qlam_Heur_Self_Delete
{
    meta:
        qlam_heur = 15
        qlam_trait = "deletes its own file and detaches"
    strings:
        $e = "/proc/self/exe" ascii
        $u1 = "unlink" ascii fullword
        $u2 = "remove" ascii fullword
        $d1 = "setsid" ascii fullword
        $d2 = "daemon" ascii fullword
    condition:
        is_elf and is_small and $e and 1 of ($u*) and 1 of ($d*)
}

rule Qlam_Heur_Persistence_Paths
{
    meta:
        qlam_heur = 15
        qlam_trait = "writes itself into startup locations"
    strings:
        $p1 = "/etc/rc.local" ascii
        $p2 = "/etc/init.d/" ascii
        $p3 = "/etc/cron.d/" ascii
        $p4 = "/etc/cron.hourly/" ascii
        $p5 = "crontab -" ascii
        $p6 = "/etc/profile.d/" ascii
        $p7 = ".bashrc" ascii
    condition:
        is_elf and is_small and 2 of them
}

rule Qlam_Heur_Watchdog
{
    meta:
        qlam_heur = 20
        qlam_trait = "disables the hardware watchdog (IoT bot behaviour)"
    strings:
        $w1 = "/dev/watchdog" ascii
        $w2 = "/dev/misc/watchdog" ascii
    condition:
        is_elf and $w1 and $w2
}

rule Qlam_Heur_Hardcoded_Server
{
    meta:
        qlam_heur = 15
        qlam_trait = "a hard-coded IP address and port next to a shell"
    strings:
        $ip = /[^0-9.][0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{2,5}[^0-9]/ ascii
        $sh = "/bin/sh" ascii
    condition:
        is_elf and is_small and $ip and $sh
}

rule Qlam_Heur_Credential_Targets
{
    meta:
        qlam_heur = 20
        qlam_trait = "reads password, key or wallet files"
    strings:
        $c1 = "/etc/shadow" ascii
        $c2 = ".ssh/id_rsa" ascii
        $c3 = ".ssh/id_ed25519" ascii
        $c4 = ".aws/credentials" ascii
        $c5 = "wallet.dat" ascii
        $c6 = ".bash_history" ascii
        $c7 = "logins.json" ascii
    condition:
        is_elf and is_small and 2 of them
}

rule Qlam_Heur_Static_Stripped
{
    meta:
        qlam_heur = 10
        qlam_trait = "statically linked with its symbols removed"
    condition:
        is_elf and elf.type == elf.ET_EXEC and not is_go_or_rust
        and elf.symtab_entries == 0
        and not for any s in elf.segments : (s.type == elf.PT_INTERP)
}
