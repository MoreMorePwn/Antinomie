/*
 * Antinomie's own YARA rules: generic indicators for triage, not verdicts.
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 MikiMiku (MoreMorePwn)
 *
 * Every rule carries a `category` meta (packer, anti-analysis, crypto,
 * persistence, execution, network, credential, evasion) used to group
 * matches in the Rules view.
 */

import "elf"
import "pe"
import "math"

/* ---- packers and protectors -------------------------------------------- */

rule ANT_Packer_UPX
{
    meta:
        description = "UPX packed executable (UPX! marker and section names)"
        category = "packer"
        author = "Antinomie"
    strings:
        $marker = "UPX!"
        $sec0 = "UPX0"
        $sec1 = "UPX1"
        $info = "$Info: This file is packed with the UPX executable packer"
    condition:
        $info or ($marker and ($sec0 or $sec1)) or (#marker >= 2 and filesize < 32MB)
}

rule ANT_Packer_MPRESS
{
    meta:
        description = "MPRESS packed PE (.MPRESS1/.MPRESS2 sections)"
        category = "packer"
        author = "Antinomie"
    condition:
        pe.is_pe and for any s in pe.sections : (s.name == ".MPRESS1" or s.name == ".MPRESS2")
}

rule ANT_Packer_ASPack
{
    meta:
        description = "ASPack packed PE (.aspack/.adata sections)"
        category = "packer"
        author = "Antinomie"
    condition:
        pe.is_pe and for any s in pe.sections : (s.name == ".aspack" or s.name == ".adata")
}

rule ANT_Protector_Themida_VMProtect
{
    meta:
        description = "Themida, WinLicense or VMProtect section names"
        category = "packer"
        author = "Antinomie"
    condition:
        pe.is_pe and for any s in pe.sections : (
            s.name == ".themida" or s.name == ".winlice" or s.name == ".vmp0" or
            s.name == ".vmp1" or s.name == ".vmp2"
        )
}

rule ANT_High_Entropy_Executable_Section
{
    meta:
        description = "An executable PE section with entropy above 7.2 bits per octet (packed or encrypted code)"
        category = "packer"
        author = "Antinomie"
    condition:
        pe.is_pe and for any s in pe.sections : (
            s.characteristics & pe.SECTION_MEM_EXECUTE and s.raw_data_size > 4096 and
            math.entropy(s.raw_data_offset, s.raw_data_size) > 7.2
        )
}

rule ANT_ELF_Stripped_Static_No_Sections
{
    meta:
        description = "ELF without section headers, typical of packed or hand-crafted binaries"
        category = "packer"
        author = "Antinomie"
    condition:
        uint32(0) == 0x464c457f and elf.number_of_sections == 0 and elf.number_of_segments > 0
}

/* ---- anti-analysis ------------------------------------------------------ */

rule ANT_AntiDebug_Linux_Ptrace
{
    meta:
        description = "Linux self-tracing or tracer checks (PTRACE_TRACEME, TracerPid)"
        category = "anti-analysis"
        author = "Antinomie"
    strings:
        $tracerpid = "TracerPid" ascii
        $status = "/proc/self/status" ascii
        $ptrace = "ptrace" ascii fullword
    condition:
        uint32(0) == 0x464c457f and ($tracerpid or ($status and $ptrace))
}

rule ANT_AntiDebug_Windows_API
{
    meta:
        description = "Windows debugger checks through well-known APIs"
        category = "anti-analysis"
        author = "Antinomie"
    strings:
        $a1 = "IsDebuggerPresent" ascii
        $a2 = "CheckRemoteDebuggerPresent" ascii
        $a3 = "NtQueryInformationProcess" ascii
        $a4 = "OutputDebugStringA" ascii
        $a5 = "NtSetInformationThread" ascii
    condition:
        pe.is_pe and 2 of them
}

rule ANT_AntiVM_Strings
{
    meta:
        description = "Strings used to detect virtual machines and sandboxes"
        category = "anti-analysis"
        author = "Antinomie"
    strings:
        $v1 = "VBoxGuest" ascii wide nocase
        $v2 = "VBOX HARDDISK" ascii wide nocase
        $v3 = "VMware Tools" ascii wide nocase
        $v4 = "vmtoolsd" ascii wide nocase
        $v5 = "QEMU HARDDISK" ascii wide nocase
        $v6 = "/sys/class/dmi/id/product_name" ascii
        $v7 = "hypervisor" ascii fullword
        $v8 = "SbieDll.dll" ascii wide nocase
        $v9 = "cuckoomon" ascii wide nocase
    condition:
        2 of them
}

rule ANT_AntiAnalysis_Timing
{
    meta:
        description = "rdtsc timing checks next to sleep or time queries"
        category = "anti-analysis"
        author = "Antinomie"
    strings:
        $rdtsc = { 0F 31 }
        $s1 = "nanosleep" ascii
        $s2 = "clock_gettime" ascii
        $s3 = "QueryPerformanceCounter" ascii
        $s4 = "GetTickCount" ascii
    condition:
        #rdtsc >= 2 and any of ($s*)
}

/* ---- cryptography ------------------------------------------------------- */

rule ANT_Crypto_AES_Sbox
{
    meta:
        description = "AES forward S-box"
        category = "crypto"
        author = "Antinomie"
    strings:
        $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
    condition:
        $sbox
}

rule ANT_Crypto_SHA256_Constants
{
    meta:
        description = "SHA-256 round constants"
        category = "crypto"
        author = "Antinomie"
    strings:
        $le = { 98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 DB B5 E9 }
        $be = { 42 8A 2F 98 71 37 44 91 B5 C0 FB CF E9 B5 DB A5 }
    condition:
        any of them
}

rule ANT_Crypto_MD5_Init
{
    meta:
        description = "MD5 or SHA-1 initial state words"
        category = "crypto"
        author = "Antinomie"
    strings:
        $init = { 01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 }
    condition:
        $init
}

rule ANT_Crypto_ChaCha_Salsa
{
    meta:
        description = "ChaCha or Salsa20 constant \"expand 32-byte k\""
        category = "crypto"
        author = "Antinomie"
    strings:
        $k32 = "expand 32-byte k" ascii
        $k16 = "expand 16-byte k" ascii
    condition:
        any of them
}

rule ANT_Crypto_RSA_Key_Material
{
    meta:
        description = "Embedded PEM private or public key"
        category = "crypto"
        author = "Antinomie"
    strings:
        $p1 = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $p2 = "-----BEGIN PRIVATE KEY-----" ascii
        $p3 = "-----BEGIN PUBLIC KEY-----" ascii
        $p4 = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
    condition:
        any of them
}

/* ---- persistence -------------------------------------------------------- */

rule ANT_Persistence_Linux
{
    meta:
        description = "Paths used for persistence on Linux (cron, systemd, shell profiles, preload)"
        category = "persistence"
        author = "Antinomie"
    strings:
        $c1 = "/etc/crontab" ascii
        $c2 = "/var/spool/cron" ascii
        $c3 = "/etc/systemd/system" ascii
        $c4 = ".bashrc" ascii
        $c5 = "/etc/rc.local" ascii
        $c6 = "/etc/ld.so.preload" ascii
        $c7 = ".config/autostart" ascii
        $c8 = "/etc/init.d/" ascii
    condition:
        uint32(0) == 0x464c457f and 2 of them
}

rule ANT_Persistence_Windows_Run_Keys
{
    meta:
        description = "Windows Run keys, services or scheduled tasks"
        category = "persistence"
        author = "Antinomie"
    strings:
        $r1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $r2 = "schtasks" ascii wide nocase
        $r3 = "CreateServiceA" ascii
        $r4 = "CreateServiceW" ascii
        $r5 = "Startup" ascii wide fullword
    condition:
        pe.is_pe and 2 of them
}

rule ANT_Preload_Hijack
{
    meta:
        description = "Dynamic loader hijacking through LD_PRELOAD or ld.so.preload"
        category = "evasion"
        author = "Antinomie"
    strings:
        $a = "LD_PRELOAD" ascii
        $b = "/etc/ld.so.preload" ascii
        $c = "dlsym" ascii fullword
    condition:
        ($a or $b) and $c
}

/* ---- execution and network ---------------------------------------------- */

rule ANT_Reverse_Shell
{
    meta:
        description = "Reverse or bind shell building blocks"
        category = "execution"
        author = "Antinomie"
    strings:
        $sh1 = "/bin/sh" ascii
        $sh2 = "/bin/bash" ascii
        $dup = "dup2" ascii fullword
        $net1 = "connect" ascii fullword
        $net2 = "socket" ascii fullword
        $tcp = "/dev/tcp/" ascii
        $nc = "nc -e" ascii
    condition:
        $tcp or $nc or (any of ($sh*) and $dup and all of ($net*))
}

rule ANT_Shell_Command_Execution
{
    meta:
        description = "Runs shell command lines"
        category = "execution"
        author = "Antinomie"
    strings:
        $a = "/bin/sh -c" ascii
        $b = "sh -c" ascii fullword
        $c = "cmd.exe /c" ascii wide nocase
        $d = "powershell -" ascii wide nocase
    condition:
        any of them
}

rule ANT_Downloader
{
    meta:
        description = "Fetches and runs remote content"
        category = "network"
        author = "Antinomie"
    strings:
        $u1 = "http://" ascii wide
        $u2 = "https://" ascii wide
        $t1 = "wget " ascii
        $t2 = "curl " ascii
        $t3 = "URLDownloadToFile" ascii
        $t4 = "InternetOpenUrl" ascii
        $x1 = "chmod +x" ascii
        $x2 = "WinExec" ascii
        $x3 = "ShellExecute" ascii
    condition:
        any of ($u*) and any of ($t*) and any of ($x*)
}

rule ANT_Raw_Network_Indicators
{
    meta:
        description = "Raw sockets, packet capture or port scanning"
        category = "network"
        author = "Antinomie"
    strings:
        $a = "SOCK_RAW" ascii
        $b = "pcap_open_live" ascii
        $c = "IPPROTO_RAW" ascii
        $d = "masscan" ascii nocase
    condition:
        any of them
}

rule ANT_Tor_Or_Onion
{
    meta:
        description = "Tor hidden service or Tor client references"
        category = "network"
        author = "Antinomie"
    strings:
        $onion = /[a-z2-7]{56}\.onion/ ascii
        $tor = "tor2web" ascii nocase
        $socks = "127.0.0.1:9050" ascii
    condition:
        any of them
}

/* ---- credentials and collection ----------------------------------------- */

rule ANT_Credential_Files
{
    meta:
        description = "Reads credential stores (shadow, SSH keys, browser logins)"
        category = "credential"
        author = "Antinomie"
    strings:
        $l1 = "/etc/shadow" ascii
        $l2 = ".ssh/id_rsa" ascii
        $l3 = ".ssh/authorized_keys" ascii
        $w1 = "Login Data" ascii wide
        $w2 = "logins.json" ascii wide
        $w3 = "lsass" ascii wide nocase
    condition:
        any of them
}

rule ANT_Keylogging
{
    meta:
        description = "Keyboard capture APIs or input device reads"
        category = "credential"
        author = "Antinomie"
    strings:
        $w1 = "GetAsyncKeyState" ascii
        $w2 = "SetWindowsHookExA" ascii
        $w3 = "SetWindowsHookExW" ascii
        $l1 = "/dev/input/event" ascii
    condition:
        any of them
}

/* ---- evasion ------------------------------------------------------------ */

rule ANT_Self_Deletion
{
    meta:
        description = "Deletes its own executable or clears logs"
        category = "evasion"
        author = "Antinomie"
    strings:
        $a = "/proc/self/exe" ascii
        $b = "unlink" ascii fullword
        $c = "/var/log/" ascii
        $d = "history -c" ascii
        $e = "wevtutil cl" ascii wide nocase
    condition:
        ($a and $b) or $d or $e or ($c and $b)
}

rule ANT_Process_Injection_Windows
{
    meta:
        description = "Classic remote-thread or hollowing injection APIs"
        category = "evasion"
        author = "Antinomie"
    strings:
        $a1 = "VirtualAllocEx" ascii
        $a2 = "WriteProcessMemory" ascii
        $a3 = "CreateRemoteThread" ascii
        $a4 = "NtUnmapViewOfSection" ascii
        $a5 = "QueueUserAPC" ascii
    condition:
        pe.is_pe and 3 of them
}

rule ANT_Process_Injection_Linux
{
    meta:
        description = "Writes into other processes through ptrace or /proc/<pid>/mem"
        category = "evasion"
        author = "Antinomie"
    strings:
        $a = "PTRACE_POKETEXT" ascii
        $b = /\/proc\/(%d|[0-9]+)\/mem/ ascii
        $c = "process_vm_writev" ascii
    condition:
        uint32(0) == 0x464c457f and any of them
}
