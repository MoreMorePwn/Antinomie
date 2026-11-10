// SPDX-License-Identifier: GPL-3.0-only
//! The words of the rules: a short title and a description for each one.
//! Written from what the rule's code checks, not from what it might mean.
//! Summary and Suspicious activity read them through [`title`] and [`description`].

/// `(rule id, title, description)`, in the order of the classification.
pub const TEXTS: &[(&str, &str, &str)] = &[
    ("process.exec", "Program started", "A program was started with exec. This is neutral context: the command line says what ran, and the other rules judge what it then did."),
    ("process.crashed_at_start", "Crashed before first call", "The sample's program died of a signal before its first system call was recorded, so there was nothing to judge. It failed while loading or in its first instructions."),
    ("process.interpreter", "Interpreter or shell started", "A shell, Python, Node, Lua, Perl, Ruby, PHP, awk or similar interpreter was started, also when a script's #! line or busybox names it. Common in normal software; what it was told to run is what matters."),
    ("execution.download_cradle", "Running downloaded code directly", "A shell command line fetches data (curl, wget, /dev/tcp, Python urlopen) and pipes it into an interpreter, substitutes it into a command, or makes it executable and starts it. Droppers use this to run a payload without a visible file."),
    ("execution.dropped_exec", "Dropped file executed", "A program that the run itself wrote earlier was executed, matched by file identity or by path. Malware that unpacks and starts a second stage looks like this."),
    ("execution.chmod_exec_temp", "Making a temp file runnable: chmod +x", "chmod gave an execute bit to a file in a temporary, hidden or /run/user location. Staged payloads are made runnable this way before they are launched."),
    ("execution.temp_exec", "Run from temp or hidden dir", "A program was executed from a temporary, hidden or shared-memory directory (for example /tmp or /dev/shm), and it was not the sample itself. Payloads are often launched from such places because any user can write there."),
    ("execution.compile_then_run", "Compiled in guest, then run", "A compiler started by the run wrote a file and that file was then executed. Malware builds payloads on the target to fit it or to avoid shipping a binary; developers do the same."),
    ("process.memfd_exec", "Running a program from memory: memfd", "A program was executed from an anonymous memory file made by memfd_create. The image never existed as a named file on disk."),
    ("execution.fileless_exec", "Executed file with no name", "An exec went through /proc/PID/fd or /dev/fd to a file that is not a memfd, or ran a file whose last hard link was already removed. The image has no name left on disk to inspect."),
    ("process.memfd", "Creating a file only in memory: memfd", "memfd_create made a file that lives only in memory. JITs and sandboxes do this legitimately; it is also the first step of fileless execution."),
    ("execution.memfd_elf", "Staging a program in memory: ELF in memfd", "A write put bytes starting with the ELF magic into a memfd. A program image is being staged in memory, usually to be executed next."),
    ("execution.dropped_library", "Dropped library mapped as code", "mmap mapped a file executable that the run itself wrote earlier. A loader is pulling in a library it just dropped."),
    ("injection.ptrace_attach", "Taking over another process: ptrace attach", "ptrace ATTACH or SEIZE on a process other than the caller. Debuggers do this, and so does an injector that takes over a running process."),
    ("injection.ptrace_poke", "Injecting into a process: ptrace write", "ptrace wrote memory or registers of a traced process (POKE and SETREGS requests). Together with an attach this is how code is injected."),
    ("injection.vm_write", "Write into another process", "process_vm_writev wrote directly into the memory of a process other than the caller. Used to inject code or data without ptrace."),
    ("injection.proc_mem_write", "Overwriting process memory via /proc/PID/mem", "A process opened /proc/PID/mem for writing, which lets it overwrite memory of that process. The tier is lowered when the process is its own."),
    ("injection.ld_preload_env", "Library injection via environment", "A program was started with LD_PRELOAD or LD_AUDIT set, or with LD_LIBRARY_PATH pointing into a temporary or hidden directory. The loader then brings in the named library before the program's own."),
    ("injection.dropped_preload", "A library the run wrote is loaded into programs", "The run wrote a shared library and then made the loader bring it into a program: through LD_PRELOAD or LD_AUDIT in a later program's environment, or by listing it in /etc/ld.so.preload. The library is scanned with the run's YARA rules when it was rebuilt whole from the recorded writes."),
    ("injection.ld_so_preload", "Hooking every program: ld.so.preload written", "The file that makes the loader inject a library into every program was created or written. A classic user-space rootkit hook."),
    ("injection.ld_so_conf", "Library search path changed", "ld.so.conf, ld.so.conf.d or the loader cache was changed. This redirects which libraries programs load; package managers and ldconfig do it as their job."),
    ("persistence.cron", "Cron job installed", "A crontab or a file under /etc/cron.* or /var/spool/cron was written, or crontab was run to install a new table. The job runs again at the chosen times."),
    ("persistence.at_job", "Job scheduled to run later: at", "The at or batch command was run, or a file in the at spool was written. The command runs once later, without the program still running."),
    ("persistence.systemd", "Service installed: systemd unit", "A unit or generator was written in a systemd system or user directory, or systemctl or service enabled a unit file the run had written. systemd starts it at boot or login."),
    ("persistence.rc_init", "Init script installed", "rc.local, inittab, an init.d or rcN.d script, or an upstart job was written, or a script the run wrote was enabled with update-rc.d or chkconfig. It runs at boot."),
    ("persistence.event_script", "Event script installed", "A script was written under update-motd.d or the NetworkManager dispatcher. These run as root on login or on network changes."),
    ("persistence.shell_profile", "Shell startup file changed", "A shell profile or rc file (/etc/profile, profile.d, .bashrc, .profile, .zshrc and similar) was written. Its commands run at every login or shell start. Read the written bytes to tell a backdoor from a setting."),
    ("persistence.ssh_authorized_keys", "SSH access file changed", "authorized_keys, ~/.ssh/rc or the sshd configuration was written. A planted key or option gives the attacker a way back in."),
    ("persistence.xdg_autostart", "Desktop autostart entry written", "A file under an autostart directory of the desktop (XDG, KDE) was written. The desktop session starts it at login."),
    ("persistence.udev", "Device rule written: udev", "A udev rule file was written. A rule can run a program when a device appears."),
    ("persistence.copy_running", "Persisted copy running outside the recorded tree", "A process the run did not start (cron, systemd or init started it) runs the sample's own program or a file the run wrote: the host read its program from the guest and its SHA-256 matched. It is the sample's persistence at work. The guest traces only the launched tree, so this copy's calls are not in the recording; when the tree ended while it still ran, the run was kept open, so the network capture covers it."),
    ("persistence.pam", "Login rules changed: PAM config or module", "A file under /etc/pam.d or /etc/security, or a pam_*.so module, was written. PAM decides logins, so a change can accept any password or log it."),
    ("persistence.module", "Kernel module loaded", "init_module or finit_module loaded a kernel module. A module runs with full kernel rights and is the usual rootkit carrier."),
    ("persistence.module_autoload", "Module autoload configured", "A file that loads kernel modules at boot (/etc/modules, modules-load.d, modprobe.d) or a .ko file under /lib/modules was written."),
    ("persistence.apt_hook", "Package manager hook written", "A configuration file of apt, dpkg, yum or dnf plugins was written. These can run commands whenever the package manager runs."),
    ("persistence.web_shell", "Script dropped in web root", "A script file (php, jsp, asp, cgi, py and similar) was created in a web server directory. An attacker's web shell is placed this way."),
    ("persistence.binary_replace", "System file overwritten", "A file in a system program or library location was created, written, cut, moved onto or linked. A trojaned sshd, ps or library persists by replacing the original."),
    ("persistence.account", "User account changed", "/etc/passwd, shadow, group or gshadow was written, or useradd, usermod, passwd, chpasswd or similar ran with arguments. A new or changed account keeps access."),
    ("persistence.config_write", "Config or autostart file written", "A file in a persistence-class place, /etc, a .ssh or a .config directory was written and no more specific persistence rule applies. Weak evidence by itself."),
    ("privilege.gain", "Rights raised", "A kernel credential record shows the task became root or gained capabilities (setuid, setresuid, capset, prctl or an exec of a setuid program), outside a user namespace of its own."),
    ("privilege.setuid_exec", "Setuid or capability program run", "An exec raised the task's rights through a setuid, setgid or file-capability program. The tier is higher when the program sits in a staging or hidden directory or was written by the run."),
    ("privilege.setid_bit", "Run-as-owner bit set: setuid or setgid", "chmod set a setuid or setgid bit, or setxattr set a file capability. The file then runs with the owner's rights."),
    ("privilege.pwnkit", "Unusual pkexec start: no arguments (PwnKit)", "pkexec was started with an empty argument vector or with GCONV_PATH set, the pattern of CVE-2021-4034 (PwnKit)."),
    ("privilege.kernel_exploit", "Root gained outside a credential call", "A credential record shows root or CAP_SYS_ADMIN/CAP_SYS_MODULE appearing during a call that does not change credentials. The kernel itself was made to hand out rights, the signature of a kernel exploit."),
    ("privilege.sudoers", "Root access rules changed: sudoers", "/etc/sudoers or a file in sudoers.d was written. It can grant any account root rights without a password."),
    ("privilege.kernel_helper_hijack", "Kernel helper path changed", "core_pattern, the kernel modprobe or hotplug helper, uevent_helper or a binfmt_misc registration was written. The kernel then runs the named program as root."),
    ("privilege.container_escape", "Container escape attempt", "The task entered the namespaces of process 1 (nsenter -t 1 or setns), or connected to a container runtime socket or API port (docker, containerd, podman, 2375, 2376). Those give control of the host."),
    ("privilege.drop", "Rights dropped", "A credential record shows the task gave up root or capabilities. Servers do this after start-up; it is context for a later gain."),
    ("privilege.userns", "User namespace created", "unshare created a new user namespace. Containers and browsers do this; exploits use it to reach kernel code that needs root."),
    ("privilege.dirty_pipe", "Overwriting a read-only file: Dirty Pipe pattern", "A file in a system, credential or persistence location was spliced into a pipe and the pipe was then written. This is the CVE-2022-0847 pattern."),
    ("memory.rwx_attempt", "Refused request for writable+executable memory", "mmap or mprotect asked for memory that is both writable and executable, and the call failed. The attempt is the signal."),
    ("memory.wx_transition", "Writable memory made executable", "mprotect made executable a range the same task had mapped writable. Unpacked or generated code starts running this way."),
    ("memory.rwx", "Writable and executable memory", "mmap or mprotect gave memory both write and execute rights. Shellcode and unpackers need this; JIT compilers do it too."),
    ("evasion.self_delete", "Running program deleted itself", "A file was removed or moved away while a process was still running it. The program leaves nothing on disk to inspect."),
    ("evasion.tool_delete", "System program deleted", "A program under /bin, /sbin or /usr/bin or similar was deleted, and the run had not written it. Removing tools such as wget or killall hinders the user and the responder."),
    ("evasion.log_clear", "Log emptied or removed", "A file under /var/log or a login record (utmp, wtmp) was cut or removed, journalctl vacuumed the journal, or syslog cleared the kernel ring buffer. Evidence is destroyed."),
    ("evasion.history_clear", "Shell history cleared", "A history file was emptied or removed, or a command or environment variable (HISTFILE=/dev/null, HISTSIZE=0, history -c) switched history off."),
    ("evasion.security_disable", "Security software disabled", "SELinux or AppArmor was set to permissive or off, or a security agent service (falco, osquery, wazuh, a cloud monitoring agent and similar) was stopped or disabled."),
    ("evasion.firewall_modify", "Firewall rules changed", "iptables, nft, ufw or firewalld flushed, opened or redirected rules, or the firewall service was stopped. Traffic is allowed or redirected."),
    ("evasion.audit_disable", "Audit disabled", "auditd was stopped or disabled, auditctl turned auditing off or deleted rules, or /etc/audit was changed. Later actions are no longer logged."),
    ("evasion.masquerade_kthread", "Named like a kernel thread", "A user process set its name to that of a kernel thread (kworker, ksoftirqd and similar, or in square brackets), by exec argv[0] or prctl. It hides in the process list."),
    ("evasion.masquerade_daemon", "Named like a system daemon", "A process set its name to that of a system daemon (sshd, cron, systemd and similar) while running a different program."),
    ("evasion.argv_masquerade", "Hiding the process name: argv[0] rewritten", "argv[0] names a different program than the image the kernel loaded (ps aux run from /tmp/x). LOW, because some tools rename argv[0] on purpose; BusyBox applets, interpreter aliases, login shells and daemon titles are not counted. MEDIUM when the claimed name is a well-known system tool and the image sits in a temp, hidden or home directory, where a disguise is meant to pass in the process list."),
    ("evasion.process_rename", "Process renamed itself", "A running process changed the name the process list shows for it: prctl(PR_SET_NAME), a write to /proc/self/comm, or a write to /proc/self/attr (its security label). LOW, because some programs set a thread name on purpose. MEDIUM when the new name is that of a kernel thread ([kworker/0:1]) or a well-known daemon (sshd, systemd, cron), which hides it in ps. Separate from the argv[0] rule: that one is about the command line given at exec, this one about a name set while running; when both fire for one process they are listed together under Related. If the name was not captured the finding says so."),
    ("evasion.sandbox_probe", "VM or sandbox check", "The task read the machine identity, CPU, disks, hypervisor devices, MAC address, uptime or a clock loop, the facts that tell a virtual machine from real hardware. The answers the guest gave are listed in Details."),
    ("evasion.probe_then_exit", "Exit or sleep after VM check", "Within seconds after an answer that gave the VM away, the task exited or went to sleep. This is a heuristic: the calls cannot say why the program stopped."),
    ("evasion.traceme", "Anti-debug check through ptrace(TRACEME)", "The task called PTRACE_TRACEME on itself, or attached to its own parent. A refusal means a debugger already traces it; it is a classic anti-debugging check."),
    ("evasion.debugger_check", "Checking for a debugger or tracer", "The task read TracerPid or the memory map of itself for debugger and instrumentation tools, queried PR_GET_DUMPABLE or installed a SIGTRAP handler. Each check is listed with the answer the guest gave."),
    ("evasion.container_check", "Container check", "The task looked for /.dockerenv, /run/.containerenv or the cgroup and scheduler files of process 1. These tell a container from a plain machine."),
    ("evasion.packed_image", "Packed program", "Static analysis found the run's own program packed. Its headers had been changed so that the packer's unpacker refuses it (MEDIUM), or they are as the packer writes them (LOW). Packers are also used by legitimate software."),
    ("evasion.long_sleep", "Long sleep", "A wait of a minute or more, before the task used the network or wrote a file. Malware delays to outlast a sandbox's time limit."),
    ("evasion.timestomp", "Changing file times: timestamps set", "utime, utimes, utimensat or futimesat set chosen times on a file, not the current time. Used to make a dropped file look old."),
    ("evasion.kill_list", "Many processes signalled", "The task sent SIGKILL or SIGTERM to five or more different processes that the run did not start within 30 seconds, or ran pkill or killall with a long list of names. Malware kills rivals and security tools."),
    ("evasion.hidden_artifact", "Hidden file created", "A file or directory with a leading dot (or a name of only dots or spaces) was created in a system or temporary directory where nothing hidden belongs."),
    ("evasion.immutable_attr", "Locking a file against change: chattr flag", "chattr or ioctl SETFLAGS set the immutable or append-only flag, so that the file cannot be changed or deleted. HIGH on persistence and credential files."),
    ("evasion.proc_hide_mount", "Hiding processes: mount over /proc", "A bind mount over /proc/PID, or a /proc mount with hidepid, hides processes from the process list."),
    ("evasion.sysctl_security", "Kernel hardening switched off", "A write to a hardening setting (ASLR, kptr_restrict, dmesg_restrict, ptrace_scope, unprivileged_bpf_disabled) or personality(ADDR_NO_RANDOMIZE) was seen. Exploits and debuggers weaken the protection this way."),
    ("credential.shadow_read", "Password hashes read", "/etc/shadow, gshadow or a backup copy was opened. The hashes can be cracked offline; login programs read it as their job."),
    ("credential.ssh_keys", "Private SSH key read", "A private key in ~/.ssh or a host key was opened, or a PRIVATE KEY block was read from a file. Keys give access to other machines."),
    ("credential.cloud_tokens", "Cloud or CI token file read", "A credential file of AWS, Azure, gcloud, kubectl, docker, git or netrc, or a Kubernetes service-account token was opened."),
    ("credential.browser_store", "Browser credential store read", "A saved-login, cookie or key database of Firefox, Chrome, Chromium, Brave or Edge was opened. Information stealers do this; the browser itself is on the allow-list."),
    ("credential.wallet", "Crypto wallet read", "A wallet.dat file or the data directory of a crypto wallet (Bitcoin, Electrum, Ethereum, Exodus, Monero and others) was opened."),
    ("credential.history_read", "Shell history read", "A shell or database history file (.bash_history, .zsh_history, .mysql_history and similar) was opened. It often holds commands with passwords and hostnames."),
    ("credential.kerberos_ccache", "Kerberos ticket read", "A Kerberos credential cache or keytab was opened. A stolen ticket can be reused to log in elsewhere."),
    ("credential.proc_mem_read", "Another process's memory read", "/proc/PID/mem of another process was opened for reading, or process_vm_readv read another process. Credential scrapers read secrets this way."),
    ("credential.cloud_metadata", "Cloud metadata service contacted", "A connection, lookup or HTTP request reached the instance metadata service (169.254.169.254 and its cloud-specific peers). Attackers fetch role credentials from it."),
    ("credential.cloud_credentials", "Cloud role credentials fetched", "The gateway saw the instance role's credentials being read from the metadata service during the run."),
    ("credential.canary_used", "Canary credential used", "The decoy cloud credential that Antinomie planted in the guest was sent to a server. Only something that read and used it can do that."),
    ("discovery.process_enum", "Process list enumerated", "ps, pgrep, top or similar ran, or the task read the command lines, names or states of ten or more processes under /proc."),
    ("discovery.system_info", "System details read", "The task asked what machine it runs on: the OS release, kernel version, hostname, CPU, memory, DMI or hypervisor files, CPU details under /sys/devices/system/cpu, the mount table, or uname, lscpu and similar. One row per kind (OS and kernel, hardware, mounts and container) with the files listed in Details. The C library's and language runtimes' own start-up reads (CPU counts, cache sizes) are left out. Almost every program does this; it is context."),
    ("discovery.network_config", "Network configuration read", "The task learned how the machine is networked: it read the routes, ARP, interface or DNS files and the open connections table, asked the kernel for interface addresses (ioctl SIOCGIFCONF, SIOCGIFADDR, SIOCGIFHWADDR) or for routes and addresses over a netlink socket (RTM_GETADDR, RTM_GETROUTE), or ran ip, ifconfig, netstat or ss."),
    ("discovery.user_enum", "Users enumerated", "The task read both /etc/passwd and /etc/group, or ran id, whoami, who, last and similar."),
    ("discovery.file_search", "Directory sweep or secret search", "find or locate searched for keys, credentials or wallets, or the task listed 200 or more different directories within a minute."),
    ("discovery.security_software", "Security software probed", "A call looked for the files of security agents (CrowdStrike, ossec, falco, clamd and others), even if absent, or for SELinux, AppArmor or audit paths (INFO)."),
    ("discovery.network_scan", "Network scan", "The task tried 20 or more address and port pairs within 10 seconds, or 10 or more hosts on one port, or ran nmap, masscan or a similar scanner. A failed scan is still the signal."),
    ("c2.reverse_shell", "Reverse shell", "A shell or interpreter was started with a connected socket as its input and output. The program called out to a controller and gives it a command line."),
    ("network.raw_socket", "Low-level network access: raw socket", "socket created a raw IP socket or a packet socket. They are needed to sniff or forge packets; capture tools do this as their job."),
    ("c2.bpf_backdoor", "Waiting for chosen packets: BPF on raw socket", "A classic socket filter was attached to a raw or packet socket. A raw socket that waits for one magic packet is how the BPFDoor backdoor listens."),
    ("bpf.socket_filter", "Selecting packets: socket filter attached", "A classic BPF filter was attached to a socket with SO_ATTACH_FILTER. Capture tools do this; so does a backdoor that selects its packets."),
    ("network.tor", "Tor use", "A connection to the local Tor SOCKS or control port, a lookup or request to a .onion name, or a Tor program (tor, torsocks) was run."),
    ("network.ip_literal", "HTTP to a bare IP address", "An HTTP request in the capture had an IP address instead of a name as its Host (the metadata service aside). Implants often skip DNS."),
    ("network.dga_nxdomain", "Random-name lookups failing", "Ten or more lookups of random-looking names failed within a minute while the resolver was answering other names. Malware tries generated domains to find its server."),
    ("network.dns_tunnel", "Data carried in DNS queries: tunnelling", "Five or more queries with labels over 40 characters to one domain, or 20 or more TXT or NULL queries to one domain within a minute. Data is carried in DNS names."),
    ("network.nonstandard_port", "Service on an unusual port", "HTTP on a port that is not a web port, SSH on a port other than 22, or TLS on a port not used for it, seen in the capture."),
    ("network.irc_c2", "IRC connection", "A connection to an IRC port (6667, 6697) or IRC commands (NICK, USER, JOIN, PRIVMSG) sent to a server. Botnets use IRC for commands."),
    ("network.web_service", "Paste or chat service used", "A lookup, HTTP request or TLS session to a paste, file-sharing or chat service (Pastebin, Telegram, Discord webhooks, transfer.sh and similar). Malware uses them to fetch commands or send data."),
    ("network.beacon", "Regular beaconing", "Eight or more requests to one host at a steady pace. An implant checks in with its controller this way; so do update checks."),
    ("network.proxy_tunnel", "Tunnel or proxy tool run", "ssh with -R, -L, -D or -w, or socat, chisel, frp, ngrok, iodine, cloudflared and similar was run. A tunnel carries other traffic to a place the firewall does not see."),
    ("c2.ioc_match", "Known bad indicator", "An indicator the run produced (an address, domain, URL or file hash) matches an entry of the bundled threat-intelligence data. The tier follows the entry's confidence; source and family are in Details."),
    ("c2.elf_download", "ELF downloaded and saved", "A program image that arrived over a socket was written to a file by the same task. The second stage was fetched and stored."),
    ("lateral.ssh_spread", "SSH after reading known hosts", "ssh, scp or sftp ran, or a connection to port 22 was made, after the task read known_hosts, ssh config or shell history. A worm picks its next targets there."),
    ("lateral.bruteforce", "Login brute force", "hydra, medusa, ncrack or a similar tool ran, or ten or more connections to SSH or telnet ports were made within a minute."),
    ("lateral.service_exploit", "Attacked service ports on many hosts", "Connections to commonly attacked service ports (Docker API, Redis, Elasticsearch, memcached, kubelet, MongoDB and others) on three or more hosts within a minute."),
    ("lateral.tool_transfer", "Files pushed to a remote host", "scp, rsync or sftp toward a remote destination, curl -T, or ssh with cat redirection sent files out. Tools are copied to the next machine this way."),
    ("exfil.file_to_socket", "File sent straight to a socket", "sendfile, copy_file_range or splice moved a file directly to a network socket. The file's contents leave without being read by the program."),
    ("exfil.large_upload", "Large upload", "The task sent more than 1 MiB to remote addresses, and either at least 10 MiB or ten times what it received."),
    ("collection.keylog", "Keyboard device read", "A keyboard event device (/dev/input/event*, uinput) was opened. A keylogger reads keystrokes there."),
    ("collection.screen_capture", "Screen captured", "/dev/fb0 was opened, or a screenshot tool (scrot, import, xwd, grim, ffmpeg x11grab and similar) ran."),
    ("collection.av_capture", "Camera or microphone used", "A video or sound capture device was opened, or arecord, fswebcam, ffmpeg with v4l2 or alsa ran."),
    ("collection.archive_staging", "Sensitive files archived", "tar, zip, 7z, gpg or openssl enc read home, .ssh, .aws or shadow paths and wrote into a temporary or hidden directory. Data is packed before it is sent out."),
    ("collection.clipboard", "Clipboard read", "xclip, xsel or wl-paste was run to read the clipboard. Copied passwords and wallet addresses are stolen this way."),
    ("collection.local_sweep", "Documents swept", "50 or more documents, databases or keys under home directories were read by one task."),
    ("impact.ransom_rewrite", "Mass rename to one extension", "20 or more files were renamed to the same new extension within 30 seconds. Only the rename pattern is judged, not the entropy of what was written."),
    ("impact.mass_rewrite", "Mass file rewrite", "Many files were renamed to one new extension and/or rewritten in place within 60 seconds. Only the pattern of renames and writes is judged."),
    ("impact.mass_delete", "Mass file deletion", "100 or more files that the run did not create were deleted within 30 seconds, from at least three directories."),
    ("impact.block_device_write", "Block device written or wiped", "A disk, partition or flash device was opened for writing or written, or an ioctl discarded, zeroed or erased it. Data is destroyed or overwritten."),
    ("impact.reboot", "Reboot or shutdown", "reboot, kexec, shutdown, poweroff or systemctl reboot was called. It ends the run and may load another kernel."),
    ("impact.miner", "Crypto miner", "A known miner program (xmrig and others) ran, a command line had mining arguments, or the Stratum mining protocol was sent to a server."),
    ("impact.miner_tuning", "Tuning the CPU for mining: huge pages, MSR", "Huge pages or the CPU's MSR registers were set, the tuning step that crypto miners perform to speed up hashing."),
    ("impact.fork_bomb", "Fork bomb", "More than 200 processes were created in one second, or 20 or more creations were refused with EAGAIN. The failing is itself the signal."),
    ("impact.ddos_flood", "Packet flood", "More than 1000 packets in one second were sent to the same address. Used to deny service to a target."),
    ("impact.service_stop", "Service stopped", "systemctl, service or a virtualisation command stopped, disabled or masked a service, or powered a virtual machine off. Availability is reduced."),
    ("impact.inhibit_recovery", "Backups or snapshots removed", "A backup file or directory (/var/backups, .bak) was deleted, or lvremove, btrfs subvolume delete, zfs destroy or a snapshot removal ran. Recovery is made harder."),
    ("bpf.program", "Running code in the kernel: eBPF program", "A BPF program was loaded or attached through bpf, a link, a raw tracepoint or a perf event. eBPF runs in the kernel and is used by rootkits and by legitimate tracers; Details gives the program and target."),
    ("rootkit.dev_mem", "Kernel memory device accessed", "/dev/mem, /dev/kmem, /dev/port or /proc/kcore was opened. They give direct access to physical or kernel memory."),
    ("process.ptrace", "Process tracing: ptrace used", "A ptrace request that is neither an attach to another process nor a write into one. Debuggers and tracers call it all the time; it is context for the injection rules."),
    ("evasion.dumpable_off", "Avoiding being attached: dumpable turned off", "prctl(PR_SET_DUMPABLE, 0) was called, so that the process cannot be attached to or dumped."),
    ("evasion.io_uring_usage", "Doing work with few system calls: io_uring", "io_uring_setup or io_uring_enter was called. Work done through a ring makes few system calls, so a tracer sees little of it."),
    ("bpf.seccomp_filter", "Restricting own system calls: seccomp filter", "A classic seccomp filter was installed. Services sandbox themselves this way, and so can a program that wants to stop a tracer."),
    ("c2.bind_shell", "Bind shell", "A shell or interpreter was started with an accepted client connection as its input and output. Someone connected in and got a command line."),
    ("network.listen_any", "Listening on all interfaces", "A TCP listen or a UDP bind on a non-loopback address and a fixed port, other than DHCP, NTP, mDNS and LLMNR. The program waits for outside connections."),
    ("network.dead_c2", "Retries a dead command server", "Ten or more connects to one public address and port failed (refused, timed out, or the network or host unreachable) and none ever succeeded. A bot whose command server is gone keeps trying. Local addresses, DNS, NTP, DHCP and the base image's own programs are not counted; a few failed tries are ordinary."),
    ("collection.tty_inject", "Keystrokes injected into a terminal", "ioctl TIOCSTI pushed characters into a terminal's input. It runs commands in another session."),
    ("impact.ransom_note", "Same note in many directories", "The same file name was created in three or more directories, as a ransom note is. Ordinary project files are excluded."),
];

/// The short title of a rule, for a table cell and a heading. An id the
/// classification does not know comes back as it is.
pub fn rule_title(id: &str) -> &str {
    TEXTS
        .iter()
        .find(|(rule, _, _)| *rule == id)
        .map_or(id, |(_, title, _)| title)
}

/// One or two sentences: what the rule saw and why it matters. Empty for an
/// id the classification does not know.
pub fn rule_description(id: &str) -> &str {
    TEXTS
        .iter()
        .find(|(rule, _, _)| *rule == id)
        .map_or("", |(_, _, description)| description)
}

#[cfg(test)]
pub mod tests {
    use super::super::table::SPECS;
    use super::*;

    #[test]
    fn every_rule_has_a_title_and_a_description_and_no_text_is_orphaned() {
        assert_eq!(TEXTS.len(), SPECS.len());
        for spec in SPECS {
            let title = rule_title(spec.id);
            let description = rule_description(spec.id);
            assert_ne!(title, spec.id, "{} has no title", spec.id);
            assert!(
                !title.trim().is_empty() && title.chars().count() <= 60,
                "{}",
                spec.id
            );
            assert!(
                description.trim().len() > 20,
                "{} has no description",
                spec.id
            );
            assert!(description.ends_with('.'), "{}: {description}", spec.id);
        }
        for (id, _, _) in TEXTS {
            assert!(
                SPECS.iter().any(|spec| spec.id == *id),
                "{id} is not a rule"
            );
        }
    }

    #[test]
    fn titles_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for (id, title, _) in TEXTS {
            assert!(seen.insert(*title), "{id} repeats the title {title}");
        }
    }

    #[test]
    fn titles_start_with_the_behaviour_in_plain_words() {
        let technical = [
            "ptrace(", "prctl(", "PR_", "mmap", "mprotect", "memfd", "/proc", "/etc", "/dev",
            "argv", "chmod", "chattr", "setuid", "io_uring", "seccomp", "eBPF", "BPF", "LD_",
            "ld.so", "dumpable", "TRACEME",
        ];
        for (id, title, _) in TEXTS {
            let first = title.chars().next().unwrap();
            assert!(first.is_uppercase(), "{id}: {title}");
            assert!(title.chars().count() <= 60, "{id}: {title}");
            for word in technical {
                assert!(!title.starts_with(word), "{id}: {title} starts with {word}");
            }
            let lower = title.to_lowercase();
            for verdict in ["malicious", "malware"] {
                assert!(!lower.contains(verdict), "{id}: {title}");
            }
        }
        assert_eq!(
            rule_title("evasion.traceme"),
            "Anti-debug check through ptrace(TRACEME)"
        );
        assert_eq!(
            rule_title("evasion.dumpable_off"),
            "Avoiding being attached: dumpable turned off"
        );
        assert_eq!(
            rule_title("evasion.argv_masquerade"),
            "Hiding the process name: argv[0] rewritten"
        );
    }

    #[test]
    fn an_unknown_rule_keeps_its_id_and_has_no_description() {
        assert_eq!(rule_title("made.up"), "made.up");
        assert_eq!(rule_description("made.up"), "");
        assert_eq!(rule_title("persistence.cron"), "Cron job installed");
    }
}
