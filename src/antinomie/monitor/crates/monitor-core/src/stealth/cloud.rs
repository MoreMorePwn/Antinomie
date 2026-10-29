// SPDX-License-Identifier: GPL-3.0-only
//! Cloud VPS profiles: a VM that looks like an instance of a KVM cloud, not
//! like a PC. Most Linux malware runs on such machines, so honest KVM traces
//! are normal there (the CPUID hypervisor flag, kvm-clock, a provider's DMI
//! strings, virtio devices, QEMU's ACPI tables); what separates a sandbox
//! from an instance is a lived-in system and the cloud's own services. A
//! cloud profile therefore keeps the hypervisor visible, takes the provider's
//! firmware strings, chipset, MAC prefix and DHCP network, and gets a fake
//! per-provider metadata service (`route/metadata.rs`) in the Routed
//! network.
//!
//! Every value is from a public dump of an instance of the provider or from
//! the project's own probe of one, cited in `catalog/SOURCES-cloud.md` with a class
//! (A seen in a public dump of the provider, B a dump of another model or
//! provider, C recollection or derived: decision needed). Nothing here is a
//! provider's software: the lived-in state is files and inert stubs only
//! (`state_files`).
use super::{MachineIdentity, NatNetwork, random_text, uuid};

/// The QEMU machine type: the chipset the guest sees.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MachineType {
    /// q35: ICH9 and the PCIe root, what Antinomie launched before 0.8.0.
    #[default]
    Q35,
    /// pc: i440FX and PIIX3, the chipset most clouds still launch (Tencent
    /// CVM, Alibaba ECS and DigitalOcean).
    Pc,
}

impl MachineType {
    /// The `-machine` type name.
    pub fn qemu(self) -> &'static str {
        match self {
            Self::Q35 => "q35",
            Self::Pc => "pc",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Q35 => "q35 (ICH9)",
            Self::Pc => "i440FX (PIIX3)",
        }
    }
}

/// How a provider's metadata service is laid out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataStyle {
    /// Tencent Cloud: `/latest/meta-data/...`, CAM role credentials.
    Tencent,
    /// Alibaba Cloud: `/latest/meta-data/...`, RAM role credentials.
    Alibaba,
    /// DigitalOcean: `/metadata/v1/...` and `/metadata/v1.json`.
    DigitalOcean,
    /// Vultr: `/v1.json` and `/v1/...`.
    Vultr,
}

/// One purchasable size of a provider: vCPUs, RAM in MiB and disk in GiB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub name: &'static str,
    pub cpus: u16,
    pub ram_mib: u32,
    pub disk_gib: u32,
}

/// Who owns a state file: root, or the provider's default user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    Root,
    User,
}

/// One file of a cloud instance's lived-in state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateFile {
    pub path: String,
    pub mode: u32,
    /// Unix time the file was last changed.
    pub mtime: u64,
    pub owner: Owner,
    pub content: Vec<u8>,
}

/// glibc `struct utmp` of x86-64, as wtmp holds it: 384 bytes.
fn utmp_record(kind: i16, line: &str, id: &str, user: &str, host: &str, time: u64) -> Vec<u8> {
    let mut record = vec![0u8; 384];
    record[0..2].copy_from_slice(&kind.to_le_bytes());
    let put = |record: &mut [u8], at: usize, text: &str, max: usize| {
        let bytes = text.as_bytes();
        let len = bytes.len().min(max);
        record[at..at + len].copy_from_slice(&bytes[..len]);
    };
    put(&mut record, 8, line, 32);
    put(&mut record, 40, id, 4);
    put(&mut record, 44, user, 32);
    put(&mut record, 76, host, 256);
    record[340..344].copy_from_slice(&(time as u32).to_le_bytes());
    record
}

/// A few days of logins as wtmp records: an earlier boot, and the default
/// user's SSH sessions from other hosts, each ended.
fn wtmp(user: &str, now: u64) -> Vec<u8> {
    const DAY: u64 = 86_400;
    let mut data = Vec::new();
    data.extend(utmp_record(
        2,
        "~",
        "~~",
        "reboot",
        "6.12.94",
        now.saturating_sub(12 * DAY),
    ));
    for (days, pid_line, host, minutes) in [
        (11, "pts/0", "203.0.113.17", 21),
        (7, "pts/0", "198.51.100.42", 9),
        (4, "pts/1", "203.0.113.17", 47),
        (1, "pts/0", "198.51.100.8", 12),
    ] {
        let start = now.saturating_sub(days * DAY) + 3 * 3600;
        let id = &pid_line[pid_line.len() - 3..];
        data.extend(utmp_record(7, pid_line, id, user, host, start));
        data.extend(utmp_record(8, pid_line, id, "", host, start + minutes * 60));
    }
    data
}

/// What a cloud's guest runs as its default login, and the agents it ships
/// (as files and inert stubs; no provider binary is copied).
#[derive(Debug, PartialEq, Eq)]
pub struct GuestState {
    pub default_user: &'static str,
    /// The cloud-init data source, `cloud.cfg`'s `datasource_list`.
    pub datasource: &'static str,
    /// Agent directories, units and their states (path, mode, content).
    pub agents: &'static [(&'static str, &'static str)],
    /// Region the instance is "in" and the instance id's form.
    pub region: &'static str,
    pub instance_prefix: &'static str,
}

/// One cloud provider whose instances are honest KVM guests.
#[derive(Debug, PartialEq, Eq)]
pub struct CloudProvider {
    pub id: &'static str,
    pub label: &'static str,
    pub machine: MachineType,
    pub bios: (&'static str, &'static str, &'static str),
    /// Manufacturer, product, version, family of the system (type 1).
    pub system: (&'static str, &'static str, &'static str, &'static str),
    pub board: (&'static str, &'static str, &'static str),
    pub chassis_manufacturer: &'static str,
    pub chassis_type: u8,
    pub cpu_manufacturer: &'static str,
    pub cpu_version: &'static str,
    pub memory_manufacturer: &'static str,
    /// The vendor part of the MAC address; None: a random locally
    /// administered address, as providers that number guests themselves.
    pub mac_prefix: Option<[u8; 3]>,
    /// network, gateway, DNS, first DHCP address.
    pub nat: (&'static str, &'static str, &'static str, &'static str),
    /// The VMware backdoor port (VMMouse in the guest).
    pub vmport: bool,
    /// An empty QEMU DVD-ROM drive.
    pub cdrom: bool,
    pub serial_digits: usize,
    pub metadata_ip: &'static str,
    pub metadata_name: &'static str,
    pub metadata: MetadataStyle,
    pub state: GuestState,
    pub plans: &'static [Plan],
}

const fn plan(name: &'static str, cpus: u16, ram_mib: u32, disk_gib: u32) -> Plan {
    Plan {
        name,
        cpus,
        ram_mib,
        disk_gib,
    }
}

pub const CLOUDS: &[CloudProvider] = &[
    CloudProvider {
        id: "cloud-tencent-cvm",
        label: "Tencent Cloud CVM",
        machine: MachineType::Pc,
        bios: ("SeaBIOS", "seabios-1.9.1-qemu-project.org", "04/01/2014"),
        system: ("Tencent Cloud", "CVM", "3.0", ""),
        board: ("Tencent Cloud", "CVM", ""),
        chassis_manufacturer: "QEMU",
        chassis_type: 1,
        cpu_manufacturer: "Smdbmds",
        cpu_version: "pc-i440fx-2.1",
        memory_manufacturer: "Smdbmds",
        mac_prefix: Some([0x52, 0x54, 0x00]),
        nat: ("10.3.0.0/22", "10.3.0.1", "10.3.0.2", "10.3.0.15"),
        vmport: true,
        cdrom: true,
        serial_digits: 0,
        metadata_ip: "169.254.0.23",
        metadata_name: "metadata.tencentyun.com",
        metadata: MetadataStyle::Tencent,
        state: GuestState {
            default_user: "ubuntu",
            datasource: "[ NoCloud, ConfigDrive, OpenStack, Ec2, None ]",
            agents: &[
                ("/usr/local/qcloud/stargate/conf/stargate.conf", "0644"),
                ("/usr/local/qcloud/monitor/barad/conf/sys.conf", "0644"),
                ("/usr/local/qcloud/YunJing/conf/version", "0644"),
                ("/usr/local/qcloud/tat_agent/conf/tat_agent.conf", "0644"),
                ("/etc/systemd/system/tat_agent.service", "0644"),
            ],
            region: "ap-guangzhou",
            instance_prefix: "ins-",
        },
        plans: &[
            plan("S5.SMALL1", 1, 1024, 50),
            plan("S5.MEDIUM2", 2, 2048, 50),
            plan("S5.MEDIUM4", 2, 4096, 50),
        ],
    },
    CloudProvider {
        id: "cloud-alibaba-ecs",
        label: "Alibaba Cloud ECS",
        machine: MachineType::Pc,
        bios: (
            "SeaBIOS",
            "rel-1.7.5-0-ge51488c-20140602_164612-nilsson.home.kraxel.org",
            "04/01/2014",
        ),
        system: ("Alibaba Cloud", "Alibaba Cloud ECS", "pc-i440fx-2.1", ""),
        board: ("Alibaba Cloud", "Alibaba Cloud ECS", ""),
        chassis_manufacturer: "Alibaba Cloud",
        chassis_type: 1,
        cpu_manufacturer: "Alibaba Cloud",
        cpu_version: "pc-i440fx-2.1",
        memory_manufacturer: "Alibaba Cloud",
        mac_prefix: Some([0x00, 0x16, 0x3e]),
        nat: ("172.16.0.0/20", "172.16.0.1", "172.16.0.2", "172.16.0.15"),
        vmport: false,
        cdrom: false,
        serial_digits: 0,
        metadata_ip: "100.100.100.200",
        metadata_name: "",
        metadata: MetadataStyle::Alibaba,
        state: GuestState {
            default_user: "root",
            datasource: "[ AliYun, None ]",
            agents: &[
                ("/usr/local/aegis/aegis_client/version", "0644"),
                ("/usr/local/share/aliyun-assist/version", "0644"),
                ("/etc/systemd/system/aliyun.service", "0644"),
                (
                    "/etc/systemd/system/multi-user.target.wants/aegis.service",
                    "0644",
                ),
            ],
            region: "cn-hangzhou",
            instance_prefix: "i-",
        },
        plans: &[
            plan("ecs.t6-c1m1.large", 2, 2048, 40),
            plan("ecs.t6-c1m2.large", 2, 4096, 40),
        ],
    },
    CloudProvider {
        id: "cloud-digitalocean-droplet",
        label: "DigitalOcean Droplet",
        machine: MachineType::Pc,
        bios: ("DigitalOcean", "20171212", "12/12/2017"),
        system: (
            "DigitalOcean",
            "Droplet",
            "20171212",
            "DigitalOcean_Droplet",
        ),
        board: ("DigitalOcean", "Droplet", ""),
        chassis_manufacturer: "QEMU",
        chassis_type: 1,
        cpu_manufacturer: "QEMU",
        cpu_version: "pc-i440fx-6.1",
        memory_manufacturer: "QEMU",
        mac_prefix: None,
        nat: ("10.116.0.0/20", "10.116.0.1", "10.116.0.2", "10.116.0.15"),
        vmport: false,
        cdrom: true,
        serial_digits: 9,
        metadata_ip: "169.254.169.254",
        metadata_name: "",
        metadata: MetadataStyle::DigitalOcean,
        state: GuestState {
            default_user: "root",
            datasource: "[ DigitalOcean, None ]",
            agents: &[
                ("/opt/digitalocean/bin/droplet-agent", "0755"),
                ("/etc/systemd/system/droplet-agent.service", "0644"),
                ("/etc/digitalocean/droplet-agent.conf", "0644"),
            ],
            region: "nyc3",
            instance_prefix: "",
        },
        plans: &[
            plan("s-1vcpu-1gb", 1, 1024, 25),
            plan("s-1vcpu-2gb", 1, 2048, 50),
            plan("s-2vcpu-2gb", 2, 2048, 60),
            plan("s-2vcpu-4gb", 2, 4096, 80),
        ],
    },
    CloudProvider {
        id: "cloud-vultr-vc2",
        label: "Vultr Cloud Compute (VC2)",
        machine: MachineType::Q35,
        bios: ("Vultr", "", ""),
        system: ("Vultr", "VC2", "pc-q35-7.0", "KVM"),
        board: ("Vultr", "VC2", ""),
        chassis_manufacturer: "QEMU",
        chassis_type: 1,
        cpu_manufacturer: "QEMU",
        cpu_version: "pc-q35-7.0",
        memory_manufacturer: "QEMU",
        mac_prefix: Some([0x56, 0x00, 0x03]),
        nat: ("10.1.96.0/22", "10.1.96.1", "10.1.96.2", "10.1.96.15"),
        vmport: false,
        cdrom: false,
        serial_digits: 0,
        metadata_ip: "169.254.169.254",
        metadata_name: "",
        metadata: MetadataStyle::Vultr,
        state: GuestState {
            default_user: "root",
            datasource: "[ Vultr, None ]",
            agents: &[("/etc/vultr/instance.conf", "0644")],
            region: "ewr",
            instance_prefix: "",
        },
        plans: &[
            plan("vc2-1c-1gb", 1, 1024, 25),
            plan("vc2-1c-2gb", 1, 2048, 55),
            plan("vc2-2c-4gb", 2, 4096, 80),
        ],
    },
];

impl CloudProvider {
    pub fn find(id: &str) -> Option<&'static Self> {
        CLOUDS.iter().find(|provider| provider.id == id)
    }

    /// The provider's DHCP network.
    pub fn nat(&self) -> NatNetwork {
        NatNetwork {
            network: self.nat.0.into(),
            gateway: self.nat.1.into(),
            dns: self.nat.2.into(),
            dhcp_start: self.nat.3.into(),
        }
    }

    /// The firmware strings of a new instance, with fresh serial and UUID.
    pub fn identity(&self) -> MachineIdentity {
        let (vendor, version, date) = self.bios;
        let (maker, product, system_version, family) = self.system;
        let serial = if self.serial_digits == 0 {
            uuid()
        } else {
            random_text(b"0123456789", self.serial_digits)
        };
        MachineIdentity {
            profile: self.id.into(),
            bios_vendor: vendor.into(),
            bios_version: version.into(),
            bios_date: date.into(),
            virtual_machine: true,
            system_manufacturer: maker.into(),
            system_product: product.into(),
            system_version: system_version.into(),
            system_family: family.into(),
            system_serial: serial.clone(),
            system_uuid: uuid(),
            board_manufacturer: self.board.0.into(),
            board_product: self.board.1.into(),
            board_version: self.board.2.into(),
            board_serial: serial.clone(),
            chassis_type: self.chassis_type,
            chassis_manufacturer: self.chassis_manufacturer.into(),
            chassis_serial: serial,
            cpu_socket: "CPU 0".into(),
            cpu_manufacturer: self.cpu_manufacturer.into(),
            cpu_version: self.cpu_version.into(),
            memory_manufacturer: self.memory_manufacturer.into(),
            memory_slots: vec![super::MemorySlot {
                locator: "DIMM 0".into(),
                bank: String::new(),
            }],
            memory_form: 9,
            memory_detail: 0x0080,
            memory_type: 0x07,
            memory_speed: 0,
            memory_rank: 0,
            memory_width: 0,
            ..MachineIdentity::default()
        }
    }

    /// The plan whose size is the VM's, if the provider sells one.
    pub fn plan_for(&self, cpus: u16, ram_mib: u32) -> Option<&Plan> {
        self.plans
            .iter()
            .find(|plan| plan.cpus == cpus && plan.ram_mib == ram_mib)
    }

    /// The instance id of the VM whose system UUID is `uuid`, in the
    /// provider's form: the same at every boot, different for every VM.
    pub fn instance_id(&self, uuid: &str) -> String {
        let hex: String = uuid.chars().filter(char::is_ascii_hexdigit).collect();
        let digits: String = hex
            .chars()
            .map(|c| char::from(b'0' + (c.to_digit(16).unwrap_or(0) % 10) as u8))
            .collect();
        match self.metadata {
            MetadataStyle::DigitalOcean => format!("3{}", &digits[..digits.len().min(8)]),
            MetadataStyle::Vultr => uuid.to_owned(),
            _ => format!("{}{}", self.state.instance_prefix, &hex[..hex.len().min(8)]),
        }
    }

    /// The host name a new instance of the provider starts with.
    pub fn hostname(&self, instance_id: &str) -> String {
        match self.metadata {
            MetadataStyle::Tencent => {
                // Named after the private address: 10.3.0.15 is VM-0-15-ubuntu.
                let octets: Vec<&str> = self.nat.3.split('.').collect();
                format!("VM-{}-{}-ubuntu", octets[2], octets[3])
            }
            MetadataStyle::Alibaba => format!("iZ{instance_id}Z"),
            MetadataStyle::DigitalOcean => {
                format!("ubuntu-s-1vcpu-1gb-{}-01", self.state.region)
            }
            MetadataStyle::Vultr => "vultr".to_owned(),
        }
    }

    /// The files a cloud instance of this provider has from its first boot,
    /// as inert content (no provider binary): cloud-init's state for
    /// `instance_id`, the default user's shell history, the login records
    /// (wtmp) and log, and the agents' directories. `now` is the Unix time
    /// the files are aged from. Per VM: a base keeps nothing of a provider.
    pub fn state_files(&self, instance_id: &str, hostname: &str, now: u64) -> Vec<StateFile> {
        const DAY: u64 = 86_400;
        let user = self.state.default_user;
        let home = if user == "root" {
            "/root".to_owned()
        } else {
            format!("/home/{user}")
        };
        let text = |path: &str, mode: u32, age: u64, owner: Owner, content: String| StateFile {
            path: path.to_owned(),
            mode,
            mtime: now.saturating_sub(age),
            owner,
            content: content.into_bytes(),
        };
        let instance = format!("/var/lib/cloud/instances/{instance_id}");
        let log_time = now.saturating_sub(12 * DAY);
        let mut files = vec![
            text("/var/lib/cloud/data/instance-id", 0o644, 12 * DAY, Owner::Root, format!("{instance_id}\n")),
            text("/var/lib/cloud/data/previous-instance-id", 0o644, 12 * DAY, Owner::Root, "NO_PREVIOUS_INSTANCE_ID\n".into()),
            text(
                "/var/lib/cloud/data/result.json",
                0o644,
                12 * DAY,
                Owner::Root,
                format!(
                    "{{\n \"v1\": {{\n  \"datasource\": \"DataSource{}\",\n  \"errors\": []\n }}\n}}\n",
                    self.datasource_name()
                ),
            ),
            text(&format!("{instance}/datasource"), 0o644, 12 * DAY, Owner::Root, format!("DataSource{}\n", self.datasource_name())),
            text(&format!("{instance}/boot-finished"), 0o644, 12 * DAY, Owner::Root, format!("{log_time}.52 - up 21.40\n")),
            text(&format!("{instance}/user-data.txt"), 0o600, 12 * DAY, Owner::Root, "#cloud-config\n{}\n".into()),
            text("/etc/cloud/cloud.cfg.d/90_provider.cfg", 0o644, 12 * DAY, Owner::Root, format!("datasource_list: {}\n", self.state.datasource)),
            text("/etc/hostname", 0o644, 12 * DAY, Owner::Root, format!("{hostname}\n")),
            text(
                "/var/log/cloud-init.log",
                0o640,
                12 * DAY,
                Owner::Root,
                format!(
                    "2026-01-01 08:00:01,201 - util.py[DEBUG]: Cloud-init v. 24.1.3 running 'init-local' at boot ({})\n\
                     2026-01-01 08:00:03,774 - __init__.py[DEBUG]: Found datasource DataSource{} for instance {instance_id}\n\
                     2026-01-01 08:00:21,409 - handlers.py[DEBUG]: finish: modules-final: SUCCESS\n",
                    self.label,
                    self.datasource_name()
                ),
            ),
            text(
                "/var/log/cloud-init-output.log",
                0o640,
                12 * DAY,
                Owner::Root,
                "Cloud-init v. 24.1.3 finished at boot. Datasource found. Up 21.40 seconds\n".into(),
            ),
            text(
                &format!("{home}/.bash_history"),
                0o600,
                DAY,
                if user == "root" { Owner::Root } else { Owner::User },
                "ls -la\ndf -h\nfree -m\nsudo apt update\nsudo apt -y upgrade\nsystemctl status ssh\ncat /var/log/auth.log | tail\nexit\n"
                    .into(),
            ),
            text(
                "/var/log/auth.log",
                0o640,
                3_600,
                Owner::Root,
                format!(
                    "Jan  9 06:41:12 {hostname} sshd[611]: Accepted publickey for {user} from 203.0.113.17 port 51724 ssh2\n\
                     Jan  9 06:41:12 {hostname} sshd[611]: pam_unix(sshd:session): session opened for user {user}\n\
                     Jan  9 07:02:40 {hostname} sshd[611]: pam_unix(sshd:session): session closed for user {user}\n"
                ),
            ),
        ];
        files.push(StateFile {
            path: "/var/log/wtmp".into(),
            mode: 0o664,
            mtime: now.saturating_sub(3_600),
            owner: Owner::Root,
            content: wtmp(user, now),
        });
        for (path, mode) in self.state.agents {
            files.push(text(
                path,
                if *mode == "0755" { 0o755 } else { 0o644 },
                12 * DAY,
                Owner::Root,
                "# inert stub\n".into(),
            ));
        }
        files
    }

    fn datasource_name(&self) -> &'static str {
        match self.metadata {
            MetadataStyle::Tencent | MetadataStyle::Alibaba => "Ec2",
            MetadataStyle::DigitalOcean => "DigitalOcean",
            MetadataStyle::Vultr => "Vultr",
        }
    }
}
