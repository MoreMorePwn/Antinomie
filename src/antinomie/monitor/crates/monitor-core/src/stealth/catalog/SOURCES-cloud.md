# Cloud profile sources

The cloud VPS profiles (`stealth/cloud.rs`) are instances of KVM clouds, not PCs, so their values come from public dmidecode and dmesg dumps of provider instances, and for Tencent from the project's own probe of a real CVM. Collected on 2026-10-29. The classes are those of `SOURCES.md`: A seen in a dump of this provider, B seen in a dump of another provider or model, C recollection, derived or unverified (decision needed). Nothing hidden by a dump was guessed; serial numbers and UUIDs are random per VM like the catalog's.

Dumps: [openbenchmarking.org](https://openbenchmarking.org) publishes the `dmidecode` and `dmesg` of the systems users benchmark. Its pages sit behind a bot check, so the values were read from search-result excerpts of the pages named below, not from the pages themselves; every excerpt is a value of a dump, but none was re-read in full.

## What every cloud profile does the same

| Field | Value | Class | Source |
| --- | --- | --- | --- |
| CPUID hypervisor flag, KVM signature, kvm-clock | visible | A | Tencent probe (`Hypervisor detected: KVM`, `kvm-clock`); DigitalOcean dmesg `Hypervisor detected: KVM` ([dmesg](https://openbenchmarking.org/system/2304186-EDGE-D09063818/2%20x%20Red%20Hat%20Virtio%20device/dmesg)). A hidden flag on a cloud DMI would itself be odd. |
| Firmware | SeaBIOS (BIOS), type 0 "system is a virtual machine" bit set | A | DigitalOcean dump (`System is a virtual machine`); Tencent probe (seabios) |
| Network card, disk | virtio-net, virtio-blk (`vda`), Red Hat PCI subsystem IDs | A | Tencent probe (virtio net/blk/balloon, 1af4 subsystems) |
| Memory | one DIMM sized to the VM, `DIMM 0`, type RAM, speed unknown | A (Tencent: 1 DIMM) | Tencent probe |
| Processor table | the host CPU's ID and caches; maker and version from the provider | see below | |

## Tencent Cloud CVM (`cloud-tencent-cvm`, i440FX)

Source: the project's own probe of a real Tencent Cloud CVM (Ubuntu, kernel 7.0, KVM) on 2026-10-29 (`dmidecode`, `dmesg` and the instance's files on the project's own instance); no public URL, and no identifier of that instance is used.

| Field | Value | Class | Note |
| --- | --- | --- | --- |
| system | `Tencent Cloud` / `CVM` / `3.0` | A | probe |
| BIOS | `SeaBIOS` / `seabios-1.9.1-qemu-project.org` | A | probe |
| BIOS date | `04/01/2014` | B | the date SeaBIOS dumps of the Alibaba instances show |
| board | `Tencent Cloud` / `CVM` | C | the probe lists the system, not the board |
| chassis | type 1 (Other), maker `QEMU` | A (type), C (maker) | |
| processor and DIMM maker | `Smdbmds` | A | probe (type 4 and 17) |
| processor version | `pc-i440fx-2.1` | B | QEMU's version string as the Alibaba dump shows it |
| chipset | i440FX (`8086:1237`), PIIX3, VMMouse (`vmport`), QEMU DVD-ROM | A | probe |
| MAC prefix | `52:54:00` | A | probe |
| DHCP network | `10.3.0.0/22` | A (network), C (gateway .1, DNS .2, first lease .15) | probe; Tencent's resolvers are public addresses, which the NAT cannot give a guest |
| metadata | `metadata.tencentyun.com` = 169.254.0.23, `/latest/meta-data/...`, CAM role credentials `cam/security-credentials/<role>` with `TmpSecretId`, `TmpSecretKey`, `Token`, `ExpiredTime` | A (address and name, from the card), C (the path layout and field names: recollection of Tencent's documentation, not re-checked) | |
| default user, agents | `ubuntu`; `/usr/local/qcloud` (stargate, barad, YunJing, tat_agent), `tat_agent.service` | A (directory names, from the card), C (file names inside) | files and one-line stubs only, no binary |
| host name | `VM-<a>-<b>-ubuntu` from the private address | C | recollection of Tencent's default |

## Alibaba Cloud ECS (`cloud-alibaba-ecs`, i440FX)

Sources: dumps of Alibaba Cloud ECS instances: [Xeon E5-2682 v4](https://openbenchmarking.org/system/1903100-RA-CPUALICRA79/Intel%20Xeon%20E5-2682%20v4/dmidecode), [Xeon Platinum 8163](https://openbenchmarking.org/system/1810151-TY-IOTEST01749/Intel%20Xeon%20Platinum%208163%20-%20cirrusdrmfb%20-%20Alibaba/dmidecode).

| Field | Value | Class | Note |
| --- | --- | --- | --- |
| system | `Alibaba Cloud` / `Alibaba Cloud ECS` / `pc-i440fx-2.1` | A | |
| BIOS | `SeaBIOS`, `04/01/2014`, version `rel-1.7.5-...` | A (vendor, date, `rel-1.7.5`) | the build suffix `-0-ge51488c-20140602_164612-nilsson.home.kraxel.org` is C: the excerpts show only `rel-1.7.5` |
| chassis, processor maker | `Alibaba Cloud`; processor version `pc-i440fx-2.1` | A | |
| board | `Alibaba Cloud` / `Alibaba Cloud ECS` | C | |
| MAC prefix | `00:16:3e` | C | recollection |
| DHCP network | `172.16.0.0/20`, gateway .1, DNS .2, lease .15 | C | Alibaba's real resolvers (100.100.2.x) are outside a private network |
| metadata | 100.100.100.200, `/latest/meta-data/...`, RAM role credentials `ram/security-credentials/<role>` with `AccessKeyId`, `AccessKeySecret`, `SecurityToken`, `Expiration` | C | recollection of Alibaba's documentation, not re-checked |
| default user, agents | `root`; `/usr/local/aegis`, `aliyun-assist` | C | |

## DigitalOcean Droplet (`cloud-digitalocean-droplet`, i440FX)

Sources: [dmidecode of a Droplet](https://openbenchmarking.org/system/2304181-EDGE-D13783818/DO-Regular%20-%20Red%20Hat%20QXL%20paravirtual%20graphic%20card%20-/dmidecode), [a second](https://openbenchmarking.org/system/2304186-EDGE-D09063818/2%20x%20Red%20Hat%20Virtio%20device/dmidecode), its dmesg (`DMI: DigitalOcean Droplet/Droplet, BIOS 20171212 12/12/2017`), and [a hardware report of a Rocky Linux Droplet](https://c3.ciq.com/submissions/6a5ff28f-cca2-4183-8f95-fc5093efa575) (machine `pc-i440fx-6.1`, 440FX chipset).

| Field | Value | Class | Note |
| --- | --- | --- | --- |
| BIOS | vendor `DigitalOcean`, version `20171212`, date `12/12/2017` | A | |
| system | `DigitalOcean` / `Droplet` / `20171212`, family `DigitalOcean_Droplet` | A | |
| board | `DigitalOcean` / `Droplet` | A | |
| chassis, processor maker, DIMM maker | `QEMU`; processor version `pc-i440fx-6.1` | C (maker), B (version: the machine type of the CIQ report) | |
| serial | 9 digits, the Droplet id | C | |
| MAC | random locally administered | C | recollection |
| DHCP network | `10.116.0.0/20` | C | a VPC range of the form DigitalOcean assigns |
| metadata | 169.254.169.254, `/metadata/v1.json`, `/metadata/v1/{id,hostname,region,user-data,...}`; the canary sits in user-data | C | recollection of DigitalOcean's documentation, not re-checked |
| default user, agents | `root`; `/opt/digitalocean/bin/droplet-agent` | C | |

## Vultr Cloud Compute (`cloud-vultr-vc2`, q35)

Sources: dumps of Vultr VC2 instances: [Intel Core - bochs-drmdrmfb - Vultr VC2](https://openbenchmarking.org/system/2304181-EDGE-V39593818/Intel%20Core%20-%20bochs-drmdrmfb%20-%20Vultr%20VC2/dmidecode), [Red Hat Virtio device](https://openbenchmarking.org/system/2304180-EDGE-V49104818/Red%20Hat%20Virtio%20device/dmidecode).

| Field | Value | Class | Note |
| --- | --- | --- | --- |
| BIOS | vendor `Vultr`, version and date not specified | A | |
| system | `Vultr` / `VC2` / `pc-q35-7.0`, family `KVM` | A | |
| chassis, processor | maker `QEMU` | A | |
| board | `Vultr` / `VC2` | C | |
| chipset | q35 | A | machine type `pc-q35-7.0` |
| MAC prefix | `56:00:03` | C | recollection |
| DHCP network | `10.1.96.0/22` | C | Vultr guests have public addresses, which the NAT cannot give |
| metadata | 169.254.169.254, `/v1.json`, `/v1/...`, `/latest/user-data`; the canary sits in user-data | C | recollection of Vultr's documentation, not re-checked |

## Not done

* **Hetzner (vServer)** and **Linode/Akamai**: no public dump with their DMI strings was found (searches on 2026-10-29 returned none), and nothing was guessed. They need a dump from an instance.
* **Plans** (`CloudProvider::plans`): vCPU, RAM and disk of common plans from recollection of the providers' price pages (class C); they are only hints.
* The display is the base's fixed one (Bochs or virtio-gpu), not Cirrus (Tencent, Alibaba) or QXL (DigitalOcean); the PCI subsystem IDs of the chipset devices are Red Hat's.

## Fake metadata service

The service answers the provider's address on every route inside the Routed network's gateway (nothing leaves the host, no real cloud is contacted). Credentials are canaries: `AKIDANTCANARY...`, `STS.ANTCANARY...`, `dop_v1_antcanary...`, `ANTCANARY...` followed by random characters, new for each run, in the provider's layout and obviously not accepted by any cloud. No real credential, key or metadata response of a provider is used. Requests, hand-outs and uses of the canary go to `cloud-metadata.json` in the run's folder.
