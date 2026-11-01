# arm64 machine sources

The arm64 machines (`stealth/catalog/arm64.rs`, MA-17) are what an arm64 VM booting through UEFI presents. Collected on 2026-11-01 from public sources only. Classes as in `SOURCES.md`: A seen in a public report of this machine, B seen in a report of another model of the maker (or another instance type of the provider), C recollection, derived or unverified (decision needed). Serial numbers and UUIDs are random per VM, from the VM's UUID; no serial of a real unit is used.

Sources:

- [Ubuntu certification: Giga Computing R272-P33 (Altra)](https://ubuntu.com/certified/202412-36110): BIOS `GIGABYTE: F33j (SCP: 2.10.20220531) (UEFI)`, processor `Ampere(TM) Ampere(R) Altra(R) Processor`, NICs Broadcom BCM57414 and Intel I350 (8086:1521), ASPEED graphics.
- [Ubuntu certification: HPE ProLiant RL300 Gen11 (Altra Max)](https://ubuntu.com/certified/202212-30922/24.04%20LTS): BIOS `HPE` 1.10, 1.20, 1.60, 1.84; board `HPE ProLiant RL300 Gen11`; Mellanox ConnectX-6 Lx; NVMe from Samsung, KIOXIA, SK hynix.
- [OpenBenchmarking search excerpt](https://openbenchmarking.org/s/Ampere+ARMv8+Neoverse-N1+128-Core): `ARMv8 Neoverse-N1 @ 3.00GHz (80 Cores)`, `HPE ProLiant RL300 Gen11 (1.10 BIOS)`.
- [Ubuntu certification: ADLINK Ampere Altra Developer Platform](https://ubuntu.com/certified/202203-30097): BIOS `ADLINK: TianoCore 2.04.100.04 (SYS: 2..6.20220308) (UEFI)`, Intel I210 (8086:1533), ASPEED graphics.
- OpenBenchmarking dmidecode dumps of EC2 Graviton instances (behind a bot check; read from search-result excerpts as `SOURCES-cloud.md` does): [Neoverse-N1 (c6g.4xlarge)](https://openbenchmarking.org/system/2212196-NE-20221219105/ARMv8%20Neoverse-N1/dmidecode) BIOS `Amazon EC2` `1.0` `11/1/2018`, processor `AWS` / `AWS Graviton2`, 2500 MHz; [Neoverse-V1 (Graviton3E)](https://openbenchmarking.org/system/2311305-NE-HPC7G16XL21/ARMv8%20Neoverse-V1/dmidecode) the same BIOS and "system is a virtual machine"; result pages name the board `Amazon EC2 c6g.xlarge (1.0 BIOS)`.
- [AWS Graviton getting-started guide, monitoring tools](https://github.com/aws/aws-graviton-getting-started/blob/main/Monitoring_Tools_on_Graviton.md): dmidecode `Socket Designation CPU00`, `Family ARMv8`, `Manufacturer AWS`.
- MAC prefixes: the IEEE MA-L registry (Debian `ieee-data`, `oui.txt`): `E0:D5:5E` Giga-byte Technology, `A0:36:9F` Intel Corporate, `00:30:64` Adlink Technology.

## What every arm64 machine does the same

| Field | Value | Class | Note |
| --- | --- | --- | --- |
| CPU | QEMU `neoverse-n1`, MIDR `0x413fd0c1` (Neoverse N1 r3p1) | C | Altra and Graviton2 are Neoverse N1 (A, every source above); the r3p1 revision is recollection of public `/proc/cpuinfo` dumps (`CPU variant 0x3`, `CPU revision 1`) |
| Firmware | AAVMF (EDK II), UEFI with ACPI | B | Ampere's and AWS's arm64 firmware are EDK II based (ADLINK's BIOS string names TianoCore) |
| Processor table | family ARMv8 (0x101), ID = MIDR, the machine's speed, one core per vCPU | B (family), C (layout) | |
| Caches | 64 KiB L1i, 64 KiB L1d, 1 MiB L2 per core, no L3 table | C | Neoverse N1's |
| Network card | Intel 82576 (QEMU `igb`) | C | the boards' I350/I210 use the same driver (igb); QEMU has no I350, I210, Broadcom, Mellanox or ENA model: a listed giveaway |
| Disk | SATA SSD on ICH9 AHCI | C | QEMU's NVMe controller names itself `QEMU NVMe Ctrl`; AHCI on an arm64 board is a listed giveaway |
| Memory | DDR4-3200 registered ECC DIMMs (servers, workstation) | C | |

## Giga Computing R272-P33 (`arm-gigabyte-r272-p33`)

| Field | Value | Class |
| --- | --- | --- |
| BIOS | `GIGABYTE` / `F33j (SCP: 2.10.20220531)` | A |
| BIOS date | `06/16/2022` | C (after the SCP date) |
| system | `GIGABYTE` / `R272-P33-00` / `0100` / `Server` | B (maker), C (the rest) |
| board | `GIGABYTE` / `MP32-AR1-00` / `01000100` | C |
| chassis | `GIGABYTE`, type 23 (rack mount) | C |
| processor | `Ampere(TM)` / `Ampere(R) Altra(R) Processor`, 3000 MHz | A (strings), C (speed: a Q80-30) |
| ACPI OEM | `Ampere` / `Altra` | C |
| timer | 25 MHz | C |
| MAC prefix | `e0:d5:5e` | A (IEEE) |
| disk, memory | Samsung PM883 `MZ7LH480HAHQ-00005`, Samsung `M393A2K43DB3-CWE` | C |

## HPE ProLiant RL300 Gen11 (`arm-hpe-rl300-gen11`)

| Field | Value | Class |
| --- | --- | --- |
| BIOS | `HPE` / `1.10` | A |
| BIOS date | `08/04/2022` | C |
| system, board | `HPE` / `ProLiant RL300 Gen11`, family `ProLiant` | A (board), B (family as HPE's x86 ProLiants) |
| chassis | `HPE`, type 23 | C |
| processor | `Ampere(TM)` / `Ampere(R) Altra(R) Processor`, 3000 MHz | A (80 cores at 3.00 GHz), B (strings from the Giga Computing unit) |
| ACPI OEM | `HPE` / `Server` | C |
| MAC prefix | `a0:36:9f` (an Intel adapter) | A (IEEE) |
| disk, memory | Micron 5300 `MTFDDAK480TDS`, Samsung `M393A4K40DB3-CWE` | C |

## ADLINK Ampere Altra Developer Platform (`arm-adlink-altra-dev`)

| Field | Value | Class |
| --- | --- | --- |
| BIOS | `ADLINK` / `TianoCore 2.04.100.04 (SYS: 2..6.20220308)` | A |
| BIOS date | `03/08/2022` | C (after the SYS date) |
| system | `ADLINK Technology Inc.` / `Ampere Altra Developer Platform` / `Rev.A1` / `AVA` | A (product), C (the rest) |
| board | `ADLINK Technology Inc.` / `COM-HPC-ALT` | C (ADLINK's module name) |
| chassis | type 17 (main server chassis: a tower workstation) | C |
| processor | `Ampere(TM)` / `Ampere(R) Altra(R) Processor`, 2200 MHz | B (strings), C (a Q64-22) |
| MAC prefix | `00:30:64` | A (IEEE) |

## AWS EC2 Graviton2 instance (`arm-aws-graviton2`)

| Field | Value | Class |
| --- | --- | --- |
| BIOS | `Amazon EC2` / `1.0` / `11/1/2018`, VM bit set | A |
| system | `Amazon EC2` / the instance type (`t4g.nano` ... `t4g.2xlarge` by vCPUs and memory) | A (maker, c6g names), B (t4g names) |
| UUID, serial | `ec2` first, the serial is the UUID | C (as x86 EC2 dumps show) |
| board, chassis | `Amazon EC2`, chassis type 1 (other) | C |
| processor | `AWS` / `AWS Graviton2`, socket `CPU00`, 2500 MHz | A |
| ACPI OEM | `AMAZON` / `AMZNFACP` | C (x86 EC2's) |
| timer | 121.875 MHz | C |
| MAC | random, locally administered | C |
| disk model | `Amazon Elastic Block Store` on SATA | B (the EBS model of x86 dumps; real instances have NVMe) |
| metadata, instance state | none (the x86 providers' are not used) | listed giveaway |

## Raspberry Pi 4 Model B and Pi 5 (`arm-rpi-4b`, `arm-rpi-5`), device-tree boards

A desktop, laptop or custom profile whose firmware is BIOS, and any arm64 machine whose UEFI cannot boot, is shown as one of these on its device tree (no UEFI, no SMBIOS, as the boards have). Sources: the Linux device trees `arch/arm64/boot/dts/broadcom/bcm2711-rpi-4-b.dts`, `bcm2711.dtsi`, `bcm2712-rpi-5-b.dts`, `bcm2712.dtsi` (kernel.org), the Raspberry Pi documentation's revision codes, and the IEEE MA-L registry.

| Field | Value | Class |
| --- | --- | --- |
| model | `Raspberry Pi 4 Model B Rev 1.4`, `Raspberry Pi 5 Model B Rev 1.0` | A (the firmware's model strings for those revisions) |
| compatible | `raspberrypi,4-model-b`, `brcm,bcm2711`; `raspberrypi,5-model-b`, `brcm,bcm2712` | A (the kernel's trees) |
| serial-number | Pi 4: `10000000` and 8 hex digits; Pi 5: 16 hex digits | A (format), random per VM |
| CPU | Pi 4: `cortex-a72` MIDR `0x410fd083` (r0p3); Pi 5: `cortex-a76` MIDR `0x414fd0b1` (r4p1) | A (Pi 4, public `/proc/cpuinfo`), C (Pi 5 revision) |
| timer | 54 MHz | A (the boards' 54 MHz crystal, `arch_timer` at 54.00MHz in their boot logs) |
| caches | Pi 4: 48 KiB L1i, 32 KiB L1d per core, one 1 MiB L2; Pi 5: 64 KiB L1i and L1d, 512 KiB L2 per core, 2 MiB L3 | A (the kernel's trees' cache nodes), C (ways) |
| MAC prefix | Pi 4 `dc:a6:32`, Pi 5 `2c:cf:67` | A (IEEE: Raspberry Pi Trading) |
| network card, disk | Intel 82576 on PCIe, SATA SSD on AHCI | listed giveaway (the boards have their own Ethernet and an SD card or USB disk) |
| interrupt controller, PCIe | virt's GICv3 and generic ECAM host, under board-style node names | listed giveaway |
