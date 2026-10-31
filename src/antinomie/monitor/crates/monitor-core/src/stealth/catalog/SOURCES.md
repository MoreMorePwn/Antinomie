# Machine catalog sources

Every string in `catalog/*.rs` and `parts.rs`, with a public report of a real unit that shows it.
Collected on 2026-10-27 from the hw-probe uploads published in the linuxhw repositories on GitHub:
[DMI](https://github.com/linuxhw/DMI) (dmidecode), [Dmesg](https://github.com/linuxhw/Dmesg) (kernel log),
[HWInfo](https://github.com/linuxhw/HWInfo) (hwinfo) and [SMART](https://github.com/linuxhw/SMART) (smartctl).
**Terms of the data.** The four linuxhw repositories are published under Creative Commons Attribution 4.0 (CC BY 4.0; the repositories' license files, checked on GitHub on 2026-10-31). The catalog copies facts (model names, BIOS versions, part strings) that real units report, and this file credits the reports it took them from, with a link to each. The hw-probe tool and the linux-hardware.org site are the same project's; their own terms were not separately checked.

hw-probe hides serial numbers, UUIDs, asset tags and some part numbers in these reports; nothing hidden was guessed.

The cloud VPS profiles are in [SOURCES-cloud.md](SOURCES-cloud.md).

## How to read it

| Class | Meaning |
| --- | --- |
| A | seen in a real unit of this model |
| B | seen in a real unit of another model (reason given) |
| C | not possible as a real combination, or not verified (decision needed) |

Counts: 1643 values of class A, 72 of class B, 13 of class C.

**Weights.** A machine's `weight` is the number of public dmidecode reports of the model in linuxhw/DMI on 2026-10-27 (all variants of the model counted). That is how often Linux users who ran hw-probe uploaded one, not a sales figure; it only orders models against each other within a preset.

**Not sourced, generated per VM.** Serial numbers (system, board, chassis, disk, memory), the system UUID, the MAC address and the disk WWN's last nine digits are random per VM. Their formats (`SerialStyle` in `catalog.rs`, the board serial's `/serial/…/` form, the disk serial prefixes in `parts.rs`) are not from a source: every public dump hides them. They are class C as a group.

**Network card.** The VM's card is QEMU's e1000e (Intel 82574L) with the maker's PCI subsystem ID. QEMU 11.0.3 (`-device help`) offers Intel e1000, e1000e, igb (82576), i82550 to i82559, i82562, i82801, Realtek RTL8139, AMD pcnet, tulip, ne2k, vmxnet3 and virtio; no Realtek RTL8168/8111 (r8169) and no Broadcom (tg3). Decision (2026-10-29): keep the 82574L on Realtek and Broadcom machines as a listed giveaway (`MachineProfile::nic_fit`), because the RTL8139 (10ec:8139) is a 100 Mbit PCI chip of 1997 that no catalog machine has and that real PCs of this age almost never show, and it takes no subsystem ID. The I210 machine (igb driver) would fit QEMU's igb better, but the guest kernel has no CONFIG_IGB (proposal for a guest card).

**Processor (SMBIOS type 4) and caches.** Voltage and upgrade code are per machine, the most common value in its reports (class A below); the external clock is 100 MHz in every report. The ID is the host CPU's CPUID leaf 1; the characteristics, core and thread counts and the caches come from the VM's topology and the host's cache directory (nothing hidden or invented).

**Memory.** Every machine lists modules of 4, 8, 16 and 32 GiB (servers 8 to 64): its own reports' parts first (class A); for a size they do not show, a part of the same maker from another machine's report, else a part of the same type, form factor, width and speed or lower (class B, the report and machine named). The memory array's slot count is the machine's listed slots (up to four) and its capacity is the slots times the largest listed module: derived, not in a source (class C as a group, like the serial formats). Dell board serials are `/<service tag>/CN<12 characters>/` as in the public listing at https://www.unixtutorial.org/great-things-you-can-confirm-with-dmidecode/ ; no public source shows the HP, Lenovo or Supermicro board, chassis or disk serial formats, so those keep their current form.


## Dell OptiPlex 7090 (`dell-optiplex-7090`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `7` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1) |  |
| manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1) |  |
| version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1) |  |
| family | `OptiPlex` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1) |  |
| board_manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1) |  |
| bios | `1.13.0 10/06/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/114DD2D67E67) |  |
| bios | `1.18.1 05/10/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/2890AA67531C) |  |
| bios | `1.2.1 11/09/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/93D3CA40FE69) |  |
| bios | `1.29.0 09/03/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/E93970759FED) |  |
| bios | `1.4.3 01/07/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1) |  |
| bios | `1.7.0 04/15/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/A73F0F85C4E4) |  |
| bios | `1.8.2 06/07/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/23543D1DA7E1) |  |
| unit | `OptiPlex 7090 / 0A52 / 073Y7Y / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/2890AA67531C) |  |
| unit | `OptiPlex 7090 / 0A52 / 07X0Y8 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/E93970759FED) |  |
| unit | `OptiPlex 7090 / 0A52 / 0FKVT5 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/23543D1DA7E1) |  |
| unit | `OptiPlex 7090 / 0A52 / 0GNVHC / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/114DD2D67E67) |  |
| unit | `OptiPlex 7090 / 0A52 / 0P9XHK / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1) |  |
| cpu generation | `Core10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1) |  |
| cpu generation | `Core11` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/114DD2D67E67) |  |
| oem string | `Dell System` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/93D3CA40FE69) |  |
| oem string | `1[{sku}]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/93D3CA40FE69) |  |
| oem string | `3[1.0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/93D3CA40FE69) |  |
| oem string | `12[www.dell.com]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/93D3CA40FE69) |  |
| oem string | `14[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/93D3CA40FE69) |  |
| oem string | `15[3]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/93D3CA40FE69) |  |
| oem string | `28[2]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/93D3CA40FE69) |  |
| acpi | `'DELL  ' 'Dell Inc'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1/DEBIAN-11/5.10.0-12-AMD64/X86_64/E167C05DD2) |  |
| nic chip | `Intel Ethernet Connection (14) I219-LM` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1/DEBIAN-11/5.10.0-12-AMD64/X86_64/E167C05DD2) |  |
| nic subsystem | `1028:0a52` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1/DEBIAN-11/5.10.0-12-AMD64/X86_64/E167C05DD2) |  |
| board_location | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1) |  |
| chassis_version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1) |  |
| chassis_sku | `Desktop` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1) |  |
| cpu_part | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1) |  |
| cpu_upgrade | `0x3e` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/114DD2D67E67) | SMBIOS upgrade code |
| cpu_voltage | `1.2 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/114DD2D67E67) | the most common reading; it differs by CPU |
| board version | `A00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1) |  |
| board version | `A01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/23543D1DA7E1) |  |
| memory slots | `DIMM1/; DIMM3/ ; DIMM4/ ; DIMM2/` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/114DD2D67E67) |  |
| memory | `01980000802C K9CXF2-MIE (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/93D3CA40FE69) |  |
| memory | `802C0000802C 8ATF1G64AZ-2G3E1 (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/A73F0F85C4E4) |  |
| memory | `802C0000802C 8ATF2G64AZ-3G2E1 (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/23543D1DA7E1) |  |
| memory | `80CE000080CE M378A2G43MX3-CWE (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/114DD2D67E67) |  |
| memory | `01980000802C K36FTX-MIR (4 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/E93970759FED) |  |
| memory | `802C0000802C 4ATF51264AZ-3G2J1 (4 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/E93970759FED) |  |
| memory | `80CE000080CE M378A4G43AB2-CWE (32 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/3AEFC11BB8D1) | no 32 GiB module with a part number in the reports of this model; the same maker's part in the reports of dell-optiplex-7080 |
| disk | `Samsung SSD 860 EVO 250GB RVT02B6Q` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%207090/A73F0F85C4E4/OL-8.6/4.18.0-372.16.1.0.2.EL8_6.X86_64/X86_64/3BED97B23E) |  |
| cdrom | `HL-DT-ST DVD+/-RW GU90N` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%207090/0EE8CCE625A1/DEBIAN-11/5.10.0-12-AMD64/X86_64/E167C05DD2) |  |

## Dell OptiPlex 7080 (`dell-optiplex-7080`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `15` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) |  |
| manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) |  |
| version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) |  |
| family | `OptiPlex` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) |  |
| board_manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) |  |
| bios | `1.1.5 06/30/2020` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/6868666F3561) |  |
| bios | `1.21.0 06/29/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/182FBFE28FB8) |  |
| bios | `1.16.0 09/07/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/4BD0B92B1363) |  |
| bios | `1.4.1 07/19/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/3AEFC11BB8D1) |  |
| bios | `1.1.10 12/10/2020` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) |  |
| bios | `1.15.0 08/09/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/726673698C84) |  |
| bios | `1.19.0 03/08/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/EBEEEC5E708F) |  |
| bios | `1.29.0 08/12/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/3C445F4C169F) |  |
| unit | `OptiPlex 7080 / 09A4 / 0J37VM / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/1E04B709DAF7) |  |
| unit | `OptiPlex 7080 / 09A4 / 0HV8FN / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) |  |
| unit | `OptiPlex 7080 / 09A4 / 07WJF3 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/726673698C84) |  |
| unit | `OptiPlex 7080 / 09A4 / 0GRJJ9 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/EBEEEC5E708F) |  |
| unit | `OptiPlex 7080 / 09A4 / 0YGYJY / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/182FBFE28FB8) |  |
| cpu generation | `Core10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) |  |
| oem string | `Dell System` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/C351C78D0E87) |  |
| oem string | `1[{sku}]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/C351C78D0E87) |  |
| oem string | `3[1.0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/C351C78D0E87) |  |
| oem string | `12[www.dell.com]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/C351C78D0E87) |  |
| oem string | `14[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/C351C78D0E87) |  |
| oem string | `15[3]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/C351C78D0E87) |  |
| oem string | `28[3]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/C351C78D0E87) |  |
| acpi | `'DELL  ' 'CBX3    '` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%207080/3AEFC11BB8D1/LINUXMINT-20.2/5.11.0-27-GENERIC/X86_64/D35C6EA078) |  |
| nic chip | `Intel Ethernet Connection (11) I219-LM` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/5170074EC08F/KUBUNTU-22.10/5.19.0-23-GENERIC/X86_64/7A28D76FE6) |  |
| nic subsystem | `1028:09a4` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/5170074EC08F/KUBUNTU-22.10/5.19.0-23-GENERIC/X86_64/7A28D76FE6) |  |
| board_location | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) |  |
| chassis_version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) |  |
| chassis_sku | `Desktop` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) |  |
| cpu_part | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) | SMBIOS upgrade code |
| cpu_voltage | `0.8 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) | the most common reading; it differs by CPU |
| board version | `A01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) |  |
| board version | `A00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/182FBFE28FB8) |  |
| memory slots | `DIMM1/; DIMM2/; DIMM3/; DIMM4/` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) |  |
| memory | `01980000802C 99U5734-056.A00G (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/4BD0B92B1363) |  |
| memory | `80CE000080CE M378A4G43AB2-CWE (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/3AEFC11BB8D1) |  |
| memory | `80AD000080AD HMA82GU6DJR8N-XN (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/6868666F3561) |  |
| memory | `019400000194 SF4642G8CK8I8HLSBG (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/182FBFE28FB8) |  |
| memory | `80AD000080AD HMA81GU6DJR8N-XN (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/0F7D6344353A) |  |
| memory | `01980000830B 9905702-121.A00G (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/C351C78D0E87) |  |
| memory | `01980000802C K36FTX-MIR (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207090/E93970759FED) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of dell-optiplex-7090 |
| disk | `TOSHIBA-TR200 SBFA15.2` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%207080/E81F7BFF0FDF/GENTOO-2.8/5.16.11-GENTOO-X86_64/X86_64/76F13AA200) |  |
| disk | `KINGSTON SA400S37240G SBFK71E0` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%207080/C00E5FD4B78E/FEDORA-36/5.19.11-200.FC36.X86_64/X86_64/73E69DEBD9) |  |

## Dell OptiPlex 5090 (`dell-optiplex-5090`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `11` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) |  |
| manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) |  |
| version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) |  |
| family | `OptiPlex` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) |  |
| board_manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) |  |
| bios | `1.13.0 10/06/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/9F0B2A1BDB54) |  |
| bios | `1.5.0 02/11/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/8BCCC1D4B69B) |  |
| bios | `1.1.36 06/22/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) |  |
| bios | `1.1.51 08/26/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/DE12D659B87E) |  |
| bios | `1.20.1 09/27/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/769D0F6F7C54) |  |
| bios | `1.21.1 11/28/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/377766EBD567) |  |
| bios | `1.28.1 08/12/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/A4E21669E9C2) |  |
| bios | `1.4.3 01/07/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/4D0B18895EB1) |  |
| bios | `1.6.0 03/14/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/E985DD9AAFE5) |  |
| unit | `OptiPlex 5090 / 0A54 / 0FXD80 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/377766EBD567) |  |
| unit | `OptiPlex 5090 / 0A54 / 0JGM7F / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) |  |
| unit | `OptiPlex 5090 / 0A54 / 0X4H68 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/769D0F6F7C54) |  |
| unit | `OptiPlex 5090 / 0A54 / 0VG93V / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/FB31ED9F19B3) |  |
| cpu generation | `Core10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) |  |
| cpu generation | `Core11` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/377766EBD567) |  |
| oem string | `Dell System` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/FB31ED9F19B3) |  |
| oem string | `1[{sku}]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/FB31ED9F19B3) |  |
| oem string | `3[1.0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/FB31ED9F19B3) |  |
| oem string | `12[www.dell.com]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/FB31ED9F19B3) |  |
| oem string | `14[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/FB31ED9F19B3) |  |
| oem string | `15[11]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/FB31ED9F19B3) |  |
| oem string | `28[3]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/FB31ED9F19B3) |  |
| acpi | `'DELL  ' 'Dell Inc'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B/UBUNTU-20.04/5.8.0-63-GENERIC/X86_64/00693243EE) |  |
| nic chip | `Intel Ethernet Connection (14) I219-LM` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/4D0B18895EB1/ROSA-12.2/5.10.74-GENERIC-2ROSA2021.1-X86_64/X86_64/46450D22D3) |  |
| nic subsystem | `1028:0a54` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/4D0B18895EB1/ROSA-12.2/5.10.74-GENERIC-2ROSA2021.1-X86_64/X86_64/46450D22D3) |  |
| board_location | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) |  |
| chassis_version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) |  |
| chassis_sku | `Desktop` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) |  |
| cpu_part | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) |  |
| cpu_upgrade | `0x3e` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/377766EBD567) | SMBIOS upgrade code |
| cpu_voltage | `0.8 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) | the most common reading; it differs by CPU |
| board version | `A00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) |  |
| memory slots | `DIMM1/; DIMM3/ ; DIMM4/ ; DIMM2/` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/377766EBD567) |  |
| memory | `80CE000080CE M378A2G43AB3-CWE (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/9F0B2A1BDB54) |  |
| memory | `802C0000802C 16ATF2G64AZ-3G2E1 (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/FB31ED9F19B3) |  |
| memory | `80AD000080AD HMAA1GU6CJR6N-XN (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/769D0F6F7C54) |  |
| memory | `0198000080AD 9905713-044.A00G (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/8BCCC1D4B69B) |  |
| memory | `01980000802C KCDT82-MIE (4 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) |  |
| memory | `80CE000080CE M378A4G43AB2-CWE (32 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207080/3AEFC11BB8D1) | no 32 GiB module with a part number in the reports of this model; the same maker's part in the reports of dell-optiplex-7080 |
| disk | `Samsung SSD 860 EVO 250GB RVT02B6Q` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%207090/A73F0F85C4E4/OL-8.6/4.18.0-372.16.1.0.2.EL8_6.X86_64/X86_64/3BED97B23E) |  |

## Dell OptiPlex 3080 (`dell-optiplex-3080`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `22` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/0B33085DFA99) |  |
| manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/0B33085DFA99) |  |
| version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/0B33085DFA99) |  |
| family | `OptiPlex` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/0B33085DFA99) |  |
| board_manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/0B33085DFA99) |  |
| bios | `1.1.0 05/31/2020` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/DC3824BFEF00) |  |
| bios | `2.0.2 05/10/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/61C8AF444CAC) |  |
| bios | `2.1.1 05/28/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/10E9173DF5CD) |  |
| bios | `2.18.0 03/08/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/60F90251CFDE) |  |
| bios | `2.19.1 05/10/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/7C16E3FA9F59) |  |
| bios | `2.23.1 12/25/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/8DB53B37F1CD) |  |
| bios | `2.14.0 07/12/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/F3C7079B61C4) |  |
| bios | `2.17.1 12/18/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/37F15B20564B) |  |
| bios | `2.2.1 08/20/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/90309B2CECDC) |  |
| bios | `2.20.0 08/17/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/814B801644CF) |  |
| unit | `OptiPlex 3080 / 09A8 / 0HGFJM / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/433DC932831E) |  |
| unit | `OptiPlex 3080 / 09A8 / 0M3F6C / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/107D164939BB) |  |
| unit | `OptiPlex 3080 / 09A8 / 0J2J3Y / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/8DB53B37F1CD) |  |
| unit | `OptiPlex 3080 / 09A8 / 0J56FD / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/DC3824BFEF00) |  |
| unit | `OptiPlex 3080 / 09A8 / 006K82 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/814B801644CF) |  |
| unit | `OptiPlex 3080 / 09A8 / 024JD7 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/A5076D229FB3) |  |
| cpu generation | `Core10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/0B33085DFA99) |  |
| oem string | `Dell System` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/90309B2CECDC) |  |
| oem string | `1[{sku}]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/90309B2CECDC) |  |
| oem string | `3[1.0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/90309B2CECDC) |  |
| oem string | `12[www.dell.com]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/90309B2CECDC) |  |
| oem string | `14[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/90309B2CECDC) |  |
| oem string | `15[11]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/90309B2CECDC) |  |
| oem string | `28[3]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/90309B2CECDC) |  |
| acpi | `'DELL  ' 'CBX3    '` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%203080/10E9173DF5CD/UBUNTU-20.04/5.11.0-27-GENERIC/X86_64/B8FE9256D0) |  |
| nic chip | `Realtek RTL8168h/8111h` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%203080/10E9173DF5CD/UBUNTU-20.04/5.11.0-27-GENERIC/X86_64/B8FE9256D0) | kernel r8169 line |
| nic subsystem | `1028:09a8` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/10E9173DF5CD/UBUNTU-20.04/5.11.0-27-GENERIC/X86_64/B8FE9256D0) |  |
| board_location | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/0B33085DFA99) |  |
| chassis_version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/0B33085DFA99) |  |
| chassis_sku | `Desktop` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/0B33085DFA99) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/0B33085DFA99) |  |
| cpu_part | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/0B33085DFA99) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/0B33085DFA99) | SMBIOS upgrade code |
| cpu_voltage | `0.7 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/107D164939BB) | the most common reading; it differs by CPU |
| board version | `A00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/10E9173DF5CD) |  |
| board version | `A01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/0B33085DFA99) |  |
| memory slots | `DIMM1/; DIMM2/` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/0B33085DFA99) |  |
| memory | `80CE000080CE M471A1K43DB1-CTD (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/8DB53B37F1CD) |  |
| memory | `019400000194 SMS4WEC8C1K0446FCG (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/0B33085DFA99) |  |
| memory | `80AD000080AD HMAA2GS6CJR8N-XN (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/A0C3EAB49CC2) |  |
| memory | `01980000802C K1CXP8-MIE (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/7C16E3FA9F59) |  |
| memory | `04CB000080AD AD4U3200J4G22-B (4 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/60F90251CFDE) |  |
| memory | `019400000194 SMS4WEC3C0K0446SCG (4 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%203080/DC3824BFEF00) |  |
| memory | `80CE000080CE M471A4G43AB1-CWE (32 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/516D58BED016) | no 32 GiB module with a part number in the reports of this model; the same maker's part in the reports of dell-latitude-5520 |
| disk | `Samsung SSD 870 EVO 500GB SVT01B6Q` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%203080/2EF782A45D9E/UBUNTU-20.04/5.11.0-41-GENERIC/X86_64/2E0D1C92B2) |  |
| disk | `PNY CS900 240GB SSD CS900J13` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%203080/2EF782A45D9E/UBUNTU-20.04/5.11.0-41-GENERIC/X86_64/88AA9F2F67) |  |

## Dell OptiPlex 7000 (`dell-optiplex-7000`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `13` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C) |  |
| manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C) |  |
| version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C) |  |
| family | `OptiPlex` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C) |  |
| board_manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C) |  |
| bios | `1.15.0 07/12/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/7241B617E4E3) |  |
| bios | `1.4.85 08/26/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/5A5A4C8E699F) |  |
| bios | `1.10.0 02/15/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/7F292C163AA9) |  |
| bios | `1.12.5 04/26/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/4916EEDAFF9A) |  |
| bios | `1.17.0 09/12/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/63830CD3C14A) |  |
| bios | `1.18.1 11/09/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/21052D054375) |  |
| bios | `1.26.0 09/10/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/1A5D011DEE79) |  |
| bios | `1.3.62 06/13/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/DBE8AB2D3BE5) |  |
| bios | `1.4.1 07/20/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/7E2C5030F69D) |  |
| bios | `1.6.1 09/15/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/8C25D9B2B397) |  |
| unit | `OptiPlex 7000 / 0AC1 / 0VNM11 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/1A5D011DEE79) |  |
| unit | `OptiPlex 7000 / 0AC1 / 0F1HC1 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/DBE8AB2D3BE5) |  |
| unit | `OptiPlex 7000 / 0AC1 / 0FG47G / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/7F292C163AA9) |  |
| unit | `OptiPlex 7000 / 0AC1 / 0MW50N / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/9A3C0E7CA5D1) |  |
| unit | `OptiPlex 7000 / 0AC1 / 0NNFGG / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/8C25D9B2B397) |  |
| unit | `OptiPlex 7000 / 0AC1 / 0VC8RJ / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C) |  |
| cpu generation | `Core12` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C) |  |
| oem string | `Dell System` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/7241B617E4E3) |  |
| oem string | `1[{sku}]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/7241B617E4E3) |  |
| oem string | `3[1.0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/7241B617E4E3) |  |
| oem string | `12[www.dell.com]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/7241B617E4E3) |  |
| oem string | `14[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/7241B617E4E3) |  |
| oem string | `15[11]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/7241B617E4E3) |  |
| oem string | `28[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/7241B617E4E3) |  |
| oem string | `29[0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/7241B617E4E3) |  |
| acpi | `'DELL  ' 'Dell Inc'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C/DEBIAN-11/5.10.0-20-AMD64/X86_64/313EA92E9C) |  |
| nic chip | `Intel Ethernet Connection (17) I219-LM` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C/DEBIAN-11/5.10.0-20-AMD64/X86_64/313EA92E9C) |  |
| nic subsystem | `1028:0ac1` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C/DEBIAN-11/5.10.0-20-AMD64/X86_64/313EA92E9C) |  |
| board_location | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C) |  |
| chassis_version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C) |  |
| chassis_sku | `Desktop` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C) |  |
| cpu_part | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C) | SMBIOS upgrade code |
| cpu_voltage | `1.0 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/1A5D011DEE79) | the most common reading; it differs by CPU |
| board version | `A01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/1A5D011DEE79) |  |
| board version | `A00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/21052D054375) |  |
| board version | `A02` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/7F292C163AA9) |  |
| board version | `A03` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/B0BBA76EBFAC) |  |
| board version | `X02` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C) |  |
| memory slots | `DIMM1/; DIMM2/` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/089EBFAFFD4C) |  |
| memory | `01980000802C K1CXP8-MIF (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/1A5D011DEE79) |  |
| memory | `0198000080AD K1CXP8-HYC (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/4916EEDAFF9A) |  |
| memory | `802C0000802C 4ATF1G64HZ-3G2F1 (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/B0BBA76EBFAC) |  |
| memory | `802C0000802C 8ATF1G64HZ-3G2J1 (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/7E2C5030F69D) |  |
| memory | `859B0000802C CT32G4SFD832A.M16FF (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/63830CD3C14A) |  |
| memory | `01980000802C 9905744-066.A00G (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/21052D054375) |  |
| memory | `01980000802C KCDT82-MIE (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of dell-optiplex-5090 |
| disk | `ST1000DM010-2EP102 1001` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%207000/7F292C163AA9/UBUNTU-22.04/5.19.0-38-GENERIC/X86_64/D1CF6FA11E) |  |
| disk | `WDC WD10EZEX-75WN4A1 13057113` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%207000/8C25D9B2B397/ARCH-ROLLING/6.0.11-ARCH1-1/X86_64/B955357CCC) |  |

## HP EliteDesk 800 G6 (`hp-elitedesk-800-g6`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `4` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479) |  |
| manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479) |  |
| version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479) |  |
| family | `103C_53307F HP EliteDesk` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479) |  |
| board_manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479) |  |
| bios | `S01 Ver. 02.05.01 01/05/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479) |  |
| bios | `S01 Ver. 02.09.00 11/02/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/B736692F455E) |  |
| unit | `HP EliteDesk 800 G6 Small Form Factor PC / 1D2T0EA#UUZ / 870C / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/C30A9CD56895) |  |
| unit | `HP EliteDesk 800 G6 Small Form Factor PC / 2H0U1PA#ABG / 870C / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/BC2D16F1081A) |  |
| unit | `HP EliteDesk 800 G6 Small Form Factor PC / 42T78EA#ABF / 870C / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/B736692F455E) |  |
| unit | `HP EliteDesk 800 G6 Small Form Factor PC / 8YM57AV / 870C / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479) |  |
| cpu generation | `Core10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479) |  |
| oem string | `FBYTE#3E3Q3X476J6S6b7B7H7M7Q7T7W7maBapaqaubhcAdUdXdpdqfPhKhZjhk8mEnVnp.N5;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/C30A9CD56895) |  |
| oem string | `BUILDID#20WWF8BT601#SUUZ#DUUZ;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/C30A9CD56895) |  |
| oem string | `EDK2_1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/C30A9CD56895) |  |
| oem string | `Buff=2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/C30A9CD56895) |  |
| oem string | `HRDWFEATS=VMCSSHAD:1;VTX:1;VTD:1;SGX:0;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/C30A9CD56895) |  |
| oem string | `MEFWRec` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/C30A9CD56895) |  |
| acpi | `'HPQOEM' 'SLIC-BPC'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/B736692F455E/UBUNTU-22.04/5.15.0-40-GENERIC/X86_64/17993CF668) |  |
| nic chip | `Intel Ethernet Connection (11) I219-LM` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479/UBUNTU-22.04/5.15.0-52-GENERIC/X86_64/76AE5C62CF) |  |
| nic subsystem | `103c:870b` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479/UBUNTU-22.04/5.15.0-52-GENERIC/X86_64/76AE5C62CF) |  |
| board_location | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479) |  |
| chassis_version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479) |  |
| cpu_part | `To Be Filled By O.E.M.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479) | SMBIOS upgrade code |
| cpu_voltage | `0.9 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479) | the most common reading; it differs by CPU |
| board version | `KBC Version 09.94.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479) |  |
| board version | `KBC Version 09.97.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/B736692F455E) |  |
| memory slots | `DIMM1/ChannelB; DIMM2/ChannelB; DIMM3/ChannelA; DIMM4/ChannelA` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/1D540E5DD479) |  |
| memory | `Samsung M378A2G43BB3-CWE (16 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T8000LIX/F5F427BCD6A9) | no 16 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkcentre-m70s-gen3 |
| memory | `Unknown - [0x9B85] CT8G4DFS824A.M8FD (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/BC2D16F1081A) |  |
| memory | `Samsung M378A5244CB0-CWE (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011T0003QFR/F0B2A55FD054) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkcentre-neo-50s-gen3 |
| disk | `X160EB SN07656` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/B736692F455E/UBUNTU-22.04/5.15.0-40-GENERIC/X86_64/17993CF668) |  |

## HP EliteDesk 805 G8 (`hp-elitedesk-805-g8`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `1` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| family | `103C_53307F HP EliteDesk` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| board_manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| bios | `T26 Ver. 02.02.00 11/03/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| unit | `HP EliteDesk 805 G8 Desktop Mini PC / 6D9U5EC#ABD / 8881 / chassis 35` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| cpu generation | `Zen3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| oem string | `FBYTE#3E476J6S6b7B7H7M7Q7T7W7maBapaqaubhcAfPhZk8mEn7nWngpnpqpr.8q;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| oem string | `BUILDID#21WWQ7BZ601#SABD#DABD;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| oem string | `EDK2_1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| oem string | `Buff=2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| oem string | `HRDWFEATS=;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| acpi | `'HPQOEM' 'SLIC-BPC'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F/ROCKY-8.7/4.18.0-425.10.1.EL8_7.X86_64/X86_64/D9864F2860) |  |
| nic chip | `Realtek RTL8168fp/RTL8117` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F/ROCKY-8.7/4.18.0-425.10.1.EL8_7.X86_64/X86_64/D9864F2860) | kernel r8169 line |
| nic subsystem | `103c:8881` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F/ROCKY-8.7/4.18.0-425.10.1.EL8_7.X86_64/X86_64/D9864F2860) |  |
| board_location | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| chassis_version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| cpu_socket | `AM4` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| cpu_part | `Unknown` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| cpu_upgrade | `0x31` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) | SMBIOS upgrade code |
| cpu_voltage | `1.4 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) | the most common reading; it differs by CPU |
| board version | `KBC Version 10.52.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| memory slots | `DIMM1/ChannelA DIMM0; DIMM3/ChannelB DIMM0` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Hewlett-Packard/EliteDesk/EliteDesk%20805%20G8%20Desktop%20Mini%20PC/C85E0CDAD14F) |  |
| memory | `Hynix HMAA1GS6CJR6N-XN (8 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) | no 8 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkpad-e15-gen3-amd |
| memory | `SK Hynix HMA851S6CJR6N-XN (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/E89A74834DB6) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of hp-250-g8 |
| memory | `SK Hynix HMAB2GS6CMR6N-XN (16 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0082PB/E8B4DDEF6312) | no 16 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkpad-t14-gen3 |
| memory | `SK Hynix HMAA4GS6CJR8N-XN (32 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AHCTO1WW/24CCFE3AAA29) | no 32 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkpad-t14-gen3 |
| disk | `X160EB SN07656` | B | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/B736692F455E/UBUNTU-22.04/5.15.0-40-GENERIC/X86_64/17993CF668) | no SATA disk in its report; EliteDesk 800 G6 (an SSD: the Desktop Mini takes no 3.5-inch disk) |

## HP EliteDesk 800 G8 (`hp-elitedesk-800-g8`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `1` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| family | `103C_53307F HP EliteDesk` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| board_manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| bios | `T01 Ver. 02.12.00 03/23/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| unit | `HP EliteDesk 800 G8 Tower PC / 27P59AV / 889C / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| cpu generation | `Core11` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| oem string | `FBYTE#3E3Y6E6J6S6a7H7M7Q7T7W7d7mbhcAfPhKhZjhk8m6n7nVngp6.3a;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| oem string | `BUILDID#21WWF8CD301#SABE#DABE;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| oem string | `EDK2_1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| oem string | `Buff=2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| oem string | `HRDWFEATS=VMCSSHAD:1;VTX:1;VTD:1;SGX:0;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| oem string | `MEFWRec` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| acpi | `'HPQOEM' 'SLIC-BPC'` | B | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/B736692F455E/UBUNTU-22.04/5.15.0-40-GENERIC/X86_64/17993CF668) | no Dmesg report; every HP business desktop in the set (800 G6, 805 G8, 400 G7, 405 G6, 600 G6) shows these |
| nic chip | `Intel I219-LM` | B | [report](https://h20195.www2.hp.com/v2/GetPDF.aspx/c07048012.pdf) | no HWInfo/Dmesg NIC line of the model; the maker's specification |
| nic subsystem | `none (Intel's own)` | C |  | no HWInfo report of the model: the card keeps Intel's subsystem ID |
| board_location | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| chassis_version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| cpu_part | `To Be Filled By O.E.M.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| cpu_upgrade | `0x3e` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) | SMBIOS upgrade code |
| cpu_voltage | `1.2 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) | the most common reading; it differs by CPU |
| board version | `KBC Version 10.57.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| memory slots | `DIMM1/ChannelB; DIMM2/ChannelB; DIMM3/ChannelA; DIMM4/ChannelA` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G8%20Tower%20PC/37F624CF3727) |  |
| memory | `Samsung M378A1K43EB2-CWE (8 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS1J200/CBCE8C6DE4A0) | no 8 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkcentre-m75s-gen2 |
| memory | `Samsung M378A5244CB0-CWE (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011T0003QFR/F0B2A55FD054) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkcentre-neo-50s-gen3 |
| memory | `Samsung M378A2G43BB3-CWE (16 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T8000LIX/F5F427BCD6A9) | no 16 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkcentre-m70s-gen3 |
| disk | `X160EB SN07656` | B | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/B736692F455E/UBUNTU-22.04/5.15.0-40-GENERIC/X86_64/17993CF668) | no Dmesg/HWInfo report; EliteDesk 800 G6 (the HP business desktop SSD in the set) |

## HP ProDesk 400 G7 (`hp-prodesk-400-g7`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `3` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/0541877294C2) |  |
| manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/0541877294C2) |  |
| version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/0541877294C2) |  |
| family | `103C_53307F HP ProDesk` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/0541877294C2) |  |
| board_manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/0541877294C2) |  |
| bios | `S08 Ver. 02.05.01 01/06/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/D4C2EB91D56B) |  |
| bios | `S08 Ver. 02.10.00 01/11/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/0541877294C2) |  |
| bios | `S08 Ver. 02.18.00 12/13/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/7DBCB845F40C) |  |
| unit | `HP ProDesk 400 G7 Small Form Factor PC / 9DF60AV / 8719 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/0541877294C2) |  |
| unit | `HP ProDesk 400 G7 Small Form Factor PC / 3F8Z0LA#ABM / 8719 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/D4C2EB91D56B) |  |
| cpu generation | `Core10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/0541877294C2) |  |
| oem string | `FBYTE#3E3Q3X476J6S6b7B7J7M7Q7T7WaBapaqaubhcAdUdpdqfAfPk8nV.EF;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/7DBCB845F40C) |  |
| oem string | `BUILDID#20WWP6CT601#SAB9#DAB9;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/7DBCB845F40C) |  |
| oem string | `EDK2_1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/7DBCB845F40C) |  |
| oem string | `Buff=2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/7DBCB845F40C) |  |
| oem string | `HRDWFEATS=VMCSSHAD:1;VTX:0;VTD:0;SGX:0;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/7DBCB845F40C) |  |
| acpi | `'HPQOEM' 'SLIC-BPC'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/7DBCB845F40C/OPENMANDRIVA-4.3/5.16.7-DESKTOP-1OMV4003/X86_64/7E0AE3D91F) |  |
| nic chip | `Intel Ethernet Connection (11) I219-LM` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/7DBCB845F40C/OPENMANDRIVA-4.3/5.16.7-DESKTOP-1OMV4003/X86_64/7E0AE3D91F) |  |
| nic subsystem | `103c:8719` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/7DBCB845F40C/OPENMANDRIVA-4.3/5.16.7-DESKTOP-1OMV4003/X86_64/7E0AE3D91F) |  |
| board_location | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/0541877294C2) |  |
| chassis_version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/0541877294C2) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/0541877294C2) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/0541877294C2) |  |
| cpu_part | `To Be Filled By O.E.M.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/0541877294C2) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/0541877294C2) | SMBIOS upgrade code |
| cpu_voltage | `0.8 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/7DBCB845F40C) | the most common reading; it differs by CPU |
| board version | `KBC Version 09.08.23` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/7DBCB845F40C) |  |
| board version | `KBC Version 09.94.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/D4C2EB91D56B) |  |
| board version | `KBC Version 09.97.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/0541877294C2) |  |
| memory slots | `DIMM1/ChannelB; DIMM3/ChannelA` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/0541877294C2) |  |
| memory | `Kingston LV32D4U2S8SD-8 (8 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) | no 8 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkcentre-m70s-gen3 |
| memory | `Samsung M378A5244CB0-CWE (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011T0003QFR/F0B2A55FD054) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkcentre-neo-50s-gen3 |
| memory | `Samsung M378A2G43BB3-CWE (16 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T8000LIX/F5F427BCD6A9) | no 16 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkcentre-m70s-gen3 |
| disk | `ST2000LM015-2E8174 0001` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/7DBCB845F40C/OPENMANDRIVA-4.3/5.16.7-DESKTOP-1OMV4003/X86_64/7E0AE3D91F) |  |

## HP ProDesk 600 G6 (`hp-prodesk-600-g6`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `3` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0) |  |
| manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0) |  |
| version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0) |  |
| family | `103C_53307F HP ProDesk` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0) |  |
| board_manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0) |  |
| bios | `S07 Ver. 02.05.01 01/05/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0) |  |
| bios | `S07 Ver. 02.16.00 06/21/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/5352A4CAF93B) |  |
| bios | `S07 Ver. 02.16.20 09/08/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/9D25E519619E) |  |
| unit | `HP ProDesk 600 G6 Small Form Factor PC / 9AW71AV / 8714 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0) |  |
| unit | `HP ProDesk 600 G6 Small Form Factor PC / 684D8LA#ABM / 8714 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/5352A4CAF93B) |  |
| cpu generation | `Core10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0) |  |
| oem string | `FBYTE#3E3Q3X476J6S6b7B7H7M7Q7T7W7maBapaqaubhcAdUdpdqfNfPhKjhk8mEnV.3e;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/5352A4CAF93B) |  |
| oem string | `BUILDID#20WWP6GT601#SABM#DABM;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/5352A4CAF93B) |  |
| oem string | `EDK2_1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/5352A4CAF93B) |  |
| oem string | `Buff=2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/5352A4CAF93B) |  |
| oem string | `HRDWFEATS=VMCSSHAD:1;VTX:1;VTD:1;SGX:0;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/5352A4CAF93B) |  |
| oem string | `MEFWRec` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/5352A4CAF93B) |  |
| acpi | `'HPQOEM' 'SLIC-BPC'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0/KDE-NEON-20.04/5.13.0-44-GENERIC/X86_64/F2959A67AE) |  |
| nic chip | `Intel Ethernet Connection (11) I219-LM` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/E6BAC0EB2E02/FEDORA-37/6.1.10-200.FC37.X86_64/X86_64/19A66B5101) |  |
| nic subsystem | `103c:8714` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/E6BAC0EB2E02/FEDORA-37/6.1.10-200.FC37.X86_64/X86_64/19A66B5101) |  |
| board_location | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0) |  |
| chassis_version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0) |  |
| cpu_part | `To Be Filled By O.E.M.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0) | SMBIOS upgrade code |
| cpu_voltage | `0.9 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0) | the most common reading; it differs by CPU |
| board version | `KBC Version 09.08.23` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/5352A4CAF93B) |  |
| board version | `KBC Version 09.94.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0) |  |
| memory slots | `DIMM1/ChannelB; DIMM2/ChannelB; DIMM3/ChannelA; DIMM4/ChannelA` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0) |  |
| memory | `Kingston LV32D4U2S8SD-8 (8 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) | no 8 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkcentre-m70s-gen3 |
| memory | `Samsung M378A2G43BB3-CWE (16 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T8000LIX/F5F427BCD6A9) | no 16 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkcentre-m70s-gen3 |
| memory | `Samsung M378A5244CB0-CWE (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011T0003QFR/F0B2A55FD054) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkcentre-neo-50s-gen3 |
| disk | `TOSHIBA DT01ACA050 MS1OA8L0` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0/KDE-NEON-20.04/5.13.0-44-GENERIC/X86_64/F2959A67AE) |  |

## HP ProDesk 405 G6 (`hp-prodesk-405-g6`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `2` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8) |  |
| manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8) |  |
| version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8) |  |
| family | `103C_53307F HP ProDesk` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8) |  |
| board_manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8) |  |
| bios | `S05 Ver. 02.06.00 11/02/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/C715FF433724) |  |
| bios | `S15 Ver. 02.04.00 06/03/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8) |  |
| unit | `HP ProDesk 405 G6 Small Form Factor PC / 293V8EA#ABE / 8835 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/C715FF433724) |  |
| unit | `HP ProDesk 405 G6 Small Form Factor PC / 293X0EA#AKS / 872D / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8) |  |
| cpu generation | `Zen2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8) |  |
| oem string | `FBYTE#3E3Q3X476J6S6b7B7J7M7Q7T7WapaqaubhcAdUdpdqfPk8nW.5r;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/C715FF433724) |  |
| oem string | `BUILDID#20WWP8DT601#SABE#DABE;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/C715FF433724) |  |
| oem string | `EDK2_1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/C715FF433724) |  |
| oem string | `Buff=2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/C715FF433724) |  |
| oem string | `HRDWFEATS=;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/C715FF433724) |  |
| acpi | `'HPQOEM' 'SLIC-BPC'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8/FEDORA-35/5.17.11-200.FC35.X86_64/X86_64/C27F333C46) |  |
| nic chip | `Realtek RTL8168fp/RTL8117` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8/FEDORA-35/5.17.11-200.FC35.X86_64/X86_64/C27F333C46) | kernel r8169 line |
| nic subsystem | `103c:872d` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8/FEDORA-35/5.17.11-200.FC35.X86_64/X86_64/C27F333C46) |  |
| board_location | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8) |  |
| chassis_version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8) |  |
| cpu_socket | `AM4` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8) |  |
| cpu_part | `Unknown` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8) |  |
| cpu_upgrade | `0x31` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8) | SMBIOS upgrade code |
| cpu_voltage | `1.2 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8) | the most common reading; it differs by CPU |
| board version | `KBC Version 09.97.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8) |  |
| board version | `KBC Version 09.99.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/C715FF433724) |  |
| memory slots | `DIMM1/ChannelB DIMM0; DIMM3/ChannelA DIMM0` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Hewlett-Packard/ProDesk/ProDesk%20405%20G6%20Small%20Form%20Factor%20PC/B15F90C079B8) |  |
| memory | `SK Hynix HMA81GU6DJR8N-XN (8 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) | no 8 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkcentre-neo-50s-gen3 |
| memory | `Samsung M378A5244CB0-CWE (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011T0003QFR/F0B2A55FD054) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkcentre-neo-50s-gen3 |
| memory | `Samsung M378A2G43BB3-CWE (16 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T8000LIX/F5F427BCD6A9) | no 16 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkcentre-m70s-gen3 |
| disk | `X160EB SN07656` | B | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/B736692F455E/UBUNTU-22.04/5.15.0-40-GENERIC/X86_64/17993CF668) | no SATA disk in its reports; EliteDesk 800 G6 (the HP business desktop SSD in the set) |

## Lenovo ThinkCentre M75q Gen 2 (`lenovo-m75q-gen2`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `16` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| version | `ThinkCentre M75q Gen 2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| family | `ThinkCentre M75q Gen 2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| board_manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| bios | `M3CKT29A 02/02/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| bios | `M3CKT28A 01/04/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJS00000/67A5CBCEF039) |  |
| bios | `M3CKT32A 02/16/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ000AIX/41ED21501F1F) |  |
| bios | `M3CKT33A 07/18/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJCTO1WW/F4477DE67F5C) |  |
| bios | `M3CKT37A 03/13/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JKS07500/E74F8329CAA5) |  |
| bios | `M3CKT3AA 01/30/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ008NGE/AA44AB49B8FC) |  |
| bios | `M47KT1AA 08/30/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JNS02N00/EFCDDA73E969) |  |
| bios | `M47KT1FA 02/25/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JN000NGE/1AEE52FF07DC) |  |
| bios | `M47KT26A 11/23/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JN000KGE/3D72BE873961) |  |
| bios | `M47KT29A 07/11/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JN000EGE/52C68CA99B3E) |  |
| unit | `11JJ0008CK / LENOVO_MT_11JJ_BU_Think_FM_ThinkCentre M75q Gen 2 / 3190 / chassis 35` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| unit | `11JJ000AIX / LENOVO_MT_11JJ_BU_Think_FM_ThinkCentre M75q Gen 2 / 3190 / chassis 35` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ000AIX/41ED21501F1F) |  |
| unit | `11JJ000BMZ / LENOVO_MT_11JJ_BU_Think_FM_ThinkCentre M75q Gen 2 / 3190 / chassis 35` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ000BMZ/C185070F41DC) |  |
| unit | `11JJ000CMT / LENOVO_MT_11JJ_BU_Think_FM_ThinkCentre M75q Gen 2 / 3190 / chassis 35` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ000CMT/522D7077AD79) |  |
| unit | `11JJ001RRU / LENOVO_MT_11JJ_BU_Think_FM_ThinkCentre M75q Gen 2 / 3190 / chassis 35` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ001RRU/B114BBC992FE) |  |
| unit | `11JJ008NGE / LENOVO_MT_11JJ_BU_Think_FM_ThinkCentre M75q Gen 2 / 3190 / chassis 35` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ008NGE/AA44AB49B8FC) |  |
| cpu generation | `Zen2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| cpu generation | `Zen3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JN000EGE/52C68CA99B3E) |  |
| oem string | `LENOVO ThinkCentre Embedded Controller -[M3CCT0fA-1.0f]-` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| oem string | `LENOVO ThinkCentre BIOS Boot Block Revision 1.29` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| oem string | `Lenovo Service Engine Not Supported` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| acpi | `'LENOVO' 'TC-M3C  '` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ000BMZ/C185070F41DC/FEDORA-37/6.1.14-200.FC37.X86_64/X86_64/56B4F8A1A9) |  |
| nic chip | `Realtek RTL8168fp/RTL8117` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ000BMZ/C185070F41DC/FEDORA-37/6.1.14-200.FC37.X86_64/X86_64/56B4F8A1A9) | kernel r8169 line |
| nic subsystem | `17aa:3190` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008UK/BDBFB765C4BC/POP%21_OS-22.04/6.0.6-76060006-GENERIC/X86_64/5AB7CCB4CC) |  |
| board_location | `Default string` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| chassis_version | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| chassis_sku | `Default string` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| cpu_socket | `AM4` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| cpu_part | `Unknown` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| cpu_upgrade | `0x31` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) | SMBIOS upgrade code |
| cpu_voltage | `1.2 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) | the most common reading; it differs by CPU |
| board version | `SDK0J40697 WIN 3305#########` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) | per-unit digits drawn at random (#) |
| board version | `NOK` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ001RRU/B114BBC992FE) |  |
| board version | `SDK0T76530 WIN 3556#########` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJCTO1WW/F4477DE67F5C) | per-unit digits drawn at random (#) |
| board version | `SDK0T76538 WIN 3556#########` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JN000GCK/6DE593E9B18A) | per-unit digits drawn at random (#) |
| memory slots | `DIMM 0/P0 CHANNEL A; DIMM 0/P0 CHANNEL B` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ0008CK/1402FBE4AAA6) |  |
| memory | `Ramaxel Technology RMSA3320MR78HAF-3200 (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JN000GCK/6DE593E9B18A) |  |
| memory | `Hynix HMA81GS6DJR8N-XN (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JNCTO1WW/0631703E328F) |  |
| memory | `Samsung M471A2K43DB1-CWE (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJS00000/67A5CBCEF039) |  |
| memory | `Unknown CT16G4SFRA32A.C8FF (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JN000EGE/52C68CA99B3E) |  |
| memory | `Unknown CT32G4SFD832A.M16FF (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ000CMT/522D7077AD79) |  |
| memory | `Kingston HP32D4S2S1ME-4 (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/45EFB5F04EDF) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of hp-250-g8 |
| disk | `HGST HTS541010A9E680 JA0OA560` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ001RRU/B114BBC992FE/ROSA-12.2/5.10.74-GENERIC-2ROSA2021.1-X86_64/X86_64/5F6F023F22) |  |

## Lenovo ThinkCentre M70s Gen 3 (`lenovo-thinkcentre-m70s-gen3`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `3` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| version | `ThinkCentre M70s Gen 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| family | `ThinkCentre M70s Gen 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| board_manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| bios | `M41KT38A 11/16/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| bios | `M41KT3EA 02/22/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T8000LIX/F5F427BCD6A9) |  |
| bios | `M41KT46A 07/24/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011TBS1M500/A7D70D1AAA74) |  |
| unit | `11T7S4E400 / LENOVO_MT_11T7_BU_Think_FM_ThinkCentre M70s Gen 3 / 32CB / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| unit | `11T8000LIX / LENOVO_MT_11T8_BU_Think_FM_ThinkCentre M70s Gen 3 / 32CB / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T8000LIX/F5F427BCD6A9) |  |
| unit | `11TBS1M500 / LENOVO_MT_11TB_BU_Think_FM_ThinkCentre M70s Gen 3 / 32CB / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011TBS1M500/A7D70D1AAA74) |  |
| cpu generation | `Core12` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| oem string | `LENOVO ThinkCentre Embedded Controller -[M41CT09A-1.09]-` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| oem string | `LENOVO ThinkCentre BIOS Boot Block Revision 1.38` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| oem string | `Lenovo Service Engine Not Supported` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| acpi | `('LENOVO', 'TC-M41  ')` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) | no Dmesg report; ThinkCentre tables are named TC- and the BIOS code (M3C, M3A, M1U, M49 in the M75q Gen 2, M75s Gen 2, M920s and neo 50s Gen 3 reports); this model's BIOS is M41KT… |
| nic chip | `Intel I219-LM` | B | [report](https://psref.lenovo.com/syspool/Sys/PDF/ThinkCentre/ThinkCentre_M70s_Gen_3/ThinkCentre_M70s_Gen_3_Spec.pdf) | no HWInfo/Dmesg NIC line of the model; the maker's specification |
| nic subsystem | `none (Intel's own)` | C |  | no HWInfo report of the model: the card keeps Intel's subsystem ID |
| board_location | `Default string` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| chassis_version | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| chassis_sku | `Default string` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| cpu_part | `To Be Filled By O.E.M.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) | SMBIOS upgrade code |
| cpu_voltage | `1.1 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) | the most common reading; it differs by CPU |
| board version | `SDK0T76530 WIN 3556#########` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) | per-unit digits drawn at random (#) |
| board version | `SDK0T76549 WIN 3792#########` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011TBS1M500/A7D70D1AAA74) | per-unit digits drawn at random (#) |
| memory slots | `Controller0-ChannelA-DIMM1/BANK 0; Controller0-ChannelA-DIMM0/BANK 0; Controller1-ChannelB-DIMM0/BANK 1; Controller1-ChannelB-DIMM1/BANK 1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| memory | `Kingston LV32D4U2S8SD-8 (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T7S4E400/7721AEEAA00F) |  |
| memory | `Samsung M378A2G43BB3-CWE (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M70s%20Gen%203%2011T8000LIX/F5F427BCD6A9) |  |
| memory | `Samsung M378A5244CB0-CWE (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011T0003QFR/F0B2A55FD054) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkcentre-neo-50s-gen3 |
| disk | `WDC WD10EZEX-08WN4A1 03.01A03` | B | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011T0003QFR/F0B2A55FD054/FEDORA-37/6.1.18-200.FC37.X86_64/X86_64/69CB363858) | no Dmesg/HWInfo report; ThinkCentre neo 50s Gen 3 (same platform) |

## Lenovo ThinkCentre neo 50s Gen 3 (`lenovo-thinkcentre-neo-50s-gen3`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `4` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SWS2AL00/09A101F055D4) |  |
| manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SWS2AL00/09A101F055D4) |  |
| version | `ThinkCentre neo 50s Gen 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SWS2AL00/09A101F055D4) |  |
| family | `ThinkCentre neo 50s Gen 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SWS2AL00/09A101F055D4) |  |
| board_manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SWS2AL00/09A101F055D4) |  |
| bios | `M49KT1EA 08/19/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| bios | `M49KT21A 01/03/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011T0003QFR/F0B2A55FD054) |  |
| bios | `M49KT2AA 03/15/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SWS2AL00/09A101F055D4) |  |
| unit | `11SWS2AL00 / LENOVO_MT_WS2A_BU_Think_FM_ThinkCentre neo 50s Gen 3 / 32E6 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SWS2AL00/09A101F055D4) |  |
| unit | `11SX002VUK / LENOVO_MT_X002_BU_Think_FM_ThinkCentre neo 50s Gen 3 / 32E6 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| unit | `11T0003QFR / LENOVO_MT_11T0_BU_Think_FM_ThinkCentre neo 50s Gen 3 / 32E6 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011T0003QFR/F0B2A55FD054) |  |
| unit | `11T0008DFM / LENOVO_MT_11T0_BU_Think_FM_ThinkCentre neo 50s Gen 3 / 32E6 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011T0008DFM/E093943EDF71) |  |
| cpu generation | `Core12` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SWS2AL00/09A101F055D4) |  |
| oem string | `LENOVO ThinkCentre Embedded Controller -[M49CT09A-1.09]-` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| oem string | `LENOVO ThinkCentre BIOS Boot Block Revision 1.1E` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| oem string | `Lenovo Service Engine Not Supported` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| acpi | `'LENOVO' 'TC-M49  '` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F/DEBIAN-10/4.19.0-23-AMD64/X86_64/C1D51DBA1D) |  |
| nic chip | `Realtek RTL8168h/8111h` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F/DEBIAN-10/4.19.0-23-AMD64/X86_64/C1D51DBA1D) | kernel r8169 line |
| nic subsystem | `none (Intel's own)` | C |  | no HWInfo report of the model: the card keeps Intel's subsystem ID |
| board_location | `Default string` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SWS2AL00/09A101F055D4) |  |
| chassis_version | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SWS2AL00/09A101F055D4) |  |
| chassis_sku | `Default string` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SWS2AL00/09A101F055D4) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SWS2AL00/09A101F055D4) |  |
| cpu_part | `To Be Filled By O.E.M.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SWS2AL00/09A101F055D4) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SWS2AL00/09A101F055D4) | SMBIOS upgrade code |
| cpu_voltage | `1.0 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) | the most common reading; it differs by CPU |
| board version | `NOK` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| board version | `SDK0T76530 WIN 3556#########` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SWS2AL00/09A101F055D4) | per-unit digits drawn at random (#) |
| memory slots | `DIMM1/BANK 0; DIMM2/BANK 0` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SWS2AL00/09A101F055D4) |  |
| memory | `0x0C97 TXU16G2M3200C16X (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011T0003QFR/F0B2A55FD054) |  |
| memory | `Golden Empire CL22-22-22 D4-3200 (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SWS2AL00/09A101F055D4) |  |
| memory | `Ramaxel Technology RMUA5190MR86H9F-3200 (4 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011T0008DFM/E093943EDF71) |  |
| memory | `Samsung M378A5244CB0-CWE (4 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011T0003QFR/F0B2A55FD054) |  |
| memory | `SK Hynix HMA81GU6DJR8N-XN (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011SX002VUK/5B1DD71AD29F) |  |
| disk | `WDC WD10EZEX-08WN4A1 03.01A03` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011T0003QFR/F0B2A55FD054/FEDORA-37/6.1.18-200.FC37.X86_64/X86_64/69CB363858) |  |

## Lenovo ThinkCentre M920s (`lenovo-thinkcentre-m920s`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `8` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| version | `ThinkCentre M920s` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| family | `ThinkCentre M920s` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| board_manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| bios | `M1UKT4EA 12/16/2019` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| bios | `M1UKT45A 07/11/2019` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SKS2SK00/C7C3BCAF5A32) |  |
| bios | `M1UKT47A 08/14/2019` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/E0B706A6FCFF) |  |
| bios | `M1UKT55A 04/22/2020` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SKS44L00/EF6E185CAE11) |  |
| bios | `M1UKT5DA 10/20/2020` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SKS0C100/8F8D78D61360) |  |
| bios | `M1UKT68A 12/27/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ0059US/0E175F0CC3BC) |  |
| bios | `M1UKT6EA 10/06/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SKS3J100/77E89EB4ED36) |  |
| unit | `10SJ001JPB / LENOVO_MT_10SJ_BU_Think_FM_ThinkCentre M920s / 3132 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| unit | `10SJ0059US / LENOVO_MT_10SJ_BU_Think_FM_ThinkCentre M920s / 3132 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ0059US/0E175F0CC3BC) |  |
| unit | `10SKS0C100 / LENOVO_MT_10SK_BU_Think_FM_ThinkCentre M920s / 3132 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SKS0C100/8F8D78D61360) |  |
| unit | `10SKS1QJ00 / LENOVO_MT_10SK_BU_Think_FM_ThinkCentre M920s / 3132 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SKS1QJ00/75124A9D4A17) |  |
| unit | `10SKS2SK00 / LENOVO_MT_10SK_BU_Think_FM_ThinkCentre M920s / 3132 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SKS2SK00/C7C3BCAF5A32) |  |
| unit | `10SKS3J100 / LENOVO_MT_10SK_BU_Think_FM_ThinkCentre M920s / 3132 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SKS3J100/77E89EB4ED36) |  |
| cpu generation | `Core6to9` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| oem string | `LENOVO ThinkCentre Embedded Controller -[M1UCT18A-1.18]-` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| oem string | `LENOVO ThinkCentre BIOS Boot Block Revision 1.4E` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| oem string | `Lenovo Service Engine Not Supported` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| acpi | `'LENOVO' 'TC-M1U  '` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691/MANJARO-19.0.1/5.5.6-1-MANJARO/X86_64/27550891B3) |  |
| nic chip | `Intel Ethernet Connection (7) I219-LM` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691/MANJARO-19.0.1/5.5.6-1-MANJARO/X86_64/27550891B3) |  |
| nic subsystem | `17aa:3132` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691/MANJARO-19.0.1/5.5.6-1-MANJARO/X86_64/27550891B3) |  |
| board_location | `Default string` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| chassis_version | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| chassis_sku | `Default string` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| cpu_part | `To Be Filled By O.E.M.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| cpu_upgrade | `0x32` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) | SMBIOS upgrade code |
| cpu_voltage | `1.0 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) | the most common reading; it differs by CPU |
| board version | `SDK0J40697 WIN 3305#########` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) | per-unit digits drawn at random (#) |
| memory slots | `ChannelA-DIMM1/BANK 1; ChannelA-DIMM0/BANK 0; ChannelB-DIMM0/BANK 2; ChannelB-DIMM1/BANK 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| memory | `Samsung M378A1K43CB2-CTD (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SJ001JPB/6AB2A35AC691) |  |
| memory | `0194 SF4641G8CK8I8HLSBG (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SKS2SK00/C7C3BCAF5A32) |  |
| memory | `Samsung M378A2K43CB1-CTD (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SKS0C100/8F8D78D61360) |  |
| memory | `Samsung M378A2K43DB1-CTD (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SKS44L00/EF6E185CAE11) |  |
| memory | `SK Hynix HMA451U6AFR8N-TF (4 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SKS3J100/77E89EB4ED36) |  |
| disk | `SanDisk SDSSDHII120G X31200RL` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SKS44L00/EF6E185CAE11/ROSA-12.2/5.10.74-GENERIC-2ROSA2021.1-X86_64/X86_64/C26BB7D11C) |  |

## Lenovo ThinkCentre M75s Gen 2 (`lenovo-thinkcentre-m75s-gen2`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `6` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2) |  |
| manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2) |  |
| version | `ThinkCentre M75s Gen 2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2) |  |
| family | `ThinkCentre M75s Gen 2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2) |  |
| board_manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2) |  |
| bios | `M46KT34A 03/02/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| bios | `M3AKT35A 06/03/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JB002GPB/A1A4A3F49260) |  |
| bios | `M3AKT3BA 06/21/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2) |  |
| bios | `M3AKT3FA 11/19/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS1J200/CBCE8C6DE4A0) |  |
| bios | `M46KT2AA 06/10/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S08900/6DFF0F133796) |  |
| unit | `11R9S02K00 / LENOVO_MT_11R9_BU_Think_FM_ThinkCentre M75s Gen 2 / 32E1 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| unit | `11JAS0CJ00 / LENOVO_MT_11JA_BU_Think_FM_ThinkCentre M75s Gen 2 / 318E / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2) |  |
| unit | `11JAS1J200 / LENOVO_MT_11JA_BU_Think_FM_ThinkCentre M75s Gen 2 / 318E / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS1J200/CBCE8C6DE4A0) |  |
| unit | `11JB002GPB / LENOVO_MT_11JB_BU_Think_FM_ThinkCentre M75s Gen 2 / 318E / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JB002GPB/A1A4A3F49260) |  |
| unit | `11R9S08900 / LENOVO_MT_11R9_BU_Think_FM_ThinkCentre M75s Gen 2 / 32E1 / chassis 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S08900/6DFF0F133796) |  |
| cpu generation | `Zen2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2) |  |
| cpu generation | `Zen3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| oem string | `LENOVO ThinkCentre Embedded Controller -[M46CT13A-1.13]-` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| oem string | `LENOVO ThinkCentre BIOS Boot Block Revision 1.34` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| oem string | `Lenovo Service Engine Not Supported` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| oem string | `INVALID` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| acpi | `'LENOVO' 'TC-M3A  '` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2/MX-21/5.10.0-19-AMD64/X86_64/6B190BFB4F) |  |
| nic chip | `Realtek RTL8168ep/8111ep` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2/MX-21/5.10.0-19-AMD64/X86_64/6B190BFB4F) | kernel r8169 line |
| nic subsystem | `17aa:318e` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2/MX-21/5.10.0-19-AMD64/X86_64/6B190BFB4F) |  |
| board_location | `Default string` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2) |  |
| chassis_version | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2) |  |
| chassis_sku | `Default string` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2) |  |
| cpu_socket | `AM4` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2) |  |
| cpu_part | `Unknown` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2) |  |
| cpu_upgrade | `0x31` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2) | SMBIOS upgrade code |
| cpu_voltage | `1.4 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) | the most common reading; it differs by CPU |
| board version | `SDK0J40697 WIN 3305#########` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JB002GPB/A1A4A3F49260) | per-unit digits drawn at random (#) |
| board version | `NOK` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2) |  |
| board version | `SDK0L22692 WIN 3792#########` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS1J200/CBCE8C6DE4A0) | per-unit digits drawn at random (#) |
| memory slots | `DIMM 1/P0 CHANNEL A; DIMM 0/P0 CHANNEL A; DIMM 0/P0 CHANNEL B; DIMM 1/P0 CHANNEL B` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2) |  |
| memory | `Unknown SMU4WEC8C1K0464FCG (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011R9S02K00/546F0B9C7736) |  |
| memory | `Ramaxel Technology RMUA5200ME78HAF-3200 (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JAS0CJ00/C5ED616588A2) |  |
| memory | `Micron Technology 8ATF2G64AZ-3G2E1 (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JB002GPB/A1A4A3F49260) |  |
| memory | `Unknown CT16G4DFRA32A.C8FE (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JB002GPB/A1A4A3F49260) |  |
| memory | `Samsung M378A5244CB0-CWE (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011T0003QFR/F0B2A55FD054) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkcentre-neo-50s-gen3 |
| disk | `KINGSTON SUV400S37240G 0C3G37R5` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JB002GPB/A1A4A3F49260/FEDORA-34/5.13.19-200.FC34.X86_64/X86_64/68F4FF7431) |  |

## Dell Latitude 5420 (`dell-latitude-5420`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `107` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E) |  |
| manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E) |  |
| version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E) |  |
| family | `Latitude` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E) |  |
| board_manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E) |  |
| bios | `1.13.1 10/13/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09DD6C37BF56) |  |
| bios | `1.17.2 03/28/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/17C0677F371B) |  |
| bios | `1.25.0 12/20/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/1C480B01C0CC) |  |
| bios | `1.30.0 07/10/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/389D66210369) |  |
| bios | `1.40.0 08/13/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/0CF1DA95927B) |  |
| bios | `1.15.1 12/20/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/3D9FEC58A5EF) |  |
| bios | `1.33.0 11/10/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/11E5360AFB1B) |  |
| bios | `1.37.0 04/22/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09A938626C31) |  |
| bios | `1.8.0 06/08/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09FFAAE0F15B) |  |
| bios | `1.10.0 07/06/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/2C35A782FDFA) |  |
| unit | `Latitude 5420 / 0A20 / 01M3M4 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09A938626C31) |  |
| unit | `Latitude 5420 / 0A20 / 03P5X2 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09FFAAE0F15B) |  |
| unit | `Latitude 5420 / 0A20 / 054CCV / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/0CD5F7B36F02) |  |
| unit | `Latitude 5420 / 0A20 / 0M51J7 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E) |  |
| unit | `Latitude 5420 / 0A20 / 047J2X / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/1B2E5B33F377) |  |
| unit | `Latitude 5420 / 0A20 / 035X97 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/2776866D5375) |  |
| cpu generation | `Core11` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E) |  |
| oem string | `Dell System` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/3155F9ED1126) |  |
| oem string | `1[{sku}]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/3155F9ED1126) |  |
| oem string | `3[1.0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/3155F9ED1126) |  |
| oem string | `12[www.dell.com]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/3155F9ED1126) |  |
| oem string | `14[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/3155F9ED1126) |  |
| oem string | `15[0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/3155F9ED1126) |  |
| acpi | `'DELL  ' 'Dell Inc'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E/UBUNTU-22.04/5.17.0-1012-OEM/X86_64/1CC724CF75) |  |
| nic chip | `Intel Ethernet Connection (13) I219-LM` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205420/05D439A6E1C6/POP%21_OS-20.04/5.16.11-76051611-GENERIC/X86_64/B1A1E20AB3) |  |
| nic subsystem | `1028:0a20` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205420/05D439A6E1C6/POP%21_OS-20.04/5.16.11-76051611-GENERIC/X86_64/B1A1E20AB3) |  |
| board_location | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E) |  |
| chassis_version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E) |  |
| chassis_sku | `Notebook` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E) |  |
| cpu_part | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E) | SMBIOS upgrade code |
| cpu_voltage | `0.7 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E) | the most common reading; it differs by CPU |
| board version | `A00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E) |  |
| board version | `A01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/2AC7C70C6075) |  |
| memory slots | `DIMM B/BANK 0; DIMM A/BANK 0` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E) |  |
| memory | `80AD000080AD HMAA2GS6CJR8N-XN (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09496B76F37E) |  |
| memory | `80AD000080AD HMAA2GS6AJR8N-XN (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09FFAAE0F15B) |  |
| memory | `80AD000080AD HMAA1GS6CJR6N-XN (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/09A938626C31) |  |
| memory | `019400000194 SMS4WEC8C1K0446FCG (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/0BB211F0B91C) |  |
| memory | `01BA000080AD M4S32S682QMMM52-12 (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/1A53DBCA11B1) |  |
| memory | `80CE000080CE M471A5244CB0-CTD (4 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205420/42162C257567) |  |
| disk | `MTFDDAV256TBN-1AR15ABHA HPC0T12` | B | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205520/1DC6794B86BA/UBUNTU-20.04/5.11.0-46-GENERIC/X86_64/95721C3566) | its one SATA disk (INTEL SSDSCKKF25…, firmware tail D16N) matches no SMART dump; Latitude 5520 (same platform) |

## Dell Latitude 5430 (`dell-latitude-5430`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `27` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/01791CD61E0F) |  |
| manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/01791CD61E0F) |  |
| version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/01791CD61E0F) |  |
| family | `Latitude` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/01791CD61E0F) |  |
| board_manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/01791CD61E0F) |  |
| bios | `1.10.0 12/16/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/189796D817B0) |  |
| bios | `1.18.0 11/14/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/0674E61967FE) |  |
| bios | `1.15.0 07/12/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/55B536D71688) |  |
| bios | `1.17.1 10/03/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/99D61C2E46CC) |  |
| bios | `1.19.0 12/18/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/4D7FA6C8B27E) |  |
| bios | `1.2.2 05/09/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/3952B6BA3834) |  |
| bios | `1.24.0 07/07/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/5C2B8203C696) |  |
| bios | `1.4.0 06/20/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/820591524D8C) |  |
| bios | `1.6.1 09/05/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/436AAE2DC600) |  |
| bios | `1.13.1 05/10/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/E4C33D62C2E9) |  |
| unit | `Latitude 5430 / 0B04 / 0260KT / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/01791CD61E0F) |  |
| unit | `Latitude 5430 / 0B04 / 01Y2TP / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/189796D817B0) |  |
| unit | `Latitude 5430 / 0B04 / 04X33N / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/5A00B380280C) |  |
| unit | `Latitude 5430 / 0B04 / 03G0RF / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/55B536D71688) |  |
| unit | `Latitude 5430 / 0B04 / 051DJX / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/0674E61967FE) |  |
| unit | `Latitude 5430 / 0B04 / 0JVPPD / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/565920793702) |  |
| cpu generation | `Core12` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/01791CD61E0F) |  |
| oem string | `Dell System` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/66FFA6731E3F) |  |
| oem string | `1[{sku}]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/66FFA6731E3F) |  |
| oem string | `3[1.0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/66FFA6731E3F) |  |
| oem string | `12[www.dell.com]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/66FFA6731E3F) |  |
| oem string | `14[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/66FFA6731E3F) |  |
| oem string | `15[0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/66FFA6731E3F) |  |
| acpi | `'DELL  ' 'Dell Inc'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Dell/Latitude/Latitude%205430/01791CD61E0F/UBUNTU-22.04/5.15.0-58-GENERIC/X86_64/2AFA57D0FA) |  |
| nic chip | `Intel Ethernet Connection (16) I219-LM` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205430/01791CD61E0F/UBUNTU-22.04/5.15.0-58-GENERIC/X86_64/2AFA57D0FA) |  |
| nic subsystem | `1028:0b04` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205430/01791CD61E0F/UBUNTU-22.04/5.15.0-58-GENERIC/X86_64/2AFA57D0FA) |  |
| board_location | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/01791CD61E0F) |  |
| chassis_version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/01791CD61E0F) |  |
| chassis_sku | `Notebook` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/01791CD61E0F) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/01791CD61E0F) |  |
| cpu_part | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/01791CD61E0F) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/01791CD61E0F) | SMBIOS upgrade code |
| cpu_voltage | `1.2 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/189796D817B0) | the most common reading; it differs by CPU |
| board version | `A00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/01791CD61E0F) |  |
| board version | `A01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/4F42BA288B25) |  |
| memory slots | `DIMM A/; DIMM B/` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/0674E61967FE) |  |
| memory | `80CE000080CE M471A1G44BB0-CWE (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/0674E61967FE) |  |
| memory | `80AD000080AD HMAA1GS6CJR6N-XN (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/3952B6BA3834) |  |
| memory | `019400000194 SMS4WEC8C2J2446SAG (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/4F42BA288B25) |  |
| memory | `01980000802C K1CXP8-MIB (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/2DE74FEFCA3B) |  |
| memory | `859B0000802C CT32G4SFD832A.M16FF (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205430/D44371F64C47) |  |
| memory | `01980000802C KCDT82-MIE (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of dell-optiplex-5090 |
| disk | `MTFDDAV256TBN-1AR15ABHA HPC0T12` | B | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205520/1DC6794B86BA/UBUNTU-20.04/5.11.0-46-GENERIC/X86_64/95721C3566) | no SATA disk in its reports; Latitude 5520 (same M.2 slot family) |

## Dell Latitude 5520 (`dell-latitude-5520`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `57` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) |  |
| manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) |  |
| version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) |  |
| family | `Latitude` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) |  |
| board_manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) |  |
| bios | `1.13.0 09/30/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/1DC6794B86BA) |  |
| bios | `1.27.0 03/17/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/4DF46FFB7B42) |  |
| bios | `1.6.0 04/19/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/089F750864FB) |  |
| bios | `1.12.2 09/13/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/34632103919C) |  |
| bios | `1.4.2 03/09/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/33DA2508EC52) |  |
| bios | `1.5.1 04/01/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) |  |
| bios | `1.18.1 04/14/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/516D58BED016) |  |
| bios | `1.31.0 08/08/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/3C81F79D4B2B) |  |
| bios | `1.8.1 06/17/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/60D3383447C0) |  |
| bios | `1.0.2 12/01/2020` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/9537F02AAC07) |  |
| unit | `Latitude 5520 / 0A21 / 0G60M3 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/383D21E1AF42) |  |
| unit | `Latitude 5520 / 0A21 / 063MV5 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/0B5385776F2E) |  |
| unit | `Latitude 5520 / 0A21 / 073T17 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) |  |
| unit | `Latitude 5520 / 0A21 / 0DPC2R / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/20F9B8A81F8A) |  |
| unit | `Latitude 5520 / 0A21 / 0MKYVR / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/0762D161707D) |  |
| unit | `Latitude 5520 / 0A21 / 0DKMM3 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/34632103919C) |  |
| cpu generation | `Core11` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) |  |
| oem string | `Dell System` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/3DC6140AFCBC) |  |
| oem string | `1[{sku}]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/3DC6140AFCBC) |  |
| oem string | `3[1.0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/3DC6140AFCBC) |  |
| oem string | `12[www.dell.com]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/3DC6140AFCBC) |  |
| oem string | `14[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/3DC6140AFCBC) |  |
| oem string | `15[11]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/3DC6140AFCBC) |  |
| acpi | `'DELL  ' 'Dell Inc'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13/LINUXMINT-20.2/5.13.0-051300-GENERIC/X86_64/83EDC6AD35) |  |
| nic chip | `Intel Ethernet Connection (13) I219-LM` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205520/0C3D50B2F8D8/UBUNTU-22.04/5.15.0-58-GENERIC/X86_64/A3541758F7) |  |
| nic subsystem | `1028:0a21` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205520/0C3D50B2F8D8/UBUNTU-22.04/5.15.0-58-GENERIC/X86_64/A3541758F7) |  |
| board_location | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) |  |
| chassis_version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) |  |
| chassis_sku | `Notebook` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) |  |
| cpu_part | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) | SMBIOS upgrade code |
| cpu_voltage | `0.7 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) | the most common reading; it differs by CPU |
| board version | `A00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) |  |
| memory slots | `DIMM 1/BANK 0; DIMM 2/BANK 0` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) |  |
| memory | `80AD000080AD HMAA2GS6CJR8N-XN (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/06DA8F88AC13) |  |
| memory | `802C0000802C 8ATF2G64HZ-3G2E2 (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/089F750864FB) |  |
| memory | `80AD000080AD HMAA1GS6CJR6N-XN (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/0BDDCBB7E495) |  |
| memory | `80CE000080CE M471A1G44BB0-CWE (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/20F9B8A81F8A) |  |
| memory | `80CE000080CE M471A4G43AB1-CWE (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/516D58BED016) |  |
| memory | `04CD000080AD F4-3200C22-32GRS (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205520/5F4FBBD5E58E) |  |
| memory | `01980000802C KCDT82-MIE (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of dell-optiplex-5090 |
| disk | `MTFDDAV256TBN-1AR15ABHA HPC0T12` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205520/1DC6794B86BA/UBUNTU-20.04/5.11.0-46-GENERIC/X86_64/95721C3566) |  |

## Dell Latitude 5530 (`dell-latitude-5530`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `28` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0995023215C8) |  |
| manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0995023215C8) |  |
| version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0995023215C8) |  |
| family | `Latitude` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0995023215C8) |  |
| board_manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0995023215C8) |  |
| bios | `1.11.3 03/02/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0995023215C8) |  |
| bios | `1.5.0 07/08/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/1735DE9EC3CE) |  |
| bios | `1.7.0 09/13/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/1C78D34B8BC4) |  |
| bios | `1.10.0 12/12/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/106AC7988AE1) |  |
| bios | `1.19.0 12/15/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/331690CFC04D) |  |
| bios | `1.9.0 11/15/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/59219C50D35C) |  |
| bios | `1.14.0 06/07/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/13426D3C1CAE) |  |
| bios | `1.15.0 07/11/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/A100DA078336) |  |
| bios | `1.2.1 04/14/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/86FDD54C2C30) |  |
| bios | `1.25.0 08/14/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/1AFAE3AEA1E4) |  |
| unit | `Latitude 5530 / 0B06 / 0C6CYC / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0995023215C8) |  |
| unit | `Latitude 5530 / 0B06 / 0K0FKG / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/1AFAE3AEA1E4) |  |
| unit | `Latitude 5530 / 0B06 / 0607DF / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/E49605BFE87C) |  |
| unit | `Latitude 5530 / 0B06 / 06MMRV / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/CE931F60035B) |  |
| unit | `Latitude 5530 / 0B06 / 07XRVJ / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/331690CFC04D) |  |
| unit | `Latitude 5530 / 0B06 / 0CCXYK / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/6D24878D3433) |  |
| cpu generation | `Core11` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/9852DAC50C4D) |  |
| cpu generation | `Core12` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0995023215C8) |  |
| oem string | `Dell System` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/465113864F48) |  |
| oem string | `1[{sku}]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/465113864F48) |  |
| oem string | `3[1.0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/465113864F48) |  |
| oem string | `12[www.dell.com]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/465113864F48) |  |
| oem string | `14[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/465113864F48) |  |
| oem string | `15[11]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/465113864F48) |  |
| acpi | `'DELL  ' 'Dell Inc'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Dell/Latitude/Latitude%205530/0995023215C8/UBUNTU-22.04/5.19.0-32-GENERIC/X86_64/802248E232) |  |
| nic chip | `Intel Ethernet Connection (16) I219-LM` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205530/273C72734052/UBUNTU-22.04/5.15.0-48-GENERIC/X86_64/9453558076) |  |
| nic subsystem | `1028:0b06` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205530/273C72734052/UBUNTU-22.04/5.15.0-48-GENERIC/X86_64/9453558076) |  |
| board_location | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0995023215C8) |  |
| chassis_version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0995023215C8) |  |
| chassis_sku | `Notebook` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0995023215C8) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0995023215C8) |  |
| cpu_part | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0995023215C8) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0995023215C8) | SMBIOS upgrade code |
| cpu_voltage | `1.2 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0F6024C05650) | the most common reading; it differs by CPU |
| board version | `A00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0995023215C8) |  |
| memory slots | `DIMM 1/BANK 0; DIMM 2/BANK 0` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0995023215C8) |  |
| memory | `80CE000080CE M471A1G44BB0-CWE (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0995023215C8) |  |
| memory | `80AD000080AD HMAA1GS6CJR6N-XN (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/1AFAE3AEA1E4) |  |
| memory | `80AD000080AD HMAA2GS6CJR8N-XN (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0F6024C05650) |  |
| memory | `80CE000080CE M471A2G43BB2-CWE (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%205530/0F6024C05650) |  |
| memory | `01980000802C KCDT82-MIE (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%205090/14C80413B16B) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of dell-optiplex-5090 |
| memory | `859B0000802C CT32G4SFD832A.M16FF (32 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/63830CD3C14A) | no 32 GiB module with a part number in the reports of this model; the same maker's part in the reports of dell-optiplex-7000 |
| disk | `MTFDDAV256TBN-1AR15ABHA HPC0T12` | B | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205520/1DC6794B86BA/UBUNTU-20.04/5.11.0-46-GENERIC/X86_64/95721C3566) | no SATA disk in its reports; Latitude 5520 (same M.2 slot family) |

## Dell Latitude 3520 (`dell-latitude-3520`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `25` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/136EC1A40F06) |  |
| manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/136EC1A40F06) |  |
| version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/136EC1A40F06) |  |
| family | `Latitude` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/136EC1A40F06) |  |
| board_manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/136EC1A40F06) |  |
| bios | `1.9.1 07/05/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/85BEF4B700E6) |  |
| bios | `1.27.0 03/13/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/136EC1A40F06) |  |
| bios | `1.25.1 01/05/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/EEF059AAD017) |  |
| bios | `1.3.1 04/23/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/BEEE0CBAF2F8) |  |
| bios | `1.30.0 06/06/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/233E4E7069F9) |  |
| bios | `1.31.0 08/11/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/9ABDDFD46087) |  |
| bios | `1.32.1 10/04/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/3E61F1A338E0) |  |
| bios | `1.10.1 08/17/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/BE448287F985) |  |
| bios | `1.12.0 10/01/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/55AF021027BF) |  |
| bios | `1.14.1 12/15/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/785177094905) |  |
| unit | `Latitude 3520 / 0A7C / 0R31RD / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/568AE610A863) |  |
| unit | `Latitude 3520 / 0B21 / 0C9RFG / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/136EC1A40F06) |  |
| unit | `Latitude 3520 / 0B21 / 03VVMC / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/3E61F1A338E0) |  |
| unit | `Latitude 3520 / 0A7C / 08N6T5 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/9ABDDFD46087) |  |
| unit | `Latitude 3520 / 0B21 / 004PGC / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/1405D592A133) |  |
| unit | `Latitude 3520 / 0B21 / 0D9VNX / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/3899B0D81E4C) |  |
| cpu generation | `Core11` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/136EC1A40F06) |  |
| oem string | `Dell System` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/A991732F85E9) |  |
| oem string | `1[{sku}]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/A991732F85E9) |  |
| oem string | `3[1.0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/A991732F85E9) |  |
| oem string | `12[www.dell.com]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/A991732F85E9) |  |
| oem string | `14[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/A991732F85E9) |  |
| oem string | `15[11]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/A991732F85E9) |  |
| acpi | `'DELL  ' 'Dell Inc'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Dell/Latitude/Latitude%203520/13DBE0B08ADA/UBUNTU-18.04/5.4.0-97-GENERIC/X86_64/7F6955E406) |  |
| nic chip | `Realtek RTL8168h/8111h` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Dell/Latitude/Latitude%203520/13DBE0B08ADA/UBUNTU-18.04/5.4.0-97-GENERIC/X86_64/7F6955E406) | kernel r8169 line |
| nic subsystem | `1028:0a7c` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%203520/13DBE0B08ADA/UBUNTU-18.04/5.4.0-97-GENERIC/X86_64/7F6955E406) |  |
| board_location | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/136EC1A40F06) |  |
| chassis_version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/136EC1A40F06) |  |
| chassis_sku | `Notebook` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/136EC1A40F06) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/136EC1A40F06) |  |
| cpu_part | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/136EC1A40F06) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/136EC1A40F06) | SMBIOS upgrade code |
| cpu_voltage | `0.7 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/136EC1A40F06) | the most common reading; it differs by CPU |
| board version | `A00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/136EC1A40F06) |  |
| memory slots | `DIMM 1/BANK 0; DIMM 2/BANK 0` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/136EC1A40F06) |  |
| memory | `80AD000080AD HMAA2GS6CJR8N-XN (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/1405D592A133) |  |
| memory | `075D00000000 GR3200S464L22/16G (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/233E4E7069F9) |  |
| memory | `80AD000080AD HMAA1GS6CJR6N-XN (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/785177094905) |  |
| memory | `01980000802C 9905700-086.A00G (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/3E61F1A338E0) |  |
| memory | `80AD000080AD HMA851S6DJR6N-XN (4 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Latitude/Latitude%203520/64EF016761BD) |  |
| memory | `859B0000802C CT32G4SFD832A.M16FF (32 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/63830CD3C14A) | no 32 GiB module with a part number in the reports of this model; the same maker's part in the reports of dell-optiplex-7000 |
| disk | `TOSHIBA MQ04ABF100 100001` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Dell/Latitude/Latitude%203520/BEEE0CBAF2F8/UBUNTU-20.04/5.10.0-1045-OEM/X86_64/B28801BF6C) |  |
| disk | `TOSHIBA MQ04ABF100 100002` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Dell/Latitude/Latitude%203520/13DBE0B08ADA/UBUNTU-18.04/5.4.0-97-GENERIC/X86_64/7F6955E406) |  |

## Dell Vostro 15 3510 (`dell-vostro-15-3510`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `23` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9) |  |
| manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9) |  |
| version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9) |  |
| family | `Vostro` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9) |  |
| board_manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9) |  |
| bios | `1.12.1 04/27/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9) |  |
| bios | `1.22.1 05/10/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/495777EA28D7) |  |
| bios | `1.27.0 02/16/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/39A43F7DF02C) |  |
| bios | `1.15.1 07/28/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/72E3ED3BC0D2) |  |
| bios | `1.21.0 03/08/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/7208D2A1AAFD) |  |
| bios | `1.32.0 08/16/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/354B1FD744F6) |  |
| bios | `1.13.0 05/17/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/9694920F0198) |  |
| bios | `1.16.0 08/15/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/A653074476B0) |  |
| bios | `1.18.2 10/27/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/9E04CDBFDAA9) |  |
| bios | `1.25.1 10/03/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/565745A40C10) |  |
| unit | `Vostro 15 3510 / 0AB2 / 0818KM / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/565745A40C10) |  |
| unit | `Vostro 15 3510 / 0AB2 / 08H85W / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/670F2341D570) |  |
| unit | `Vostro 15 3510 / 0AB3 / 095CG8 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9) |  |
| unit | `Vostro 15 3510 / 0AB2 / 0N9K43 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/7208D2A1AAFD) |  |
| unit | `Vostro 15 3510 / 0ADB / 00NFD7 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/39A43F7DF02C) |  |
| unit | `Vostro 15 3510 / 0AB2 / 04H6FV / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/354B1FD744F6) |  |
| cpu generation | `Core10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9) |  |
| cpu generation | `Core11` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/354B1FD744F6) |  |
| oem string | `Dell System` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/972B5709FF1E) |  |
| oem string | `1[{sku}]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/972B5709FF1E) |  |
| oem string | `3[1.0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/972B5709FF1E) |  |
| oem string | `12[www.dell.com]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/972B5709FF1E) |  |
| oem string | `14[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/972B5709FF1E) |  |
| oem string | `15[0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/972B5709FF1E) |  |
| acpi | `'DELL  ' 'Dell Inc'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Dell/Vostro/Vostro%2015%203510/84A15211A44E/UBUNTU-20.04/5.14.0-1045-OEM/X86_64/BCB8DBF459) |  |
| nic chip | `Realtek RTL8168h/8111h` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9/MANJARO-21.3.4/5.15.55-1-MANJARO/X86_64/8327D57F7B) | kernel r8169 line |
| nic subsystem | `1028:0ab2` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/9694920F0198/ARCO-ROLLING/5.18.10-ZEN1-1-ZEN/X86_64/B44D77C9A0) |  |
| board_location | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9) |  |
| chassis_version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9) |  |
| chassis_sku | `Notebook` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9) |  |
| cpu_socket | `CPU 1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9) |  |
| cpu_part | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9) | SMBIOS upgrade code |
| cpu_voltage | `0.8 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/354B1FD744F6) | the most common reading; it differs by CPU |
| board version | `A00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9) |  |
| memory slots | `DIMM A/; DIMM B/` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9) |  |
| memory | `80AD000080AD HMAA1GS6CJR6N-XN (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/354B1FD744F6) |  |
| memory | `019400000000 SMS4WEC8C1K0446FCG (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/3453024970F9) |  |
| memory | `04CB000080AD AD4S3200J4G22-B (4 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/BCCAAC10EEB7) |  |
| memory | `04CB000080AD AL1P32NC4U1-B89S (4 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/9CF0A42E9C33) |  |
| memory | `075D00000000 GR3200S464L22S/16G (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Dell/Vostro/Vostro%2015%203510/495777EA28D7) |  |
| memory | `859B0000802C CT32G4SFD832A.M16FF (32 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Desktop/Dell/OptiPlex/OptiPlex%207000/63830CD3C14A) | no 32 GiB module with a part number in the reports of this model; the same maker's part in the reports of dell-optiplex-7000 |
| disk | `ST1000LM049-2GH172 SDM1` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%203080/720698D0737E/UBUNTU-22.04/5.15.0-43-GENERIC/X86_64/B1011AE242) |  |

## HP 250 G8 (`hp-250-g8`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `43` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `Insyde` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0C75DE10669C) |  |
| manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0C75DE10669C) |  |
| version | `Type1ProductConfigId` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0C75DE10669C) |  |
| family | `103C_5336AN HP 200` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0C75DE10669C) |  |
| board_manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0C75DE10669C) |  |
| bios | `F.53 10/15/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0C75DE10669C) |  |
| bios | `F.41 12/21/2020` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/146CB534D161) |  |
| bios | `F.43 03/31/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/2D31D08D9E61) |  |
| bios | `F.63 08/24/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/3C4087A29BA4) |  |
| bios | `F.45 06/16/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/1FB883613B6D) |  |
| bios | `F.46 07/27/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/6645D499C7B9) |  |
| bios | `F.52 09/10/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/3D873C6BF9FB) |  |
| bios | `F.54 05/11/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/551945D48A90) |  |
| bios | `F.50 08/12/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/9ACD22A738D9) |  |
| bios | `F.55 07/07/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/C7E5690EEC81) |  |
| unit | `HP 250 G8 Notebook PC / 2W8W2EA#ACB / 85F3 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/95EBE86D09AB) |  |
| unit | `HP 250 G8 Notebook PC / 2X7V7EA#AKD / 85F3 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/2D31D08D9E61) |  |
| unit | `HP 250 G8 Notebook PC / 4P375ES#ABD / 881D / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/DAEE91B88EB6) |  |
| unit | `HP 250 G8 Notebook PC / 59S26EA#ABZ / 881D / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/3C4087A29BA4) |  |
| unit | `HP 250 G8 Notebook PC / 2E9G8EA#ABZ / 85F5 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/1F277278F495) |  |
| unit | `HP 250 G8 Notebook PC / 2E9H2EA#AKC / 85F3 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/9ACD22A738D9) |  |
| cpu generation | `Core10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/2D31D08D9E61) |  |
| cpu generation | `Core11` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0C75DE10669C) |  |
| oem string | `$HP$` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/5C1D4AB5A76F) |  |
| oem string | `OemString2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/5C1D4AB5A76F) |  |
| oem string | `BCU_Y` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/5C1D4AB5A76F) |  |
| oem string | `ABS 70/71 78 79 7A 7B` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/5C1D4AB5A76F) |  |
| oem string | `OemString5` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/5C1D4AB5A76F) |  |
| oem string | `HP_Mute_LED_P_G` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/5C1D4AB5A76F) |  |
| oem string | `FBYTE#3K3Y5Y6E6b7J7M7d7japawbhfPm9.7d;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/5C1D4AB5A76F) |  |
| oem string | `BUILDID#20WW2F6D602#SABD#DABD;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/5C1D4AB5A76F) |  |
| oem string | `OemString9` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/5C1D4AB5A76F) |  |
| oem string | `OemString10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/5C1D4AB5A76F) |  |
| oem string | `OemString11` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/5C1D4AB5A76F) |  |
| acpi | `'HPQOEM' 'SLIC-MPC'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0498C96992DD/LMDE-5/5.10.0-21-AMD64/X86_64/08D9BFBB41) |  |
| nic chip | `Realtek RTL8168h/8111h` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0498C96992DD/LMDE-5/5.10.0-21-AMD64/X86_64/08D9BFBB41) | kernel r8169 line |
| nic subsystem | `103c:881d` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0C75DE10669C/DEBIAN-11/5.10.0-18-AMD64/X86_64/AE83BEC6AD) |  |
| board_location | `Type2 - Board Chassis Location` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0C75DE10669C) |  |
| chassis_version | `Chassis Version` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0C75DE10669C) |  |
| chassis_sku | `SKU Number` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0C75DE10669C) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0C75DE10669C) |  |
| cpu_part | `To Be Filled By O.E.M.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0C75DE10669C) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0C75DE10669C) | SMBIOS upgrade code |
| cpu_voltage | `0.7 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0FB594E96E36) | the most common reading; it differs by CPU |
| board version | `50.27` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0C75DE10669C) |  |
| board version | `50.24` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/146CB534D161) |  |
| board version | `50.34` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0CDD126C1852) |  |
| board version | `40.33` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/2D31D08D9E61) |  |
| board version | `39.43` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/1F277278F495) |  |
| board version | `40.34` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/9CF3900C24A8) |  |
| memory slots | `Bottom - Slot 1 (left)/BANK 0; Bottom - Slot 2 (right)/BANK 0` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0C75DE10669C) |  |
| memory | `Nanya Technology NT8GA64D88CX3S-JR (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0FB594E96E36) |  |
| memory | `Micron Technology 8ATF1G64HZ-3G2R1 (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/0C75DE10669C) |  |
| memory | `G Skill Intl F4-2666C19-16GRS (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/8A760A7C7500) |  |
| memory | `Micron Technology 8ATF2G64HZ-3G2F1 (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/9ACD22A738D9) |  |
| memory | `Kingston HP32D4S2S1ME-4 (4 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/45EFB5F04EDF) |  |
| memory | `SK Hynix HMA851S6CJR6N-XN (4 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/E89A74834DB6) |  |
| memory | `Kingston 9905744-111.A00G (32 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH00BNUS/020A277D9883) | no 32 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkpad-t14-gen3 |
| disk | `MTFDDAV256TDL-1AW1ZABHA HPC0032` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/1F277278F495/DEBIAN-11/5.10.0-9-AMD64/X86_64/C0A39342C3) |  |

## HP ProBook 450 G8 (`hp-probook-450-g8`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `60` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/04C7D6437DD8) |  |
| manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/04C7D6437DD8) |  |
| version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/04C7D6437DD8) |  |
| family | `103C_5336AN HP ProBook` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/04C7D6437DD8) |  |
| board_manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/04C7D6437DD8) |  |
| bios | `T70 Ver. 01.03.02 01/14/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/122666C6340C) |  |
| bios | `T70 Ver. 01.04.01 05/26/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/1FF0BC1E80CD) |  |
| bios | `T70 Ver. 01.08.02 01/14/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/426343574F2F) |  |
| bios | `T70 Ver. 01.08.20 03/12/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/5930B3B8F5A4) |  |
| bios | `T70 Ver. 01.09.01 05/05/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/1FA8FCE8B96B) |  |
| bios | `T70 Ver. 01.12.00 01/03/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/AC4C5F90EF0C) |  |
| bios | `T87 Ver. 01.08.02 01/17/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/168914A672A1) |  |
| bios | `T70 Ver. 01.02.04 10/16/2020` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/AC69B4DF84A8) |  |
| bios | `T70 Ver. 01.06.03 08/26/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/812E7034DA78) |  |
| bios | `T70 Ver. 01.06.04 10/08/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/339D7CD7C7EA) |  |
| unit | `HP ProBook 450 G8 Notebook PC / 1A896AV / 87E1 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/7F1C7174624A) |  |
| unit | `HP ProBook 450 G8 Notebook PC / 27J71EA#AKD / 87E1 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/65730B84D3C7) |  |
| unit | `HP ProBook 450 G8 Notebook PC / 1A893AV / 87E1 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/339D7CD7C7EA) |  |
| unit | `HP ProBook 450 G8 Notebook PC / 27J71EA#ABE / 87E1 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/4562E0C0F67A) |  |
| unit | `HP ProBook 450 G8 Notebook PC / 28K94UT#ABA / 87E1 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/127F26C4D075) |  |
| unit | `HP ProBook 450 G8 Notebook PC / 2X7X1EA#ABB / 87E1 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/85484292398E) |  |
| cpu generation | `Core11` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/04C7D6437DD8) |  |
| oem string | `FBYTE#3X476J6S6b7B7J7M7Q7W7m7saBapaqauawbUbhcAdUdpdqfPguk8mE.qH;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/4562E0C0F67A) |  |
| oem string | `BUILDID#20WWR3CT601#SABE#DABE;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/4562E0C0F67A) |  |
| oem string | `EDK2_1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/4562E0C0F67A) |  |
| oem string | `Buff=2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/4562E0C0F67A) |  |
| oem string | `HRDWFEATS=VTX:1;VTD:1;SGX:0;PROGKEY:1;NONHPBATDET:1;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/4562E0C0F67A) |  |
| oem string | `MEFWRec` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/4562E0C0F67A) |  |
| acpi | `'HPQOEM' 'SLIC-BPC'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/04C7D6437DD8/POP%21_OS-21.04/5.15.5-76051505-GENERIC/X86_64/1576089D35) |  |
| nic chip | `Realtek RTL8168h/8111h` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/062696808061/FEDORA-34/5.11.12-300.FC34.X86_64/X86_64/D9A33B7287) | kernel r8169 line |
| nic subsystem | `103c:87e1` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/062696808061/FEDORA-34/5.11.12-300.FC34.X86_64/X86_64/D9A33B7287) |  |
| board_location | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/04C7D6437DD8) |  |
| chassis_version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/04C7D6437DD8) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/04C7D6437DD8) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/04C7D6437DD8) |  |
| cpu_part | `To Be Filled By O.E.M.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/04C7D6437DD8) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/04C7D6437DD8) | SMBIOS upgrade code |
| cpu_voltage | `0.8 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/04C7D6437DD8) | the most common reading; it differs by CPU |
| board version | `KBC Version 33.08.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/122666C6340C) |  |
| board version | `KBC Version 33.0C.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/1FF0BC1E80CD) |  |
| board version | `KBC Version 33.19.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/426343574F2F) |  |
| board version | `KBC Version 33.1C.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/1FA8FCE8B96B) |  |
| board version | `KBC Version 33.14.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/127F26C4D075) |  |
| board version | `KBC Version 33.15.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/04C7D6437DD8) |  |
| memory slots | `Bottom-Slot 1(left)/Controller0ChannelADimm0; Bottom-Slot 2(right)/Controller1ChannelADimm0` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/04C7D6437DD8) |  |
| memory | `Kingston 9905624-059.A00G (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/657E21304C05) |  |
| memory | `Unknown - [0x7A01] D22.27562S.001 (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/1FF0BC1E80CD) |  |
| memory | `Unknown - [0x9B85] CT16G4SFRA32A.C8FE (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/B0498E403A6B) |  |
| memory | `Kingston 9905700-122.A00G (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/85484292398E) |  |
| memory | `Kingston HP32D4S2S1ME-4 (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/45EFB5F04EDF) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of hp-250-g8 |
| memory | `Kingston 9905744-111.A00G (32 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH00BNUS/020A277D9883) | no 32 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkpad-t14-gen3 |
| disk | `Samsung SSD 860 EVO M.2 500GB RVT24B6Q` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/657E21304C05/POP%21_OS-22.04/6.0.2-76060002-GENERIC/X86_64/E7DB99BE75) |  |

## HP ProBook 440 G8 (`hp-probook-440-g8`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `40` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/00CF868D7516) |  |
| manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/00CF868D7516) |  |
| version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/03D0CB789537) |  |
| family | `103C_5336AN HP ProBook` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/00CF868D7516) |  |
| board_manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/00CF868D7516) |  |
| bios | `T70 Ver. 01.03.02 01/14/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/03D0CB789537) |  |
| bios | `T70 Ver. 01.08.02 01/14/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/D5F68F218006) |  |
| bios | `T70 Ver. 01.14.00 06/27/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/50F6DE4DA732) |  |
| bios | `T87 Ver. 01.09.01 05/05/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/681D28C4A24A) |  |
| bios | `T88 Ver. 01.08.02 01/17/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/6A80E6C48EFD) |  |
| bios | `T70 Ver. 01.07.02 11/26/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/D6921D87C9E3) |  |
| bios | `T70 Ver. 01.10.00 07/14/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/999C054772A3) |  |
| bios | `T70 Ver. 01.13.01 03/30/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/374C2B2C887F) |  |
| bios | `T70 Ver. 01.06.03 08/26/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/812814174B96) |  |
| bios | `T70 Ver. 01.06.04 10/08/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/CF3ED496B47D) |  |
| unit | `HP ProBook 440 G8 Notebook PC / 2Q528AV / 87E0 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/59958873BA53) |  |
| unit | `HP ProBook 440 G8 Notebook PC / 364C3PA#ACJ / 87E0 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/03D0CB789537) |  |
| unit | `HP ProBook 440 G8 Notebook PC / 486U5PA#ABG / 87E0 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/805F36BF9450) |  |
| unit | `HP ProBook 440 G8 Notebook PC / 203D8EA#ABH / 87E0 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/554757868DC8) |  |
| unit | `HP ProBook 440 G8 Notebook PC / 203F2EA#AB9 / 87E0 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/F9CE94130923) |  |
| unit | `HP ProBook 440 G8 Notebook PC / 26M74LT#ABM / 87E0 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/37A0048EBC96) |  |
| cpu generation | `Core11` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/00CF868D7516) |  |
| oem string | `FBYTE#3X476J6S6b7B7J7M7Q7W7m7saBapaqauawbUbhcAdUdpdqfPguk8mEn7nV.Ge;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/681D28C4A24A) |  |
| oem string | `BUILDID#20WWR3FT601#SACB#DACB;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/681D28C4A24A) |  |
| oem string | `EDK2_1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/681D28C4A24A) |  |
| oem string | `Buff=2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/681D28C4A24A) |  |
| oem string | `HRDWFEATS=VTX:1;VTD:1;SGX:0;PROGKEY:1;NONHPBATDET:1;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/681D28C4A24A) |  |
| oem string | `MEFWRec` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/681D28C4A24A) |  |
| acpi | `'HPQOEM' 'SLIC-BPC'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/03D0CB789537/UBUNTU-20.04/5.11.0-27-GENERIC/X86_64/D866EDFE76) |  |
| nic chip | `Realtek RTL8168h/8111h` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/03D0CB789537/UBUNTU-20.04/5.11.0-27-GENERIC/X86_64/D866EDFE76) | kernel r8169 line |
| nic subsystem | `103c:87e0` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/03D0CB789537/UBUNTU-20.04/5.11.0-27-GENERIC/X86_64/D866EDFE76) |  |
| board_location | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/00CF868D7516) |  |
| chassis_version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/00CF868D7516) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/00CF868D7516) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/00CF868D7516) |  |
| cpu_part | `To Be Filled By O.E.M.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/00CF868D7516) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/00CF868D7516) | SMBIOS upgrade code |
| cpu_voltage | `0.7 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/03D0CB789537) | the most common reading; it differs by CPU |
| board version | `KBC Version 33.24.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/50F6DE4DA732) |  |
| board version | `KBC Version 33.08.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/03D0CB789537) |  |
| board version | `KBC Version 54.07.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/6A80E6C48EFD) |  |
| board version | `KBC Version 54.10.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/5FC995FB8B8A) |  |
| board version | `KBC Version 33.14.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/6F9DA93DCBAE) |  |
| board version | `KBC Version 33.19.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/D5F68F218006) |  |
| memory slots | `Bottom-Slot 1(left)/Controller0ChannelADimm0; Bottom-Slot 2(right)/Controller1ChannelADimm0` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/00CF868D7516) |  |
| memory | `Unknown - [0x7A01] D22.2756BS.001 (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/981783CA5E16) |  |
| memory | `Unknown - [0x9B85] CT8G4SFRA32A.C8FP (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/374C2B2C887F) |  |
| memory | `Unknown - [0x9B85] CT16G4SFRA32A.C8FF (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/D914BFDB2BB0) |  |
| memory | `Unknown - [0x9B85] CT16G4SFD832A.C16FJ (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/39DAE73B2DFC) |  |
| memory | `Kingston HP32D4S2S1ME-4 (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/45EFB5F04EDF) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of hp-250-g8 |
| memory | `Unknown - [0x9B85] CT32G4SFD832A.C16FF (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20440%20G8%20Notebook%20PC/50F6DE4DA732) |  |
| disk | `Samsung SSD 860 EVO M.2 500GB RVT24B6Q` | B | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/657E21304C05/POP%21_OS-22.04/6.0.2-76060002-GENERIC/X86_64/E7DB99BE75) | no SATA disk in its reports; ProBook 450 G8 (same chassis family) |

## HP ProBook 455 G8 (`hp-probook-455-g8`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `20` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) |  |
| manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) |  |
| version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) |  |
| family | `103C_5336AN HP ProBook` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) |  |
| board_manufacturer | `HP` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) |  |
| bios | `T78 Ver. 01.11.00 10/14/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/495BFD3F00D2) |  |
| bios | `T78 Ver. 01.06.00 07/26/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/40D0537D4DB2) |  |
| bios | `T78 Ver. 01.07.00 10/08/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/2FC17D1011A6) |  |
| bios | `T78 Ver. 01.08.00 12/24/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) |  |
| bios | `T78 Ver. 01.08.20 03/14/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/38294B8797C8) |  |
| bios | `T78 Ver. 01.09.10 05/19/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/46769EF55033) |  |
| bios | `T78 Ver. 01.17.01 05/03/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/A291DCFFFD91) |  |
| bios | `T78 Ver. 01.12.00 12/30/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/F636AF200A74) |  |
| bios | `T78 Ver. 01.13.01 03/31/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/8EDCE850BBEA) |  |
| unit | `HP ProBook 455 G8 Notebook PC / 3A5M6EA#ACB / 8864 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) |  |
| unit | `HP ProBook 455 G8 Notebook PC / 3Z6P5ES#ABD / 8864 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/40D0537D4DB2) |  |
| unit | `HP ProBook 455 G8 Notebook PC / 3Z6P9ES#ABD / 8864 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/495BFD3F00D2) |  |
| unit | `HP ProBook 455 G8 Notebook PC / 59S11EA#ABZ / 8864 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/8355EA7D7299) |  |
| unit | `HP ProBook 455 G8 Notebook PC / 1Y9H2AV / 8864 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/AA3969C3E712) |  |
| unit | `HP ProBook 455 G8 Notebook PC / 32N90EA#ABZ / 8864 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/6286C93AB7D3) |  |
| cpu generation | `Zen3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) |  |
| oem string | `FBYTE#3X476J6S6b7B7J7M7Q7W7m7saBapaqauawbUbhcAdUdpdqfPguk8mEn7nW.5f;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/40D0537D4DB2) |  |
| oem string | `BUILDID#21WWPDCT601#SABD#DABD;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/40D0537D4DB2) |  |
| oem string | `EDK2_1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/40D0537D4DB2) |  |
| oem string | `Buff=2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/40D0537D4DB2) |  |
| oem string | `HRDWFEATS=;PROGKEY:1;NONHPBATDET:1;` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/40D0537D4DB2) |  |
| acpi | `'HPQOEM' 'SLIC-BPC'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6/FEDORA-36/5.17.0-0.RC7.116.FC36.X86_64/X86_64/5BFF5642BA) |  |
| nic chip | `Realtek RTL8168h/8111h` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6/FEDORA-36/5.17.0-0.RC7.116.FC36.X86_64/X86_64/5BFF5642BA) | kernel r8169 line |
| nic subsystem | `103c:8864` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/0027F27DB82F/UBUNTU-22.04/5.15.0-25-GENERIC/X86_64/96C0510005) |  |
| board_location | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) |  |
| chassis_version | ` ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) |  |
| cpu_socket | `FP6` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) |  |
| cpu_part | `Unknown` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) |  |
| cpu_upgrade | `0x06` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) | SMBIOS upgrade code |
| cpu_voltage | `1.2 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) | the most common reading; it differs by CPU |
| board version | `KBC Version 41.23.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) |  |
| board version | `KBC Version 41.28.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/495BFD3F00D2) |  |
| board version | `KBC Version 41.1B.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/40D0537D4DB2) |  |
| board version | `KBC Version 41.1E.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/2FC17D1011A6) |  |
| board version | `KBC Version 41.25.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/46769EF55033) |  |
| board version | `KBC Version 41.31.00` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/A291DCFFFD91) |  |
| memory slots | `Bottom-Slot 1(left)/ChannelA0; Bottom-Slot 2(right)/ChannelB0` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) |  |
| memory | `Kingston 9905700-072.A01G (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/18D11FD497F6) |  |
| memory | `Unknown - [0x9B85] CT16G4SFRA32A.C8FF (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/ProBook/ProBook%20455%20G8%20Notebook%20PC/A291DCFFFD91) |  |
| memory | `Samsung M471A1G44BB0-CWE (8 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) | no 8 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkpad-t14-gen3 |
| memory | `Kingston 9905744-111.A00G (32 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH00BNUS/020A277D9883) | no 32 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkpad-t14-gen3 |
| memory | `Kingston HP32D4S2S1ME-4 (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/45EFB5F04EDF) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of hp-250-g8 |
| disk | `Samsung SSD 860 EVO M.2 500GB RVT24B6Q` | B | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/657E21304C05/POP%21_OS-22.04/6.0.2-76060002-GENERIC/X86_64/E7DB99BE75) | no SATA disk in its reports; ProBook 450 G8 (same chassis family) |

## Lenovo ThinkPad T14 Gen 3 (AMD) (`lenovo-t14-gen3-amd`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `23` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) |  |
| manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) |  |
| version | `ThinkPad T14 Gen 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) |  |
| family | `ThinkPad T14 Gen 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) |  |
| board_manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) |  |
| bios | `R23ET70W (1.40 ) 08/08/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) |  |
| bios | `R23ET60W (1.30 ) 09/14/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF001PHH/1F8EAD10FEED) |  |
| bios | `R23ET62W (1.32 ) 11/11/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF003WUS/2111809AA2AE) |  |
| bios | `R23ET65W (1.35 ) 03/21/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF004PGE/696E48381F84) |  |
| bios | `R23ET77W (1.53 ) 05/29/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CFS0FU00/284DFCB31095) |  |
| bios | `R23ET80W (1.56 ) 10/28/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF001PPH/AF0AA9DAEAC1) |  |
| bios | `R23ET53W (1.23 ) 07/14/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF002TGE/9ECAE2EAA4B2) |  |
| bios | `R23ET59W (1.29 ) 09/01/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CFCTO1WW/64B17C2468A8) |  |
| bios | `R23ET71W (1.47 ) 09/14/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF002UMZ/0B5AB7D98010) |  |
| bios | `R23ET78W (1.54 ) 08/05/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF002YMH/9F55158530D7) |  |
| unit | `21CFCTO1WW / LENOVO_MT_21CF_BU_Think_FM_ThinkPad T14 Gen 3 / 21CFCTO1WW / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CFCTO1WW/64B17C2468A8) |  |
| unit | `21CGS0LG00 / LENOVO_MT_21CG_BU_Think_FM_ThinkPad T14 Gen 3 / 21CGS0LG00 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CGS0LG00/37AF237D2062) |  |
| unit | `21CF000CUS / LENOVO_MT_21CF_BU_Think_FM_ThinkPad T14 Gen 3 / 21CF000CUS / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) |  |
| unit | `21CF001PHH / LENOVO_MT_21CF_BU_Think_FM_ThinkPad T14 Gen 3 / 21CF001PHH / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF001PHH/1F8EAD10FEED) |  |
| unit | `21CF001PPH / LENOVO_MT_21CF_BU_Think_FM_ThinkPad T14 Gen 3 / 21CF001PPH / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF001PPH/AF0AA9DAEAC1) |  |
| unit | `21CF002GMX / LENOVO_MT_21CF_BU_Think_FM_ThinkPad T14 Gen 3 / 21CF002GMX / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF002GMX/0E1CFF24E847) |  |
| cpu generation | `Zen3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) |  |
| acpi | `'LENOVO' 'TP-R23  '` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF001PHH/1F8EAD10FEED/ARCH-ROLLING/6.2.7-ARCH1-1/X86_64/0880214933) |  |
| nic chip | `Realtek RTL8168ep/8111ep` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF002TGE/9ECAE2EAA4B2/UBUNTU-22.04/5.19.5-051905-GENERIC/X86_64/8BF0000C61) | kernel r8169 line |
| nic subsystem | `17aa:50b6` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF002TGE/9ECAE2EAA4B2/UBUNTU-22.04/5.19.5-051905-GENERIC/X86_64/8BF0000C61) |  |
| board_location | `Not Available` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) |  |
| chassis_version | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) |  |
| cpu_socket | `FP7` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) |  |
| cpu_part | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) |  |
| cpu_upgrade | `0x06` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) | SMBIOS upgrade code |
| cpu_voltage | `1.2 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) | the most common reading; it differs by CPU |
| board version | `ThinkPad` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF001PHH/1F8EAD10FEED) |  |
| board version | `SDK0T76538 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) |  |
| board version | `SDK0T76530 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF003TUS/73C9FF1BD839) |  |
| board version | `SDK0K17763 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF002UMZ/0B5AB7D98010) |  |
| board version | `SDK0T76461 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CFCTO1WW/AF50416A84FF) |  |
| memory slots | `DIMM 0/P0 CHANNEL A; DIMM 0/P0 CHANNEL B; DIMM 0/P0 CHANNEL C; DIMM 0/P0 CHANNEL D` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) |  |
| memory | `Micron Technology MT62F1G32D4DR-031 WT (4 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF000CUS/0151DA67ED76) |  |
| memory | `Micron Technology MT62F2G32D8DR-031 WT (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF004PGE/696E48381F84) |  |
| memory | `Hynix H9JCNNNCP3MLYR-N6E (4 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CF002GMX/0E1CFF24E847) |  |
| memory | `Hynix H9JCNNNFA5MLYR-N6E (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021CFS08M00/8805D2B2F753) |  |
| disk | `MTFDDAV256TBN-1AR15ABHA HPC0T12` | C | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205520/1DC6794B86BA/UBUNTU-20.04/5.11.0-46-GENERIC/X86_64/95721C3566) | no SATA disk in any of the ThinkPad Dmesg/HWInfo reports; the PSREF of the T14 Gen 2 AMD (https://psref.lenovo.com/syspool/Sys/PDF/ThinkPad/ThinkPad_T14_Gen_2_AMD/ThinkPad_T14_Gen_2_AMD_Spec.html) lists one PCIe NVMe M.2 slot only: a SATA disk is a stand-in from a Latitude 5520 (decision needed) |

## Lenovo ThinkPad T14 Gen 3 (Intel) (`lenovo-thinkpad-t14-gen3`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `52` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) |  |
| manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) |  |
| version | `ThinkPad T14 Gen 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) |  |
| family | `ThinkPad T14 Gen 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) |  |
| board_manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) |  |
| bios | `N3MET16W (1.15 ) 06/25/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH00C3AU/C548E97522E8) |  |
| bios | `N3MET18W (1.17 ) 10/24/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH00BNUS/020A277D9883) |  |
| bios | `N3MET11W (1.10 ) 12/07/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0082PB/E8B4DDEF6312) |  |
| bios | `N3MET12W (1.11 ) 02/09/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AHCTO1WW/3D5B408DCD5C) |  |
| bios | `N3MET10W (1.07 ) 11/07/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0083RT/1903B1CD3E08) |  |
| bios | `N3BET28W (1.06 ) 03/01/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) |  |
| bios | `N3BET47W (1.25 ) 07/11/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AHCTO1WW/B03D7C467444) |  |
| bios | `N3BET52W (1.30 ) 12/07/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH008LRI/20E450F73DE1) |  |
| bios | `N3BET53W (1.31 ) 02/09/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AHS02B00/C58099376D88) |  |
| bios | `N3BET59W (1.37 ) 10/24/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH1SIT01/643CFB64FDD5) |  |
| unit | `21AHCTO1WW / LENOVO_MT_21AH_BU_Think_FM_ThinkPad T14 Gen 3 / 21AHCTO1WW / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AHCTO1WW/24CCFE3AAA29) |  |
| unit | `21AH00HXGE / LENOVO_MT_21AH_BU_Think_FM_ThinkPad T14 Gen 3 / 21AH00HXGE / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH00HXGE/6B5BE567D17B) |  |
| unit | `21AH00BQUS / LENOVO_MT_21AH_BU_Think_FM_ThinkPad T14 Gen 3 / 21AH00BQUS / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH00BQUS/6633D4943D0B) |  |
| unit | `21AH0019US / LENOVO_MT_21AH_BU_Think_FM_ThinkPad T14 Gen 3 / 21AH0019US / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) |  |
| unit | `21AH0082PB / LENOVO_MT_21AH_BU_Think_FM_ThinkPad T14 Gen 3 / 21AH0082PB / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0082PB/E8B4DDEF6312) |  |
| unit | `21AH0083RT / LENOVO_MT_21AH_BU_Think_FM_ThinkPad T14 Gen 3 / 21AH0083RT / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0083RT/1903B1CD3E08) |  |
| cpu generation | `Core12` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) |  |
| acpi | `'LENOVO' 'TP-N3M  '` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0082PB/E8B4DDEF6312/EURO-8.7/4.18.0-425.3.1.EL8.X86_64/X86_64/0A98E4CAE4) |  |
| nic chip | `Intel Ethernet Connection (16) I219-V` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94/DEBIAN-11/5.10.0-13-AMD64/X86_64/EAAD038FDE) |  |
| nic subsystem | `17aa:22e8` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94/DEBIAN-11/5.10.0-13-AMD64/X86_64/EAAD038FDE) |  |
| board_location | `Not Available` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) |  |
| chassis_version | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) |  |
| cpu_part | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) | SMBIOS upgrade code |
| cpu_voltage | `1.1 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) | the most common reading; it differs by CPU |
| board version | `SDK0T76530 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) |  |
| board version | `SDK0T76538 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH00BNUS/020A277D9883) |  |
| board version | `Not Defined` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH1SIT01/643CFB64FDD5) |  |
| board version | `SDK0K17763 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AJS1AW01/72D46F3A461B) |  |
| board version | `SDK0T76479 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AHA015CD/3A1D9D23C611) |  |
| memory slots | `Controller0-ChannelA/BANK 0; Controller0-ChannelB-DIMM0/BANK 1; Controller0-ChannelC-DIMM0/BANK 2; Controller0-ChannelD-DIMM0/BANK 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) |  |
| memory | `SK Hynix HMAB2GS6CMR6N-XN (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0082PB/E8B4DDEF6312) |  |
| memory | `Samsung M471A2G43BB2-CWE (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH008LRI/20E450F73DE1) |  |
| memory | `Samsung M471A1G44BB0-CWE (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) |  |
| memory | `SK Hynix HMAA1GS6CJR6N-XN (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH0019US/9625EE3D8D94) |  |
| memory | `Kingston 9905744-111.A00G (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH00BNUS/020A277D9883) |  |
| memory | `Foxline FL3200D4S22-32G (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH00BRUS/F61010F3DC8E) |  |
| memory | `Kingston HP32D4S2S1ME-4 (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/45EFB5F04EDF) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of hp-250-g8 |
| disk | `MTFDDAV256TBN-1AR15ABHA HPC0T12` | C | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205520/1DC6794B86BA/UBUNTU-20.04/5.11.0-46-GENERIC/X86_64/95721C3566) | no SATA disk in any of the ThinkPad Dmesg/HWInfo reports; the PSREF of the T14 Gen 2 AMD (https://psref.lenovo.com/syspool/Sys/PDF/ThinkPad/ThinkPad_T14_Gen_2_AMD/ThinkPad_T14_Gen_2_AMD_Spec.html) lists one PCIe NVMe M.2 slot only: a SATA disk is a stand-in from a Latitude 5520 (decision needed) |

## Lenovo ThinkPad E14 Gen 4 (Intel) (`lenovo-thinkpad-e14-gen4`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `21` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) |  |
| manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) |  |
| version | `ThinkPad E14 Gen 4` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) |  |
| family | `ThinkPad E14 Gen 4` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) |  |
| board_manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) |  |
| bios | `R1SET45W(1.16) 11/11/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E30061CK/3604BE223EA7) |  |
| bios | `R1SET38W(1.09) 05/25/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) |  |
| bios | `R1SET47W(1.18) 02/25/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E300DQVA/16C538529377) |  |
| bios | `R1SET37W(1.08) 05/11/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3005DGE/5A2C70D347A2) |  |
| bios | `R1SET44W(1.15) 10/11/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3CTO1WW/C2D511629375) |  |
| bios | `R1SET46W(1.17) 01/12/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3005DGE/6506293D7139) |  |
| bios | `R1SET54W(1.25) 10/31/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3CTO1WW/6E085204D72A) |  |
| bios | `R1SET42W(1.13) 08/12/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E4CTO1WW/E689887A539D) |  |
| bios | `R1SET49W(1.20) 04/13/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3008RUS/AE56FE0730BC) |  |
| bios | `R1SET53W(1.24) 07/20/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E30087TX/415E8CC4B431) |  |
| unit | `21E3CTO1WW / LENOVO_MT_21E3_BU_Think_FM_ThinkPad E14 Gen 4 / 21E3CTO1WW / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3CTO1WW/6E085204D72A) |  |
| unit | `21E3005DGE / LENOVO_MT_21E3_BU_Think_FM_ThinkPad E14 Gen 4 / 21E3005DGE / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3005DGE/5A2C70D347A2) |  |
| unit | `21E4CTO1WW / LENOVO_MT_21E4_BU_Think_FM_ThinkPad E14 Gen 4 / 21E4CTO1WW / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E4CTO1WW/E13FB0FD8DCF) |  |
| unit | `21E4S2JB00 / LENOVO_MT_21E4_BU_Think_FM_ThinkPad E14 Gen 4 / 21E4S2JB00 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E4S2JB00/75F53706B700) |  |
| unit | `21E3000LAU / LENOVO_MT_21E3_BU_Think_FM_ThinkPad E14 Gen 4 / 21E3000LAU / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) |  |
| unit | `21E30061CK / LENOVO_MT_21E3_BU_Think_FM_ThinkPad E14 Gen 4 / 21E30061CK / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E30061CK/3604BE223EA7) |  |
| cpu generation | `Core12` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) |  |
| acpi | `'LENOVO' 'TP-R1S  '` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3005DGE/5A2C70D347A2/DEBIAN-TESTING/5.18.0-2-AMD64/X86_64/0121EFA569) |  |
| nic chip | `Intel Ethernet Connection (16) I219-V` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3005DGE/5A2C70D347A2/DEBIAN-TESTING/5.18.0-2-AMD64/X86_64/0121EFA569) |  |
| nic subsystem | `17aa:50a0` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3005DGE/5A2C70D347A2/DEBIAN-TESTING/5.18.0-2-AMD64/X86_64/0121EFA569) |  |
| board_location | `Not Available` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) |  |
| chassis_version | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) |  |
| cpu_part | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) | SMBIOS upgrade code |
| cpu_voltage | `1.1 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) | the most common reading; it differs by CPU |
| board version | `Not Defined` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E30087TX/415E8CC4B431) |  |
| board version | `SDK0T76530 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3005DGE/5A2C70D347A2) |  |
| board version | `SDK0T76485 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3S05B00/E1F414934528) |  |
| board version | `SDK0T76538 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) |  |
| memory slots | `Controller0-ChannelA-DIMM0/BANK 0; Controller0-ChannelB-DIMM0/BANK 1; Controller0-ChannelC-DIMM0/BANK 2; Controller0-ChannelD-DIMM0/BANK 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) |  |
| memory | `Samsung M471A1G44BB0-CWE (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) |  |
| memory | `SK Hynix HMAA1GS6CJR6N-XN (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3000LAU/58F4508E0105) |  |
| memory | `Crucial Technology CT32G4SFD832A.M16FF (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E300ESPB/E69E18C34452) |  |
| memory | `Kingston 9905744-111.A00G (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E30066SP/E84030EC0D8E) |  |
| memory | `Kingston KF3200C20S4/16G (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3CTO1WW/791D1E9C4104) |  |
| memory | `Samsung M471A2G43BB2-CWE (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E14%20Gen%204%2021E3CTO1WW/C2D511629375) |  |
| memory | `Kingston HP32D4S2S1ME-4 (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/45EFB5F04EDF) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of hp-250-g8 |
| disk | `MTFDDAV256TBN-1AR15ABHA HPC0T12` | C | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205520/1DC6794B86BA/UBUNTU-20.04/5.11.0-46-GENERIC/X86_64/95721C3566) | no SATA disk in any of the ThinkPad Dmesg/HWInfo reports; the PSREF of the T14 Gen 2 AMD (https://psref.lenovo.com/syspool/Sys/PDF/ThinkPad/ThinkPad_T14_Gen_2_AMD/ThinkPad_T14_Gen_2_AMD_Spec.html) lists one PCIe NVMe M.2 slot only: a SATA disk is a stand-in from a Latitude 5520 (decision needed) |

## Lenovo ThinkPad L14 Gen 2 (Intel) (`lenovo-thinkpad-l14-gen2`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `16` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) |  |
| manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) |  |
| version | `ThinkPad L14 Gen 2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) |  |
| family | `ThinkPad L14 Gen 2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) |  |
| board_manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) |  |
| bios | `R1JET53W (1.53 ) 11/23/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1004CMX/100EF806B4BA) |  |
| bios | `R1JET46W (1.46 ) 06/21/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1004CMX/067E5C8E9747) |  |
| bios | `R1JET47W (1.47 ) 06/30/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) |  |
| bios | `R1JET62W (1.62 ) 03/22/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X10044EQ/10906F1220F9) |  |
| bios | `R1JET63W (1.63 ) 06/27/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1S12N00/A6DEF9DACA36) |  |
| bios | `R1JET17W (1.06 ) 12/09/2020` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X2S06Y00/5CBD9662220D) |  |
| bios | `R1JET43W (1.43 ) 05/04/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X2A00KCD/8956482774FB) |  |
| bios | `R1JET68W (1.68 ) 01/30/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X2006PBO/56B8743C99A4) |  |
| unit | `20X1004CMX / LENOVO_MT_20X1_BU_Think_FM_ThinkPad L14 Gen 2 / 20X1004CMX / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1004CMX/067E5C8E9747) |  |
| unit | `20X1003WGE / LENOVO_MT_20X1_BU_Think_FM_ThinkPad L14 Gen 2 / 20X1003WGE / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) |  |
| unit | `20X10044EQ / LENOVO_MT_20X1_BU_Think_FM_ThinkPad L14 Gen 2 / 20X10044EQ / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X10044EQ/10906F1220F9) |  |
| unit | `20X1006BFR / LENOVO_MT_20X1_BU_Think_FM_ThinkPad L14 Gen 2 / 20X1006BFR / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1006BFR/09963BD05BCE) |  |
| unit | `20X1S07900 / LENOVO_MT_20X1_BU_Think_FM_ThinkPad L14 Gen 2 / 20X1S07900 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1S07900/9CE2CF269013) |  |
| unit | `20X1S12N00 / LENOVO_MT_20X1_BU_Think_FM_ThinkPad L14 Gen 2 / 20X1S12N00 / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1S12N00/A6DEF9DACA36) |  |
| cpu generation | `Core11` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) |  |
| acpi | `'LENOVO' 'TP-R1J  '` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1000VMZ/A2C7DDE9F011/UBUNTU-18.04/5.4.0-87-GENERIC/X86_64/62872F38DE) |  |
| nic chip | `Intel Ethernet Connection (13) I219-V` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003GUS/54FFCCFB88AB/POP%21_OS-21.04/5.13.0-7620-GENERIC/X86_64/3861D9BAA5) |  |
| nic subsystem | `17aa:508f` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003GUS/54FFCCFB88AB/POP%21_OS-21.04/5.13.0-7620-GENERIC/X86_64/3861D9BAA5) |  |
| board_location | `Not Available` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) |  |
| chassis_version | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) |  |
| cpu_socket | `U3E1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) |  |
| cpu_part | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) |  |
| cpu_upgrade | `0x01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) | SMBIOS upgrade code |
| cpu_voltage | `0.7 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) | the most common reading; it differs by CPU |
| board version | `SDK0J40697 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) |  |
| board version | `Not Defined` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X2006PBO/56B8743C99A4) |  |
| board version | `SDK0K09938 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X2A00KCD/8956482774FB) |  |
| board version | `SDK0T76530 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1S12N00/A6DEF9DACA36) |  |
| memory slots | `Controller0-ChannelA-DIMM0/BANK 0; Controller1-ChannelA-DIMM0/BANK 0` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) |  |
| memory | `Samsung M471A2G43AB2-CWE (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X2S06Y00/5CBD9662220D) |  |
| memory | `0x0B2C HKED4162CAB1G4HB1 (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X2006PBO/56B8743C99A4) |  |
| memory | `Samsung M471A1G44AB0-CWE (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1003WGE/07C04D306272) |  |
| memory | `Crucial Technology CT8G4SFRA32A.C8FE (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202%2020X1S07900/9CE2CF269013) |  |
| memory | `Kingston HP32D4S2S1ME-4 (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/45EFB5F04EDF) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of hp-250-g8 |
| memory | `Kingston 9905744-111.A00G (32 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%203%2021AH00BNUS/020A277D9883) | no 32 GiB module with a part number in the reports of this model; the same maker's part in the reports of lenovo-thinkpad-t14-gen3 |
| disk | `MTFDDAV256TBN-1AR15ABHA HPC0T12` | C | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205520/1DC6794B86BA/UBUNTU-20.04/5.11.0-46-GENERIC/X86_64/95721C3566) | no SATA disk in any of the ThinkPad Dmesg/HWInfo reports; the PSREF of the T14 Gen 2 AMD (https://psref.lenovo.com/syspool/Sys/PDF/ThinkPad/ThinkPad_T14_Gen_2_AMD/ThinkPad_T14_Gen_2_AMD_Spec.html) lists one PCIe NVMe M.2 slot only: a SATA disk is a stand-in from a Latitude 5520 (decision needed) |

## Lenovo ThinkPad E15 Gen 3 (AMD) (`lenovo-thinkpad-e15-gen3-amd`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `77` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) |  |
| manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) |  |
| version | `ThinkPad E15 Gen 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) |  |
| family | `ThinkPad E15 Gen 3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) |  |
| board_manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) |  |
| bios | `R1OET31W (1.10 ) 11/29/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003VGE/1A857580260A) |  |
| bios | `R1OET28W (1.07 ) 07/15/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003XIX/19DD06322F24) |  |
| bios | `R1OET27W (1.06 ) 05/17/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003DUS/0DE78EED36DC) |  |
| bios | `R1OET35W (1.14 ) 11/30/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003VGE/04120C1F1334) |  |
| bios | `R1OET30W (1.09 ) 11/05/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003VCK/E2430F7BF6CA) |  |
| bios | `R1OET32W (1.11 ) 02/11/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003JUS/D73470E2E724) |  |
| bios | `R1OET33W (1.12 ) 05/07/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003VGE/1EBAEA140F3E) |  |
| bios | `R1OET34W (1.13 ) 07/09/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003VRT/EE0D966A46F2) |  |
| bios | `R1OET26W (1.05 ) 04/28/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003UGE/B8CD886D750F) |  |
| bios | `R1OET36W (1.15 ) 06/07/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG004BMX/E25B41D4A596) |  |
| unit | `20YG003VGE / LENOVO_MT_20YG_BU_Think_FM_ThinkPad E15 Gen 3 / 20YG003VGE / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003VGE/04120C1F1334) |  |
| unit | `20YG0041MX / LENOVO_MT_20YG_BU_Think_FM_ThinkPad E15 Gen 3 / 20YG0041MX / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG0041MX/769524EB0009) |  |
| unit | `20YG001NJP / LENOVO_MT_20YG_BU_Think_FM_ThinkPad E15 Gen 3 / 20YG001NJP / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) |  |
| unit | `20YG003DUS / LENOVO_MT_20YG_BU_Think_FM_ThinkPad E15 Gen 3 / 20YG003DUS / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003DUS/0DE78EED36DC) |  |
| unit | `20YG003JUS / LENOVO_MT_20YG_BU_Think_FM_ThinkPad E15 Gen 3 / 20YG003JUS / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003JUS/D73470E2E724) |  |
| unit | `20YG003UGE / LENOVO_MT_20YG_BU_Think_FM_ThinkPad E15 Gen 3 / 20YG003UGE / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003UGE/B8CD886D750F) |  |
| cpu generation | `Zen2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) |  |
| acpi | `'LENOVO' 'TP-R1O  '` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003DUS/0DE78EED36DC/UBUNTU-20.04/5.13.0-25-GENERIC/X86_64/FCD259F1F2) |  |
| nic chip | `Realtek RTL8168gu/8111gu` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003DUS/0DE78EED36DC/UBUNTU-20.04/5.13.0-25-GENERIC/X86_64/FCD259F1F2) | kernel r8169 line |
| nic subsystem | `17aa:5097` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003DUS/0DE78EED36DC/UBUNTU-20.04/5.13.0-25-GENERIC/X86_64/FCD259F1F2) |  |
| board_location | `Not Available` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) |  |
| chassis_version | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) |  |
| cpu_socket | `FP6` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) |  |
| cpu_part | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) |  |
| cpu_upgrade | `0x06` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) | SMBIOS upgrade code |
| cpu_voltage | `1.2 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) | the most common reading; it differs by CPU |
| board version | `Not Defined` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) |  |
| memory slots | `DIMM 0/P0 CHANNEL A; DIMM 0/P0 CHANNEL B` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) |  |
| memory | `Hynix HMAA1GS6CJR6N-XN (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG001NJP/F275C0730825) |  |
| memory | `Micron Technology 4ATF1G64HZ-3G2E1 (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003UGE/B8CD886D750F) |  |
| memory | `Hynix HMAA2GS6CJR8N-XN (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003YMH/074CDDD5387F) |  |
| memory | `Kingston 9905700-095.A00G (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003VRT/EE0D966A46F2) |  |
| memory | `Unknown CT32G4SFD832A.C16FF (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG003XGE/20FB5F309405) |  |
| memory | `Unknown CT32G4SFD832A.C16FF (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20E15%20Gen%203%2020YG006BMX/440B37DEE09E) |  |
| memory | `Kingston HP32D4S2S1ME-4 (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/45EFB5F04EDF) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of hp-250-g8 |
| disk | `MTFDDAV256TBN-1AR15ABHA HPC0T12` | C | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205520/1DC6794B86BA/UBUNTU-20.04/5.11.0-46-GENERIC/X86_64/95721C3566) | no SATA disk in any of the ThinkPad Dmesg/HWInfo reports; the PSREF of the T14 Gen 2 AMD (https://psref.lenovo.com/syspool/Sys/PDF/ThinkPad/ThinkPad_T14_Gen_2_AMD/ThinkPad_T14_Gen_2_AMD_Spec.html) lists one PCIe NVMe M.2 slot only: a SATA disk is a stand-in from a Latitude 5520 (decision needed) |

## Lenovo ThinkPad L14 Gen 2 (AMD) (`lenovo-thinkpad-l14-gen2-amd`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `16` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) |  |
| manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) |  |
| version | `ThinkPad L14 Gen 2a` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) |  |
| family | `ThinkPad L14 Gen 2a` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) |  |
| board_manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) |  |
| bios | `R1KET45W (1.30 ) 11/17/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/B89503C66E9B) |  |
| bios | `R1KET36W (1.21 ) 11/25/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X5003MMX/026C1B7CE1B4) |  |
| bios | `R1KET30W (1.15 ) 06/03/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) |  |
| bios | `R1KET42W (1.27 ) 03/01/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50049GE/1A699E41092C) |  |
| bios | `R1KET26W (1.11 ) 04/21/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50049GE/08B34FA434DF) |  |
| bios | `R1KET40W (1.25 ) 10/10/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X5003KFR/7E217C887D72) |  |
| bios | `R1KET40W (1.25 ) 11/10/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X6S15A00/B12E4B54E373) |  |
| bios | `R1KET43W (1.28 ) 06/20/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50038MH/CD00A2FADAA4) |  |
| unit | `20X50049GE / LENOVO_MT_20X5_BU_Think_FM_ThinkPad L14 Gen 2a / 20X50049GE / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50049GE/08B34FA434DF) |  |
| unit | `20X50009GE / LENOVO_MT_20X5_BU_Think_FM_ThinkPad L14 Gen 2a / 20X50009GE / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) |  |
| unit | `20X50038MH / LENOVO_MT_20X5_BU_Think_FM_ThinkPad L14 Gen 2a / 20X50038MH / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50038MH/CD00A2FADAA4) |  |
| unit | `20X5003KFR / LENOVO_MT_20X5_BU_Think_FM_ThinkPad L14 Gen 2a / 20X5003KFR / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X5003KFR/7E217C887D72) |  |
| unit | `20X5003MMX / LENOVO_MT_20X5_BU_Think_FM_ThinkPad L14 Gen 2a / 20X5003MMX / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X5003MMX/026C1B7CE1B4) |  |
| unit | `20X50051HH / LENOVO_MT_20X5_BU_Think_FM_ThinkPad L14 Gen 2a / 20X50051HH / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50051HH/D2A387C36B6F) |  |
| cpu generation | `Zen3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) |  |
| acpi | `'LENOVO' 'TP-R1K  '` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389/ARCH/5.12.13-ARCH1-2/X86_64/BDBA392A3F) |  |
| nic chip | `Realtek RTL8168ep/8111ep` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X5003KFR/7E217C887D72/XUBUNTU-22.04/6.1.6-060106-GENERIC/X86_64/251A926C19) | kernel r8169 line |
| nic subsystem | `17aa:5091` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X5003KFR/7E217C887D72/XUBUNTU-22.04/6.1.6-060106-GENERIC/X86_64/251A926C19) |  |
| board_location | `Not Available` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) |  |
| chassis_version | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) |  |
| cpu_socket | `FP6` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) |  |
| cpu_part | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) |  |
| cpu_upgrade | `0x06` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) | SMBIOS upgrade code |
| cpu_voltage | `1.2 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) | the most common reading; it differs by CPU |
| board version | `Not Defined` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) |  |
| memory slots | `DIMM 0/P0 CHANNEL A; DIMM 0/P0 CHANNEL B` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) |  |
| memory | `Hynix HMAA2GS6CJR8N-XN (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50049GE/08B34FA434DF) |  |
| memory | `Ramaxel Technology RMSA3320ME88HBF-3200 (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/1DFDA90A8389) |  |
| memory | `Kingston 9905744-062.A00G (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50049GE/A175E82A68C1) |  |
| memory | `Kingston KHX3200C20S4/32GX (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X50009GE/B89503C66E9B) |  |
| memory | `Hynix HMAA1GS6CJR6N-XN (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X6S15A00/B12E4B54E373) |  |
| memory | `Samsung M471A1G44AB0-CWE (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20L14%20Gen%202a%2020X6S15C00/DFE10C8659DC) |  |
| memory | `Kingston HP32D4S2S1ME-4 (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/45EFB5F04EDF) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of hp-250-g8 |
| disk | `MTFDDAV256TBN-1AR15ABHA HPC0T12` | C | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205520/1DC6794B86BA/UBUNTU-20.04/5.11.0-46-GENERIC/X86_64/95721C3566) | no SATA disk in any of the ThinkPad Dmesg/HWInfo reports; the PSREF of the T14 Gen 2 AMD (https://psref.lenovo.com/syspool/Sys/PDF/ThinkPad/ThinkPad_T14_Gen_2_AMD/ThinkPad_T14_Gen_2_AMD_Spec.html) lists one PCIe NVMe M.2 slot only: a SATA disk is a stand-in from a Latitude 5520 (decision needed) |

## Lenovo ThinkPad T14 Gen 2 (AMD) (`lenovo-thinkpad-t14-gen2-amd`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `33` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YHV/66597B3DC7B7) |  |
| manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YHV/66597B3DC7B7) |  |
| version | `ThinkPad T14 Gen 2a` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YHV/66597B3DC7B7) |  |
| family | `ThinkPad T14 Gen 2a` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YHV/66597B3DC7B7) |  |
| board_manufacturer | `LENOVO` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YHV/66597B3DC7B7) |  |
| bios | `R1MET54W (1.24 ) 05/15/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK001AUS/3886FD98D53B) |  |
| bios | `R1MET51W (1.21 ) 09/15/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK001AUS/EED3AE1F8D69) |  |
| bios | `R1MET39W (1.09 ) 06/21/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK0015US/930AF8D5AE2E) |  |
| bios | `R1MET41W (1.11 ) 09/03/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XKA001CD/543A9CC31B7A) |  |
| bios | `R1MET55W (1.25 ) 10/30/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK0019US/C6EB9F1B7EEA) |  |
| bios | `R1MET43W (1.13 ) 11/05/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK002UCK/5DD9F5A72DDD) |  |
| bios | `R1MET44W (1.14 ) 01/21/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YHV/66597B3DC7B7) |  |
| bios | `R1MET47W (1.17 ) 04/14/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YRI/F364B0DFC1FC) |  |
| bios | `R1MET48W (1.18 ) 05/13/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK002SCK/91FE35D93EC5) |  |
| bios | `R1MET49W (1.19 ) 06/27/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YSP/D6A8B91E81B7) |  |
| unit | `20XL0014GE / LENOVO_MT_20XL_BU_Think_FM_ThinkPad T14 Gen 2a / 20XL0014GE / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XL0014GE/05EC38DA4373) |  |
| unit | `20XKCTO1WW / LENOVO_MT_20XK_BU_Think_FM_ThinkPad T14 Gen 2a / 20XKCTO1WW / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XKCTO1WW/189B8026E614) |  |
| unit | `20XK0019US / LENOVO_MT_20XK_BU_Think_FM_ThinkPad T14 Gen 2a / 20XK0019US / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK0019US/760AC52BE2EA) |  |
| unit | `20XK001AUS / LENOVO_MT_20XK_BU_Think_FM_ThinkPad T14 Gen 2a / 20XK001AUS / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK001AUS/3886FD98D53B) |  |
| unit | `20XK001BUS / LENOVO_MT_20XK_BU_Think_FM_ThinkPad T14 Gen 2a / 20XK001BUS / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK001BUS/8117C57A14BD) |  |
| unit | `20XL0012GE / LENOVO_MT_20XL_BU_Think_FM_ThinkPad T14 Gen 2a / 20XL0012GE / chassis 10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XL0012GE/30EDCC01F25B) |  |
| cpu generation | `Zen3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YHV/66597B3DC7B7) |  |
| acpi | `'LENOVO' 'TP-R1M  '` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YRI/F364B0DFC1FC/GENTOO-2.8/5.18.10-K08/X86_64/8F36480AD7) |  |
| nic chip | `Realtek RTL8168ep/8111ep` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YRI/F364B0DFC1FC/GENTOO-2.8/5.18.10-K08/X86_64/8F36480AD7) | kernel r8169 line |
| nic subsystem | `17aa:5094` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YRI/F364B0DFC1FC/GENTOO-2.8/5.18.10-K08/X86_64/8F36480AD7) |  |
| board_location | `Not Available` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YHV/66597B3DC7B7) |  |
| chassis_version | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YHV/66597B3DC7B7) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YHV/66597B3DC7B7) |  |
| cpu_socket | `FP6` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YHV/66597B3DC7B7) |  |
| cpu_part | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YHV/66597B3DC7B7) |  |
| cpu_upgrade | `0x06` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YHV/66597B3DC7B7) | SMBIOS upgrade code |
| cpu_voltage | `1.2 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YHV/66597B3DC7B7) | the most common reading; it differs by CPU |
| board version | `SDK0J40697 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YHV/66597B3DC7B7) |  |
| board version | `Not Defined` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK0015US/930AF8D5AE2E) |  |
| board version | `SDK0J40709 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XKCTO1WW/189B8026E614) |  |
| board version | `SDK0T76463 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XKCTO1WW/1C7E8BD403FE) |  |
| board version | `SDK0T76479 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XKA004CD/B4E865620787) |  |
| board version | `SDK0T76530 WIN` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XLS30800/E69C29467E18) |  |
| memory slots | `DIMM 0/P0 CHANNEL A; DIMM 0/P0 CHANNEL B` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YHV/66597B3DC7B7) |  |
| memory | `Micron Technology 4ATS2G64HZ-3G2B1 (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YRI/F364B0DFC1FC) |  |
| memory | `Samsung M471A2G44AM0-CWE (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK001BUS/8117C57A14BD) |  |
| memory | `Samsung M471A1G44AB0-CWE (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK001AUS/EED3AE1F8D69) |  |
| memory | `Hynix HMAA1GS6CJR6N-XN (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK001AUS/3886FD98D53B) |  |
| memory | `Samsung M471A4G43AB1-CWE (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK000YSP/D6A8B91E81B7) |  |
| memory | `Unknown LD4AS032G-H3200GST (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T14%20Gen%202a%2020XK007DMH/99A08BC54C0D) |  |
| memory | `Kingston HP32D4S2S1ME-4 (4 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/45EFB5F04EDF) | no 4 GiB module with a part number in the reports of this model; the same maker's part in the reports of hp-250-g8 |
| disk | `MTFDDAV256TBN-1AR15ABHA HPC0T12` | C | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205520/1DC6794B86BA/UBUNTU-20.04/5.11.0-46-GENERIC/X86_64/95721C3566) | no SATA disk in any of the ThinkPad Dmesg/HWInfo reports; the PSREF of the T14 Gen 2 AMD (https://psref.lenovo.com/syspool/Sys/PDF/ThinkPad/ThinkPad_T14_Gen_2_AMD/ThinkPad_T14_Gen_2_AMD_Spec.html) lists one PCIe NVMe M.2 slot only: a SATA disk is a stand-in from a Latitude 5520 (decision needed) |

## Supermicro X11SCL-F (Super Server) (`supermicro-x11scl`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `6` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `American Megatrends Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| manufacturer | `Supermicro` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| version | `0123456789` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| family | `To be filled by O.E.M.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| board_manufacturer | `Supermicro` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| bios | `1.6 05/28/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/617C605D5B8B) |  |
| bios | `1.2 11/20/2019` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| bios | `1.3 02/20/2020` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/A7AA64186E4B) |  |
| bios | `1.5 10/05/2020` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/BAD6EC448C66) |  |
| bios | `1.8 05/13/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/FE7A1386B0BB) |  |
| unit | `Super Server / To be filled by O.E.M. / X11SCL-F / chassis 17` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| cpu generation | `Core6to9` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| oem string | `Intel CoffeeLake-S/CannonLake-H/MehlowSVR         ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| oem string | `Supermicro motherboard-X11 Series                 ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| acpi | `'SUPERM' 'SUPERM  '` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Server/Supermicro/Super/Super%20Server/069184BFB536/UBUNTU-18.04/5.3.0-41-GENERIC/X86_64/18D32F5FF4) |  |
| nic chip | `Intel I210 Gigabit Network Connection` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536/UBUNTU-18.04/5.3.0-41-GENERIC/X86_64/18D32F5FF4) |  |
| nic subsystem | `15d9:1533` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536/UBUNTU-18.04/5.3.0-41-GENERIC/X86_64/18D32F5FF4) |  |
| board_location | `To be filled by O.E.M.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| chassis_version | `0123456789` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| chassis_sku | `To be filled by O.E.M.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| cpu_socket | `CPU` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| cpu_part | `To Be Filled By O.E.M.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| cpu_upgrade | `0x32` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) | SMBIOS upgrade code |
| cpu_voltage | `1.0 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) | the most common reading; it differs by CPU |
| board version | `1.01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| memory slots | `DIMMA2/P0_Node0_Channel0_Dimm1; DIMMA1/P0_Node0_Channel0_Dimm0; DIMMB1/P0_Node0_Channel1_Dimm0; DIMMB2/P0_Node0_Channel1_Dimm1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| memory | `Kingston 9965684-013.A00G (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) |  |
| memory | `Samsung M391A1K43BB2-CTD (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/BAD6EC448C66) |  |
| memory | `Kingston 9965745-002.A00G (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/A1AAA9CEAEE9) |  |
| memory | `Samsung M391A4G43MB1-CTD (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/617C605D5B8B) |  |
| disk | `INTEL SSDSC2KB480G7 SCV10150` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Server/Supermicro/Super/Super%20Server/069184BFB536/UBUNTU-18.04/5.3.0-41-GENERIC/X86_64/18D32F5FF4) |  |

## Supermicro H12SSL-i (Super Server) (`supermicro-h12ssl`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `4` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `American Megatrends Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) |  |
| manufacturer | `Supermicro` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) |  |
| version | `0123456789` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) |  |
| family | `To be filled by O.E.M.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) |  |
| board_manufacturer | `Supermicro` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) |  |
| bios | `2.0 02/22/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/1B06E0E943D0) |  |
| bios | `2.3 10/20/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) |  |
| bios | `2.4 04/14/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/35951405EF49) |  |
| bios | `2.9 05/28/2024` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/B5CC5EAAF621) |  |
| unit | `Super Server / To be filled by O.E.M. / H12SSL-i / chassis 17` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) |  |
| cpu generation | `Zen2` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/1B06E0E943D0) |  |
| cpu generation | `Zen3` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) |  |
| oem string | `AMD EPYC Soc/Rome                                 ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/1B06E0E943D0) |  |
| oem string | `Supermicro motherboard-H12 Series                 ` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/1B06E0E943D0) |  |
| acpi | `'SUPERM' 'SMCI--MB'` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Server/Supermicro/Super/Super%20Server/04875F94AAC5/UBUNTU-22.04/5.15.0-25-GENERIC/X86_64/4F88FE663E) |  |
| nic chip | `Broadcom NetXtreme BCM5720 Gigabit Ethernet PCIe` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Server/Supermicro/Super/Super%20Server/1B06E0E943D0/FEDORA-36/5.17.5-300.FC36.X86_64/X86_64/153F5DBEB5) |  |
| nic subsystem | `15d9:165f` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5/UBUNTU-22.04/5.15.0-25-GENERIC/X86_64/4F88FE663E) |  |
| board_location | `To be filled by O.E.M.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) |  |
| chassis_version | `0123456789` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) |  |
| chassis_sku | `To be filled by O.E.M.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) |  |
| cpu_socket | `CPU` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) |  |
| cpu_part | `Unknown` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) |  |
| cpu_upgrade | `0x37` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) | SMBIOS upgrade code |
| cpu_voltage | `1.1 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) | the most common reading; it differs by CPU |
| board version | `1.01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) |  |
| board version | `1.10` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/B5CC5EAAF621) |  |
| memory slots | `DIMMA1/P0_Node0_Channel0_Dimm0; DIMMB1/P0_Node0_Channel1_Dimm0; DIMMC1/P0_Node0_Channel2_Dimm0; DIMMD1/P0_Node0_Channel3_Dimm0` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) |  |
| memory | `Micron Technology 18ASF2G72PZ-3G2R1 (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/1B06E0E943D0) |  |
| memory | `Kingston 9965640-033.C00G (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/35951405EF49) |  |
| memory | `Micron Technology 36ASF4G72PZ-3G2R1 (32 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/04875F94AAC5) |  |
| memory | `Samsung M393A8G40AB2-CWE (64 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/B5CC5EAAF621) |  |
| memory | `Kingston 9965684-013.A00G (8 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/069184BFB536) | no 8 GiB module with a part number in the reports of this model; the same maker's part in the reports of supermicro-x11scl |
| disk | `Samsung SSD 870 EVO 500GB SVT02B6Q` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Server/Supermicro/Super/Super%20Server/EAF1AC2ED184/GENTOO-2.8/5.15.41-GENTOO-HARDENED1/X86_64/6492614879) |  |

## Dell PowerEdge R240 (`dell-poweredge-r240`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `3` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| family | `PowerEdge` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| board_manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| bios | `2.10.1 05/26/2022` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/7ED18DB7AC28) |  |
| bios | `2.4.1 09/27/2018` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/83EA7CA85F81) |  |
| bios | `2.8.3 12/15/2021` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| unit | `PowerEdge R240 / SKU=088F;ModelName=PowerEdge R240 / 0DRR0P / chassis 23` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| unit | `PowerEdge R240 / SKU=088F;ModelName=PowerEdge R240 / 0PJPW3 / chassis 23` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/83EA7CA85F81) |  |
| cpu generation | `Core6to9` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| oem string | `Dell System` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| oem string | `5[0000]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| oem string | `14[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| oem string | `26[0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| oem string | `17[FFFFFFFFFFFFFFFF]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| oem string | `18[0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| oem string | `19[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| acpi | `'DELL  ' 'PE_SC3  '` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA/DEBIAN-11/5.13.19-4-PVE/X86_64/5011114071) |  |
| nic chip | `Broadcom NetXtreme BCM5720 2-port Gigabit Ethernet PCIe` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA/DEBIAN-11/5.13.19-4-PVE/X86_64/5011114071) |  |
| nic subsystem | `1028:088f` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA/DEBIAN-11/5.13.19-4-PVE/X86_64/5011114071) |  |
| board_location | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| chassis_version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| cpu_socket | `CPU1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| cpu_part | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| cpu_upgrade | `0x32` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) | SMBIOS upgrade code |
| cpu_voltage | `1.5 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) | the most common reading; it differs by CPU |
| board version | `A01` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/7ED18DB7AC28) |  |
| board version | `A04` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/83EA7CA85F81) |  |
| board version | `A08` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| memory slots | `A1/; A2/; A3/; A4/` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA) |  |
| memory | `00CE00000A02 M391A2K43BB1-CTD (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/83EA7CA85F81) |  |
| memory | `00CE00000A07 M391A2K43BB1-CTD (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/83EA7CA85F81) |  |
| memory | `00CE00000A06 M391A1K43BB2-CTD (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/7ED18DB7AC28) |  |
| disk | `TOSHIBA MG03ACA300 FL1A` | A | [report](https://github.com/linuxhw/Dmesg/blob/main/Server/Dell/PowerEdge/PowerEdge%20R240/7ED18DB7AC28/UBUNTU-20.04/5.15.0-48-GENERIC/X86_64/029040A622) |  |

## Dell PowerEdge T140 (`dell-poweredge-t140`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `1` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| family | `PowerEdge` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| board_manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| bios | `1.0.2 11/13/2018` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| unit | `PowerEdge T140 / SKU=NotProvided;ModelName=PowerEdge T140 / 0C2GT0 / chassis 17` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| cpu generation | `Core6to9` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| oem string | `Dell System` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| oem string | `5[0000]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| oem string | `14[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| oem string | `26[0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| oem string | `17[FFFFFFFFFFFFFFFF]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| oem string | `18[0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| oem string | `19[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| acpi | `'DELL  ' 'PE_SC3  '` | B | [report](https://github.com/linuxhw/Dmesg/blob/main/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA/DEBIAN-11/5.13.19-4-PVE/X86_64/5011114071) | no Dmesg report; PowerEdge R240 (same platform and PE_SC3 firmware family) |
| nic chip | `Broadcom NetXtreme BCM5720 Gigabit Ethernet PCIe` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032/CLEAROS-7/3.10.0-1127.13.1.EL7.X86_64/X86_64/56CB3FC570) |  |
| nic subsystem | `1028:0891` | A | [report](https://github.com/linuxhw/HWInfo/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032/CLEAROS-7/3.10.0-1127.13.1.EL7.X86_64/X86_64/56CB3FC570) |  |
| board_location | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| chassis_version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| cpu_socket | `CPU1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| cpu_part | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| cpu_upgrade | `0x32` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) | SMBIOS upgrade code |
| cpu_voltage | `1.5 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) | the most common reading; it differs by CPU |
| board version | `A02` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| memory slots | `A1/; A2/; A3/; A4/` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| memory | `019400000A00 SF4721G8CK8M8HLSBG (8 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20T140/58DAE2F02032) |  |
| memory | `00CE00000A07 M391A2K43BB1-CTD (16 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/83EA7CA85F81) | no 16 GiB module with a part number in the reports of this model; a 16 GiB DDR4-2666 part in the reports of dell-poweredge-r240 |
| disk | `TOSHIBA MG03ACA300 FL1A` | B | [report](https://github.com/linuxhw/Dmesg/blob/main/Server/Dell/PowerEdge/PowerEdge%20R240/7ED18DB7AC28/UBUNTU-20.04/5.15.0-48-GENERIC/X86_64/029040A622) | no SATA disk in its report; PowerEdge R240 (same platform) |

## Dell PowerEdge R350 (`dell-poweredge-r350`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `1` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| family | `PowerEdge` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| board_manufacturer | `Dell Inc.` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| bios | `1.7.3 06/06/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| unit | `PowerEdge R350 / SKU=0A94;ModelName=PowerEdge R350 / 0MTYYT / chassis 23` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| cpu generation | `Core11` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| oem string | `Dell System` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| oem string | `5[0000]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| oem string | `14[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| oem string | `18[0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| oem string | `19[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| oem string | `26[0]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| oem string | `31[1]` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| acpi | `'DELL  ' 'PE_SC3  '` | B | [report](https://github.com/linuxhw/Dmesg/blob/main/Server/Dell/PowerEdge/PowerEdge%20R240/3378DCFA2CDA/DEBIAN-11/5.13.19-4-PVE/X86_64/5011114071) | no Dmesg report; PowerEdge R240 (same PE_SC3 firmware family) |
| nic chip | `Broadcom BCM5720` | B | [report](https://i.dell.com/sites/csdocuments/product_docs/en/dell-emc-poweredge-r350-spec-sheet.pdf) | no HWInfo/Dmesg NIC line of the model; the maker's specification |
| nic subsystem | `none (Intel's own)` | C |  | no HWInfo report of the model: the card keeps Intel's subsystem ID |
| board_location | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| chassis_version | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| chassis_sku | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| cpu_socket | `CPU1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| cpu_part | `` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| cpu_upgrade | `0x32` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) | SMBIOS upgrade code |
| cpu_voltage | `1.5 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) | the most common reading; it differs by CPU |
| board version | `A03` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| memory slots | `A1/; A2/; A3/; A4/` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| memory | `002C00000C01 9ASF2G72AZ-3G2F1 (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R350/95232CC6FD85) |  |
| memory | `00CE00000A06 M391A1K43BB2-CTD (8 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Server/Dell/PowerEdge/PowerEdge%20R240/7ED18DB7AC28) | no 8 GiB module with a part number in the reports of this model; a 8 GiB DDR4-2666 part in the reports of dell-poweredge-r240 |
| disk | `TOSHIBA MG03ACA300 FL1A` | B | [report](https://github.com/linuxhw/Dmesg/blob/main/Server/Dell/PowerEdge/PowerEdge%20R240/7ED18DB7AC28/UBUNTU-20.04/5.15.0-48-GENERIC/X86_64/029040A622) | no Dmesg report; PowerEdge R240 |

## Lenovo ThinkSystem SR250 V2 (`lenovo-thinksystem-sr250-v2`)

| Field | Value | Class | Source | Note |
| --- | --- | --- | --- | --- |
| weight | `1` | A |  | reports of the model in linuxhw/DMI on 2026-10-27 |
| bios_vendor | `Lenovo` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) |  |
| manufacturer | `Lenovo` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) |  |
| version | `03` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) |  |
| family | `ThinkSystem` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) |  |
| board_manufacturer | `Lenovo` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) |  |
| bios | `TQE108G-1.21 04/06/2023` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) |  |
| unit | `ThinkSystem SR250 V2 / 7D7QCTO1WW / SB27B23563 / chassis 23` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) |  |
| cpu generation | `Core11` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) |  |
| oem string | `$BA BIOS AC Module Version -[1.0.1]-` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) |  |
| acpi | `('LENOVO', 'TC-TQE  ')` | C |  | no Dmesg report of the model and no sibling: kept, not verified |
| nic chip | `Broadcom BCM5720` | B | [report](https://lenovopress.lenovo.com/lp1549-thinksystem-sr250-v2) | no HWInfo/Dmesg NIC line of the model; the maker's specification |
| nic subsystem | `none (Intel's own)` | C |  | no HWInfo report of the model: the card keeps Intel's subsystem ID |
| board_location | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) |  |
| chassis_version | `None` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) |  |
| chassis_sku | `7D7QCTO1WW` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) |  |
| cpu_socket | `CPU 1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) |  |
| cpu_part | `none` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) |  |
| cpu_upgrade | `0x3e` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) | SMBIOS upgrade code |
| cpu_voltage | `1.3 V` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) | the most common reading; it differs by CPU |
| board version | `03` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) |  |
| memory slots | `DIMM 4/CPU 1; DIMM 3/CPU 1; DIMM 2/CPU 1; DIMM 1/CPU 1` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) |  |
| memory | `Samsung M391A2K43DB1-CWE (16 GiB)` | A | [report](https://github.com/linuxhw/DMI/blob/master/Server/Lenovo/ThinkSystem/ThinkSystem%20SR250%20V2/DCE46F160939) |  |
| memory | `Samsung M391A1K43BB2-CTD (8 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/BAD6EC448C66) | no 8 GiB module with a part number in the reports of this model; the same maker's part in the reports of supermicro-x11scl |
| memory | `Samsung M391A4G43MB1-CTD (32 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/617C605D5B8B) | no 32 GiB module with a part number in the reports of this model; the same maker's part in the reports of supermicro-x11scl |
| memory | `Samsung M393A8G40AB2-CWE (64 GiB)` | B | [report](https://github.com/linuxhw/DMI/blob/master/Server/Supermicro/Super/Super%20Server/B5CC5EAAF621) | no 64 GiB module with a part number in the reports of this model; the same maker's part in the reports of supermicro-h12ssl |
| disk | `TOSHIBA MG03ACA300 FL1A` | B | [report](https://github.com/linuxhw/Dmesg/blob/main/Server/Dell/PowerEdge/PowerEdge%20R240/7ED18DB7AC28/UBUNTU-20.04/5.15.0-48-GENERIC/X86_64/029040A622) | no Dmesg report and no Lenovo server with one; PowerEdge R240 |

## Disks

| Disk | Firmware | WWN OUI | Rotation | Firmware seen | OUI and rotation |
| --- | --- | --- | --- | --- | --- |
| `HGST HTS541010A9E680` | `JA0OA560` | `000cca` | 5400 rpm | [report](https://github.com/linuxhw/Dmesg/blob/main/Mini%20Pc/Lenovo/ThinkCentre/ThinkCentre%20M75q%20Gen%202%2011JJ001RRU/B114BBC992FE/ROSA-12.2/5.10.74-GENERIC-2ROSA2021.1-X86_64/X86_64/5F6F023F22) | [smartctl](https://github.com/linuxhw/SMART/blob/master/HDD/HGST/HTS5410/HTS541010A9E680/0786B89AC52E) |
| `INTEL SSDSC2KB480G7` | `SCV10150` | `5cd2e4` | Solid State Device | [report](https://github.com/linuxhw/Dmesg/blob/main/Server/Supermicro/Super/Super%20Server/069184BFB536/UBUNTU-18.04/5.3.0-41-GENERIC/X86_64/18D32F5FF4) | [smartctl](https://github.com/linuxhw/SMART/blob/master/SSD/Intel/SSDSC2/SSDSC2KB480G7/053F2ECB2FF5) |
| `KINGSTON SA400S37240G` | `SBFK71E0` | `0026b7` | Solid State Device | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%207080/C00E5FD4B78E/FEDORA-36/5.19.11-200.FC36.X86_64/X86_64/73E69DEBD9) | [smartctl](https://github.com/linuxhw/SMART/blob/master/SSD/Kingston/SA400/SA400S37240G/02B650A724FF) |
| `KINGSTON SUV400S37240G` | `0C3G37R5` | `none` | Solid State Device | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M75s%20Gen%202%2011JB002GPB/A1A4A3F49260/FEDORA-34/5.13.19-200.FC34.X86_64/X86_64/68F4FF7431) | [smartctl](https://github.com/linuxhw/SMART/blob/master/SSD/Kingston/SUV400/SUV400S37240G/002D4E5B7EB2) |
| `MTFDDAV256TBN-1AR15ABHA` | `HPC0T12` | `00a075` | Solid State Device | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Dell/Latitude/Latitude%205520/1DC6794B86BA/UBUNTU-20.04/5.11.0-46-GENERIC/X86_64/95721C3566) | [smartctl](https://github.com/linuxhw/SMART/blob/master/SSD/Micron/MTFDDAV256/MTFDDAV256TBN-1AR15ABHA/029DE3474FB0) |
| `MTFDDAV256TDL-1AW1ZABHA` | `HPC0032` | `00a075` | Solid State Device | [report](https://github.com/linuxhw/HWInfo/blob/master/Notebook/Hewlett-Packard/250/250%20G8%20Notebook%20PC/1F277278F495/DEBIAN-11/5.10.0-9-AMD64/X86_64/C0A39342C3) | [smartctl](https://github.com/linuxhw/SMART/blob/master/SSD/Micron/MTFDDAV256/MTFDDAV256TDL-1AW1ZABHA/067156723C3C) |
| `PNY CS900 240GB SSD` | `CS900J13` | `f8db4c` | Solid State Device | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%203080/2EF782A45D9E/UBUNTU-20.04/5.11.0-41-GENERIC/X86_64/88AA9F2F67) | [smartctl](https://github.com/linuxhw/SMART/blob/master/SSD/PNY/CS900/CS900%20240GB%20SSD/0773C730F088) |
| `Samsung SSD 860 EVO 250GB` | `RVT02B6Q` | `002538` | Solid State Device | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%207090/A73F0F85C4E4/OL-8.6/4.18.0-372.16.1.0.2.EL8_6.X86_64/X86_64/3BED97B23E) | [smartctl](https://github.com/linuxhw/SMART/blob/master/SSD/Samsung/SSD%20860/SSD%20860%20EVO%20250GB/1D0B726A7838) |
| `Samsung SSD 860 EVO M.2 500GB` | `RVT24B6Q` | `002538` | Solid State Device | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Hewlett-Packard/ProBook/ProBook%20450%20G8%20Notebook%20PC/657E21304C05/POP%21_OS-22.04/6.0.2-76060002-GENERIC/X86_64/E7DB99BE75) | [smartctl](https://github.com/linuxhw/SMART/blob/master/SSD/Samsung/SSD%20860/SSD%20860%20EVO%20M.2%20500GB/15A8A6E94C79) |
| `Samsung SSD 870 EVO 500GB` | `SVT01B6Q` | `002538` | Solid State Device | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%203080/2EF782A45D9E/UBUNTU-20.04/5.11.0-41-GENERIC/X86_64/2E0D1C92B2) | [smartctl](https://github.com/linuxhw/SMART/blob/master/SSD/Samsung/SSD%20870/SSD%20870%20EVO%20500GB/081F119C751B) |
| `Samsung SSD 870 EVO 500GB` | `SVT02B6Q` | `002538` | Solid State Device | [report](https://github.com/linuxhw/Dmesg/blob/main/Server/Supermicro/Super/Super%20Server/EAF1AC2ED184/GENTOO-2.8/5.15.41-GENTOO-HARDENED1/X86_64/6492614879) | [smartctl](https://github.com/linuxhw/SMART/blob/master/SSD/Samsung/SSD%20870/SSD%20870%20EVO%20500GB/081F119C751B) |
| `SanDisk SDSSDHII120G` | `X31200RL` | `001b44` | Solid State Device | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Lenovo/ThinkCentre/ThinkCentre%20M920s%2010SKS44L00/EF6E185CAE11/ROSA-12.2/5.10.74-GENERIC-2ROSA2021.1-X86_64/X86_64/C26BB7D11C) | [smartctl](https://github.com/linuxhw/SMART/blob/master/SSD/SanDisk/SDSSDHII/SDSSDHII120G/02DC795F7D6C) |
| `ST1000DM010-2EP102` | `1001` | `000c50` | 7200 rpm | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%207000/7F292C163AA9/UBUNTU-22.04/5.19.0-38-GENERIC/X86_64/D1CF6FA11E) | [smartctl](https://github.com/linuxhw/SMART/blob/master/HDD/Seagate/ST1000/ST1000DM010-2EP102/070A733C4F65) |
| `ST1000LM049-2GH172` | `SDM1` | `000c50` | 7200 rpm | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%203080/720698D0737E/UBUNTU-22.04/5.15.0-43-GENERIC/X86_64/B1011AE242) | [smartctl](https://github.com/linuxhw/SMART/blob/master/HDD/Seagate/ST1000/ST1000LM049-2GH172/00D0A289171D) |
| `ST2000LM015-2E8174` | `0001` | `000c50` | 5400 rpm | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Hewlett-Packard/ProDesk/ProDesk%20400%20G7%20Small%20Form%20Factor%20PC/7DBCB845F40C/OPENMANDRIVA-4.3/5.16.7-DESKTOP-1OMV4003/X86_64/7E0AE3D91F) | [smartctl](https://github.com/linuxhw/SMART/blob/master/HDD/Seagate/ST2000/ST2000LM015-2E8174/040DEECF0A9F) |
| `TOSHIBA DT01ACA050` | `MS1OA8L0` | `000039` | 7200 rpm | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Hewlett-Packard/ProDesk/ProDesk%20600%20G6%20Small%20Form%20Factor%20PC/2632124B31C0/KDE-NEON-20.04/5.13.0-44-GENERIC/X86_64/F2959A67AE) | [smartctl](https://github.com/linuxhw/SMART/blob/master/HDD/Toshiba/DT01/DT01ACA050/000490E2339A) |
| `TOSHIBA MG03ACA300` | `FL1A` | `000039` | 7200 rpm | [report](https://github.com/linuxhw/Dmesg/blob/main/Server/Dell/PowerEdge/PowerEdge%20R240/7ED18DB7AC28/UBUNTU-20.04/5.15.0-48-GENERIC/X86_64/029040A622) | [smartctl](https://github.com/linuxhw/SMART/blob/master/HDD/Toshiba/MG03/MG03ACA300/2001FA5305FC) |
| `TOSHIBA MQ04ABF100` | `100001` | `000039` | 5400 rpm | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Dell/Latitude/Latitude%203520/BEEE0CBAF2F8/UBUNTU-20.04/5.10.0-1045-OEM/X86_64/B28801BF6C) | [smartctl](https://github.com/linuxhw/SMART/blob/master/HDD/Toshiba/MQ04/MQ04ABF100/13FF084BC3F4) |
| `TOSHIBA MQ04ABF100` | `100002` | `000039` | 5400 rpm | [report](https://github.com/linuxhw/Dmesg/blob/main/Notebook/Dell/Latitude/Latitude%203520/13DBE0B08ADA/UBUNTU-18.04/5.4.0-97-GENERIC/X86_64/7F6955E406) | [smartctl](https://github.com/linuxhw/SMART/blob/master/HDD/Toshiba/MQ04/MQ04ABF100/13FF084BC3F4) |
| `TOSHIBA-TR200` | `SBFA15.2` | `00080d` | Solid State Device | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%207080/E81F7BFF0FDF/GENTOO-2.8/5.16.11-GENTOO-X86_64/X86_64/76F13AA200) | [smartctl](https://github.com/linuxhw/SMART/blob/master/SSD/Toshiba/TR200/TR200%20240GB/01CF3F0F437B) |
| `WDC WD10EZEX-08WN4A1` | `03.01A03` | `0014ee` | 7200 rpm | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Lenovo/ThinkCentre/ThinkCentre%20neo%2050s%20Gen%203%2011T0003QFR/F0B2A55FD054/FEDORA-37/6.1.18-200.FC37.X86_64/X86_64/69CB363858) | [smartctl](https://github.com/linuxhw/SMART/blob/master/HDD/WDC/WD10/WD10EZEX-08WN4A1/13FEBB647CC9) |
| `WDC WD10EZEX-75WN4A1` | `13057113` | `0014ee` | 7200 rpm | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Dell/OptiPlex/OptiPlex%207000/8C25D9B2B397/ARCH-ROLLING/6.0.11-ARCH1-1/X86_64/B955357CCC) | [smartctl](https://github.com/linuxhw/SMART/blob/master/HDD/WDC/WD10/WD10EZEX-75WN4A1/22388504EE53) |
| `X160EB` | `SN07656` | `000000` | Solid State Device | [report](https://github.com/linuxhw/Dmesg/blob/main/Desktop/Hewlett-Packard/EliteDesk/EliteDesk%20800%20G6%20Small%20Form%20Factor%20PC/B736692F455E/UBUNTU-22.04/5.15.0-40-GENERIC/X86_64/17993CF668) | [smartctl](https://github.com/linuxhw/SMART/blob/master/SSD/China/X160/X160EB/A582C108FDED) |
