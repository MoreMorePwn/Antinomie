// SPDX-License-Identifier: GPL-3.0-only
//! What the guest facade (guest patch 0052) shows for QEMU's devices on a
//! desktop or laptop machine: the GPU, the NVMe drive of an NVMe-only laptop,
//! the USB mouse, the EFI firmware vendor and the ACPI creator ID, each as
//! public reports of real units of the model (or, where they have none, of a
//! sibling) show them; cited in `catalog/SOURCES.md` ("Guest facade").
//!
//! Server machines have none: a server or cloud machine legitimately looks
//! like QEMU/KVM to the programs that run on it.
use super::super::parts::NvmeModel;

/// A USB mouse as its device descriptor and strings name it.
pub(in crate::stealth) struct UsbMouse {
    pub vendor: u16,
    pub product: u16,
    /// bcdDevice.
    pub release: u16,
    pub manufacturer: &'static str,
    pub product_name: &'static str,
}

/// Dell MS116 (the mouse Dell's desktops ship with).
pub(in crate::stealth) const DELL_MS116: UsbMouse = UsbMouse {
    vendor: 0x413c,
    product: 0x301a,
    release: 0x0100,
    manufacturer: "PixArt",
    product_name: "Dell MS116 USB Optical Mouse",
};

/// HP 320M (the mouse HP's desktops ship with).
pub(in crate::stealth) const HP_320M: UsbMouse = UsbMouse {
    vendor: 0x0d62,
    product: 0x4141,
    release: 0x0100,
    manufacturer: "PixArt",
    product_name: "HP 320M USB Optical Mouse",
};

/// Logitech M105, seen with Lenovo and HP laptops.
pub(in crate::stealth) const LOGITECH_M105: UsbMouse = UsbMouse {
    vendor: 0x046d,
    product: 0xc077,
    release: 0x7200,
    manufacturer: "Logitech",
    product_name: "USB Optical Mouse",
};

/// The firmware's ACPI creator ID and revision (the tables' header, as the
/// kernel logs it) and its EFI vendor.
#[derive(Clone, Copy)]
pub(in crate::stealth) struct Firmware {
    pub acpi_creator: &'static str,
    pub acpi_creator_revision: u32,
    pub efi_vendor: &'static str,
}

const DELL: Firmware = Firmware {
    acpi_creator: "    ",
    acpi_creator_revision: 0x0100_0013,
    efi_vendor: "Dell",
};
const HP: Firmware = Firmware {
    acpi_creator: "HP  ",
    acpi_creator_revision: 0x0000_0001,
    efi_vendor: "HP",
};
const HP_INSYDE: Firmware = Firmware {
    acpi_creator: "HP  ",
    acpi_creator_revision: 0x0004_0000,
    efi_vendor: "INSYDE Corp.",
};
const LENOVO: Firmware = Firmware {
    acpi_creator: "PTEC",
    acpi_creator_revision: 0x0000_0002,
    efi_vendor: "Lenovo",
};

/// The facade of one machine.
pub(in crate::stealth) struct MachineFacade {
    pub machine: &'static str,
    /// The integrated GPU's PCI vendor and device; its subsystem is the
    /// board's.
    pub gpu: (u16, u16),
    /// The board's PCI subsystem for a machine whose identity has none (its
    /// network card is Intel's own).
    pub board_subsystem: Option<(u16, u16)>,
    /// The NVMe drive of a machine whose units have M.2 NVMe slots only.
    pub nvme: Option<&'static NvmeModel>,
    pub mouse: &'static UsbMouse,
    pub firmware: Firmware,
}

use super::super::parts as p;

const fn facade(
    machine: &'static str,
    gpu: (u16, u16),
    nvme: Option<&'static NvmeModel>,
    mouse: &'static UsbMouse,
    firmware: Firmware,
) -> MachineFacade {
    MachineFacade {
        machine,
        gpu,
        board_subsystem: None,
        nvme,
        mouse,
        firmware,
    }
}

pub(in crate::stealth) static FACADES: &[MachineFacade] = &[
    facade(
        "dell-optiplex-7090",
        (0x8086, 0x9bc5),
        None,
        &DELL_MS116,
        DELL,
    ),
    facade(
        "dell-optiplex-7080",
        (0x8086, 0x9bc5),
        None,
        &DELL_MS116,
        DELL,
    ),
    facade(
        "dell-optiplex-5090",
        (0x8086, 0x4c8a),
        None,
        &DELL_MS116,
        DELL,
    ),
    facade(
        "dell-optiplex-3080",
        (0x8086, 0x9bc8),
        None,
        &DELL_MS116,
        DELL,
    ),
    facade(
        "dell-optiplex-7000",
        (0x8086, 0x4680),
        None,
        &DELL_MS116,
        DELL,
    ),
    facade("hp-elitedesk-800-g6", (0x8086, 0x9bc5), None, &HP_320M, HP),
    facade("hp-elitedesk-805-g8", (0x1002, 0x1638), None, &HP_320M, HP),
    MachineFacade {
        board_subsystem: Some((0x103c, 0x870c)),
        ..facade("hp-elitedesk-800-g8", (0x8086, 0x4c8a), None, &HP_320M, HP)
    },
    facade("hp-prodesk-400-g7", (0x8086, 0x9bc5), None, &HP_320M, HP),
    facade("hp-prodesk-600-g6", (0x8086, 0x9bc8), None, &HP_320M, HP),
    facade("hp-prodesk-405-g6", (0x1002, 0x1636), None, &HP_320M, HP),
    facade(
        "lenovo-m75q-gen2",
        (0x1002, 0x1636),
        None,
        &LOGITECH_M105,
        LENOVO,
    ),
    MachineFacade {
        board_subsystem: Some((0x17aa, 0x3132)),
        ..facade(
            "lenovo-thinkcentre-m70s-gen3",
            (0x8086, 0x4680),
            None,
            &LOGITECH_M105,
            LENOVO,
        )
    },
    MachineFacade {
        board_subsystem: Some((0x17aa, 0x3132)),
        ..facade(
            "lenovo-thinkcentre-neo-50s-gen3",
            (0x8086, 0x4680),
            None,
            &LOGITECH_M105,
            LENOVO,
        )
    },
    facade(
        "lenovo-thinkcentre-m920s",
        (0x8086, 0x3e92),
        None,
        &LOGITECH_M105,
        LENOVO,
    ),
    facade(
        "lenovo-thinkcentre-m75s-gen2",
        (0x1002, 0x1636),
        None,
        &LOGITECH_M105,
        LENOVO,
    ),
    facade(
        "dell-latitude-5420",
        (0x8086, 0x9a49),
        Some(&p::SAMSUNG_MZVLB256HBHQ_00000),
        &DELL_MS116,
        DELL,
    ),
    facade(
        "dell-latitude-5430",
        (0x8086, 0x4628),
        Some(&p::KIOXIA_KBG50ZNS256G),
        &DELL_MS116,
        DELL,
    ),
    facade(
        "dell-latitude-5520",
        (0x8086, 0x9a49),
        None,
        &DELL_MS116,
        DELL,
    ),
    facade(
        "dell-latitude-5530",
        (0x8086, 0x46a6),
        Some(&p::SK_HYNIX_PC801_1TB),
        &DELL_MS116,
        DELL,
    ),
    facade(
        "dell-latitude-3520",
        (0x8086, 0x9a78),
        None,
        &DELL_MS116,
        DELL,
    ),
    facade(
        "dell-vostro-15-3510",
        (0x8086, 0x9a49),
        None,
        &DELL_MS116,
        DELL,
    ),
    facade(
        "hp-250-g8",
        (0x8086, 0x9a78),
        None,
        &LOGITECH_M105,
        HP_INSYDE,
    ),
    facade(
        "hp-probook-450-g8",
        (0x8086, 0x9a49),
        Some(&p::KIOXIA_KBG40ZNS256G),
        &HP_320M,
        HP,
    ),
    facade(
        "hp-probook-440-g8",
        (0x8086, 0x9a49),
        Some(&p::KIOXIA_KBG40ZNS256G),
        &HP_320M,
        HP,
    ),
    facade(
        "hp-probook-455-g8",
        (0x1002, 0x1638),
        Some(&p::SAMSUNG_MZVLQ256HAJD_000H1),
        &HP_320M,
        HP,
    ),
    facade(
        "lenovo-t14-gen3-amd",
        (0x1002, 0x1681),
        Some(&p::MICRON_2450_MTFDKBA512TFK),
        &LOGITECH_M105,
        LENOVO,
    ),
    facade(
        "lenovo-thinkpad-t14-gen3",
        (0x8086, 0x46a6),
        Some(&p::SAMSUNG_MZVL2512HCJQ_00BL7),
        &LOGITECH_M105,
        LENOVO,
    ),
    facade(
        "lenovo-thinkpad-e14-gen4",
        (0x8086, 0x46a8),
        Some(&p::MICRON_MTFDKCD512TFK),
        &LOGITECH_M105,
        LENOVO,
    ),
    facade(
        "lenovo-thinkpad-l14-gen2",
        (0x8086, 0x9a49),
        Some(&p::SAMSUNG_MZVLB256HBHQ_000L7),
        &LOGITECH_M105,
        LENOVO,
    ),
    facade(
        "lenovo-thinkpad-e15-gen3-amd",
        (0x1002, 0x164c),
        Some(&p::SAMSUNG_MZVLB256HBHQ_000L7),
        &LOGITECH_M105,
        LENOVO,
    ),
    facade(
        "lenovo-thinkpad-l14-gen2-amd",
        (0x1002, 0x1638),
        Some(&p::SK_HYNIX_BC711_256GB),
        &LOGITECH_M105,
        LENOVO,
    ),
    facade(
        "lenovo-thinkpad-t14-gen2-amd",
        (0x1002, 0x1638),
        Some(&p::SK_HYNIX_BC711_256GB),
        &LOGITECH_M105,
        LENOVO,
    ),
];

/// The facade of the machine `id`, if it has one.
pub(in crate::stealth) fn of(id: &str) -> Option<&'static MachineFacade> {
    FACADES.iter().find(|facade| facade.machine == id)
}
