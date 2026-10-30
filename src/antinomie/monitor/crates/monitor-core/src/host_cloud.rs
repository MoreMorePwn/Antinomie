// SPDX-License-Identifier: GPL-3.0-only
//! Whether this computer is itself an instance of a cloud provider. A VM on
//! NAT reaches this computer's network, and on a cloud instance that network
//! answers the provider's real metadata service at 169.254.169.254, with
//! whatever credentials the instance holds.
use std::path::Path;

/// DMI fields that name the provider, as the kernel shows them.
const FIELDS: [&str; 5] = [
    "sys_vendor",
    "product_name",
    "bios_vendor",
    "board_vendor",
    "chassis_asset_tag",
];

/// (what the field holds, lower case, provider) in the order they are tried.
const PROVIDERS: [(&str, &str); 11] = [
    ("amazon ec2", "Amazon EC2"),
    ("google compute engine", "Google Compute Engine"),
    // Azure's chassis asset tag; a Hyper-V host is not Azure.
    ("7783-7084-3265-9085-8269-3286-77", "Microsoft Azure"),
    ("digitalocean", "DigitalOcean"),
    ("hetzner", "Hetzner Cloud"),
    ("vultr", "Vultr"),
    ("ovh", "OVHcloud"),
    ("alibaba cloud", "Alibaba Cloud"),
    ("tencent cloud", "Tencent Cloud"),
    ("oraclecloud.com", "Oracle Cloud"),
    ("openstack", "OpenStack"),
];

/// The provider these DMI values belong to, if they are a cloud instance's.
pub fn provider_of(values: &[String]) -> Option<&'static str> {
    let values: Vec<String> = values.iter().map(|value| value.to_lowercase()).collect();
    PROVIDERS
        .iter()
        .find(|(needle, _)| values.iter().any(|value| value.contains(needle)))
        .map(|(_, provider)| *provider)
}

/// The provider this computer runs on, read from its DMI data under `root`
/// (`/sys/class/dmi/id`); `None` on hardware, in WSL and in a local VM.
pub fn provider_in(root: &Path) -> Option<&'static str> {
    let values: Vec<String> = FIELDS
        .iter()
        .filter_map(|field| std::fs::read_to_string(root.join(field)).ok())
        .map(|value| value.trim().to_owned())
        .collect();
    provider_of(&values)
}

/// [`provider_in`] for this computer.
pub fn host_cloud_provider() -> Option<&'static str> {
    provider_in(Path::new("/sys/class/dmi/id"))
}

/// What a VM on NAT can reach on a cloud instance, said once for the run's notes.
pub fn nat_note(provider: &str) -> String {
    format!(
        "This computer is a {provider} instance, and the VM's NAT lets the sample reach its network, \
         including the provider's real metadata service at 169.254.169.254. A Routed network keeps \
         the sample away from it."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dmi(name: &str, fields: &[(&str, &str)]) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ant-host-cloud-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (field, value) in fields {
            std::fs::write(dir.join(field), format!("{value}\n")).unwrap();
        }
        dir
    }

    #[test]
    fn a_cloud_instance_is_named_by_its_dmi_data_and_hardware_is_not() {
        let ec2 = dmi(
            "ec2",
            &[("sys_vendor", "Amazon EC2"), ("product_name", "t3.micro")],
        );
        assert_eq!(provider_in(&ec2), Some("Amazon EC2"));
        let gce = dmi("gce", &[("product_name", "Google Compute Engine")]);
        assert_eq!(provider_in(&gce), Some("Google Compute Engine"));
        let azure = dmi(
            "azure",
            &[
                ("sys_vendor", "Microsoft Corporation"),
                ("product_name", "Virtual Machine"),
                ("chassis_asset_tag", "7783-7084-3265-9085-8269-3286-77"),
            ],
        );
        assert_eq!(provider_in(&azure), Some("Microsoft Azure"));
        // Hyper-V without Azure's tag, a laptop and a machine with no DMI are not clouds.
        let hyperv = dmi(
            "hyperv",
            &[
                ("sys_vendor", "Microsoft Corporation"),
                ("product_name", "Virtual Machine"),
            ],
        );
        assert_eq!(provider_in(&hyperv), None);
        let laptop = dmi(
            "laptop",
            &[("sys_vendor", "Dell Inc."), ("product_name", "XPS 13")],
        );
        assert_eq!(provider_in(&laptop), None);
        assert_eq!(provider_in(Path::new("/nonexistent/dmi")), None);
        for dir in [ec2, gce, azure, hyperv, laptop] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn the_note_names_the_provider_and_the_way_out() {
        let note = nat_note("Hetzner Cloud");
        assert!(note.contains("Hetzner Cloud instance"));
        assert!(note.contains("169.254.169.254"));
        assert!(note.contains("Routed"));
    }
}
