// SPDX-License-Identifier: GPL-3.0-only
//! Which accelerator a VM boots with, and how long its start waits for QEMU
//! and the guest.
//!
//! One decision serves every launch path (start, snapshot restore, the
//! full-snapshot identity), so the same VM never boots with KVM in one place
//! and TCG in another. The waits were written for KVM speed; TCG is software
//! emulation, 10 to 50 times slower, so they scale with the accelerator and
//! with the load on the host.
use crate::api::{BackendOptions, StartSettings, VmAcceleration, VmCpuModel, VmLaunchOptions};
use std::{fs::OpenOptions, time::Duration};

/// The accelerator QEMU runs with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accelerator {
    Kvm,
    Tcg,
}

impl Accelerator {
    /// The name QEMU's `-accel` takes.
    pub fn qemu_name(self) -> &'static str {
        match self {
            Self::Kvm => "kvm",
            Self::Tcg => "tcg",
        }
    }
}

/// The accelerator a launch uses and, when KVM was wanted but unusable, why
/// it is TCG instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Choice {
    pub accelerator: Accelerator,
    /// Set only when the launch fell back from KVM: `KVM is not available on
    /// this host (<reason>)`.
    pub fallback: Option<String>,
}

impl Choice {
    pub fn is_tcg(&self) -> bool {
        self.accelerator == Accelerator::Tcg
    }

    /// What the user is told when a start fell back to TCG; `None` otherwise.
    pub fn fallback_warning(&self, vm_name: &str) -> Option<String> {
        self.fallback.as_ref().map(|reason| {
            format!(
                "{reason}; {vm_name} runs with TCG software emulation, so expect much slower performance."
            )
        })
    }

    /// The value recorded with a run: `kvm`, `tcg`, or `tcg (KVM unavailable)`.
    pub fn record(&self) -> String {
        match (&self.accelerator, &self.fallback) {
            (Accelerator::Tcg, Some(_)) => "tcg (KVM unavailable)".into(),
            (accelerator, _) => accelerator.qemu_name().into(),
        }
    }
}

/// Why `/dev/kvm` cannot be used, or `None` when it opens for reading and
/// writing.
pub fn kvm_problem() -> Option<String> {
    kvm_problem_at(std::path::Path::new("/dev/kvm"))
}

/// [`kvm_problem`] for another device path (the test seam).
pub fn kvm_problem_at(device: &std::path::Path) -> Option<String> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
        .err()
        .map(|error| format!("cannot open {}: {error}", device.display()))
}

/// The accelerator for `launch`, probing `/dev/kvm` when it matters.
pub fn choose(options: &BackendOptions, launch: &VmLaunchOptions) -> Result<Choice, String> {
    choose_with(options, launch, kvm_problem)
}

/// [`choose`] with the KVM probe supplied (the test seam).
///
/// | Setting | KVM usable | KVM unusable |
/// |---|---|---|
/// | TCG, or the `--tcg` override | TCG | TCG |
/// | Default | KVM | TCG, with the reason |
/// | KVM | KVM | TCG with the reason when "Use TCG when KVM is unavailable" is on, else an error |
pub fn choose_with(
    options: &BackendOptions,
    launch: &VmLaunchOptions,
    probe: impl FnOnce() -> Option<String>,
) -> Result<Choice, String> {
    if options.force_tcg || launch.acceleration == VmAcceleration::Tcg {
        return Ok(Choice {
            accelerator: Accelerator::Tcg,
            fallback: None,
        });
    }
    let Some(problem) = probe() else {
        return Ok(Choice {
            accelerator: Accelerator::Kvm,
            fallback: None,
        });
    };
    let reason = format!("KVM is not available on this host ({problem})");
    if launch.acceleration == VmAcceleration::Kvm && !options.start.kvm_fallback {
        return Err(format!(
            "{reason}. Use TCG for this VM (VM settings > Acceleration), or turn on \"Use TCG when KVM is unavailable\" in Tools > Settings > Advanced. TCG is software emulation and much slower."
        ));
    }
    if launch.cpu_model == VmCpuModel::Host {
        return Err(format!(
            "{reason}, and the host CPU model needs KVM. Choose another CPU model in VM settings to run with TCG."
        ));
    }
    Ok(Choice {
        accelerator: Accelerator::Tcg,
        fallback: Some(reason),
    })
}

/// The waits of one start, scaled once for the accelerator and the host load.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Waits {
    scale: f64,
    guest_connect: Duration,
}

/// Most a host load can stretch a wait.
const LOAD_SCALE_CAP: f64 = 4.0;

/// Load factor: 1 until the one-minute load average exceeds the CPU count,
/// then in proportion, up to four times.
pub fn load_scale(load1: f64, cpus: usize) -> f64 {
    if !load1.is_finite() || cpus == 0 {
        return 1.0;
    }
    (load1 / cpus as f64).clamp(1.0, LOAD_SCALE_CAP)
}

fn host_load_scale() -> f64 {
    let load = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|text| text.split_whitespace().next()?.parse().ok())
        .unwrap_or(0.0);
    load_scale(
        load,
        std::thread::available_parallelism().map_or(1, usize::from),
    )
}

impl Waits {
    /// The waits of an idle host at KVM speed (tests, tools without a start).
    pub fn kvm_default() -> Self {
        Self::with_load(
            &Choice {
                accelerator: Accelerator::Kvm,
                fallback: None,
            },
            &StartSettings::default(),
            1.0,
        )
    }

    /// For `choice`, with the host's load now.
    pub fn new(choice: &Choice, settings: &StartSettings) -> Self {
        Self::with_load(choice, settings, host_load_scale())
    }

    /// For `choice`, with a given load factor (the test seam).
    pub fn with_load(choice: &Choice, settings: &StartSettings, load: f64) -> Self {
        let tcg = if choice.is_tcg() {
            f64::from(settings.tcg_multiplier.max(1))
        } else {
            1.0
        };
        Self {
            scale: tcg * load.max(1.0),
            guest_connect: Duration::from_secs(u64::from(settings.guest_connect_secs.max(1))),
        }
    }

    /// `base` stretched for this start.
    pub fn scaled(&self, base: Duration) -> Duration {
        base.mul_f64(self.scale)
    }

    /// How long the host waits for the guest to publish its transport.
    pub fn guest_connect(&self) -> Duration {
        self.scaled(self.guest_connect)
    }

    /// One QMP reply (5 s at KVM speed).
    pub fn qmp_reply(&self) -> Duration {
        self.scaled(Duration::from_secs(5))
    }

    /// QEMU creating its monitor socket and greeting (60 s at KVM speed).
    pub fn qmp_startup(&self) -> Duration {
        self.scaled(Duration::from_secs(60))
    }

    /// A QMP connection to a running QEMU (2 s at KVM speed).
    pub fn qmp_connect(&self) -> Duration {
        self.scaled(Duration::from_secs(2))
    }

    /// The host side of the snapshot state stream (30 s at KVM speed).
    pub fn state_socket(&self) -> Duration {
        self.scaled(Duration::from_secs(30))
    }

    /// A whole snapshot migration (300 s at KVM speed).
    pub fn migration(&self) -> Duration {
        self.scaled(Duration::from_secs(300))
    }

    /// How long a silent guest is still taken for alive, milliseconds.
    pub fn guest_health_ms(&self) -> i32 {
        i32::try_from(self.scaled(Duration::from_secs(30)).as_millis()).unwrap_or(i32::MAX)
    }

    /// A guest answering a resume or reconnect request (10 s at KVM speed).
    pub fn resume_ms(&self) -> i32 {
        i32::try_from(self.scaled(Duration::from_secs(10)).as_millis()).unwrap_or(i32::MAX)
    }

    /// The same, for the transport's own handshake after the guest is up.
    pub fn guest_connect_ms(&self) -> i32 {
        i32::try_from(self.guest_connect().as_millis()).unwrap_or(i32::MAX)
    }

    /// The factor over KVM speed, for messages.
    pub fn factor(&self) -> f64 {
        self.scale
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch(acceleration: VmAcceleration) -> VmLaunchOptions {
        VmLaunchOptions {
            acceleration,
            ..VmLaunchOptions::default()
        }
    }

    fn missing() -> Option<String> {
        Some("cannot open /dev/kvm: No such file or directory (os error 2)".into())
    }

    #[test]
    fn default_without_kvm_falls_back_to_tcg_with_the_reason() {
        let choice = choose_with(
            &BackendOptions::default(),
            &launch(VmAcceleration::Default),
            missing,
        )
        .unwrap();
        assert_eq!(choice.accelerator, Accelerator::Tcg);
        let warning = choice.fallback_warning("Lab").unwrap();
        assert!(warning.starts_with("KVM is not available on this host (cannot open /dev/kvm"));
        assert!(warning.contains("Lab runs with TCG software emulation"));
        assert!(warning.contains("much slower"));
        assert_eq!(choice.record(), "tcg (KVM unavailable)");
    }

    #[test]
    fn default_with_kvm_uses_kvm_and_explicit_tcg_never_probes() {
        let kvm = choose_with(
            &BackendOptions::default(),
            &launch(VmAcceleration::Default),
            || None,
        )
        .unwrap();
        assert_eq!((kvm.accelerator, kvm.fallback), (Accelerator::Kvm, None));
        let tcg = choose_with(
            &BackendOptions::default(),
            &launch(VmAcceleration::Tcg),
            || unreachable!("explicit TCG needs no probe"),
        )
        .unwrap();
        assert_eq!((tcg.accelerator, tcg.fallback), (Accelerator::Tcg, None));
        let forced = BackendOptions {
            force_tcg: true,
            ..BackendOptions::default()
        };
        let choice = choose_with(&forced, &launch(VmAcceleration::Kvm), || {
            unreachable!("the override needs no probe")
        })
        .unwrap();
        assert!(choice.is_tcg() && choice.fallback.is_none());
    }

    #[test]
    fn explicit_kvm_without_kvm_refuses_unless_the_app_setting_allows_tcg() {
        let error = choose_with(
            &BackendOptions::default(),
            &launch(VmAcceleration::Kvm),
            missing,
        )
        .unwrap_err();
        assert!(error.contains("KVM is not available on this host"));
        assert!(error.contains("Use TCG for this VM"));
        assert!(error.contains("Use TCG when KVM is unavailable"));
        let mut options = BackendOptions::default();
        options.start.kvm_fallback = true;
        let choice = choose_with(&options, &launch(VmAcceleration::Kvm), missing).unwrap();
        assert!(choice.is_tcg() && choice.fallback.is_some());
    }

    #[test]
    fn host_cpu_model_cannot_fall_back() {
        let mut launch = launch(VmAcceleration::Default);
        launch.cpu_model = VmCpuModel::Host;
        let error = choose_with(&BackendOptions::default(), &launch, missing).unwrap_err();
        assert!(error.contains("host CPU model needs KVM"));
    }

    #[test]
    fn a_device_that_is_absent_or_unreadable_is_a_problem() {
        let directory = std::env::temp_dir().join(format!("ant-accel-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let absent = directory.join("kvm");
        assert!(kvm_problem_at(&absent).unwrap().contains("No such file"));
        std::fs::write(&absent, b"").unwrap();
        assert!(kvm_problem_at(&absent).is_none());
        // A directory opens for reading but not for writing.
        assert!(kvm_problem_at(&directory).is_some());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn waits_scale_with_the_accelerator_and_the_load() {
        let settings = StartSettings::default();
        let kvm = Choice {
            accelerator: Accelerator::Kvm,
            fallback: None,
        };
        let tcg = Choice {
            accelerator: Accelerator::Tcg,
            fallback: None,
        };
        let fast = Waits::with_load(&kvm, &settings, 1.0);
        assert_eq!(fast.guest_connect(), Duration::from_secs(20));
        assert_eq!(fast.qmp_reply(), Duration::from_secs(5));
        let slow = Waits::with_load(&tcg, &settings, 1.0);
        assert_eq!(
            slow.guest_connect(),
            Duration::from_secs(20 * u64::from(settings.tcg_multiplier))
        );
        assert!(slow.qmp_reply() > fast.qmp_reply());
        let loaded = Waits::with_load(&tcg, &settings, 2.0);
        assert_eq!(loaded.guest_connect(), slow.guest_connect() * 2);
        assert_eq!(load_scale(16.0, 8), 2.0);
        assert_eq!(load_scale(2.0, 8), 1.0);
        assert_eq!(load_scale(500.0, 8), LOAD_SCALE_CAP);
        assert_eq!(load_scale(f64::NAN, 8), 1.0);
    }

    #[test]
    fn a_larger_multiplier_gives_the_user_more_time() {
        let tcg = Choice {
            accelerator: Accelerator::Tcg,
            fallback: None,
        };
        let more = StartSettings {
            tcg_multiplier: 40,
            ..StartSettings::default()
        };
        assert_eq!(
            Waits::with_load(&tcg, &more, 1.0).guest_connect(),
            Duration::from_secs(800)
        );
    }
}
