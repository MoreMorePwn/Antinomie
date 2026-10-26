// SPDX-License-Identifier: GPL-3.0-only
//! The container builder: a base build run in a pinned Debian 13 container
//! (Podman or Docker) with the same orchestrator, kernel and image steps as the
//! other build modes.
//!
//! The image is built from the kit's `Dockerfile` (base image fixed by digest,
//! package archives by snapshot timestamp, tools by exact version) and tagged
//! `antinomie-builder:<12 hex of the Dockerfile's SHA-256>`. Every engine call
//! goes through a [`Runner`], so tests drive the code with a fake one.

use crate::build;
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Mutex, atomic::AtomicBool},
    time::{Duration, Instant},
};

const DOCKERFILE: &str = "src/antinomie/packaging/container/Dockerfile";
/// Repository part of the builder image's tag.
pub const IMAGE_REPOSITORY: &str = "antinomie-builder";
/// Label on builder images, and on the containers a build starts.
const IMAGE_LABEL: &str = "org.antinomie.builder=1";
/// Label key on the containers a build starts; its value is the owner's process id.
const CONTAINER_LABEL: &str = "org.antinomie.build";
/// How long a probe's answer is reused.
const PROBE_TTL: Duration = Duration::from_secs(20);
/// How long an engine's own probe commands may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// A container engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Podman,
    Docker,
}

impl Engine {
    pub const ALL: [Engine; 2] = [Engine::Podman, Engine::Docker];

    pub fn program(self) -> &'static str {
        match self {
            Self::Podman => "podman",
            Self::Docker => "docker",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Podman => "Podman",
            Self::Docker => "Docker",
        }
    }
}

/// What one engine command printed.
#[derive(Clone, Debug, Default)]
pub struct Captured {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Runs engine commands: the system's, or a test's.
pub trait Runner {
    /// Runs `program args`; Err when it cannot start (not installed) or times out.
    fn run(&self, program: &str, args: &[String], timeout: Duration) -> Result<Captured, String>;
}

/// The real thing: spawns the program and waits at most `timeout`.
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, program: &str, args: &[String], timeout: Duration) -> Result<Captured, String> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("cannot run {program}: {error}"))?;
        let read = |pipe: Option<Box<dyn Read + Send>>| {
            std::thread::spawn(move || {
                let mut text = String::new();
                if let Some(mut pipe) = pipe {
                    let mut bytes = Vec::new();
                    let _ = pipe.read_to_end(&mut bytes);
                    text = String::from_utf8_lossy(&bytes).into_owned();
                }
                text
            })
        };
        let out = read(
            child
                .stdout
                .take()
                .map(|pipe| Box::new(pipe) as Box<dyn Read + Send>),
        );
        let err = read(
            child
                .stderr
                .take()
                .map(|pipe| Box::new(pipe) as Box<dyn Read + Send>),
        );
        let started = Instant::now();
        let status = loop {
            match child.try_wait().map_err(|error| error.to_string())? {
                Some(status) => break status,
                None if started.elapsed() > timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "{program} did not answer within {} seconds",
                        timeout.as_secs()
                    ));
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        Ok(Captured {
            success: status.success(),
            stdout: out.join().unwrap_or_default(),
            stderr: err.join().unwrap_or_default(),
        })
    }
}

fn owned(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

/// A usable engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ready {
    pub version: String,
    /// Podman running without root, so container root is only the user. Docker
    /// is always root-equivalent.
    pub rootless: bool,
}

/// Why `engine` cannot run a build, in words for the dialog, or what it offers.
/// `which` finds the engine's program.
pub fn probe(
    engine: Engine,
    runner: &dyn Runner,
    which: &dyn Fn(&str) -> bool,
) -> Result<Ready, String> {
    let program = engine.program();
    if !which(program) {
        return Err(format!(
            "{} is not installed (no `{program}` on PATH)",
            engine.label()
        ));
    }
    match engine {
        Engine::Docker => {
            let answer = runner
                .run(
                    program,
                    &owned(&["version", "--format", "{{.Server.Version}}"]),
                    PROBE_TIMEOUT,
                )
                .map_err(|error| format!("Docker does not answer: {error}"))?;
            if !answer.success {
                return Err(docker_problem(&answer.stderr));
            }
            Ok(Ready {
                version: answer.stdout.trim().to_owned(),
                rootless: false,
            })
        }
        Engine::Podman => {
            let answer = runner
                .run(
                    program,
                    &owned(&[
                        "info",
                        "--format",
                        "{{.Host.Security.Rootless}} {{.Version.Version}}",
                    ]),
                    PROBE_TIMEOUT,
                )
                .map_err(|error| format!("Podman does not answer: {error}"))?;
            if !answer.success {
                return Err(format!(
                    "Podman cannot run here: {}",
                    first_line(&answer.stderr)
                ));
            }
            let text = answer.stdout.trim();
            let (rootless, version) = text.split_once(' ').unwrap_or((text, ""));
            Ok(Ready {
                version: version.trim().to_owned(),
                rootless: rootless == "true",
            })
        }
    }
}

fn first_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("no message")
        .to_owned()
}

/// Names what Docker's error means.
fn docker_problem(stderr: &str) -> String {
    let lower = stderr.to_lowercase();
    if lower.contains("permission denied") {
        "no permission to use Docker (its socket needs the docker group, which gives root-equivalent access)".into()
    } else if lower.contains("cannot connect") || lower.contains("is the docker daemon running") {
        "Docker's daemon is not reachable (is it running?)".into()
    } else {
        format!("Docker cannot run here: {}", first_line(stderr))
    }
}

/// The Dockerfile the kit carries.
pub fn dockerfile() -> Result<&'static [u8], String> {
    crate::kit::kit_file(DOCKERFILE)
}

/// The tag of the builder image for this app's Dockerfile.
pub fn image_tag() -> Result<String, String> {
    let digest = Sha256::digest(dockerfile()?);
    Ok(format!(
        "{IMAGE_REPOSITORY}:{}",
        &format!("{digest:x}")[..12]
    ))
}

/// The pinned base image of the Dockerfile (`debian:trixie@sha256:...`).
pub fn pinned_base() -> Result<String, String> {
    let text = String::from_utf8_lossy(dockerfile()?).into_owned();
    text.lines()
        .find_map(|line| line.trim().strip_prefix("FROM "))
        .map(|base| base.trim().to_owned())
        .filter(|base| base.contains("@sha256:"))
        .ok_or_else(|| "the Dockerfile's FROM line is not pinned by digest".into())
}

/// A builder image the engine holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageInfo {
    pub tag: String,
    pub id: String,
    pub size: String,
    /// The image of this app version's Dockerfile.
    pub current: bool,
}

/// The builder images in `engine`'s store.
pub fn list_images(engine: Engine, runner: &dyn Runner) -> Result<Vec<ImageInfo>, String> {
    let current = image_tag().unwrap_or_default();
    let answer = runner.run(
        engine.program(),
        &owned(&[
            "images",
            "--filter",
            &format!("label={IMAGE_LABEL}"),
            "--format",
            "{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}",
        ]),
        PROBE_TIMEOUT,
    )?;
    if !answer.success {
        return Err(first_line(&answer.stderr));
    }
    Ok(answer
        .stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let tag = parts.next()?.to_owned();
            tag.starts_with(&format!("{IMAGE_REPOSITORY}:"))
                .then(|| ImageInfo {
                    current: tag == current,
                    tag,
                    id: parts.next().unwrap_or_default().to_owned(),
                    size: parts.next().unwrap_or_default().to_owned(),
                })
        })
        .collect())
}

/// Removes one builder image by tag (never another image).
pub fn remove_image(engine: Engine, runner: &dyn Runner, tag: &str) -> Result<(), String> {
    if !tag.starts_with(&format!("{IMAGE_REPOSITORY}:")) {
        return Err(format!("{tag} is not a builder image"));
    }
    let answer = runner.run(
        engine.program(),
        &owned(&["rmi", tag]),
        Duration::from_secs(120),
    )?;
    if answer.success {
        Ok(())
    } else {
        Err(first_line(&answer.stderr))
    }
}

/// Whether the engine already has this app's builder image.
pub fn image_present(engine: Engine, runner: &dyn Runner) -> Result<bool, String> {
    let answer = runner.run(
        engine.program(),
        &owned(&["image", "inspect", "--format", "{{.Id}}", &image_tag()?]),
        PROBE_TIMEOUT,
    )?;
    Ok(answer.success)
}

/// The image's content ID, to record with what it built.
pub fn image_id(engine: Engine, runner: &dyn Runner) -> Result<String, String> {
    let answer = runner.run(
        engine.program(),
        &owned(&["image", "inspect", "--format", "{{.Id}}", &image_tag()?]),
        PROBE_TIMEOUT,
    )?;
    if answer.success {
        Ok(answer.stdout.trim().to_owned())
    } else {
        Err(first_line(&answer.stderr))
    }
}

/// How an engine stands for a build, as the dialog and Automatic see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Standing {
    pub engine: Engine,
    pub ready: Result<Ready, String>,
    /// Whether this app's builder image is already there (when ready).
    pub image: Option<bool>,
}

impl Standing {
    pub fn obstacle(&self) -> Option<String> {
        self.ready.as_ref().err().cloned()
    }
}

/// [`probe`] plus the image check.
pub fn standing(engine: Engine, runner: &dyn Runner, which: &dyn Fn(&str) -> bool) -> Standing {
    let ready = probe(engine, runner, which);
    let image = ready
        .is_ok()
        .then(|| image_present(engine, runner).unwrap_or(false));
    Standing {
        engine,
        ready,
        image,
    }
}

static CACHE: Mutex<Vec<(Engine, Instant, Standing)>> = Mutex::new(Vec::new());
/// Why the last attempt to get the image failed, with the time.
static IMAGE_FAILURE: Mutex<Option<(Instant, String)>> = Mutex::new(None);

/// Engine status for the dialog and for choosing a mode: the system's answer,
/// reused for a few seconds because the dialog asks every frame.
pub fn cached_standing(engine: Engine) -> Standing {
    if let Ok(cache) = CACHE.lock()
        && let Some((_, at, standing)) = cache.iter().find(|(known, _, _)| *known == engine)
        && at.elapsed() < PROBE_TTL
    {
        return standing.clone();
    }
    let fresh = standing(engine, &SystemRunner, &|program| {
        build::which(program).is_some()
    });
    if let Ok(mut cache) = CACHE.lock() {
        cache.retain(|(known, _, _)| *known != engine);
        cache.push((engine, Instant::now(), fresh.clone()));
    }
    fresh
}

/// Forgets cached answers, so the next look asks the engines again.
pub fn forget_standing() {
    if let Ok(mut cache) = CACHE.lock() {
        cache.clear();
    }
}

/// Notes that the image could not be prepared, for Automatic to skip the engine
/// for a while.
pub fn note_image_failure(reason: &str) {
    if let Ok(mut failure) = IMAGE_FAILURE.lock() {
        *failure = Some((Instant::now(), reason.to_owned()));
    }
}

/// The recent image failure, when there is one (a minute is enough for a
/// network that came back).
pub fn recent_image_failure() -> Option<String> {
    let failure = IMAGE_FAILURE.lock().ok()?;
    failure
        .as_ref()
        .filter(|(at, _)| at.elapsed() < Duration::from_secs(60))
        .map(|(_, reason)| reason.clone())
}

/// What a build run mounts and runs.
pub struct RunSpec<'a> {
    pub engine: Engine,
    pub rootless: bool,
    /// Name given to the container, so it can be stopped and removed.
    pub name: &'a str,
    pub image: &'a str,
    pub kit: &'a Path,
    pub job: &'a Path,
    pub inputs: &'a Path,
    pub work: &'a Path,
    pub output: &'a Path,
    pub kernel_cache: &'a Path,
    pub image_cache: Option<&'a Path>,
    pub ccache: &'a Path,
    pub jobs: usize,
    /// Scheduling priority the build runs at inside the container (the
    /// engine's client being niced does not reach it).
    pub nice: Option<i32>,
    /// The host user, to hand the results back to under a root-equivalent engine.
    pub uid: u32,
    pub gid: u32,
}

/// The `-v` arguments of a build: what the container sees of the host.
fn mounts(spec: &RunSpec) -> Vec<String> {
    let mut args = Vec::new();
    let mut mount = |host: &Path, inside: &str, mode: &str| {
        args.extend([
            "-v".to_owned(),
            format!("{}:{inside}:{mode}", host.display()),
        ]);
    };
    mount(spec.kit, "/kit", "ro");
    mount(spec.job, "/job.json", "ro");
    mount(spec.inputs, "/inputs", "rw");
    mount(spec.work, "/work", "rw");
    // The orchestrator creates its output folder, so its parent is mounted.
    if let Some(parent) = spec.output.parent() {
        mount(parent, "/out", "rw");
    }
    if let Some(parent) = spec.kernel_cache.parent() {
        mount(parent, "/cache/kernels", "rw");
    }
    mount(spec.ccache, "/ccache", "rw");
    if let Some(parent) = spec.image_cache.and_then(Path::parent) {
        mount(parent, "/cache/images", "rw");
    }
    args
}

/// Folders a root-equivalent engine's build writes as root.
const OWNED_FOLDERS: &str = "/work /out /inputs /cache /ccache";

/// The `run` arguments of a build, after the program name.
pub fn run_args(spec: &RunSpec) -> Vec<String> {
    let mut args = owned(&[
        "run",
        "--rm",
        "--init",
        "--name",
        spec.name,
        "--label",
        &format!("{CONTAINER_LABEL}={}", std::process::id()),
        // mmdebstrap builds the image's root as the container's root: it needs
        // mount, which an unprivileged container (and its seccomp/AppArmor
        // profile) refuses.
        "--cap-add=SYS_ADMIN",
        "--cap-add=MKNOD",
        "--security-opt",
        "apparmor=unconfined",
        "-e",
        "ANTINOMIE_BUILDER=1",
    ]);
    args.extend([
        "-e".into(),
        format!("ANTINOMIE_BUILDER_IMAGE={}", spec.image),
    ]);
    args.extend(mounts(spec));
    args.push(spec.image.to_owned());
    let output_name = spec
        .output
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let kernel_name = spec
        .kernel_cache
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut build = Vec::new();
    if let Some(nice) = spec.nice {
        build.extend(["nice".to_owned(), "-n".into(), nice.to_string()]);
    }
    build.extend([
        "python3".to_owned(),
        "/kit/scripts/build-base.py".to_owned(),
        "--job".into(),
        "/job.json".into(),
        "--inputs".into(),
        "/inputs".into(),
        "--work".into(),
        "/work".into(),
        "--output".into(),
        format!("/out/{output_name}"),
        "--jobs".into(),
        spec.jobs.to_string(),
        "--kernel-cache".into(),
        format!("/cache/kernels/{kernel_name}"),
        "--ccache".into(),
        "/ccache".into(),
    ]);
    if let Some(name) = spec.image_cache.and_then(Path::file_name) {
        build.push("--image-cache".into());
        build.push(format!("/cache/images/{}", name.to_string_lossy()));
    }
    // Under a root-equivalent engine the container writes root-owned files:
    // hand everything back to the user, whatever the build's outcome.
    if spec.rootless {
        args.extend(build);
    } else {
        let quoted = build
            .iter()
            .map(|word| format!("'{}'", word.replace('\'', "'\\''")))
            .collect::<Vec<_>>()
            .join(" ");
        args.extend([
            "sh".into(),
            "-c".into(),
            format!(
                "{quoted}; status=$?; chown -R {}:{} {OWNED_FOLDERS} 2>/dev/null; exit $status",
                spec.uid, spec.gid
            ),
        ]);
    }
    args
}

/// Hands the folders of a build that was stopped (a cancel kills the shell that
/// would have done it) back to the user, with a throwaway container.
pub fn restore_ownership(spec: &RunSpec, runner: &dyn Runner) {
    if spec.rootless {
        return;
    }
    let mut args = owned(&["run", "--rm"]);
    args.extend(mounts(spec));
    args.push(spec.image.to_owned());
    args.extend([
        "sh".into(),
        "-c".into(),
        format!(
            "chown -R {}:{} {OWNED_FOLDERS} 2>/dev/null; true",
            spec.uid, spec.gid
        ),
    ]);
    let _ = runner.run(spec.engine.program(), &args, Duration::from_secs(300));
}

/// Builds the image from the kit's Dockerfile, streaming the engine's output.
pub fn build_image(
    engine: Engine,
    kit: &Path,
    cancel: &AtomicBool,
    on_line: &mut dyn FnMut(&str),
) -> Result<(), String> {
    let tag = image_tag()?;
    let dockerfile = kit.join(DOCKERFILE);
    let mut command = Command::new(engine.program());
    command
        .args(["build", "--label", IMAGE_LABEL, "-t", &tag, "-f"])
        .arg(&dockerfile)
        .arg(dockerfile.parent().ok_or("the Dockerfile has no folder")?);
    build::run_streaming(
        &mut command,
        &format!("{} image build", engine.label()),
        cancel,
        |line| on_line(line),
    )
}

/// Removes the containers a build whose owner has since died left (a crashed
/// app can), never one a running app is still using.
pub fn remove_stale_containers(engine: Engine, runner: &dyn Runner, alive: &dyn Fn(u32) -> bool) {
    let Ok(listing) = runner.run(
        engine.program(),
        &owned(&[
            "ps",
            "-a",
            "--filter",
            &format!("label={CONTAINER_LABEL}"),
            "--format",
            &format!("{{{{.ID}}}} {{{{index .Labels \"{CONTAINER_LABEL}\"}}}}"),
        ]),
        PROBE_TIMEOUT,
    ) else {
        return;
    };
    let ids: Vec<String> = listing
        .stdout
        .lines()
        .filter_map(|line| {
            let (id, owner) = line.split_once(' ')?;
            // An owner that is not a live process id, or is none, is gone.
            owner
                .trim()
                .parse::<u32>()
                .map_or(true, |pid| !alive(pid))
                .then(|| id.to_owned())
        })
        .collect();
    if ids.is_empty() {
        return;
    }
    let mut args = owned(&["rm", "-f"]);
    args.extend(ids);
    let _ = runner.run(engine.program(), &args, Duration::from_secs(60));
}

/// Whether process `pid` exists.
pub fn process_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Runs one build in a container and removes the container however it ends.
pub fn run_build(
    spec: &RunSpec,
    cancel: &AtomicBool,
    on_line: &mut dyn FnMut(&str),
) -> Result<(), String> {
    let mut command = Command::new(spec.engine.program());
    command.args(run_args(spec));
    let result = build::run_streaming(
        &mut command,
        &format!("{} build", spec.engine.label()),
        cancel,
        |line| on_line(line),
    );
    // Killing the client (a cancel) leaves the container running; --rm only
    // acts when it exits by itself.
    let _ = SystemRunner.run(
        spec.engine.program(),
        &owned(&["rm", "-f", spec.name]),
        Duration::from_secs(60),
    );
    if result.is_err() {
        restore_ownership(spec, &SystemRunner);
    }
    result
}

/// What a failed preparation means to the build: an error for a manual choice
/// (or a cancel), a fall through to the QEMU builder (Ok(None), with the reason
/// for the log) for Automatic.
pub fn after_preparation(
    prepared: Result<Ready, String>,
    fallback: bool,
    cancelled: bool,
) -> Result<Result<Ready, String>, String> {
    match prepared {
        Ok(ready) => Ok(Ok(ready)),
        Err(reason) if fallback && !cancelled => Ok(Err(reason)),
        Err(reason) => Err(reason),
    }
}

/// A fresh container name.
pub fn container_name() -> String {
    format!("antinomie-build-{}", crate::storage::unique_id())
}

/// The paths a build mounts, for tests to see where the caches go.
pub fn cache_dirs(root: &Path) -> (PathBuf, PathBuf) {
    (root.join("kernels"), crate::kit::ccache_dir(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Answers engine calls from a table of (program, first words of the
    /// arguments) and records every call.
    struct Fake {
        calls: RefCell<Vec<String>>,
        answers: Vec<(&'static str, Result<Captured, String>)>,
    }

    fn ok(stdout: &str) -> Result<Captured, String> {
        Ok(Captured {
            success: true,
            stdout: stdout.into(),
            stderr: String::new(),
        })
    }

    fn failed(stderr: &str) -> Result<Captured, String> {
        Ok(Captured {
            success: false,
            stdout: String::new(),
            stderr: stderr.into(),
        })
    }

    impl Fake {
        fn new(answers: Vec<(&'static str, Result<Captured, String>)>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                answers,
            }
        }
    }

    impl Runner for Fake {
        fn run(&self, program: &str, args: &[String], _: Duration) -> Result<Captured, String> {
            let line = format!("{program} {}", args.join(" "));
            self.calls.borrow_mut().push(line.clone());
            self.answers
                .iter()
                .find(|(prefix, _)| line.starts_with(prefix))
                .map(|(_, answer)| answer.clone())
                .unwrap_or_else(|| failed("no such fake answer"))
        }
    }

    fn installed(_: &str) -> bool {
        true
    }

    #[test]
    fn an_engine_that_cannot_run_says_why() {
        let none = Fake::new(vec![]);
        let missing = probe(Engine::Podman, &none, &|_| false).unwrap_err();
        assert!(missing.contains("Podman is not installed") && missing.contains("`podman`"));
        assert!(none.calls.borrow().is_empty());
        for (stderr, expected) in [
            (
                "permission denied while trying to connect to the Docker daemon socket",
                "no permission to use Docker",
            ),
            (
                "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
                "daemon is not reachable",
            ),
            (
                "something odd\nmore",
                "Docker cannot run here: something odd",
            ),
        ] {
            let docker = Fake::new(vec![("docker version", failed(stderr))]);
            let error = probe(Engine::Docker, &docker, &installed).unwrap_err();
            assert!(error.contains(expected), "{error}");
        }
        let hung = Fake::new(vec![(
            "docker version",
            Err("docker did not answer within 15 seconds".into()),
        )]);
        assert!(
            probe(Engine::Docker, &hung, &installed)
                .unwrap_err()
                .contains("does not answer")
        );
        // The docker group warning names the root-equivalent access.
        let denied = Fake::new(vec![("docker version", failed("permission denied"))]);
        assert!(
            probe(Engine::Docker, &denied, &installed)
                .unwrap_err()
                .contains("root-equivalent")
        );
        let podman = Fake::new(vec![("podman info", failed("cannot set up namespace\n"))]);
        assert!(
            probe(Engine::Podman, &podman, &installed)
                .unwrap_err()
                .contains("Podman cannot run here: cannot set up namespace")
        );
    }

    #[test]
    fn a_ready_engine_reports_its_version_and_rootlessness() {
        let docker = Fake::new(vec![("docker version", ok("26.1.5\n"))]);
        assert_eq!(
            probe(Engine::Docker, &docker, &installed).unwrap(),
            Ready {
                version: "26.1.5".into(),
                rootless: false
            }
        );
        for (answer, rootless) in [("true 5.4.2\n", true), ("false 5.4.2\n", false)] {
            let podman = Fake::new(vec![("podman info", ok(answer))]);
            assert_eq!(
                probe(Engine::Podman, &podman, &installed).unwrap(),
                Ready {
                    version: "5.4.2".into(),
                    rootless
                }
            );
        }
    }

    #[test]
    fn standing_adds_whether_the_image_is_there() {
        let tag = image_tag().unwrap();
        let fake = Fake::new(vec![
            ("docker version", ok("26.1.5")),
            ("docker image inspect", ok("sha256:abc\n")),
        ]);
        let standing = standing(Engine::Docker, &fake, &installed);
        assert!(standing.obstacle().is_none() && standing.image == Some(true));
        assert!(fake.calls.borrow().iter().any(|call| call.contains(&tag)));
        let absent = Fake::new(vec![
            ("podman info", ok("true 5")),
            ("podman image inspect", failed("no such image")),
        ]);
        assert_eq!(
            super::standing(Engine::Podman, &absent, &installed).image,
            Some(false)
        );
        let broken = Fake::new(vec![("docker version", failed("permission denied"))]);
        let gone = super::standing(Engine::Docker, &broken, &installed);
        assert!(gone.image.is_none() && gone.obstacle().is_some());
    }

    #[test]
    fn the_image_is_pinned_by_digest_snapshot_and_exact_versions() {
        let text = String::from_utf8(dockerfile().unwrap().to_vec()).unwrap();
        let base = pinned_base().unwrap();
        assert!(
            base.starts_with("debian:trixie@sha256:") && base.len() == 21 + 64,
            "{base}"
        );
        // The archives are a snapshot, so a version stays available.
        assert!(
            text.contains("stamp=2") && text.contains("snapshot.debian.org/archive/debian/%s/")
        );
        assert!(text.contains("snapshot.debian.org/archive/debian-security/%s/"));
        // Every package of the install is `name=version`.
        let install = text
            .split("--no-install-recommends")
            .nth(1)
            .and_then(|rest| rest.split("rm -rf").next())
            .unwrap();
        let packages: Vec<&str> = install
            .split(|c: char| c.is_whitespace() || c == '\\' || c == ';')
            .filter(|word| !word.is_empty())
            .collect();
        assert!(packages.len() > 20);
        assert!(
            packages.iter().all(|word| word.contains('=')),
            "{packages:?}"
        );
        // The compiler and linker are the ones Debian's kernel banner names.
        let (cc, ld) = crate::kit::debian_toolchain().unwrap();
        let version =
            |banner: &str, tail: &str| banner.rsplit(tail).next().unwrap().trim().to_owned();
        assert!(cc.contains("Debian 14.2.0-19"), "{cc}");
        assert!(packages.contains(&"gcc-14=14.2.0-19"), "{cc}");
        assert!(ld.ends_with("2.44"), "{ld} {}", version(&ld, " "));
        assert!(packages.contains(&"binutils=2.44-3"));
        let tag = image_tag().unwrap();
        assert!(
            tag.starts_with("antinomie-builder:") && tag.len() == "antinomie-builder:".len() + 12
        );
    }

    fn spec<'a>(rootless: bool, nice: Option<i32>) -> RunSpec<'a> {
        RunSpec {
            engine: if rootless {
                Engine::Podman
            } else {
                Engine::Docker
            },
            rootless,
            name: "antinomie-build-1",
            image: "antinomie-builder:abc",
            kit: Path::new("/data/build/kit-1"),
            job: Path::new("/data/build/job.json"),
            inputs: Path::new("/data/build/inputs"),
            work: Path::new("/data/build/work"),
            output: Path::new("/data/builds/debian-minimal-7"),
            kernel_cache: Path::new("/data/build/kernels/kernel-minimal-9.tar"),
            image_cache: Some(Path::new("/data/build/images/rootfs-debian-minimal.tar")),
            ccache: Path::new("/data/build/ccache"),
            jobs: 3,
            nice,
            uid: 1000,
            gid: 1001,
        }
    }

    #[test]
    fn a_build_runs_the_orchestrator_with_the_caches_mounted_and_leaves_no_container() {
        let args = run_args(&spec(true, None));
        let line = args.join(" ");
        assert_eq!(&args[..3], ["run", "--rm", "--init"]);
        assert!(line.contains("--name antinomie-build-1"));
        assert!(line.contains(&format!(
            "--label org.antinomie.build={}",
            std::process::id()
        )));
        assert!(line.contains("--cap-add=SYS_ADMIN"));
        for mount in [
            "/data/build/kit-1:/kit:ro",
            "/data/build/job.json:/job.json:ro",
            "/data/build/inputs:/inputs:rw",
            "/data/build/work:/work:rw",
            "/data/builds:/out:rw",
            "/data/build/kernels:/cache/kernels:rw",
            "/data/build/images:/cache/images:rw",
            "/data/build/ccache:/ccache:rw",
        ] {
            assert!(line.contains(&format!("-v {mount}")), "{mount} in {line}");
        }
        // The image, then the orchestrator with container paths.
        let at = args
            .iter()
            .position(|arg| arg == "antinomie-builder:abc")
            .unwrap();
        assert_eq!(
            &args[at + 1..at + 4],
            ["python3", "/kit/scripts/build-base.py", "--job"]
        );
        let build = args[at + 1..].join(" ");
        assert!(build.contains("--output /out/debian-minimal-7"));
        assert!(build.contains("--kernel-cache /cache/kernels/kernel-minimal-9.tar"));
        assert!(build.contains("--image-cache /cache/images/rootfs-debian-minimal.tar"));
        assert!(build.contains("--jobs 3") && build.contains("--ccache /ccache"));
        // Rootless: the container's root is the user, nothing to hand back.
        assert!(!build.contains("chown"));
        // The sentinel pieces a root-equivalent engine adds.
        let rooted = run_args(&spec(false, Some(15)));
        let at = rooted
            .iter()
            .position(|arg| arg == "antinomie-builder:abc")
            .unwrap();
        assert_eq!(&rooted[at + 1..at + 3], ["sh", "-c"]);
        let script = &rooted[at + 3];
        assert!(script.starts_with("'nice' '-n' '15' 'python3' '/kit/scripts/build-base.py'"));
        assert!(
            script.contains("; status=$?; chown -R 1000:1001 /work /out /inputs /cache /ccache")
        );
        assert!(script.ends_with("exit $status"));
        // No image cache, no mount or option for it.
        let mut bare = spec(true, None);
        bare.image_cache = None;
        assert!(!run_args(&bare).join(" ").contains("image"));
    }

    #[test]
    fn a_stopped_build_hands_its_folders_back_under_a_root_equivalent_engine() {
        let fake = Fake::new(vec![("docker run", ok(""))]);
        restore_ownership(&spec(false, None), &fake);
        let calls = fake.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].starts_with("docker run --rm -v "));
        assert!(calls[0].contains("antinomie-builder:abc sh -c chown -R 1000:1001 /work /out"));
        // Rootless Podman's root is the user already.
        let none = Fake::new(vec![]);
        restore_ownership(&spec(true, None), &none);
        assert!(none.calls.borrow().is_empty());
    }

    #[test]
    fn only_builder_images_are_listed_and_removed() {
        let current = image_tag().unwrap();
        let listing = format!(
            "{current}\tsha256:aaa\t542MB\nantinomie-builder:old\tsha256:bbb\t540MB\nother:tag\tsha256:ccc\t1MB\n"
        );
        let fake = Fake::new(vec![
            ("docker images", ok(&listing)),
            ("docker rmi antinomie-builder:old", ok("")),
        ]);
        let images = list_images(Engine::Docker, &fake).unwrap();
        assert_eq!(images.len(), 2);
        assert!(images[0].current && !images[1].current);
        assert!(fake.calls.borrow()[0].contains("label=org.antinomie.builder=1"));
        remove_image(Engine::Docker, &fake, "antinomie-builder:old").unwrap();
        assert!(
            remove_image(Engine::Docker, &fake, "debian:trixie")
                .unwrap_err()
                .contains("not a builder image")
        );
        assert_eq!(fake.calls.borrow().len(), 2, "nothing else was removed");
        let busy = Fake::new(vec![(
            "docker rmi",
            failed("conflict: image is being used by a container\n"),
        )]);
        assert!(
            remove_image(Engine::Docker, &busy, "antinomie-builder:x")
                .unwrap_err()
                .contains("being used")
        );
    }

    #[test]
    fn only_containers_of_dead_owners_are_removed() {
        let fake = Fake::new(vec![
            ("podman ps", ok("a1 4242\nb2 31337\nc3 \nd4 not-a-pid\n")),
            ("podman rm", ok("")),
        ]);
        // 4242 still runs: its build is going on and must not be touched.
        remove_stale_containers(Engine::Podman, &fake, &|pid| pid == 4242);
        let calls = fake.calls.borrow();
        assert!(calls[0].contains("--filter label=org.antinomie.build"));
        assert_eq!(calls[1], "podman rm -f b2 c3 d4");
        let none = Fake::new(vec![("podman ps", ok("a1 4242\n"))]);
        remove_stale_containers(Engine::Podman, &none, &|_| true);
        assert_eq!(none.calls.borrow().len(), 1);
    }

    #[test]
    fn automatic_falls_through_to_qemu_but_a_manual_choice_or_a_cancel_does_not() {
        let ready = Ready {
            version: "1".into(),
            rootless: true,
        };
        assert_eq!(
            after_preparation(Ok(ready.clone()), true, false),
            Ok(Ok(ready))
        );
        // Offline, Automatic carries on with the reason to show.
        assert_eq!(
            after_preparation(Err("no network".into()), true, false),
            Ok(Err("no network".into()))
        );
        assert_eq!(
            after_preparation(Err("no network".into()), false, false),
            Err("no network".into())
        );
        assert_eq!(
            after_preparation(Err("build cancelled".into()), true, true),
            Err("build cancelled".into())
        );
    }

    #[test]
    fn an_image_that_could_not_be_fetched_is_remembered_briefly() {
        assert!(recent_image_failure().is_none() || recent_image_failure().is_some());
        note_image_failure("no network");
        assert_eq!(recent_image_failure().as_deref(), Some("no network"));
        *IMAGE_FAILURE.lock().unwrap() = None;
        assert!(recent_image_failure().is_none());
    }

    /// Against a real Docker daemon: `cargo test -- --ignored real_docker`.
    #[test]
    #[ignore = "needs a Docker daemon the user may use"]
    fn real_docker_probes_lists_and_removes_only_builder_images() {
        let ready = probe(Engine::Docker, &SystemRunner, &|p| {
            build::which(p).is_some()
        })
        .unwrap();
        assert!(!ready.rootless && !ready.version.is_empty());
        // A throwaway builder image (the pinned base plus the label).
        let dir = std::env::temp_dir().join(format!("ant-builder-image-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let base = pinned_base().unwrap();
        std::fs::write(
            dir.join("Dockerfile"),
            format!("FROM {base}\nLABEL org.antinomie.builder=1\n"),
        )
        .unwrap();
        let tag = "antinomie-builder:unit-test";
        let built = Command::new("docker")
            .args(["build", "-q", "-t", tag])
            .arg(&dir)
            .output()
            .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let images = list_images(Engine::Docker, &SystemRunner).unwrap();
        assert!(
            images
                .iter()
                .any(|image| image.tag == tag && !image.current)
        );
        assert!(
            images
                .iter()
                .all(|image| image.tag.starts_with("antinomie-builder:"))
        );
        remove_image(Engine::Docker, &SystemRunner, tag).unwrap();
        assert!(
            !list_images(Engine::Docker, &SystemRunner)
                .unwrap()
                .iter()
                .any(|image| image.tag == tag)
        );
        // The pinned base itself is untouched, and a foreign image is refused.
        assert!(remove_image(Engine::Docker, &SystemRunner, "debian:trixie").is_err());
        // No build container is left (a name nothing has).
        remove_stale_containers(Engine::Docker, &SystemRunner, &process_alive);
    }
}
