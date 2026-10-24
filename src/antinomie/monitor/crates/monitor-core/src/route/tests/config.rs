//! The saved route settings and the checked form of each route.
use super::{no_data, scratch};
use crate::route::{
    InetSimMode, RouteConfig, RouteKind, TorConfig, TorMode, load_config, save_config, tool_on_path,
};
use std::os::unix::fs::PermissionsExt;

#[test]
fn the_defaults_are_valid_and_every_route_that_needs_nothing_is_ready() {
    let config = RouteConfig::default();
    config.validate().unwrap();
    assert_eq!(config.default_route, RouteKind::Drop);
    for kind in [RouteKind::Drop, RouteKind::Internet, RouteKind::InetSim] {
        assert_eq!(config.spec(no_data(), kind).unwrap().kind, kind);
        assert_eq!(config.setup_problem(kind), None);
    }
    assert!(config.setup_problem(RouteKind::Vpn).is_some());
    assert!(config.setup_problem(RouteKind::Socks5).is_some());
}

#[test]
fn bad_settings_are_refused_with_a_reason() {
    let check = |edit: &dyn Fn(&mut RouteConfig), needle: &str| {
        let mut config = RouteConfig::default();
        edit(&mut config);
        let error = config.validate().unwrap_err();
        assert!(error.contains(needle), "{error} does not mention {needle}");
        assert!(
            config.spec(no_data(), RouteKind::Drop).is_err(),
            "nothing resolves from bad settings"
        );
    };
    let socks = |c: &mut RouteConfig, text: &str| {
        c.tor.mode = TorMode::Socks;
        c.tor.socks = text.into();
    };
    check(&|c| socks(c, "no-port"), "Tor SOCKS address");
    check(&|c| socks(c, "127.0.0.1:0"), "no valid port");
    check(&|c| socks(c, "bad host:9050"), "not a host name");
    check(&|c| c.tor.probe = "nonsense".into(), "check target");
    check(&|c| c.vpn.probe = "x:99999".into(), "check target");
    check(
        &|c| {
            c.socks5.host = "proxy.example".into();
            c.socks5.port = 0;
        },
        "port",
    );
    check(&|c| c.socks5.host = "a b".into(), "SOCKS5 host");
    check(
        &|c| c.socks5.username = "me".into(),
        "both a user name and a password",
    );
    check(
        &|c| c.socks5.password = "pw".into(),
        "both a user name and a password",
    );
    check(
        &|c| {
            c.socks5.username = "u".repeat(256);
            c.socks5.password = "p".into();
        },
        "255 bytes",
    );
    check(
        &|c| {
            c.socks5.username = "u\0".into();
            c.socks5.password = "p".into();
        },
        "NUL",
    );
    check(&|c| c.inetsim.sinkhole = "not-an-ip".into(), "sinkhole");
    check(
        &|c| {
            c.inetsim.mode = InetSimMode::External;
            c.inetsim.host = "bad host".into();
        },
        "InetSim host",
    );
}

#[test]
fn routes_that_need_setup_say_what_is_missing() {
    let config = RouteConfig::default();
    let error = config.spec(no_data(), RouteKind::Socks5).unwrap_err();
    assert!(
        error.contains("SOCKS5") && error.contains("host"),
        "{error}"
    );
    let error = config.spec(no_data(), RouteKind::Vpn).unwrap_err();
    assert!(error.contains("wireproxy configuration"), "{error}");
    let dir = scratch("vpn-spec");
    let mut config = RouteConfig::default();
    config.vpn.config = dir.join("missing.conf").display().to_string();
    assert!(
        config
            .spec(no_data(), RouteKind::Vpn)
            .unwrap_err()
            .contains("missing.conf")
    );
    // A configuration without a [Socks5] section cannot be a route.
    let plain = dir.join("wp.conf");
    std::fs::write(&plain, "[Interface]\nPrivateKey = x\n").unwrap();
    config.vpn.config = plain.display().to_string();
    assert!(
        config
            .spec(no_data(), RouteKind::Vpn)
            .unwrap_err()
            .contains("[Socks5]")
    );
    // With the section, the program must exist.
    std::fs::write(
        &plain,
        "[Interface]\nPrivateKey = x\n[Socks5]\nBindAddress = 127.0.0.1:25344 # c\n",
    )
    .unwrap();
    config.vpn.wireproxy = dir.join("nope").display().to_string();
    assert!(
        config
            .spec(no_data(), RouteKind::Vpn)
            .unwrap_err()
            .contains("is not a file")
    );
    let program = dir.join("wireproxy");
    std::fs::write(&program, "#!/bin/sh\n").unwrap();
    config.vpn.wireproxy = program.display().to_string();
    let spec = config.spec(no_data(), RouteKind::Vpn).unwrap();
    assert_eq!(spec.wireproxy.as_ref().unwrap().binary, program);
    assert!(spec.label.contains("127.0.0.1:25344"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn settings_are_saved_owner_only_and_come_back() {
    let dir = scratch("save");
    assert_eq!(load_config(&dir).unwrap(), RouteConfig::default());
    let mut config = RouteConfig {
        default_route: RouteKind::InetSim,
        ..RouteConfig::default()
    };
    config.socks5.host = "proxy.example".into();
    config.socks5.username = "me".into();
    config.socks5.password = "hunter2".into();
    save_config(&dir, &config).unwrap();
    let file = dir.join("network").join("routes.json");
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(file.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(load_config(&dir).unwrap(), config);
    // Invalid settings are not written.
    config.tor.mode = TorMode::Socks;
    config.tor.socks = "x".into();
    assert!(save_config(&dir, &config).is_err());
    assert_eq!(load_config(&dir).unwrap().tor, TorConfig::default());
    // A damaged file is an error, never silently the defaults.
    std::fs::write(&file, b"{broken").unwrap();
    assert!(load_config(&dir).is_err());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_password_is_never_printed() {
    let mut config = RouteConfig::default();
    config.socks5.host = "proxy.example".into();
    config.socks5.username = "someone".into();
    config.socks5.password = "hunter2".into();
    let printed = format!(
        "{config:?} {:?}",
        config.spec(no_data(), RouteKind::Socks5).unwrap()
    );
    assert!(!printed.contains("hunter2"), "{printed}");
    assert!(!printed.contains("someone"), "{printed}");
    // The label, which ends up in run records, has the host and port only.
    let spec = config.spec(no_data(), RouteKind::Socks5).unwrap();
    assert_eq!(spec.label, "SOCKS5 proxy proxy.example:1080");
}

#[test]
fn tools_are_looked_up_on_path_only() {
    assert!(tool_on_path("sh").is_some());
    assert!(tool_on_path("definitely-not-installed-xyz").is_none());
}

/// An installed Antinomie copy of `id`, as the managed-tools installer leaves it.
fn install_managed(data: &std::path::Path, id: &str, entry: &str) -> std::path::PathBuf {
    let tool = crate::analysis_tools::tools_dir(data).join(id);
    let program = tool.join(entry);
    std::fs::create_dir_all(program.parent().unwrap()).unwrap();
    std::fs::write(&program, "#!/bin/sh\n").unwrap();
    std::fs::write(
        tool.join("tool.json"),
        format!(r#"{{"id":"{id}","version":"1"}}"#),
    )
    .unwrap();
    program
}

#[test]
fn the_own_tor_route_needs_no_socks_address_and_uses_the_programs_in_order() {
    let data = scratch("tor-spec");
    let mut config = RouteConfig::default();
    // The default is Antinomie's own tor.
    assert_eq!(config.tor.mode, TorMode::Own);
    // A bad SOCKS address does not matter while the mode does not use it.
    config.tor.socks = "no-port".into();
    config.validate().unwrap();
    // PATH and the system's places are searched, so pin them to nothing: a
    // path set in Settings wins over everything and must be a file.
    config.tor.program = data.join("missing").display().to_string();
    let error = config.spec(&data, RouteKind::Tor).unwrap_err();
    assert!(error.contains("not a file"), "{error}");
    let own = data.join("my-tor");
    std::fs::write(&own, "#!/bin/sh\n").unwrap();
    config.tor.program = own.display().to_string();
    let spec = config.spec(&data, RouteKind::Tor).unwrap();
    let launch = spec.tor.clone().unwrap();
    assert_eq!(launch.binary, own);
    assert_eq!(
        launch.lib_dir, None,
        "a program of the user's keeps its own libraries"
    );
    assert_eq!(launch.state_root, data.join("network").join("tor"));
    assert!(spec.label.contains("started by Antinomie"));
    // No credentials, and a placeholder port until tor starts.
    assert!(spec.wireproxy.is_none());
    let mut spec = spec;
    spec.set_socks_port(41_000);
    assert!(format!("{spec:?}").contains("41000"));

    // Settings > "use this SOCKS address" is the old behaviour, with no tor.
    config.tor.mode = TorMode::Socks;
    config.tor.socks = "127.0.0.1:9050".into();
    let spec = config.spec(&data, RouteKind::Tor).unwrap();
    assert!(spec.tor.is_none());
    assert_eq!(spec.label, "Tor via 127.0.0.1:9050");
    let _ = std::fs::remove_dir_all(data);
}

#[test]
fn an_installed_tor_and_wireproxy_are_used_when_nothing_else_is_set() {
    let data = scratch("managed-spec");
    let tor = install_managed(&data, "tor", "tor/tor");
    let wireproxy = install_managed(&data, "wireproxy", "wireproxy");
    let mut config = RouteConfig::default();
    // The system's copies come first, so this only holds on a machine
    // without them; skip the check that would name the system's path then.
    let system_tor = tool_on_path("tor").is_some()
        || crate::analysis_tools::TOR_SYSTEM
            .iter()
            .any(|p| std::path::Path::new(p).is_file());
    if !system_tor {
        let launch = config.spec(&data, RouteKind::Tor).unwrap().tor.unwrap();
        assert_eq!(launch.binary, tor);
        // The bundle's libraries sit next to its tor, its geoip files in data/.
        assert_eq!(launch.lib_dir, Some(tor.parent().unwrap().to_path_buf()));
        assert_eq!(
            launch.geoip_dir,
            Some(crate::analysis_tools::tools_dir(&data).join("tor/data"))
        );
    }
    let conf = data.join("wp.conf");
    std::fs::write(&conf, "[Socks5]\nBindAddress = 127.0.0.1:25344\n").unwrap();
    config.vpn.config = conf.display().to_string();
    if tool_on_path("wireproxy").is_none()
        && !crate::analysis_tools::WIREPROXY_SYSTEM
            .iter()
            .any(|p| std::path::Path::new(p).is_file())
    {
        let spec = config.spec(&data, RouteKind::Vpn).unwrap();
        assert_eq!(spec.wireproxy.unwrap().binary, wireproxy);
    }
    // Without the install the route says how to get the program.
    let empty = scratch("managed-none");
    if !system_tor {
        let error = config.spec(&empty, RouteKind::Tor).unwrap_err();
        assert!(error.contains("Settings > Network routes"), "{error}");
    }
    let _ = std::fs::remove_dir_all(data);
    let _ = std::fs::remove_dir_all(empty);
}
