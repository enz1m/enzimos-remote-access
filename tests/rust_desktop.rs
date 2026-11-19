// SPDX-License-Identifier: MIT
use enzimos_remote_access::{desktop_grant, desktop_identity};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    net::IpAddr,
    os::unix::fs::{PermissionsExt, symlink},
};
fn grant(uid: u32) -> Value {
    json!({"schema":1,"boot_id":"boot-a","uid":uid,"nonce":"a".repeat(64),
        "interface":"enp1s0","zone":"public",
        "configuration":{"schema":1,"enabled":true,"mode":"session-sharing","listen_address":"192.0.2.4","port":5900,"allowed_networks":["192.0.2.0/24"],"view_only":true,"max_fps":30,"output":null},
        "session":{"uid":uid,"id":"c1","leader":123,"seat":"seat0","manager_owned":true,
            "compositor":{"pid":124,"start_ticks":4321,"device":1,"inode":2,"mount_namespace":[3,4]},
            "wayland":{"path":format!("/run/user/{uid}/wayland-0"),"device":5,"inode":6}}})
}
#[test]
fn run_only_grants_refuse_foreign_stale_and_loose_proofs() {
    let addresses = BTreeSet::from(["192.0.2.4".parse::<IpAddr>().unwrap()]);
    let g = grant(1000);
    assert_eq!(
        desktop_grant::validate(&g, 1000, "boot-a", &addresses).unwrap(),
        g
    );
    assert!(desktop_grant::validate(&g, 1001, "boot-a", &addresses).is_err());
    assert!(desktop_grant::validate(&g, 1000, "boot-b", &addresses).is_err());
    for (pointer, replacement) in [
        ("/schema", json!(1.0)),
        ("/uid", json!(true)),
        ("/nonce", json!("A".repeat(64))),
        ("/interface", json!("eth0\n")),
        ("/configuration/mode", json!("remote-login")),
        ("/configuration/enabled", json!(false)),
        ("/session/manager_owned", json!(1)),
        ("/session/leader", json!(1u64 << 31)),
        ("/session/compositor/pid", json!(0)),
        ("/session/compositor/mount_namespace", json!([1, 2, 3])),
        (
            "/session/wayland/path",
            json!("/run/user/1000/../1001/wayland-0"),
        ),
        ("/session/compositor/start_ticks", json!(true)),
    ] {
        let mut bad = g.clone();
        *bad.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            desktop_grant::validate(&bad, 1000, "boot-a", &addresses).is_err(),
            "{pointer}"
        );
    }
    let mut extra = g;
    extra["session"]["reusable"] = json!(true);
    assert!(desktop_grant::validate(&extra, 1000, "boot-a", &addresses).is_err());
}
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid, getuid).")]
fn private_tls_identity_persists_and_refuses_tampering() {
    let uid = unsafe { libc::getuid() };
    if uid < 1000 || uid != unsafe { libc::geteuid() } {
        return;
    }
    let root = tempfile::Builder::new()
        .prefix("desktop-identity-")
        .tempdir_in(std::path::PathBuf::from(
            std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        ))
        .unwrap();
    let directory = root.path().join("identity");
    let first = desktop_identity::ensure(&directory, uid).unwrap();
    assert_eq!(first.password().len(), 43);
    assert_eq!(first.certificate_sha256_fingerprint.len(), 64);
    let second = desktop_identity::ensure(&directory, uid).unwrap();
    assert_eq!(first.password(), second.password());
    assert_eq!(
        first.certificate_sha256_fingerprint,
        second.certificate_sha256_fingerprint
    );
    let certificate = std::fs::read(directory.join("certificate.pem")).unwrap();
    let cert = openssl::x509::X509::from_pem(&certificate).unwrap();
    assert!(
        cert.subject_alt_names()
            .unwrap()
            .iter()
            .any(|n| n.dnsname() == Some("enzimos-remote"))
    );
    assert!(
        first
            .tls_config(&directory)
            .unwrap()
            .starts_with(b"enable_auth=true\nenable_pam=false\n")
    );
    std::fs::set_permissions(
        directory.join("private-key.pem"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(desktop_identity::ensure(&directory, uid).is_err());
    std::fs::set_permissions(
        directory.join("private-key.pem"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(
        directory.join("credential.json"),
        b"{\"schema\":1,\"schema\":1}",
    )
    .unwrap();
    assert!(desktop_identity::ensure(&directory, uid).is_err());
    assert_eq!(
        std::fs::read(directory.join("certificate.pem")).unwrap(),
        certificate
    );
}
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid, getuid).")]
fn partial_and_linked_identity_never_regenerates() {
    let uid = unsafe { libc::getuid() };
    if uid < 1000 || uid != unsafe { libc::geteuid() } {
        return;
    }
    let root = tempfile::Builder::new()
        .prefix("desktop-partial-")
        .tempdir_in(std::path::PathBuf::from(
            std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        ))
        .unwrap();
    let directory = root.path().join("identity");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    symlink(
        root.path().join("missing"),
        directory.join("certificate.pem"),
    )
    .unwrap();
    assert!(desktop_identity::ensure(&directory, uid).is_err());
    assert!(!directory.join("private-key.pem").exists());
    assert!(directory.join("certificate.pem").is_symlink());
}

#[test]
fn logind_authority_requires_exact_typed_unlocked_local_session() {
    use enzimos_remote_access::desktop_session::{self, Properties};
    use zbus::zvariant::{OwnedObjectPath, Value};
    let mut p = Properties::new();
    for (key, text) in [("Id", "c1"), ("Type", "wayland"), ("Class", "user")] {
        p.insert(key.into(), Value::from(text).try_to_owned().unwrap());
    }
    p.insert(
        "User".into(),
        Value::from((
            1000u32,
            OwnedObjectPath::try_from("/org/freedesktop/login1/user/_1000").unwrap(),
        ))
        .try_to_owned()
        .unwrap(),
    );
    p.insert(
        "Seat".into(),
        Value::from((
            "seat0",
            OwnedObjectPath::try_from("/org/freedesktop/login1/seat/seat0").unwrap(),
        ))
        .try_to_owned()
        .unwrap(),
    );
    p.insert("Leader".into(), 123u32.into());
    for (key, value) in [("Active", true), ("LockedHint", false), ("Remote", false)] {
        p.insert(key.into(), value.into());
    }
    assert_eq!(
        desktop_session::session(&p, 1000, "c1").unwrap(),
        json!({"uid":1000,"id":"c1","leader":123,"seat":"seat0"})
    );
    assert!(desktop_session::session(&p, 1001, "c1").is_err());
    assert!(desktop_session::session(&p, 1000, "c2").is_err());
    let bound = grant(1000)["session"].clone();
    assert!(!desktop_session::locked(&p, &bound).unwrap());
    p.insert("LockedHint".into(), true.into());
    assert!(desktop_session::session(&p, 1000, "c1").is_err());
    assert!(desktop_session::locked(&p, &bound).unwrap());
    let mut foreign = bound.clone();
    foreign["leader"] = json!(124);
    assert!(desktop_session::locked(&p, &foreign).is_err());
    p.insert("LockedHint".into(), false.into());
    p.insert("Active".into(), 1u32.into());
    assert!(desktop_session::session(&p, 1000, "c1").is_err());
    assert!(desktop_session::locked(&p, &bound).is_err());
}

#[test]
fn native_unit_requires_paired_worker_and_listener_lifetime_properties() {
    use enzimos_remote_access::{desktop_unit_trust as trust, system::Properties};
    use zbus::zvariant::Value;
    let mut unit = Properties::new();
    for (key, text) in [
        ("Id", "enzimos-desktop-sharing@1000.service"),
        ("ActiveState", "inactive"),
        ("FragmentPath", trust::TEMPLATE),
    ] {
        unit.insert(key.into(), Value::from(text).try_to_owned().unwrap());
    }
    unit.insert("Transient".into(), false.into());
    unit.insert(
        "DropInPaths".into(),
        Value::from(Vec::<String>::new()).try_to_owned().unwrap(),
    );
    let mut service = Properties::new();
    for (key, text) in [
        (
            "ControlGroup",
            "/system.slice/enzimos-desktop-sharing@1000.service",
        ),
        ("User", "1000"),
        ("KillMode", "control-group"),
        ("Restart", "no"),
        ("FileDescriptorStorePreserve", "yes"),
        ("NotifyAccess", "exec"),
    ] {
        service.insert(key.into(), Value::from(text).try_to_owned().unwrap());
    }
    for (key, value) in [
        ("MainPID", 0u32),
        ("ControlPID", 0),
        ("NFileDescriptorStore", 0),
        ("FileDescriptorStoreMax", 1),
    ] {
        service.insert(key.into(), value.into());
    }
    service.insert(
        "ExecStart".into(),
        Value::from(vec![(
            trust::WORKER,
            vec![trust::WORKER],
            false,
            0u64,
            0u64,
            0u64,
            0u64,
            0u32,
            0i32,
            0i32,
        )])
        .try_to_owned()
        .unwrap(),
    );
    trust::validate(&unit, &service, 1000).unwrap();
    let group = service.remove("ControlGroup").unwrap();
    service.insert(
        "ControlGroup".into(),
        Value::from("").try_to_owned().unwrap(),
    );
    trust::validate(&unit, &service, 1000).unwrap();
    service.insert("ControlPID".into(), 123u32.into());
    assert!(trust::validate(&unit, &service, 1000).is_err());
    service.insert("ControlPID".into(), 0u32.into());
    service.insert("ControlGroup".into(), group);
    for (key, wrong) in [
        ("Restart", "always"),
        ("NotifyAccess", "all"),
        ("FileDescriptorStorePreserve", "no"),
        ("KillMode", "process"),
        ("User", "root"),
    ] {
        let original = service.remove(key).unwrap();
        service.insert(key.into(), Value::from(wrong).try_to_owned().unwrap());
        assert!(trust::validate(&unit, &service, 1000).is_err(), "{key}");
        service.insert(key.into(), original);
    }
    service.insert(
        "ExecStart".into(),
        Value::from(vec![(
            "/usr/bin/python3",
            vec![
                "/usr/bin/python3",
                "-I",
                "/usr/lib/enzimos-remote/desktop-worker-entry.py",
            ],
            false,
            0u64,
            0u64,
            0u64,
            0u64,
            0u32,
            0i32,
            0i32,
        )])
        .try_to_owned()
        .unwrap(),
    );
    assert!(trust::validate(&unit, &service, 1000).is_err());
    assert_eq!(
        enzimos_remote_access::compositor_grant::body(1000, true).unwrap(),
        b"uid=1000\ncgroup=/system.slice/enzimos-desktop-sharing@1000.service\nkinds=capture\n"
    );
    assert!(enzimos_remote_access::compositor_grant::body(0, false).is_err());
}

#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid, getuid).")]
fn user_owned_system_credential_requires_read_only_mount_and_single_link() {
    let uid = unsafe { libc::getuid() };
    if uid < 1000 || uid != unsafe { libc::geteuid() } {
        return;
    }
    let root = tempfile::Builder::new()
        .prefix("desktop-credential-")
        .tempdir_in(std::path::PathBuf::from(
            std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        ))
        .unwrap();
    let path = root.path().join("desktop-config");
    std::fs::write(&path, b"{}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    let error = enzimos_remote_access::desktop_credential::read(&path, uid).unwrap_err();
    assert_eq!(error.0, "desktop-system-credential-writable-mount");
    std::fs::hard_link(&path, root.path().join("link")).unwrap();
    assert_eq!(
        enzimos_remote_access::desktop_credential::read(&path, uid)
            .unwrap_err()
            .0,
        "desktop-system-credential-permissions"
    );
}

#[test]
fn authenticated_viewer_status_refuses_ambiguous_and_hostile_provider_replies() {
    // Client status comes from the provider's authenticated-client API and must
    // preserve uncertainty instead of accepting ambiguous or unbounded replies.
    let reply =
        json!({"id":1,"code":0,"data":[{"id":"3","address":"192.0.2.8","username":"viewer"}]});
    let observed = enzimos_remote_access::desktop_viewers::clients(&reply).unwrap();
    assert_eq!(observed["connected_count"], 1);
    assert_eq!(observed["clients"][0]["address"], "192.0.2.8");
    for bad in [
        json!({"id":2,"code":0,"data":[]}),
        json!({"id":1,"code":1,"data":[]}),
        json!({"id":1,"code":0,"data":[{"id":"1"},{"id":"1"}]}),
        json!({"id":1,"code":0,"data":[{"id":"1","username":"viewer\nspoof"}]}),
    ] {
        assert!(enzimos_remote_access::desktop_viewers::clients(&bad).is_err());
    }
}
#[test]
fn worker_launch_has_exact_encrypted_arguments_and_no_secret_arguments() {
    let configuration = grant(1000)["configuration"].clone();
    let directory = std::path::Path::new("/run/user/1000/enzimos-sharing/0123456789abcdef");
    let args =
        enzimos_remote_access::desktop_worker::command(&configuration, directory, 64).unwrap();
    assert_eq!(
        args,
        [
            "--config=/run/user/1000/enzimos-sharing/0123456789abcdef/wayvnc.conf",
            "--socket=/run/user/1000/enzimos-sharing/0123456789abcdef/control.sock",
            "--log-level=error",
            "--max-fps=30",
            "--disable-resizing",
            "--disable-input",
            "fd:64"
        ]
    );
    assert!(enzimos_remote_access::desktop_worker::command(&configuration, directory, 2).is_err());
    let mut invalid = configuration;
    invalid["output"] = json!("HDMI-1\npassword=oops");
    assert!(enzimos_remote_access::desktop_worker::command(&invalid, directory, 64).is_err());
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_enzimos-desktop-worker"))
        .arg("unexpected")
        .env_clear()
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("desktop-worker-arguments-unavailable")
    );
}

#[test]
fn rdp_grants_require_the_reviewed_provider_identity_and_legacy_grants_refuse_it() {
    let addresses = BTreeSet::from(["192.0.2.4".parse::<IpAddr>().unwrap()]);
    let legacy = grant(1000);
    let mut rdp = legacy.clone();
    rdp["configuration"] = json!({"schema":2,"enabled":true,"mode":"session-sharing","protocol":"rdp","listen_address":"192.0.2.4","port":3389,"allowed_networks":["192.0.2.0/24"],"view_only":true});
    assert!(desktop_grant::validate(&rdp, 1000, "boot-a", &addresses).is_err());
    let proof = json!({"name":"krdp-protected-sharing-v1","manifest_sha256":"a".repeat(64)});
    rdp["provider"] = proof.clone();
    assert_eq!(
        desktop_grant::validate(&rdp, 1000, "boot-a", &addresses).unwrap(),
        rdp
    );
    for proof in [
        json!({"name":"wayvnc","manifest_sha256":"a".repeat(64)}),
        json!({"name":"krdp-protected-sharing-v1","manifest_sha256":"A".repeat(64)}),
        json!({"name":"krdp-protected-sharing-v1","manifest_sha256":"a".repeat(64),"allow_replay":true}),
    ] {
        let mut altered = rdp.clone();
        altered["provider"] = proof;
        assert!(desktop_grant::validate(&altered, 1000, "boot-a", &addresses).is_err());
    }
    let mut altered = legacy;
    altered["provider"] = proof;
    assert!(desktop_grant::validate(&altered, 1000, "boot-a", &addresses).is_err());
}

#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid, getuid).")]
fn an_identity_left_incomplete_by_an_interrupted_first_run_is_replaced() {
    let uid = unsafe { libc::getuid() };
    if uid < 1000 || uid != unsafe { libc::geteuid() } {
        return;
    }
    let root = tempfile::Builder::new()
        .prefix("desktop-interrupted-")
        .tempdir_in(std::path::PathBuf::from(
            std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        ))
        .unwrap();
    let directory = root.path().join("identity");
    let first = desktop_identity::ensure(&directory, uid).unwrap();
    // The worker died after writing the certificate but before the credential.
    std::fs::remove_file(directory.join("credential.json")).unwrap();
    let renewed = desktop_identity::ensure(&directory, uid).unwrap();
    assert_ne!(first.password(), renewed.password());
    assert_eq!(
        desktop_identity::ensure(&directory, uid)
            .unwrap()
            .password(),
        renewed.password()
    );
}
