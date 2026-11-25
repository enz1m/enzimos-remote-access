// SPDX-License-Identifier: MIT
use enzimos_remote_access::{
    desktop_grant,
    desktop_unattended::{self, Store},
    network,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::IpAddr};

fn configuration() -> Value {
    json!({"schema":1,"enabled":true,"mode":"session-sharing","listen_address":"192.0.2.4","port":5900,"allowed_networks":["192.0.2.0/24"],"view_only":true,"max_fps":15,"output":null})
}
fn reviewed_network() -> Value {
    json!([network::identity(
        "192.0.2.4".parse().unwrap(),
        "enp1s0",
        Some("home"),
        Some("0f8e4c1a-7b1d-4a8e-9f00-3b5a2c6d7e81"),
    )])
}
fn record(uid: u32) -> Value {
    desktop_unattended::record(uid, &configuration(), &reviewed_network()).unwrap()
}
#[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
fn store(root: &std::path::Path) -> Store {
    Store::new(root, unsafe { libc::getuid() }, 1000).unwrap()
}
fn scratch() -> tempfile::TempDir {
    let work = std::env::var_os("ENZIMOS_TEST_TMPDIR").map_or_else(
        || env!("CARGO_MANIFEST_DIR").into(),
        std::path::PathBuf::from,
    );
    tempfile::Builder::new()
        .prefix("unattended-")
        .tempdir_in(work)
        .unwrap()
}

#[test]
fn records_hold_only_encrypted_vnc_sharing_on_an_identified_reviewed_network() {
    desktop_unattended::validate(&record(1000), 1000).unwrap();
    assert!(desktop_unattended::validate(&record(1000), 1001).is_err());
    for (pointer, replacement) in [
        ("/schema", json!(2)),
        ("/uid", json!(999)),
        ("/configuration/enabled", json!(false)),
        ("/configuration/mode", json!("remote-login")),
        ("/configuration/listen_address", json!("192.0.2.5")),
        ("/configuration/allowed_networks", json!(["0.0.0.0/0"])),
        ("/configuration/port", json!(80)),
        ("/network/0/connection", json!(null)),
        ("/network/0/zone", json!(null)),
        ("/network/0/address", json!("192.0.2.5")),
        ("/network", json!([])),
    ] {
        let mut bad = record(1000);
        *bad.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            desktop_unattended::validate(&bad, 1000).is_err(),
            "{pointer}"
        );
    }
    let mut extra = record(1000);
    extra["password"] = json!("secret");
    assert!(desktop_unattended::validate(&extra, 1000).is_err());
    let mut rdp = configuration();
    rdp["schema"] = json!(2);
    assert!(desktop_unattended::record(1000, &rdp, &reviewed_network()).is_err());
    assert_eq!(
        desktop_unattended::reviewed(&record(1000))["connection"],
        "0f8e4c1a-7b1d-4a8e-9f00-3b5a2c6d7e81"
    );
}

#[test]
fn turning_unattended_sharing_on_and_off_round_trips_one_private_file() {
    let root = scratch();
    let store = store(root.path());
    assert_eq!(store.load().unwrap(), None);
    store.remove().unwrap();
    store.write(&record(1000)).unwrap();
    assert_eq!(store.load().unwrap(), Some(record(1000)));
    let path = root.path().join("1000/unattended.json");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert!(store.write(&record(1001)).is_err());
    assert_eq!(store.load().unwrap(), Some(record(1000)));
    store.remove().unwrap();
    assert_eq!(store.load().unwrap(), None);
    assert!(!path.exists());
}

#[test]
fn records_from_other_releases_leave_sharing_off_and_stay_in_place() {
    let root = scratch();
    let store = store(root.path());
    let path = root.path().join("1000/unattended.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        path.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let mut newer = record(1000);
    newer["schema"] = json!(2);
    newer["lock_screen"] = json!(true);
    for body in [newer.to_string(), "{not json".to_owned()] {
        std::fs::write(&path, &body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(store.load().unwrap(), None);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), body);
    }
    // A schema-1 record that does not validate is refused rather than read as off.
    let mut widened = record(1000);
    widened["configuration"]["allowed_networks"] = json!(["0.0.0.0/0"]);
    std::fs::write(&path, widened.to_string()).unwrap();
    assert!(store.load().is_err());
}

#[test]
fn grants_without_a_reviewed_connection_still_load_and_accept_any_connection() {
    let addresses = BTreeSet::from(["192.0.2.4".parse::<IpAddr>().unwrap()]);
    let session = json!({"uid":1000,"id":"c1","leader":123,"seat":"seat0","manager_owned":true,
        "compositor":{"pid":124,"start_ticks":4321,"device":1,"inode":2,"mount_namespace":[3,4]},
        "wayland":{"path":"/run/user/1000/wayland-0","device":5,"inode":6}});
    let legacy = json!({"schema":1,"boot_id":"boot-a","uid":1000,"nonce":"a".repeat(64),
        "interface":"enp1s0","zone":"home","configuration":configuration(),"session":session});
    assert_eq!(
        desktop_grant::validate(&legacy, 1000, "boot-a", &addresses).unwrap(),
        legacy
    );
    desktop_grant::approved_connection(&legacy, None).unwrap();
    desktop_grant::approved_connection(&legacy, Some("other")).unwrap();

    let mut reviewed = legacy.clone();
    reviewed["connection"] = json!("0f8e4c1a-7b1d-4a8e-9f00-3b5a2c6d7e81");
    desktop_grant::validate(&reviewed, 1000, "boot-a", &addresses).unwrap();
    desktop_grant::approved_connection(&reviewed, Some("0f8e4c1a-7b1d-4a8e-9f00-3b5a2c6d7e81"))
        .unwrap();
    for observed in [None, Some("other")] {
        assert_eq!(
            desktop_grant::approved_connection(&reviewed, observed)
                .unwrap_err()
                .0,
            "desktop-approved-network-changed"
        );
    }
    let mut unmanaged = legacy.clone();
    unmanaged["connection"] = Value::Null;
    desktop_grant::validate(&unmanaged, 1000, "boot-a", &addresses).unwrap();
    desktop_grant::approved_connection(&unmanaged, Some("any")).unwrap();
    let mut malformed = legacy;
    malformed["connection"] = json!("not a uuid\n");
    assert!(desktop_grant::validate(&malformed, 1000, "boot-a", &addresses).is_err());
}
