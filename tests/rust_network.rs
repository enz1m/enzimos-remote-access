// SPDX-License-Identifier: MIT
//! Tests of the reviewed network identity and its approval sidecar.
use enzimos_platform::{files, json};
use enzimos_remote_access::{
    network,
    state::{self, State},
};
use serde_json::{Value, json};
use std::{net::IpAddr, os::unix::fs::PermissionsExt, path::Path};

const HOME: &str = "5f0c8b1e-2d3a-4c5b-9e6f-7a8b9c0d1e2f";

fn approved_network() -> Value {
    json!([network::identity(
        "192.168.10.5".parse().expect("test fixture"),
        "wlan0",
        Some("home"),
        Some(HOME)
    )])
}
fn configuration() -> Value {
    json!({"enabled":true,"autostart":true,"listen_address":"192.168.10.5"})
}
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn write_record(directory: &Path, record: &Value) {
    files::atomic(
        &directory.join("approval.json"),
        &json::canonical(record).expect("test fixture"),
        0o600,
        // SAFETY: geteuid has no preconditions and cannot fail.
        Some(unsafe { libc::geteuid() }),
        true,
    )
    .expect("test fixture");
}

#[test]
fn tentative_and_failed_duplicate_addresses_are_not_listenable() {
    let body = json!([{
        "ifname":"enp1s0","flags":["UP"],
        "addr_info":[
            {"local":"2001:db8::1","tentative":true},
            {"local":"2001:db8::2","dadfailed":true,"tentative":true},
            {"local":"2001:db8::3","tentative":true,"optimistic":true},
            {"local":"2001:db8::4"},
            {"local":"192.0.2.4"}
        ]
    }]);
    let found = network::parse_interfaces(body.to_string().as_bytes()).unwrap();
    let listed: Vec<IpAddr> = found.keys().copied().collect();
    assert_eq!(
        listed,
        ["192.0.2.4", "2001:db8::3", "2001:db8::4"]
            .map(|a| a.parse::<IpAddr>().unwrap())
            .to_vec()
    );
}

#[test]
fn a_different_interface_zone_or_connection_is_not_the_approved_network() {
    let approved = approved_network();
    network::require_identity(&approved, &approved_network()).unwrap();
    let address = "192.168.10.5".parse().unwrap();
    for observed in [
        network::identity(address, "enp1s0", Some("home"), Some(HOME)),
        network::identity(address, "wlan0", Some("public"), Some(HOME)),
        network::identity(
            address,
            "wlan0",
            Some("home"),
            Some("0b6d2f3e-1111-4c5b-9e6f-7a8b9c0d1e2f"),
        ),
        network::identity(address, "wlan0", Some("home"), None),
    ] {
        assert_eq!(
            network::require_identity(&approved, &json!([observed]))
                .unwrap_err()
                .0,
            "ssh-approved-network-changed"
        );
    }
}

#[test]
fn without_firewalld_the_reviewed_interface_and_connection_still_decide() {
    let approved = approved_network();
    let address = "192.168.10.5".parse().unwrap();
    network::require_identity(
        &approved,
        &json!([network::identity(address, "wlan0", None, Some(HOME))]),
    )
    .unwrap();
    for observed in [
        network::identity(address, "enp1s0", None, Some(HOME)),
        network::identity(address, "wlan0", None, None),
    ] {
        assert_eq!(
            network::require_identity(&approved, &json!([observed]))
                .unwrap_err()
                .0,
            "ssh-approved-network-changed"
        );
    }
}

#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn states() -> (tempfile::TempDir, std::path::PathBuf, State, State) {
    let work = std::path::PathBuf::from(
        std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    );
    let temp = tempfile::Builder::new()
        .prefix("rust-ssh-state-fixture-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(work)
        .expect("test fixture");
    // SAFETY: geteuid has no preconditions and cannot fail.
    let owner = unsafe { libc::geteuid() };
    let directory = temp.path().join("ssh");
    let approving = State::new(&directory, owner, "approval-boot".into()).expect("test fixture");
    let later = State::new(&directory, owner, "later-boot".into()).expect("test fixture");
    (temp, directory, approving, later)
}
fn on_disk(directory: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(directory.join("approval.json")).expect("test fixture"))
        .expect("test fixture")
}
// The exact check of the released ssh-entry, which refuses any other field set.
fn previous_release_reads(record: &Value) -> bool {
    let mut names = record
        .as_object()
        .expect("test fixture")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    names.sort_unstable();
    names
        == [
            "boot_id",
            "configuration",
            "detail",
            "phase",
            "schema",
            "uid",
        ]
        && record["schema"] == 1
        && state::validate(record).is_ok()
}
fn legacy() -> Value {
    json!({"schema":1,"uid":1000,"phase":"complete","boot_id":"approval-boot","configuration":configuration(),"detail":""})
}

#[test]
fn a_reviewed_network_is_kept_beside_a_record_the_previous_release_reads() {
    let (_temp, directory, approving, later) = states();
    let written = approving
        .write(1000, "complete", &configuration(), &approved_network(), "")
        .unwrap();
    assert!(previous_release_reads(&on_disk(&directory)));
    assert_eq!(written["network"], approved_network());
    assert_eq!(later.eligible().unwrap()["network"], approved_network());

    approving
        .write(1000, "complete", &configuration(), &Value::Null, "")
        .unwrap();
    assert!(!directory.join("approval-network.json").exists());
    assert!(later.eligible().unwrap()["network"].is_null());
}

#[test]
fn a_schema_1_approval_still_autostarts_and_its_upgrade_records_the_observed_network() {
    let (_temp, directory, _approving, later) = states();
    write_record(&directory, &legacy());
    let approved = later.eligible().unwrap();
    assert!(approved["network"].is_null());

    later.upgrade(&approved, Some(&approved_network())).unwrap();
    assert_eq!(on_disk(&directory), legacy());
    assert_eq!(later.eligible().unwrap()["network"], approved_network());

    let upgraded = later.eligible().unwrap();
    let other = json!([network::identity(
        "192.168.10.5".parse().unwrap(),
        "wlan0",
        Some("public"),
        Some(HOME)
    )]);
    later.upgrade(&upgraded, Some(&other)).unwrap();
    assert_eq!(
        later.eligible().unwrap()["network"],
        approved_network(),
        "an upgrade never replaces a recorded network"
    );
}

#[test]
fn an_approval_rewritten_by_the_previous_release_drops_the_stale_network() {
    let (_temp, directory, approving, later) = states();
    approving
        .write(1000, "complete", &configuration(), &approved_network(), "")
        .unwrap();
    let mut rewritten = legacy();
    rewritten["configuration"]["autostart"] = json!(false);
    rewritten["boot_id"] = json!("later-boot");
    write_record(&directory, &rewritten);
    assert!(later.eligible().unwrap()["network"].is_null());

    std::fs::write(directory.join("approval-network.json"), b"{not json").unwrap();
    assert!(later.eligible().unwrap()["network"].is_null());
}

#[test]
fn a_pre_release_schema_2_record_is_read_and_split_on_upgrade() {
    let (_temp, directory, _approving, later) = states();
    let mut record = legacy();
    record["schema"] = json!(2);
    record["network"] = approved_network();
    write_record(&directory, &record);

    let approved = later.eligible().unwrap();
    assert_eq!(approved["schema"], 1);
    assert_eq!(approved["network"], approved_network());

    later.upgrade(&approved, None).unwrap();
    assert!(previous_release_reads(&on_disk(&directory)));
    assert_eq!(later.eligible().unwrap(), approved);
}

#[test]
fn a_network_that_does_not_describe_the_listen_addresses_refuses() {
    let (_temp, directory, approving, later) = states();
    let misplaced = json!([network::identity(
        "192.168.10.6".parse().unwrap(),
        "wlan0",
        Some("home"),
        Some(HOME)
    )]);
    assert!(
        approving
            .write(1000, "complete", &configuration(), &misplaced, "")
            .is_err()
    );
    let mut record = legacy();
    record["schema"] = json!(2);
    record["network"] = misplaced.clone();
    write_record(&directory, &record);
    assert!(later.load().is_err());

    approving
        .write(1000, "complete", &configuration(), &approved_network(), "")
        .unwrap();
    let mut sidecar: Value =
        serde_json::from_slice(&std::fs::read(directory.join("approval-network.json")).unwrap())
            .unwrap();
    sidecar["network"] = misplaced;
    files::atomic(
        &directory.join("approval-network.json"),
        &json::canonical(&sidecar).unwrap(),
        0o600,
        None,
        true,
    )
    .unwrap();
    assert!(later.load().is_err());
}
