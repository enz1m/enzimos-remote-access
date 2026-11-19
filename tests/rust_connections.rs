// SPDX-License-Identifier: MIT
use enzimos_platform::{files, json};
use enzimos_remote_access::connections::{self, Tracker};
use serde_json::json as value;
use std::{os::unix::fs::PermissionsExt, path::Path};
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn connection_leases_are_typed_boot_and_account_bound_without_trusting_pids_alone() {
    let boot = "00000000-0000-0000-0000-000000000001";
    let row = value!({"pid":42,"start_ticks":1234,"address":"127.0.0.1","port":2222});
    let record = value!({"schema":1,"boot_id":boot,"uid":1000,"processes":[row]});
    connections::validate(&record).unwrap();
    for (key, v) in [
        ("pid", value!(true)),
        ("pid", value!(0)),
        ("start_ticks", value!(false)),
        ("port", value!(65536)),
        ("address", value!("not an IP")),
    ] {
        let mut bad = record.clone();
        bad["processes"][0][key] = v;
        assert!(connections::validate(&bad).is_err());
    }
    let mut multiple = record.clone();
    multiple["processes"][0]["addresses"] = value!(["127.0.0.1", "::1"]);
    connections::validate(&multiple).unwrap();
    multiple["processes"][0]["addresses"] = value!(["::1"]);
    assert!(connections::validate(&multiple).is_err());
    let mut duplicate = record.clone();
    duplicate["processes"]
        .as_array_mut()
        .unwrap()
        .push(record["processes"][0].clone());
    assert!(connections::validate(&duplicate).is_err());
    let work = std::path::PathBuf::from(
        std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    );
    let temp = tempfile::Builder::new()
        .prefix("rust-ssh-leases-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(work)
        .unwrap();
    let owner = unsafe { libc::geteuid() };
    files::atomic(
        &temp.path().join("connections.json"),
        &json::canonical(&record).unwrap(),
        0o600,
        Some(owner),
        false,
    )
    .unwrap();
    let mut tracker = Tracker {
        directory: temp.path().into(),
        uid: 1000,
        owner,
        boot_id: boot.into(),
        addresses: vec!["127.0.0.1".parse().unwrap()],
        port: 2222,
    };
    assert_eq!(tracker.load().unwrap().len(), 1);
    tracker.uid = 1001;
    assert!(tracker.load().unwrap().is_empty());
    tracker.uid = 1000;
    tracker.boot_id = "00000000-0000-0000-0000-000000000002".into();
    assert!(tracker.load().unwrap().is_empty());
    assert!(tracker.disconnect(&[], || Ok(())).is_err());
    assert!(connections::descendants(0, 1000).unwrap().is_empty());
}
