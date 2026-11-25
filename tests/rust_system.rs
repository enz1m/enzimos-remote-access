// SPDX-License-Identifier: MIT
//! Tests of the remote-access system handling.
use enzimos_remote_access::system::{self, Properties};
use zbus::zvariant::Value;
#[test]
fn fixed_units_and_typed_snapshots_refuse_stock_services_and_active_fd_cleanup() {
    for name in [
        system::SSH,
        "enzimos-desktop-sharing@1000.service",
        "enzimos-desktop-sharing@4294967294.service",
    ] {
        system::unit(name).unwrap();
    }
    for name in [
        "sshd.service",
        "enzimos-desktop-sharing@0.service",
        "enzimos-desktop-sharing@01000.service",
        "enzimos-desktop-sharing@4294967295.service",
        "enzimos-desktop-sharing@1000.service\n",
    ] {
        assert!(system::unit(name).is_err());
    }
    let mut unit = Properties::new();
    unit.insert(
        "ActiveState".into(),
        Value::from("inactive").try_to_owned().unwrap(),
    );
    let mut service = Properties::new();
    for (key, n) in [
        ("MainPID", 0u32),
        ("ControlPID", 0),
        ("NFileDescriptorStore", 1),
    ] {
        service.insert(key.into(), n.into());
    }
    service.insert(
        "ControlGroup".into(),
        Value::from("/system.slice/enzimos-desktop-sharing@1000.service")
            .try_to_owned()
            .unwrap(),
    );
    system::stopped(&system::snapshot(&unit, &service).unwrap()).unwrap();
    service.insert("MainPID".into(), 12u32.into());
    assert!(system::stopped(&system::snapshot(&unit, &service).unwrap()).is_err());
    service.insert("MainPID".into(), false.into());
    assert!(system::snapshot(&unit, &service).is_err());
    service.insert("MainPID".into(), 0u32.into());
    service.insert("NFileDescriptorStore".into(), 1u64.into());
    assert!(system::snapshot(&unit, &service).is_err());
}
