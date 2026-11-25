// SPDX-License-Identifier: MIT
use enzimos_remote_access::desktop_unit_trust;
use serde_json::Value;
const DESKTOP: &str = include_str!("../packaging/enzimos-desktop-sharing@.service");
const SSH: &str = include_str!("../packaging/enzimos-sshd.service");
const SSH_GUARD: &str = include_str!("../packaging/enzimos-sshd-firewall.service");
const DESKTOP_GUARD: &str = include_str!("../packaging/enzimos-desktop-sharing-firewall@.service");
fn fields(body: &str, key: &str) -> Vec<String> {
    body.lines()
        .filter_map(|line| line.strip_prefix(&format!("{key}=")))
        .map(str::to_owned)
        .collect()
}
#[test]
fn native_availability_refuses_a_changed_template() {
    assert!(desktop_unit_trust::native_template(DESKTOP.as_bytes()));
    let changed = DESKTOP.replace("desktop-entry release %i", "desktop-entry prepare %i");
    assert_ne!(changed, DESKTOP);
    assert!(!desktop_unit_trust::native_template(changed.as_bytes()));
}
#[test]
fn native_desktop_template_preserves_privileged_cleanup_and_original_listener_retention() {
    assert_eq!(fields(DESKTOP, "User"), ["%i"]);
    assert_eq!(fields(DESKTOP, "ExecStart"), [desktop_unit_trust::WORKER]);
    assert_eq!(
        fields(DESKTOP, "ExecStartPre"),
        ["+/usr/lib/enzimos-remote/desktop-entry prepare %i"]
    );
    assert_eq!(
        fields(DESKTOP, "ExecStopPost"),
        ["+/usr/lib/enzimos-remote/desktop-entry release %i"]
    );
    for (key, expected) in [
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("NotifyAccess", "exec"),
        ("FileDescriptorStoreMax", "1"),
        ("FileDescriptorStorePreserve", "yes"),
        ("NoNewPrivileges", "yes"),
    ] {
        assert_eq!(fields(DESKTOP, key), [expected]);
    }
    assert_eq!(
        fields(DESKTOP, "LoadCredential"),
        ["desktop-config:/run/enzimos-remote/sharing/%i/grant.json"]
    );
    assert!(fields(DESKTOP, "WantedBy").is_empty());
}
#[test]
fn listeners_and_their_firewall_guards_stop_together_but_outlive_firewalld() {
    for (unit, peer) in [
        (SSH, "enzimos-sshd-firewall.service"),
        (SSH_GUARD, "enzimos-sshd.service"),
        (DESKTOP, "enzimos-desktop-sharing-firewall@%i.service"),
        (DESKTOP_GUARD, "enzimos-desktop-sharing@%i.service"),
    ] {
        assert_eq!(fields(unit, "BindsTo"), [peer]);
        assert_eq!(fields(unit, "Restart"), ["no"]);
        assert_eq!(fields(unit, "Requires"), ["dbus.service"]);
        assert!(
            fields(unit, "After")
                .iter()
                .any(|after| after.split_whitespace().any(|u| u == "firewalld.service")),
            "unit is not ordered after firewalld"
        );
        for key in ["Wants", "PartOf", "Requisite"] {
            assert!(
                fields(unit, key).iter().all(|v| !v.contains("firewalld")),
                "{key}= couples a listener to firewalld"
            );
        }
    }
    assert!(
        fields(SSH, "Wants").iter().any(|wants| wants
            .split_whitespace()
            .any(|u| u == "enzimos-sshd-retry.timer")),
        "an enabled listener does not arm its retry timer"
    );
    assert_eq!(
        fields(SSH, "ExecStartPost"),
        ["/usr/lib/enzimos-remote/ssh-entry verify"]
    );
    assert_eq!(
        fields(SSH_GUARD, "ExecStart"),
        ["/usr/lib/enzimos-remote/ssh-entry watch"]
    );
    assert_eq!(
        fields(DESKTOP_GUARD, "ExecStart"),
        ["/usr/lib/enzimos-remote/desktop-entry watch %i"]
    );
    assert!(fields(DESKTOP_GUARD, "User").is_empty());
}
#[test]
fn all_unit_commands_resolve_to_packaged_binaries() {
    let spec: Value = serde_json::from_str(include_str!("../packaging/rust/runtime.json")).unwrap();
    assert_eq!(spec["automatic_activation"], false);
    let binaries: Vec<_> = spec["binaries"]
        .as_object()
        .unwrap()
        .values()
        .map(|v| format!("/{}", v.as_str().unwrap()))
        .collect();
    for body in [
        DESKTOP,
        SSH,
        SSH_GUARD,
        DESKTOP_GUARD,
        include_str!("../packaging/enzimos-sshd-retry.service"),
        include_str!("../packaging/enzimos-remote-access.service"),
        include_str!("../packaging/org.enzimos.Remote1.service"),
    ] {
        for key in [
            "Exec",
            "ExecStart",
            "ExecStartPre",
            "ExecStartPost",
            "ExecStopPost",
        ] {
            for command in fields(body, key) {
                let program = command
                    .trim_start_matches('+')
                    .split_whitespace()
                    .next()
                    .unwrap();
                assert!(
                    binaries.iter().any(|p| p == program) || program == "/usr/bin/sshd",
                    "unpackaged command: {program}"
                );
            }
        }
    }
    let policy = include_str!("../packaging/org.enzimos.Remote1.policy");
    assert_eq!(
        policy
            .matches("<allow_active>auth_admin</allow_active>")
            .count(),
        2
    );
}
