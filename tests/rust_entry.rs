// SPDX-License-Identifier: MIT
use std::process::Command;
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn unit_entry_rejects_unrecognized_operations_and_unprivileged_startup_before_bus_access() {
    let binary = env!("CARGO_BIN_EXE_enzimos-ssh-entry");
    for args in [vec![], vec!["unknown"], vec!["prepare", "extra"]] {
        let result = Command::new(binary)
            .args(args)
            .env_clear()
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(
            String::from_utf8(result.stderr)
                .unwrap()
                .contains("unit-operation-unavailable")
        );
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        let result = Command::new(binary)
            .arg("prepare")
            .env_clear()
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(
            String::from_utf8(result.stderr)
                .unwrap()
                .contains("initial-root-service-required")
        );
    }
}
