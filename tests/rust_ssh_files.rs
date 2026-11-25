// SPDX-License-Identifier: MIT
use enzimos_platform::{files, json};
use enzimos_remote_access::ssh_files::Layout;
use serde_json::json as value;
use std::os::unix::fs::PermissionsExt;
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn native_host_identity_is_private_persistent_and_never_replaced_after_partial_creation() {
    let work = std::path::PathBuf::from(
        std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    );
    let temp = tempfile::Builder::new()
        .prefix("rust-ssh-key-fixture-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(work)
        .unwrap();
    // SAFETY: geteuid has no preconditions and cannot fail.
    let owner = unsafe { libc::geteuid() };
    let layout = Layout {
        state: temp.path().join("ssh"),
        configuration: temp.path().join("etc"),
        owner,
    };
    let first = layout.host_identity().unwrap();
    assert!(first.starts_with("SHA256:"));
    assert_eq!(first, layout.host_identity().unwrap());
    let public = layout.public_host_key().unwrap().unwrap();
    assert!(public.starts_with("ssh-ed25519 "));
    let secret = layout.state.join("host_ed25519");
    let body = std::fs::read(&secret).unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(layout.host_identity().is_err());
    assert_eq!(std::fs::read(&secret).unwrap(), body);
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let other = Layout {
        state: temp.path().join("other"),
        configuration: temp.path().join("other-etc"),
        owner,
    };
    other.host_identity().unwrap();
    let another = std::fs::read(other.state.join("host_ed25519.pub")).unwrap();
    files::atomic(
        &layout.state.join("host_ed25519.pub"),
        &another,
        0o644,
        Some(owner),
        true,
    )
    .unwrap();
    assert!(layout.host_identity().is_err());
    assert_eq!(std::fs::read(&secret).unwrap(), body);
    let incomplete = Layout {
        state: temp.path().join("partial"),
        configuration: temp.path().join("partial-etc"),
        owner,
    };
    files::create_directory(&incomplete.state, 0o700, owner).unwrap();
    files::atomic(
        &incomplete.state.join("host_ed25519.pub"),
        &another,
        0o644,
        Some(owner),
        false,
    )
    .unwrap();
    assert!(incomplete.host_identity().is_err());
    assert!(!incomplete.state.join("host_ed25519").exists());
    std::fs::remove_file(incomplete.state.join("host_ed25519.pub")).unwrap();
    files::atomic(
        &incomplete.state.join("host-key-creation.json"),
        &json::canonical(
            &value!({"schema":1,"phase":"prepared","stage":"f".repeat(32),"fingerprint":null}),
        )
        .unwrap(),
        0o600,
        Some(owner),
        false,
    )
    .unwrap();
    assert!(incomplete.host_identity().is_err());
    assert!(!incomplete.state.join("host_ed25519").exists());
    std::fs::remove_file(&secret).unwrap();
    std::os::unix::fs::symlink("host_ed25519.pub", &secret).unwrap();
    assert!(layout.host_identity().is_err());
}
