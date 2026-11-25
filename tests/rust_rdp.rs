// SPDX-License-Identifier: MIT
use enzimos_remote_access::{config, desktop_rdp, desktop_worker};
use serde_json::json;
use std::{
    collections::BTreeSet,
    io::Read,
    os::fd::{AsFd, AsRawFd},
    os::unix::fs::MetadataExt,
    path::Path,
};
fn configuration() -> serde_json::Value {
    json!({"schema":2,"enabled":true,"mode":"session-sharing","protocol":"rdp","listen_address":"192.0.2.4","port":3389,"allowed_networks":["192.0.2.0/24"],"view_only":true})
}
#[test]
fn versioned_protocol_keeps_legacy_capture_options_separate() {
    let addresses = BTreeSet::from(["192.0.2.4".parse().unwrap()]);
    let request = configuration();
    assert_eq!(config::desktop(&request, &addresses).unwrap(), request);
    for (name, value) in [
        ("schema", json!(2.0)),
        ("protocol", json!("vnc")),
        ("mode", json!("remote-login")),
        ("max_fps", json!(30)),
        ("output", json!(null)),
        ("view_only", json!(1)),
    ] {
        let mut altered = request.clone();
        altered[name] = value;
        assert!(config::desktop(&altered, &addresses).is_err(), "{name}");
    }
    assert!(desktop_worker::command(&request, Path::new("/run/user/1000/identity"), 64).is_err());
    let args = desktop_rdp::command(
        &request,
        Path::new("/home/admin/.local/share/enzimos/remote-desktop"),
        64,
        65,
    )
    .unwrap();
    assert_eq!(args.len(), 15);
    assert_eq!(
        &args[0..4],
        ["--sharing-password-fd", "65", "--listener-fd", "64"]
    );
    assert_eq!(&args[12..15], ["--mode", "SharedAccess", "--view-only"]);
    assert!(
        !args
            .iter()
            .any(|a| a.contains("max-fps") || a.contains("output=") || a.contains("password="))
    );
    assert!(desktop_rdp::command(&request, Path::new("/identity"), 64, 64).is_err());
    assert!(desktop_rdp::command(&request, Path::new("relative"), 64, 65).is_err());
}
#[test]
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (fcntl, ftruncate, getuid, pread and others)."
)]
fn anonymous_credential_is_sealed_private_and_closed_by_ownership() {
    let password = "A".repeat(43);
    let fd = desktop_rdp::credential(&password).unwrap();
    let raw = fd.as_raw_fd();
    let mut reader = std::fs::File::from(fd.as_fd().try_clone_to_owned().unwrap());
    let meta = reader.metadata().unwrap();
    assert_eq!(meta.nlink(), 0);
    assert_eq!(meta.mode() & 0o7777, 0o600);
    // SAFETY: getuid has no preconditions and cannot fail.
    assert_eq!(meta.uid(), unsafe { libc::getuid() });
    assert_eq!(
        // SAFETY: F_GET_SEALS takes no pointers and `fd` keeps `raw` open.
        unsafe { libc::fcntl(raw, libc::F_GET_SEALS) },
        desktop_rdp::SEALS
    );
    assert_ne!(
        // SAFETY: F_GETFD takes no pointers and `fd` keeps `raw` open.
        unsafe { libc::fcntl(raw, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    let mut bytes = vec![0; 43];
    assert_eq!(
        // SAFETY: The buffer pointer and length describe `bytes`, and `fd` keeps `raw` open.
        unsafe { libc::pread(raw, bytes.as_mut_ptr().cast(), bytes.len(), 0) },
        43
    );
    assert_eq!(bytes, password.as_bytes());
    // SAFETY: The buffer is a 1-byte literal and `fd` keeps `raw` open.
    assert_eq!(unsafe { libc::pwrite(raw, b"B".as_ptr().cast(), 1, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );
    // SAFETY: ftruncate takes no pointers and `fd` keeps `raw` open.
    assert_eq!(unsafe { libc::ftruncate(raw, 0) }, -1);
    // Receiver uses pread, so neither party depends on the shared write offset.
    let mut remaining = Vec::new();
    reader.read_to_end(&mut remaining).unwrap();
    assert!(remaining.is_empty());
    drop(fd);
    // SAFETY: F_GETFD takes no pointers; it only probes a closed descriptor number.
    assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
    for bad in [
        "short".to_owned(),
        "A".repeat(129),
        format!("{}\n", "A".repeat(32)),
    ] {
        assert!(desktop_rdp::credential(&bad).is_err());
    }
}

#[test]
#[allow(unsafe_code, reason = "Fork-child setup must run before exec.")]
fn child_executes_the_retained_elf_and_propagates_exec_failure() {
    use std::os::unix::process::CommandExt;
    let original = std::fs::File::open("/usr/bin/true").unwrap();
    let argv = vec![std::ffi::CString::new("retained-true").unwrap()];
    let mut command = std::process::Command::new("/usr/bin/false");
    command.env_clear();
    // SAFETY: The pre_exec closure only calls `exec_original`, which uses preallocated arguments.
    unsafe {
        command.pre_exec(move || desktop_rdp::exec_original(&original, &argv, &[]));
    }
    assert!(command.status().unwrap().success());
    let original = std::fs::File::open("/dev/null").unwrap();
    let argv = vec![std::ffi::CString::new("invalid-image").unwrap()];
    let mut command = std::process::Command::new("/usr/bin/true");
    command.env_clear();
    // SAFETY: The pre_exec closure only calls `exec_original`, which uses preallocated arguments.
    unsafe {
        command.pre_exec(move || desktop_rdp::exec_original(&original, &argv, &[]));
    }
    assert!(command.spawn().is_err());
}
