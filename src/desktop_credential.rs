// SPDX-License-Identifier: MIT
//! The worker accepts only PID 1's fixed credential location in its fixed unit.
use crate::{desktop_grant, network};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::Value;
use std::{
    io::Read,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
/// Read the system credential at `path` for `uid`.
///
/// # Errors
///
/// Fails when the credential is missing, writable, or changed.
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatvfs).")]
pub fn read(path: &Path, uid: u32) -> Result<Vec<u8>> {
    desktop_grant::account(uid)?;
    let parent = files::directory(
        path.parent()
            .ok_or_else(|| Error("desktop-system-credential-required".into()))?,
        Some(uid),
    )?;
    let mut file = files::open_relative(
        &parent,
        Path::new(
            path.file_name()
                .ok_or_else(|| Error("desktop-system-credential-required".into()))?,
        ),
    )?;
    let before = file.metadata()?;
    require(
        (before.uid() == 0 || before.uid() == uid)
            && before.nlink() == 1
            && before.mode() & 0o237 == 0
            && (1..=65536).contains(&before.len()),
        "desktop-system-credential-permissions",
    )?;
    if before.uid() != 0 {
        // SAFETY: `libc::statvfs` is a plain C struct, for which all-zero bytes are a valid value.
        let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
        require(
            // SAFETY: `vfs` is a writable `libc::statvfs` and `file` keeps the descriptor open.
            unsafe { libc::fstatvfs(file.as_raw_fd(), &mut vfs) } == 0
                && vfs.f_flag & libc::ST_RDONLY != 0,
            "desktop-system-credential-writable-mount",
        )?;
    }
    let mut bytes = Vec::new();
    (&mut file).take(65537).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    require(
        bytes.len() as u64 == before.len() && identity(&before) == identity(&after),
        "desktop-system-credential-changed",
    )?;
    Ok(bytes)
}
fn identity(m: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64, u32, u32, u64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.uid(),
        m.mode(),
        m.nlink(),
    )
}
/// The grant passed as a systemd credential to `uid`'s sharing unit.
///
/// # Errors
///
/// Fails outside that unit or when the credential is invalid.
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid, getuid).")]
pub fn credential(uid: u32) -> Result<Value> {
    desktop_grant::account(uid)?;
    require(
        // SAFETY: geteuid and getuid have no preconditions and cannot fail.
        unsafe { libc::getuid() } == uid && unsafe { libc::geteuid() } == uid,
        "desktop-ordinary-user-worker-required",
    )?;
    let unit = format!("enzimos-desktop-sharing@{uid}.service");
    let directory = format!("/run/credentials/{unit}");
    require(
        std::env::var("CREDENTIALS_DIRECTORY").ok().as_deref() == Some(&directory),
        "desktop-system-credential-required",
    )?;
    let pid = std::process::id();
    let groups =
        files::read_kernel_owned(&PathBuf::from(format!("/proc/{pid}/cgroup")), 8192, uid)?;
    let group = format!("0::/system.slice/{unit}");
    require(
        groups
            .split(|b| *b == b'\n')
            .any(|row| row == group.as_bytes()),
        "desktop-system-unit-required",
    )?;
    let boot = String::from_utf8(files::read_kernel(
        Path::new("/proc/sys/kernel/random/boot_id"),
        128,
    )?)
    .map_err(|_| Error("desktop-boot-identity-unavailable".into()))?;
    let addresses = network::interfaces()?;
    desktop_grant::validate(
        &json::decode(
            &read(&PathBuf::from(directory).join("desktop-config"), uid)?,
            65536,
        )?,
        uid,
        boot.trim(),
        &addresses.keys().copied().collect(),
    )
}
