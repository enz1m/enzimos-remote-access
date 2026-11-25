// SPDX-License-Identifier: MIT
//! Public Root approval has capture/input authority only in the fixed unit cgroup.
use crate::desktop_grant;
use enzimos_platform::{Error, Result, files, require};
use std::{
    ffi::CString,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
const BASE: &str = "/run/enzimos-compositor-grants";
pub fn group(uid: u32) -> Result<String> {
    Ok(format!(
        "/system.slice/enzimos-desktop-sharing@{}.service",
        desktop_grant::account(uid)?
    ))
}
fn name(uid: u32) -> Result<String> {
    Ok(format!(
        "enzimos-desktop-sharing@{}.grant",
        desktop_grant::account(uid)?
    ))
}
pub fn body(uid: u32, view_only: bool) -> Result<Vec<u8>> {
    Ok(format!(
        "uid={uid}\ncgroup={}\nkinds={}\n",
        group(uid)?,
        if view_only {
            "capture"
        } else {
            "capture,input"
        }
    )
    .into_bytes())
}
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
pub fn publish(uid: u32, view_only: bool) -> Result<()> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    require(unsafe { libc::geteuid() } == 0, "Root authority required")?;
    let groups = files::read_kernel(
        &PathBuf::from(format!("/proc/{}/cgroup", std::process::id())),
        8192,
    )?;
    let expected = format!("0::{}\n", group(uid)?);
    require(
        groups == expected.as_bytes(),
        "compositor-grant-unit-required",
    )?;
    files::ensure_directory(Path::new(BASE), 0o755, 0)?;
    let destination = Path::new(BASE).join(name(uid)?);
    files::read_optional(&destination, 4096, Some(0), true)?;
    files::atomic(&destination, &body(uid, view_only)?, 0o644, Some(0), true)
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (fstatat, geteuid, unlinkat)."
)]
pub fn revoke(uid: u32) -> Result<()> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    require(unsafe { libc::geteuid() } == 0, "Root authority required")?;
    match std::fs::symlink_metadata(BASE) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let directory = files::directory(Path::new(BASE), Some(0))?;
    let meta = directory.metadata()?;
    require(
        meta.uid() == 0 && meta.mode() & 0o7777 == 0o755,
        "compositor-grant-directory-unsafe",
    )?;
    let file_name = name(uid)?;
    if files::read_optional(&Path::new(BASE).join(&file_name), 4096, Some(0), true)?.is_none() {
        return Ok(());
    }
    let file = files::open_relative(&directory, Path::new(&file_name))?;
    let before = file.metadata()?;
    let c = CString::new(file_name).map_err(|_| Error("compositor-grant-file-unsafe".into()))?;
    // SAFETY: `libc::stat` is a plain C struct, for which all-zero bytes are a valid value.
    let mut observed: libc::stat = unsafe { std::mem::zeroed() };
    require(
        // SAFETY: The name is a NUL-terminated CString, `observed` is a writable `libc::stat`, and
        // `directory` stays open.
        unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                c.as_ptr(),
                &mut observed,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
            && observed.st_dev == before.dev()
            && observed.st_ino == before.ino()
            && observed.st_uid == 0
            && observed.st_nlink == 1
            && observed.st_mode & (libc::S_IFMT | 0o022) == libc::S_IFREG,
        "compositor-grant-file-unsafe",
    )?;
    require(
        // SAFETY: `c` is a NUL-terminated CString and `directory` keeps the descriptor open.
        unsafe { libc::unlinkat(directory.as_raw_fd(), c.as_ptr(), 0) } == 0,
        "compositor-grant-revocation-uncertain",
    )?;
    directory.sync_all()?;
    Ok(())
}
