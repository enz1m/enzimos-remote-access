// SPDX-License-Identifier: MIT
//! Retain the compositor task and require the same live Wayland socket peer.
use crate::desktop_grant;
use enzimos_platform::{
    Error, Result, files,
    process_identity::{self, Retained},
    require,
};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeSet, VecDeque},
    ffi::CString,
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
};
/// Installed compositor executable.
pub const COMPOSITOR: &str = "/usr/lib/enzui/compositor/hyprland-current-build/Hyprland";
/// Metadata of the installed file `path`, requiring Root-owned unwritable ancestors.
///
/// # Errors
///
/// Fails when the file or an ancestor is untrusted.
pub fn installed(path: &Path) -> Result<std::fs::Metadata> {
    let parent = files::directory(
        path.parent()
            .ok_or_else(|| Error("desktop-installed-path-untrusted".into()))?,
        Some(0),
    )?;
    let file = files::open_relative(
        &parent,
        Path::new(
            path.file_name()
                .ok_or_else(|| Error("desktop-installed-path-untrusted".into()))?,
        ),
    )?;
    let m = file.metadata()?;
    require(
        m.uid() == 0 && m.mode() & 0o022 == 0,
        "desktop-installed-file-untrusted",
    )?;
    Ok(m)
}
fn kernel(pid: u32, uid: u32, name: &str, limit: usize) -> Result<String> {
    String::from_utf8(files::read_kernel_owned(
        &PathBuf::from(format!("/proc/{pid}")).join(name),
        limit,
        uid,
    )?)
    .map_err(|_| Error("desktop-process-identity".into()))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
fn follow_kernel(pid: u32, uid: u32, name: &str) -> Result<File> {
    require(
        matches!(name, "exe" | "ns/mnt"),
        "desktop-kernel-identity-path",
    )?;
    let root = files::directory(&PathBuf::from(format!("/proc/{pid}")), Some(uid))?;
    let name =
        CString::new(name).map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
    // SAFETY: `name` is a NUL-terminated CString and `root` keeps the descriptor open.
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC,
        )
    };
    require(fd >= 0, "desktop-process-identity-unavailable")?;
    // SAFETY: `fd` was just returned by openat and is owned by nothing else.
    Ok(unsafe { File::from_raw_fd(fd) })
}
/// Mount namespace device and inode of process `pid` of `uid`.
///
/// # Errors
///
/// Fails when the process cannot be inspected.
pub fn namespace(pid: u32, uid: u32) -> Result<[u64; 2]> {
    let m = follow_kernel(pid, uid, "ns/mnt")?.metadata()?;
    Ok([m.dev(), m.ino()])
}
fn group_admitted(groups: &str, uid: u32, id: &str, manager_owned: bool) -> bool {
    let prefix = format!("0::/user.slice/user-{uid}.slice/");
    let scope = format!("session-{id}.scope");
    let managed = format!("user@{uid}.service/app.slice/enzui-platform-desktop-");
    groups.lines().any(|row| {
        let Some(rest) = row.strip_prefix(&prefix) else {
            return false;
        };
        // Reject noncanonical cgroups even when the last component looks right.
        if rest
            .split('/')
            .any(|s| s.is_empty() || matches!(s, "." | ".."))
        {
            return false;
        }
        if rest.rsplit('/').next() == Some(scope.as_str()) {
            return true;
        }
        manager_owned
            && rest
                .strip_prefix(&managed)
                .and_then(|s| s.strip_suffix(".service/supervisor"))
                .is_some_and(|s| {
                    s.len() == 16
                        && s.bytes()
                            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                })
    })
}
/// Identity proof of compositor `pid` in session `id` of `uid`.
///
/// # Errors
///
/// Fails when the process is not that session's compositor.
pub fn process(
    pid: u32,
    uid: u32,
    id: &str,
    manager_owned: bool,
    initial_namespace: [u64; 2],
) -> Result<Value> {
    desktop_grant::account(uid)?;
    require(pid > 0 && pid < 1 << 31, "desktop-process-identity")?;
    let stat = process_identity::parse_stat(&kernel(pid, uid, "stat", 8192)?, pid)?;
    let retained = Retained::open(pid, stat.start_ticks, uid, &[PathBuf::from(COMPOSITOR)])?;
    require(
        namespace(pid, uid)? == initial_namespace,
        "desktop-compositor-namespace",
    )?;
    require(
        process_identity::parse_uids(&kernel(pid, uid, "status", 65536)?)? == [uid; 4],
        "desktop-compositor-user",
    )?;
    require(
        group_admitted(&kernel(pid, uid, "cgroup", 8192)?, uid, id, manager_owned),
        "desktop-compositor-session",
    )?;
    let m = follow_kernel(pid, uid, "exe")?.metadata()?;
    retained.recheck()?;
    require(
        namespace(pid, uid)? == initial_namespace
            && process_identity::parse_uids(&kernel(pid, uid, "status", 65536)?)? == [uid; 4]
            && group_admitted(&kernel(pid, uid, "cgroup", 8192)?, uid, id, manager_owned),
        "desktop-compositor-replaced",
    )?;
    Ok(
        value!({"pid":pid,"start_ticks":stat.start_ticks,"device":m.dev(),"inode":m.ino(),"mount_namespace":initial_namespace}),
    )
}
/// Descendant processes of `leader` owned by `uid`.
///
/// # Errors
///
/// Fails when a process is invalid or the bound is exceeded.
pub fn descendants(leader: u32, uid: u32) -> Result<Vec<u32>> {
    let mut pending = VecDeque::from([leader]);
    let mut seen = BTreeSet::new();
    while let Some(pid) = pending.pop_front() {
        require(pid > 0 && pid < 1 << 31, "desktop-session-process-invalid")?;
        if !seen.insert(pid) {
            continue;
        }
        // Browser-heavy sessions easily exceed a few hundred processes.
        require(seen.len() <= 4096, "desktop-session-process-bound")?;
        let children = match kernel(pid, uid, &format!("task/{pid}/children"), 8192) {
            Ok(s) => s,
            Err(e) => {
                if std::fs::symlink_metadata(format!("/proc/{pid}"))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                {
                    continue;
                }
                return Err(e);
            }
        };
        for child in children.split_whitespace() {
            pending.push_back(
                child
                    .parse()
                    .map_err(|_| Error("desktop-session-process-invalid".into()))?,
            );
            require(pending.len() <= 16384, "desktop-session-process-bound")?;
        }
    }
    Ok(seen.into_iter().collect())
}
/// Proof that Wayland socket `path` of `uid` is served by `pid`.
///
/// # Errors
///
/// Fails when the socket is untrusted, has another peer, or was replaced.
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (connect, getsockopt, openat, socket)."
)]
pub fn socket_peer(path: &Path, uid: u32, pid: u32) -> Result<Value> {
    let prefix = format!("/run/user/{uid}/wayland-");
    require(
        path.to_str()
            .and_then(|s| s.strip_prefix(&prefix))
            .is_some_and(|s| (1..=3).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_digit())),
        "desktop-wayland-socket-untrusted",
    )?;
    let parent = files::directory(
        path.parent()
            .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
        Some(uid),
    )?;
    let p = parent.metadata()?;
    require(
        p.uid() == uid && p.mode() & 0o077 == 0,
        "desktop-wayland-socket-untrusted",
    )?;
    let name = CString::new(
        path.file_name()
            .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?
            .as_bytes(),
    )
    .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
    // SAFETY: `name` is a NUL-terminated CString and `parent` keeps the descriptor open.
    let node = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    require(node >= 0, "desktop-wayland-socket-untrusted")?;
    // SAFETY: `node` was just returned by openat and is owned by nothing else.
    let node = unsafe { File::from_raw_fd(node) };
    let m = node.metadata()?;
    require(
        m.uid() == uid && m.mode() & libc::S_IFMT == libc::S_IFSOCK,
        "desktop-wayland-socket-untrusted",
    )?;
    // SAFETY: socket takes no pointers.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    require(fd >= 0, "desktop-wayland-peer-unavailable")?;
    // SAFETY: `fd` was just returned by socket and is owned by nothing else.
    let socket = unsafe { File::from_raw_fd(fd) };
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: `libc::sockaddr_un` is a plain C struct, for which all-zero bytes are a valid value.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    require(
        bytes.len() < address.sun_path.len(),
        "desktop-wayland-socket-untrusted",
    )?;
    address.sun_family = libc::AF_UNIX as _;
    for (to, from) in address.sun_path.iter_mut().zip(bytes) {
        *to = *from as _;
    }
    // SAFETY: `address` is a complete sockaddr_un passed with its size, and `socket` owns `fd`.
    let rc = unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of_val(&address) as _,
        )
    };
    // Unix backlog exhaustion returns EAGAIN; it does not mean a connection is pending.
    require(rc == 0, "desktop-wayland-peer-unavailable")?;
    // SAFETY: `libc::ucred` is a plain C struct, for which all-zero bytes are a valid value.
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&credentials) as libc::socklen_t;
    require(
        // SAFETY: The option buffer is `credentials` with its size in `size`, and `socket` is open.
        unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut size,
            )
        } == 0
            && size as usize == std::mem::size_of_val(&credentials)
            && credentials.uid == uid
            && credentials.pid as u32 == pid,
        "desktop-wayland-peer-untrusted",
    )?;
    let after = std::fs::symlink_metadata(path)?;
    let parent_after = files::directory(
        path.parent()
            .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
        Some(uid),
    )?
    .metadata()?;
    require(
        (m.dev(), m.ino(), m.uid(), m.mode())
            == (after.dev(), after.ino(), after.uid(), after.mode())
            && (p.dev(), p.ino()) == (parent_after.dev(), parent_after.ino()),
        "desktop-wayland-socket-replaced",
    )?;
    Ok(value!({"path":path,"device":m.dev(),"inode":m.ino()}))
}
/// Recheck a session proof and retain its compositor.
///
/// # Errors
///
/// Fails when the proof is invalid or the compositor or socket was replaced.
pub fn verify(bound: &Value) -> Result<Retained> {
    let uid = bound["uid"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| Error("desktop-session-proof-invalid".into()))?;
    desktop_grant::session(bound, uid)?;
    let proof = &bound["compositor"];
    let pid = proof["pid"]
        .as_u64()
        .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?
        as u32;
    let ns = [
        proof["mount_namespace"][0]
            .as_u64()
            .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?,
        proof["mount_namespace"][1]
            .as_u64()
            .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?,
    ];
    let retained = Retained::open(
        pid,
        proof["start_ticks"]
            .as_u64()
            .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?,
        uid,
        &[PathBuf::from(COMPOSITOR)],
    )?;
    require(
        process(
            pid,
            uid,
            bound["id"]
                .as_str()
                .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?,
            bound["manager_owned"]
                .as_bool()
                .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?,
            ns,
        )? == *proof,
        "desktop-compositor-replaced",
    )?;
    require(
        socket_peer(
            Path::new(
                bound["wayland"]["path"]
                    .as_str()
                    .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?,
            ),
            uid,
            pid,
        )? == bound["wayland"],
        "desktop-wayland-socket-replaced",
    )?;
    retained.recheck()?;
    Ok(retained)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compositor_cgroup_authority_is_specific() {
        assert!(group_admitted(
            "0::/user.slice/user-1000.slice/session-c1.scope\n",
            1000,
            "c1",
            false
        ));
        let managed = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/enzui-platform-desktop-0123456789abcdef.service/supervisor";
        assert!(group_admitted(managed, 1000, "c1", true));
        assert!(!group_admitted(managed, 1000, "c1", false));
        for wrong in [
            managed.replace("1000", "1001"),
            managed.replace("abcdef", "ABCDEF"),
            managed.replace("/supervisor", "/helper"),
            "0::/user.slice/user-1000.slice/../session-c1.scope".into(),
            "0::/system.slice/session-c1.scope".into(),
        ] {
            assert!(!group_admitted(&wrong, 1000, "c1", true));
        }
    }
}
