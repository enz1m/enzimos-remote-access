// SPDX-License-Identifier: MIT
//! Root observes protected tasks without changing their dumpability or permissions.
use crate::{desktop_grant, desktop_rdp, desktop_unit_trust, sockets, ssh_provider};
use enzimos_platform::{Error, Result, files, process_identity, require};
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};

fn epoch(m: &std::fs::Metadata) -> (u64, u64, u64, u32, u32, u32, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid, getuid).")]
fn context(uid: u32) -> Result<()> {
    desktop_grant::account(uid)?;
    require(
        // SAFETY: geteuid and getuid have no preconditions and cannot fail.
        unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0,
        "desktop-rdp-root-observer-required",
    )?;
    ssh_provider::root_context()
}
fn row(
    stat: &str,
    status: &str,
    group: &str,
    pid: u32,
    uid: u32,
    parent: Option<u32>,
) -> Result<process_identity::Stat> {
    let task = process_identity::parse_stat(stat, pid)?;
    require(
        !matches!(task.state, 'Z' | 'X' | 'x') && process_identity::parse_uids(status)? == [uid; 4],
        "desktop-rdp-task-identity",
    )?;
    if let Some(parent) = parent {
        require(task.parent == parent, "desktop-rdp-task-parent")?;
    }
    let expected = format!("0::/system.slice/enzimos-desktop-sharing@{uid}.service");
    require(
        group
            .lines()
            .filter(|s| s.starts_with("0::"))
            .eq([expected.as_str()]),
        "desktop-rdp-task-cgroup",
    )?;
    Ok(task)
}
struct Task {
    pid: u32,
    uid: u32,
    parent: Option<u32>,
    start: u64,
    directory: File,
    image: File,
    pidfd: File,
}
impl Task {
    fn read(&self, name: &str, limit: usize) -> Result<String> {
        // Linux assigns Root ownership to proc entries of nondumpable tasks.
        // The actual task UID is checked independently from kernel status.
        String::from_utf8(files::read_kernel(
            &PathBuf::from(format!("/proc/{}", self.pid)).join(name),
            limit,
        )?)
        .map_err(|_| Error("desktop-rdp-task-observation".into()))
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (poll).")]
    fn live(&self) -> Result<()> {
        let mut entry = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        require(
            // SAFETY: `entry` is one writable pollfd and the count is 1.
            unsafe { libc::poll(&mut entry, 1, 0) } == 0,
            "desktop-rdp-task-exited",
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat, syscall).")]
    fn observe(pid: u32, uid: u32, parent: Option<u32>, fixed: &File) -> Result<Self> {
        context(uid)?;
        require(pid > 0 && pid < i32::MAX as u32, "desktop-rdp-task-pid")?;
        // SAFETY: pidfd_open takes no pointers.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
        require(raw >= 0, "desktop-rdp-task-pidfd")?;
        // SAFETY: `raw` was just returned by pidfd_open and is owned by nothing else.
        let pidfd = unsafe { File::from_raw_fd(raw) };
        let directory = files::directory(&PathBuf::from(format!("/proc/{pid}")), Some(0))?;
        // SAFETY: The name is a NUL-terminated literal and `directory` keeps the descriptor open.
        let raw = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c"exe".as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        require(raw >= 0, "desktop-rdp-task-executable")?;
        // SAFETY: `raw` was just returned by openat and is owned by nothing else.
        let image = unsafe { File::from_raw_fd(raw) };
        let mut task = Self {
            pid,
            uid,
            parent,
            start: 0,
            directory,
            image,
            pidfd,
        };
        task.live()?;
        let observed = row(
            &task.read("stat", 8192)?,
            &task.read("status", 65536)?,
            &task.read("cgroup", 8192)?,
            pid,
            uid,
            parent,
        )?;
        task.start = observed.start_ticks;
        task.recheck(fixed)?;
        Ok(task)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
    fn recheck(&self, fixed: &File) -> Result<()> {
        context(self.uid)?;
        self.live()?;
        let observed = row(
            &self.read("stat", 8192)?,
            &self.read("status", 65536)?,
            &self.read("cgroup", 8192)?,
            self.pid,
            self.uid,
            self.parent,
        )?;
        require(
            observed.start_ticks == self.start,
            "desktop-rdp-task-reused",
        )?;
        let named = files::directory(&PathBuf::from(format!("/proc/{}", self.pid)), Some(0))?;
        let held = self.directory.metadata()?;
        let current = named.metadata()?;
        require(
            held.dev() == current.dev() && held.ino() == current.ino(),
            "desktop-rdp-task-directory-replaced",
        )?;
        // SAFETY: The name is a NUL-terminated literal and `self.directory` keeps the descriptor
        // open.
        let raw = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                c"exe".as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        require(raw >= 0, "desktop-rdp-task-executable")?;
        // SAFETY: `raw` was just returned by openat and is owned by nothing else.
        let current = unsafe { File::from_raw_fd(raw) };
        require(
            epoch(&self.image.metadata()?) == epoch(&fixed.metadata()?)
                && epoch(&current.metadata()?) == epoch(&fixed.metadata()?),
            "desktop-rdp-task-executable-changed",
        )?;
        self.live()
    }
}
fn worker_image() -> Result<(File, std::fs::Metadata)> {
    let path = Path::new(desktop_unit_trust::WORKER);
    let parent = files::directory(
        path.parent()
            .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
        Some(0),
    )?;
    let file = files::open_relative(
        &parent,
        Path::new(
            path.file_name()
                .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
        ),
    )?;
    let meta = file.metadata()?;
    require(
        meta.is_file()
            && meta.uid() == 0
            && meta.gid() == 0
            && meta.mode() & 0o6022 == 0
            && meta.mode() & 0o111 != 0
            && meta.nlink() == 1,
        "desktop-rdp-worker-executable-untrusted",
    )?;
    Ok((file, meta))
}
fn protected_proc(pid: u32, uid: u32) -> Result<bool> {
    let metadata = std::fs::symlink_metadata(format!("/proc/{pid}"))?;
    require(
        metadata.is_dir() && [0, uid].contains(&metadata.uid()),
        "desktop-rdp-task-proc-owner",
    )?;
    Ok(metadata.uid() == 0)
}
/// Whether the RDP worker of `main_pid` listens on `address`:`port` for `uid`.
///
/// # Errors
///
/// Fails when a worker child is invalid or changed.
pub fn listening(
    uid: u32,
    main_pid: u32,
    address: std::net::IpAddr,
    port: u16,
    proof: &serde_json::Value,
) -> Result<bool> {
    context(uid)?;
    let installed = desktop_rdp::Installed::observe()?;
    installed.matches(proof)?;
    let provider_image = installed.executable()?;
    let (worker_image, original_worker) = worker_image()?;
    // A freshly started worker has not reached its privacy setup yet.
    // That phase is never admitted as a ready protected provider.
    if !protected_proc(main_pid, uid)? {
        return Ok(false);
    }
    let worker = Task::observe(main_pid, uid, None, &worker_image)?;
    let children = worker.read(&format!("task/{main_pid}/children"), 8192)?;
    let children = children.split_whitespace().collect::<Vec<_>>();
    if children.is_empty() {
        worker.recheck(&worker_image)?;
        return Ok(false);
    }
    require(children.len() == 1, "desktop-rdp-worker-child-bound")?;
    let pid = children[0]
        .parse()
        .map_err(|_| Error("desktop-rdp-task-pid".into()))?;
    if !protected_proc(pid, uid)? {
        worker.recheck(&worker_image)?;
        return Ok(false);
    }
    let provider = Task::observe(pid, uid, Some(main_pid), &provider_image)?;
    let worker_sockets = sockets::inodes(main_pid, 0)?;
    let provider_sockets = sockets::inodes(pid, 0)?;
    let shared = worker_sockets
        .intersection(&provider_sockets)
        .copied()
        .collect();
    let result = sockets::listening(&sockets::table()?, &shared, address, port);
    installed.matches(proof)?;
    let (named_worker, current_worker) = self::worker_image()?;
    require(
        epoch(&original_worker) == epoch(&worker_image.metadata()?)
            && epoch(&original_worker) == epoch(&current_worker)
            && epoch(&original_worker) == epoch(&named_worker.metadata()?),
        "desktop-rdp-worker-executable-replaced",
    )?;
    provider.recheck(&provider_image)?;
    worker.recheck(&worker_image)?;
    require(
        worker
            .read(&format!("task/{main_pid}/children"), 8192)?
            .split_whitespace()
            .eq([children[0]]),
        "desktop-rdp-worker-child-changed",
    )?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
    fn root_observer_refuses_before_any_task_or_installed_file_access() {
        // SAFETY: getuid has no preconditions and cannot fail.
        if unsafe { libc::getuid() } == 0 {
            return;
        }
        assert_eq!(
            listening(
                1000,
                1,
                "192.0.2.4".parse().unwrap(),
                3389,
                &serde_json::Value::Null
            )
            .unwrap_err()
            .0,
            "desktop-rdp-root-observer-required"
        );
    }
    #[test]
    fn kernel_rows_require_actual_uids_parent_and_exact_unit() {
        let stat = format!("123 (protected peer) S 122 {} 456", "0 ".repeat(17));
        let group = "0::/system.slice/enzimos-desktop-sharing@1000.service\n";
        assert!(
            row(
                &stat,
                "Uid:\t1000\t1000\t1000\t1000\n",
                group,
                123,
                1000,
                Some(122)
            )
            .is_ok()
        );
        for (uid, parent, group) in [
            (1001, Some(122), group),
            (1000, Some(121), group),
            (1000, Some(122), "0::/user.slice/other.service\n"),
        ] {
            assert!(
                row(
                    &stat,
                    "Uid:\t1000\t1000\t1000\t1000\n",
                    group,
                    123,
                    uid,
                    parent
                )
                .is_err()
            );
        }
        assert!(row(&stat, "Uid:\t0\t0\t0\t0\n", group, 123, 1000, Some(122)).is_err());
    }
}
