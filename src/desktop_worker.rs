// SPDX-License-Identifier: MIT
//! The encrypted capture process runs as the approved desktop owner, never Root.
use crate::{
    config, desktop_binding, desktop_events::Watch, desktop_grant, desktop_identity,
    desktop_session::Session, firewall_bus::Firewall, firewall_lease,
};
use enzimos_platform::{Error, Result, files, require};
use serde_json::Value;
use std::{
    net::TcpListener,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::unix::AsyncFd,
    process::{Child, Command},
    signal::unix::{SignalKind, signal},
};

pub fn command(configuration: &Value, directory: &Path, listener_fd: i32) -> Result<Vec<String>> {
    require(
        !crate::desktop_rdp::selected(configuration),
        "desktop-wayvnc-configuration-required",
    )?;
    require((3..=1024).contains(&listener_fd), "desktop-listener-fd")?;
    let _path_check = config::tls_config(directory, &"A".repeat(32))?;
    let address = configuration["listen_address"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error("desktop-listen-address-unavailable".into()))?;
    let checked = config::desktop(configuration, &std::collections::BTreeSet::from([address]))?;
    require(
        checked == *configuration
            && checked["enabled"] == true
            && checked["mode"] == "session-sharing",
        "desktop-sharing-grant-required",
    )?;
    let mut args = vec![
        format!("--config={}", directory.join("wayvnc.conf").display()),
        format!("--socket={}", directory.join("control.sock").display()),
        "--log-level=error".into(),
        format!("--max-fps={}", checked["max_fps"].as_u64().unwrap()),
        "--disable-resizing".into(),
    ];
    if checked["view_only"] == true {
        args.push("--disable-input".into());
    }
    if let Some(output) = checked["output"].as_str() {
        args.push(format!("--output={output}"));
    }
    args.push(format!("fd:{listener_fd}"));
    Ok(args)
}
// The Root firewall guard keeps the lease; the worker cannot write firewall rules.
async fn check(
    session: &Session,
    bus: &zbus::Connection,
    grant: &Value,
) -> Result<enzimos_platform::process_identity::Retained> {
    let retained = check_session(session, grant).await?;
    check_network(bus, grant).await?;
    Ok(retained)
}
async fn check_session(
    session: &Session,
    grant: &Value,
) -> Result<enzimos_platform::process_identity::Retained> {
    let retained = session.verify_granted(&grant["session"]).await?;
    retained.recheck()?;
    Ok(retained)
}
async fn check_network(bus: &zbus::Connection, grant: &Value) -> Result<()> {
    let firewall = Firewall::new(bus.clone()).await?;
    desktop_grant::verify_network(grant, &firewall).await
}
// A firewalld reload or restart and a NetworkManager reconnect briefly report
// another zone or no answer; only a lasting network change ends sharing.
fn settle_network(result: Result<()>, unsettled: &mut Option<Instant>) -> Result<()> {
    let Err(error) = result else {
        *unsettled = None;
        return Ok(());
    };
    let since = *unsettled.get_or_insert_with(Instant::now);
    if firewall_lease::definitive(&error) && since.elapsed() >= firewall_lease::RESTORE_WINDOW {
        return Err(error);
    }
    eprintln!("desktop network not confirmed yet: {error}");
    Ok(())
}
struct Capture {
    child: Child,
    pidfd: OwnedFd,
}
impl Capture {
    #[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
    fn signal(&self, value: i32) -> Result<()> {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                value,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        require(
            rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
            "desktop-owned-child-signal-unavailable",
        )
    }
    async fn stop(&mut self) -> Result<()> {
        let termination = self.signal(libc::SIGTERM);
        if let Ok(status) = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await {
            status?;
            return termination;
        }
        self.signal(libc::SIGKILL)?;
        tokio::time::timeout(Duration::from_secs(5), self.child.wait())
            .await
            .map_err(|_| Error("desktop-owned-child-reap-uncertain".into()))??;
        termination
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        let _ = self.signal(libc::SIGKILL);
    }
}
#[allow(unsafe_code, reason = "Fork-child setup must run before exec.")]
pub async fn run(
    uid: u32,
    grant: Value,
    connection: TcpListener,
    home: PathBuf,
    bus: zbus::Connection,
) -> Result<()> {
    desktop_grant::account(uid)?;
    require(
        unsafe { libc::getuid() } == uid
            && unsafe { libc::geteuid() } == uid
            && grant["uid"].as_u64() == Some(uid as u64),
        "desktop-ordinary-user-worker-required",
    )?;
    desktop_grant::session(&grant["session"], uid)?;
    let session = Session::new(bus.clone()).await?;
    let session_id = grant["session"]["id"].as_str().unwrap();
    let mut watch = Watch::new(&bus, &session, session_id).await?;
    let mut term = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let identity_path = home.join(".local/share/enzimos/remote-desktop");
    let private_runtime = PathBuf::from(format!("/run/user/{uid}/enzimos-sharing")).join(
        grant["nonce"]
            .as_str()
            .filter(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            .ok_or_else(|| Error("desktop-grant-invalid".into()))?
            .get(..16)
            .unwrap(),
    );
    let rdp = crate::desktop_rdp::selected(&grant["configuration"]);
    if rdp {
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        require(
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } == 0
                && unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } == 0,
            "desktop-worker-privacy-unavailable",
        )?;
    }
    let installed_rdp = if rdp {
        let installed = crate::desktop_rdp::Installed::observe()?;
        installed.matches(&grant["provider"])?;
        Some(installed)
    } else {
        None
    };
    let program = if rdp {
        crate::desktop_rdp::PROGRAM
    } else {
        "/usr/bin/wayvnc"
    };
    let runtime_copy = private_runtime.clone();
    let identity_copy = identity_path.clone();
    let credential = tokio::task::spawn_blocking(move || -> Result<Option<OwnedFd>> {
        let identity = desktop_identity::ensure(&identity_copy, uid)?;
        files::ensure_directory(&runtime_copy, 0o700, uid)?;
        if rdp {
            crate::desktop_rdp::credential(identity.password()).map(Some)
        } else {
            files::atomic(
                &runtime_copy.join("wayvnc.conf"),
                &identity.tls_config(&identity_copy)?,
                0o600,
                Some(uid),
                true,
            )?;
            Ok(None)
        }
    })
    .await
    .map_err(|_| Error("desktop-identity-operation-unavailable".into()))??;
    let retained = check(&session, &bus, &grant).await?;
    require(!watch.lost(), "desktop-session-authority-lost")?;
    let compositor_exit = AsyncFd::new(retained.pidfd().try_clone_to_owned()?)?;
    let fixed = desktop_binding::installed(Path::new(program))?;
    use std::os::unix::fs::MetadataExt;
    require(
        fixed.mode() & 0o111 != 0,
        "desktop-capture-program-unavailable",
    )?;
    let fd = unsafe { libc::fcntl(connection.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
    require(fd >= 0, "desktop-listener-duplication-unavailable")?;
    let inherited = unsafe { OwnedFd::from_raw_fd(fd) };
    require(
        (64..=1024).contains(&fd),
        "desktop-listener-duplication-unavailable",
    )?;
    let credential_fd = credential.as_ref().map(AsRawFd::as_raw_fd);
    let args = if let Some(secret) = credential_fd {
        crate::desktop_rdp::command(&grant["configuration"], &identity_path, fd, secret)?
    } else {
        command(&grant["configuration"], &private_runtime, fd)?
    };
    if let Some(installed) = &installed_rdp {
        installed.recheck()?;
    }
    let mut capture = Command::new(program);
    capture
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LANG", "C.UTF-8")
        .env("HOME", &home)
        .env("XDG_RUNTIME_DIR", format!("/run/user/{uid}"))
        .env(
            "WAYLAND_DISPLAY",
            Path::new(grant["session"]["wayland"]["path"].as_str().unwrap())
                .file_name()
                .unwrap(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if rdp {
        capture.env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path=/run/user/{uid}/bus"),
        );
    }
    let executable = installed_rdp
        .as_ref()
        .map(crate::desktop_rdp::Installed::executable)
        .transpose()?;
    let argv = std::iter::once(std::ffi::OsStr::new(program))
        .chain(capture.as_std().get_args())
        .map(|s| {
            std::ffi::CString::new(s.as_encoded_bytes())
                .map_err(|_| Error("desktop-capture-argument-invalid".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    let environment = capture
        .as_std()
        .get_envs()
        .filter_map(|(key, value)| value.map(|value| (key, value)))
        .map(|(key, value)| {
            let mut bytes = key.as_encoded_bytes().to_vec();
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_encoded_bytes());
            std::ffi::CString::new(bytes)
                .map_err(|_| Error("desktop-capture-environment-invalid".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    unsafe {
        capture.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some(secret) = credential_fd {
                if libc::fcntl(secret, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if let Some(executable) = &executable {
                return crate::desktop_rdp::exec_original(executable, &argv, &environment);
            }
            Ok(())
        });
    }
    let child = capture.spawn()?;
    drop(credential);
    drop(inherited);
    drop(connection);
    let pid = child
        .id()
        .ok_or_else(|| Error("desktop-capture-process-unavailable".into()))?;
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
    require(pidfd >= 0, "desktop-capture-process-unavailable")?;
    let mut capture = Capture {
        child,
        pidfd: unsafe { OwnedFd::from_raw_fd(pidfd) },
    };
    let result: Result<()> = async {
        let now = desktop_binding::installed(Path::new(program))?;
        require((fixed.dev(), fixed.ino(), fixed.len(), fixed.mtime(), fixed.mtime_nsec(), fixed.ctime(), fixed.ctime_nsec()) == (now.dev(), now.ino(), now.len(), now.mtime(), now.mtime_nsec(), now.ctime(), now.ctime_nsec()), "desktop-capture-program-replaced")?;
        // The protected child cannot be inspected through proc after disabling dumps.
        // Its executable comes from the original checked FD and its task from spawn/pidfd.
        if !rdp {
        let stat = String::from_utf8(files::read_kernel_owned(&PathBuf::from(format!("/proc/{pid}/stat")), 8192, uid)?).map_err(|_| Error("desktop-capture-process-unavailable".into()))?;
        let stat = enzimos_platform::process_identity::parse_stat(&stat, pid)?;
        let owned = enzimos_platform::process_identity::Retained::open(pid, stat.start_ticks, uid, &[PathBuf::from(program)])?;
        let status = String::from_utf8(files::read_kernel_owned(&PathBuf::from(format!("/proc/{pid}/status")), 65536, uid)?).map_err(|_| Error("desktop-capture-process-unavailable".into()))?;
        require(enzimos_platform::process_identity::parse_uids(&status)? == [uid;4], "desktop-capture-user-changed")?;
        owned.recheck()?;
        }
        if let Some(installed) = &installed_rdp { installed.recheck()?; }
        check(&session, &bus, &grant).await?;
        require(!watch.lost(), "desktop-session-authority-lost")?;
        let mut unsettled = None;
        loop {
            tokio::select! {
                status = capture.child.wait() => { status?; return Err(Error("desktop-capture-process-exited".into())); },
                _ = term.recv() => return Ok(()),
                _ = interrupt.recv() => return Ok(()),
                _ = compositor_exit.readable() => return Err(Error("desktop-compositor-exited".into())),
                event = watch.changed() => {
                    event?;
                    if watch.firewall_moved() {
                        watch.retire();
                        watch = Watch::new(&bus, &session, session_id).await?;
                    }
                    check_session(&session, &grant).await?;
                    require(!watch.lost(), "desktop-session-authority-lost")?;
                    settle_network(check_network(&bus, &grant).await, &mut unsettled)?;
                },
                () = tokio::time::sleep(Duration::from_secs(1)), if unsettled.is_some() => {
                    settle_network(check_network(&bus, &grant).await, &mut unsettled)?;
                },
            }
        }
    }.await;
    // Retire callbacks before delivering termination to the owned capture child.
    watch.retire();
    let stopped = capture.stop().await;
    // The per-run config holds the sharing password; never leave copies behind.
    let _ = std::fs::remove_dir_all(&private_runtime);
    stopped?;
    // The compositor can close WayVNC before the logind signal is consumed.
    // Only a positively observed lock of this exact session is a normal stop;
    // owner loss, network errors and an ordinary capture crash remain failures.
    if result.as_ref().is_err_and(|error| {
        matches!(
            error.0.as_str(),
            "desktop-capture-process-exited" | "desktop-local-unlocked-session-required"
        )
    }) && session
        .locked_after_capture_stop(&grant["session"])
        .await
        .unwrap_or(false)
    {
        return Ok(());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
    async fn only_the_spawned_capture_task_is_signalled_and_reaped() {
        let child = Command::new("/usr/bin/sleep")
            .arg("30")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
        assert!(fd >= 0);
        let mut capture = Capture {
            child,
            pidfd: unsafe { OwnedFd::from_raw_fd(fd) },
        };
        capture.stop().await.unwrap();
        assert!(capture.child.try_wait().unwrap().is_some());
        // A second stop through the same pidfd cannot hit a reused numeric PID.
        capture.stop().await.unwrap();
    }
}
