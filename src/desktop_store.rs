// SPDX-License-Identifier: MIT
//! PID 1 retains the endpoint until Root revokes both grants and firewall leases.
use crate::{
    desktop_grant, desktop_unit_trust, listener, notify,
    system::{Snapshot, System},
};
use enzimos_platform::{Error, Result, files, require};
use std::{
    net::{SocketAddr, TcpListener},
    os::fd::{AsFd, BorrowedFd},
    path::{Path, PathBuf},
};
use zbus::Connection;
const NOTIFY: &str = "/run/systemd/notify";
/// The sharing listener held in the unit's systemd file descriptor store.
pub struct Store {
    system: System,
    uid: u32,
}
impl Store {
    /// Open the store of `uid`'s sharing unit.
    ///
    /// # Errors
    ///
    /// Fails when the unit cannot be resolved.
    pub async fn new(connection: Connection, uid: u32) -> Result<Self> {
        desktop_grant::account(uid)?;
        Ok(Self {
            system: System::new(
                connection,
                &format!("enzimos-desktop-sharing@{uid}.service"),
            )
            .await?,
            uid,
        })
    }
    async fn properties(&self) -> Result<Snapshot> {
        desktop_unit_trust::properties(&self.system, self.uid).await
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    fn control(&self, p: &Snapshot) -> Result<bool> {
        let pid = std::process::id();
        let groups = files::read_kernel(&PathBuf::from(format!("/proc/{pid}/cgroup")), 8192)?;
        let expected = format!("0::/system.slice/{}", self.system.unit_name());
        // SAFETY: geteuid has no preconditions and cannot fail.
        Ok(unsafe { libc::geteuid() } == 0
            && p.control_pid == pid
            && groups
                .split(|b| *b == b'\n')
                .filter(|s| !s.is_empty())
                .any(|s| s == expected.as_bytes()))
    }
    async fn notify(&self, message: &[u8], fd: Option<BorrowedFd<'_>>) -> Result<()> {
        require(
            std::env::var("NOTIFY_SOCKET").ok().as_deref() == Some(NOTIFY)
                && self.control(&self.properties().await?)?,
            "desktop-listener-control-process-required",
        )?;
        notify::send(Path::new(NOTIFY), message, fd)?;
        // A receipt is not acceptance: callers must observe the actual FD count.
        tokio::task::spawn_blocking(|| notify::barrier(Path::new(NOTIFY)))
            .await
            .map_err(|_| Error("desktop-listener-store-receipt-uncertain".into()))?
    }
    /// Reserve `endpoint` and store its listener.
    ///
    /// # Errors
    ///
    /// Fails when the unit is not in its prepare step or storing is unconfirmed.
    pub async fn hold(&self, endpoint: SocketAddr) -> Result<TcpListener> {
        let p = self.properties().await?;
        require(
            self.control(&p)? && p.main_pid == 0,
            "desktop-listener-prepare-control-required",
        )?;
        require(p.fdstore == 0, "desktop-listener-cleanup-required")?;
        let socket = listener::reserve(endpoint)?;
        self.notify(
            b"FDSTORE=1\nFDNAME=desktop-listener\nFDPOLL=0",
            Some(socket.as_fd()),
        )
        .await?;
        require(
            self.properties().await?.fdstore == 1,
            "desktop-listener-store-unconfirmed",
        )?;
        Ok(socket)
    }
    /// Caller invokes only after revoking compositor grants and firewall leases.
    ///
    /// # Errors
    ///
    /// Fails when removal is unconfirmed.
    pub async fn clear(&self) -> Result<()> {
        let p = self.properties().await?;
        if p.fdstore == 0 {
            return Ok(());
        }
        if self.control(&p)? {
            self.notify(b"FDSTOREREMOVE=1\nFDNAME=desktop-listener", None)
                .await?;
        } else {
            self.system.clean_fdstore().await?;
        }
        require(
            self.properties().await?.fdstore == 0,
            "desktop-listener-release-unconfirmed",
        )
    }
}
