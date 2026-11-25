// SPDX-License-Identifier: MIT
//! Fixed separately owned units; no stock SSH unit or caller-selected operation.
use crate::bus_adapter::Pinned;
use enzimos_platform::{Error, Result, require};
use std::{collections::HashMap, time::Duration};
use zbus::{
    Connection,
    zvariant::{OwnedObjectPath, OwnedValue},
};
/// Unit name of the SSH service.
pub const SSH: &str = "enzimos-sshd.service";
/// Timer that retries SSH autostart after its approved network appears late.
pub const SSH_RETRY: &str = "enzimos-sshd-retry.timer";
const MANAGER: &str = "org.freedesktop.systemd1.Manager";
const PATH: &str = "/org/freedesktop/systemd1";
/// D-Bus properties of one systemd interface, by name.
pub type Properties = HashMap<String, OwnedValue>;
fn field<T: TryFrom<OwnedValue>>(v: &Properties, key: &str) -> Result<T> {
    T::try_from(
        v.get(key)
            .ok_or_else(|| Error("remote-unit-property-missing".into()))?
            .try_clone()
            .map_err(|_| Error("remote-unit-property-type".into()))?,
    )
    .map_err(|_| Error("remote-unit-property-type".into()))
}
/// Require one of the fixed remote-access unit names.
///
/// # Errors
///
/// Fails for any other unit.
pub fn unit(value: &str) -> Result<()> {
    if value == SSH {
        return Ok(());
    }
    let uid = value
        .strip_prefix("enzimos-desktop-sharing@")
        .or_else(|| value.strip_prefix("enzimos-desktop-sharing-autostart@"))
        .and_then(|s| s.strip_suffix(".service"))
        .ok_or_else(|| Error("remote-system-unit-invalid".into()))?;
    let n = uid
        .parse::<u32>()
        .map_err(|_| Error("remote-system-unit-invalid".into()))?;
    require(
        (1000..u32::MAX).contains(&n) && n.to_string() == uid,
        "remote-system-unit-invalid",
    )
}
/// Observed state of a unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Unit ActiveState.
    pub active: String,
    /// Main PID, or 0.
    pub main_pid: u32,
    /// Control PID, or 0.
    pub control_pid: u32,
    /// Number of descriptors in the unit's fd store.
    pub fdstore: u32,
    /// Control group path.
    pub cgroup: String,
}
/// Build a snapshot from unit and service properties.
///
/// # Errors
///
/// Fails when a property is missing, mistyped, or out of bounds.
pub fn snapshot(unit: &Properties, service: &Properties) -> Result<Snapshot> {
    require(
        unit.len() <= 512 && service.len() <= 512,
        "remote-unit-property-bound",
    )?;
    let active = field::<String>(unit, "ActiveState")?;
    let cgroup = field::<String>(service, "ControlGroup")?;
    let main_pid = field::<u32>(service, "MainPID")?;
    let control_pid = field::<u32>(service, "ControlPID")?;
    require(
        !active.is_empty()
            && active.len() <= 32
            && active.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
            && cgroup.len() <= 2048
            && !cgroup.chars().any(char::is_control)
            && main_pid < i32::MAX as u32
            && control_pid < i32::MAX as u32,
        "remote-unit-property-bound",
    )?;
    Ok(Snapshot {
        active,
        main_pid,
        control_pid,
        fdstore: field(service, "NFileDescriptorStore")?,
        cgroup,
    })
}
/// One fixed systemd unit on the system bus.
#[derive(Clone)]
pub struct System {
    bus: Pinned,
    unit: String,
}
impl System {
    /// The unit name.
    pub fn unit_name(&self) -> &str {
        &self.unit
    }
    /// Bind to unit `name` through systemd on `connection`.
    ///
    /// # Errors
    ///
    /// Fails for other units or when systemd is unavailable.
    pub async fn new(connection: Connection, name: &str) -> Result<Self> {
        unit(name)?;
        Ok(Self {
            bus: Pinned::new(connection, "org.freedesktop.systemd1").await?,
            unit: name.into(),
        })
    }
    /// Current state of the unit.
    ///
    /// # Errors
    ///
    /// Fails when the properties cannot be read.
    pub async fn properties(&self) -> Result<Snapshot> {
        let (unit, service) = self.raw_properties().await?;
        snapshot(&unit, &service)
    }
    /// Raw unit and service properties.
    ///
    /// # Errors
    ///
    /// Fails when the unit cannot be loaded or its properties read.
    pub async fn raw_properties(&self) -> Result<(Properties, Properties)> {
        let path: OwnedObjectPath = self
            .bus
            .call(PATH, MANAGER, "LoadUnit", &(self.unit.as_str(),))
            .await?;
        require(
            path.as_str().starts_with("/org/freedesktop/systemd1/unit/")
                && path.as_str().len() <= 512,
            "remote-unit-path-invalid",
        )?;
        let unit: Properties = self
            .bus
            .call(
                path.as_str(),
                "org.freedesktop.DBus.Properties",
                "GetAll",
                &("org.freedesktop.systemd1.Unit",),
            )
            .await?;
        let service: Properties = self
            .bus
            .call(
                path.as_str(),
                "org.freedesktop.DBus.Properties",
                "GetAll",
                &("org.freedesktop.systemd1.Service",),
            )
            .await?;
        require(
            unit.len() <= 512 && service.len() <= 512,
            "remote-unit-property-bound",
        )?;
        Ok((unit, service))
    }
    /// Whether the unit has entered the active state during this boot.
    ///
    /// # Errors
    /// Fails when systemd's owner changes or the property is unavailable.
    pub async fn activated(&self) -> Result<bool> {
        let (unit, _) = self.raw_properties().await?;
        Ok(field::<u64>(&unit, "ActiveEnterTimestampMonotonic")? != 0)
    }
    /// Stops the SSH autostart retry timer without waiting for the job.
    ///
    /// # Errors
    /// Fails for a non-SSH unit or when systemd refuses the job.
    pub async fn stop_retry(&self) -> Result<()> {
        self.retry_job("StopUnit").await
    }
    /// Starts the SSH retry timer for this boot without waiting for the job.
    ///
    /// # Errors
    /// Fails for a non-SSH unit or when systemd refuses the job.
    pub async fn start_retry(&self) -> Result<()> {
        self.retry_job("StartUnit").await
    }
    async fn retry_job(&self, method: &str) -> Result<()> {
        require(self.unit == SSH, "remote-system-unit-invalid")?;
        let path: OwnedObjectPath = self
            .bus
            .call(PATH, MANAGER, method, &(SSH_RETRY, "replace"))
            .await?;
        require(
            path.as_str().starts_with("/org/freedesktop/systemd1/job/")
                && path.as_str().len() <= 128,
            "remote-unit-job-invalid",
        )
    }
    /// Start or stop the unit (`start` or `stop`) and wait for the job.
    ///
    /// # Errors
    ///
    /// Fails for other operations or when the job fails or times out.
    pub async fn job(&self, operation: &str) -> Result<()> {
        let method = match operation {
            "start" => "StartUnit",
            "stop" => "StopUnit",
            _ => return Err(Error("remote-unit-operation-invalid".into())),
        };
        let path: OwnedObjectPath = self
            .bus
            .call(PATH, MANAGER, method, &(self.unit.as_str(), "replace"))
            .await?;
        require(
            path.as_str().starts_with("/org/freedesktop/systemd1/job/")
                && path.as_str().len() <= 128,
            "remote-unit-job-invalid",
        )?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
        loop {
            require(
                tokio::time::Instant::now() < deadline,
                "remote-unit-transition-timeout",
            )?;
            let rows: Vec<(
                u32,
                String,
                String,
                String,
                OwnedObjectPath,
                OwnedObjectPath,
            )> = self.bus.call(PATH, MANAGER, "ListJobs", &()).await?;
            require(rows.len() <= 8192, "remote-unit-job-bound")?;
            if !rows.iter().any(|r| r.4 == path) {
                let active = self.properties().await?.active;
                return require(
                    if operation == "start" {
                        active == "active"
                    } else {
                        matches!(active.as_str(), "inactive" | "failed")
                    },
                    "remote-unit-transition-unconfirmed",
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    /// Enable or disable the unit at boot.
    ///
    /// # Errors
    ///
    /// Fails when the unit cannot be enabled or disabled.
    pub async fn autostart(&self, enabled: bool) -> Result<()> {
        let changes: Vec<(String, String, String)> = if enabled {
            let (install, changes): (bool, Vec<(String, String, String)>) = self
                .bus
                .call(
                    PATH,
                    MANAGER,
                    "EnableUnitFiles",
                    &(vec![self.unit.as_str()], false, false),
                )
                .await?;
            require(install, "remote-unit-no-autostart-install-information")?;
            changes
        } else {
            self.bus
                .call(
                    PATH,
                    MANAGER,
                    "DisableUnitFiles",
                    &(vec![self.unit.as_str()], false),
                )
                .await?
        };
        require(
            changes.len() <= 4096
                && changes
                    .iter()
                    .all(|r| r.0.len() <= 32 && r.1.len() <= 4096 && r.2.len() <= 4096),
            "remote-unit-enablement-bound",
        )?;
        self.bus.call(PATH, MANAGER, "Reload", &()).await
    }
    /// Empty the unit's fd store; the unit must be stopped.
    ///
    /// # Errors
    ///
    /// Fails while the unit runs or when cleaning fails or times out.
    pub async fn clean_fdstore(&self) -> Result<()> {
        require(
            self.unit != SSH,
            "desktop-listener-clean-requires-stopped-unit",
        )?;
        let mut value = self.properties().await?;
        stopped(&value)?;
        if value.fdstore == 0 {
            return Ok(());
        }
        if value.active == "failed" {
            self.bus
                .call::<_, ()>(PATH, MANAGER, "ResetFailedUnit", &(self.unit.as_str(),))
                .await?;
            value = self.properties().await?;
            stopped(&value)?;
            require(
                value.active == "inactive",
                "desktop-listener-clean-requires-stopped-unit",
            )?;
            if value.fdstore == 0 {
                return Ok(());
            }
        }
        self.bus
            .call::<_, ()>(
                PATH,
                MANAGER,
                "CleanUnit",
                &(self.unit.as_str(), vec!["fdstore"]),
            )
            .await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
        loop {
            value = self.properties().await?;
            stopped(&value)?;
            if value.fdstore == 0 {
                return Ok(());
            }
            require(
                tokio::time::Instant::now() < deadline,
                "desktop-listener-fdstore-clean-timeout",
            )?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
/// Require that `value` is a stopped unit.
///
/// # Errors
///
/// Fails while the unit is active.
pub fn stopped(value: &Snapshot) -> Result<()> {
    require(
        matches!(value.active.as_str(), "inactive" | "failed")
            && value.main_pid == 0
            && value.control_pid == 0,
        "desktop-listener-clean-requires-stopped-unit",
    )
}
