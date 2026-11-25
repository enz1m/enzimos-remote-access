// SPDX-License-Identifier: MIT
//! Native units must be installed together with their native worker bytes.
use crate::{
    desktop_grant,
    system::{self, Properties, Snapshot},
};
use enzimos_platform::{Error, Result, require};
use std::path::Path;
use zbus::zvariant::OwnedValue;
pub const TEMPLATE: &str = "/usr/lib/systemd/system/enzimos-desktop-sharing@.service";
/// The per-account watcher that starts unattended sharing after sign-in.
pub const AUTOSTART_TEMPLATE: &str =
    "/usr/lib/systemd/system/enzimos-desktop-sharing-autostart@.service";
pub const WORKER: &str = "/usr/lib/enzimos-remote/desktop-worker";
const NATIVE_TEMPLATE: &[u8] = include_bytes!("../packaging/enzimos-desktop-sharing@.service");
pub fn native_template(bytes: &[u8]) -> bool {
    bytes == NATIVE_TEMPLATE
}
pub fn installed_template_matches() -> Result<bool> {
    crate::desktop_binding::installed(Path::new(TEMPLATE))?;
    let bytes = enzimos_platform::files::read(Path::new(TEMPLATE), 128 * 1024, Some(0), true)?;
    Ok(native_template(&bytes))
}
fn field<T: TryFrom<OwnedValue>>(p: &Properties, key: &str) -> Result<T> {
    T::try_from(
        p.get(key)
            .ok_or_else(|| Error("desktop-system-unit-untrusted".into()))?
            .try_clone()
            .map_err(|_| Error("desktop-system-unit-untrusted".into()))?,
    )
    .map_err(|_| Error("desktop-system-unit-untrusted".into()))
}
pub fn validate(unit: &Properties, service: &Properties, uid: u32) -> Result<Snapshot> {
    desktop_grant::account(uid)?;
    let snapshot = system::snapshot(unit, service)?;
    require(
        field::<String>(unit, "Id")? == format!("enzimos-desktop-sharing@{uid}.service")
            && !field::<bool>(unit, "Transient")?
            && field::<String>(unit, "FragmentPath")? == TEMPLATE
            && field::<Vec<String>>(unit, "DropInPaths")?.is_empty(),
        "desktop-system-unit-untrusted",
    )?;
    // systemd's ExecStart a(sasbttttuii) is checked without coercing booleans/integers.
    type Exec = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);
    let starts: Vec<Exec> = field(service, "ExecStart")?;
    require(
        field::<String>(service, "User")? == uid.to_string()
            && field::<String>(service, "KillMode")? == "control-group"
            && field::<String>(service, "Restart")? == "no"
            && starts.len() == 1
            && starts[0].0 == WORKER
            && starts[0].1 == [WORKER]
            && !starts[0].2,
        "desktop-system-unit-untrusted",
    )?;
    require(
        field::<u32>(service, "FileDescriptorStoreMax")? == 1
            && field::<String>(service, "FileDescriptorStorePreserve")? == "yes"
            && field::<String>(service, "NotifyAccess")? == "exec"
            && snapshot.fdstore <= 1
            && (snapshot.cgroup == format!("/system.slice/enzimos-desktop-sharing@{uid}.service")
                || (snapshot.cgroup.is_empty()
                    && matches!(snapshot.active.as_str(), "inactive" | "failed")
                    && snapshot.main_pid == 0
                    && snapshot.control_pid == 0)),
        "desktop-listener-lifetime-untrusted",
    )?;
    Ok(snapshot)
}
pub async fn properties(system: &system::System, uid: u32) -> Result<Snapshot> {
    let (unit, service) = system.raw_properties().await?;
    let result = validate(&unit, &service, uid)?;
    require(
        installed_template_matches()?,
        "desktop-system-unit-untrusted",
    )?;
    // Reading these fixed files walks every ancestor without following symlinks.
    crate::desktop_binding::installed(Path::new(TEMPLATE))?;
    crate::desktop_binding::installed(Path::new(WORKER))?;
    Ok(result)
}
