// SPDX-License-Identifier: MIT
//! Root reserves before granting the firewall; release revokes before freeing it.
use crate::{
    compositor_grant, desktop_grant, desktop_session::Session, desktop_store::Store, firewall,
    firewall_bus::Firewall, firewall_journal::Journal, network, ssh_provider,
};
use enzimos_platform::{Error, Result, files, require};
use std::net::SocketAddr;
use zbus::Connection;
pub async fn entry(operation: &str, uid: u32, connection: Connection) -> Result<()> {
    require(
        matches!(operation, "prepare" | "release"),
        "desktop-unit-operation-invalid",
    )?;
    desktop_grant::account(uid)?;
    ssh_provider::root_context()?;
    let operation = operation.to_owned();
    let runtime = tokio::runtime::Handle::current();
    // The lock lives inside the job until cleanup finishes, including caller cancellation.
    tokio::task::spawn_blocking(move || execute(&operation, uid, connection, &runtime))
        .await
        .map_err(|_| Error("desktop-unit-outcome-unknown".into()))?
}
fn execute(
    operation: &str,
    uid: u32,
    connection: Connection,
    runtime: &tokio::runtime::Handle,
) -> Result<()> {
    ssh_provider::root_context()?;
    let directory = desktop_grant::folder(uid)?;
    files::ensure_directory(&directory, 0o700, 0)?;
    let _lock = files::Lock::acquire(&directory.join("firewall.lock"), 0)?;
    let boot = ssh_provider::boot_id()?;
    let mut provider = runtime.block_on(Firewall::new(connection.clone()))?;
    let path = directory.join("firewall.json");
    let mut journal = Journal {
        path: &path,
        owner: 0,
        boot_id: &boot,
        interface: &mut provider,
    };
    let store = runtime.block_on(Store::new(connection.clone(), uid))?;
    if operation == "release" {
        // Attempt every cleanup step even if an earlier one fails, so a grant
        // revocation error never leaves the firewall rule and socket open.
        let revoked = desktop_grant::revoke(uid);
        let capture_revoked = compositor_grant::revoke(uid);
        let released = journal.release();
        let cleared = runtime.block_on(store.clear());
        revoked?;
        capture_revoked?;
        released?;
        return cleared;
    }
    let addresses = network::interfaces()?;
    let grant = desktop_grant::validate(
        &desktop_grant::load(uid)?,
        uid,
        &boot,
        &addresses.keys().copied().collect(),
    )?;
    let session = runtime.block_on(Session::new(connection))?;
    runtime.block_on(session.verify(&grant["session"]))?;
    let configuration = &grant["configuration"];
    let provider_identity = if crate::desktop_rdp::selected(configuration) {
        let installed = crate::desktop_rdp::Installed::observe()?;
        installed.matches(&grant["provider"])?;
        Some(installed)
    } else {
        None
    };

    let ip = configuration["listen_address"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error("desktop-approved-network-changed".into()))?;
    let interface = addresses
        .get(&ip)
        .ok_or_else(|| Error("desktop-approved-network-changed".into()))?;
    require(
        grant["interface"] == *interface
            && grant["zone"] == runtime.block_on(journal.interface.zone_for(interface))?,
        "desktop-approved-network-changed",
    )?;
    compositor_grant::revoke(uid)?;
    journal.release()?;
    let endpoint = SocketAddr::new(
        ip,
        configuration["port"]
            .as_u64()
            .ok_or_else(|| Error("desktop-listen-port".into()))? as u16,
    );
    let connection = runtime.block_on(store.hold(endpoint))?;
    let result: Result<()> = (|| {
        journal.acquire(&firewall::rules(configuration, firewall::TARGET)?)?;
        runtime.block_on(session.verify(&grant["session"]))?;
        require(desktop_grant::load(uid)? == grant, "desktop-grant-changed")?;
        if let Some(installed) = &provider_identity {
            installed.matches(&grant["provider"])?;
        }
        compositor_grant::publish(uid, configuration["view_only"].as_bool().unwrap())?;
        if let Some(installed) = &provider_identity {
            installed.matches(&grant["provider"])?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        let _ = compositor_grant::revoke(uid);
        let _ = journal.release();
        let _ = runtime.block_on(store.clear());
        return Err(error);
    }
    // Only the control helper's duplicate closes here; PID 1 keeps its reservation.
    drop(connection);
    Ok(())
}
