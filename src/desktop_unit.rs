// SPDX-License-Identifier: MIT
//! Root reserves before granting the firewall; release revokes before freeing it.
use crate::{
    compositor_grant,
    desktop_events::Watch,
    desktop_grant,
    desktop_provider::{Desktop, Resumed},
    desktop_session::Session,
    desktop_store::Store,
    firewall::{self, Rule},
    firewall_bus::Firewall,
    firewall_journal::Journal,
    firewall_lease::{self, Restored},
    network, ssh_provider,
    system::System,
};
use enzimos_platform::{Error, Result, files, require};
use serde_json::Value;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use zbus::Connection;
/// Runs one fixed Root operation of `enzimos-desktop-sharing@UID.service`.
///
/// `prepare` and `release` run inside the sharing unit; `watch` runs in its
/// firewall guard unit and keeps the lease across firewalld reloads, stops and
/// restarts. Without a running firewalld, sharing runs unfiltered. `autostart`
/// runs in `enzimos-desktop-sharing-autostart@UID.service` and starts
/// unattended sharing whenever the account's session and reviewed network allow it.
///
/// # Errors
/// Fails for an unknown operation or account, without initial-namespace root,
/// or when the grant, session, network or firewall lease do not match.
pub async fn entry(operation: &str, uid: u32, connection: Connection) -> Result<()> {
    require(
        matches!(operation, "prepare" | "release" | "watch" | "autostart"),
        "desktop-unit-operation-invalid",
    )?;
    desktop_grant::account(uid)?;
    ssh_provider::root_context()?;
    match operation {
        "watch" => return watch(uid, connection).await,
        "autostart" => return autostart(uid, connection).await,
        _ => {}
    }
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
        let released = journal.release_or_forget();
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
    let session = runtime.block_on(Session::new(connection.clone()))?;
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
    let interface = desktop_grant::approved_interface(&grant, &addresses)?;
    let firewall_running = runtime.block_on(journal.interface.running())?;
    let zone = if firewall_running {
        Some(runtime.block_on(journal.interface.zone_for(&interface))?)
    } else {
        None
    };
    desktop_grant::approved_zone(&grant, zone.as_deref())?;
    desktop_grant::approved_connection(
        &grant,
        runtime
            .block_on(network::connection(&connection, &interface))?
            .as_deref(),
    )?;
    compositor_grant::revoke(uid)?;
    if firewall_running {
        journal.release()?;
    } else {
        journal.forget()?;
    }
    let endpoint = SocketAddr::new(
        ip,
        configuration["port"]
            .as_u64()
            .ok_or_else(|| Error("desktop-listen-port".into()))? as u16,
    );
    let connection = runtime.block_on(store.hold(endpoint))?;
    let result: Result<()> = (|| {
        // A firewalld that starts after the zone check is leased by the guard,
        // which checks the reviewed zone first.
        if firewall_running {
            journal.acquire(&firewall::rules(configuration, firewall::TARGET)?)?;
        }
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
        let _ = journal.release_or_forget();
        let _ = runtime.block_on(store.clear());
        return Err(error);
    }
    // Only the control helper's duplicate closes here; PID 1 keeps its reservation.
    drop(connection);
    Ok(())
}
struct Guarded {
    uid: u32,
    connection: Connection,
    boot: String,
    grant: Value,
    rules: Vec<Rule>,
    system: System,
    main_pid: u32,
}
// Exiting stops sharing: the sharing unit and its guard bind each other.
async fn watch(uid: u32, connection: Connection) -> Result<()> {
    let boot = ssh_provider::boot_id()?;
    let grant = tokio::task::spawn_blocking(move || desktop_grant::load(uid))
        .await
        .map_err(|_| Error("desktop-unit-outcome-unknown".into()))??;
    let rules = firewall::rules(&grant["configuration"], firewall::TARGET)?;
    let system = System::new(
        connection.clone(),
        &format!("enzimos-desktop-sharing@{uid}.service"),
    )
    .await?;
    let listener = system.properties().await?;
    require(
        listener.active == "active" && listener.main_pid > 0,
        "desktop-listener-not-active",
    )?;
    let guarded = Arc::new(Guarded {
        uid,
        connection: connection.clone(),
        boot,
        grant,
        rules,
        system,
        main_pid: listener.main_pid,
    });
    firewall_lease::follow(&connection, "desktop", move || renew(&guarded)).await
}
fn renew(guarded: &Guarded) -> Result<Restored> {
    let runtime = tokio::runtime::Handle::current();
    let directory = desktop_grant::folder(guarded.uid)?;
    let _lock = files::Lock::acquire(&directory.join("firewall.lock"), 0)?;
    let mut provider = runtime.block_on(Firewall::new(guarded.connection.clone()))?;
    let running = runtime.block_on(provider.running())?;
    let observer = provider.clone();
    let path = directory.join("firewall.json");
    let mut journal = Journal {
        path: &path,
        owner: 0,
        boot_id: &guarded.boot,
        interface: &mut provider,
    };
    firewall_lease::restore(&mut journal, &guarded.rules, running, || {
        require(
            desktop_grant::load(guarded.uid)? == guarded.grant,
            "desktop-grant-changed",
        )?;
        let listener = runtime.block_on(guarded.system.properties())?;
        require(
            listener.active == "active" && listener.main_pid == guarded.main_pid,
            "desktop-listener-not-active",
        )?;
        runtime.block_on(desktop_grant::verify_network(
            &guarded.grant,
            &guarded.connection,
            &observer,
        ))
    })
}

/// Longest pause after failed start attempts.
const RETRY_LIMIT: Duration = Duration::from_secs(600);
/// How often a watcher looks for the compositor of a session that has signed in.
const COMPOSITOR_RECHECK: Duration = Duration::from_secs(2);

// Exits once unattended sharing is off; the remote service disables this unit then.
async fn autostart(uid: u32, connection: Connection) -> Result<()> {
    let mut failures = 0u32;
    let mut previous = None;
    loop {
        // Subscribing before each attempt leaves no unobserved change.
        let events = Watch::sessions(&connection).await;
        // A fresh provider binds the current logind, systemd and firewalld owners.
        let result = match Desktop::new(connection.clone()).await {
            Ok(mut desktop) => tokio::task::spawn_blocking(move || desktop.resume(uid))
                .await
                .map_err(|_| Error("desktop-unattended-unavailable".into()))?,
            Err(error) => Err(error),
        };
        let report = match &result {
            Ok(resumed) => format!("{resumed:?}"),
            Err(error) => format!("failed: {error}"),
        };
        if previous.as_ref() != Some(&report) {
            eprintln!("unattended desktop sharing: {report}");
            previous = Some(report);
        }
        let mut recheck = firewall_lease::RECHECK;
        match result {
            Ok(Resumed::Off) => return Ok(()),
            Ok(Resumed::Running | Resumed::Started) => failures = 0,
            // A signed-in session's compositor and socket appear without a bus signal.
            Ok(Resumed::Waiting(reason)) if reason.starts_with("desktop-owned-") => {
                recheck = COMPOSITOR_RECHECK;
            }
            Ok(Resumed::Waiting(_)) => {}
            Err(_) => {
                // A start that fails keeps failing on the same session; back off.
                failures = failures.saturating_add(1);
                let pause = firewall_lease::RECHECK
                    .saturating_mul(1 << failures.min(6))
                    .min(RETRY_LIMIT);
                tokio::time::sleep(pause).await;
                continue;
            }
        }
        let waited = match events {
            Ok(mut events) => tokio::time::timeout(recheck, events.changed())
                .await
                .unwrap_or(Ok(())),
            Err(error) => Err(error),
        };
        if let Err(error) = waited {
            eprintln!("unattended desktop sharing events unavailable: {error}");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}
