// SPDX-License-Identifier: MIT
//! A running listener keeps its lease across firewalld reloads, stops and restarts.
use crate::{
    desktop_events::Watch,
    firewall::{Interface, Rule},
    firewall_journal::Journal,
};
use enzimos_platform::{Error, Result};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use zbus::Connection;

/// What [`restore`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restored {
    /// firewalld is not running, so nothing filters the listener and no lease exists.
    NoFirewall,
    /// Every lease rule is present.
    Held,
    /// Missing rules were acquired again.
    Reacquired,
}

/// Brings the lease of a listener that keeps running in line with firewalld.
///
/// While firewalld is stopped the journal's records are dropped, because
/// firewalld discards runtime rules when it stops. Missing rules are acquired
/// again only after `approved` confirms the reviewed approval, listener and
/// network still hold.
///
/// # Errors
/// Fails when `approved` refuses or firewalld does not confirm the lease.
pub fn restore<I: Interface>(
    journal: &mut Journal<'_, I>,
    rules: &[Rule],
    running: bool,
    approved: impl FnOnce() -> Result<()>,
) -> Result<Restored> {
    if !running {
        journal.forget()?;
        return Ok(Restored::NoFirewall);
    }
    let mut held = true;
    for rule in rules {
        held &= journal.interface.query(rule)?;
    }
    if held {
        return Ok(Restored::Held);
    }
    approved()?;
    journal.release()?;
    journal.acquire(rules)?;
    Ok(Restored::Reacquired)
}

/// How long a guard retries before a changed approval, network or listener ends it.
pub const RESTORE_WINDOW: Duration = Duration::from_secs(20);

/// Refusals that end a guard, and with it the listener, once [`RESTORE_WINDOW`] ends.
///
/// Any other failure, such as a firewalld that is starting, reloading or not
/// answering, is retried for as long as the listener runs.
pub const DEFINITIVE: &[&str] = &[
    "remote-approved-configuration-changed",
    "ssh-approved-network-changed",
    "listen-address-unavailable",
    "ssh-listener-not-active",
    "desktop-grant-changed",
    "desktop-approved-network-changed",
    "desktop-listener-not-active",
];

/// Whether `error` reports a changed approval, network or listener.
pub fn definitive(error: &Error) -> bool {
    DEFINITIVE.contains(&error.0.as_str())
}

/// Runs `attempt` in a blocking worker until it succeeds or fails definitively.
///
/// firewalld can own its bus name before it answers, and an interface can
/// briefly leave its zone while NetworkManager reconnects, so every failure is
/// retried within [`RESTORE_WINDOW`]. After it, only [`definitive`] failures
/// are returned; others keep being retried.
///
/// # Errors
/// Returns a definitive failure that persists past the window.
pub async fn keep<F>(attempt: F) -> Result<Restored>
where
    F: Fn() -> Result<Restored> + Send + Sync + 'static,
{
    let attempt = Arc::new(attempt);
    let deadline = Instant::now() + RESTORE_WINDOW;
    let mut reported = None;
    loop {
        let run = Arc::clone(&attempt);
        let result = tokio::task::spawn_blocking(move || run())
            .await
            .map_err(|_| Error("unit-firewall-worker-unavailable".into()))?;
        let error = match result {
            Ok(restored) => return Ok(restored),
            Err(error) if Instant::now() >= deadline && definitive(&error) => return Err(error),
            Err(error) => error,
        };
        if reported.as_ref() != Some(&error.0) {
            eprintln!("firewall lease not restored yet: {error}");
            reported = Some(error.0);
        }
        let pause = if Instant::now() < deadline { 1 } else { 5 };
        tokio::time::sleep(Duration::from_secs(pause)).await;
    }
}

/// Keeps a listener's lease on every firewalld change until it fails definitively.
///
/// A bus subscription that fails is retried; it never ends the listener.
///
/// # Errors
/// Returns the definitive failure from [`keep`].
pub async fn follow<F>(connection: &Connection, label: &str, attempt: F) -> Result<()>
where
    F: Fn() -> Result<Restored> + Send + Sync + 'static,
{
    let attempt = Arc::new(attempt);
    let mut previous = None;
    loop {
        // Subscribing before each check leaves no unobserved firewalld change.
        let events = Watch::firewall(connection).await;
        let run = Arc::clone(&attempt);
        let restored = keep(move || run()).await?;
        if previous != Some(restored) {
            eprintln!("{label} firewall lease: {restored:?}");
            previous = Some(restored);
        }
        let waited = match events {
            Ok(mut events) => events.changed().await,
            Err(error) => Err(error),
        };
        if let Err(error) = waited {
            eprintln!("{label} firewall events unavailable: {error}");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}
