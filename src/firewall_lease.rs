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
    /// Every lease rule is present and nothing changed.
    Held,
    /// The lease was brought back to every rule.
    Reacquired,
}

/// Checks that the reviewed approval, listener and network still hold, and
/// brings the lease of the running listener in line with the result.
///
/// `approved` runs on every call. While it confirms, every lease rule is held.
/// While it reports that the reviewed network no longer applies, only the
/// lease's reject rules are held, so no new connection reaches the listener
/// until the network returns or the guard stops it. Any other failure leaves
/// the lease unchanged. While firewalld is stopped the journal's records are
/// dropped, because firewalld discards runtime rules when it stops.
///
/// # Errors
/// Returns the refusal of `approved`, or fails when firewalld does not confirm
/// the lease.
pub fn restore<I: Interface>(
    journal: &mut Journal<'_, I>,
    rules: &[Rule],
    running: bool,
    approved: impl FnOnce() -> Result<()>,
) -> Result<Restored> {
    if !running {
        journal.forget()?;
        approved()?;
        return Ok(Restored::NoFirewall);
    }
    let refusal = match approved() {
        Ok(()) => None,
        Err(error) if NETWORK_CHANGED.contains(&error.0.as_str()) => Some(error),
        // After any other failure the guard may no longer own the lease.
        Err(error) => return Err(error),
    };
    let desired: Vec<Rule> = rules
        .iter()
        .filter(|rule| rule.rejects())
        .chain(
            rules
                .iter()
                .filter(|rule| refusal.is_none() && !rule.rejects()),
        )
        .cloned()
        .collect();
    let changed = journal.reconcile(&desired);
    if let Some(error) = refusal {
        return Err(error);
    }
    Ok(if changed? {
        Restored::Reacquired
    } else {
        Restored::Held
    })
}

/// Refusals reporting that a listener's reviewed network no longer applies.
pub const NETWORK_CHANGED: &[&str] = &[
    "ssh-approved-network-changed",
    "listen-address-unavailable",
    "desktop-approved-network-changed",
];

/// How long a guard retries before a changed approval, network or listener ends it.
pub const RESTORE_WINDOW: Duration = Duration::from_secs(20);

/// How often a guard checks without an event.
///
/// Address changes made outside NetworkManager have no bus signal.
pub const RECHECK: Duration = Duration::from_secs(15);

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

/// Keeps a listener's lease on every firewalld or NetworkManager change, and at
/// least every [`RECHECK`], until it fails definitively.
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
        // Subscribing before each check leaves no unobserved change.
        let events = Watch::lease(connection).await;
        let run = Arc::clone(&attempt);
        let restored = keep(move || run()).await?;
        if previous != Some(restored) {
            eprintln!("{label} firewall lease: {restored:?}");
            previous = Some(restored);
        }
        let waited = match events {
            Ok(mut events) => tokio::time::timeout(RECHECK, events.changed())
                .await
                .unwrap_or(Ok(())),
            Err(error) => Err(error),
        };
        if let Err(error) = waited {
            eprintln!("{label} firewall events unavailable: {error}");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}
