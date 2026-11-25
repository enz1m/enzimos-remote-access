// SPDX-License-Identifier: MIT
//! Configuration transactions retain established SSH sessions unless separately reviewed.
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json};
/// Side effects of an SSH configuration transaction.
pub trait Provider {
    /// Guard that keeps other configuration transactions out.
    type Exclusive;
    /// A configuration ready to publish.
    type Prepared;
    /// Take the exclusive configuration guard.
    ///
    /// # Errors
    ///
    /// Fails when another transaction holds it.
    fn exclusive(&mut self) -> Result<Self::Exclusive>;
    /// The current configuration, if any.
    ///
    /// # Errors
    ///
    /// Fails when it cannot be read.
    fn current(&mut self) -> Result<Option<Value>>;
    /// Established remote connections.
    ///
    /// # Errors
    ///
    /// Fails when they cannot be observed.
    fn connections(&mut self) -> Result<Vec<Value>>;
    /// Prepare `configuration` for publication.
    ///
    /// # Errors
    ///
    /// Fails when it is invalid or cannot be staged.
    fn prepare(&mut self, configuration: &Value) -> Result<Self::Prepared>;
    /// Record that `uid` has a pending change to `reviewed`.
    ///
    /// # Errors
    ///
    /// Fails when the record cannot be written.
    fn pending(&mut self, uid: u32, reviewed: &Value) -> Result<()>;
    /// Stop the SSH listener.
    ///
    /// # Errors
    ///
    /// Fails when it cannot be stopped.
    fn stop_listening(&mut self) -> Result<()>;
    /// Release the firewall opening.
    ///
    /// # Errors
    ///
    /// Fails when it cannot be released.
    fn release_firewall(&mut self) -> Result<()>;
    /// Publish the prepared configuration.
    ///
    /// # Errors
    ///
    /// Fails when it cannot be written.
    fn publish(&mut self, prepared: Self::Prepared) -> Result<()>;
    /// Enable or disable starting SSH at boot.
    ///
    /// # Errors
    ///
    /// Fails when the unit cannot be changed.
    fn set_autostart(&mut self, enabled: bool) -> Result<()>;
    /// Start the SSH listener.
    ///
    /// # Errors
    ///
    /// Fails when it cannot be started.
    fn start_listening(&mut self) -> Result<()>;
    /// Verify the listener serves `configuration`.
    ///
    /// # Errors
    ///
    /// Fails when it differs.
    fn verify_listener(&mut self, configuration: &Value) -> Result<()>;
    /// Record a completed change by `uid`.
    ///
    /// # Errors
    ///
    /// Fails when the record cannot be written.
    fn complete(&mut self, uid: u32, configuration: &Value, result: &Value) -> Result<()>;
    /// Record a failed change by `uid`.
    ///
    /// # Errors
    ///
    /// Fails when the record cannot be written.
    fn failed(&mut self, uid: u32, detail: &str) -> Result<()>;
    /// Record a change by `uid` with an uncertain outcome.
    ///
    /// # Errors
    ///
    /// Fails when the record cannot be written.
    fn uncertain(&mut self, uid: u32, detail: &str) -> Result<()>;
    /// Disconnect sessions owned by the service, calling `before_commit` first.
    ///
    /// # Errors
    ///
    /// Fails when `before_commit` fails or a session cannot be disconnected.
    fn disconnect_owned_sessions(
        &mut self,
        before_commit: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()>;
    /// Whether the SSH listener is active.
    ///
    /// # Errors
    ///
    /// Fails when its state cannot be read.
    fn listener_active(&mut self) -> Result<bool>;
}
/// [`apply_checked`] with a `before_commit` that ignores the provider.
///
/// # Errors
///
/// As [`apply_checked`].
pub fn apply<P: Provider, F: FnMut() -> Result<()>>(
    provider: &mut P,
    uid: u32,
    reviewed: &Value,
    mut before_commit: F,
) -> Result<Value> {
    apply_checked(provider, uid, reviewed, |_| before_commit())
}
/// Apply the configuration `reviewed` for `uid`, stopping, publishing and restarting the listener
/// as needed.
///
/// # Errors
///
/// Fails for non-ordinary accounts, when another account has connections, the review is invalid,
/// `before_commit` fails, or a step fails.
pub fn apply_checked<P: Provider, F: FnMut(&mut P) -> Result<()>>(
    provider: &mut P,
    uid: u32,
    reviewed: &Value,
    mut before_commit: F,
) -> Result<Value> {
    require((1000..u32::MAX).contains(&uid), "ordinary-account-required")?;
    let _exclusive = provider.exclusive()?;
    before_commit(provider)?;
    let current = provider.current()?;
    if current.as_ref().is_some_and(|c| c["uid"] != uid) {
        require(
            provider.connections()?.is_empty(),
            "another-account-has-remote-connections",
        )?;
    }
    let configuration = &reviewed["plan"]["configuration"];
    require(
        configuration.is_object()
            && configuration["enabled"].is_boolean()
            && configuration["autostart"].is_boolean(),
        "review-plan-invalid",
    )?;
    let prepared = provider.prepare(configuration)?;
    before_commit(provider)?;
    provider.pending(uid, reviewed)?;
    let change: Result<Value> = (|| {
        provider.stop_listening()?;
        provider.release_firewall()?;
        provider.publish(prepared)?;
        let enabled = configuration["enabled"]
            .as_bool()
            .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?;
        let autostart = enabled
            && configuration["autostart"]
                .as_bool()
                .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?;
        provider.set_autostart(autostart)?;
        if enabled {
            provider.start_listening()?;
            provider.verify_listener(configuration)?;
        }
        let result = json!({"schema":1,"listening":enabled,"autostart":autostart,"existing_connections_disconnected":false,"connections":provider.connections()?});
        provider.complete(uid, configuration, &result)?;
        Ok(result)
    })();
    match change {
        Ok(result) => Ok(result),
        Err(_) => {
            let cleanup = [
                provider.stop_listening(),
                provider.release_firewall(),
                provider.set_autostart(false),
            ];
            if cleanup.iter().any(Result::is_err) {
                provider.uncertain(uid, "listener-or-firewall-cleanup-needs-review")?;
                return Err(Error("remote-state-uncertain-no-auto-retry".into()));
            }
            provider.failed(uid, "configuration-not-activated")?;
            Err(Error("remote-configuration-not-activated".into()))
        }
    }
}
/// [`disconnect_checked`] with no review step.
///
/// # Errors
///
/// As [`disconnect_checked`].
pub fn disconnect<P: Provider, F: FnMut() -> Result<()>>(
    provider: &mut P,
    uid: u32,
    before_commit: F,
) -> Result<Value> {
    disconnect_checked(provider, uid, |_| Ok(()), before_commit)
}
/// Disconnect every remote session for owner `uid` and report what was closed.
///
/// # Errors
///
/// Fails when `uid` is not the owner, the review fails, or a disconnect fails.
pub fn disconnect_checked<P: Provider, F: FnMut(&mut P) -> Result<()>, S: FnMut() -> Result<()>>(
    provider: &mut P,
    uid: u32,
    mut reviewed: F,
    mut before_commit: S,
) -> Result<Value> {
    let _exclusive = provider.exclusive()?;
    reviewed(provider)?;
    before_commit()?;
    let current = provider
        .current()?
        .ok_or_else(|| Error("remote-owner-mismatch".into()))?;
    require(current["uid"] == uid, "remote-owner-mismatch")?;
    let connections = provider.connections()?;
    reviewed(provider)?;
    before_commit()?;
    provider.disconnect_owned_sessions(&mut before_commit)?;
    Ok(
        json!({"schema":1,"disconnected_connection_count":connections.len(),"listening":provider.listener_active()?,"unrelated_sessions_signalled":false}),
    )
}
