// SPDX-License-Identifier: MIT
//! Configuration transactions retain established SSH sessions unless separately reviewed.
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json};
pub trait Provider {
    type Exclusive;
    type Prepared;
    fn exclusive(&mut self) -> Result<Self::Exclusive>;
    fn current(&mut self) -> Result<Option<Value>>;
    fn connections(&mut self) -> Result<Vec<Value>>;
    fn prepare(&mut self, configuration: &Value) -> Result<Self::Prepared>;
    fn pending(&mut self, uid: u32, reviewed: &Value) -> Result<()>;
    fn stop_listening(&mut self) -> Result<()>;
    fn release_firewall(&mut self) -> Result<()>;
    fn publish(&mut self, prepared: Self::Prepared) -> Result<()>;
    fn set_autostart(&mut self, enabled: bool) -> Result<()>;
    fn start_listening(&mut self) -> Result<()>;
    fn verify_listener(&mut self, configuration: &Value) -> Result<()>;
    fn complete(&mut self, uid: u32, configuration: &Value, result: &Value) -> Result<()>;
    fn failed(&mut self, uid: u32, detail: &str) -> Result<()>;
    fn uncertain(&mut self, uid: u32, detail: &str) -> Result<()>;
    fn disconnect_owned_sessions(
        &mut self,
        before_commit: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()>;
    fn listener_active(&mut self) -> Result<bool>;
}
pub fn apply<P: Provider, F: FnMut() -> Result<()>>(
    provider: &mut P,
    uid: u32,
    reviewed: &Value,
    mut before_commit: F,
) -> Result<Value> {
    apply_checked(provider, uid, reviewed, |_| before_commit())
}
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
pub fn disconnect<P: Provider, F: FnMut() -> Result<()>>(
    provider: &mut P,
    uid: u32,
    before_commit: F,
) -> Result<Value> {
    disconnect_checked(provider, uid, |_| Ok(()), before_commit)
}
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
