// SPDX-License-Identifier: MIT
//! Concrete separately owned SSH lifecycle, invoked by fresh-authority dispatch.
use crate::{
    config,
    connections::Tracker,
    controller::Provider,
    dispatch::ReviewedProvider,
    firewall::{self, Rule},
    firewall_bus::Firewall,
    firewall_journal::Journal,
    firewall_lease::{self, Restored},
    network,
    ssh_files::{Layout, Prepared},
    state::State,
    system::{self, System},
};
use enzimos_platform::{Error, Result, accounts, files, json, require};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::Path,
    time::{Duration, Instant},
};
use zbus::Connection;
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
pub fn root_context() -> Result<()> {
    require(
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() } == 0,
        "initial-root-service-required",
    )?;
    for kind in ["mnt", "net"] {
        require(
            std::fs::read_link(format!("/proc/self/ns/{kind}"))?
                == std::fs::read_link(format!("/proc/1/ns/{kind}"))?,
            "initial-root-service-namespace-required",
        )?;
    }
    Ok(())
}
pub(crate) fn boot_id() -> Result<String> {
    let body = files::read_kernel(Path::new("/proc/sys/kernel/random/boot_id"), 64)?;
    let s = std::str::from_utf8(&body)
        .map_err(|_| Error("boot-identity-unavailable".into()))?
        .trim();
    require(
        s.len() == 36
            && s.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                }
            }),
        "boot-identity-unavailable",
    )?;
    Ok(s.into())
}
fn approved_addresses(configuration: &Value) -> Result<Vec<IpAddr>> {
    config::listen_addresses(
        &configuration["listen_address"],
        configuration.get("listen_addresses"),
    )
}
fn approved_port(configuration: &Value) -> Result<u16> {
    configuration["port"]
        .as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .filter(|n| *n >= 22)
        .ok_or_else(|| Error("ssh-approved-port-invalid".into()))
}
enum Readiness {
    Ready {
        interfaces: BTreeMap<IpAddr, String>,
        firewall_running: bool,
        observed: Value,
    },
    Waiting(&'static str),
}
async fn approved_network(
    bus: &Connection,
    firewall: &Firewall,
    approved: &Value,
) -> Result<Readiness> {
    let addresses = approved_addresses(&approved["configuration"])?;
    let interfaces = network::interfaces()?;
    if !addresses.iter().all(|a| interfaces.contains_key(a)) {
        return Ok(Readiness::Waiting("listen-address-unavailable"));
    }
    let firewall_running = firewall.running().await?;
    let observed = network::observe(
        bus,
        firewall_running.then_some(firewall),
        &interfaces,
        &addresses,
    )
    .await?;
    // An approval made before network review starts as it did then; its first
    // start records the network it runs on (`State::upgrade`).
    if approved["network"].is_array()
        && network::require_identity(&approved["network"], &observed).is_err()
    {
        return Ok(Readiness::Waiting("ssh-approved-network-changed"));
    }
    Ok(Readiness::Ready {
        interfaces,
        firewall_running,
        observed,
    })
}
async fn confirm_listeners(
    system: &System,
    uid: u32,
    addresses: &[IpAddr],
    port: u16,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let properties = system.properties().await?;
        require(
            matches!(properties.active.as_str(), "active" | "activating")
                && properties.main_pid > 0,
            "ssh-listener-not-active",
        )?;
        let mut confirmed = true;
        for address in addresses {
            confirmed &= crate::connections::listener(properties.main_pid, uid, *address, port)?;
        }
        if confirmed {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(Error("ssh-listener-socket-unconfirmed".into()))
}
fn uid(v: &Value) -> Result<u32> {
    v["uid"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| (1000..u32::MAX).contains(n))
        .ok_or_else(|| Error("remote-account-unavailable".into()))
}
pub struct Ssh {
    bus: Connection,
    state: State,
    layout: Layout,
    system: System,
    firewall: Firewall,
    runtime: tokio::runtime::Handle,
    boot: String,
}
impl Ssh {
    pub async fn new(connection: Connection) -> Result<Self> {
        root_context()?;
        for path in ["/var/lib/enzimos/remote", "/var/lib/enzimos/remote/ssh"] {
            files::ensure_directory(Path::new(path), 0o700, 0)?;
        }
        let boot = boot_id()?;
        let layout = Layout::default();
        let state = State::new(&layout.state, 0, boot.clone())?;
        let system = System::new(connection.clone(), system::SSH).await?;
        let firewall = Firewall::new(connection.clone()).await?;
        Ok(Self {
            bus: connection,
            state,
            layout,
            system,
            firewall,
            runtime: tokio::runtime::Handle::current(),
            boot,
        })
    }
    fn tracker(&self) -> Result<Option<Tracker>> {
        self.state
            .load()?
            .map(|v| {
                Ok(Tracker {
                    directory: self.layout.state.clone(),
                    uid: uid(&v)?,
                    owner: 0,
                    boot_id: self.boot.clone(),
                    addresses: approved_addresses(&v["configuration"])?,
                    port: approved_port(&v["configuration"])?,
                })
            })
            .transpose()
    }
    fn write_phase(
        &mut self,
        uid: u32,
        phase: &str,
        configuration: Option<&Value>,
        detail: &str,
    ) -> Result<()> {
        let current = self
            .state
            .load()?
            .ok_or_else(|| Error("remote-pending-state-unavailable".into()))?;
        self.state.write(
            uid,
            phase,
            configuration.unwrap_or_else(|| &current["configuration"]),
            &current["network"],
            detail,
        )?;
        Ok(())
    }
}
impl ReviewedProvider for Ssh {
    fn review(&mut self, uid: u32, request: &Value) -> Result<Value> {
        root_context()?;
        require((1000..u32::MAX).contains(&uid), "ordinary-account-required")?;
        let account = accounts::lookup_uid(uid)?;
        let enabled = request["enabled"].as_bool() != Some(false);
        let addresses = if enabled {
            network::interfaces()?
        } else {
            Default::default()
        };
        let configuration = config::ssh(
            request,
            &account.name,
            &addresses.keys().copied().collect::<BTreeSet<_>>(),
        )?;
        let mut interfaces = Vec::new();
        let mut zones = Vec::new();
        let mut primary = None;
        let mut identity = Value::Null;
        if enabled {
            // Apply stops the running listener before acquiring the new lease.
            firewall::lease_rules(&configuration)?;
            identity = self.runtime.block_on(network::observe(
                &self.bus,
                Some(&self.firewall),
                &addresses,
                &approved_addresses(&configuration)?,
            ))?;
            require(
                configuration["autostart"] != true || network::identifies_connections(&identity),
                "ssh-autostart-network-identity-unavailable",
            )?;
            for row in identity.as_array().into_iter().flatten() {
                if row["address"] == configuration["listen_address"] {
                    primary = Some((row["interface"].clone(), row["zone"].clone()));
                }
                interfaces.push(row["interface"].clone());
                zones.push(row["zone"].clone());
            }
        }
        let (interface, zone) = primary.unzip();
        let key_only = configuration.get("allow_password").and_then(Value::as_bool) != Some(true);
        let plan = value!({"schema":1,"configuration":configuration,"uid":uid,"interface":interface,"zone":zone,"network":identity,"previous_state_sha256":json::fingerprint(&value!(self.state.load()?))?,"interfaces":interfaces,"zones":zones,"key_only":key_only,"root_login":false,"existing_sessions_disconnected":false,"stock_sshd_changed":false,"private_host_identity":true});
        Ok(value!({"plan_sha256":json::fingerprint(&plan)?,"plan":plan}))
    }
    fn review_disconnect(&mut self, uid: u32) -> Result<Value> {
        let current = self
            .state
            .load()?
            .ok_or_else(|| Error("remote-owner-mismatch".into()))?;
        require(
            current["uid"].as_u64() == Some(u64::from(uid)),
            "remote-owner-mismatch",
        )?;
        let plan = value!({"schema":1,"uid":uid,"previous_state_sha256":json::fingerprint(&current)?,"sessions":self.connections()?,"listener_stopped":false,"unrelated_sessions_signalled":false});
        Ok(value!({"plan_sha256":json::fingerprint(&plan)?,"plan":plan}))
    }
    fn query(&mut self, uid: u32) -> Result<Value> {
        let current = self.state.load()?;
        if current
            .as_ref()
            .is_some_and(|v| v["uid"].as_u64() != Some(u64::from(uid)))
        {
            return Ok(
                value!({"schema":1,"owned_by_another_account":true,"configuration":null,"listening":self.listener_active()?,"connections":[]}),
            );
        }
        let current = current.map(|mut v| {
            if let Some(object) = v.as_object_mut() {
                object.remove("network");
            }
            v
        });
        Ok(
            value!({"schema":1,"owned_by_another_account":false,"configuration":current,"listening":self.listener_active()?,"connections":self.connections()?,"host_public_key":self.layout.public_host_key()?,"sharing_protocols":["ssh","sftp"],"remote_login_qualified":false}),
        )
    }
}
impl Provider for Ssh {
    type Exclusive = files::Lock;
    type Prepared = Prepared;
    fn exclusive(&mut self) -> Result<Self::Exclusive> {
        root_context()?;
        self.state.exclusive()
    }
    fn current(&mut self) -> Result<Option<Value>> {
        self.state.load()
    }
    fn connections(&mut self) -> Result<Vec<Value>> {
        match self.tracker()? {
            None => Ok(Vec::new()),
            Some(tracker) => {
                tracker.query(self.runtime.block_on(self.system.properties())?.main_pid)
            }
        }
    }
    fn prepare(&mut self, configuration: &Value) -> Result<Prepared> {
        if configuration["enabled"] == true {
            firewall::lease_rules(configuration)?;
        }
        self.layout.prepare(configuration)
    }
    fn pending(&mut self, uid: u32, reviewed: &Value) -> Result<()> {
        self.state.write(
            uid,
            "pending",
            &reviewed["plan"]["configuration"],
            &reviewed["plan"]["network"],
            "",
        )?;
        Ok(())
    }
    fn stop_listening(&mut self) -> Result<()> {
        self.connections()?;
        Resume::new(&self.layout.state).clear()?;
        self.runtime.block_on(self.system.job("stop"))
    }
    fn release_firewall(&mut self) -> Result<()> {
        let _lock = files::Lock::acquire(&self.layout.state.join("firewall.lock"), 0)?;
        Journal {
            path: &self.layout.state.join("firewall.json"),
            owner: 0,
            boot_id: &self.boot,
            interface: &mut self.firewall,
        }
        .release_or_forget()?;
        Ok(())
    }
    fn publish(&mut self, prepared: Prepared) -> Result<()> {
        self.layout.publish(prepared)
    }
    fn set_autostart(&mut self, enabled: bool) -> Result<()> {
        self.runtime.block_on(self.system.autostart(enabled))
    }
    fn start_listening(&mut self) -> Result<()> {
        self.runtime.block_on(self.system.job("start"))
    }
    fn verify_listener(&mut self, configuration: &Value) -> Result<()> {
        let current = self
            .state
            .load()?
            .ok_or_else(|| Error("remote-listener-not-approved".into()))?;
        self.runtime.block_on(confirm_listeners(
            &self.system,
            uid(&current)?,
            &approved_addresses(configuration)?,
            approved_port(configuration)?,
        ))
    }
    fn complete(&mut self, uid: u32, configuration: &Value, _result: &Value) -> Result<()> {
        self.write_phase(uid, "complete", Some(configuration), "")
    }
    fn failed(&mut self, uid: u32, detail: &str) -> Result<()> {
        self.write_phase(uid, "failed", None, detail)
    }
    fn uncertain(&mut self, uid: u32, detail: &str) -> Result<()> {
        self.write_phase(uid, "uncertain", None, detail)
    }
    fn disconnect_owned_sessions(&mut self, before: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        let tracker = self
            .tracker()?
            .ok_or_else(|| Error("remote-owner-unavailable".into()))?;
        let rows = tracker.query(self.runtime.block_on(self.system.properties())?.main_pid)?;
        tracker.disconnect(&rows, before)
    }
    fn listener_active(&mut self) -> Result<bool> {
        let properties = self.runtime.block_on(self.system.properties())?;
        if properties.active != "active" || properties.main_pid == 0 {
            return Ok(false);
        }
        let Some(current) = self.state.load()? else {
            return Ok(false);
        };
        let configuration = &current["configuration"];
        let port = approved_port(configuration)?;
        for address in approved_addresses(configuration)? {
            if !crate::connections::listener(properties.main_pid, uid(&current)?, address, port)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
// Stays within the unit's TimeoutStartSec (enzimos-sshd.service).
const APPROVED_ADDRESS_WAIT: Duration = Duration::from_secs(60);

/// Runs one fixed operation of the SSH units.
///
/// `prepare`, `verify` and `release` run inside `enzimos-sshd.service`, `watch`
/// keeps its firewall lease while it runs, and `retry` starts it once a late
/// approved network appears. Each checks published bytes and approval again,
/// independently of API preparation. Without a running firewalld the listener
/// starts and keeps running unfiltered; `watch` leases it once firewalld runs.
///
/// # Errors
/// Fails for an unknown operation, without initial-namespace root, or when the
/// approval, published files, network or firewall lease do not match.
pub async fn entry(operation: &str, connection: Connection) -> Result<()> {
    root_context()?;
    match operation {
        "prepare" | "release" => prepare_or_release(operation, connection).await,
        "verify" => verify(connection).await,
        "watch" => watch(connection).await,
        "retry" => retry(connection).await,
        _ => Err(Error("unit-operation-unavailable".into())),
    }
}
async fn prepare_or_release(operation: &str, connection: Connection) -> Result<()> {
    let layout = Layout::default();
    let boot = boot_id()?;
    let state = State::new(&layout.state, 0, boot.clone())?;
    let mut firewall = Firewall::new(connection.clone()).await?;
    let _lock = files::Lock::acquire(&layout.state.join("firewall.lock"), 0)?;
    if operation == "release" {
        return tokio::task::spawn_blocking(move || {
            let _lock = _lock;
            Journal {
                path: &layout.state.join("firewall.json"),
                owner: 0,
                boot_id: &boot,
                interface: &mut firewall,
            }
            .release_or_forget()?;
            Ok(())
        })
        .await
        .map_err(|_| Error("unit-firewall-worker-unavailable".into()))?;
    }
    let approved = state.eligible()?;
    let account = accounts::lookup_uid(uid(&approved)?)?;
    let normalized = approved["configuration"].clone();
    let mut request = normalized.clone();
    request
        .as_object_mut()
        .ok_or_else(|| Error("remote-approved-configuration-changed".into()))?
        .remove("account");
    request["public_keys"] = value!(
        normalized["public_keys"]
            .as_array()
            .ok_or_else(|| Error("remote-approved-keys-changed".into()))?
            .iter()
            .map(|r| r["key"].clone())
            .collect::<Vec<_>>()
    );
    // At startup the approved network often connects after this unit starts;
    // the listener still binds only the approved addresses on the reviewed network.
    let deadline = Instant::now() + APPROVED_ADDRESS_WAIT;
    let (addresses, firewall_running, observed) = loop {
        match approved_network(&connection, &firewall, &approved).await? {
            Readiness::Ready {
                interfaces,
                firewall_running,
                observed,
            } => break (interfaces, firewall_running, observed),
            Readiness::Waiting(reason) if Instant::now() >= deadline => {
                return Err(Error(reason.into()));
            }
            Readiness::Waiting(_) => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    };
    let configuration = config::ssh(
        &request,
        &account.name,
        &addresses.keys().copied().collect(),
    )?;
    require(
        configuration == normalized,
        "remote-approved-configuration-changed",
    )?;
    require(
        files::read(
            &layout.configuration.join("sshd_config"),
            65536,
            Some(0),
            true,
        )? == config::render_ssh(&configuration)?.as_bytes(),
        "remote-published-configuration-changed",
    )?;
    let keys = configuration["public_keys"]
        .as_array()
        .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?
        .iter()
        .map(|r| {
            r["key"]
                .as_str()
                .ok_or_else(|| Error("unexpected JSON value type".into()))
        })
        .collect::<Result<Vec<_>>>()?
        .join("\n")
        + "\n";
    require(
        files::read(
            &layout
                .configuration
                .join("authorized_keys")
                .join(&account.name),
            65536,
            Some(0),
            true,
        )? == keys.as_bytes(),
        "remote-published-keys-changed",
    )?;
    // The interface's zone may already allow the port (public allows ssh/22):
    // use the priority policy, whose trailing reject makes allowed_networks a
    // real whitelist for sshd's pre-authentication surface too.
    let rules = firewall::lease_rules(&configuration)?;
    // The synchronous lease adapter must run in a bounded blocking worker.
    tokio::task::spawn_blocking(move || {
        let _lock = _lock;
        require(
            state.eligible()? == approved,
            "remote-approved-configuration-changed",
        )?;
        // A configuration transaction that starts this unit has just written the
        // current layout and holds the lock.
        if let Some(_exclusive) = state.try_exclusive()? {
            let recordable = firewall_running && network::identifies_connections(&observed);
            if let Err(error) = state.upgrade(&approved, recordable.then_some(&observed)) {
                eprintln!("ssh approval upgrade deferred: {error}");
            }
        }
        let mut journal = Journal {
            path: &layout.state.join("firewall.json"),
            owner: 0,
            boot_id: &boot,
            interface: &mut firewall,
        };
        // A firewalld that starts after the network check is leased by the guard,
        // which checks the reviewed zone first.
        if firewall_running {
            journal.release()?;
            journal.acquire(&rules)?;
        } else {
            journal.forget()?;
        }
        Ok(())
    })
    .await
    .map_err(|_| Error("unit-firewall-worker-unavailable".into()))?
}
async fn verify(connection: Connection) -> Result<()> {
    let layout = Layout::default();
    let approved = State::new(&layout.state, 0, boot_id()?)?.eligible()?;
    let system = System::new(connection, system::SSH).await?;
    confirm_listeners(
        &system,
        uid(&approved)?,
        &approved_addresses(&approved["configuration"])?,
        approved_port(&approved["configuration"])?,
    )
    .await
}
// Exiting stops the listener: the units bind each other.
async fn watch(connection: Connection) -> Result<()> {
    let result = guard(connection.clone()).await;
    if let Err(error) = &result
        && resumable(error)
    {
        Resume::new(&Layout::default().state).mark(&boot_id()?)?;
        System::new(connection, system::SSH)
            .await?
            .start_retry()
            .await?;
    }
    result
}
// A network that left the reviewed one may come back; a changed approval or a
// stopped listener is a decision the guard must not undo.
fn resumable(error: &Error) -> bool {
    firewall_lease::definitive(error)
        && !matches!(
            error.0.as_str(),
            "remote-approved-configuration-changed" | "ssh-listener-not-active"
        )
}
/// Records that the firewall guard stopped SSH during this boot, so the retry
/// timer restarts it once the reviewed network is back.
struct Resume {
    path: std::path::PathBuf,
}
impl Resume {
    fn new(directory: &Path) -> Self {
        Self {
            path: directory.join("resume.json"),
        }
    }
    fn mark(&self, boot: &str) -> Result<()> {
        files::atomic(
            &self.path,
            &json::canonical(&value!({"schema":1,"boot_id":boot}))?,
            0o600,
            Some(0),
            true,
        )
    }
    fn pending(&self, boot: &str) -> Result<bool> {
        let Some(body) = files::read_optional(&self.path, 4096, Some(0), true)? else {
            return Ok(false);
        };
        Ok(json::decode(&body, 4096).is_ok_and(|v| v == value!({"schema":1,"boot_id":boot})))
    }
    fn clear(&self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }
}
async fn guard(connection: Connection) -> Result<()> {
    let boot = boot_id()?;
    let approved = State::new(&Layout::default().state, 0, boot.clone())?.eligible()?;
    let rules = firewall::lease_rules(&approved["configuration"])?;
    let system = System::new(connection.clone(), system::SSH).await?;
    let listener = system.properties().await?;
    require(
        listener.active == "active" && listener.main_pid > 0,
        "ssh-listener-not-active",
    )?;
    let guarded = std::sync::Arc::new(Guarded {
        connection: connection.clone(),
        boot,
        approved,
        rules,
        system,
        main_pid: listener.main_pid,
    });
    firewall_lease::follow(&connection, "ssh", move || renew_lease(&guarded)).await
}
struct Guarded {
    connection: Connection,
    boot: String,
    approved: Value,
    rules: Vec<Rule>,
    system: System,
    main_pid: u32,
}
// The lease admits connections only for the same running listener, the same
// reviewed approval and the reviewed network.
fn renew_lease(guarded: &Guarded) -> Result<Restored> {
    let runtime = tokio::runtime::Handle::current();
    let layout = Layout::default();
    let _lock = files::Lock::acquire(&layout.state.join("firewall.lock"), 0)?;
    let mut firewall = runtime.block_on(Firewall::new(guarded.connection.clone()))?;
    let running = runtime.block_on(firewall.running())?;
    let observer = firewall.clone();
    let mut journal = Journal {
        path: &layout.state.join("firewall.json"),
        owner: 0,
        boot_id: &guarded.boot,
        interface: &mut firewall,
    };
    firewall_lease::restore(&mut journal, &guarded.rules, running, || {
        require(
            same_review(
                &State::new(&layout.state, 0, guarded.boot.clone())?.eligible()?,
                &guarded.approved,
            ),
            "remote-approved-configuration-changed",
        )?;
        let listener = runtime.block_on(guarded.system.properties())?;
        require(
            listener.active == "active" && listener.main_pid == guarded.main_pid,
            "ssh-listener-not-active",
        )?;
        match runtime.block_on(approved_network(
            &guarded.connection,
            &observer,
            &guarded.approved,
        ))? {
            Readiness::Ready { .. } => Ok(()),
            Readiness::Waiting(reason) => Err(Error(reason.into())),
        }
    })
}
// The listener can start while its approval is still pending; completing that
// same approval is not a change of what was reviewed.
fn same_review(current: &Value, approved: &Value) -> bool {
    ["configuration", "network", "uid"]
        .iter()
        .all(|key| current[key] == approved[key])
}
async fn retry(connection: Connection) -> Result<()> {
    let layout = Layout::default();
    let boot = boot_id()?;
    let state = State::new(&layout.state, 0, boot.clone())?;
    let resume = Resume::new(&layout.state);
    let system = System::new(connection.clone(), system::SSH).await?;
    let resuming = resume.pending(&boot)?;
    let approved = match state.eligible() {
        Ok(approved) if resuming || approved["configuration"]["autostart"] == true => approved,
        _ => {
            resume.clear()?;
            return system.stop_retry().await;
        }
    };
    if !resuming && system.activated().await? {
        return system.stop_retry().await;
    }
    if system::stopped(&system.properties().await?).is_err() {
        return Ok(());
    }
    let firewall = Firewall::new(connection.clone()).await?;
    if !matches!(
        approved_network(&connection, &firewall, &approved).await?,
        Readiness::Ready { .. }
    ) {
        return Ok(());
    }
    // Configuration transactions hold this lock while the listener is stopped.
    let Some(_exclusive) = state.try_exclusive()? else {
        return Ok(());
    };
    require(
        state.eligible()? == approved,
        "remote-approved-configuration-changed",
    )?;
    resume.clear()?;
    let started = system.job("start").await;
    system.stop_retry().await?;
    started
}

#[cfg(test)]
mod tests {
    use super::same_review;
    use serde_json::json;

    #[test]
    fn completing_the_approval_keeps_the_review_but_a_new_network_does_not() {
        let pending = json!({"phase": "pending", "configuration": {"port": 22}, "network": [{"connection": "a"}], "uid": 1000});
        let mut complete = pending.clone();
        complete["phase"] = json!("complete");
        assert!(same_review(&complete, &pending));
        complete["network"] = json!([{"connection": "b"}]);
        assert!(!same_review(&complete, &pending));
    }
}
