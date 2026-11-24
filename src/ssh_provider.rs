// SPDX-License-Identifier: MIT
//! Concrete separately owned SSH lifecycle, invoked by fresh-authority dispatch.
use crate::{
    config,
    connections::Tracker,
    controller::Provider,
    dispatch::ReviewedProvider,
    firewall,
    firewall_bus::Firewall,
    firewall_journal::Journal,
    network,
    ssh_files::{Layout, Prepared},
    state::State,
    system::{self, System},
};
use enzimos_platform::{Error, Result, accounts, files, json, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, Instant},
};
use zbus::Connection;
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
pub fn root_context() -> Result<()> {
    require(
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
fn uid(v: &Value) -> Result<u32> {
    v["uid"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| (1000..u32::MAX).contains(n))
        .ok_or_else(|| Error("remote-account-unavailable".into()))
}
pub struct Ssh {
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
        let firewall = Firewall::new(connection).await?;
        Ok(Self {
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
                    addresses: config::listen_addresses(
                        &v["configuration"]["listen_address"],
                        v["configuration"].get("listen_addresses"),
                    )?,
                    port: v["configuration"]["port"]
                        .as_u64()
                        .and_then(|n| u16::try_from(n).ok())
                        .filter(|n| *n >= 22)
                        .ok_or_else(|| Error("ssh-approved-port-invalid".into()))?,
                })
            })
            .transpose()
    }
    fn write_failure(&mut self, uid: u32, phase: &str, detail: &str) -> Result<()> {
        let configuration = self
            .state
            .load()?
            .ok_or_else(|| Error("remote-pending-state-unavailable".into()))?["configuration"]
            .clone();
        self.state.write(uid, phase, &configuration, detail)?;
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
        if enabled {
            for address in config::listen_addresses(
                &configuration["listen_address"],
                configuration.get("listen_addresses"),
            )? {
                let interface = addresses
                    .get(&address)
                    .ok_or_else(|| Error("listen-address-unavailable".into()))?;
                let zone = self.runtime.block_on(self.firewall.zone_for(interface))?;
                if address.to_string() == configuration["listen_address"] {
                    primary = Some((interface.clone(), zone.clone()));
                }
                interfaces.push(interface.clone());
                zones.push(zone);
            }
        }
        let (interface, zone) = primary.unzip();
        let key_only = configuration.get("allow_password").and_then(Value::as_bool) != Some(true);
        let plan = value!({"schema":1,"configuration":configuration,"uid":uid,"interface":interface,"zone":zone,"previous_state_sha256":json::fingerprint(&value!(self.state.load()?))?,"interfaces":interfaces,"zones":zones,"key_only":key_only,"root_login":false,"existing_sessions_disconnected":false,"stock_sshd_changed":false,"private_host_identity":true});
        Ok(value!({"plan_sha256":json::fingerprint(&plan)?,"plan":plan}))
    }
    fn review_disconnect(&mut self, uid: u32) -> Result<Value> {
        let current = self
            .state
            .load()?
            .ok_or_else(|| Error("remote-owner-mismatch".into()))?;
        require(
            current["uid"].as_u64() == Some(uid as u64),
            "remote-owner-mismatch",
        )?;
        let plan = value!({"schema":1,"uid":uid,"previous_state_sha256":json::fingerprint(&current)?,"sessions":self.connections()?,"listener_stopped":false,"unrelated_sessions_signalled":false});
        Ok(value!({"plan_sha256":json::fingerprint(&plan)?,"plan":plan}))
    }
    fn query(&mut self, uid: u32) -> Result<Value> {
        let current = self.state.load()?;
        if current
            .as_ref()
            .is_some_and(|v| v["uid"].as_u64() != Some(uid as u64))
        {
            return Ok(
                value!({"schema":1,"owned_by_another_account":true,"configuration":null,"listening":self.listener_active()?,"connections":[]}),
            );
        }
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
        self.layout.prepare(configuration)
    }
    fn pending(&mut self, uid: u32, reviewed: &Value) -> Result<()> {
        self.state
            .write(uid, "pending", &reviewed["plan"]["configuration"], "")?;
        Ok(())
    }
    fn stop_listening(&mut self) -> Result<()> {
        self.connections()?;
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
        .release()
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
        let deadline = Instant::now() + Duration::from_secs(5);
        let current = self
            .state
            .load()?
            .ok_or_else(|| Error("remote-listener-not-approved".into()))?;
        let addresses = config::listen_addresses(
            &configuration["listen_address"],
            configuration.get("listen_addresses"),
        )?;
        let port = configuration["port"]
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p >= 22)
            .ok_or_else(|| Error("ssh-approved-port-invalid".into()))?;
        while Instant::now() < deadline {
            let properties = self.runtime.block_on(self.system.properties())?;
            require(
                properties.active == "active" && properties.main_pid > 0,
                "ssh-listener-not-active",
            )?;
            let mut confirmed = true;
            for address in &addresses {
                confirmed &= crate::connections::listener(
                    properties.main_pid,
                    uid(&current)?,
                    *address,
                    port,
                )?;
            }
            if confirmed {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(Error("ssh-listener-socket-unconfirmed".into()))
    }
    fn complete(&mut self, uid: u32, configuration: &Value, _result: &Value) -> Result<()> {
        self.state.write(uid, "complete", configuration, "")?;
        Ok(())
    }
    fn failed(&mut self, uid: u32, detail: &str) -> Result<()> {
        self.write_failure(uid, "failed", detail)
    }
    fn uncertain(&mut self, uid: u32, detail: &str) -> Result<()> {
        self.write_failure(uid, "uncertain", detail)
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
        let port = configuration["port"]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port >= 22)
            .ok_or_else(|| Error("ssh-approved-port-invalid".into()))?;
        for address in config::listen_addresses(
            &configuration["listen_address"],
            configuration.get("listen_addresses"),
        )? {
            if !crate::connections::listener(properties.main_pid, uid(&current)?, address, port)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
// Stays within the unit's TimeoutStartSec (enzimos-sshd.service).
const APPROVED_ADDRESS_WAIT: Duration = Duration::from_secs(60);

/// Unit startup checks published bytes again, independently of API preparation.
pub async fn entry(operation: &str, connection: Connection) -> Result<()> {
    root_context()?;
    require(
        matches!(operation, "prepare" | "release"),
        "unit-operation-unavailable",
    )?;
    let layout = Layout::default();
    let boot = boot_id()?;
    let state = State::new(&layout.state, 0, boot.clone())?;
    let mut firewall = Firewall::new(connection).await?;
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
            .release()
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
    // the listener still binds only the approved addresses.
    let approved_addresses = config::listen_addresses(
        &normalized["listen_address"],
        normalized.get("listen_addresses"),
    )?;
    let deadline = Instant::now() + APPROVED_ADDRESS_WAIT;
    let addresses = loop {
        let addresses = network::interfaces()?;
        if approved_addresses
            .iter()
            .all(|address| addresses.contains_key(address))
            || Instant::now() >= deadline
        {
            break addresses;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
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
        .unwrap()
        .iter()
        .map(|r| r["key"].as_str().unwrap())
        .collect::<Vec<_>>()
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
    // Every selected address must still belong to a firewalld-managed interface.
    for address in config::listen_addresses(
        &configuration["listen_address"],
        configuration.get("listen_addresses"),
    )? {
        firewall
            .zone_for(
                addresses
                    .get(&address)
                    .ok_or_else(|| Error("listen-address-unavailable".into()))?,
            )
            .await?;
    }
    // The synchronous lease adapter must run in a bounded blocking worker.
    tokio::task::spawn_blocking(move || {
        let _lock = _lock;
        require(
            state.eligible()? == approved,
            "remote-approved-configuration-changed",
        )?;
        let mut journal = Journal {
            path: &layout.state.join("firewall.json"),
            owner: 0,
            boot_id: &boot,
            interface: &mut firewall,
        };
        journal.release()?;
        // The interface's zone may already allow the port (public allows ssh/22):
        // use the priority policy, whose trailing reject makes allowed_networks a
        // real whitelist for sshd's pre-authentication surface too.
        journal.acquire(&firewall::rules(&configuration, firewall::TARGET)?)?;
        Ok(())
    })
    .await
    .map_err(|_| Error("unit-firewall-worker-unavailable".into()))?
}
