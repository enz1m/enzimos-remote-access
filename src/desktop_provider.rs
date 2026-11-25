// SPDX-License-Identifier: MIT
//! Reviewed, run-only desktop sharing with durable pending-before-mutation state.
use crate::{
    config, desktop_binding, desktop_grant,
    desktop_session::Session,
    desktop_unattended::{self, Store},
    desktop_unit, desktop_unit_trust,
    firewall_bus::Firewall,
    network, sockets, ssh_provider,
    system::{self, System},
};
use enzimos_platform::{
    Error, Result, files, json,
    process_identity::{self, Retained},
    require,
};
use enzimos_system_backend::authority::Peer;
use serde_json::{Value, json as value};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use zbus::Connection;
/// A reviewed desktop sharing mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// Starts or reconfigures sharing.
    Apply,
    /// Stops sharing and turns unattended sharing off.
    Stop,
    /// Turns unattended sharing on or off.
    Unattended,
}
pub trait Reviewed: Send + 'static {
    fn query(&mut self, peer: &Peer) -> Result<Value>;
    fn review(&mut self, peer: &Peer, configuration: &Value) -> Result<Value>;
    fn review_stop(&mut self, peer: &Peer) -> Result<Value>;
    fn review_unattended(&mut self, peer: &Peer, enabled: bool) -> Result<Value>;
    fn change(
        &mut self,
        peer: &Peer,
        reviewed: &Value,
        operation: Operation,
        before_commit: &mut dyn FnMut(&mut Self, bool) -> Result<()>,
    ) -> Result<Value>;
}
/// What one unattended start attempt found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resumed {
    /// Unattended sharing is off for the account.
    Off,
    /// The sharing unit is already running or changing state.
    Running,
    /// Sharing started on the reviewed network.
    Started,
    /// A condition for starting does not hold yet.
    Waiting(String),
}
/// The watcher unit that starts unattended sharing for one account.
///
/// # Errors
/// Fails for an account outside the ordinary range.
pub fn autostart_unit(uid: u32) -> Result<String> {
    Ok(format!(
        "enzimos-desktop-sharing-autostart@{}.service",
        desktop_grant::account(uid)?
    ))
}
// Interactive changes wait for an unattended start attempt to finish.
fn operation_lock(directory: &Path) -> Result<files::Lock> {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Some(lock) = files::Lock::try_acquire(&directory.join("operation.lock"), 0)? {
            return Ok(lock);
        }
        require(Instant::now() < deadline, "desktop-operation-in-progress")?;
        std::thread::sleep(Duration::from_millis(200));
    }
}
pub struct Desktop {
    connection: Connection,
    session: Session,
    firewall: Firewall,
    runtime: tokio::runtime::Handle,
}
impl Desktop {
    pub async fn new(connection: Connection) -> Result<Self> {
        ssh_provider::root_context()?;
        Ok(Self {
            session: Session::new(connection.clone()).await?,
            firewall: Firewall::new(connection.clone()).await?,
            connection,
            runtime: tokio::runtime::Handle::current(),
        })
    }
    fn system(&self, uid: u32) -> Result<System> {
        self.runtime.block_on(System::new(
            self.connection.clone(),
            &format!(
                "enzimos-desktop-sharing@{}.service",
                desktop_grant::account(uid)?
            ),
        ))
    }
    fn properties(&self, uid: u32) -> Result<system::Snapshot> {
        self.runtime
            .block_on(desktop_unit_trust::properties(&self.system(uid)?, uid))
    }
    fn current(&self, uid: u32) -> Result<Option<Value>> {
        match std::fs::symlink_metadata(desktop_grant::folder(uid)?.join("grant.json")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
            Ok(_) => desktop_grant::load(uid).map(Some),
        }
    }
    fn snapshot(&self, uid: u32) -> Result<Value> {
        let system = self.system(uid)?;
        let (unit, service) = self.runtime.block_on(system.raw_properties())?;
        let p = desktop_unit_trust::validate(&unit, &service, uid)?;
        desktop_binding::installed(Path::new(desktop_unit_trust::TEMPLATE))?;
        desktop_binding::installed(Path::new(desktop_unit_trust::WORKER))?;
        let invocation = Vec::<u8>::try_from(
            unit.get("InvocationID")
                .ok_or_else(|| Error("desktop-system-unit-untrusted".into()))?
                .try_clone()
                .map_err(|_| Error("desktop-system-unit-untrusted".into()))?,
        )
        .map_err(|_| Error("desktop-system-unit-untrusted".into()))?;
        require(
            invocation.is_empty() || invocation.len() == 16,
            "desktop-system-unit-untrusted",
        )?;
        Ok(
            value!({"grant":self.current(uid)?,"state":p.active,"pid":p.main_pid,"invocation":invocation,"reserved_descriptors":p.fdstore,"unattended":Store::installed(uid)?.load()?}),
        )
    }
    fn listening(&self, uid: u32, grant: Option<&Value>) -> Result<bool> {
        let Some(grant) = grant else {
            return Ok(false);
        };
        let p = self.properties(uid)?;
        if p.active != "active" || p.main_pid == 0 {
            return Ok(false);
        }
        let address: IpAddr = grant["configuration"]["listen_address"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error("desktop-grant-invalid".into()))?;
        let port = grant["configuration"]["port"]
            .as_u64()
            .filter(|n| (1024..=65535).contains(n))
            .ok_or_else(|| Error("desktop-grant-invalid".into()))? as u16;
        if crate::desktop_rdp::selected(&grant["configuration"]) {
            return crate::desktop_rdp_observer::listening(
                uid,
                p.main_pid,
                address,
                port,
                &grant["provider"],
            );
        }
        let table = sockets::table()?;
        let group = format!("0::/system.slice/enzimos-desktop-sharing@{uid}.service");
        for pid in desktop_binding::descendants(p.main_pid, uid)? {
            let result: Result<bool> = (|| {
                let root = PathBuf::from(format!("/proc/{pid}"));
                let read = |name: &str, limit| -> Result<String> {
                    String::from_utf8(files::read_kernel_owned(&root.join(name), limit, uid)?)
                        .map_err(|_| Error("desktop-process-identity".into()))
                };
                let stat = process_identity::parse_stat(&read("stat", 8192)?, pid)?;
                let retained = Retained::open(
                    pid,
                    stat.start_ticks,
                    uid,
                    &[PathBuf::from(
                        if crate::desktop_rdp::selected(&grant["configuration"]) {
                            crate::desktop_rdp::PROGRAM
                        } else {
                            "/usr/bin/wayvnc"
                        },
                    )],
                )?;
                require(
                    process_identity::parse_uids(&read("status", 65536)?)? == [uid; 4]
                        && read("cgroup", 8192)?
                            .lines()
                            .filter(|s| s.starts_with("0::"))
                            .eq([group.as_str()]),
                    "desktop-capture-process-untrusted",
                )?;
                let owned = sockets::inodes(pid, uid)?;
                retained.recheck()?;
                Ok(sockets::listening(&table, &owned, address, port))
            })();
            if result.is_ok_and(|v| v) {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn ready(&self, uid: u32, grant: &Value) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if self.listening(uid, Some(grant))? {
                return Ok(());
            }
            if !matches!(
                self.properties(uid)?.active.as_str(),
                "active" | "activating"
            ) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(Error("desktop-encrypted-listener-unconfirmed".into()))
    }
    fn release(&self, uid: u32) -> Result<()> {
        self.runtime
            .block_on(desktop_unit::entry("release", uid, self.connection.clone()))
    }
    fn autostart(&self, uid: u32) -> Result<System> {
        self.runtime
            .block_on(System::new(self.connection.clone(), &autostart_unit(uid)?))
    }
    // A failure between steps leaves at most a watcher without a record, which exits.
    fn set_unattended(&self, uid: u32, record: Option<&Value>) -> Result<()> {
        let store = Store::installed(uid)?;
        let watcher = self.autostart(uid)?;
        match record {
            Some(record) => {
                self.runtime.block_on(watcher.autostart(true))?;
                store.write(record)?;
                self.runtime.block_on(watcher.job("start"))
            }
            None => {
                store.remove()?;
                self.runtime.block_on(watcher.autostart(false))?;
                self.runtime.block_on(watcher.job("stop"))
            }
        }
    }
    fn reviewed_network(&self, address: IpAddr) -> Result<Value> {
        let addresses = network::interfaces()?;
        require(
            self.runtime.block_on(self.firewall.running())?,
            "desktop-unattended-network-identity-unavailable",
        )?;
        let observed = self.runtime.block_on(network::observe(
            &self.connection,
            Some(&self.firewall),
            &addresses,
            &[address],
        ))?;
        require(
            network::identifies_connections(&observed),
            "desktop-unattended-network-identity-unavailable",
        )?;
        Ok(observed)
    }
    /// Starts unattended sharing for `uid` when its record, signed-in local
    /// session and reviewed network all allow it.
    ///
    /// The grant binds the account's current display session, exactly as an
    /// interactive approval would. Nothing starts while another desktop
    /// operation runs, cleanup is pending, or a prior operation is unfinished.
    ///
    /// # Errors
    /// Fails when state cannot be read or a started unit does not confirm its
    /// encrypted listener; the attempt is then rolled back.
    pub fn resume(&mut self, uid: u32) -> Result<Resumed> {
        let store = Store::installed(uid)?;
        let waiting = |reason: &str| Ok(Resumed::Waiting(reason.into()));
        let idle = |p: &system::Snapshot| -> Option<Result<Resumed>> {
            if !matches!(p.active.as_str(), "inactive" | "failed") {
                return Some(Ok(Resumed::Running));
            }
            (p.fdstore > 0).then(|| waiting("desktop-listener-cleanup-required"))
        };
        if store.load()?.is_none() {
            return Ok(Resumed::Off);
        }
        if let Some(result) = idle(&self.properties(uid)?) {
            return result;
        }
        let directory = desktop_grant::folder(uid)?;
        files::ensure_directory(&directory, 0o700, 0)?;
        let Some(_lock) = files::Lock::try_acquire(&directory.join("operation.lock"), 0)? else {
            return waiting("desktop-operation-in-progress");
        };
        if self.unfinished(uid)? {
            return waiting("desktop-prior-operation-needs-reviewed-stop");
        }
        let Some(record) = store.load()? else {
            return Ok(Resumed::Off);
        };
        if let Some(result) = idle(&self.properties(uid)?) {
            return result;
        }
        let Some(id) = self.runtime.block_on(self.session.display(uid))? else {
            return waiting("desktop-session-unavailable");
        };
        if self
            .runtime
            .block_on(self.session.values(uid, &id))
            .is_err()
        {
            return waiting("desktop-local-unlocked-session-required");
        }
        desktop_binding::installed(Path::new("/usr/bin/wayvnc"))?;
        let configuration = &record["configuration"];
        let address: IpAddr = configuration["listen_address"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error("desktop-unattended-record-invalid".into()))?;
        let addresses = network::interfaces()?;
        if !addresses.contains_key(&address) {
            return waiting("listen-address-unavailable");
        }
        let running = self.runtime.block_on(self.firewall.running())?;
        let observed = self.runtime.block_on(network::observe(
            &self.connection,
            running.then_some(&self.firewall),
            &addresses,
            &[address],
        ))?;
        if network::require_identity(&record["network"], &observed).is_err() {
            return waiting("desktop-approved-network-changed");
        }
        let checked = config::desktop(configuration, &addresses.keys().copied().collect())?;
        let bound = match self.runtime.block_on(self.session.discover(uid, &id)) {
            Ok(bound) => bound,
            Err(error) => return waiting(&error.0),
        };
        let row = desktop_unattended::reviewed(&record);
        let boot = ssh_provider::boot_id()?;
        let grant = value!({"schema":1,"boot_id":boot,"uid":uid,"nonce":files::random_hex(32)?,"session":bound,"configuration":checked,"interface":row["interface"],"zone":row["zone"],"connection":row["connection"]});
        let started: Result<()> = (|| {
            desktop_grant::publish(&grant, uid, &boot, &addresses.keys().copied().collect())?;
            require(
                store.load()?.as_ref() == Some(&record),
                "desktop-unattended-record-changed",
            )?;
            self.runtime.block_on(self.system(uid)?.job("start"))?;
            self.ready(uid, &grant)
        })();
        if let Err(error) = started {
            let _ = self.runtime.block_on(self.system(uid)?.job("stop"));
            self.release(uid)?;
            return Err(error);
        }
        Ok(Resumed::Started)
    }
    fn receipt(
        &self,
        uid: u32,
        phase: &str,
        stopping: bool,
        reviewed: &Value,
        result: Value,
    ) -> Result<()> {
        let record = value!({"schema":1,"boot_id":ssh_provider::boot_id()?,"uid":uid,"phase":phase,"operation":if stopping { "stop" } else { "apply" },"plan_sha256":reviewed["plan_sha256"],"result":result});
        receipt_validate(&record, uid)?;
        files::atomic(
            &desktop_grant::folder(uid)?.join("operation.json"),
            &json::canonical(&record)?,
            0o600,
            Some(0),
            true,
        )
    }
    fn unfinished(&self, uid: u32) -> Result<bool> {
        let Some(bytes) = files::read_optional(
            &desktop_grant::folder(uid)?.join("operation.json"),
            65536,
            Some(0),
            true,
        )?
        else {
            return Ok(false);
        };
        let record = json::decode(&bytes, 65536)?;
        receipt_validate(&record, uid)?;
        Ok(record["boot_id"] == ssh_provider::boot_id()?
            && matches!(record["phase"].as_str(), Some("pending" | "uncertain")))
    }
}
pub fn receipt_validate(record: &Value, uid: u32) -> Result<()> {
    json::fields(
        record,
        "schema boot_id uid phase operation plan_sha256 result",
    )?;
    desktop_grant::account(uid)?;
    require(
        record["schema"].as_u64() == Some(1)
            && record["uid"].as_u64() == Some(uid as u64)
            && record["boot_id"].as_str().is_some_and(|s| {
                s.len() == 36
                    && s.bytes().enumerate().all(|(i, b)| {
                        if [8, 13, 18, 23].contains(&i) {
                            b == b'-'
                        } else {
                            b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                        }
                    })
            })
            && matches!(
                record["phase"].as_str(),
                Some("pending" | "complete" | "failed" | "uncertain")
            )
            && matches!(record["operation"].as_str(), Some("apply" | "stop"))
            && record["plan_sha256"].as_str().is_some_and(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            && (record["result"].is_object() || record["result"].is_null()),
        "desktop-operation-receipt-invalid",
    )
}
impl Reviewed for Desktop {
    fn query(&mut self, peer: &Peer) -> Result<Value> {
        let uid = desktop_grant::account(peer.uid)?;
        let grant = self.current(uid)?;
        let unattended = Store::installed(uid)?.load()?;
        let p = self.properties(uid)?;
        let viewers = if p.active == "inactive" && p.main_pid == 0 {
            value!({"status":"available","connected_count":0,"clients":[]})
        } else if p.active == "active" && p.main_pid > 0 {
            if let Some(grant) = grant
                .as_ref()
                .filter(|g| !crate::desktop_rdp::selected(&g["configuration"]))
            {
                self.runtime
                    .block_on(crate::desktop_viewers::observe(uid, p.main_pid, grant))
                    .unwrap_or_else(
                        |_| value!({"status":"unavailable","connected_count":null,"clients":null}),
                    )
            } else {
                value!({"status":"unavailable","connected_count":null,"clients":null})
            }
        } else {
            value!({"status":"unavailable","connected_count":null,"clients":null})
        };
        Ok(
            value!({"schema":1,"configuration":grant.as_ref().map(|g| &g["configuration"]),"viewers":viewers,"listening":self.listening(uid, grant.as_ref())?,"state":p.active,"endpoint_reserved":p.fdstore>0,"cleanup_pending":p.fdstore>0 && matches!(p.active.as_str(), "inactive" | "failed"),"encrypted_only":true,"autostart":unattended.is_some(),"unattended":unattended.as_ref().map(|r| value!({"configuration":r["configuration"],"interface":desktop_unattended::reviewed(r)["interface"]})),"remote_login":false,"ends_on_lock_logout_or_inactive":true,"credentials_owned_by_user":true}),
        )
    }
    fn review(&mut self, peer: &Peer, configuration: &Value) -> Result<Value> {
        require(peer.kind == "wayland", "desktop-wayland-session-required")?;
        let provider = if crate::desktop_rdp::selected(configuration) {
            Some(crate::desktop_rdp::Installed::observe()?)
        } else {
            desktop_binding::installed(Path::new("/usr/bin/wayvnc"))?;
            None
        };
        let addresses = network::interfaces()?;
        let checked = config::desktop(configuration, &addresses.keys().copied().collect())?;
        require(
            checked["mode"] == "session-sharing",
            "remote-login-provider-unavailable",
        )?;
        require(checked["enabled"] == true, "use-stop-desktop-sharing")?;
        let bound = self
            .runtime
            .block_on(self.session.discover(peer.uid, &peer.id))?;
        let ip = checked["listen_address"]
            .as_str()
            .unwrap()
            .parse::<IpAddr>()
            .map_err(|_| Error("desktop-listen-address-unavailable".into()))?;
        let interface = addresses
            .get(&ip)
            .ok_or_else(|| Error("desktop-listen-address-unavailable".into()))?;
        let zone = self.runtime.block_on(self.firewall.zone_for(interface))?;
        let connection = self
            .runtime
            .block_on(network::connection(&self.connection, interface))?;
        // Unattended sharing follows a changed configuration only onto an identifiable network.
        let unattended = Store::installed(peer.uid)?.load()?.is_some();
        require(
            !unattended || provider.is_none(),
            "desktop-unattended-provider-unavailable",
        )?;
        require(
            !unattended || connection.is_some(),
            "desktop-unattended-network-identity-unavailable",
        )?;
        let mut plan = value!({"schema":1,"uid":peer.uid,"configuration":checked,"session":bound,"interface":interface,"zone":zone,"connection":connection,"previous_state_sha256":json::fingerprint(&self.snapshot(peer.uid)?)?,"encrypted_only":true,"autostart":unattended,"ends_on_lock_logout_or_inactive":true,"existing_desktop_clients_disconnected":true,"ssh_connections_changed":false});
        if let Some(provider) = &provider {
            provider.recheck()?;
            plan["provider"] = provider.proof();
        }
        Ok(value!({"plan_sha256":json::fingerprint(&plan)?,"plan":plan}))
    }
    fn review_stop(&mut self, peer: &Peer) -> Result<Value> {
        let unattended = Store::installed(peer.uid)?.load()?.is_some();
        let plan = value!({"schema":1,"uid":peer.uid,"previous_state_sha256":json::fingerprint(&self.snapshot(peer.uid)?)?,"desktop_clients_disconnected":true,"ssh_connections_changed":false,"autostart":false,"unattended_turned_off":unattended});
        Ok(value!({"plan_sha256":json::fingerprint(&plan)?,"plan":plan}))
    }
    fn review_unattended(&mut self, peer: &Peer, enabled: bool) -> Result<Value> {
        require(peer.kind == "wayland", "desktop-wayland-session-required")?;
        let uid = desktop_grant::account(peer.uid)?;
        let previous = json::fingerprint(&self.snapshot(uid)?)?;
        if !enabled {
            let plan = value!({"schema":1,"uid":uid,"unattended":false,"previous_state_sha256":previous,"sharing_now_unchanged":true});
            return Ok(value!({"plan_sha256":json::fingerprint(&plan)?,"plan":plan}));
        }
        let grant = self
            .current(uid)?
            .ok_or_else(|| Error("desktop-unattended-requires-sharing".into()))?;
        require(
            !crate::desktop_rdp::selected(&grant["configuration"]),
            "desktop-unattended-provider-unavailable",
        )?;
        require(
            grant["session"]["id"] == peer.id.as_str() && self.listening(uid, Some(&grant))?,
            "desktop-unattended-requires-sharing",
        )?;
        let configuration = &grant["configuration"];
        let address: IpAddr = configuration["listen_address"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error("desktop-grant-invalid".into()))?;
        let network = self.reviewed_network(address)?;
        let row = &network[0];
        require(
            row["interface"] == grant["interface"]
                && row["zone"] == grant["zone"]
                && grant
                    .get("connection")
                    .is_none_or(|reviewed| *reviewed == row["connection"]),
            "desktop-approved-network-changed",
        )?;
        desktop_unattended::record(uid, configuration, &network)?;
        let plan = value!({"schema":1,"uid":uid,"unattended":true,"configuration":configuration,"network":network,"previous_state_sha256":previous,"starts_after_sign_in":true,"starts_before_sign_in":false,"ends_on_lock_logout_or_inactive":true,"resumes_after_unlock":true,"stops_off_reviewed_network":true,"credentials_unchanged":true});
        Ok(value!({"plan_sha256":json::fingerprint(&plan)?,"plan":plan}))
    }
    fn change(
        &mut self,
        peer: &Peer,
        reviewed: &Value,
        operation: Operation,
        before_commit: &mut dyn FnMut(&mut Self, bool) -> Result<()>,
    ) -> Result<Value> {
        let uid = desktop_grant::account(peer.uid)?;
        let directory = desktop_grant::folder(uid)?;
        files::ensure_directory(&directory, 0o700, 0)?;
        let _lock = operation_lock(&directory)?;
        if operation == Operation::Unattended {
            before_commit(self, true)?;
            let plan = &reviewed["plan"];
            let enabled = plan["unattended"] == true;
            let record = enabled
                .then(|| desktop_unattended::record(uid, &plan["configuration"], &plan["network"]))
                .transpose()?;
            self.set_unattended(uid, record.as_ref())?;
            return Ok(value!({"schema":1,"unattended":enabled}));
        }
        let stopping = operation == Operation::Stop;
        require(
            stopping || !self.unfinished(uid)?,
            "desktop-prior-operation-needs-reviewed-stop",
        )?;
        before_commit(self, true)?;
        self.receipt(uid, "pending", stopping, reviewed, Value::Null)?;
        let mut touched = false;
        let change: Result<Value> = (|| {
            before_commit(self, true)?;
            touched = true;
            if stopping && reviewed["plan"]["unattended_turned_off"] == true {
                self.set_unattended(uid, None)?;
            }
            self.runtime.block_on(self.system(uid)?.job("stop"))?;
            self.release(uid)?;
            if stopping {
                return Ok(
                    value!({"schema":1,"stopped":true,"desktop_clients_disconnected":true,"ssh_connections_changed":false}),
                );
            }
            let plan = &reviewed["plan"];
            before_commit(self, false)?;
            self.runtime
                .block_on(self.session.verify(&plan["session"]))?;
            let addresses = network::interfaces()?;
            let mut grant = value!({"schema":1,"boot_id":ssh_provider::boot_id()?,"uid":uid,"nonce":files::random_hex(32)?,"session":plan["session"],"configuration":plan["configuration"],"interface":plan["interface"],"zone":plan["zone"],"connection":plan["connection"]});
            if crate::desktop_rdp::selected(&plan["configuration"]) {
                crate::desktop_rdp::Installed::observe()?.matches(&plan["provider"])?;
                grant["provider"] = plan["provider"].clone();
            }
            desktop_grant::publish(
                &grant,
                uid,
                &ssh_provider::boot_id()?,
                &addresses.keys().copied().collect(),
            )?;
            before_commit(self, false)?;
            self.runtime
                .block_on(self.session.verify(&plan["session"]))?;
            self.runtime.block_on(self.system(uid)?.job("start"))?;
            self.ready(uid, &grant)?;
            before_commit(self, false)?;
            self.runtime
                .block_on(self.session.verify(&plan["session"]))?;
            if plan["autostart"] == true {
                let network = value!([network::identity(
                    grant["configuration"]["listen_address"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .ok_or_else(|| Error("desktop-grant-invalid".into()))?,
                    grant["interface"].as_str().unwrap_or_default(),
                    grant["zone"].as_str(),
                    grant["connection"].as_str(),
                )]);
                Store::installed(uid)?.write(&desktop_unattended::record(
                    uid,
                    &grant["configuration"],
                    &network,
                )?)?;
            }
            Ok(
                value!({"schema":1,"listening":true,"configuration":grant["configuration"],"autostart":plan["autostart"],"ends_on_lock_logout_or_inactive":true}),
            )
        })();
        match change {
            Ok(result) => {
                self.receipt(uid, "complete", stopping, reviewed, result.clone())?;
                Ok(result)
            }
            Err(error) => {
                let cleanup: Result<()> = if touched {
                    (|| {
                        self.runtime.block_on(self.system(uid)?.job("stop"))?;
                        self.release(uid)
                    })()
                } else {
                    Ok(())
                };
                self.receipt(
                    uid,
                    if cleanup.is_ok() {
                        "failed"
                    } else {
                        "uncertain"
                    },
                    stopping,
                    reviewed,
                    Value::Null,
                )?;
                cleanup?;
                Err(error)
            }
        }
    }
}
