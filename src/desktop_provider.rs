// SPDX-License-Identifier: MIT
//! Reviewed, run-only desktop sharing with durable pending-before-mutation state.
use crate::{
    config, desktop_binding, desktop_grant,
    desktop_session::Session,
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
pub trait Reviewed: Send + 'static {
    fn query(&mut self, peer: &Peer) -> Result<Value>;
    fn review(&mut self, peer: &Peer, configuration: &Value) -> Result<Value>;
    fn review_stop(&mut self, peer: &Peer) -> Result<Value>;
    fn change(
        &mut self,
        peer: &Peer,
        reviewed: &Value,
        stopping: bool,
        before_commit: &mut dyn FnMut(&mut Self, bool) -> Result<()>,
    ) -> Result<Value>;
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
            value!({"grant":self.current(uid)?,"state":p.active,"pid":p.main_pid,"invocation":invocation,"reserved_descriptors":p.fdstore}),
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
            value!({"schema":1,"configuration":grant.as_ref().map(|g| &g["configuration"]),"viewers":viewers,"listening":self.listening(uid, grant.as_ref())?,"state":p.active,"endpoint_reserved":p.fdstore>0,"cleanup_pending":p.fdstore>0 && matches!(p.active.as_str(), "inactive" | "failed"),"encrypted_only":true,"autostart":false,"remote_login":false,"ends_on_lock_logout_or_inactive":true,"credentials_owned_by_user":true}),
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
        let mut plan = value!({"schema":1,"uid":peer.uid,"configuration":checked,"session":bound,"interface":interface,"zone":zone,"previous_state_sha256":json::fingerprint(&self.snapshot(peer.uid)?)?,"encrypted_only":true,"autostart":false,"ends_on_lock_logout_or_inactive":true,"existing_desktop_clients_disconnected":true,"ssh_connections_changed":false});
        if let Some(provider) = &provider {
            provider.recheck()?;
            plan["provider"] = provider.proof();
        }
        Ok(value!({"plan_sha256":json::fingerprint(&plan)?,"plan":plan}))
    }
    fn review_stop(&mut self, peer: &Peer) -> Result<Value> {
        let plan = value!({"schema":1,"uid":peer.uid,"previous_state_sha256":json::fingerprint(&self.snapshot(peer.uid)?)?,"desktop_clients_disconnected":true,"ssh_connections_changed":false,"autostart":false});
        Ok(value!({"plan_sha256":json::fingerprint(&plan)?,"plan":plan}))
    }
    fn change(
        &mut self,
        peer: &Peer,
        reviewed: &Value,
        stopping: bool,
        before_commit: &mut dyn FnMut(&mut Self, bool) -> Result<()>,
    ) -> Result<Value> {
        let uid = desktop_grant::account(peer.uid)?;
        let directory = desktop_grant::folder(uid)?;
        files::ensure_directory(&directory, 0o700, 0)?;
        let _lock = files::Lock::acquire(&directory.join("operation.lock"), 0)?;
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
            let mut grant = value!({"schema":1,"boot_id":ssh_provider::boot_id()?,"uid":uid,"nonce":files::random_hex(32)?,"session":plan["session"],"configuration":plan["configuration"],"interface":plan["interface"],"zone":plan["zone"]});
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
            Ok(
                value!({"schema":1,"listening":true,"configuration":grant["configuration"],"autostart":false,"ends_on_lock_logout_or_inactive":true}),
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
