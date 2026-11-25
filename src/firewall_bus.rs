// SPDX-License-Identifier: MIT
//! Runtime-only firewalld calls, pinned to one unique provider owner.
use crate::{
    bus_adapter::Pinned,
    firewall::{self, Interface, Rule},
    firewall_journal::Journal,
    network,
};
use enzimos_platform::{Error, Result, require};
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};
use zbus::{
    Connection,
    zvariant::{OwnedValue, Value},
};
const PATH: &str = "/org/fedoraproject/FirewallD1";
const CORE: &str = "org.fedoraproject.FirewallD1";
const ZONE: &str = "org.fedoraproject.FirewallD1.zone";
const POLICY: &str = "org.fedoraproject.FirewallD1.policy";
fn field<T: TryFrom<OwnedValue>>(v: &HashMap<String, OwnedValue>, key: &str) -> Result<T> {
    T::try_from(
        v.get(key)
            .ok_or_else(|| Error("remote-firewall-policy-missing-field".into()))?
            .try_clone()
            .map_err(|_| Error("remote-firewall-policy-field-type".into()))?,
    )
    .map_err(|_| Error("remote-firewall-policy-field-type".into()))
}
pub fn policy_rows(settings: &HashMap<String, OwnedValue>) -> Result<Vec<String>> {
    require(
        settings.len() <= 128
            && field::<String>(settings, "target")? == "CONTINUE"
            && field::<i32>(settings, "priority")? == -32000
            && field::<Vec<String>>(settings, "ingress_zones")? == vec!["ANY"]
            && field::<Vec<String>>(settings, "egress_zones")? == vec!["HOST"],
        "remote-firewall-policy-changed",
    )?;
    // firewalld omits empty list keys, so the packaged policy before its first
    // rule has no `rich_rules` at all.
    let rows = if settings.contains_key("rich_rules") {
        field::<Vec<String>>(settings, "rich_rules")?
    } else {
        Vec::new()
    };
    require(
        rows.len() <= 128
            && rows
                .iter()
                .all(|s| !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control))
            && rows.iter().collect::<BTreeSet<_>>().len() == rows.len(),
        "remote-firewall-policy-bound",
    )?;
    Ok(rows)
}
#[derive(Clone)]
pub struct Firewall {
    connection: Connection,
    bus: Arc<tokio::sync::OnceCell<Pinned>>,
    runtime: tokio::runtime::Handle,
}
impl Firewall {
    pub async fn new(connection: Connection) -> Result<Self> {
        let bus = tokio::sync::OnceCell::new();
        if let Some(pinned) =
            Pinned::if_running(connection.clone(), "org.fedoraproject.FirewallD1").await?
        {
            let _ = bus.set(pinned);
        }
        Ok(Self {
            connection,
            bus: Arc::new(bus),
            runtime: tokio::runtime::Handle::current(),
        })
    }
    async fn bus(&self) -> Result<&Pinned> {
        // A stopped provider has no identity to bind yet. Once bound, owner changes still fail closed.
        self.bus
            .get_or_try_init(|| async {
                Pinned::if_running(self.connection.clone(), "org.fedoraproject.FirewallD1")
                    .await?
                    .ok_or_else(|| Error("remote-firewall-inactive".into()))
            })
            .await
    }
    /// Whether firewalld is running, binding this handle to its owner when it is.
    ///
    /// # Errors
    /// Fails when the bus cannot answer.
    pub async fn running(&self) -> Result<bool> {
        match self.bus().await {
            Ok(_) => Ok(true),
            Err(error) if error.0 == "remote-firewall-inactive" => Ok(false),
            Err(error) => Err(error),
        }
    }
    pub async fn zone_for(&self, interface: &str) -> Result<String> {
        require(
            !interface.is_empty()
                && interface.len() <= 64
                && !interface.chars().any(char::is_control),
            "firewall-interface-unavailable",
        )?;
        let mut zone: String = self
            .bus()
            .await?
            .call(PATH, ZONE, "getZoneOfInterface", &(interface,))
            .await?;
        if zone.is_empty() {
            zone = self
                .bus()
                .await?
                .call(PATH, CORE, "getDefaultZone", &())
                .await?;
        }
        network::zone(&serde_json::json!(&zone))?;
        Ok(zone)
    }
    pub async fn rows(&self) -> Result<Vec<String>> {
        let settings: HashMap<String, OwnedValue> = self
            .bus()
            .await?
            .call(PATH, POLICY, "getPolicySettings", &(firewall::NAME,))
            .await?;
        policy_rows(&settings)
    }
    pub async fn query_async(&self, row: &Rule) -> Result<bool> {
        if row.zone == firewall::TARGET {
            Ok(self.rows().await?.contains(&row.rule))
        } else {
            network::zone(&serde_json::json!(&row.zone))?;
            self.bus()
                .await?
                .call(
                    PATH,
                    ZONE,
                    "queryRichRule",
                    &(row.zone.as_str(), row.rule.as_str()),
                )
                .await
        }
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    async fn change_policy(&self, rule: &str, adding: bool) -> Result<String> {
        require(
            !rule.is_empty() && rule.len() <= 512 && !rule.chars().any(char::is_control),
            "remote-firewall-rule-bound",
        )?;
        // The policy's rich-rule list is read, edited and written back whole;
        // every user's prepare/release edits it, so serialize them globally or
        // one user's release can resurrect another's removed rules.
        // Production edits always run as root; unprivileged test fixtures use a
        // private bus and have no shared policy to protect.
        // SAFETY: geteuid has no preconditions and cannot fail.
        let _policy = if unsafe { libc::geteuid() } == 0 {
            Some(policy_lock().await?)
        } else {
            None
        };
        let mut rows = self.rows().await?;
        let present = rows.iter().position(|r| r == rule);
        if adding {
            if present.is_some() {
                return Ok(firewall::TARGET.into());
            }
            require(rows.len() < 128, "remote-firewall-policy-bound")?;
            rows.push(rule.into());
        } else {
            let Some(index) = present else {
                return Ok(firewall::TARGET.into());
            };
            rows.remove(index);
        }
        let mut settings = HashMap::new();
        settings.insert(
            "rich_rules",
            Value::from(rows.clone())
                .try_to_owned()
                .map_err(|_| Error("remote-firewall-rule-type".into()))?,
        );
        self.bus()
            .await?
            .call::<_, ()>(
                PATH,
                POLICY,
                "setPolicySettings",
                &(firewall::NAME, settings),
            )
            .await?;
        let actual = self.rows().await?;
        require(
            actual.len() == rows.len()
                && actual.iter().collect::<BTreeSet<_>>() == rows.iter().collect::<BTreeSet<_>>(),
            "remote-firewall-policy-unconfirmed",
        )?;
        Ok(firewall::TARGET.into())
    }
    pub async fn add_async(&self, row: &Rule) -> Result<String> {
        if row.zone == firewall::TARGET {
            self.change_policy(&row.rule, true).await
        } else {
            network::zone(&serde_json::json!(&row.zone))?;
            self.bus()
                .await?
                .call(
                    PATH,
                    ZONE,
                    "addRichRule",
                    &(row.zone.as_str(), row.rule.as_str(), 0i32),
                )
                .await
        }
    }
    pub async fn remove_async(&self, row: &Rule) -> Result<()> {
        let zone = if row.zone == firewall::TARGET {
            self.change_policy(&row.rule, false).await?
        } else {
            network::zone(&serde_json::json!(&row.zone))?;
            self.bus()
                .await?
                .call(
                    PATH,
                    ZONE,
                    "removeRichRule",
                    &(row.zone.as_str(), row.rule.as_str()),
                )
                .await?
        };
        require(zone == row.zone, "firewall-zone-changed")
    }
}
impl Journal<'_, Firewall> {
    /// Releases the owned rules, or forgets them while firewalld is not running.
    ///
    /// Returns whether firewalld is running.
    ///
    /// # Errors
    /// Fails when a running firewalld does not confirm removal.
    pub fn release_or_forget(&mut self) -> Result<bool> {
        if self.interface.runtime.block_on(self.interface.running())? {
            self.release()?;
            Ok(true)
        } else {
            self.forget()?;
            Ok(false)
        }
    }
}
// These synchronous adapters run inside the dispatcher's bounded blocking jobs,
// never from a Tokio worker that is already polling this runtime.
impl Interface for Firewall {
    fn query(&mut self, row: &Rule) -> Result<bool> {
        self.runtime.block_on(self.query_async(row))
    }
    fn add(&mut self, row: &Rule) -> Result<String> {
        self.runtime.block_on(self.add_async(row))
    }
    fn remove(&mut self, row: &Rule) -> Result<()> {
        self.runtime.block_on(self.remove_async(row))
    }
}

async fn policy_lock() -> Result<enzimos_platform::files::Lock> {
    let directory = std::path::Path::new("/run/enzimos-remote");
    enzimos_platform::files::ensure_directory(directory, 0o700, 0)?;
    let path = directory.join("policy.lock");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if let Some(lock) = enzimos_platform::files::Lock::try_acquire(&path, 0)? {
            return Ok(lock);
        }
        require(
            std::time::Instant::now() < deadline,
            "remote-firewall-policy-busy",
        )?;
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}
