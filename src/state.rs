// SPDX-License-Identifier: MIT
use crate::{config, network};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::path::{Path, PathBuf};

/// Reviewed network identity of the approval, kept beside `approval.json`.
const NETWORK: &str = "approval-network.json";

/// Validates an `approval.json` record in the schema every release reads.
///
/// # Errors
/// Fails for missing, extra or malformed fields.
pub fn validate(v: &Value) -> Result<()> {
    json::fields(v, "schema uid phase boot_id configuration detail")?;
    require(
        v["schema"] == 1
            && v["uid"]
                .as_u64()
                .is_some_and(|n| (1000..u64::from(u32::MAX)).contains(&n))
            && matches!(
                v["phase"].as_str(),
                Some("pending" | "complete" | "failed" | "uncertain")
            )
            && v["boot_id"].is_string()
            && v["configuration"].is_object()
            && v["detail"]
                .as_str()
                .is_some_and(|s| s.chars().count() <= 160),
        "remote-state-fields",
    )
}
fn validate_network(network: &Value, record: &Value) -> Result<()> {
    if network.is_null() {
        return Ok(());
    }
    network::validate_identity(
        network,
        &config::listen_addresses(
            &record["configuration"]["listen_address"],
            record["configuration"].get("listen_addresses"),
        )?,
    )
}
// The sidecar applies only to the approval it was written for; an approval
// rewritten by a release that does not know the sidecar leaves it stale.
fn binding(record: &Value) -> Result<String> {
    json::fingerprint(&value!({
        "uid": record["uid"],
        "boot_id": record["boot_id"],
        "configuration": record["configuration"],
    }))
}
pub struct State {
    directory: PathBuf,
    owner: u32,
    boot_id: String,
}
impl State {
    pub fn new(directory: &Path, owner: u32, boot_id: String) -> Result<Self> {
        files::ensure_directory(directory, 0o700, owner)?;
        Ok(Self {
            directory: directory.to_owned(),
            owner,
            boot_id,
        })
    }
    fn record_path(&self) -> PathBuf {
        self.directory.join("approval.json")
    }
    fn network_path(&self) -> PathBuf {
        self.directory.join(NETWORK)
    }
    fn read(&self, path: &Path) -> Result<Option<Value>> {
        files::read_optional(path, 65536, Some(self.owner), true)?
            .map(|body| json::decode(&body, 65536))
            .transpose()
    }
    /// Loads the approval with its reviewed network identity under `network`.
    ///
    /// `network` is `null` for an approval made before network review, or one
    /// whose sidecar was written for a different approval.
    ///
    /// # Errors
    /// Fails for a malformed approval or a malformed sidecar bound to it.
    pub fn load(&self) -> Result<Option<Value>> {
        let Some(mut record) = self.read(&self.record_path())? else {
            return Ok(None);
        };
        let network = if record["schema"] == 2 {
            // Pre-release builds kept the identity inside the record.
            let object = record
                .as_object_mut()
                .ok_or_else(|| Error("remote-state-fields".into()))?;
            let network = object
                .remove("network")
                .ok_or_else(|| Error("remote-state-fields".into()))?;
            object.insert("schema".into(), value!(1));
            network
        } else {
            Value::Null
        };
        validate(&record)?;
        let network = if network.is_null() {
            self.sidecar(&record)?
        } else {
            network
        };
        validate_network(&network, &record)?;
        record["network"] = network;
        Ok(Some(record))
    }
    fn sidecar(&self, record: &Value) -> Result<Value> {
        let Some(body) = files::read_optional(&self.network_path(), 65536, Some(self.owner), true)?
        else {
            return Ok(Value::Null);
        };
        // An unreadable sidecar leaves the approval as one made before network review.
        let Ok(sidecar) = json::decode(&body, 65536) else {
            return Ok(Value::Null);
        };
        if sidecar["schema"] != 1 || sidecar["approval_sha256"] != binding(record)? {
            return Ok(Value::Null);
        }
        json::fields(&sidecar, "schema approval_sha256 network")?;
        Ok(sidecar["network"].clone())
    }
    fn write_sidecar(&self, record: &Value, network: &Value) -> Result<()> {
        if network.is_null() {
            return match std::fs::remove_file(self.network_path()) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
                _ => Ok(()),
            };
        }
        let sidecar = value!({"schema":1,"approval_sha256":binding(record)?,"network":network});
        files::atomic(
            &self.network_path(),
            &json::canonical(&sidecar)?,
            0o600,
            Some(self.owner),
            true,
        )
    }
    /// Writes an approval readable by every release, with `network` in its sidecar.
    ///
    /// # Errors
    /// Fails for invalid fields or when either file cannot be written.
    pub fn write(
        &self,
        uid: u32,
        phase: &str,
        configuration: &Value,
        network: &Value,
        detail: &str,
    ) -> Result<Value> {
        let record = value!({"schema":1,"uid":uid,"phase":phase,"boot_id":self.boot_id,"configuration":configuration,"detail":detail});
        validate(&record)?;
        validate_network(network, &record)?;
        // Sidecar first: a crash in between leaves the previous approval unbound, never misbound.
        self.write_sidecar(&record, network)?;
        files::atomic(
            &self.record_path(),
            &json::canonical(&record)?,
            0o600,
            Some(self.owner),
            true,
        )?;
        let written = self
            .load()?
            .ok_or_else(|| Error("remote-state-write-unconfirmed".into()))?;
        require(
            written["network"] == *network,
            "remote-state-write-unconfirmed",
        )?;
        Ok(written)
    }
    /// Brings `approved` to the current on-disk layout without changing what it approves.
    ///
    /// A pre-release schema-2 record is split into a schema-1 record and its sidecar.
    /// An approval without a network identity records `observed`, the network
    /// its listener runs on now. The caller holds [`State::exclusive`].
    ///
    /// # Errors
    /// Fails when the approval changed since `approved` was loaded or cannot be rewritten.
    pub fn upgrade(&self, approved: &Value, observed: Option<&Value>) -> Result<()> {
        require(
            self.load()?.as_ref() == Some(approved),
            "remote-approved-configuration-changed",
        )?;
        let on_disk = self
            .read(&self.record_path())?
            .ok_or_else(|| Error("remote-listener-not-approved".into()))?;
        let mut record = approved.clone();
        if let Some(object) = record.as_object_mut() {
            object.remove("network");
        }
        let network = match observed {
            Some(observed) if approved["network"].is_null() => observed.clone(),
            _ => approved["network"].clone(),
        };
        if on_disk == record && network == approved["network"] {
            return Ok(());
        }
        validate_network(&network, &record)?;
        self.write_sidecar(&record, &network)?;
        if on_disk != record {
            files::atomic(
                &self.record_path(),
                &json::canonical(&record)?,
                0o600,
                Some(self.owner),
                true,
            )?;
        }
        Ok(())
    }
    /// Loads the approval a listener may start from during this boot.
    ///
    /// # Errors
    /// Fails for a disabled, unfinished or other-boot approval without autostart.
    pub fn eligible(&self) -> Result<Value> {
        let v = self
            .load()?
            .ok_or_else(|| Error("remote-listener-not-approved".into()))?;
        require(
            v["configuration"]["enabled"] == true,
            "remote-listener-not-approved",
        )?;
        require(
            (v["phase"] == "pending" && v["boot_id"] == self.boot_id)
                || (v["phase"] == "complete"
                    && (v["boot_id"] == self.boot_id || v["configuration"]["autostart"] == true)),
            "remote-unfinished-or-autostart-unapproved",
        )?;
        Ok(v)
    }
    /// Waits for the lock that configuration transactions hold.
    ///
    /// # Errors
    /// Fails when the lock file cannot be opened.
    pub fn exclusive(&self) -> Result<files::Lock> {
        files::Lock::acquire(&self.directory.join("configuration.lock"), self.owner)
    }
    /// Takes the configuration lock unless a transaction holds it.
    ///
    /// # Errors
    /// Fails when the lock file cannot be opened.
    pub fn try_exclusive(&self) -> Result<Option<files::Lock>> {
        files::Lock::try_acquire(&self.directory.join("configuration.lock"), self.owner)
    }
}
