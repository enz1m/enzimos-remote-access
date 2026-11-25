// SPDX-License-Identifier: MIT
//! The owner's standing approval to start desktop sharing after sign-in.
//!
//! The record lives in its own file, which releases without unattended
//! sharing never read. See `docs/DESKTOP_SHARING.md` for its format.
use crate::{config, desktop_grant, network};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

/// Root's folder for per-account unattended sharing records.
pub const STATE: &str = "/var/lib/enzimos/remote/desktop";
const RECORD: &str = "unattended.json";

/// Validates a schema-1 record for `uid`.
///
/// # Errors
/// Fails for missing, extra or malformed fields, a configuration that is not
/// encrypted VNC session sharing, or a network identity without a reviewed
/// zone and NetworkManager connection.
pub fn validate(record: &Value, uid: u32) -> Result<()> {
    json::fields(record, "schema uid configuration network")?;
    desktop_grant::account(uid)?;
    let configuration = &record["configuration"];
    require(
        record["schema"].as_u64() == Some(1)
            && record["uid"].as_u64() == Some(u64::from(uid))
            && configuration["schema"].as_u64() == Some(1)
            && configuration["enabled"] == true
            && configuration["mode"] == "session-sharing",
        "desktop-unattended-record-invalid",
    )?;
    let address: IpAddr = configuration["listen_address"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error("desktop-unattended-record-invalid".into()))?;
    require(
        config::desktop(configuration, &[address].into())? == *configuration,
        "desktop-unattended-record-invalid",
    )?;
    network::validate_identity(&record["network"], &[address])?;
    require(
        network::identifies_connections(&record["network"]),
        "desktop-unattended-record-invalid",
    )
}

/// Builds the record for a reviewed configuration and the network it was approved on.
///
/// # Errors
/// Fails when the result does not validate.
pub fn record(uid: u32, configuration: &Value, network: &Value) -> Result<Value> {
    let record = value!({"schema":1,"uid":uid,"configuration":configuration,"network":network});
    validate(&record, uid)?;
    Ok(record)
}

/// The reviewed network row of a validated record.
pub fn reviewed(record: &Value) -> &Value {
    &record["network"][0]
}

/// One account's record under a Root-owned state folder.
pub struct Store {
    directory: PathBuf,
    owner: u32,
    uid: u32,
}
impl Store {
    /// Uses the installed state folder for `uid`.
    ///
    /// # Errors
    /// Fails for an account outside the ordinary range.
    pub fn installed(uid: u32) -> Result<Self> {
        Self::new(Path::new(STATE), 0, uid)
    }
    /// Uses `root/<uid>`, owned by `owner`.
    ///
    /// # Errors
    /// Fails for an account outside the ordinary range.
    pub fn new(root: &Path, owner: u32, uid: u32) -> Result<Self> {
        Ok(Self {
            directory: root.join(desktop_grant::account(uid)?.to_string()),
            owner,
            uid,
        })
    }
    fn path(&self) -> PathBuf {
        self.directory.join(RECORD)
    }
    /// Loads the record, or `None` when unattended sharing is off.
    ///
    /// A record that is not valid JSON or has another schema is treated as off
    /// and left in place.
    ///
    /// # Errors
    /// Fails for unsafe file ownership or a malformed schema-1 record.
    pub fn load(&self) -> Result<Option<Value>> {
        if std::fs::symlink_metadata(&self.directory)
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(None);
        }
        let Some(body) = files::read_optional(&self.path(), 65536, Some(self.owner), true)? else {
            return Ok(None);
        };
        let Ok(record) = json::decode(&body, 65536) else {
            return Ok(None);
        };
        if record["schema"].as_u64() != Some(1) {
            return Ok(None);
        }
        validate(&record, self.uid)?;
        Ok(Some(record))
    }
    /// Replaces the record.
    ///
    /// # Errors
    /// Fails for an invalid record or when it cannot be written durably.
    pub fn write(&self, record: &Value) -> Result<()> {
        validate(record, self.uid)?;
        files::ensure_directory(&self.directory, 0o700, self.owner)?;
        files::atomic(
            &self.path(),
            &json::canonical(record)?,
            0o600,
            Some(self.owner),
            true,
        )?;
        require(
            self.load()?.as_ref() == Some(record),
            "desktop-unattended-write-unconfirmed",
        )
    }
    /// Removes the record; removing an absent record succeeds.
    ///
    /// # Errors
    /// Fails when the file exists but cannot be removed.
    pub fn remove(&self) -> Result<()> {
        match std::fs::remove_file(self.path()) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }
}
