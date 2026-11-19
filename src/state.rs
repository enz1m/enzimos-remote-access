// SPDX-License-Identifier: MIT
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::path::{Path, PathBuf};

pub fn validate(v: &Value) -> Result<()> {
    json::fields(v, "schema uid phase boot_id configuration detail")?;
    require(
        v["schema"] == 1
            && v["uid"]
                .as_u64()
                .is_some_and(|n| (1000..u32::MAX as u64).contains(&n))
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
    pub fn load(&self) -> Result<Option<Value>> {
        let Some(body) = files::read_optional(
            &self.directory.join("approval.json"),
            65536,
            Some(self.owner),
            true,
        )?
        else {
            return Ok(None);
        };
        let v = json::decode(&body, 65536)?;
        validate(&v)?;
        Ok(Some(v))
    }
    pub fn write(
        &self,
        uid: u32,
        phase: &str,
        configuration: &Value,
        detail: &str,
    ) -> Result<Value> {
        let v = value!({"schema":1,"uid":uid,"phase":phase,"boot_id":self.boot_id,"configuration":configuration,"detail":detail});
        validate(&v)?;
        files::atomic(
            &self.directory.join("approval.json"),
            &json::canonical(&v)?,
            0o600,
            Some(self.owner),
            true,
        )?;
        self.load()?
            .ok_or_else(|| Error("remote-state-write-unconfirmed".into()))
    }
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
    pub fn exclusive(&self) -> Result<files::Lock> {
        files::Lock::acquire(&self.directory.join("configuration.lock"), self.owner)
    }
}
