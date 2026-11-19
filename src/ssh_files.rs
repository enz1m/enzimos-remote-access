// SPDX-License-Identifier: MIT
//! Separate host identity and validated, Root-owned OpenSSH publication.
use crate::{config, keys};
use enzimos_platform::{Error, Result, files, json, memfile, process, publication, require};
use serde_json::{Value, json as value};
use std::{
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;
pub struct Layout {
    pub state: PathBuf,
    pub configuration: PathBuf,
    pub owner: u32,
}
impl Default for Layout {
    fn default() -> Self {
        Self {
            state: "/var/lib/enzimos/remote/ssh".into(),
            configuration: "/etc/enzimos/remote".into(),
            owner: 0,
        }
    }
}
fn private(path: &Path, owner: u32) -> Result<std::fs::File> {
    let held = files::ensure_directory(path, 0o700, owner)?;
    require(
        held.metadata()?.uid() == owner && held.metadata()?.mode() & 0o777 == 0o700,
        "ssh-private-state-required",
    )?;
    Ok(held)
}
fn output(
    program: &str,
    args: &[&str],
    descriptors: &[std::os::fd::BorrowedFd<'_>],
) -> Result<String> {
    let out = process::run_with_fds(
        program,
        args,
        &[],
        Duration::from_secs(20),
        65536,
        descriptors,
    )?;
    require(out.status.success(), "openssh-validation-failed")?;
    String::from_utf8(out.stdout).map_err(|_| Error("openssh-output-encoding".into()))
}
fn private_key(path: &Path, owner: u32) -> Result<Zeroizing<Vec<u8>>> {
    let held = files::directory(
        path.parent()
            .ok_or_else(|| Error("host-key-parent".into()))?,
        Some(owner),
    )?;
    let mut file = files::open_relative(
        &held,
        Path::new(
            path.file_name()
                .ok_or_else(|| Error("host-key-name".into()))?,
        ),
    )?;
    let before = file.metadata()?;
    require(
        before.uid() == owner
            && before.mode() & 0o077 == 0
            && before.nlink() == 1
            && before.len() <= 16384,
        "host-key-not-private",
    )?;
    use std::io::Read;
    let mut data = Zeroizing::new(Vec::new());
    (&mut file).take(16385).read_to_end(&mut data)?;
    let identity = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    require(
        data.len() as u64 == before.len() && identity(&before) == identity(&file.metadata()?),
        "host-key-changed-during-read",
    )?;
    Ok(data)
}
fn public(data: &[u8]) -> Result<Value> {
    let text =
        std::str::from_utf8(data).map_err(|_| Error("host-public-identity-unavailable".into()))?;
    let words = text.split_whitespace().collect::<Vec<_>>();
    require(
        words.len() >= 2 && words.len() <= 32 && words[0] == "ssh-ed25519",
        "host-public-identity-unavailable",
    )?;
    keys::public_key(&format!("{} {}", words[0], words[1]))
}
impl Layout {
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    pub fn host_identity(&self) -> Result<String> {
        require(
            unsafe { libc::geteuid() } == self.owner,
            "host-key-writer-required",
        )?;
        let _held = private(&self.state, self.owner)?;
        let _lock = files::Lock::acquire(&self.state.join("host-key.lock"), self.owner)?;
        let secret = self.state.join("host_ed25519");
        let pubkey = self.state.join("host_ed25519.pub");
        let receipt = self.state.join("host-key-creation.json");
        let record = files::read_optional(&receipt, 4096, Some(self.owner), true)?
            .map(|b| json::decode(&b, 4096))
            .transpose()?;
        if let Some(record) = &record {
            json::fields(record, "schema phase stage fingerprint")?;
            require(
                record["schema"] == 1 && record["phase"] == "complete",
                "host-key-creation-interrupted-no-auto-retry",
            )?;
        }
        let missing = |p: &Path| -> Result<bool> {
            match std::fs::symlink_metadata(p) {
                Ok(_) => Ok(false),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
                Err(e) => Err(e.into()),
            }
        };
        if missing(&secret)? {
            require(
                record.is_none() && missing(&pubkey)?,
                "host-key-pair-incomplete-no-auto-replacement",
            )?;
            let token = files::random_hex(16)?;
            let stage = self.state.join(format!(".host-key-{token}"));
            let mut record =
                value!({"schema":1,"phase":"prepared","stage":token,"fingerprint":null});
            publication::Prepared::write(&receipt, &json::canonical(&record)?, self.owner)?
                .commit(false)?;
            private(&stage, self.owner)?;
            let generated = stage.join("key");
            let spelling = generated
                .to_str()
                .ok_or_else(|| Error("host-key-path-encoding".into()))?;
            output(
                "/usr/bin/ssh-keygen",
                &["-q", "-t", "ed25519", "-N", "", "-f", spelling],
                &[],
            )?;
            let body = private_key(&generated, self.owner)?;
            let public_body = files::read(&stage.join("key.pub"), 4096, Some(self.owner), true)?;
            let identity = public(&public_body)?;
            let key = memfile::sealed("enzimos-ssh-host-key", &body)?;
            let derived = output(
                "/usr/bin/ssh-keygen",
                &["-y", "-f", "@fd:0"],
                &[key.as_fd()],
            )?;
            require(
                public(derived.as_bytes())?["key"] == identity["key"],
                "host-key-pair-mismatch",
            )?;
            files::atomic(&secret, &body, 0o600, Some(self.owner), false)?;
            files::atomic(&pubkey, &public_body, 0o644, Some(self.owner), false)?;
            record["phase"] = value!("complete");
            record["fingerprint"] = identity["fingerprint"].clone();
            publication::Prepared::write(&receipt, &json::canonical(&record)?, self.owner)?
                .commit(true)?;
            // The private creation stage remains confined until explicit cleanup;
            // incomplete publication is never mistaken for permission to rotate.
        }
        let body = private_key(&secret, self.owner)?;
        let identity = public(&files::read(&pubkey, 4096, Some(self.owner), true)?)?;
        let key = memfile::sealed("enzimos-ssh-host-key", &body)?;
        let derived = output(
            "/usr/bin/ssh-keygen",
            &["-y", "-f", "@fd:0"],
            &[key.as_fd()],
        )?;
        require(
            public(derived.as_bytes())?["key"] == identity["key"],
            "host-key-pair-mismatch",
        )?;
        if let Some(record) = record {
            require(
                record["fingerprint"] == identity["fingerprint"],
                "host-key-identity-changed",
            )?;
        }
        Ok(identity["fingerprint"]
            .as_str()
            .ok_or_else(|| Error("host-key-fingerprint".into()))?
            .to_owned())
    }
    pub fn public_host_key(&self) -> Result<Option<String>> {
        files::read_optional(
            &self.state.join("host_ed25519.pub"),
            4096,
            Some(self.owner),
            true,
        )?
        .map(|b| {
            Ok(public(&b)?["key"]
                .as_str()
                .ok_or_else(|| Error("host-public-identity-unavailable".into()))?
                .to_owned())
        })
        .transpose()
    }
    pub fn prepare(&self, configuration: &Value) -> Result<Prepared> {
        let rendered = config::render_ssh(configuration)?;
        let account = configuration["account"]
            .as_str()
            .ok_or_else(|| Error("ordinary-account-required".into()))?
            .to_owned();
        let fingerprint = self.host_identity()?;
        let keys = configuration["public_keys"]
            .as_array()
            .ok_or_else(|| Error("public-key-list-bound".into()))?
            .iter()
            .map(|row| {
                row["key"]
                    .as_str()
                    .ok_or_else(|| Error("public-key-input-invalid".into()))
            })
            .collect::<Result<Vec<_>>>()?
            .join("\n")
            + "\n";
        files::atomic(
            &self.state.join("candidate_authorized_keys"),
            keys.as_bytes(),
            0o600,
            Some(self.owner),
            true,
        )?;
        if !configuration["public_keys"]
            .as_array()
            .is_some_and(Vec::is_empty)
        {
            output(
                "/usr/bin/ssh-keygen",
                &[
                    "-l",
                    "-E",
                    "sha256",
                    "-f",
                    self.state
                        .join("candidate_authorized_keys")
                        .to_str()
                        .ok_or_else(|| Error("ssh-candidate-path".into()))?,
                ],
                &[],
            )?;
        }
        files::atomic(
            &self.state.join("candidate_sshd_config"),
            rendered.as_bytes(),
            0o600,
            Some(self.owner),
            true,
        )?;
        output(
            "/usr/bin/sshd",
            &[
                "-t",
                "-f",
                self.state
                    .join("candidate_sshd_config")
                    .to_str()
                    .ok_or_else(|| Error("ssh-candidate-path".into()))?,
            ],
            &[],
        )?;
        Ok(Prepared {
            configuration: configuration.clone(),
            rendered,
            keys,
            account,
            fingerprint,
        })
    }
    pub fn publish(&self, prepared: Prepared) -> Result<()> {
        require(
            config::render_ssh(&prepared.configuration)? == prepared.rendered
                && self.host_identity()? == prepared.fingerprint,
            "ssh-prepared-identity-changed",
        )?;
        files::ensure_directory(&self.configuration, 0o755, self.owner)?;
        let directory = self.configuration.join("authorized_keys");
        files::ensure_directory(&directory, 0o755, self.owner)?;
        files::atomic(
            &directory.join(&prepared.account),
            prepared.keys.as_bytes(),
            0o644,
            Some(self.owner),
            true,
        )?;
        files::atomic(
            &self.configuration.join("sshd_config"),
            prepared.rendered.as_bytes(),
            0o644,
            Some(self.owner),
            true,
        )
    }
}
pub struct Prepared {
    configuration: Value,
    rendered: String,
    keys: String,
    account: String,
    pub fingerprint: String,
}
