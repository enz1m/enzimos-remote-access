// SPDX-License-Identifier: MIT
//! Protected RDP arguments and anonymous credentials for an approved user worker.
use enzimos_platform::{Error, Result, require};
use serde_json::Value;
use std::{
    fs::File,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

/// Installed path of the RDP server.
pub const PROGRAM: &str = "/usr/lib/enzimos-rdp-provider/bin/krdpserver";
/// Seals of the anonymous credential memfd.
pub const SEALS: i32 =
    libc::F_SEAL_SEAL | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_WRITE;

/// Whether `configuration` selects RDP.
pub fn selected(configuration: &Value) -> bool {
    configuration["schema"].as_u64() == Some(2) && configuration["protocol"] == "rdp"
}

/// RDP server arguments for `configuration` with the inherited `listener` and `credential`
/// descriptors.
///
/// # Errors
///
/// Fails when the configuration is not RDP, a descriptor is invalid, or the address is unavailable.
pub fn command(
    configuration: &Value,
    identity: &Path,
    listener: i32,
    credential: i32,
) -> Result<Vec<String>> {
    require(
        selected(configuration),
        "desktop-rdp-configuration-required",
    )?;
    require(
        (3..=1024).contains(&listener)
            && (3..=1024).contains(&credential)
            && listener != credential,
        "desktop-rdp-descriptors-invalid",
    )?;
    let address = configuration["listen_address"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error("desktop-listen-address-unavailable".into()))?;
    let checked =
        crate::config::desktop(configuration, &std::collections::BTreeSet::from([address]))?;
    require(
        checked == *configuration
            && checked["enabled"] == true
            && checked["mode"] == "session-sharing",
        "desktop-sharing-grant-required",
    )?;
    let _path = crate::config::tls_config(identity, &"A".repeat(32))?;
    let mut args = vec![
        "--sharing-password-fd".into(),
        credential.to_string(),
        "--listener-fd".into(),
        listener.to_string(),
        "--address".into(),
        checked["listen_address"]
            .as_str()
            .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?
            .into(),
        "--port".into(),
        checked["port"]
            .as_u64()
            .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?
            .to_string(),
        "--certificate".into(),
        identity
            .join("certificate.pem")
            .to_string_lossy()
            .into_owned(),
        "--certificate-key".into(),
        identity
            .join("private-key.pem")
            .to_string_lossy()
            .into_owned(),
        "--mode".into(),
        "SharedAccess".into(),
    ];
    if checked["view_only"] == true {
        args.push("--view-only".into());
    }
    Ok(args)
}

/// A sealed memfd holding `password` for the RDP server.
///
/// # Errors
///
/// Fails when the password is invalid or the memfd cannot be created and sealed.
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (fchmod, fcntl, getuid, memfd_create)."
)]
pub fn credential(password: &str) -> Result<OwnedFd> {
    require(
        (32..=128).contains(&password.len())
            && password
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c)),
        "desktop-private-password-bound",
    )?;
    // SAFETY: The name is a NUL-terminated literal.
    let raw = unsafe {
        libc::memfd_create(
            c"enzimos-sharing".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    require(raw >= 0, "desktop-anonymous-credential-unavailable")?;
    // SAFETY: `raw` was just returned by memfd_create and is owned by nothing else.
    let mut file = unsafe { File::from_raw_fd(raw) };
    require(
        // SAFETY: fchmod takes no pointers and `file` owns `raw`.
        unsafe { libc::fchmod(raw, 0o600) } == 0,
        "desktop-anonymous-credential-permissions",
    )?;
    file.write_all(password.as_bytes())?;
    require(
        // SAFETY: F_ADD_SEALS takes no pointers and `file` owns `raw`.
        unsafe { libc::fcntl(raw, libc::F_ADD_SEALS, SEALS) } == 0,
        "desktop-anonymous-credential-sealing",
    )?;
    let meta = file.metadata()?;
    require(
        // SAFETY: getuid has no preconditions and cannot fail.
        meta.uid() == unsafe { libc::getuid() }
            && meta.nlink() == 0
            && meta.mode() & 0o7777 == 0o600
            && meta.len() == password.len() as u64
            // SAFETY: F_GET_SEALS takes no pointers and `file` owns `raw`.
            && unsafe { libc::fcntl(raw, libc::F_GET_SEALS) } == SEALS,
        "desktop-anonymous-credential-changed",
    )?;
    // SAFETY: F_DUPFD_CLOEXEC takes no pointers and `file` keeps the source open.
    let inherited = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
    require(inherited >= 0, "desktop-anonymous-credential-duplication")?;
    // SAFETY: `inherited` is a fresh duplicate owned by nothing else.
    let inherited = unsafe { OwnedFd::from_raw_fd(inherited) };
    require(
        inherited.as_raw_fd() <= 1024,
        "desktop-anonymous-credential-descriptor-bound",
    )?;
    Ok(inherited)
}

const PREFIX: &str = "/usr/lib/enzimos-rdp-provider";
const MANIFEST: &str = "/usr/lib/enzimos-rdp-provider/installed-provider.json";
const ELFS: [&str; 5] = [
    "bin/krdpserver",
    "lib/libKRdp.so.6",
    "lib/libKPipeWire.so.6",
    "lib/libKPipeWireRecord.so.6",
    "lib/libKPipeWireDmaBuf.so.6",
];

/// The installed RDP provider, retained with its manifest.
pub struct Installed {
    manifest_sha256: String,
    members: Vec<(std::path::PathBuf, File, std::fs::Metadata)>,
}
fn epoch(meta: &std::fs::Metadata) -> (u64, u64, u64, u32, u32, u32, u64, i64, i64, i64, i64) {
    (
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.uid(),
        meta.gid(),
        meta.mode(),
        meta.nlink(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
    )
}
fn open_installed(
    path: &Path,
    limit: u64,
) -> Result<(std::path::PathBuf, File, std::fs::Metadata)> {
    let canonical = std::fs::canonicalize(path)?;
    require(canonical.starts_with(PREFIX), "desktop-rdp-installed-path")?;
    let parent = enzimos_platform::files::directory(
        canonical
            .parent()
            .ok_or_else(|| Error("desktop-rdp-installed-path".into()))?,
        Some(0),
    )?;
    let file = enzimos_platform::files::open_relative(
        &parent,
        Path::new(
            canonical
                .file_name()
                .ok_or_else(|| Error("desktop-rdp-installed-path".into()))?,
        ),
    )?;
    let meta = file.metadata()?;
    require(
        meta.is_file()
            && meta.uid() == 0
            && meta.gid() == 0
            && meta.mode() & 0o6022 == 0
            && meta.nlink() == 1
            && meta.len() > 0
            && meta.len() <= limit,
        "desktop-rdp-installed-file-untrusted",
    )?;
    Ok((path.to_path_buf(), file, meta))
}
impl Installed {
    /// Observe the installed RDP provider.
    ///
    /// # Errors
    ///
    /// Fails when the manifest or an installed file is invalid.
    pub fn observe() -> Result<Self> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let original = open_installed(Path::new(MANIFEST), 65536)?;
        let mut bytes = Vec::new();
        (&original.1).take(65537).read_to_end(&mut bytes)?;
        let manifest = enzimos_platform::json::decode(&bytes, 65536)?;
        enzimos_platform::json::fields(&manifest, "schema provider scope elfs")?;
        require(
            manifest["schema"].as_u64() == Some(1)
                && manifest["provider"] == "krdp-protected-sharing-v1"
                && manifest["scope"] == "protected-session-sharing",
            "desktop-rdp-installed-admission-required",
        )?;
        let hashes = manifest["elfs"]
            .as_object()
            .ok_or_else(|| Error("desktop-rdp-installed-inventory".into()))?;
        require(
            hashes.len() == ELFS.len() && ELFS.iter().all(|name| hashes.contains_key(*name)),
            "desktop-rdp-installed-inventory",
        )?;
        let mut members = vec![original];
        for name in ELFS {
            let member = open_installed(&Path::new(PREFIX).join(name), 8 * 1024 * 1024)?;
            let mut bytes = Vec::new();
            (&member.1)
                .take(8 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            require(
                bytes.starts_with(b"\x7fELF")
                    && hashes[name] == format!("{:x}", Sha256::digest(&bytes)),
                "desktop-rdp-installed-bytes-changed",
            )?;
            members.push(member);
        }
        let installed = Self {
            members,
            manifest_sha256: format!("{:x}", Sha256::digest(&bytes)),
        };
        installed.recheck()?;
        Ok(installed)
    }
    /// JSON proof of the reviewed provider.
    pub fn proof(&self) -> Value {
        serde_json::json!({"name":"krdp-protected-sharing-v1", "manifest_sha256":self.manifest_sha256})
    }
    /// Require that `proof` names this provider.
    ///
    /// # Errors
    ///
    /// Fails when the provider changed.
    pub fn matches(&self, proof: &Value) -> Result<()> {
        self.recheck()?;
        require(
            self.proof() == *proof,
            "desktop-rdp-reviewed-provider-changed",
        )
    }
    /// The provider executable, refusing file capabilities.
    ///
    /// # Errors
    ///
    /// Fails when the executable is not executable, has capabilities, or changed.
    #[allow(unsafe_code, reason = "Linux syscall ABI (fgetxattr).")]
    pub fn executable(&self) -> Result<File> {
        self.recheck()?;
        let (_, file, meta) = &self.members[1];
        require(meta.mode() & 0o111 != 0, "desktop-rdp-installed-executable")?;
        // SAFETY: A null buffer with size 0 only queries the attribute size, and `file` stays open.
        let capabilities = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                c"security.capability".as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };
        require(
            capabilities == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
            "desktop-rdp-installed-capabilities-refused",
        )?;
        Ok(file.try_clone()?)
    }
    /// Verify the installed files are unchanged.
    ///
    /// # Errors
    ///
    /// Fails when a file was replaced.
    pub fn recheck(&self) -> Result<()> {
        for (path, file, original) in &self.members {
            let (_, named, meta) = open_installed(path, 8 * 1024 * 1024)?;
            require(
                epoch(original) == epoch(&file.metadata()?)
                    && epoch(original) == epoch(&meta)
                    && epoch(original) == epoch(&named.metadata()?),
                "desktop-rdp-installed-file-replaced",
            )?;
        }
        Ok(())
    }
}

/// Execute the retained ELF using preallocated strings; safe for a forked child.
///
/// # Errors
///
/// Fails when the argument or environment list is too long, or execveat fails.
#[allow(unsafe_code, reason = "Linux syscall ABI (execveat).")]
pub fn exec_original(
    file: &File,
    argv: &[std::ffi::CString],
    environment: &[std::ffi::CString],
) -> std::io::Result<()> {
    let mut args = [std::ptr::null_mut(); 17];
    let mut env = [std::ptr::null_mut(); 16];
    if argv.is_empty() || argv.len() >= args.len() || environment.len() >= env.len() {
        return Err(std::io::Error::from_raw_os_error(libc::E2BIG));
    }
    for (slot, value) in args.iter_mut().zip(argv) {
        *slot = value.as_ptr().cast_mut();
    }
    for (slot, value) in env.iter_mut().zip(environment) {
        *slot = value.as_ptr().cast_mut();
    }
    // SAFETY: `args` and `env` are null-terminated arrays of pointers into CStrings that outlive
    // the call.
    unsafe {
        libc::execveat(
            file.as_raw_fd(),
            c"".as_ptr(),
            args.as_ptr(),
            env.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
    Err(std::io::Error::last_os_error())
}
