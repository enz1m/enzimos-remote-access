// SPDX-License-Identifier: MIT
//! Logind supplies live authority; caller paths never select a compositor.
use crate::{bus_adapter::Pinned, desktop_binding, desktop_grant};
use enzimos_platform::{
    Error, Result, accounts, files,
    process_identity::{self, Retained},
    require,
};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
};
use zbus::{
    Connection,
    zvariant::{OwnedObjectPath, OwnedValue},
};
pub type Properties = HashMap<String, OwnedValue>;
fn field<T: TryFrom<OwnedValue>>(p: &Properties, key: &str) -> Result<T> {
    require(p.len() <= 512, "desktop-session-property-bound")?;
    T::try_from(
        p.get(key)
            .ok_or_else(|| Error("desktop-session-property-missing".into()))?
            .try_clone()
            .map_err(|_| Error("desktop-session-property-type".into()))?,
    )
    .map_err(|_| Error("desktop-session-property-type".into()))
}
fn identifier(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}
fn identity(p: &Properties, uid: u32, id: &str) -> Result<Value> {
    desktop_grant::account(uid)?;
    let user: (u32, OwnedObjectPath) = field(p, "User")?;
    let seat: (String, OwnedObjectPath) = field(p, "Seat")?;
    let leader: u32 = field(p, "Leader")?;
    require(
        identifier(id)
            && field::<String>(p, "Id")? == id
            && user.0 == uid
            && user.1.as_str().starts_with("/org/freedesktop/login1/user/")
            && identifier(&seat.0)
            && seat.1.as_str().starts_with("/org/freedesktop/login1/seat/")
            && leader > 0
            && leader < 1 << 31
            && field::<String>(p, "Type")? == "wayland"
            && field::<String>(p, "Class")? == "user",
        "desktop-local-unlocked-session-required",
    )?;
    require(
        !field::<bool>(p, "Remote")?,
        "desktop-local-unlocked-session-required",
    )?;
    Ok(value!({"uid":uid,"id":id,"leader":leader,"seat":seat.0}))
}
pub fn session(p: &Properties, uid: u32, id: &str) -> Result<Value> {
    let observed = identity(p, uid, id)?;
    for (key, expected) in [("Active", true), ("LockedHint", false)] {
        require(
            field::<bool>(p, key)? == expected,
            "desktop-local-unlocked-session-required",
        )?;
    }
    Ok(observed)
}
/// Classify a completed revocation; this never grants permission to capture.
pub fn locked(p: &Properties, bound: &Value) -> Result<bool> {
    let uid = bound["uid"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| Error("desktop-session-proof-invalid".into()))?;
    desktop_grant::session(bound, uid)?;
    let observed = identity(p, uid, bound["id"].as_str().unwrap())?;
    for key in ["uid", "id", "leader", "seat"] {
        require(observed[key] == bound[key], "desktop-session-changed")?;
    }
    let _: bool = field(p, "Active")?;
    field(p, "LockedHint")
}
#[derive(Clone)]
pub struct Session {
    login: Pinned,
    system: Pinned,
}
impl Session {
    pub fn login_owner(&self) -> &str {
        self.login.owner()
    }
    pub async fn session_path(&self, id: &str) -> Result<OwnedObjectPath> {
        require(identifier(id), "desktop-session-proof-invalid")?;
        let path: OwnedObjectPath = self
            .login
            .call(
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "GetSession",
                &(id,),
            )
            .await?;
        require(
            path.as_str()
                .starts_with("/org/freedesktop/login1/session/")
                && path.as_str().len() <= 512,
            "desktop-session-path-invalid",
        )?;
        Ok(path)
    }
    pub async fn new(connection: Connection) -> Result<Self> {
        Ok(Self {
            login: Pinned::new(connection.clone(), "org.freedesktop.login1").await?,
            system: Pinned::new(connection, "org.freedesktop.systemd1").await?,
        })
    }
    pub async fn recheck_owners(&self) -> Result<()> {
        self.login.recheck().await?;
        self.system.recheck().await
    }
    pub async fn locked(&self, bound: &Value) -> Result<bool> {
        self.recheck_owners().await?;
        let id = bound["id"]
            .as_str()
            .ok_or_else(|| Error("desktop-session-proof-invalid".into()))?;
        let path = self.session_path(id).await?;
        let properties =
            Self::properties(&self.login, path.as_str(), "org.freedesktop.login1.Session").await?;
        let result = locked(&properties, bound)?;
        self.recheck_owners().await?;
        Ok(result)
    }
    /// The compositor may revoke capture before its asynchronous logind update.
    /// Called only after the capture child has been reaped, never during capture.
    pub async fn locked_after_capture_stop(&self, bound: &Value) -> Result<bool> {
        // The acknowledged lock publisher allows three seconds for its logind call.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if self.locked(bound).await? {
                return Ok(true);
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
    async fn properties(bus: &Pinned, path: &str, interface: &str) -> Result<Properties> {
        bus.call(
            path,
            "org.freedesktop.DBus.Properties",
            "GetAll",
            &(interface,),
        )
        .await
    }
    pub async fn values(&self, uid: u32, id: &str) -> Result<Value> {
        require(identifier(id), "desktop-session-proof-invalid")?;
        let path: OwnedObjectPath = self
            .login
            .call(
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "GetSession",
                &(id,),
            )
            .await?;
        require(
            path.as_str()
                .starts_with("/org/freedesktop/login1/session/")
                && path.as_str().len() <= 512,
            "desktop-session-path-invalid",
        )?;
        session(
            &Self::properties(&self.login, path.as_str(), "org.freedesktop.login1.Session").await?,
            uid,
            id,
        )
    }
    /// Returns the account's current display session, if it is signed in.
    ///
    /// # Errors
    /// Fails when logind's owner changes or its reply is malformed.
    pub async fn display(&self, uid: u32) -> Result<Option<String>> {
        desktop_grant::account(uid)?;
        let path: OwnedObjectPath = match self
            .login
            .call(
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "GetUser",
                &(uid,),
            )
            .await
        {
            Ok(path) => path,
            Err(_) => {
                self.recheck_owners().await?;
                return Ok(None);
            }
        };
        require(
            path.as_str().starts_with("/org/freedesktop/login1/user/")
                && path.as_str().len() <= 512,
            "desktop-user-manager-unavailable",
        )?;
        let user =
            Self::properties(&self.login, path.as_str(), "org.freedesktop.login1.User").await?;
        let display: (String, OwnedObjectPath) = field(&user, "Display")?;
        require(
            field::<u32>(&user, "UID")? == uid && (display.0.is_empty() || identifier(&display.0)),
            "desktop-session-proof-invalid",
        )?;
        Ok((!display.0.is_empty()).then_some(display.0))
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    pub async fn manager_pid(&self, uid: u32, id: &str) -> Result<u32> {
        require(
            unsafe { libc::geteuid() } == 0,
            "Root desktop discovery required",
        )?;
        desktop_grant::account(uid)?;
        require(identifier(id), "desktop-session-proof-invalid")?;
        let account = accounts::lookup_uid(uid)?;
        let path: OwnedObjectPath = self
            .login
            .call(
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "GetUser",
                &(uid,),
            )
            .await?;
        require(
            path.as_str().starts_with("/org/freedesktop/login1/user/")
                && path.as_str().len() <= 512,
            "desktop-user-manager-unavailable",
        )?;
        let user =
            Self::properties(&self.login, path.as_str(), "org.freedesktop.login1.User").await?;
        let unit = format!("user@{uid}.service");
        let display: (String, OwnedObjectPath) = field(&user, "Display")?;
        require(
            field::<u32>(&user, "UID")? == uid
                && field::<String>(&user, "Service")? == unit
                && field::<String>(&user, "RuntimePath")? == format!("/run/user/{uid}")
                && display.0 == id,
            "desktop-user-manager-unavailable",
        )?;
        let path: OwnedObjectPath = self
            .system
            .call(
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "GetUnit",
                &(unit.as_str(),),
            )
            .await?;
        require(
            path.as_str().starts_with("/org/freedesktop/systemd1/unit/")
                && path.as_str().len() <= 512,
            "desktop-user-manager-unavailable",
        )?;
        let properties =
            Self::properties(&self.system, path.as_str(), "org.freedesktop.systemd1.Unit").await?;
        let service = Self::properties(
            &self.system,
            path.as_str(),
            "org.freedesktop.systemd1.Service",
        )
        .await?;
        require(
            field::<String>(&properties, "Id")? == unit
                && field::<String>(&properties, "ActiveState")? == "active"
                && !field::<bool>(&properties, "Transient")?,
            "desktop-user-manager-unavailable",
        )?;
        let fragment = field::<String>(&properties, "FragmentPath")?;
        require(
            matches!(
                fragment.as_str(),
                "/usr/lib/systemd/system/user@.service" | "/etc/systemd/system/user@.service"
            ),
            "desktop-user-manager-untrusted",
        )?;
        files::read(Path::new(&fragment), 1024 * 1024, Some(0), false)?;
        let drops: Vec<String> = field(&properties, "DropInPaths")?;
        require(drops.len() <= 16, "desktop-user-manager-untrusted")?;
        for drop in drops {
            let p = Path::new(&drop);
            require(
                p.starts_with("/usr/lib/systemd/system") || p.starts_with("/etc/systemd/system"),
                "desktop-user-manager-untrusted",
            )?;
            files::read(p, 1024 * 1024, Some(0), false)?;
        }
        let user = field::<String>(&service, "User")?;
        require(
            user == uid.to_string() || user == account.name,
            "desktop-user-manager-unavailable",
        )?;
        let pid: u32 = field(&service, "MainPID")?;
        require(pid > 0 && pid < 1 << 31, "desktop-user-manager-unavailable")?;
        let root = PathBuf::from(format!("/proc/{pid}"));
        let read = |name: &str, limit| -> Result<String> {
            String::from_utf8(files::read_kernel_owned(&root.join(name), limit, uid)?)
                .map_err(|_| Error("desktop-user-manager-untrusted".into()))
        };
        let stat = process_identity::parse_stat(&read("stat", 8192)?, pid)?;
        let retained = Retained::open(
            pid,
            stat.start_ticks,
            uid,
            &[PathBuf::from("/usr/lib/systemd/systemd")],
        )?;
        let group = format!("/user.slice/user-{uid}.slice/user@{uid}.service");
        require(
            field::<String>(&service, "ControlGroup")? == group
                && process_identity::parse_uids(&read("status", 65536)?)? == [uid; 4]
                && read("cgroup", 8192)?
                    .lines()
                    .any(|s| s == format!("0::{group}") || s == format!("0::{group}/init.scope")),
            "desktop-user-manager-untrusted",
        )?;
        retained.recheck()?;
        self.recheck_owners().await?;
        Ok(pid)
    }
    pub async fn verify_granted(&self, bound: &Value) -> Result<Retained> {
        let uid = bound["uid"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| Error("desktop-session-proof-invalid".into()))?;
        desktop_grant::session(bound, uid)?;
        let observed = self.values(uid, bound["id"].as_str().unwrap()).await?;
        for key in ["uid", "id", "leader", "seat"] {
            require(observed[key] == bound[key], "desktop-session-changed")?;
        }
        let copy = bound.clone();
        let retained = tokio::task::spawn_blocking(move || desktop_binding::verify(&copy))
            .await
            .map_err(|_| Error("desktop-session-observation-unavailable".into()))??;
        // A lock/logout event during process observation also refuses admission.
        require(
            self.values(uid, bound["id"].as_str().unwrap()).await? == observed,
            "desktop-session-changed",
        )?;
        Ok(retained)
    }
    pub async fn verify(&self, bound: &Value) -> Result<Retained> {
        let uid = bound["uid"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| Error("desktop-session-proof-invalid".into()))?;
        desktop_grant::session(bound, uid)?;
        self.manager_pid(uid, bound["id"].as_str().unwrap()).await?;
        self.verify_granted(bound).await
    }
    pub async fn discover(&self, uid: u32, id: &str) -> Result<Value> {
        let base = self.values(uid, id).await?;
        let manager = self.manager_pid(uid, id).await?;
        let leader = base["leader"].as_u64().unwrap() as u32;
        let identifier = id.to_owned();
        let mut bound = tokio::task::spawn_blocking(move || -> Result<Value> {
            let ns = desktop_binding::namespace(1, 0)?;
            let mut seen = BTreeSet::new();
            let mut matches = Vec::new();
            for root in [leader, manager] {
                for pid in desktop_binding::descendants(root, uid)? {
                    if !seen.insert(pid) {
                        continue;
                    }
                    require(seen.len() <= 512, "desktop-session-process-bound")?;
                    if let Ok(proof) = desktop_binding::process(pid, uid, &identifier, true, ns) {
                        matches.push(proof);
                    }
                }
            }
            require(matches.len() == 1, "desktop-owned-compositor-unavailable")?;
            let proof = matches.pop().unwrap();
            let runtime = PathBuf::from(format!("/run/user/{uid}"));
            let mut sockets = Vec::new();
            let mut count = 0;
            for entry in std::fs::read_dir(&runtime)? {
                let entry = entry?;
                let name = entry.file_name();
                let Some(suffix) = name.to_str().and_then(|s| s.strip_prefix("wayland-")) else {
                    continue;
                };
                if !(1..=3).contains(&suffix.len()) || !suffix.bytes().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                count += 1;
                require(count <= 16, "desktop-wayland-socket-bound")?;
                if let Ok(socket) = desktop_binding::socket_peer(
                    &entry.path(),
                    uid,
                    proof["pid"].as_u64().unwrap() as u32,
                ) {
                    sockets.push(socket);
                }
            }
            require(
                sockets.len() == 1,
                "desktop-owned-wayland-socket-unavailable",
            )?;
            Ok(value!({"compositor":proof,"wayland":sockets.pop().unwrap(),"manager_owned":true}))
        })
        .await
        .map_err(|_| Error("desktop-session-observation-unavailable".into()))??;
        for key in ["uid", "id", "leader", "seat"] {
            bound[key] = base[key].clone();
        }
        self.verify(&bound).await?;
        Ok(bound)
    }
}
