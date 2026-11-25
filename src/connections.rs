// SPDX-License-Identifier: MIT
//! Remember verified SSH descendants across PAM/logind cgroup moves.
use crate::sockets;
use enzimos_platform::{
    Error, Result, files, json,
    process_identity::{self, Retained},
    require,
};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::PathBuf,
};
const EXECUTABLES: [&str; 3] = [
    "/usr/bin/sshd",
    "/usr/lib/ssh/sshd-session",
    "/usr/lib/ssh/sshd-auth",
];
const CGROUP: &str = "0::/system.slice/enzimos-sshd.service";
fn field_u32(v: &Value, k: &str) -> Result<u32> {
    v[k].as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n > 0 && *n < i32::MAX as u32)
        .ok_or_else(|| Error("ssh-connection-journal-invalid".into()))
}
pub fn validate(v: &Value) -> Result<Vec<Value>> {
    json::fields(v, "schema boot_id uid processes")?;
    require(
        v["schema"].as_u64() == Some(1)
            && v["uid"]
                .as_u64()
                .is_some_and(|u| (1000..u64::from(u32::MAX)).contains(&u))
            && v["boot_id"].as_str().is_some_and(|s| {
                s.len() == 36
                    && s.bytes().enumerate().all(|(i, b)| {
                        if [8, 13, 18, 23].contains(&i) {
                            b == b'-'
                        } else {
                            b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                        }
                    })
            }),
        "ssh-connection-journal-invalid",
    )?;
    let rows = v["processes"]
        .as_array()
        .filter(|r| r.len() <= 512)
        .ok_or_else(|| Error("ssh-connection-journal-invalid".into()))?;
    let mut seen = BTreeSet::new();
    for row in rows {
        let mut required = row.clone();
        if let Some(fields) = required.as_object_mut() {
            fields.remove("addresses");
        }
        json::fields(&required, "pid start_ticks address port")?;
        crate::config::listen_addresses(&row["address"], row.get("addresses"))?;
        require(
            seen.insert(field_u32(row, "pid")?)
                && row["start_ticks"].as_u64().is_some_and(|n| n > 0)
                && row["port"]
                    .as_u64()
                    .is_some_and(|n| (1..=65535).contains(&n))
                && row["address"]
                    .as_str()
                    .is_some_and(|s| s.len() <= 64 && s.parse::<IpAddr>().is_ok()),
            "ssh-connection-journal-invalid",
        )?;
    }
    Ok(rows.clone())
}
fn read(pid: u32, uid: u32, name: &str, bound: usize) -> Result<String> {
    String::from_utf8(files::read_kernel_owned(
        &PathBuf::from(format!("/proc/{pid}/{name}")),
        bound,
        uid,
    )?)
    .map_err(|_| Error("ssh-process-observation-encoding".into()))
}
fn retained(pid: u32, uid: u32) -> Result<Retained> {
    let stat = process_identity::parse_stat(&read(pid, uid, "stat", 8192)?, pid)?;
    Retained::open(
        pid,
        stat.start_ticks,
        uid,
        &EXECUTABLES.iter().map(PathBuf::from).collect::<Vec<_>>(),
    )
}
pub fn listener(main: u32, uid: u32, address: IpAddr, port: u16) -> Result<bool> {
    let process = retained(main, uid)?;
    require(
        read(main, uid, "cgroup", 65536)?
            .lines()
            .filter(|s| s.starts_with("0::"))
            .eq([CGROUP]),
        "ssh-listener-cgroup-mismatch",
    )?;
    let table = sockets::table()?;
    let owned = sockets::inodes(main, uid)?;
    process.recheck()?;
    Ok(sockets::listening(&table, &owned, address, port))
}
pub fn descendants(main: u32, uid: u32) -> Result<Vec<Value>> {
    if main == 0 {
        return Ok(Vec::new());
    }
    let origin = retained(main, uid)?;
    require(
        read(main, uid, "cgroup", 65536)?
            .lines()
            .filter(|s| s.starts_with("0::"))
            .eq([CGROUP]),
        "ssh-listener-cgroup-mismatch",
    )?;
    let mut queue = vec![main];
    let mut found = Vec::new();
    let mut seen = BTreeSet::from([main]);
    while let Some(parent) = queue.pop() {
        let children = match read(parent, uid, &format!("task/{parent}/children"), 8192) {
            Ok(body) => body,
            Err(_)
                if std::fs::symlink_metadata(format!("/proc/{parent}"))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        for p in children.split_whitespace() {
            let pid = p
                .parse::<u32>()
                .map_err(|_| Error("ssh-descendant-pid".into()))?;
            if !seen.insert(pid) {
                continue;
            }
            require(seen.len() <= 512, "ssh-descendant-bound")?;
            let Ok(child) = retained(pid, uid) else {
                continue;
            };
            if child.stat.parent != parent {
                continue;
            }
            child.recheck()?;
            found.push(value!({"pid":pid,"start_ticks":child.stat.start_ticks}));
            queue.push(pid);
        }
    }
    origin.recheck()?;
    Ok(found)
}
pub struct Tracker {
    pub directory: PathBuf,
    pub uid: u32,
    pub owner: u32,
    pub boot_id: String,
    pub addresses: Vec<IpAddr>,
    pub port: u16,
}
impl Tracker {
    fn path(&self) -> PathBuf {
        self.directory.join("connections.json")
    }
    pub fn load(&self) -> Result<Vec<Value>> {
        let Some(body) = files::read_optional(&self.path(), 131072, Some(self.owner), true)? else {
            return Ok(Vec::new());
        };
        let value = json::decode(&body, 131072)?;
        let rows = validate(&value)?;
        if value["boot_id"] == self.boot_id && value["uid"].as_u64() == Some(u64::from(self.uid)) {
            Ok(rows)
        } else {
            Ok(Vec::new())
        }
    }
    fn save(&self, rows: &[Value]) -> Result<()> {
        let value = value!({"schema":1,"boot_id":self.boot_id,"uid":self.uid,"processes":rows});
        validate(&value)?;
        files::atomic(
            &self.path(),
            &json::canonical(&value)?,
            0o600,
            Some(self.owner),
            true,
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    pub fn query(&self, main: u32) -> Result<Vec<Value>> {
        require(
            self.owner == 0
                // SAFETY: geteuid has no preconditions and cannot fail.
                && unsafe { libc::geteuid() } == 0
                && (1000..u32::MAX).contains(&self.uid)
                && self.port > 0
                && (1..=8).contains(&self.addresses.len()),
            "ssh-tracker-root-account-required",
        )?;
        let previous = self.load()?;
        let mut leases = BTreeMap::new();
        for row in &previous {
            leases.insert(field_u32(row, "pid")?, row.clone());
        }
        for mut row in descendants(main, self.uid)? {
            row["address"] = value!(self.addresses[0].to_string());
            if self.addresses.len() > 1 {
                row["addresses"] = value!(
                    self.addresses
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                );
            }
            row["port"] = value!(self.port);
            leases.insert(field_u32(&row, "pid")?, row);
        }
        require(leases.len() <= 512, "ssh-connection-journal-bound")?;
        let table = sockets::table()?;
        let mut current = Vec::new();
        let mut found: BTreeMap<u64, Value> = BTreeMap::new();
        for (pid, row) in leases {
            let Ok(process) = retained(pid, self.uid) else {
                continue;
            };
            if row["start_ticks"].as_u64() != Some(process.stat.start_ticks) {
                continue;
            }
            let inodes = match sockets::inodes(pid, self.uid) {
                Ok(rows) => rows,
                Err(_) if process.exited()? => continue,
                Err(error) => return Err(error),
            };
            if process.exited()? {
                continue;
            }
            process.recheck()?;
            for inode in inodes {
                let Some(socket) = table.get(&inode) else {
                    continue;
                };
                if socket.state != "01"
                    || !crate::config::listen_addresses(&row["address"], row.get("addresses"))?
                        .contains(&socket.address)
                    || row["port"].as_u64() != Some(u64::from(socket.port))
                {
                    continue;
                }
                let item=found.entry(inode).or_insert_with(||value!({"socket_inode":inode,"remote_address":socket.remote_address.to_string(),"remote_port":socket.remote_port,"processes":[]}));
                item["processes"]
                    .as_array_mut()
                    .ok_or_else(|| Error("unexpected JSON value type".into()))?
                    .push(value!({"pid":pid,"start_ticks":process.stat.start_ticks}));
            }
            current.push(row);
        }
        if current != previous {
            self.save(&current)?;
        }
        Ok(found.into_values().collect())
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    pub fn disconnect<F: FnMut() -> Result<()>>(
        &self,
        rows: &[Value],
        mut before_commit: F,
    ) -> Result<()> {
        require(
            // SAFETY: geteuid has no preconditions and cannot fail.
            self.owner == 0 && unsafe { libc::geteuid() } == 0 && rows.len() <= 512,
            "ssh-disconnect-root-required",
        )?;
        let leases = self
            .load()?
            .into_iter()
            .map(|r| Ok((field_u32(&r, "pid")?, r)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mut identities = BTreeMap::new();
        for connection in rows {
            json::fields(
                connection,
                "socket_inode remote_address remote_port processes",
            )?;
            let processes = connection["processes"]
                .as_array()
                .filter(|r| r.len() <= 512)
                .ok_or_else(|| Error("ssh-disconnect-process-bound".into()))?;
            for row in processes {
                json::fields(row, "pid start_ticks")?;
                let pid = field_u32(row, "pid")?;
                let start = row["start_ticks"]
                    .as_u64()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| Error("ssh-session-not-owned".into()))?;
                require(
                    leases
                        .get(&pid)
                        .is_some_and(|r| r["start_ticks"].as_u64() == Some(start)),
                    "ssh-session-not-owned",
                )?;
                if let Some(previous) = identities.insert(pid, start) {
                    require(previous == start, "ssh-session-identity-conflict")?;
                }
            }
        }
        require(identities.len() <= 512, "ssh-disconnect-process-bound")?;
        let mut held = Vec::new();
        for (pid, start) in identities {
            held.push(Retained::open(
                pid,
                start,
                self.uid,
                &EXECUTABLES.iter().map(PathBuf::from).collect::<Vec<_>>(),
            )?);
        }
        before_commit()?;
        for process in &held {
            process.recheck()?;
        }
        for process in held {
            process.terminate(&mut before_commit)?;
        }
        Ok(())
    }
}
