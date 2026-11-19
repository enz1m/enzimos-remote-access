// SPDX-License-Identifier: MIT
//! Bounded client observations from the retained WayVNC process, never TCP counts.
use enzimos_platform::{
    Error, Result, files, json,
    process_identity::{self, Retained},
    require,
};
use serde_json::{Value, json as value};
use std::{collections::BTreeSet, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

const LIMIT: usize = 65536;

fn capture(pid: u32, uid: u32) -> Result<Retained> {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let read = |name: &str, limit| -> Result<String> {
        String::from_utf8(files::read_kernel_owned(&root.join(name), limit, uid)?)
            .map_err(|_| Error("desktop-viewers-unavailable".into()))
    };
    let stat = process_identity::parse_stat(&read("stat", 8192)?, pid)?;
    let retained = Retained::open(
        pid,
        stat.start_ticks,
        uid,
        &[PathBuf::from("/usr/bin/wayvnc")],
    )?;
    let group = format!("0::/system.slice/enzimos-desktop-sharing@{uid}.service");
    require(
        process_identity::parse_uids(&read("status", 65536)?)? == [uid; 4]
            && read("cgroup", 8192)?
                .lines()
                .filter(|s| s.starts_with("0::"))
                .eq([group.as_str()]),
        "desktop-capture-process-untrusted",
    )?;
    Ok(retained)
}

/// Validate the WayVNC 0.10 client-list reply before exposing display-only data.
///
/// # Errors
/// Refuses malformed, excessive or ambiguous client identities.
pub fn clients(reply: &Value) -> Result<Value> {
    require(
        reply["id"].as_u64() == Some(1) && reply["code"].as_u64() == Some(0),
        "desktop-viewers-unavailable",
    )?;
    let rows = reply["data"]
        .as_array()
        .ok_or_else(|| Error("desktop-viewers-unavailable".into()))?;
    require(rows.len() <= 64, "desktop-viewers-bound")?;
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for row in rows {
        let id = row["id"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(|| Error("desktop-viewers-unavailable".into()))?;
        require(seen.insert(id), "desktop-viewers-unavailable")?;
        let text = |field: &str, limit: usize| -> Result<Value> {
            match row.get(field) {
                None | Some(Value::Null) => Ok(Value::Null),
                Some(Value::String(s)) if s.len() <= limit && !s.chars().any(char::is_control) => {
                    Ok(value!(s))
                }
                _ => Err(Error("desktop-viewers-unavailable".into())),
            }
        };
        result.push(
            value!({"id":id,"address":text("address", 256)?,"username":text("username", 256)?}),
        );
    }
    Ok(value!({"status":"available","connected_count":result.len(),"clients":result}))
}

async fn exchange(uid: u32, pid: u32, path: &std::path::Path) -> Result<Value> {
    let retained = capture(pid, uid)?;
    let mut socket = UnixStream::connect(path).await?;
    let peer = socket.peer_cred()?;
    require(
        peer.uid() == uid && peer.pid() == Some(pid as i32),
        "desktop-viewer-peer-untrusted",
    )?;
    retained.recheck()?;
    socket
        .write_all(b"{\"method\":\"client-list\",\"id\":1}\n")
        .await?;
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        let n = socket.read(&mut buffer).await?;
        require(n > 0 && bytes.len() + n <= LIMIT, "desktop-viewers-bound")?;
        bytes.extend_from_slice(&buffer[..n]);
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(_) => {
                let result = clients(&json::decode(&bytes, LIMIT)?)?;
                retained.recheck()?;
                return Ok(result);
            }
            Err(e) if e.is_eof() => {}
            Err(_) => return Err(Error("desktop-viewers-unavailable".into())),
        }
    }
}

pub(crate) async fn observe(uid: u32, leader: u32, grant: &Value) -> Result<Value> {
    let nonce = grant["nonce"]
        .as_str()
        .filter(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or_else(|| Error("desktop-grant-invalid".into()))?;
    let path = PathBuf::from(format!(
        "/run/user/{uid}/enzimos-sharing/{}/control.sock",
        &nonce[..16]
    ));
    // A replaced owner-writable pathname is insufficient: SO_PEERCRED must match
    // the pinned installed capture task in the approved system-service cgroup.
    let run = async {
        for pid in crate::desktop_binding::descendants(leader, uid)? {
            if let Ok(result) = exchange(uid, pid, &path).await {
                return Ok(result);
            }
        }
        Err(Error("desktop-viewers-unavailable".into()))
    };
    tokio::time::timeout(Duration::from_secs(1), run)
        .await
        .map_err(|_| Error("desktop-viewers-unavailable".into()))?
}
