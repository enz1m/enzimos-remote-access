// SPDX-License-Identifier: MIT
//! A run-only Root grant binds a boot, account, compositor and network approval.
use crate::{config, firewall_bus::Firewall, network};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub fn account(uid: u32) -> Result<u32> {
    require((1000..u32::MAX).contains(&uid), "desktop-account-invalid")?;
    Ok(uid)
}
pub fn folder(uid: u32) -> Result<PathBuf> {
    Ok(Path::new("/run/enzimos-remote/sharing").join(account(uid)?.to_string()))
}
fn text(v: &Value, extra: &[u8]) -> bool {
    v.as_str().is_some_and(|s| {
        (1..=64).contains(&s.len())
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
    })
}
fn positive(v: &Value) -> Result<u64> {
    let n = v
        .as_u64()
        .ok_or_else(|| Error("desktop-session-proof-invalid".into()))?;
    require(n > 0, "desktop-session-proof-invalid")?;
    Ok(n)
}
pub fn session(bound: &Value, uid: u32) -> Result<()> {
    json::fields(bound, "uid id leader seat compositor wayland manager_owned")?;
    require(
        bound["uid"].as_u64() == Some(account(uid)? as u64)
            && bound["manager_owned"].is_boolean()
            && text(&bound["id"], b"_-")
            && text(&bound["seat"], b"_-"),
        "desktop-session-proof-invalid",
    )?;
    let proof = &bound["compositor"];
    let wayland = &bound["wayland"];
    json::fields(proof, "pid start_ticks device inode mount_namespace")?;
    json::fields(wayland, "path device inode")?;
    for v in [
        &bound["leader"],
        &proof["pid"],
        &proof["start_ticks"],
        &proof["device"],
        &proof["inode"],
        &wayland["device"],
        &wayland["inode"],
    ] {
        positive(v)?;
    }
    require(
        positive(&bound["leader"])? < 1 << 31 && positive(&proof["pid"])? < 1 << 31,
        "desktop-session-proof-invalid",
    )?;
    let ns = proof["mount_namespace"]
        .as_array()
        .ok_or_else(|| Error("desktop-session-proof-invalid".into()))?;
    require(ns.len() == 2, "desktop-session-proof-invalid")?;
    for n in ns {
        positive(n)?;
    }
    let prefix = format!("/run/user/{uid}/wayland-");
    require(
        wayland["path"]
            .as_str()
            .and_then(|s| s.strip_prefix(&prefix))
            .is_some_and(|s| (1..=3).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_digit())),
        "desktop-session-proof-invalid",
    )
}
pub fn validate(
    value: &Value,
    uid: u32,
    boot: &str,
    addresses: &BTreeSet<IpAddr>,
) -> Result<Value> {
    let rdp = crate::desktop_rdp::selected(&value["configuration"]);
    json::fields(
        value,
        if rdp {
            "schema boot_id uid nonce session configuration interface zone provider"
        } else {
            "schema boot_id uid nonce session configuration interface zone"
        },
    )?;
    if rdp {
        json::fields(&value["provider"], "name manifest_sha256")?;
        require(
            value["provider"]["name"] == "krdp-protected-sharing-v1"
                && value["provider"]["manifest_sha256"]
                    .as_str()
                    .is_some_and(|s| {
                        s.len() == 64
                            && s.bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    }),
            "desktop-rdp-provider-proof-invalid",
        )?;
    }
    require(value["schema"].as_u64() == Some(1), "desktop-grant-invalid")?;
    require(
        value["uid"].as_u64() == Some(account(uid)? as u64)
            && value["boot_id"].as_str() == Some(boot)
            && value["nonce"].as_str().is_some_and(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            }),
        "desktop-grant-stale-or-foreign",
    )?;
    require(
        text(&value["interface"], b"_.:-") && text(&value["zone"], b"_.:-"),
        "desktop-network-proof-invalid",
    )?;
    session(&value["session"], uid)?;
    let checked = config::desktop(&value["configuration"], addresses)?;
    require(
        checked["enabled"] == true && checked["mode"] == "session-sharing",
        "desktop-sharing-grant-required",
    )?;
    let mut result = value.clone();
    result["configuration"] = checked;
    Ok(result)
}
pub fn load(uid: u32) -> Result<Value> {
    let path = folder(uid)?.join("grant.json");
    let parent = files::directory(path.parent().unwrap(), Some(0))?;
    let mut file = files::open_relative(&parent, Path::new("grant.json"))?;
    let m = file.metadata()?;
    require(
        m.uid() == 0 && m.mode() & 0o7777 == 0o600 && m.nlink() == 1 && m.len() <= 65536,
        "desktop-grant-permissions",
    )?;
    let mut data = Vec::new();
    use std::io::Read;
    (&mut file).take(65537).read_to_end(&mut data)?;
    let after = file.metadata()?;
    require(
        data.len() as u64 == m.len()
            && (
                m.dev(),
                m.ino(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            ) == (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec(),
            ),
        "desktop-grant-changed",
    )?;
    json::decode(&data, 65536)
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (fstatat, geteuid, unlinkat)."
)]
pub fn revoke(uid: u32) -> Result<()> {
    require(unsafe { libc::geteuid() } == 0, "Root authority required")?;
    let directory = folder(uid)?;
    let held = files::directory(&directory, Some(0))?;
    if files::read_optional(&directory.join("grant.json"), 65536, Some(0), true)?.is_none() {
        return Ok(());
    }
    let file = files::open_relative(&held, Path::new("grant.json"))?;
    let m = file.metadata()?;
    require(
        m.uid() == 0 && m.mode() & 0o7777 == 0o600 && m.nlink() == 1,
        "desktop-grant-permissions",
    )?;
    use std::os::fd::AsRawFd;
    let mut named: libc::stat = unsafe { std::mem::zeroed() };
    let name = c"grant.json";
    require(
        unsafe {
            libc::fstatat(
                held.as_raw_fd(),
                name.as_ptr(),
                &mut named,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
            && named.st_dev == m.dev()
            && named.st_ino == m.ino(),
        "desktop-grant-changed",
    )?;
    require(
        unsafe { libc::unlinkat(held.as_raw_fd(), name.as_ptr(), 0) } == 0,
        "desktop-grant-revocation-uncertain",
    )?;
    held.sync_all()?;
    Ok(())
}
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
pub fn publish(value: &Value, uid: u32, boot: &str, addresses: &BTreeSet<IpAddr>) -> Result<()> {
    require(unsafe { libc::geteuid() } == 0, "Root authority required")?;
    let checked = validate(value, uid, boot, addresses)?;
    require(checked == *value, "desktop-grant-noncanonical")?;
    let directory = folder(uid)?;
    files::ensure_directory(&directory, 0o700, 0)?;
    files::atomic(
        &directory.join("grant.json"),
        &json::canonical(&checked)?,
        0o600,
        Some(0),
        true,
    )
}
/// Returns the interface that still carries the grant's listen address.
///
/// # Errors
/// Fails with `desktop-approved-network-changed` when the address moved or vanished.
pub fn approved_interface(grant: &Value, interfaces: &BTreeMap<IpAddr, String>) -> Result<String> {
    let ip: IpAddr = grant["configuration"]["listen_address"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error("desktop-approved-network-changed".into()))?;
    let interface = interfaces
        .get(&ip)
        .ok_or_else(|| Error("desktop-approved-network-changed".into()))?;
    require(
        grant["interface"] == *interface,
        "desktop-approved-network-changed",
    )?;
    Ok(interface.clone())
}
/// Refuses a firewall zone other than the reviewed one.
///
/// `zone` is `None` while firewalld is not running, which leaves nothing to compare.
///
/// # Errors
/// Fails with `desktop-approved-network-changed` for a different zone.
pub fn approved_zone(grant: &Value, zone: Option<&str>) -> Result<()> {
    require(
        zone.is_none_or(|zone| grant["zone"] == zone),
        "desktop-approved-network-changed",
    )
}
/// Confirms the grant's reviewed interface, and its zone while firewalld runs.
///
/// # Errors
/// Fails when the network changed or cannot be observed.
pub async fn verify_network(grant: &Value, firewall: &Firewall) -> Result<()> {
    let interfaces = tokio::task::spawn_blocking(network::interfaces)
        .await
        .map_err(|_| Error("desktop-network-observation-unavailable".into()))??;
    let interface = approved_interface(grant, &interfaces)?;
    let zone = if firewall.running().await? {
        Some(firewall.zone_for(&interface).await?)
    } else {
        None
    };
    approved_zone(grant, zone.as_deref())
}
