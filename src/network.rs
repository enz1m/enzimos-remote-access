// SPDX-License-Identifier: MIT
use crate::{bus_adapter::Pinned, firewall_bus::Firewall};
use enzimos_platform::{Error, Result, json, process, require};
use serde_json::{Value, json as value};
use std::{collections::BTreeMap, net::IpAddr, time::Duration};
use zbus::{
    Connection,
    zvariant::{OwnedObjectPath, OwnedValue},
};
pub fn parse_interfaces(body: &[u8]) -> Result<BTreeMap<IpAddr, String>> {
    let v = json::decode(body, 131072)?;
    let rows = v
        .as_array()
        .ok_or_else(|| Error("local-interface-bound".into()))?;
    require(rows.len() <= 256, "local-interface-bound")?;
    let mut found = BTreeMap::new();
    for row in rows {
        let flags = row["flags"]
            .as_array()
            .ok_or_else(|| Error("local-interface-fields".into()))?;
        if !flags.iter().any(|v| v == "UP") {
            continue;
        }
        let interface = row["ifname"]
            .as_str()
            .ok_or_else(|| Error("local-interface-fields".into()))?;
        require(
            !interface.is_empty()
                && interface.len() <= 64
                && !interface.starts_with('-')
                && !interface.chars().any(char::is_control),
            "local-interface-fields",
        )?;
        let addresses = row["addr_info"]
            .as_array()
            .ok_or_else(|| Error("local-interface-fields".into()))?;
        require(addresses.len() <= 256, "local-address-bound")?;
        for a in addresses {
            let Some(ip) = a["local"].as_str().and_then(|s| s.parse::<IpAddr>().ok()) else {
                continue;
            };
            // A tentative address cannot be bound until duplicate detection succeeds.
            let unusable =
                a["dadfailed"] == true || (a["tentative"] == true && a["optimistic"] != true);
            if ip.is_unspecified() || ip.is_multicast() || unusable {
                continue;
            }
            if let Some(previous) = found.insert(ip, interface.to_owned()) {
                require(previous == interface, "ambiguous-local-address-interface")?;
            }
        }
    }
    Ok(found)
}
pub fn interfaces() -> Result<BTreeMap<IpAddr, String>> {
    let result = process::run(
        "/usr/bin/ip",
        &["-j", "address", "show"],
        &[],
        Duration::from_secs(5),
        131072,
    )?;
    require(result.status.success(), "local-addresses-unavailable")?;
    parse_interfaces(&result.stdout)
}
pub fn zone(value: &Value) -> Result<&str> {
    let s = value
        .as_str()
        .ok_or_else(|| Error("firewall-zone-unavailable".into()))?;
    require(
        !s.is_empty()
            && s.len() <= 64
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "firewall-zone-unavailable",
    )?;
    Ok(s)
}

const NETWORK_MANAGER: &str = "org.freedesktop.NetworkManager";
fn property<T: TryFrom<OwnedValue>>(value: OwnedValue) -> Result<T> {
    T::try_from(value).map_err(|_| Error("network-connection-identity-invalid".into()))
}
/// Returns the UUID of the NetworkManager connection active on `interface`.
///
/// Returns `None` when NetworkManager is not running or does not manage the
/// interface.
///
/// # Errors
/// Fails when NetworkManager's owner changes or its reply is malformed.
pub async fn connection(bus: &Connection, interface: &str) -> Result<Option<String>> {
    let Some(manager) = Pinned::if_running(bus.clone(), NETWORK_MANAGER).await? else {
        return Ok(None);
    };
    let device: OwnedObjectPath = match manager
        .call(
            "/org/freedesktop/NetworkManager",
            NETWORK_MANAGER,
            "GetDeviceByIpIface",
            &(interface,),
        )
        .await
    {
        Ok(device) => device,
        Err(_) => {
            manager.recheck().await?;
            return Ok(None);
        }
    };
    let active: OwnedObjectPath = property(
        manager
            .call::<_, OwnedValue>(
                device.as_str(),
                "org.freedesktop.DBus.Properties",
                "Get",
                &("org.freedesktop.NetworkManager.Device", "ActiveConnection"),
            )
            .await?,
    )?;
    if active.as_str() == "/" {
        return Ok(None);
    }
    let uuid: String = property(
        manager
            .call::<_, OwnedValue>(
                active.as_str(),
                "org.freedesktop.DBus.Properties",
                "Get",
                &("org.freedesktop.NetworkManager.Connection.Active", "Uuid"),
            )
            .await?,
    )?;
    require(
        (1..=64).contains(&uuid.len()) && uuid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
        "network-connection-identity-invalid",
    )?;
    Ok(Some(uuid.to_ascii_lowercase()))
}
/// Describes the network one listen address was observed on.
///
/// `zone` is `None` while firewalld is not running.
pub fn identity(
    address: IpAddr,
    interface: &str,
    zone: Option<&str>,
    connection: Option<&str>,
) -> Value {
    value!({"address":address.to_string(),"interface":interface,"zone":zone,"connection":connection})
}
/// Validates a reviewed network identity for `addresses`, in listen-address order.
///
/// # Errors
/// Refuses rows that do not describe exactly `addresses` or carry invalid names.
pub fn validate_identity(v: &Value, addresses: &[IpAddr]) -> Result<()> {
    let rows = v
        .as_array()
        .filter(|rows| rows.len() == addresses.len())
        .ok_or_else(|| Error("ssh-network-identity-invalid".into()))?;
    let text = |v: &Value| {
        v.as_str()
            .is_some_and(|s| !s.is_empty() && s.len() <= 64 && !s.chars().any(char::is_control))
    };
    for (row, address) in rows.iter().zip(addresses) {
        json::fields(row, "address interface zone connection")?;
        require(
            row["address"] == address.to_string()
                && text(&row["interface"])
                && zone(&row["zone"]).is_ok()
                && (row["connection"].is_null() || text(&row["connection"])),
            "ssh-network-identity-invalid",
        )?;
    }
    Ok(())
}
/// Whether every listen address was reviewed on an identifiable network connection.
pub fn identifies_connections(v: &Value) -> bool {
    v.as_array().is_some_and(|rows| {
        !rows.is_empty() && rows.iter().all(|row| row["connection"].is_string())
    })
}
/// Refuses an observed network that differs from the reviewed one.
///
/// An observed row without a zone, taken while firewalld is not running,
/// matches any reviewed zone.
///
/// # Errors
/// Fails with `ssh-approved-network-changed` when any address, interface,
/// firewall zone or connection differs.
pub fn require_identity(approved: &Value, observed: &Value) -> Result<()> {
    let same = match (approved.as_array(), observed.as_array()) {
        (Some(approved), Some(observed)) => {
            approved.len() == observed.len()
                && approved.iter().zip(observed).all(|(approved, observed)| {
                    ["address", "interface", "connection"]
                        .iter()
                        .all(|key| approved[key] == observed[key])
                        && (observed["zone"].is_null() || approved["zone"] == observed["zone"])
                        && observed.as_object().is_some_and(|row| row.len() == 4)
                })
        }
        _ => false,
    };
    require(same, "ssh-approved-network-changed")
}
/// Observes the network each of `addresses` is on now, in the reviewed identity format.
///
/// Without a running firewalld (`None`) the rows carry no zone.
///
/// # Errors
/// Fails with `listen-address-unavailable` when an address is not assigned, or
/// when firewalld or NetworkManager cannot be read.
pub async fn observe(
    bus: &Connection,
    firewall: Option<&Firewall>,
    interfaces: &BTreeMap<IpAddr, String>,
    addresses: &[IpAddr],
) -> Result<Value> {
    let mut rows = Vec::new();
    for address in addresses {
        let interface = interfaces
            .get(address)
            .ok_or_else(|| Error("listen-address-unavailable".into()))?;
        let zone = match firewall {
            Some(firewall) => Some(firewall.zone_for(interface).await?),
            None => None,
        };
        let connection = connection(bus, interface).await?;
        rows.push(identity(
            *address,
            interface,
            zone.as_deref(),
            connection.as_deref(),
        ));
    }
    Ok(Value::Array(rows))
}
