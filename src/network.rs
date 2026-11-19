// SPDX-License-Identifier: MIT
use enzimos_platform::{Error, Result, json, process, require};
use serde_json::Value;
use std::{collections::BTreeMap, net::IpAddr, time::Duration};
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
            if ip.is_unspecified() || ip.is_multicast() {
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
