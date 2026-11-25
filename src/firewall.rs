// SPDX-License-Identifier: MIT
use enzimos_platform::{Error, Result, require};
use ipnet::IpNet;
use serde_json::{Value, json as value};
use std::net::IpAddr;
pub const NAME: &str = "enzimosRemote";
pub const TARGET: &str = "policy:enzimosRemote";
/// Most rules one listener's lease may own; the journal is bounded to match.
pub const LEASE_RULES: usize = 17;
pub fn policy_rows(v: &Value) -> Result<Vec<String>> {
    require(
        v["target"] == "CONTINUE"
            && v["priority"].as_i64() == Some(-32000)
            && v["ingress_zones"] == value!(["ANY"])
            && v["egress_zones"] == value!(["HOST"]),
        "remote firewall policy changed",
    )?;
    let empty = Vec::new();
    let rows = match &v["rich_rules"] {
        Value::Null => &empty,
        rows => rows
            .as_array()
            .ok_or_else(|| Error("remote firewall policy bound".into()))?,
    };
    require(rows.len() <= 128, "remote firewall policy bound")?;
    rows.iter()
        .map(|r| {
            let s = r
                .as_str()
                .ok_or_else(|| Error("invalid rich rule".into()))?;
            require(
                s.len() <= 512 && !s.contains('\0'),
                "remote firewall rule bound",
            )?;
            Ok(s.into())
        })
        .collect()
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rule {
    pub zone: String,
    pub rule: String,
}
pub fn rules(config: &Value, zone: &str) -> Result<Vec<Rule>> {
    require(
        zone == TARGET
            || (!zone.is_empty()
                && zone.len() <= 64
                && zone
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))),
        "firewall zone unavailable",
    )?;
    if let Some(selected) = config.get("listen_addresses") {
        let addresses = crate::config::listen_addresses(&config["listen_address"], Some(selected))?;
        let networks = config["allowed_networks"]
            .as_array()
            .filter(|rows| (1..=16).contains(&rows.len()))
            .ok_or_else(|| Error("firewall network bound".into()))?;
        let mut parsed = Vec::new();
        for network in networks {
            let ip = network
                .as_str()
                .ok_or_else(|| Error("invalid source network".into()))?
                .parse::<IpNet>()
                .map_err(|_| Error("invalid source network".into()))?;
            require(
                addresses
                    .iter()
                    .any(|address| address.is_ipv4() == ip.addr().is_ipv4()),
                "firewall network identity/family",
            )?;
            parsed.push((ip.addr().is_ipv4(), network.clone()));
        }
        let mut one = config.clone();
        one.as_object_mut()
            .ok_or_else(|| Error("invalid remote configuration".into()))?
            .remove("listen_addresses");
        let mut result = Vec::new();
        for address in addresses {
            one["listen_address"] = value!(address.to_string());
            one["allowed_networks"] = value!(
                parsed
                    .iter()
                    .filter(|(ipv4, _)| *ipv4 == address.is_ipv4())
                    .map(|(_, row)| row.clone())
                    .collect::<Vec<_>>()
            );
            result.extend(rules(&one, zone)?);
        }
        return Ok(result);
    }
    let address = config["listen_address"]
        .as_str()
        .ok_or_else(|| Error("listen address required".into()))?
        .parse::<IpAddr>()
        .map_err(|_| Error("invalid listen address".into()))?;
    require(
        !address.is_unspecified() && !address.is_multicast(),
        "invalid listen address",
    )?;
    let port = config["port"]
        .as_u64()
        .filter(|p| (22..=65535).contains(p))
        .ok_or_else(|| Error("listen port bound".into()))?;
    let networks = config["allowed_networks"]
        .as_array()
        .ok_or_else(|| Error("firewall network bound".into()))?;
    require((1..=16).contains(&networks.len()), "firewall network bound")?;
    let family = if address.is_ipv4() { "ipv4" } else { "ipv6" };
    let priority = if zone == TARGET {
        " priority=\"-32768\""
    } else {
        ""
    };
    let mut rows = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for n in networks {
        let network = n
            .as_str()
            .ok_or_else(|| Error("invalid source network".into()))?
            .parse::<IpNet>()
            .map_err(|_| Error("invalid source network".into()))?;
        require(
            network == network.trunc()
                && network.addr().is_ipv4() == address.is_ipv4()
                && network.prefix_len() >= if address.is_ipv4() { 8 } else { 32 }
                && !network.addr().is_multicast()
                && seen.insert(network),
            "firewall network identity/family",
        )?;
        rows.push(Rule{zone:zone.into(),rule:format!("rule{priority} family=\"{family}\" source address=\"{network}\" destination address=\"{address}\" port port=\"{port}\" protocol=\"tcp\" accept")});
    }
    if zone == TARGET {
        rows.push(Rule{zone:zone.into(),rule:format!("rule priority=\"-32767\" family=\"{family}\" destination address=\"{address}\" port port=\"{port}\" protocol=\"tcp\" reject")});
    }
    Ok(rows)
}
/// Computes the priority-policy lease for `config`, refusing one over [`LEASE_RULES`].
///
/// # Errors
/// Fails for an invalid configuration or one that needs more rules than a lease holds.
pub fn lease_rules(config: &Value) -> Result<Vec<Rule>> {
    let rows = rules(config, TARGET)?;
    require(rows.len() <= LEASE_RULES, "firewall-lease-bound")?;
    Ok(rows)
}
/// Implementations pin and recheck their D-Bus owner on each operation.
pub trait Interface {
    fn query(&mut self, row: &Rule) -> Result<bool>;
    fn add(&mut self, row: &Rule) -> Result<String>;
    fn remove(&mut self, row: &Rule) -> Result<()>;
}
pub struct Lease {
    pub owned: Vec<Rule>,
    pub preexisting: Vec<Rule>,
}
pub fn acquire<I: Interface>(interface: &mut I, desired: &[Rule]) -> Result<Lease> {
    require(
        (1..=LEASE_RULES).contains(&desired.len()),
        "firewall lease bound",
    )?;
    let mut lease = Lease {
        owned: Vec::new(),
        preexisting: Vec::new(),
    };
    let result: Result<()> = (|| {
        for row in desired {
            if interface.query(row)? {
                lease.preexisting.push(row.clone());
                continue;
            }
            // Record before calling: a timeout may occur after a successful mutation.
            lease.owned.push(row.clone());
            let returned = interface.add(row)?;
            require(returned == row.zone, "firewall zone changed")?;
            require(interface.query(row)?, "firewall rule unconfirmed")?;
        }
        Ok(())
    })();
    if let Err(e) = result {
        release(interface, &lease.owned)?;
        return Err(e);
    }
    Ok(lease)
}
pub fn release<I: Interface>(interface: &mut I, owned: &[Rule]) -> Result<()> {
    let mut failed = false;
    for row in owned.iter().rev() {
        let result: Result<()> = (|| {
            if interface.query(row)? {
                interface.remove(row)?;
                require(!interface.query(row)?, "firewall removal unconfirmed")?;
            }
            Ok(())
        })();
        if result.is_err() {
            failed = true;
        }
    }
    require(!failed, "firewall cleanup incomplete")
}
