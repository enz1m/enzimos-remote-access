// SPDX-License-Identifier: MIT
use crate::keys;
use enzimos_platform::{Error, Result, json, require};
use ipnet::IpNet;
use serde_json::{Value, json as value};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::Path;

fn address(v: &Value, addresses: &BTreeSet<IpAddr>) -> Result<IpAddr> {
    let ip = explicit_address(v)?;
    require(addresses.contains(&ip), "listen-address-unavailable")?;
    Ok(ip)
}
fn explicit_address(v: &Value) -> Result<IpAddr> {
    let ip = v
        .as_str()
        .filter(|v| v.len() <= 64)
        .ok_or_else(|| Error("listen-address-unavailable".into()))?
        .parse::<IpAddr>()
        .map_err(|_| Error("listen-address-unavailable".into()))?;
    require(
        !ip.is_unspecified() && !ip.is_multicast(),
        "listen-address-unavailable",
    )?;
    Ok(ip)
}
/// Decode a bounded set of explicit listener addresses, preserving single-address configurations.
///
/// # Errors
/// Refuses wildcard, multicast, duplicate or missing primary addresses and sets over eight.
pub fn listen_addresses(primary: &Value, selected: Option<&Value>) -> Result<Vec<IpAddr>> {
    let primary = explicit_address(primary)?;
    let Some(selected) = selected else {
        return Ok(vec![primary]);
    };
    let rows = selected
        .as_array()
        .filter(|rows| (1..=8).contains(&rows.len()))
        .ok_or_else(|| Error("listen-address-bound".into()))?;
    let mut addresses = BTreeSet::new();
    for row in rows {
        require(
            addresses.insert(explicit_address(row)?),
            "listen-address-duplicate",
        )?;
    }
    require(addresses.contains(&primary), "listen-address-unavailable")?;
    Ok(addresses.into_iter().collect())
}
fn ssh_networks(v: &Value, addresses: &[IpAddr]) -> Result<Vec<String>> {
    let rows = v
        .as_array()
        .filter(|rows| (1..=16).contains(&rows.len()))
        .ok_or_else(|| Error("network-bound".into()))?;
    let mut parsed = Vec::new();
    for row in rows {
        let net = row
            .as_str()
            .ok_or_else(|| Error("network-invalid".into()))?
            .parse::<IpNet>()
            .map_err(|_| Error("network-invalid".into()))?;
        require(
            addresses
                .iter()
                .any(|ip| ip.is_ipv4() == net.addr().is_ipv4()),
            "network-too-broad-or-wrong-family",
        )?;
        parsed.push((net.addr().is_ipv4(), row.clone()));
    }
    let mut result = BTreeSet::new();
    for ipv4 in [true, false] {
        if let Some(ip) = addresses.iter().find(|ip| ip.is_ipv4() == ipv4) {
            let same_family = value!(
                parsed
                    .iter()
                    .filter(|(family, _)| *family == ipv4)
                    .map(|(_, row)| row.clone())
                    .collect::<Vec<_>>()
            );
            result.extend(networks(&same_family, *ip)?);
        }
    }
    Ok(result.into_iter().collect())
}
fn networks(v: &Value, ip: IpAddr) -> Result<Vec<String>> {
    let rows = v.as_array().ok_or_else(|| Error("network-bound".into()))?;
    require((1..=16).contains(&rows.len()), "network-bound")?;
    let mut seen = BTreeSet::new();
    for row in rows {
        let network: IpNet = row
            .as_str()
            .ok_or_else(|| Error("network-invalid".into()))?
            .parse()
            .map_err(|_| Error("network-invalid".into()))?;
        require(network.addr() == network.network(), "network-invalid")?;
        require(
            network.addr().is_ipv4() == ip.is_ipv4()
                && !network.addr().is_multicast()
                && network.prefix_len() >= if ip.is_ipv4() { 8 } else { 32 },
            "network-too-broad-or-wrong-family",
        )?;
        require(seen.insert(network.to_string()), "network-duplicate")?;
    }
    Ok(seen.into_iter().collect())
}
fn boolean(v: &Value) -> Result<bool> {
    v.as_bool()
        .ok_or_else(|| Error("configuration-fields".into()))
}
fn integer(v: &Value, lo: u64, hi: u64, code: &str) -> Result<u64> {
    let n = v.as_u64().ok_or_else(|| Error(code.into()))?;
    require((lo..=hi).contains(&n), code)?;
    Ok(n)
}
pub fn ssh(v: &Value, account: &str, addresses: &BTreeSet<IpAddr>) -> Result<Value> {
    let mut required = v.clone();
    if let Some(fields) = required.as_object_mut() {
        fields.remove("allow_password");
        fields.remove("listen_addresses");
    }
    json::fields(
        &required,
        "schema enabled autostart listen_address port allowed_networks public_keys allow_local_forwarding",
    )?;
    require(v["schema"] == 1, "ssh-configuration-fields")?;
    require(
        !account.is_empty()
            && account.len() <= 32
            && account != "root"
            && (account.as_bytes()[0].is_ascii_lowercase() || account.starts_with('_'))
            && account
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-".contains(&c)),
        "ordinary-account-required",
    )?;
    for key in ["enabled", "autostart", "allow_local_forwarding"] {
        boolean(&v[key])?;
    }
    integer(&v["port"], 22, 65535, "ssh-listen-port")?;
    let selected = listen_addresses(&v["listen_address"], v.get("listen_addresses"))?;
    // Stopping a listener must work even after its interface disappears.
    if v["enabled"] == true {
        require(
            selected.iter().all(|ip| addresses.contains(ip)),
            "listen-address-unavailable",
        )?;
    }
    let mut result = v.clone();
    let primary = explicit_address(&v["listen_address"])?;
    result["listen_address"] = value!(primary.to_string());
    if v.get("listen_addresses").is_some() {
        result["listen_addresses"] =
            value!(selected.iter().map(ToString::to_string).collect::<Vec<_>>());
    }
    result["allowed_networks"] = value!(ssh_networks(&v["allowed_networks"], &selected)?);
    let password = v
        .get("allow_password")
        .map(boolean)
        .transpose()?
        .unwrap_or(false);
    let public_keys = if password && v["public_keys"].as_array().is_some_and(Vec::is_empty) {
        Vec::new()
    } else {
        keys::key_list(&v["public_keys"])?
    };
    result["public_keys"] = value!(public_keys);
    result["account"] = value!(account);
    Ok(result)
}
pub fn render_ssh(c: &Value) -> Result<String> {
    // Public callers cannot bypass review by passing a hand-built Value with
    // injected account or network lines directly to the renderer.
    let account = c["account"]
        .as_str()
        .ok_or_else(|| Error("ordinary-account-required".into()))?;
    let observed = listen_addresses(&c["listen_address"], c.get("listen_addresses"))?;
    let mut request = c.clone();
    request
        .as_object_mut()
        .ok_or_else(|| Error("ssh-configuration-fields".into()))?
        .remove("account");
    request["public_keys"] = value!(
        c["public_keys"]
            .as_array()
            .ok_or_else(|| Error("public-key-list-bound".into()))?
            .iter()
            .map(|row| row["key"].clone())
            .collect::<Vec<_>>()
    );
    let checked = ssh(&request, account, &observed.iter().copied().collect())?;
    require(checked == *c, "noncanonical reviewed SSH configuration")?;
    let c = &checked;
    let users = c["allowed_networks"]
        .as_array()
        .ok_or_else(|| Error("invalid SSH networks".into()))?
        .iter()
        .map(|n| {
            format!(
                "{}@{}",
                c["account"].as_str().unwrap_or(""),
                n.as_str().unwrap_or("")
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let forwarding = boolean(&c["allow_local_forwarding"])?;
    let password = c
        .get("allow_password")
        .map(boolean)
        .transpose()?
        .unwrap_or(false);
    let has_keys = c["public_keys"]
        .as_array()
        .is_some_and(|keys| !keys.is_empty());
    let mut rows = vec![
        format!(
            "Port {}",
            integer(&c["port"], 22, 65535, "ssh-listen-port")?
        ),
        format!(
            "AddressFamily {}",
            if observed.iter().all(IpAddr::is_ipv6) {
                "inet6"
            } else if observed.iter().all(IpAddr::is_ipv4) {
                "inet"
            } else {
                "any"
            }
        ),
        "HostKey /var/lib/enzimos/remote/ssh/host_ed25519".into(),
        "AuthorizedKeysFile /etc/enzimos/remote/authorized_keys/%u".into(),
        "AuthorizedKeysCommand none".into(),
        "StrictModes yes".into(),
        format!("AllowUsers {users}"),
    ];
    rows.splice(
        1..1,
        observed.iter().map(|ip| {
            format!(
                "ListenAddress {}",
                if ip.is_ipv6() {
                    format!("[{ip}]")
                } else {
                    ip.to_string()
                }
            )
        }),
    );
    rows.extend(
        [
            "PermitRootLogin no",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "PermitEmptyPasswords no",
            "AuthenticationMethods publickey",
            "PubkeyAuthentication yes",
            "HostbasedAuthentication no",
            "GSSAPIAuthentication no",
            "UsePAM yes",
            "X11Forwarding no",
            "AllowAgentForwarding no",
            "PermitTunnel no",
            "PermitUserRC no",
            "AllowStreamLocalForwarding no",
            "GatewayPorts no",
            "PermitListen none",
        ]
        .map(|directive| match directive {
            "PasswordAuthentication no" if password => "PasswordAuthentication yes".to_owned(),
            "AuthenticationMethods publickey" if password => if has_keys {
                "AuthenticationMethods publickey password"
            } else {
                "AuthenticationMethods password"
            }
            .to_owned(),
            _ => directive.to_owned(),
        }),
    );
    rows.push(format!(
        "AllowTcpForwarding {}",
        if forwarding { "local" } else { "no" }
    ));
    rows.push(
        if forwarding {
            "PermitOpen localhost:* 127.0.0.1:* [::1]:*"
        } else {
            "PermitOpen none"
        }
        .into(),
    );
    rows.extend(
        [
            "MaxAuthTries 3",
            "MaxSessions 4",
            "MaxStartups 10:30:30",
            "LoginGraceTime 30",
            "LogLevel INFO",
            "FingerprintHash sha256",
            "ClientAliveInterval 60",
            "ClientAliveCountMax 3",
            "PidFile /var/lib/enzimos/remote/ssh/sshd.pid",
            "Subsystem sftp internal-sftp",
        ]
        .map(str::to_owned),
    );
    Ok(rows.join("\n") + "\n")
}
pub fn desktop(v: &Value, addresses: &BTreeSet<IpAddr>) -> Result<Value> {
    let rdp = v["schema"].as_u64() == Some(2);
    json::fields(
        v,
        if rdp {
            "schema enabled mode protocol listen_address port allowed_networks view_only"
        } else {
            "schema enabled mode listen_address port allowed_networks view_only max_fps output"
        },
    )?;
    require(
        if rdp {
            v["protocol"] == "rdp" && v["mode"] == "session-sharing"
        } else {
            v["schema"].as_u64() == Some(1)
                && matches!(v["mode"].as_str(), Some("session-sharing" | "remote-login"))
        },
        "desktop-configuration-fields",
    )?;
    for key in ["enabled", "view_only"] {
        boolean(&v[key])?;
    }
    integer(&v["port"], 1024, 65535, "desktop-listen-port")?;
    if !rdp {
        integer(&v["max_fps"], 1, 60, "desktop-frame-rate-bound")?;
        require(
            v["output"].is_null()
                || v["output"].as_str().is_some_and(|s| {
                    !s.is_empty()
                        && s.len() <= 80
                        && s.bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
                }),
            "desktop-output-invalid",
        )?;
        require(
            v["mode"] != "remote-login" || v["output"].is_null(),
            "remote-login-has-private-display",
        )?;
    }
    let ip = address(&v["listen_address"], addresses)?;
    let mut result = v.clone();
    result["listen_address"] = value!(ip.to_string());
    result["allowed_networks"] = value!(networks(&v["allowed_networks"], ip)?);
    Ok(result)
}
pub fn tls_config(directory: &Path, password: &str) -> Result<Vec<u8>> {
    require(
        directory.is_absolute()
            && directory.components().all(|c| {
                matches!(
                    c,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
            && !directory
                .as_os_str()
                .as_encoded_bytes()
                .iter()
                .any(|c| b"\n\r\0=".contains(c)),
        "desktop-private-identity-path",
    )?;
    require(
        (32..=128).contains(&password.len())
            && password
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c)),
        "desktop-private-password-bound",
    )?;
    let directory = directory
        .to_str()
        .ok_or_else(|| Error("desktop-private-identity-path".into()))?;
    Ok(format!("enable_auth=true\nenable_pam=false\nusername=enzimos\nrelax_encryption=false\nallow_broken_crypto=false\npassword={password}\ncertificate_file={directory}/certificate.pem\nprivate_key_file={directory}/private-key.pem\n").into_bytes())
}
