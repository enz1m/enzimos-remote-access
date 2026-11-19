// SPDX-License-Identifier: MIT
use base64::{Engine, engine::general_purpose::STANDARD};
use enzimos_remote_access::{config, keys, state};
use serde_json::{Value, json};
use std::collections::BTreeSet;
fn encoded(name: &str, values: &[&[u8]]) -> String {
    let mut data = Vec::new();
    for field in std::iter::once(name.as_bytes()).chain(values.iter().copied()) {
        data.extend_from_slice(&(field.len() as u32).to_be_bytes());
        data.extend_from_slice(field);
    }
    format!("{name} {}", STANDARD.encode(data))
}
fn key() -> String {
    encoded("ssh-ed25519", &[&[b'k'; 32]])
}
fn fixture() -> Value {
    json!({"schema":1,"enabled":true,"autostart":false,"listen_address":"192.168.10.5","port":2222,"allowed_networks":["192.168.10.0/24"],"public_keys":[key()],"allow_local_forwarding":false})
}
#[test]
fn authentication_configuration_rejects_injection_and_network_widening() {
    let addresses = BTreeSet::from(["192.168.10.5".parse().unwrap()]);
    let valid = config::ssh(&fixture(), "admin", &addresses).unwrap();
    let text = config::render_ssh(&valid).unwrap();
    for directive in [
        "PasswordAuthentication no",
        "PermitRootLogin no",
        "AllowUsers admin@192.168.10.0/24",
        "AuthenticationMethods publickey",
        "PermitOpen none",
        "AllowTcpForwarding no",
        "X11Forwarding no",
        "Subsystem sftp internal-sftp",
    ] {
        assert!(text.contains(directive));
    }
    for (field, replacement) in [
        ("port", json!(true)),
        ("listen_address", json!("0.0.0.0")),
        ("listen_address", json!("192.168.10.6")),
        ("listen_address", json!("192.168.10.5\nPermitRootLogin yes")),
        ("allowed_networks", json!(["0.0.0.0/0"])),
        ("allowed_networks", json!(["192.168.10.1/24"])),
        ("allowed_networks", json!(["2001:db8::/32"])),
        ("autostart", json!(1)),
    ] {
        let mut v = fixture();
        v[field] = replacement;
        assert!(
            config::ssh(&v, "admin", &addresses).is_err(),
            "accepted {field}"
        );
    }
    let all_addresses = BTreeSet::from([
        "192.168.10.5".parse().unwrap(),
        "2001:db8::5".parse().unwrap(),
    ]);
    let mut multiple = fixture();
    multiple["listen_addresses"] = json!(["192.168.10.5", "2001:db8::5"]);
    multiple["allowed_networks"] = json!(["192.168.10.0/24", "2001:db8::/64"]);
    let valid_multiple = config::ssh(&multiple, "admin", &all_addresses).unwrap();
    let rendered = config::render_ssh(&valid_multiple).unwrap();
    let mut ipv6_primary = multiple.clone();
    ipv6_primary["listen_address"] = json!("2001:db8::5");
    let checked = config::ssh(&ipv6_primary, "admin", &all_addresses).unwrap();
    assert_eq!(checked["listen_address"], "2001:db8::5");
    assert_eq!(config::render_ssh(&checked).unwrap(), rendered);
    assert!(rendered.contains("AddressFamily any\n"));
    for address in ["192.168.10.5", "[2001:db8::5]"] {
        assert!(rendered.contains(&format!("ListenAddress {address}\n")));
    }
    assert!(rendered.contains("admin@2001:db8::/64"));
    assert!(config::ssh(&multiple, "admin", &addresses).is_err());
    for selected in [
        json!([]),
        json!(["192.168.10.5", "192.168.10.5"]),
        json!(["2001:db8::5"]),
        json!(["192.168.10.5", "::"]),
    ] {
        let mut bad = multiple.clone();
        bad["listen_addresses"] = selected;
        assert!(config::ssh(&bad, "admin", &all_addresses).is_err());
    }
    multiple["allowed_networks"] = json!(["192.168.10.0/24"]);
    assert!(config::ssh(&multiple, "admin", &all_addresses).is_err());
    assert!(config::ssh(&fixture(), "root", &addresses).is_err());
    let mut password = fixture();
    password["allow_password"] = json!(true);
    let mixed = config::ssh(&password, "admin", &addresses).unwrap();
    let rendered = config::render_ssh(&mixed).unwrap();
    assert!(rendered.contains("PasswordAuthentication yes\n"));
    assert!(rendered.contains("AuthenticationMethods publickey password\n"));
    password["public_keys"] = json!([]);
    let only_password = config::ssh(&password, "admin", &addresses).unwrap();
    let rendered = config::render_ssh(&only_password).unwrap();
    assert!(rendered.contains("AuthenticationMethods password\n"));
    assert!(rendered.contains("PermitRootLogin no\n"));
    assert!(rendered.contains("PermitEmptyPasswords no\n"));
    assert!(config::ssh(&password, "root", &addresses).is_err());
    password["allow_password"] = json!(false);
    assert!(config::ssh(&password, "admin", &addresses).is_err());
    password["allow_password"] = json!("yes\nPermitRootLogin yes");
    assert!(config::ssh(&password, "admin", &addresses).is_err());
}
#[test]
fn public_key_parser_rejects_private_material_options_and_weak_rsa() {
    let ordinary = key();
    for v in [
        format!("command=do-something {ordinary}"),
        format!("{ordinary}\n{ordinary}"),
        "-----BEGIN OPENSSH PRIVATE KEY-----".into(),
        "ssh-ed25519 !invalid".into(),
        encoded("ssh-ed25519", &[&[b'k'; 31]]),
        ordinary.replace("ssh-ed25519 ", "ssh-rsa "),
    ] {
        assert!(keys::public_key(&v).is_err());
    }
    assert!(keys::key_list(&json!([ordinary, format!("{} renamed", key())])).is_err());
    for bits in [2048, 3072] {
        let mut modulus = vec![0u8; bits / 8 + 1];
        modulus[1] = 0x80;
        *modulus.last_mut().unwrap() = 1;
        let v = encoded("ssh-rsa", &[&[1, 0, 1], &modulus]);
        assert_eq!(keys::public_key(&v).is_ok(), bits == 3072);
    }
    let hardware = encoded("sk-ssh-ed25519@openssh.com", &[&[b'k'; 32], b"ssh:"]);
    assert_eq!(
        keys::public_key(&hardware).unwrap()["hardware_backed"],
        true
    );
    assert!(
        keys::public_key(&encoded(
            "sk-ssh-ed25519@openssh.com",
            &[&[b'k'; 32], b"bad\napplication"]
        ))
        .is_err()
    );
}
#[test]
fn malformed_or_ambiguous_approval_records_refuse() {
    let record = json!({"schema":1,"uid":1000,"phase":"complete","boot_id":"current","configuration":{"enabled":true},"detail":""});
    state::validate(&record).unwrap();
    for (name, v) in [
        ("uid", json!(true)),
        ("phase", json!("retry")),
        ("configuration", json!([])),
        ("detail", json!("x".repeat(161))),
    ] {
        let mut changed = record.clone();
        changed[name] = v;
        assert!(state::validate(&changed).is_err());
    }
}
