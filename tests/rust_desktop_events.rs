// SPDX-License-Identifier: MIT
//! Fake providers run exclusively on an owned private Unix session bus.
use enzimos_remote_access::desktop_events::Watch;
use std::{collections::HashMap, process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, BufReader};
use zbus::{
    connection::Builder,
    zvariant::{OwnedObjectPath, OwnedValue},
};
const SESSION: &str = "/org/freedesktop/login1/session/c1";
async fn changed(connection: &zbus::Connection) {
    connection
        .emit_signal(
            None::<&str>,
            SESSION,
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            &(
                "org.freedesktop.login1.Session",
                HashMap::<String, OwnedValue>::new(),
                Vec::<String>::new(),
            ),
        )
        .await
        .unwrap();
}
async fn wait_lost(watch: &Watch) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !watch.lost() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}
async fn private_bus() -> (tempfile::TempDir, String, tokio::process::Child) {
    let work = std::path::PathBuf::from(
        std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    );
    let temp = tempfile::Builder::new()
        .prefix("desktop-bus-")
        .tempdir_in(work)
        .unwrap();
    let address = format!("unix:path={}", temp.path().join("bus").display());
    let mut daemon = tokio::process::Command::new("/usr/bin/dbus-daemon")
        .args([
            "--session",
            "--nofork",
            "--print-address=1",
            "--address",
            &address,
        ])
        .env_clear()
        .env("PATH", "/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut output = BufReader::new(daemon.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(3), output.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert!(line.starts_with(&address));
    (temp, address, daemon)
}
async fn named(address: &str, name: &str) -> zbus::Connection {
    Builder::address(address)
        .unwrap()
        .name(name.to_owned())
        .unwrap()
        .build()
        .await
        .unwrap()
}
async fn quiet(watch: &mut Watch) -> bool {
    tokio::time::timeout(Duration::from_millis(60), watch.changed())
        .await
        .is_err()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn desktop_events_are_sender_bound_and_only_logind_loss_is_fatal() {
    let (_temp, address, mut daemon) = private_bus().await;
    let login = Builder::address(address.as_str())
        .unwrap()
        .name("org.freedesktop.login1")
        .unwrap()
        .build()
        .await
        .unwrap();
    let firewall = Builder::address(address.as_str())
        .unwrap()
        .name("org.fedoraproject.FirewallD1")
        .unwrap()
        .build()
        .await
        .unwrap();
    let client = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let attacker = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut watch = Watch::subscribe(
        &client,
        login.unique_name().unwrap().as_str(),
        Some(firewall.unique_name().unwrap().as_str()),
        SESSION,
        "c1",
    )
    .await
    .unwrap();
    changed(&attacker).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(60), watch.changed())
            .await
            .is_err()
    );
    login
        .emit_signal(
            None::<&str>,
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            "SessionRemoved",
            &(
                "c2",
                OwnedObjectPath::try_from("/org/freedesktop/login1/session/c2").unwrap(),
            ),
        )
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(60), watch.changed())
            .await
            .is_err()
    );
    changed(&login).await;
    tokio::time::timeout(Duration::from_secs(2), watch.changed())
        .await
        .unwrap()
        .unwrap();
    for _ in 0..8 {
        changed(&login).await;
    }
    login
        .emit_signal(
            None::<&str>,
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            "SessionRemoved",
            &("c1", OwnedObjectPath::try_from(SESSION).unwrap()),
        )
        .await
        .unwrap();
    wait_lost(&watch).await;
    assert!(watch.changed().await.is_err());
    watch.retire();
    assert!(watch.changed().await.is_err());
    let mut replacement_watch = Watch::subscribe(
        &client,
        login.unique_name().unwrap().as_str(),
        Some(firewall.unique_name().unwrap().as_str()),
        SESSION,
        "c1",
    )
    .await
    .unwrap();
    firewall
        .release_name("org.fedoraproject.FirewallD1")
        .await
        .unwrap();
    let replacement = Builder::address(address.as_str())
        .unwrap()
        .name("org.fedoraproject.FirewallD1")
        .unwrap()
        .build()
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), replacement_watch.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(replacement_watch.firewall_moved());
    assert!(!replacement_watch.lost());
    login.release_name("org.freedesktop.login1").await.unwrap();
    wait_lost(&replacement_watch).await;
    assert!(replacement_watch.changed().await.is_err());
    replacement_watch.retire();
    drop(replacement);
    drop(attacker);
    drop(client);
    drop(firewall);
    drop(login);
    daemon.kill().await.unwrap();
    daemon.wait().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_firewall_guard_follows_firewalld_while_it_stops_and_starts() {
    let (_temp, address, mut daemon) = private_bus().await;
    const FIREWALLD: &str = "org.fedoraproject.FirewallD1";
    let client = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let attacker = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut absent = Watch::lease(&client).await.unwrap();
    assert!(quiet(&mut absent).await);
    let firewalld = named(&address, FIREWALLD).await;
    tokio::time::timeout(Duration::from_secs(2), absent.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(absent.firewall_moved());
    absent.retire();

    let mut running = Watch::lease(&client).await.unwrap();
    attacker
        .emit_signal(
            None::<&str>,
            "/org/fedoraproject/FirewallD1",
            FIREWALLD,
            "Reloaded",
            &(),
        )
        .await
        .unwrap();
    assert!(quiet(&mut running).await);
    firewalld
        .emit_signal(
            None::<&str>,
            "/org/fedoraproject/FirewallD1",
            FIREWALLD,
            "Reloaded",
            &(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), running.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(!running.firewall_moved());
    drop(firewalld);
    tokio::time::timeout(Duration::from_secs(2), running.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(running.firewall_moved());
    assert!(!running.lost());
    running.retire();
    drop(attacker);
    drop(client);
    daemon.kill().await.unwrap();
    daemon.wait().await.unwrap();
}
async fn device_changed(connection: &zbus::Connection, interface: &str) -> zbus::Result<()> {
    connection
        .emit_signal(
            None::<&str>,
            "/org/freedesktop/NetworkManager/Devices/2",
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            &(
                interface,
                HashMap::<String, OwnedValue>::new(),
                Vec::<String>::new(),
            ),
        )
        .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_firewall_guard_follows_networkmanager_devices_and_connections() {
    let (_temp, address, mut daemon) = private_bus().await;
    const NETWORK_MANAGER: &str = "org.freedesktop.NetworkManager";
    let client = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let attacker = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut absent = Watch::lease(&client).await.unwrap();
    assert!(quiet(&mut absent).await);
    let network = named(&address, NETWORK_MANAGER).await;
    tokio::time::timeout(Duration::from_secs(2), absent.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(!absent.firewall_moved());
    absent.retire();

    let mut running = Watch::lease(&client).await.unwrap();
    device_changed(&attacker, "org.freedesktop.NetworkManager.Device")
        .await
        .unwrap();
    device_changed(&network, "org.freedesktop.NetworkManager.Device.Wireless")
        .await
        .unwrap();
    assert!(quiet(&mut running).await);
    for interface in [
        "org.freedesktop.NetworkManager.Device",
        "org.freedesktop.NetworkManager.IP4Config",
    ] {
        device_changed(&network, interface).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), running.changed())
            .await
            .unwrap()
            .unwrap();
    }
    network
        .emit_signal(
            None::<&str>,
            "/org/freedesktop/NetworkManager/Devices/2",
            "org.freedesktop.NetworkManager.Device",
            "StateChanged",
            &(30_u32, 100_u32, 39_u32),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), running.changed())
        .await
        .unwrap()
        .unwrap();
    drop(network);
    tokio::time::timeout(Duration::from_secs(2), running.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(!running.lost());
    running.retire();
    drop(attacker);
    drop(client);
    daemon.kill().await.unwrap();
    daemon.wait().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unattended_watcher_wakes_for_logind_sessions_from_logind_only() {
    let (_temp, address, mut daemon) = private_bus().await;
    let client = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let attacker = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    assert!(Watch::sessions(&client).await.is_err());
    let login = named(&address, "org.freedesktop.login1").await;
    let mut watch = Watch::sessions(&client).await.unwrap();
    changed(&attacker).await;
    assert!(quiet(&mut watch).await);
    changed(&login).await;
    tokio::time::timeout(Duration::from_secs(2), watch.changed())
        .await
        .unwrap()
        .unwrap();
    for (member, body) in [("SessionNew", "c2"), ("SessionRemoved", "c2")] {
        login
            .emit_signal(
                None::<&str>,
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                member,
                &(
                    body,
                    OwnedObjectPath::try_from("/org/freedesktop/login1/session/c2").unwrap(),
                ),
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), watch.changed())
            .await
            .unwrap()
            .unwrap();
    }
    login
        .emit_signal(
            None::<&str>,
            "/org/freedesktop/login1/user/_1000",
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            &(
                "org.freedesktop.login1.User",
                HashMap::<String, OwnedValue>::new(),
                Vec::<String>::new(),
            ),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), watch.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(!watch.lost());
    watch.retire();
    drop(login);
    drop(attacker);
    drop(client);
    daemon.kill().await.unwrap();
    daemon.wait().await.unwrap();
}
