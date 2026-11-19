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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn desktop_events_are_sender_bound_and_loss_survives_a_full_queue() {
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
        firewall.unique_name().unwrap().as_str(),
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
        firewall.unique_name().unwrap().as_str(),
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
