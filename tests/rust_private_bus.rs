// SPDX-License-Identifier: MIT
//! All daemon calls in this test go to an owned, private session bus and fakes.
use enzimos_remote_access::{
    bus_adapter::Pinned,
    firewall::{self, Rule},
    firewall_bus::Firewall,
    system::System,
};
use std::collections::HashMap;
use std::{
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use zbus::zvariant::{OwnedValue, Value};
use zbus::{connection::Builder, zvariant::OwnedObjectPath};
#[derive(Clone)]
struct Policy {
    rows: Arc<Mutex<Vec<String>>>,
    invalid: Arc<AtomicU32>,
}
#[zbus::interface(name = "org.fedoraproject.FirewallD1.policy")]
impl Policy {
    #[zbus(name = "getPolicySettings")]
    fn get(&self, name: &str) -> HashMap<String, OwnedValue> {
        assert_eq!(name, firewall::NAME);
        let mut settings = HashMap::new();
        settings.insert(
            "target".into(),
            Value::from("CONTINUE").try_to_owned().unwrap(),
        );
        settings.insert(
            "priority".into(),
            if self.invalid.load(Ordering::SeqCst) == 0 {
                (-32000i32).into()
            } else {
                false.into()
            },
        );
        for (key, rows) in [
            ("ingress_zones", vec!["ANY".to_owned()]),
            ("egress_zones", vec!["HOST".to_owned()]),
            ("rich_rules", self.rows.lock().unwrap().clone()),
        ] {
            // Like firewalld 2.5, leave out empty lists.
            if !rows.is_empty() {
                settings.insert(key.into(), Value::from(rows).try_to_owned().unwrap());
            }
        }
        settings
    }
    #[zbus(name = "setPolicySettings")]
    fn set(&self, name: &str, settings: HashMap<String, OwnedValue>) {
        assert_eq!(name, firewall::NAME);
        assert_eq!(settings.len(), 1);
        *self.rows.lock().unwrap() =
            Vec::<String>::try_from(settings["rich_rules"].try_clone().unwrap()).unwrap();
    }
}
const PATH_UNIT: &str =
    "/org/freedesktop/systemd1/unit/enzimos_2ddesktop_2dsharing_401000_2eservice";
#[derive(Clone)]
struct Data {
    loads: Arc<AtomicU32>,
    clean: Arc<AtomicU32>,
    store: Arc<AtomicU32>,
    main: Arc<AtomicU32>,
}
struct Manager(Data);
#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl Manager {
    fn load_unit(&self, name: &str) -> OwnedObjectPath {
        assert_eq!(name, "enzimos-desktop-sharing@1000.service");
        self.0.loads.fetch_add(1, Ordering::SeqCst);
        OwnedObjectPath::try_from(PATH_UNIT).unwrap()
    }
    fn clean_unit(&self, name: &str, mask: Vec<String>) {
        assert_eq!(name, "enzimos-desktop-sharing@1000.service");
        assert_eq!(mask, vec!["fdstore"]);
        self.0.clean.fetch_add(1, Ordering::SeqCst);
        self.0.store.store(0, Ordering::SeqCst);
    }
}
struct Unit;
#[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
impl Unit {
    #[zbus(property)]
    fn active_state(&self) -> &str {
        "inactive"
    }
}
struct Service(Data);
#[zbus::interface(name = "org.freedesktop.systemd1.Service")]
impl Service {
    #[zbus(property, name = "MainPID")]
    fn main_pid(&self) -> u32 {
        self.0.main.load(Ordering::SeqCst)
    }
    #[zbus(property, name = "ControlPID")]
    fn control_pid(&self) -> u32 {
        0
    }
    #[zbus(property, name = "NFileDescriptorStore")]
    fn fdstore(&self) -> u32 {
        self.0.store.load(Ordering::SeqCst)
    }
    #[zbus(property)]
    fn control_group(&self) -> &str {
        "/system.slice/enzimos-desktop-sharing@1000.service"
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_bus_cleanup_is_exact_and_provider_replacement_never_retries() {
    let work = std::path::PathBuf::from(
        std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    );
    let temp = tempfile::Builder::new()
        .prefix("rb-")
        .permissions(std::fs::Permissions::from_mode(0o700))
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
    let mut line = String::new();
    let mut output = BufReader::new(daemon.stdout.take().unwrap());
    tokio::time::timeout(Duration::from_secs(2), output.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert!(line.starts_with(&address));
    let data = Data {
        loads: Arc::new(AtomicU32::new(0)),
        clean: Arc::new(AtomicU32::new(0)),
        store: Arc::new(AtomicU32::new(1)),
        main: Arc::new(AtomicU32::new(0)),
    };
    let policy = Policy {
        rows: Arc::new(Mutex::new(vec!["borrowed fixture rule".into()])),
        invalid: Arc::new(AtomicU32::new(0)),
    };
    let server = Builder::address(address.as_str())
        .unwrap()
        .name("org.freedesktop.systemd1")
        .unwrap()
        .name("org.fedoraproject.FirewallD1")
        .unwrap()
        .serve_at("/org/fedoraproject/FirewallD1", policy.clone())
        .unwrap()
        .serve_at("/org/freedesktop/systemd1", Manager(data.clone()))
        .unwrap()
        .serve_at(PATH_UNIT, Unit)
        .unwrap()
        .serve_at(PATH_UNIT, Service(data.clone()))
        .unwrap()
        .build()
        .await
        .unwrap();
    let connection = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let pinned = Pinned::new(connection.clone(), "org.freedesktop.systemd1")
        .await
        .unwrap();
    let firewall = Firewall::new(connection.clone()).await.unwrap();
    let row = Rule {
        zone: firewall::TARGET.into(),
        rule: "owned fixture rule".into(),
    };
    assert!(!firewall.query_async(&row).await.unwrap());
    assert_eq!(firewall.add_async(&row).await.unwrap(), firewall::TARGET);
    assert!(firewall.query_async(&row).await.unwrap());
    assert!(
        policy
            .rows
            .lock()
            .unwrap()
            .contains(&"borrowed fixture rule".to_owned())
    );
    firewall.remove_async(&row).await.unwrap();
    assert_eq!(
        *policy.rows.lock().unwrap(),
        vec!["borrowed fixture rule".to_owned()]
    );
    policy.invalid.store(1, Ordering::SeqCst);
    assert!(firewall.add_async(&row).await.is_err());
    assert_eq!(
        *policy.rows.lock().unwrap(),
        vec!["borrowed fixture rule".to_owned()]
    );
    policy.invalid.store(0, Ordering::SeqCst);
    let system = System::new(connection.clone(), "enzimos-desktop-sharing@1000.service")
        .await
        .unwrap();
    assert_eq!(system.properties().await.unwrap().fdstore, 1);
    system.clean_fdstore().await.unwrap();
    assert_eq!(data.clean.load(Ordering::SeqCst), 1);
    data.store.store(1, Ordering::SeqCst);
    data.main.store(42, Ordering::SeqCst);
    assert!(system.clean_fdstore().await.is_err());
    assert_eq!(data.clean.load(Ordering::SeqCst), 1);
    assert!(
        System::new(connection.clone(), "sshd.service")
            .await
            .is_err()
    );
    server
        .release_name("org.fedoraproject.FirewallD1")
        .await
        .unwrap();
    let inactive = Firewall::new(connection.clone()).await.unwrap();
    assert!(!inactive.running().await.unwrap());
    assert_eq!(
        inactive.zone_for("eth0").await.unwrap_err().0,
        "remote-firewall-inactive"
    );
    assert!(firewall.query_async(&row).await.is_err());
    let restarted_firewall = Builder::address(address.as_str())
        .unwrap()
        .name("org.fedoraproject.FirewallD1")
        .unwrap()
        .serve_at("/org/fedoraproject/FirewallD1", policy.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    assert!(inactive.running().await.unwrap());
    assert_eq!(
        inactive.rows().await.unwrap(),
        vec!["borrowed fixture rule".to_owned()]
    );
    assert!(firewall.rows().await.is_err());
    drop(restarted_firewall);
    server
        .release_name("org.freedesktop.systemd1")
        .await
        .unwrap();
    let replacement = Builder::address(address.as_str())
        .unwrap()
        .name("org.freedesktop.systemd1")
        .unwrap()
        .build()
        .await
        .unwrap();
    let before = data.loads.load(Ordering::SeqCst);
    assert!(pinned.recheck().await.is_err());
    assert!(system.properties().await.is_err());
    assert_eq!(data.loads.load(Ordering::SeqCst), before);
    drop(replacement);
    drop(system);
    drop(pinned);
    drop(firewall);
    drop(connection);
    drop(server);
    daemon.start_kill().unwrap();
    daemon.wait().await.unwrap();
}
