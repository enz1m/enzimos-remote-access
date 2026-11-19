// SPDX-License-Identifier: MIT
//! Actual bus-derived sender credentials with fake logind/polkit, never host PAM.
use enzimos_system_backend::authority::Authority;
use std::{
    collections::HashMap,
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, BufReader};
use zbus::{
    connection::Builder,
    zvariant::{OwnedObjectPath, OwnedValue},
};
const SESSION: &str = "/org/freedesktop/login1/session/c1";
const USER: &str = "/org/freedesktop/login1/user/_1000";
#[derive(Clone)]
struct State {
    uid: u32,
    active: Arc<AtomicBool>,
    locked: Arc<AtomicBool>,
    mode: Arc<AtomicU32>,
    user_queries: Arc<AtomicU32>,
    policy_calls: Arc<AtomicU32>,
    delay: Arc<AtomicU32>,
    ids: Arc<Mutex<Vec<String>>>,
    cancelled: Arc<Mutex<Vec<String>>>,
}
#[derive(zbus::DBusError, Debug)]
#[zbus(prefix = "org.freedesktop.login1")]
enum LoginError {
    NoSessionForPID(String),
    Unavailable(String),
}
struct Login(State);
#[zbus::interface(name = "org.freedesktop.login1.Manager")]
impl Login {
    #[zbus(name = "GetSessionByPID")]
    fn session(&self, pid: u32) -> Result<OwnedObjectPath, LoginError> {
        assert_eq!(pid, std::process::id());
        match self.0.mode.load(Ordering::SeqCst) {
            0 => Ok(SESSION.try_into().unwrap()),
            1 => Err(LoginError::NoSessionForPID("no session".into())),
            _ => Err(LoginError::Unavailable("no authority".into())),
        }
    }
    #[zbus(name = "GetUserByPID")]
    fn user(&self, pid: u32) -> OwnedObjectPath {
        assert_eq!(pid, std::process::id());
        self.0.user_queries.fetch_add(1, Ordering::SeqCst);
        USER.try_into().unwrap()
    }
}
struct Local(State);
#[zbus::interface(name = "org.freedesktop.login1.Session")]
impl Local {
    #[zbus(property)]
    fn active(&self) -> bool {
        self.0.active.load(Ordering::SeqCst)
    }
    #[zbus(property)]
    fn locked_hint(&self) -> bool {
        self.0.locked.load(Ordering::SeqCst)
    }
    #[zbus(property)]
    fn remote(&self) -> bool {
        false
    }
    #[zbus(property)]
    fn user(&self) -> (u32, OwnedObjectPath) {
        (self.0.uid, USER.try_into().unwrap())
    }
    #[zbus(property)]
    fn seat(&self) -> (String, OwnedObjectPath) {
        (
            "seat0".into(),
            "/org/freedesktop/login1/seat/seat0".try_into().unwrap(),
        )
    }
    #[zbus(property)]
    fn class(&self) -> &str {
        "user"
    }
    #[zbus(property, name = "Type")]
    fn kind(&self) -> &str {
        "wayland"
    }
    #[zbus(property)]
    fn id(&self) -> &str {
        "c1"
    }
}
struct User(State);
#[zbus::interface(name = "org.freedesktop.login1.User")]
impl User {
    #[zbus(property, name = "UID")]
    fn uid(&self) -> u32 {
        self.0.uid
    }
    #[zbus(property)]
    fn service(&self) -> String {
        format!("user@{}.service", self.0.uid)
    }
    #[zbus(property)]
    fn display(&self) -> (String, OwnedObjectPath) {
        ("c1".into(), SESSION.try_into().unwrap())
    }
    #[zbus(property)]
    fn sessions(&self) -> Vec<(String, OwnedObjectPath)> {
        vec![("c1".into(), SESSION.try_into().unwrap())]
    }
}
struct Policy(State);
#[zbus::interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl Policy {
    async fn check_authorization(
        &self,
        subject: (String, HashMap<String, OwnedValue>),
        action: &str,
        details: HashMap<String, String>,
        flags: u32,
        cancellation_id: &str,
    ) -> (bool, bool, HashMap<String, String>) {
        assert_eq!(subject.0, "system-bus-name");
        assert_eq!(subject.1.len(), 1);
        assert!(
            String::try_from(subject.1["name"].try_clone().unwrap())
                .unwrap()
                .starts_with(':')
        );
        assert!(matches!(
            action,
            "org.enzimos.remote.configure" | "org.enzimos.remote.desktop"
        ));
        assert!(details.is_empty() && flags <= 1);
        self.0.ids.lock().unwrap().push(cancellation_id.into());
        self.0.policy_calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(u64::from(
            self.0.delay.load(Ordering::SeqCst),
        )))
        .await;
        (true, false, HashMap::new())
    }
    fn cancel_check_authorization(&self, id: &str) {
        self.0.cancelled.lock().unwrap().push(id.into());
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
async fn fresh_authority_rechecks_lock_owner_specific_fallback_and_cancels_pending_prompt() {
    let uid = unsafe { libc::getuid() };
    if uid < 1000 {
        return;
    }
    let work = std::path::PathBuf::from(
        std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    );
    let temp = tempfile::Builder::new()
        .prefix("authority-bus-")
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
    let mut reader = BufReader::new(daemon.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert!(line.starts_with(&address));
    let data = State {
        uid,
        active: Arc::new(AtomicBool::new(true)),
        locked: Arc::new(AtomicBool::new(false)),
        mode: Arc::new(AtomicU32::new(0)),
        user_queries: Arc::new(AtomicU32::new(0)),
        policy_calls: Arc::new(AtomicU32::new(0)),
        delay: Arc::new(AtomicU32::new(0)),
        ids: Arc::new(Mutex::new(Vec::new())),
        cancelled: Arc::new(Mutex::new(Vec::new())),
    };
    let login = Builder::address(address.as_str())
        .unwrap()
        .name("org.freedesktop.login1")
        .unwrap()
        .serve_at("/org/freedesktop/login1", Login(data.clone()))
        .unwrap()
        .serve_at(SESSION, Local(data.clone()))
        .unwrap()
        .serve_at(USER, User(data.clone()))
        .unwrap()
        .build()
        .await
        .unwrap();
    let policy = Builder::address(address.as_str())
        .unwrap()
        .name("org.freedesktop.PolicyKit1")
        .unwrap()
        .serve_at(
            "/org/freedesktop/PolicyKit1/Authority",
            Policy(data.clone()),
        )
        .unwrap()
        .build()
        .await
        .unwrap();
    let caller = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let authority = Authority::new(caller.clone()).await.unwrap();
    let sender = caller.unique_name().unwrap().to_string();
    let peer = authority.peer(&sender).await.unwrap();
    assert_eq!(peer.uid, uid);
    assert_eq!(peer.id, "c1");
    data.active.store(false, Ordering::SeqCst);
    assert!(authority.peer(&sender).await.is_err());
    data.active.store(true, Ordering::SeqCst);
    let grant = authority
        .authorize(
            &sender,
            "org.enzimos.remote.desktop",
            false,
            Instant::now(),
            150000,
        )
        .await
        .unwrap();
    data.locked.store(true, Ordering::SeqCst);
    assert!(authority.recheck(&grant).await.is_err());
    let calls = data.policy_calls.load(Ordering::SeqCst);
    assert!(
        authority
            .authorize(
                &sender,
                "org.enzimos.remote.configure",
                true,
                Instant::now(),
                150000
            )
            .await
            .is_err()
    );
    assert_eq!(data.policy_calls.load(Ordering::SeqCst), calls);
    data.locked.store(false, Ordering::SeqCst);
    data.mode.store(1, Ordering::SeqCst);
    assert!(
        authority
            .peer(&sender)
            .await
            .unwrap()
            .origin_session
            .is_none()
    );
    let queries = data.user_queries.load(Ordering::SeqCst);
    data.mode.store(2, Ordering::SeqCst);
    assert!(authority.peer(&sender).await.is_err());
    assert_eq!(data.user_queries.load(Ordering::SeqCst), queries);
    data.mode.store(0, Ordering::SeqCst);
    data.delay.store(500, Ordering::SeqCst);
    let pending_authority = authority.clone();
    let pending_sender = sender.clone();
    let before = data.policy_calls.load(Ordering::SeqCst);
    let pending = tokio::spawn(async move {
        pending_authority
            .authorize(
                &pending_sender,
                "org.enzimos.remote.desktop",
                true,
                Instant::now(),
                150000,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while data.policy_calls.load(Ordering::SeqCst) == before {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    pending.abort();
    assert!(matches!(pending.await, Err(error) if error.is_cancelled()));
    tokio::time::timeout(Duration::from_secs(2), async {
        while data.cancelled.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        data.cancelled.lock().unwrap()[0],
        *data.ids.lock().unwrap().last().unwrap()
    );
    policy
        .release_name("org.freedesktop.PolicyKit1")
        .await
        .unwrap();
    let replacement = Builder::address(address.as_str())
        .unwrap()
        .name("org.freedesktop.PolicyKit1")
        .unwrap()
        .serve_at(
            "/org/freedesktop/PolicyKit1/Authority",
            Policy(data.clone()),
        )
        .unwrap()
        .build()
        .await
        .unwrap();
    assert!(authority.recheck(&grant).await.is_err());
    drop(authority);
    drop(caller);
    drop(replacement);
    drop(policy);
    drop(login);
    daemon.kill().await.unwrap();
    daemon.wait().await.unwrap();
}
