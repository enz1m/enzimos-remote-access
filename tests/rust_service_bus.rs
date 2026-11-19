// SPDX-License-Identifier: MIT
//! Exercise actual D-Bus frames, replies and idle lifetime on an owned Unix bus.
use enzimos_platform::{Error, Result};
use enzimos_remote_access::service::{self, Call, Handler};
use serde_json::{Value, json};
use std::{
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use zbus::{
    MatchRule, Message, MessageStream, Proxy,
    connection::Builder,
    fdo::DBusProxy,
    message::{Flags, Type},
};
#[derive(Clone)]
struct Fake {
    calls: Arc<AtomicU32>,
    idle: Arc<AtomicBool>,
    changed: Arc<tokio::sync::Notify>,
}
impl Handler for Fake {
    async fn handle(&self, call: Call) -> Result<Value> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if call.member == "Apply" {
            return Err(Error("private material must never leave an error".into()));
        }
        Ok(json!({"schema":1,"member":call.member}))
    }
    fn idle(&self) -> bool {
        self.idle.load(Ordering::SeqCst)
    }
    async fn settled(&self) {
        loop {
            let wait = self.changed.notified();
            tokio::pin!(wait);
            wait.as_mut().enable();
            if self.idle() {
                return;
            }
            wait.await;
        }
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_service_preserves_wire_refusals_no_reply_and_full_idle_lifetime() {
    let work = std::path::PathBuf::from(
        std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    );
    let temp = tempfile::Builder::new()
        .prefix("service-bus-")
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
    let server = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let rule = MatchRule::builder().msg_type(Type::MethodCall).build();
    let stream = MessageStream::for_match_rule(rule, &server, Some(32))
        .await
        .unwrap();
    let fake = Fake {
        calls: Arc::new(AtomicU32::new(0)),
        idle: Arc::new(AtomicBool::new(false)),
        changed: Arc::new(tokio::sync::Notify::new()),
    };
    let control = fake.clone();
    let task = tokio::spawn(service::serve(stream, fake, Duration::from_millis(100)));
    let client = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let bus = DBusProxy::new(&client).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !bus
            .name_has_owner(service::NAME.try_into().unwrap())
            .await
            .unwrap()
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let proxy = Proxy::new(&client, service::NAME, service::PATH, service::NAME)
        .await
        .unwrap();
    let body: String = proxy.call("Query", &()).await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({"schema":1,"member":"Query"})
    );
    let no_reply = Message::method_call(service::PATH, "Apply")
        .unwrap()
        .destination(service::NAME)
        .unwrap()
        .interface(service::NAME)
        .unwrap()
        .with_flags(Flags::NoReplyExpected)
        .unwrap()
        .build(&"{}")
        .unwrap();
    client.send(&no_reply).await.unwrap();
    let _: String = proxy.call("Query", &()).await.unwrap();
    assert_eq!(control.calls.load(Ordering::SeqCst), 2);
    for (method, body) in [("Apply", "x".repeat(65537)), ("UnknownMethod", "{}".into())] {
        let result = proxy.call::<_, _, String>(method, &body).await;
        match result {
            Err(zbus::Error::MethodError(name, Some(message), _)) => {
                assert_eq!(name.as_str(), "org.enzimos.Remote1.Refused");
                assert!(!message.contains("private"));
            }
            _ => panic!("expected exact public refusal"),
        }
    }
    assert_eq!(control.calls.load(Ordering::SeqCst), 2);
    let wrong_type = proxy.call::<_, _, String>("Apply", &7u32).await;
    assert!(matches!(wrong_type, Err(zbus::Error::MethodError(_, _, _))));
    let wrong_path = Proxy::new(&client, service::NAME, "/wrong", service::NAME)
        .await
        .unwrap();
    assert!(matches!(
        wrong_path.call::<_, _, String>("Query", &()).await,
        Err(zbus::Error::MethodError(_, _, _))
    ));
    assert_eq!(control.calls.load(Ordering::SeqCst), 2);
    let refused = proxy.call::<_, _, String>("Apply", &"{}").await;
    match refused {
        Err(zbus::Error::MethodError(name, Some(message), _)) => {
            assert_eq!(name.as_str(), "org.enzimos.Remote1.Refused");
            assert_eq!(message, "operation-unavailable-or-outcome-unknown");
        }
        _ => panic!("expected safe public error"),
    }
    tokio::time::sleep(Duration::from_millis(180)).await;
    assert!(
        !task.is_finished(),
        "blocking-job idle guard must keep the service alive"
    );
    let resumed = std::time::Instant::now();
    control.idle.store(true, Ordering::SeqCst);
    control.changed.notify_waiters();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        resumed.elapsed() >= Duration::from_millis(90),
        "retiring the last blocking job renews the full idle deadline"
    );
    assert!(
        !bus.name_has_owner(service::NAME.try_into().unwrap())
            .await
            .unwrap()
    );
    drop(proxy);
    drop(wrong_path);
    drop(bus);
    drop(client);
    drop(server);
    daemon.kill().await.unwrap();
    daemon.wait().await.unwrap();
}
