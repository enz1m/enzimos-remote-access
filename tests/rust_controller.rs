// SPDX-License-Identifier: MIT
//! Tests of the remote-access controller handling.
use enzimos_platform::{Error, Result};
use enzimos_remote_access::{
    controller::{self, Provider},
    session_guard::Guard,
};
use serde_json::{Value, json};
#[derive(Default)]
struct Fake {
    events: Vec<&'static str>,
    fail_publish: bool,
    fail_cleanup: bool,
    owner: u32,
    connections: Vec<Value>,
}
impl Fake {
    fn event(&mut self, s: &'static str) -> Result<()> {
        self.events.push(s);
        Ok(())
    }
}
impl Provider for Fake {
    type Exclusive = ();
    type Prepared = ();
    fn exclusive(&mut self) -> Result<()> {
        self.event("lock")
    }
    fn current(&mut self) -> Result<Option<Value>> {
        Ok(Some(json!({"uid":self.owner})))
    }
    fn connections(&mut self) -> Result<Vec<Value>> {
        Ok(self.connections.clone())
    }
    fn prepare(&mut self, _: &Value) -> Result<()> {
        self.event("prepare")
    }
    fn pending(&mut self, _: u32, _: &Value) -> Result<()> {
        self.event("pending")
    }
    fn stop_listening(&mut self) -> Result<()> {
        self.event("stop")
    }
    fn release_firewall(&mut self) -> Result<()> {
        self.event("release")?;
        if self.fail_cleanup && self.events.contains(&"publish") {
            Err(Error("fixture".into()))
        } else {
            Ok(())
        }
    }
    fn publish(&mut self, (): ()) -> Result<()> {
        self.event("publish")?;
        if self.fail_publish {
            Err(Error("fixture".into()))
        } else {
            Ok(())
        }
    }
    fn set_autostart(&mut self, on: bool) -> Result<()> {
        self.event(if on { "autostart" } else { "no-autostart" })
    }
    fn start_listening(&mut self) -> Result<()> {
        self.event("start")
    }
    fn verify_listener(&mut self, _: &Value) -> Result<()> {
        self.event("verify")
    }
    fn complete(&mut self, _: u32, _: &Value, _: &Value) -> Result<()> {
        self.event("complete")
    }
    fn failed(&mut self, _: u32, _: &str) -> Result<()> {
        self.event("failed")
    }
    fn uncertain(&mut self, _: u32, _: &str) -> Result<()> {
        self.event("uncertain")
    }
    fn disconnect_owned_sessions(&mut self, before: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        before()?;
        self.event("disconnect")?;
        self.connections.clear();
        Ok(())
    }
    fn listener_active(&mut self) -> Result<bool> {
        Ok(true)
    }
}
fn reviewed() -> Value {
    json!({"plan":{"configuration":{"enabled":true,"autostart":true}}})
}
#[test]
fn durable_pending_precedes_changes_preserves_sessions_and_revokes_on_failure() {
    let connection = json!({"pid":123});
    let mut p = Fake {
        owner: 1000,
        connections: vec![connection.clone()],
        ..Default::default()
    };
    let mut checks = 0;
    let result = controller::apply(&mut p, 1000, &reviewed(), || {
        checks += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(checks, 2);
    assert_eq!(result["existing_connections_disconnected"], false);
    assert_eq!(p.connections, vec![connection]);
    assert_eq!(
        p.events,
        vec![
            "lock",
            "prepare",
            "pending",
            "stop",
            "release",
            "publish",
            "autostart",
            "start",
            "verify",
            "complete"
        ]
    );
    for uncertain in [false, true] {
        let mut p = Fake {
            owner: 1000,
            fail_publish: true,
            fail_cleanup: uncertain,
            ..Default::default()
        };
        assert!(controller::apply(&mut p, 1000, &reviewed(), || Ok(())).is_err());
        assert_eq!(
            p.events.last(),
            Some(&if uncertain { "uncertain" } else { "failed" })
        );
        assert!(
            p.events
                .windows(3)
                .any(|events| events == ["stop", "release", "no-autostart"])
        );
        assert!(!p.events.contains(&"start"));
        assert!(!p.events.contains(&"complete"));
    }
    let mut p = Fake {
        owner: 1001,
        connections: vec![json!({"pid":456})],
        ..Default::default()
    };
    assert!(controller::apply(&mut p, 1000, &reviewed(), || Ok(())).is_err());
    assert!(!p.events.contains(&"pending"));
    let mut p = Fake {
        owner: 1000,
        ..Default::default()
    };
    let mut checks = 0;
    assert!(
        controller::apply(&mut p, 1000, &reviewed(), || {
            checks += 1;
            if checks == 2 {
                Err(Error("authorization withdrawn".into()))
            } else {
                Ok(())
            }
        })
        .is_err()
    );
    assert!(!p.events.contains(&"pending"));
    assert!(!p.events.contains(&"stop"));
}
#[test]
fn disconnect_and_session_loss_are_fresh_and_one_shot() {
    let mut p = Fake {
        owner: 1000,
        connections: vec![json!({"pid":123})],
        ..Default::default()
    };
    let mut checks = 0;
    let result = controller::disconnect(&mut p, 1000, || {
        checks += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(checks, 3);
    assert_eq!(result["disconnected_connection_count"], 1);
    assert_eq!(result["unrelated_sessions_signalled"], false);
    let mut p = Fake {
        owner: 1001,
        ..Default::default()
    };
    assert!(controller::disconnect(&mut p, 1000, || Ok(())).is_err());
    assert!(!p.events.contains(&"disconnect"));
    let mut guard = Guard::default();
    let stops = std::cell::Cell::new(0);
    guard
        .start(|| Ok(()), |_| stops.set(stops.get() + 1))
        .unwrap();
    assert!(guard.changed());
    assert!(!guard.changed());
    guard.recheck(
        || Err(Error("locked".into())),
        |_| stops.set(stops.get() + 1),
    );
    guard.lost(|_| stops.set(stops.get() + 1));
    assert_eq!(stops.get(), 1);
    assert!(guard.closed());
    assert!(!guard.changed());
}
