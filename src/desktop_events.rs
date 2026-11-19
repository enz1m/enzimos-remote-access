// SPDX-License-Identifier: MIT
//! Event-triggered rechecks coalesce; owner loss latches even when the queue is full.
use crate::{
    bus_adapter::{Pinned, bounded},
    desktop_session::Session,
};
use enzimos_platform::{Error, Result, require};
use futures_util::StreamExt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{sync::mpsc, task::JoinHandle};
use zbus::{Connection, MatchRule, Message, MessageStream, message::Type};
enum Kind {
    Changed,
    Removed(String),
    Owners { login: String, firewall: String },
}
struct State {
    closed: AtomicBool,
    lost: AtomicBool,
    sender: mpsc::Sender<()>,
}
impl State {
    fn changed(&self, lost: bool) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        if lost {
            self.lost.store(true, Ordering::Release);
        }
        let _ = self.sender.try_send(());
    }
}
pub struct Watch {
    state: Arc<State>,
    receiver: mpsc::Receiver<()>,
    tasks: Vec<JoinHandle<()>>,
}
impl Drop for Watch {
    fn drop(&mut self) {
        self.retire();
    }
}
impl Watch {
    pub async fn new(connection: &Connection, session: &Session, id: &str) -> Result<Self> {
        let path = session.session_path(id).await?;
        let firewall = Pinned::new(connection.clone(), "org.fedoraproject.FirewallD1").await?;
        let watch = Self::subscribe(
            connection,
            session.login_owner(),
            firewall.owner(),
            path.as_str(),
            id,
        )
        .await?;
        session.recheck_owners().await?;
        firewall.recheck().await?;
        Ok(watch)
    }
    /// Also permits owned private-bus fixtures to prove the subscription boundary.
    pub async fn subscribe(
        connection: &Connection,
        login: &str,
        firewall: &str,
        path: &str,
        id: &str,
    ) -> Result<Self> {
        require(
            login.starts_with(':')
                && firewall.starts_with(':')
                && path.starts_with("/org/freedesktop/login1/session/")
                && id.len() <= 64,
            "desktop-watch-authority-invalid",
        )?;
        let (sender, receiver) = mpsc::channel(1);
        let state = Arc::new(State {
            closed: AtomicBool::new(false),
            lost: AtomicBool::new(false),
            sender,
        });
        let mut watch = Self {
            state,
            receiver,
            tasks: Vec::new(),
        };
        let rules = rules(login, firewall, path, id)
            .map_err(|_| Error("desktop-watch-authority-invalid".into()))?;
        for (rule, kind) in rules {
            let mut stream =
                bounded(MessageStream::for_match_rule(rule, connection, Some(32)), 2).await?;
            let state = watch.state.clone();
            watch.tasks.push(tokio::spawn(async move {
                while let Some(message) = stream.next().await {
                    if state.closed.load(Ordering::Acquire) {
                        break;
                    }
                    match message {
                        Ok(message) => match classify(&message, &kind) {
                            Ok(Some(lost)) => state.changed(lost),
                            Ok(None) => {}
                            Err(_) => {
                                state.changed(true);
                                break;
                            }
                        },
                        Err(_) => {
                            state.changed(true);
                            break;
                        }
                    }
                }
                state.changed(true);
            }));
        }
        Ok(watch)
    }
    pub async fn changed(&mut self) -> Result<()> {
        require(
            !self.state.closed.load(Ordering::Acquire),
            "desktop-watch-retired",
        )?;
        self.receiver
            .recv()
            .await
            .ok_or_else(|| Error("desktop-session-authority-lost".into()))?;
        require(!self.lost(), "desktop-session-authority-lost")
    }
    pub fn lost(&self) -> bool {
        self.state.lost.load(Ordering::Acquire)
    }
    pub fn retire(&mut self) {
        self.state.closed.store(true, Ordering::Release);
        self.receiver.close();
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}
fn classify(message: &Message, kind: &Kind) -> Result<Option<bool>> {
    match kind {
        Kind::Changed => Ok(Some(false)),
        Kind::Removed(id) => {
            let (removed, _): (String, zbus::zvariant::OwnedObjectPath) = message
                .body()
                .deserialize()
                .map_err(|_| Error("desktop-session-event-invalid".into()))?;
            Ok((removed == *id).then_some(true))
        }
        Kind::Owners { login, firewall } => {
            let (name, _, new): (String, String, String) = message
                .body()
                .deserialize()
                .map_err(|_| Error("desktop-owner-event-invalid".into()))?;
            Ok(match name.as_str() {
                "org.freedesktop.login1" => (new != *login).then_some(true),
                "org.fedoraproject.FirewallD1" => (new != *firewall).then_some(true),
                _ => None,
            })
        }
    }
}

fn rules(
    login: &str,
    firewall: &str,
    path: &str,
    id: &str,
) -> zbus::Result<Vec<(MatchRule<'static>, Kind)>> {
    let build = || MatchRule::builder().msg_type(Type::Signal);
    let rules = vec![
        (
            build()
                .sender(login)?
                .path(path)?
                .interface("org.freedesktop.DBus.Properties")?
                .member("PropertiesChanged")?
                .arg(0, "org.freedesktop.login1.Session")?
                .build()
                .to_owned(),
            Kind::Changed,
        ),
        (
            build()
                .sender(login)?
                .path("/org/freedesktop/login1")?
                .interface("org.freedesktop.login1.Manager")?
                .member("SessionRemoved")?
                .build()
                .to_owned(),
            Kind::Removed(id.into()),
        ),
        (
            build()
                .sender("org.freedesktop.DBus")?
                .path("/org/freedesktop/DBus")?
                .interface("org.freedesktop.DBus")?
                .member("NameOwnerChanged")?
                .build()
                .to_owned(),
            Kind::Owners {
                login: login.into(),
                firewall: firewall.into(),
            },
        ),
        (
            build()
                .sender(firewall)?
                .path("/org/fedoraproject/FirewallD1")?
                .build()
                .to_owned(),
            Kind::Changed,
        ),
    ];
    Ok(rules)
}
