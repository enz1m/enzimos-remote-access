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
const FIREWALLD: &str = "org.fedoraproject.FirewallD1";
const NETWORK_MANAGER: &str = "org.freedesktop.NetworkManager";
enum Kind {
    Changed,
    Removed(String),
    Owners {
        login: Option<String>,
        firewall: Option<String>,
        network: bool,
    },
}
enum Event {
    Changed,
    Lost,
    FirewallMoved,
}
struct State {
    closed: AtomicBool,
    lost: AtomicBool,
    moved: AtomicBool,
    sender: mpsc::Sender<()>,
}
impl State {
    fn changed(&self, event: &Event) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        match event {
            Event::Changed => {}
            Event::Lost => self.lost.store(true, Ordering::Release),
            Event::FirewallMoved => self.moved.store(true, Ordering::Release),
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
    /// Watches the session and follows firewalld while it starts, stops or restarts.
    ///
    /// # Errors
    /// Fails when logind or the bus cannot be observed or logind's owner changes.
    pub async fn new(connection: &Connection, session: &Session, id: &str) -> Result<Self> {
        let path = session.session_path(id).await?;
        let firewall = Pinned::if_running(connection.clone(), FIREWALLD).await?;
        let watch = Self::subscribe(
            connection,
            session.login_owner(),
            firewall.as_ref().map(Pinned::owner),
            path.as_str(),
            id,
        )
        .await?;
        session.recheck_owners().await?;
        watch.settle_firewall(connection, firewall.as_ref()).await?;
        Ok(watch)
    }
    /// Also permits owned private-bus fixtures to prove the subscription boundary.
    pub async fn subscribe(
        connection: &Connection,
        login: &str,
        firewall: Option<&str>,
        path: &str,
        id: &str,
    ) -> Result<Self> {
        require(
            login.starts_with(':')
                && firewall.is_none_or(|owner| owner.starts_with(':'))
                && path.starts_with("/org/freedesktop/login1/session/")
                && id.len() <= 64,
            "desktop-watch-authority-invalid",
        )?;
        let rules = rules(login, firewall, path, id)
            .map_err(|_| Error("desktop-watch-authority-invalid".into()))?;
        Self::spawn(connection, rules).await
    }
    /// Watches firewalld and NetworkManager, for a guard that keeps a listener's
    /// firewall lease on its reviewed network.
    ///
    /// Reports a change when either starts, stops or restarts, when firewalld
    /// signals, and when NetworkManager reports a device, address or active
    /// connection change.
    ///
    /// # Errors
    /// Fails when the bus cannot be observed.
    pub async fn lease(connection: &Connection) -> Result<Self> {
        let firewall = Pinned::if_running(connection.clone(), FIREWALLD).await?;
        let network = Pinned::if_running(connection.clone(), NETWORK_MANAGER).await?;
        let mut rules = firewall_rules(None, firewall.as_ref().map(Pinned::owner), true)
            .map_err(|_| Error("desktop-watch-authority-invalid".into()))?;
        if let Some(network) = &network {
            rules.extend(
                network_rules(network.owner())
                    .map_err(|_| Error("desktop-watch-authority-invalid".into()))?,
            );
        }
        let watch = Self::spawn(connection, rules).await?;
        watch.settle_firewall(connection, firewall.as_ref()).await?;
        let current = Pinned::if_running(connection.clone(), NETWORK_MANAGER).await?;
        if current.as_ref().map(Pinned::owner) != network.as_ref().map(Pinned::owner) {
            watch.state.changed(&Event::Changed);
        }
        Ok(watch)
    }
    /// Watches logind sessions, firewalld and NetworkManager, for starting a
    /// listener once its account's session and reviewed network are ready.
    ///
    /// Reports a change when a session or user appears, disappears or changes
    /// properties, and for every event [`Watch::lease`] reports.
    ///
    /// # Errors
    /// Fails when logind or the bus cannot be observed.
    pub async fn sessions(connection: &Connection) -> Result<Self> {
        let login = Pinned::new(connection.clone(), "org.freedesktop.login1").await?;
        let firewall = Pinned::if_running(connection.clone(), FIREWALLD).await?;
        let network = Pinned::if_running(connection.clone(), NETWORK_MANAGER).await?;
        let rules = firewall_rules(None, firewall.as_ref().map(Pinned::owner), true)
            .and_then(|mut rules| {
                rules.extend(login_rules(login.owner())?);
                if let Some(network) = &network {
                    rules.extend(network_rules(network.owner())?);
                }
                Ok(rules)
            })
            .map_err(|_| Error("desktop-watch-authority-invalid".into()))?;
        let watch = Self::spawn(connection, rules).await?;
        watch.settle_firewall(connection, firewall.as_ref()).await?;
        if login.recheck().await.is_err()
            || Pinned::if_running(connection.clone(), NETWORK_MANAGER)
                .await?
                .as_ref()
                .map(Pinned::owner)
                != network.as_ref().map(Pinned::owner)
        {
            watch.state.changed(&Event::Changed);
        }
        Ok(watch)
    }
    // An owner change between the first read and the subscription has no event of its own.
    async fn settle_firewall(
        &self,
        connection: &Connection,
        pinned: Option<&Pinned>,
    ) -> Result<()> {
        let current = Pinned::if_running(connection.clone(), FIREWALLD).await?;
        if current.as_ref().map(Pinned::owner) != pinned.map(Pinned::owner) {
            self.state.changed(&Event::FirewallMoved);
        }
        Ok(())
    }
    async fn spawn(
        connection: &Connection,
        rules: Vec<(MatchRule<'static>, Kind)>,
    ) -> Result<Self> {
        let (sender, receiver) = mpsc::channel(1);
        let state = Arc::new(State {
            closed: AtomicBool::new(false),
            lost: AtomicBool::new(false),
            moved: AtomicBool::new(false),
            sender,
        });
        let mut watch = Self {
            state,
            receiver,
            tasks: Vec::new(),
        };
        for (rule, kind) in rules {
            let mut stream =
                bounded(MessageStream::for_match_rule(rule, connection, Some(32)), 2).await?;
            let state = std::sync::Arc::clone(&watch.state);
            watch.tasks.push(tokio::spawn(async move {
                while let Some(message) = stream.next().await {
                    if state.closed.load(Ordering::Acquire) {
                        break;
                    }
                    match message {
                        Ok(message) => match classify(&message, &kind) {
                            Ok(Some(event)) => state.changed(&event),
                            Ok(None) => {}
                            Err(_) => {
                                state.changed(&Event::Lost);
                                break;
                            }
                        },
                        Err(_) => {
                            state.changed(&Event::Lost);
                            break;
                        }
                    }
                }
                state.changed(&Event::Lost);
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
    /// Whether firewalld started, stopped or restarted since this watch subscribed.
    ///
    /// Signals from a new firewalld owner reach only a new watch.
    pub fn firewall_moved(&self) -> bool {
        self.state.moved.load(Ordering::Acquire)
    }
    pub fn retire(&mut self) {
        self.state.closed.store(true, Ordering::Release);
        self.receiver.close();
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}
fn classify(message: &Message, kind: &Kind) -> Result<Option<Event>> {
    match kind {
        Kind::Changed => Ok(Some(Event::Changed)),
        Kind::Removed(id) => {
            let (removed, _): (String, zbus::zvariant::OwnedObjectPath) = message
                .body()
                .deserialize()
                .map_err(|_| Error("desktop-session-event-invalid".into()))?;
            Ok((removed == *id).then_some(Event::Lost))
        }
        Kind::Owners {
            login,
            firewall,
            network,
        } => {
            let (name, _, new): (String, String, String) = message
                .body()
                .deserialize()
                .map_err(|_| Error("desktop-owner-event-invalid".into()))?;
            Ok(match name.as_str() {
                "org.freedesktop.login1" => login
                    .as_ref()
                    .and_then(|login| (new != *login).then_some(Event::Lost)),
                FIREWALLD => {
                    (new != firewall.as_deref().unwrap_or_default()).then_some(Event::FirewallMoved)
                }
                NETWORK_MANAGER => network.then_some(Event::Changed),
                _ => None,
            })
        }
    }
}

fn rules(
    login: &str,
    firewall: Option<&str>,
    path: &str,
    id: &str,
) -> zbus::Result<Vec<(MatchRule<'static>, Kind)>> {
    let build = || MatchRule::builder().msg_type(Type::Signal);
    let mut rules = vec![
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
    ];
    rules.extend(firewall_rules(Some(login), firewall, false)?);
    Ok(rules)
}
fn firewall_rules(
    login: Option<&str>,
    firewall: Option<&str>,
    network: bool,
) -> zbus::Result<Vec<(MatchRule<'static>, Kind)>> {
    let build = || MatchRule::builder().msg_type(Type::Signal);
    let mut rules = vec![(
        build()
            .sender("org.freedesktop.DBus")?
            .path("/org/freedesktop/DBus")?
            .interface("org.freedesktop.DBus")?
            .member("NameOwnerChanged")?
            .build()
            .to_owned(),
        Kind::Owners {
            login: login.map(Into::into),
            firewall: firewall.map(Into::into),
            network,
        },
    )];
    if let Some(firewall) = firewall {
        rules.push((
            build()
                .sender(firewall)?
                .path("/org/fedoraproject/FirewallD1")?
                .build()
                .to_owned(),
            Kind::Changed,
        ));
    }
    Ok(rules)
}
fn login_rules(owner: &str) -> zbus::Result<Vec<(MatchRule<'static>, Kind)>> {
    let build = || MatchRule::builder().msg_type(Type::Signal).sender(owner);
    let mut rules = vec![(
        build()?
            .path("/org/freedesktop/login1")?
            .interface("org.freedesktop.login1.Manager")?
            .build()
            .to_owned(),
        Kind::Changed,
    )];
    for interface in [
        "org.freedesktop.login1.Session",
        "org.freedesktop.login1.User",
    ] {
        rules.push((
            build()?
                .interface("org.freedesktop.DBus.Properties")?
                .member("PropertiesChanged")?
                .arg(0, interface)?
                .build()
                .to_owned(),
            Kind::Changed,
        ));
    }
    Ok(rules)
}
// Wireless scan and statistics properties are left out: they change constantly.
fn network_rules(owner: &str) -> zbus::Result<Vec<(MatchRule<'static>, Kind)>> {
    let build = || MatchRule::builder().msg_type(Type::Signal).sender(owner);
    let mut rules = vec![(
        build()?
            .interface("org.freedesktop.NetworkManager.Device")?
            .member("StateChanged")?
            .build()
            .to_owned(),
        Kind::Changed,
    )];
    for interface in [
        "org.freedesktop.NetworkManager",
        "org.freedesktop.NetworkManager.Device",
        "org.freedesktop.NetworkManager.IP4Config",
        "org.freedesktop.NetworkManager.IP6Config",
    ] {
        rules.push((
            build()?
                .interface("org.freedesktop.DBus.Properties")?
                .member("PropertiesChanged")?
                .arg(0, interface)?
                .build()
                .to_owned(),
            Kind::Changed,
        ));
    }
    Ok(rules)
}
