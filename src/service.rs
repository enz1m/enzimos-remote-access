// SPDX-License-Identifier: MIT
//! Exact existing wire methods; malformed/no-reply calls never reach providers.
use crate::slots::Slots;
use crate::{
    desktop_binding, desktop_dispatch,
    desktop_provider::{Desktop, Operation},
    desktop_unit_trust, dispatch,
    ssh_provider::Ssh,
};
use enzimos_platform::{Error, Result, json, require};
use enzimos_system_backend::authority::Authority;
use futures_util::StreamExt;
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    future::Future,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{task::JoinSet, time::Instant};
use zbus::{
    AsyncDrop, Connection, Message, MessageStream,
    fdo::{RequestNameFlags, RequestNameReply},
    message::{Flags, Type},
};
pub const NAME: &str = "org.enzimos.Remote1";
pub const PATH: &str = "/org/enzimos/Remote1";
const METHODS: [(&str, bool); 13] = [
    ("GetCapabilities", false),
    ("Query", false),
    ("Review", true),
    ("Apply", true),
    ("ReviewDisconnect", true),
    ("Disconnect", true),
    ("QueryDesktop", false),
    ("ReviewDesktop", true),
    ("ApplyDesktop", true),
    ("ReviewStopDesktop", true),
    ("StopDesktop", true),
    ("ReviewDesktopUnattended", true),
    ("SetDesktopUnattended", true),
];
pub struct Call {
    pub member: &'static str,
    pub sender: String,
    pub body: Option<String>,
}
pub fn validate(message: &Message) -> Result<Call> {
    let header = message.header();
    require(
        header.primary().msg_type() == Type::MethodCall
            && header.path().map(|p| p.as_str()) == Some(PATH)
            && header.interface().map(|i| i.as_str()) == Some(NAME)
            && !header.primary().flags().contains(Flags::NoReplyExpected),
        "wire-method-or-signature-unavailable",
    )?;
    let (member, has_body) = METHODS
        .iter()
        .find(|(name, _)| header.member().map(|m| m.as_str()) == Some(*name))
        .ok_or_else(|| Error("wire-method-or-signature-unavailable".into()))?;
    let sender = header
        .sender()
        .map(|s| s.as_str())
        .ok_or_else(|| Error("unique-system-bus-sender-required".into()))?;
    let parts = sender
        .strip_prefix(':')
        .map(|s| s.split('.').collect::<Vec<_>>())
        .unwrap_or_default();
    require(
        sender.len() <= 255
            && parts.len() == 2
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
        "unique-system-bus-sender-required",
    )?;
    require(
        message.body().signature().to_string() == if *has_body { "s" } else { "" },
        "wire-method-or-signature-unavailable",
    )?;
    let body: Option<String> = if *has_body {
        Some(
            message
                .body()
                .deserialize()
                .map_err(|_| Error("wire-method-or-signature-unavailable".into()))?,
        )
    } else {
        message
            .body()
            .deserialize::<()>()
            .map_err(|_| Error("wire-method-or-signature-unavailable".into()))?;
        None
    };
    require(
        body.as_ref()
            .is_none_or(|s| s.len() <= dispatch::MAX_REQUEST),
        "request-bound",
    )?;
    Ok(Call {
        member,
        sender: sender.into(),
        body,
    })
}
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, call: Call) -> impl Future<Output = Result<Value>> + Send;
    fn idle(&self) -> bool;
    fn settled(&self) -> impl Future<Output = ()> + Send;
    fn invalidate(&self, _connection: &Connection) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }
}
pub struct Api {
    ssh: dispatch::Dispatcher<Ssh>,
    desktop: desktop_dispatch::Dispatcher<Desktop>,
    slots: Arc<Slots>,
    desktop_observers: Mutex<BTreeMap<String, Value>>,
}
impl Api {
    pub async fn new(connection: Connection) -> Result<Self> {
        let authority = Authority::new(connection.clone()).await?;
        let slots = Slots::new();
        let ssh = Ssh::new(connection.clone()).await?;
        let desktop = Desktop::new(connection).await?;
        Ok(Self {
            ssh: dispatch::Dispatcher::with_slots(authority.clone(), ssh, slots.clone()),
            desktop: desktop_dispatch::Dispatcher::new(authority, desktop, slots.clone()),
            slots,
            desktop_observers: Mutex::new(BTreeMap::new()),
        })
    }
}
impl Handler for Api {
    async fn handle(&self, call: Call) -> Result<Value> {
        let body = call.body.as_deref().unwrap_or("");
        match call.member {
            "GetCapabilities" => Ok(capabilities()),
            "Query" => self.ssh.query(&call.sender).await,
            "Review" => self.ssh.review(body, &call.sender, false).await,
            "Apply" => self.ssh.mutate(body, &call.sender, false).await,
            "ReviewDisconnect" => self.ssh.review(body, &call.sender, true).await,
            "Disconnect" => self.ssh.mutate(body, &call.sender, true).await,
            "QueryDesktop" => {
                let result = self.desktop.query(&call.sender).await?;
                let mut observers = self
                    .desktop_observers
                    .lock()
                    .map_err(|_| Error("remote-provider-unavailable".into()))?;
                require(
                    observers.contains_key(&call.sender) || observers.len() < 8,
                    "remote-observer-bound",
                )?;
                observers.insert(call.sender, result.clone());
                Ok(result)
            }
            "ReviewDesktop" => {
                self.desktop
                    .review(body, &call.sender, Operation::Apply)
                    .await
            }
            "ApplyDesktop" => {
                self.desktop
                    .mutate(body, &call.sender, Operation::Apply)
                    .await
            }
            "ReviewStopDesktop" => {
                self.desktop
                    .review(body, &call.sender, Operation::Stop)
                    .await
            }
            "StopDesktop" => {
                self.desktop
                    .mutate(body, &call.sender, Operation::Stop)
                    .await
            }
            "ReviewDesktopUnattended" => {
                self.desktop
                    .review(body, &call.sender, Operation::Unattended)
                    .await
            }
            "SetDesktopUnattended" => {
                self.desktop
                    .mutate(body, &call.sender, Operation::Unattended)
                    .await
            }
            _ => Err(Error("wire-method-or-signature-unavailable".into())),
        }
    }
    fn idle(&self) -> bool {
        self.slots.idle()
    }
    async fn settled(&self) {
        self.slots.settled().await;
    }
    async fn invalidate(&self, connection: &Connection) -> Result<()> {
        let observers = self
            .desktop_observers
            .lock()
            .map_err(|_| Error("remote-provider-unavailable".into()))?
            .clone();
        for (sender, previous) in observers {
            // Query reauthenticates the unique sender and its current local session.
            let result = self.desktop.query(&sender).await;
            if result
                .as_ref()
                .is_err_and(|e| e.0 == "remote-request-bound")
            {
                continue;
            }
            if result.as_ref().is_ok_and(|value| *value == previous) {
                continue;
            }
            // An invalidation contains no viewer or account data. Consumers requery
            // through the normal authorization boundary, including after owner loss.
            let _ = crate::bus_adapter::bounded(
                connection.emit_signal(Some(sender.as_str()), PATH, NAME, "DesktopChanged", &()),
                2,
            )
            .await;
            let mut current = self
                .desktop_observers
                .lock()
                .map_err(|_| Error("remote-provider-unavailable".into()))?;
            // Do not overwrite a newer query that completed during this observation.
            if current.get(&sender) == Some(&previous) {
                if let Ok(value) = result {
                    current.insert(sender, value);
                } else {
                    current.remove(&sender);
                }
            }
        }
        Ok(())
    }
}
pub fn capabilities() -> Value {
    use std::os::unix::fs::MetadataExt;
    let available = [
        "/usr/bin/wayvnc",
        desktop_unit_trust::WORKER,
        desktop_unit_trust::TEMPLATE,
        "/usr/lib/enzimos-remote/desktop-entry",
    ]
    .iter()
    .all(|p| {
        desktop_binding::installed(Path::new(p))
            .is_ok_and(|m| *p == desktop_unit_trust::TEMPLATE || m.mode() & 0o111 != 0)
    });
    let available = available && desktop_unit_trust::installed_template_matches().unwrap_or(false);
    let unattended = available
        && desktop_binding::installed(Path::new(desktop_unit_trust::AUTOSTART_TEMPLATE)).is_ok();
    value!({"schema":1,"ssh":true,"sftp":true,"key_only":false,"ssh_password_authentication":true,"ssh_multiple_addresses":true,"desktop_sharing":available,"desktop_sharing_backend":true,"desktop_viewers":true,"desktop_changed_signal":true,"desktop_unattended":unattended,"remote_login":false,"rdp":false,"default_enabled":false})
}
fn public(error: Error) -> String {
    let s = error.0;
    if (1..=96).contains(&s.len())
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        s
    } else {
        "operation-unavailable-or-outcome-unknown".into()
    }
}
async fn reply(connection: &Connection, message: &Message, result: Result<Value>) -> Result<()> {
    match result {
        Ok(value) => {
            let body = String::from_utf8(json::canonical(&value)?)
                .map_err(|_| Error("remote-reply-encoding".into()))?;
            crate::bus_adapter::bounded(connection.reply(&message.header(), &body), 2).await
        }
        Err(error) => {
            crate::bus_adapter::bounded(
                connection.reply_error(
                    &message.header(),
                    "org.enzimos.Remote1.Refused",
                    &public(error),
                ),
                2,
            )
            .await
        }
    }
}
pub async fn serve<H: Handler>(
    mut stream: MessageStream,
    handler: H,
    idle: Duration,
) -> Result<()> {
    require(!idle.is_zero(), "remote-idle-deadline-invalid")?;
    let connection = Connection::from(&stream);
    let ownership = crate::bus_adapter::bounded(
        connection.request_name_with_flags(NAME, RequestNameFlags::DoNotQueue.into()),
        2,
    )
    .await?;
    require(
        ownership == RequestNameReply::PrimaryOwner,
        "remote-service-name-unavailable",
    )?;
    let handler = Arc::new(handler);
    let mut tasks = JoinSet::new();
    let mut last = Instant::now();
    let mut changes = tokio::time::interval(Duration::from_secs(2));
    changes.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut observation = None;
    loop {
        let deadline = last + idle;
        tokio::select! {
            _ = changes.tick(), if observation.is_none() => {
                let handler = handler.clone();
                let connection = connection.clone();
                observation = Some(tokio::spawn(async move { handler.invalidate(&connection).await }));
            },
            _ = async { if let Some(task) = observation.as_mut() { let _ = task.await; } }, if observation.is_some() => {
                observation = None;
            },
            message = stream.next() => {
                let message = message.ok_or_else(|| Error("remote-service-bus-disconnected".into()))?.map_err(|_| Error("remote-service-bus-disconnected".into()))?;
                if message.header().primary().msg_type() != Type::MethodCall { continue; }
                let call = validate(&message);
                if tasks.len() >= 8 || call.is_err() {
                    let error = call.err().unwrap_or_else(|| Error("remote-request-bound".into()));
                    reply(&connection, &message, Err(error)).await?;
                    last = Instant::now();
                    continue;
                }
                let call = call.unwrap();
                let handler = handler.clone();
                let connection = connection.clone();
                tasks.spawn(async move {
                    let result = tokio::time::timeout(Duration::from_secs(180), handler.handle(call)).await.unwrap_or_else(|_| Err(Error("remote-request-outcome-unknown".into())));
                    reply(&connection, &message, result).await
                });
            },
            finished = tasks.join_next(), if !tasks.is_empty() => {
                finished.ok_or_else(|| Error("remote-request-outcome-unknown".into()))?.map_err(|_| Error("remote-request-outcome-unknown".into()))??;
                last = Instant::now();
            },
            _ = tokio::time::sleep_until(deadline), if tasks.is_empty() && handler.idle() => {
                if tasks.is_empty() && handler.idle() && Instant::now() >= deadline { break; }
            },
            _ = handler.settled(), if tasks.is_empty() && !handler.idle() => { last = Instant::now(); },
        }
    }
    if let Some(task) = observation {
        task.abort();
        let _ = task.await;
    }
    crate::bus_adapter::bounded(connection.release_name(NAME), 2).await?;
    stream.async_drop().await;
    Ok(())
}
