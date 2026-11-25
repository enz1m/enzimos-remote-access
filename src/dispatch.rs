// SPDX-License-Identifier: MIT
//! Fresh bus/logind/polkit authority around reviewed SSH lifecycle operations.
use crate::controller::{self, Provider};
use crate::slots::{Permit, Slots};
use enzimos_platform::{Error, Result, json, require};
use enzimos_system_backend::authority::{Authority, Peer};
use serde_json::Value;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
pub const MAX_REQUEST: usize = 65536;
pub fn decode(body: &str, fields: &str) -> Result<Value> {
    let v = json::decode(body.as_bytes(), MAX_REQUEST)?;
    json::fields(&v, &format!("schema {fields}"))?;
    require(v["schema"].as_u64() == Some(1), "request-fields")?;
    Ok(v)
}
pub fn mutation_request(body: &str, apply: bool) -> Result<Value> {
    reviewed_mutation(body, apply.then_some("configuration"))
}
/// Decodes a mutation carrying its reviewed digest, approval deadline and,
/// when `field` names one, the reviewed request field.
///
/// # Errors
/// Fails for missing, extra or malformed fields.
pub fn reviewed_mutation(body: &str, field: Option<&str>) -> Result<Value> {
    let v = decode(
        body,
        &match field {
            Some(field) => format!("{field} plan_sha256 allow_interaction valid_for_ms"),
            None => "plan_sha256 allow_interaction valid_for_ms".into(),
        },
    )?;
    require(
        v["allow_interaction"].is_boolean()
            && v["valid_for_ms"]
                .as_u64()
                .is_some_and(|n| (1000..=150000).contains(&n)),
        "request-deadline-or-interaction",
    )?;
    let digest = v["plan_sha256"]
        .as_str()
        .ok_or_else(|| Error("review-digest".into()))?;
    require(
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "review-digest",
    )?;
    Ok(v)
}
fn graphical(peer: &Peer) -> Result<()> {
    require(
        matches!(peer.kind.as_str(), "wayland" | "x11"),
        "active-local-graphical-session-required",
    )
}
pub trait ReviewedProvider: Provider + Send + 'static {
    fn review(&mut self, uid: u32, configuration: &Value) -> Result<Value>;
    fn review_disconnect(&mut self, uid: u32) -> Result<Value>;
    fn query(&mut self, uid: u32) -> Result<Value>;
}
struct Alive(Arc<AtomicBool>);
impl Drop for Alive {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
pub struct Dispatcher<P> {
    authority: Authority,
    provider: Arc<Mutex<P>>,
    slots: Arc<Slots>,
}
impl<P: ReviewedProvider> Dispatcher<P> {
    pub fn new(authority: Authority, provider: P) -> Self {
        Self::with_slots(authority, provider, Slots::new())
    }
    pub fn with_slots(authority: Authority, provider: P, slots: Arc<Slots>) -> Self {
        Self {
            authority,
            provider: Arc::new(Mutex::new(provider)),
            slots,
        }
    }
    pub async fn query(&self, sender: &str) -> Result<Value> {
        let permit = self.slots.acquire()?;
        let peer = self.authority.peer(sender).await?;
        graphical(&peer)?;
        let provider = self.provider.clone();
        let authority = self.authority.clone();
        let sender = sender.to_owned();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut provider = provider
                .lock()
                .map_err(|_| Error("remote-provider-unavailable".into()))?;
            require(
                runtime.block_on(authority.peer(&sender))? == peer,
                "caller-session-changed",
            )?;
            provider.query(peer.uid)
        })
        .await
        .map_err(|_| Error("remote-provider-unavailable".into()))?
    }
    pub async fn review(&self, body: &str, sender: &str, disconnect: bool) -> Result<Value> {
        let permit = self.slots.acquire()?;
        let (result, _permit) = self.review_inner(body, sender, disconnect, permit).await?;
        Ok(result)
    }
    async fn review_inner(
        &self,
        body: &str,
        sender: &str,
        disconnect: bool,
        permit: Permit,
    ) -> Result<(Value, Permit)> {
        let request = decode(body, if disconnect { "" } else { "configuration" })?;
        let peer = self.authority.peer(sender).await?;
        graphical(&peer)?;
        let provider = self.provider.clone();
        let authority = self.authority.clone();
        let sender = sender.to_owned();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let mut p = provider
                .lock()
                .map_err(|_| Error("remote-provider-unavailable".into()))?;
            require(
                runtime.block_on(authority.peer(&sender))? == peer,
                "caller-session-changed",
            )?;
            let result = if disconnect {
                p.review_disconnect(peer.uid)
            } else {
                p.review(peer.uid, &request["configuration"])
            }?;
            Ok((result, permit))
        })
        .await
        .map_err(|_| Error("remote-provider-unavailable".into()))?
    }
    pub async fn mutate(&self, body: &str, sender: &str, disconnect: bool) -> Result<Value> {
        let arrived = Instant::now();
        let permit = self.slots.acquire()?;
        let request = mutation_request(body, !disconnect)?;
        let peer = self.authority.peer(sender).await?;
        graphical(&peer)?;
        let review_body = if disconnect {
            "{\"schema\":1}".to_owned()
        } else {
            body_for_review(&request)?
        };
        let (initial, permit) = self
            .review_inner(&review_body, sender, disconnect, permit)
            .await?;
        require(
            initial["plan_sha256"] == request["plan_sha256"],
            "review-stale",
        )?;
        let grant = self
            .authority
            .authorize(
                sender,
                "org.enzimos.remote.configure",
                request["allow_interaction"].as_bool().unwrap(),
                arrived,
                request["valid_for_ms"].as_u64().unwrap(),
            )
            .await?;
        require(grant.peer == peer, "caller-session-changed")?;
        let alive = Alive(Arc::new(AtomicBool::new(true)));
        let active = alive.0.clone();
        let provider = self.provider.clone();
        let authority = self.authority.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut p = provider
                .lock()
                .map_err(|_| Error("remote-provider-unavailable".into()))?;
            // Re-observe review before controller takes its exclusive operation
            // lock; controller calls this again under that lock before pending.
            let check = |p: &mut P| -> Result<()> {
                require(active.load(Ordering::Acquire), "request-cancelled")?;
                runtime.block_on(authority.recheck(&grant))?;
                let current = if disconnect {
                    p.review_disconnect(peer.uid)?
                } else {
                    p.review(peer.uid, &request["configuration"])?
                };
                require(current == initial, "review-stale")
            };
            let before = || {
                require(active.load(Ordering::Acquire), "request-cancelled")?;
                runtime.block_on(authority.recheck(&grant))
            };
            if disconnect {
                controller::disconnect_checked(&mut *p, peer.uid, check, before)
            } else {
                controller::apply_checked(&mut *p, peer.uid, &initial, check)
            }
        })
        .await
        .map_err(|_| Error("remote-provider-unavailable".into()))?
    }
}
fn body_for_review(v: &Value) -> Result<String> {
    String::from_utf8(json::canonical(
        &serde_json::json!({"schema":1,"configuration":v["configuration"]}),
    )?)
    .map_err(|_| Error("request-invalid".into()))
}
