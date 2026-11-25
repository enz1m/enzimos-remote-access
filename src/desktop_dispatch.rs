// SPDX-License-Identifier: MIT
//! Fresh sender-bound desktop authority and review survive blocking-job cancellation.
use crate::slots::{Permit, Slots};
use crate::{
    desktop_provider::{Operation, Reviewed},
    dispatch,
};
use enzimos_platform::{Error, Result, require};
use enzimos_system_backend::authority::{Authority, Peer};
use serde_json::Value;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
fn graphical(peer: &Peer) -> Result<()> {
    require(
        matches!(peer.kind.as_str(), "wayland" | "x11"),
        "active-local-graphical-session-required",
    )
}
fn request_fields(operation: Operation) -> &'static str {
    match operation {
        Operation::Apply => "configuration",
        Operation::Stop => "",
        Operation::Unattended => "unattended",
    }
}
fn review<P: Reviewed>(
    provider: &mut P,
    peer: &Peer,
    operation: Operation,
    request: &Value,
) -> Result<Value> {
    match operation {
        Operation::Apply => provider.review(peer, &request["configuration"]),
        Operation::Stop => provider.review_stop(peer),
        Operation::Unattended => provider.review_unattended(
            peer,
            request["unattended"]
                .as_bool()
                .ok_or_else(|| Error("request-fields".into()))?,
        ),
    }
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
impl<P: Reviewed> Dispatcher<P> {
    pub fn new(authority: Authority, provider: P, slots: Arc<Slots>) -> Self {
        Self {
            authority,
            provider: Arc::new(Mutex::new(provider)),
            slots,
        }
    }
    fn permit(&self) -> Result<Permit> {
        self.slots.acquire()
    }
    pub async fn query(&self, sender: &str) -> Result<Value> {
        let permit = self.permit()?;
        let peer = self.authority.peer(sender).await?;
        graphical(&peer)?;
        let authority = self.authority.clone();
        let sender = sender.to_owned();
        let provider = self.provider.clone();
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
            provider.query(&peer)
        })
        .await
        .map_err(|_| Error("remote-provider-unavailable".into()))?
    }
    async fn reviewed(
        &self,
        body: &str,
        sender: &str,
        operation: Operation,
        permit: Permit,
    ) -> Result<(Value, Peer, Permit)> {
        let request = dispatch::decode(body, request_fields(operation))?;
        if operation == Operation::Unattended {
            require(request["unattended"].is_boolean(), "request-fields")?;
        }
        let peer = self.authority.peer(sender).await?;
        graphical(&peer)?;
        let authority = self.authority.clone();
        let sender = sender.to_owned();
        let provider = self.provider.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let mut provider = provider
                .lock()
                .map_err(|_| Error("remote-provider-unavailable".into()))?;
            require(
                runtime.block_on(authority.peer(&sender))? == peer,
                "caller-session-changed",
            )?;
            let review = review(&mut *provider, &peer, operation, &request)?;
            Ok((review, peer, permit))
        })
        .await
        .map_err(|_| Error("remote-provider-unavailable".into()))?
    }
    pub async fn review(&self, body: &str, sender: &str, operation: Operation) -> Result<Value> {
        let (review, _, _permit) = self
            .reviewed(body, sender, operation, self.permit()?)
            .await?;
        Ok(review)
    }
    pub async fn mutate(&self, body: &str, sender: &str, operation: Operation) -> Result<Value> {
        let arrived = Instant::now();
        let permit = self.permit()?;
        let request = dispatch::reviewed_mutation(
            body,
            match operation {
                Operation::Apply => Some("configuration"),
                Operation::Stop => None,
                Operation::Unattended => Some("unattended"),
            },
        )?;
        let review_body = serde_json::to_string(&match operation {
            Operation::Stop => serde_json::json!({"schema":1}),
            Operation::Apply => {
                serde_json::json!({"schema":1,"configuration":request["configuration"]})
            }
            Operation::Unattended => {
                serde_json::json!({"schema":1,"unattended":request["unattended"]})
            }
        })?;
        let (reviewed, peer, permit) = self
            .reviewed(&review_body, sender, operation, permit)
            .await?;
        require(
            reviewed["plan_sha256"] == request["plan_sha256"],
            "review-stale",
        )?;
        let grant = self
            .authority
            .authorize(
                sender,
                "org.enzimos.remote.desktop",
                request["allow_interaction"].as_bool().unwrap(),
                arrived,
                request["valid_for_ms"].as_u64().unwrap(),
            )
            .await?;
        require(grant.peer == peer, "caller-session-changed")?;
        let alive = Alive(Arc::new(AtomicBool::new(true)));
        let active = alive.0.clone();
        let authority = self.authority.clone();
        let provider = self.provider.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut provider = provider
                .lock()
                .map_err(|_| Error("remote-provider-unavailable".into()))?;
            let mut before_commit = |provider: &mut P, check_review: bool| {
                require(active.load(Ordering::Acquire), "request-cancelled")?;
                runtime.block_on(authority.recheck(&grant))?;
                if check_review {
                    let actual = review(provider, &peer, operation, &request)?;
                    require(actual == reviewed, "review-stale")?;
                }
                Ok(())
            };
            before_commit(&mut *provider, true)?;
            provider.change(&peer, &reviewed, operation, &mut before_commit)
        })
        .await
        .map_err(|_| Error("remote-provider-unavailable".into()))?
    }
}
