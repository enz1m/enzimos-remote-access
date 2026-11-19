// SPDX-License-Identifier: MIT
//! Fresh sender-bound desktop authority and review survive blocking-job cancellation.
use crate::slots::{Permit, Slots};
use crate::{desktop_provider::Reviewed, dispatch};
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
        stopping: bool,
        permit: Permit,
    ) -> Result<(Value, Peer, Permit)> {
        let request = dispatch::decode(body, if stopping { "" } else { "configuration" })?;
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
            let review = if stopping {
                provider.review_stop(&peer)
            } else {
                provider.review(&peer, &request["configuration"])
            }?;
            Ok((review, peer, permit))
        })
        .await
        .map_err(|_| Error("remote-provider-unavailable".into()))?
    }
    pub async fn review(&self, body: &str, sender: &str, stopping: bool) -> Result<Value> {
        let (review, _, _permit) = self
            .reviewed(body, sender, stopping, self.permit()?)
            .await?;
        Ok(review)
    }
    pub async fn mutate(&self, body: &str, sender: &str, stopping: bool) -> Result<Value> {
        let arrived = Instant::now();
        let permit = self.permit()?;
        let request = dispatch::mutation_request(body, !stopping)?;
        let review_body = if stopping {
            "{\"schema\":1}".to_owned()
        } else {
            serde_json::to_string(
                &serde_json::json!({"schema":1,"configuration":request["configuration"]}),
            )?
        };
        let (reviewed, peer, permit) = self
            .reviewed(&review_body, sender, stopping, permit)
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
                    let actual = if stopping {
                        provider.review_stop(&peer)
                    } else {
                        provider.review(&peer, &request["configuration"])
                    }?;
                    require(actual == reviewed, "review-stale")?;
                }
                Ok(())
            };
            before_commit(&mut *provider, true)?;
            provider.change(&peer, &reviewed, stopping, &mut before_commit)
        })
        .await
        .map_err(|_| Error("remote-provider-unavailable".into()))?
    }
}
