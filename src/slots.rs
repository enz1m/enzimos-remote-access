// SPDX-License-Identifier: MIT
//! A blocking job retains its request slot and wakes idle observers on retirement.
use enzimos_platform::{Error, Result};
use std::sync::Arc;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
/// Bounded request slots shared by the dispatchers.
pub struct Slots {
    semaphore: Arc<Semaphore>,
    changed: Notify,
}
/// A held request slot, released on drop.
pub struct Permit {
    permit: Option<OwnedSemaphorePermit>,
    slots: Arc<Slots>,
}
impl Drop for Permit {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.slots.changed.notify_waiters();
    }
}
impl Slots {
    /// Empty slots.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            semaphore: Arc::new(Semaphore::new(8)),
            changed: Notify::new(),
        })
    }
    /// Take a slot.
    ///
    /// # Errors
    ///
    /// Fails when every slot is in use.
    pub fn acquire(self: &Arc<Self>) -> Result<Permit> {
        let permit = std::sync::Arc::clone(&self.semaphore)
            .try_acquire_owned()
            .map_err(|_| Error("remote-request-bound".into()))?;
        Ok(Permit {
            permit: Some(permit),
            slots: std::sync::Arc::clone(self),
        })
    }
    /// Whether no slot is in use.
    pub fn idle(&self) -> bool {
        self.semaphore.available_permits() == 8
    }
    /// Wait until no slot is in use.
    pub async fn settled(&self) {
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
