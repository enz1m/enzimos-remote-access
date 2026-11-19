// SPDX-License-Identifier: MIT
//! Event consumers coalesce rechecks; authority loss ends sharing once.
use enzimos_platform::{Result, require};
#[derive(Default)]
pub struct Guard {
    closed: bool,
    pending: bool,
}
impl Guard {
    pub fn start<F: FnOnce() -> Result<()>, S: FnOnce(&str)>(
        &mut self,
        verify: F,
        stop: S,
    ) -> Result<()> {
        require(!self.closed, "desktop-session-guard-closed")?;
        match verify() {
            Ok(()) => Ok(()),
            Err(e) => {
                self.close("desktop-session-unavailable", stop);
                Err(e)
            }
        }
    }
    /// Returns true exactly once until the scheduled task runs.
    pub fn changed(&mut self) -> bool {
        if self.closed || self.pending {
            return false;
        }
        self.pending = true;
        true
    }
    pub fn recheck<F: FnOnce() -> Result<()>, S: FnOnce(&str)>(&mut self, verify: F, stop: S) {
        self.pending = false;
        if !self.closed && verify().is_err() {
            self.close("desktop-session-unavailable", stop);
        }
    }
    pub fn lost<S: FnOnce(&str)>(&mut self, stop: S) {
        self.close("desktop-session-authority-lost", stop);
    }
    pub fn close<S: FnOnce(&str)>(&mut self, reason: &str, stop: S) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.pending = false;
        stop(reason);
    }
    pub fn retire(&mut self) {
        self.closed = true;
        self.pending = false;
    }
    pub fn closed(&self) -> bool {
        self.closed
    }
}
