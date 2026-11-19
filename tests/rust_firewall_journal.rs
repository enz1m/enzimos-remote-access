// SPDX-License-Identifier: MIT
use enzimos_platform::{Error, Result};
use enzimos_remote_access::{
    firewall::{Interface, Rule},
    firewall_journal::Journal,
};
use std::{
    collections::BTreeSet,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
struct Firewall {
    rows: BTreeSet<String>,
    path: PathBuf,
    add_loses_reply: bool,
    refuse_remove: bool,
}
impl Interface for Firewall {
    fn query(&mut self, r: &Rule) -> Result<bool> {
        Ok(self.rows.contains(&r.rule))
    }
    fn add(&mut self, r: &Rule) -> Result<String> {
        let receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&self.path).unwrap()).unwrap();
        assert!(
            receipt["owned"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["rule"] == r.rule)
        );
        self.rows.insert(r.rule.clone());
        if self.add_loses_reply {
            Err(Error("reply lost".into()))
        } else {
            Ok(r.zone.clone())
        }
    }
    fn remove(&mut self, r: &Rule) -> Result<()> {
        if self.refuse_remove {
            Err(Error("cleanup unavailable".into()))
        } else {
            self.rows.remove(&r.rule);
            Ok(())
        }
    }
}
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn persistent_firewall_ownership_precedes_calls_and_retains_uncertain_cleanup() {
    let work = std::path::PathBuf::from(
        std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    );
    let temp = tempfile::Builder::new()
        .prefix("rust-firewall-fixture-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(work)
        .unwrap();
    let path = temp.path().join("firewall.json");
    let owner = unsafe { libc::geteuid() };
    let boot = "00000000-0000-0000-0000-000000000001";
    let borrowed = Rule {
        zone: "policy:enzimosRemote".into(),
        rule: "borrowed accept fixture".into(),
    };
    let owned = Rule {
        zone: borrowed.zone.clone(),
        rule: "owned reject fixture".into(),
    };
    let mut interface = Firewall {
        rows: BTreeSet::from([borrowed.rule.clone()]),
        path: path.clone(),
        add_loses_reply: true,
        refuse_remove: true,
    };
    let mut journal = Journal {
        path: &path,
        owner,
        boot_id: boot,
        interface: &mut interface,
    };
    assert!(journal.acquire(&[borrowed.clone(), owned.clone()]).is_err());
    assert_eq!(journal.load().unwrap(), vec![owned.clone()]);
    assert!(journal.acquire(std::slice::from_ref(&owned)).is_err());
    journal.interface.refuse_remove = false;
    journal.release().unwrap();
    assert!(journal.interface.rows.contains(&borrowed.rule));
    assert!(!journal.interface.rows.contains(&owned.rule));
    assert!(journal.load().unwrap().is_empty());
    journal.interface.add_loses_reply = false;
    let lease = journal.acquire(&[borrowed.clone(), owned.clone()]).unwrap();
    assert_eq!(lease.preexisting, vec![borrowed.clone()]);
    assert_eq!(lease.owned, vec![owned.clone()]);
    journal.boot_id = "00000000-0000-0000-0000-000000000002";
    journal.release().unwrap();
    assert!(journal.interface.rows.contains(&owned.rule));
    journal.boot_id = boot;
    journal.release().unwrap();
    assert_eq!(journal.interface.rows, BTreeSet::from([borrowed.rule]));
}
