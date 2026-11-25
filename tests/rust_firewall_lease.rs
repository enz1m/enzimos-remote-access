// SPDX-License-Identifier: MIT
use enzimos_platform::{Error, Result};
use enzimos_remote_access::{
    firewall::{Interface, Rule},
    firewall_journal::Journal,
    firewall_lease::{Restored, definitive, restore},
};
use std::{collections::BTreeSet, os::unix::fs::PermissionsExt, path::Path};
#[derive(Default)]
struct Firewalld {
    rows: BTreeSet<String>,
    stopped: bool,
}
impl Interface for Firewalld {
    fn query(&mut self, r: &Rule) -> Result<bool> {
        assert!(!self.stopped, "a stopped firewalld was queried");
        Ok(self.rows.contains(&r.rule))
    }
    fn add(&mut self, r: &Rule) -> Result<String> {
        assert!(!self.stopped, "a stopped firewalld was changed");
        self.rows.insert(r.rule.clone());
        Ok(r.zone.clone())
    }
    fn remove(&mut self, r: &Rule) -> Result<()> {
        assert!(!self.stopped, "a stopped firewalld was changed");
        self.rows.remove(&r.rule);
        Ok(())
    }
}
fn lease() -> Vec<Rule> {
    ["accept from approved network", "reject everything else"]
        .map(|rule| Rule {
            zone: "policy:enzimosRemote".into(),
            rule: rule.into(),
        })
        .to_vec()
}
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn journal<'a>(path: &'a Path, firewalld: &'a mut Firewalld) -> Journal<'a, Firewalld> {
    Journal {
        path,
        owner: unsafe { libc::geteuid() },
        boot_id: "00000000-0000-0000-0000-000000000001",
        interface: firewalld,
    }
}
fn fixture() -> tempfile::TempDir {
    let work = std::path::PathBuf::from(
        std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    );
    tempfile::Builder::new()
        .prefix("rust-firewall-lease-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(work)
        .unwrap()
}

#[test]
fn a_firewalld_reload_restores_the_lease_once_the_approval_still_holds() {
    let temp = fixture();
    let path = temp.path().join("firewall.json");
    let mut firewalld = Firewalld::default();
    let rules = lease();
    let mut journal = journal(&path, &mut firewalld);
    journal.acquire(&rules).unwrap();

    let held = restore(&mut journal, &rules, true, || {
        panic!("an intact lease needs no approval check")
    });
    assert_eq!(held.unwrap(), Restored::Held);

    journal.interface.rows.clear();
    let mut checked = false;
    let restored = restore(&mut journal, &rules, true, || {
        checked = true;
        Ok(())
    });
    assert_eq!(restored.unwrap(), Restored::Reacquired);
    assert!(checked, "the approval was not checked before leasing again");
    assert_eq!(journal.load().unwrap(), rules);
    assert_eq!(journal.interface.rows.len(), rules.len());
}

#[test]
fn a_changed_approval_or_network_refuses_to_lease_again() {
    let temp = fixture();
    let path = temp.path().join("firewall.json");
    let mut firewalld = Firewalld::default();
    let rules = lease();
    let mut journal = journal(&path, &mut firewalld);
    journal.acquire(&rules).unwrap();
    journal.interface.rows.clear();
    for refusal in [
        "remote-approved-configuration-changed",
        "ssh-approved-network-changed",
        "desktop-approved-network-changed",
    ] {
        let error = restore(&mut journal, &rules, true, || Err(Error(refusal.into())));
        assert_eq!(error.unwrap_err().0, refusal);
        assert!(journal.interface.rows.is_empty());
    }
}

#[test]
fn without_firewalld_the_listener_keeps_running_with_no_lease_recorded() {
    let temp = fixture();
    let path = temp.path().join("firewall.json");
    let mut firewalld = Firewalld::default();
    let rules = lease();
    let mut journal = journal(&path, &mut firewalld);
    journal.acquire(&rules).unwrap();
    journal.interface.rows.clear();
    journal.interface.stopped = true;

    let restored = restore(&mut journal, &rules, false, || {
        panic!("nothing is leased while firewalld is stopped")
    });
    assert_eq!(restored.unwrap(), Restored::NoFirewall);
    assert!(journal.load().unwrap().is_empty());

    journal.interface.stopped = false;
    let restored = restore(&mut journal, &rules, true, || Ok(()));
    assert_eq!(restored.unwrap(), Restored::Reacquired);
    assert_eq!(journal.load().unwrap(), rules);
}

#[test]
fn only_a_changed_approval_network_or_listener_ends_a_guard() {
    for firewalld in [
        "remote-firewall-inactive",
        "remote-provider-unavailable",
        "remote-provider-owner-changed-no-retry",
        "remote-firewall-policy-changed",
        "firewall-zone-changed",
        "unit-firewall-worker-unavailable",
    ] {
        assert!(!definitive(&Error(firewalld.into())), "{firewalld}");
    }
    for refusal in [
        "remote-approved-configuration-changed",
        "ssh-approved-network-changed",
        "desktop-approved-network-changed",
        "ssh-listener-not-active",
    ] {
        assert!(definitive(&Error(refusal.into())), "{refusal}");
    }
}
