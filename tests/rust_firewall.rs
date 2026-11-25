// SPDX-License-Identifier: MIT
//! Tests of the remote-access firewall handling.
use enzimos_platform::{Error, Result};
use enzimos_remote_access::firewall::{self, Interface, Rule};
use serde_json::json;
struct Fake {
    rows: Vec<Rule>,
    fail_after_add: bool,
    removed: Vec<Rule>,
}
impl Interface for Fake {
    fn query(&mut self, r: &Rule) -> Result<bool> {
        Ok(self.rows.contains(r))
    }
    fn add(&mut self, r: &Rule) -> Result<String> {
        self.rows.push(r.clone());
        if self.fail_after_add {
            Err(Error("lost response after mutation".into()))
        } else {
            Ok(r.zone.clone())
        }
    }
    fn remove(&mut self, r: &Rule) -> Result<()> {
        self.rows.retain(|v| v != r);
        self.removed.push(r.clone());
        Ok(())
    }
}
#[test]
fn scoped_accepts_precede_reject_and_cleanup_never_removes_borrowed_rules() {
    let config =
        json!({"listen_address":"192.0.2.1","port":45344,"allowed_networks":["192.0.2.0/24"]});
    let rows = firewall::rules(&config, firewall::TARGET).unwrap();
    assert!(rows[0].rule.starts_with("rule priority=\"-32768\""));
    assert!(rows[1].rule.starts_with("rule priority=\"-32767\""));
    assert!(rows[1].rule.ends_with(" reject"));
    let multiple = json!({"listen_address":"192.0.2.1", "listen_addresses":["192.0.2.1", "2001:db8::1"], "port":45344, "allowed_networks":["192.0.2.0/24", "2001:db8::/64"]});
    let combined = firewall::rules(&multiple, firewall::TARGET).unwrap();
    assert_eq!(combined.len(), 4);
    for (address, network) in [
        ("192.0.2.1", "192.0.2.0/24"),
        ("2001:db8::1", "2001:db8::/64"),
    ] {
        assert!(combined.iter().any(|row| row.rule.contains(address)
            && row.rule.contains(network)
            && row.rule.ends_with(" accept")));
        assert!(
            combined
                .iter()
                .any(|row| row.rule.contains(address) && row.rule.ends_with(" reject"))
        );
    }
    let mut fake = Fake {
        rows: vec![rows[0].clone()],
        fail_after_add: false,
        removed: vec![],
    };
    let lease = firewall::acquire(&mut fake, &rows).unwrap();
    assert_eq!(lease.preexisting, vec![rows[0].clone()]);
    assert_eq!(lease.owned, vec![rows[1].clone()]);
    firewall::release(&mut fake, &lease.owned).unwrap();
    assert_eq!(fake.rows, vec![rows[0].clone()]);
}
#[test]
fn lost_add_response_is_cleaned_up_and_untrusted_policy_is_refused() {
    let row = Rule {
        zone: firewall::TARGET.into(),
        rule: "fixture".into(),
    };
    let mut fake = Fake {
        rows: vec![],
        fail_after_add: true,
        removed: vec![],
    };
    assert!(firewall::acquire(&mut fake, std::slice::from_ref(&row)).is_err());
    assert!(fake.rows.is_empty());
    assert_eq!(fake.removed, vec![row]);
    let v = json!({"target":"CONTINUE","priority":-32000,"ingress_zones":["ANY"],"egress_zones":["HOST"],"rich_rules":[]});
    firewall::policy_rows(&v).unwrap();
    // firewalld leaves out empty lists.
    let mut missing = v.clone();
    missing.as_object_mut().unwrap().remove("rich_rules");
    assert!(firewall::policy_rows(&missing).unwrap().is_empty());
    let mut bad = v;
    bad["priority"] = json!(0);
    assert!(firewall::policy_rows(&bad).is_err());
}
#[test]
fn a_configuration_needing_more_rules_than_one_lease_is_refused_before_apply() {
    let networks: Vec<String> = (0..16).map(|n| format!("192.0.{n}.0/24")).collect();
    let single = json!({"listen_address":"192.0.2.1","port":45344,"allowed_networks":networks});
    assert_eq!(
        firewall::lease_rules(&single).unwrap().len(),
        firewall::LEASE_RULES
    );
    let mut paired = single;
    paired["listen_addresses"] = json!(["192.0.2.1", "198.51.100.1"]);
    assert_eq!(
        firewall::rules(&paired, firewall::TARGET).unwrap().len(),
        34
    );
    assert_eq!(
        firewall::lease_rules(&paired).unwrap_err().0,
        "firewall-lease-bound"
    );
}
