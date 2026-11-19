// SPDX-License-Identifier: MIT
//! Durable runtime-rule ownership precedes each mutation; borrowed rules stay.
use crate::firewall::{Interface, Lease, Rule};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::path::Path;
pub fn validate(v: &Value) -> Result<Vec<Rule>> {
    json::fields(v, "schema boot_id owned")?;
    require(
        v["schema"].as_u64() == Some(1)
            && v["boot_id"].as_str().is_some_and(|s| {
                s.len() == 36
                    && s.bytes().enumerate().all(|(i, b)| {
                        if [8, 13, 18, 23].contains(&i) {
                            b == b'-'
                        } else {
                            b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                        }
                    })
            }),
        "firewall-journal-invalid",
    )?;
    let owned = v["owned"]
        .as_array()
        .filter(|r| r.len() <= 17)
        .ok_or_else(|| Error("firewall-journal-invalid".into()))?;
    let mut seen = std::collections::BTreeSet::new();
    owned
        .iter()
        .map(|row| {
            json::fields(row, "zone rule")?;
            let zone = row["zone"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 64 && !s.chars().any(char::is_control))
                .ok_or_else(|| Error("firewall-journal-invalid".into()))?;
            let rule = row["rule"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control))
                .ok_or_else(|| Error("firewall-journal-invalid".into()))?;
            require(
                seen.insert((zone.to_owned(), rule.to_owned())),
                "firewall-journal-duplicate",
            )?;
            Ok(Rule {
                zone: zone.into(),
                rule: rule.into(),
            })
        })
        .collect()
}
pub struct Journal<'a, I> {
    pub path: &'a Path,
    pub owner: u32,
    pub boot_id: &'a str,
    pub interface: &'a mut I,
}
impl<I: Interface> Journal<'_, I> {
    pub fn load(&self) -> Result<Vec<Rule>> {
        let Some(body) = files::read_optional(self.path, 16384, Some(self.owner), true)? else {
            return Ok(Vec::new());
        };
        let value = json::decode(&body, 16384)?;
        let rows = validate(&value)?;
        if value["boot_id"] == self.boot_id {
            Ok(rows)
        } else {
            Ok(Vec::new())
        }
    }
    fn save(&self, owned: &[Rule]) -> Result<()> {
        let body = value!({"schema":1,"boot_id":self.boot_id,"owned":owned.iter().map(|r|value!({"zone":r.zone,"rule":r.rule})).collect::<Vec<_>>()});
        validate(&body)?;
        files::atomic(
            self.path,
            &json::canonical(&body)?,
            0o600,
            Some(self.owner),
            true,
        )
    }
    pub fn acquire(&mut self, desired: &[Rule]) -> Result<Lease> {
        require(
            self.load()?.is_empty(),
            "firewall-prior-lease-needs-cleanup",
        )?;
        require((1..=17).contains(&desired.len()), "firewall-lease-bound")?;
        validate(
            &value!({"schema":1,"boot_id":self.boot_id,"owned":desired.iter().map(|r|value!({"zone":r.zone,"rule":r.rule})).collect::<Vec<_>>()}),
        )?;
        let mut lease = Lease {
            owned: Vec::new(),
            preexisting: Vec::new(),
        };
        let result: Result<()> = (|| {
            for row in desired {
                if self.interface.query(row)? {
                    lease.preexisting.push(row.clone());
                    continue;
                }
                lease.owned.push(row.clone());
                self.save(&lease.owned)?;
                require(
                    self.interface.add(row)? == row.zone && self.interface.query(row)?,
                    "firewall-rule-unconfirmed",
                )?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.release()?;
            return Err(error);
        }
        Ok(lease)
    }
    pub fn release(&mut self) -> Result<()> {
        let mut owned = self.load()?;
        while let Some(row) = owned.last() {
            if self.interface.query(row)? {
                self.interface.remove(row)?;
            }
            require(
                !self.interface.query(row)?,
                "firewall-rule-removal-unconfirmed",
            )?;
            owned.pop();
            self.save(&owned)?;
        }
        Ok(())
    }
}
