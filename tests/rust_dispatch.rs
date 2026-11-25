// SPDX-License-Identifier: MIT
use enzimos_remote_access::dispatch;
use serde_json::json;
#[test]
fn reviewed_mutations_reject_duplicates_wrong_types_and_unbounded_deadlines() {
    let v = json!({"schema":1,"configuration":{},"plan_sha256":"a".repeat(64),"allow_interaction":false,"valid_for_ms":150000});
    assert!(dispatch::mutation_request(&v.to_string(), true).is_ok());
    for (key, bad) in [
        ("schema", json!(true)),
        ("valid_for_ms", json!(150001)),
        ("valid_for_ms", json!(999)),
        ("valid_for_ms", json!(1000.0)),
        ("allow_interaction", json!(0)),
        ("plan_sha256", json!("A".repeat(64))),
    ] {
        let mut badv = v.clone();
        badv[key] = bad;
        assert!(dispatch::mutation_request(&badv.to_string(), true).is_err());
    }
    assert!(dispatch::decode("{\"schema\":1,\"schema\":1}", "").is_err());
    assert!(dispatch::decode("{\"schema\":1,\"extra\":0}", "").is_err());
    assert!(dispatch::decode(&" ".repeat(65537), "").is_err());
    assert!(dispatch::decode("{\"schema\":1,\"configuration\":NaN}", "configuration").is_err());
}
#[test]
fn unattended_mutations_carry_only_their_reviewed_toggle() {
    let digest = "a".repeat(64);
    let body = |extra: serde_json::Value| {
        let mut v = serde_json::json!({"schema":1,"plan_sha256":digest,"allow_interaction":true,"valid_for_ms":60000});
        for (key, value) in extra.as_object().unwrap() {
            v[key] = value.clone();
        }
        v.to_string()
    };
    let decoded = dispatch::reviewed_mutation(
        &body(serde_json::json!({"unattended":true})),
        Some("unattended"),
    )
    .unwrap();
    assert_eq!(decoded["unattended"], true);
    for refused in [
        body(serde_json::json!({})),
        body(serde_json::json!({"unattended":true,"configuration":{}})),
        body(serde_json::json!({"configuration":{}})),
    ] {
        assert!(dispatch::reviewed_mutation(&refused, Some("unattended")).is_err());
    }
    assert!(dispatch::reviewed_mutation(&body(serde_json::json!({})), None).is_ok());
}
