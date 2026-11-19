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
