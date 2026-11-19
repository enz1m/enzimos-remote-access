// SPDX-License-Identifier: MIT
use enzimos_remote_access::{desktop_provider, service};
use serde_json::json;
use zbus::{Message, message::Flags};
fn call(member: &str, has_body: bool) -> Message {
    let builder = Message::method_call(service::PATH, member)
        .unwrap()
        .interface(service::NAME)
        .unwrap()
        .sender(":1.27")
        .unwrap();
    if has_body {
        builder.build(&"{\"schema\":1}").unwrap()
    } else {
        builder.build(&()).unwrap()
    }
}
#[test]
fn service_wire_rejects_wrong_path_signature_sender_and_no_reply_before_dispatch() {
    for (member, body) in [
        ("GetCapabilities", false),
        ("Query", false),
        ("Review", true),
        ("Apply", true),
        ("ReviewDisconnect", true),
        ("Disconnect", true),
        ("QueryDesktop", false),
        ("ReviewDesktop", true),
        ("ApplyDesktop", true),
        ("ReviewStopDesktop", true),
        ("StopDesktop", true),
    ] {
        let parsed = service::validate(&call(member, body)).unwrap();
        assert_eq!(parsed.member, member);
        assert_eq!(parsed.sender, ":1.27");
        assert_eq!(parsed.body.is_some(), body);
        assert!(service::validate(&call(member, !body)).is_err());
    }
    assert!(service::validate(&call("Introspect", false)).is_err());
    for (path, interface, sender) in [
        ("/bad", service::NAME, ":1.27"),
        (service::PATH, "org.enzimos.Other1", ":1.27"),
        (service::PATH, service::NAME, ":abc.def"),
    ] {
        let message = Message::method_call(path, "Apply")
            .unwrap()
            .interface(interface)
            .unwrap()
            .sender(sender)
            .unwrap()
            .build(&"{}")
            .unwrap();
        assert!(service::validate(&message).is_err());
    }
    let message = Message::method_call(service::PATH, "Apply")
        .unwrap()
        .interface(service::NAME)
        .unwrap()
        .sender(":1.27")
        .unwrap()
        .with_flags(Flags::NoReplyExpected)
        .unwrap()
        .build(&"{}")
        .unwrap();
    assert!(service::validate(&message).is_err());
    let capabilities = service::capabilities();
    assert_eq!(capabilities["rdp"], false);
    assert_eq!(capabilities["remote_login"], false);
    assert_eq!(capabilities["default_enabled"], false);
}
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn uncertain_desktop_receipts_are_exact_account_and_boot_bound() {
    let record = json!({"schema":1,"boot_id":"11111111-1111-1111-1111-111111111111","uid":1000,"phase":"uncertain","operation":"apply","plan_sha256":"a".repeat(64),"result":null});
    desktop_provider::receipt_validate(&record, 1000).unwrap();
    assert!(desktop_provider::receipt_validate(&record, 1001).is_err());
    for (key, wrong) in [
        ("phase", json!("retry")),
        ("operation", json!("exec")),
        ("boot_id", json!("old")),
        ("uid", json!(true)),
        ("plan_sha256", json!("A".repeat(64))),
        ("result", json!("secret")),
    ] {
        let mut bad = record.clone();
        bad[key] = wrong;
        assert!(
            desktop_provider::receipt_validate(&bad, 1000).is_err(),
            "{key}"
        );
    }
    for (program, args) in [
        (
            env!("CARGO_BIN_EXE_enzimos-remote-service"),
            vec!["unexpected"],
        ),
        (
            env!("CARGO_BIN_EXE_enzimos-desktop-entry"),
            vec!["prepare", "01000"],
        ),
        (
            env!("CARGO_BIN_EXE_enzimos-desktop-entry"),
            vec!["prepare", "1000"],
        ),
    ] {
        if unsafe { libc::geteuid() } == 0 && args == ["prepare", "1000"] {
            continue;
        }
        let result = std::process::Command::new(program)
            .args(args)
            .env_clear()
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
    }
}

#[test]
fn local_client_preserves_review_envelope_and_validates_the_returned_digest() {
    use enzimos_remote_access::client;
    let plan = json!({"schema":1,"uid":1000});
    let review =
        json!({"plan_sha256":enzimos_platform::json::fingerprint(&plan).unwrap(),"plan":plan});
    let bytes = serde_json::to_vec(&review).unwrap();
    assert_eq!(client::decode_reply("Review", &bytes).unwrap(), review);
    assert_eq!(
        client::decode_reply("ReviewStopDesktop", &bytes).unwrap(),
        review
    );
    assert!(client::decode_reply("Query", &bytes).is_err());
    let mut wrong = review;
    wrong["plan_sha256"] = json!("a".repeat(64));
    assert!(client::decode_reply("ReviewDesktop", &serde_json::to_vec(&wrong).unwrap()).is_err());
    let args = ["apply-desktop", "--allow-interaction", "configuration.json"].map(String::from);
    let command = client::parse(&args).unwrap();
    assert!(command.interaction);
    assert_eq!(
        command.configuration.unwrap(),
        std::path::PathBuf::from("configuration.json")
    );
    for args in [
        vec!["query", "--allow-interaction"],
        vec!["apply"],
        vec!["apply", "a", "b"],
        vec!["disconnect", "--allow-interaction", "--allow-interaction"],
    ] {
        assert!(client::parse(&args.into_iter().map(String::from).collect::<Vec<_>>()).is_err());
    }
    let help = std::process::Command::new(env!("CARGO_BIN_EXE_enzimos-remote"))
        .arg("--help")
        .env_clear()
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(
        String::from_utf8(help.stdout)
            .unwrap()
            .contains("review-stop-desktop")
    );
}
