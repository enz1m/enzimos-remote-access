// SPDX-License-Identifier: MIT
use enzimos_platform::{Error, Result, require};
#[allow(
    unsafe_code,
    reason = "Single-threaded startup sanitizes the process environment before launching workers."
)]
fn execute() -> Result<()> {
    require(
        std::env::args_os().count() == 1,
        "remote-service-arguments-unavailable",
    )?;
    enzimos_remote_access::ssh_provider::root_context()?;
    std::env::set_current_dir("/")?;
    for (name, _) in std::env::vars_os() {
        unsafe { std::env::remove_var(name) };
    }
    for (name, value) in [
        ("PATH", "/usr/bin"),
        ("HOME", "/nonexistent"),
        ("LANG", "C"),
        ("LC_ALL", "C"),
    ] {
        unsafe { std::env::set_var(name, value) };
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| Error("remote-service-runtime-unavailable".into()))?;
    runtime.block_on(async {
        let builder = zbus::connection::Builder::system()
            .map_err(|_| Error("remote-service-bus-unavailable".into()))?
            .max_queued(32);
        let connection = enzimos_remote_access::bus_adapter::bounded(builder.build(), 5).await?;
        let api = enzimos_remote_access::service::Api::new(connection.clone()).await?;
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::MethodCall)
            .build();
        let stream = enzimos_remote_access::bus_adapter::bounded(
            zbus::MessageStream::for_match_rule(rule, &connection, Some(32)),
            2,
        )
        .await?;
        enzimos_remote_access::service::serve(stream, api, std::time::Duration::from_secs(60)).await
    })
}
fn main() {
    if let Err(error) = execute() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
