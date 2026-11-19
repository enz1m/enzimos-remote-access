// SPDX-License-Identifier: MIT
use enzimos_platform::{Error, Result, require};
#[allow(
    unsafe_code,
    reason = "Single-threaded startup sanitizes the process environment before launching workers."
)]
fn execute() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    require(
        args.len() == 2 && matches!(args[0].as_str(), "prepare" | "release"),
        "desktop-unit-operation-invalid",
    )?;
    let uid = args[1]
        .parse::<u32>()
        .map_err(|_| Error("desktop-account-invalid".into()))?;
    enzimos_remote_access::desktop_grant::account(uid)?;
    require(uid.to_string() == args[1], "desktop-account-invalid")?;
    enzimos_remote_access::ssh_provider::root_context()?;
    let notify = std::env::var("NOTIFY_SOCKET")
        .ok()
        .filter(|s| s == "/run/systemd/notify");
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
    if let Some(notify) = notify {
        unsafe { std::env::set_var("NOTIFY_SOCKET", notify) };
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| Error("desktop-unit-runtime-unavailable".into()))?;
    runtime.block_on(async {
        let connection =
            enzimos_remote_access::bus_adapter::bounded(zbus::Connection::system(), 5).await?;
        enzimos_remote_access::desktop_unit::entry(&args[0], uid, connection).await
    })
}
fn main() {
    if let Err(error) = execute() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
