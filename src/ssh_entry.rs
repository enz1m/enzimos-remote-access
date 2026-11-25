// SPDX-License-Identifier: MIT
//! Entry point of the SSH listener, firewall guard and retry units.
use enzimos_platform::{Error, Result, require};
#[allow(
    unsafe_code,
    reason = "Single-threaded startup sanitizes the process environment before launching workers."
)]
fn execute() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    require(
        args.len() == 1
            && matches!(
                args[0].as_str(),
                "prepare" | "release" | "verify" | "watch" | "retry"
            ),
        "unit-operation-unavailable",
    )?;
    enzimos_remote_access::ssh_provider::root_context()?;
    std::env::set_current_dir("/")?;
    // This runs before creating Tokio or any background task.
    for (name, _) in std::env::vars_os() {
        // SAFETY: The process is still single-threaded here, so no other thread reads the
        // environment.
        unsafe { std::env::remove_var(name) };
    }
    for (name, value) in [
        ("PATH", "/usr/bin"),
        ("HOME", "/nonexistent"),
        ("LANG", "C"),
        ("LC_ALL", "C"),
    ] {
        // SAFETY: The process is still single-threaded here, so no other thread reads the
        // environment.
        unsafe { std::env::set_var(name, value) };
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| Error("unit-runtime-unavailable".into()))?;
    runtime.block_on(async {
        let connection =
            enzimos_remote_access::bus_adapter::bounded(zbus::Connection::system(), 5).await?;
        enzimos_remote_access::ssh_provider::entry(&args[0], connection).await
    })
}
fn main() {
    if let Err(error) = execute() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
