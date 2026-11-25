// SPDX-License-Identifier: MIT
//! Desktop-sharing worker run as the sharing user.
use enzimos_platform::{Error, Result, accounts, require};
use enzimos_remote_access::{bus_adapter, desktop_credential, desktop_worker, listener};
#[allow(
    unsafe_code,
    reason = "Single-threaded startup sanitizes the process environment before launching workers."
)]
fn execute() -> Result<()> {
    require(
        std::env::args_os().count() == 1,
        "desktop-worker-arguments-unavailable",
    )?;
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    let grant = desktop_credential::credential(uid)?;
    let account = accounts::lookup_uid(uid)?;
    let configuration = &grant["configuration"];
    let endpoint = std::net::SocketAddr::new(
        configuration["listen_address"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error("desktop-listen-address-unavailable".into()))?,
        configuration["port"]
            .as_u64()
            .ok_or_else(|| Error("desktop-listen-port".into()))? as u16,
    );
    let connection = listener::receive(endpoint)?;
    std::env::set_current_dir("/")?;
    // Before Tokio starts threads; no caller-controlled bus address or injection survives.
    for (name, _) in std::env::vars_os() {
        // SAFETY: The process is still single-threaded here, so no other thread reads the
        // environment.
        unsafe { std::env::remove_var(name) };
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| Error("desktop-worker-runtime-unavailable".into()))?;
    runtime.block_on(async {
        let bus = bus_adapter::bounded(zbus::Connection::system(), 5).await?;
        desktop_worker::run(uid, grant, connection, account.home.into(), bus).await
    })
}
fn main() {
    if let Err(error) = execute() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
