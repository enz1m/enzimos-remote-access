// SPDX-License-Identifier: MIT
//! Explicit local review followed by fresh approval; only JSON crosses the bus.
use crate::{dispatch, service};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{path::PathBuf, time::Duration};
use zbus::{Connection, Proxy};
pub struct Command {
    pub name: String,
    pub configuration: Option<PathBuf>,
    pub interaction: bool,
    /// The requested state for unattended desktop sharing commands.
    pub unattended: Option<bool>,
}
pub const HELP: &str = "enzimos-remote capabilities|query|query-desktop|review-disconnect|disconnect|review-stop-desktop|stop-desktop|review FILE|apply FILE|review-desktop FILE|apply-desktop FILE|review-unattended-desktop on|off|set-unattended-desktop on|off [--allow-interaction]\n";
pub fn parse(args: &[String]) -> Result<Command> {
    require(!args.is_empty(), "invalid-local-command")?;
    let name = args[0].as_str();
    if matches!(name, "review-unattended-desktop" | "set-unattended-desktop") {
        let mutation = name == "set-unattended-desktop";
        let unattended = match args.get(1).map(String::as_str) {
            Some("on") => true,
            Some("off") => false,
            _ => return Err(Error("invalid-local-command".into())),
        };
        let interaction = match &args[2..] {
            [] => false,
            [flag] if mutation && flag == "--allow-interaction" => true,
            _ => return Err(Error("invalid-local-command".into())),
        };
        return Ok(Command {
            name: name.into(),
            configuration: None,
            interaction,
            unattended: Some(unattended),
        });
    }
    require(
        matches!(
            name,
            "capabilities"
                | "query"
                | "query-desktop"
                | "review-disconnect"
                | "disconnect"
                | "review-stop-desktop"
                | "stop-desktop"
                | "review"
                | "apply"
                | "review-desktop"
                | "apply-desktop"
        ),
        "invalid-local-command",
    )?;
    let mutation = matches!(
        name,
        "apply" | "apply-desktop" | "disconnect" | "stop-desktop"
    );
    let needs_file = matches!(
        name,
        "review" | "apply" | "review-desktop" | "apply-desktop"
    );
    let mut interaction = false;
    let mut configuration = None;
    for arg in &args[1..] {
        if arg == "--allow-interaction" {
            require(mutation && !interaction, "invalid-local-command")?;
            interaction = true;
        } else {
            require(
                needs_file && configuration.is_none() && !arg.starts_with('-'),
                "invalid-local-command",
            )?;
            configuration = Some(PathBuf::from(arg));
        }
    }
    require(
        needs_file == configuration.is_some(),
        "invalid-local-command",
    )?;
    Ok(Command {
        name: name.into(),
        configuration,
        interaction,
        unattended: None,
    })
}
async fn call(connection: &Connection, member: &str, body: Option<Value>) -> Result<Value> {
    let proxy = crate::bus_adapter::bounded(
        Proxy::new(connection, service::NAME, service::PATH, service::NAME),
        2,
    )
    .await?;
    let result: String = match body {
        Some(body) => {
            let body = String::from_utf8(json::canonical(&body)?)
                .map_err(|_| Error("invalid-local-configuration".into()))?;
            require(
                body.len() <= dispatch::MAX_REQUEST,
                "invalid-local-configuration",
            )?;
            tokio::time::timeout(Duration::from_secs(160), proxy.call(member, &body))
                .await
                .map_err(|_| Error("remote-request-outcome-unknown".into()))?
                .map_err(public_bus_error)?
        }
        None => tokio::time::timeout(Duration::from_secs(160), proxy.call(member, &()))
            .await
            .map_err(|_| Error("remote-request-outcome-unknown".into()))?
            .map_err(public_bus_error)?,
    };
    decode_reply(member, result.as_bytes())
}
pub fn decode_reply(member: &str, body: &[u8]) -> Result<Value> {
    let value = json::decode(body, 2 * 1024 * 1024)?;
    if member.starts_with("Review") {
        json::fields(&value, "plan plan_sha256")?;
        require(
            value["plan"]["schema"].as_u64() == Some(1)
                && value["plan_sha256"] == json::fingerprint(&value["plan"])?,
            "remote-reply-invalid",
        )?;
    } else {
        require(value["schema"].as_u64() == Some(1), "remote-reply-invalid")?;
    }
    Ok(value)
}
fn public_bus_error(error: zbus::Error) -> Error {
    if let zbus::Error::MethodError(name, Some(message), _) = error {
        if name.as_str() == "org.enzimos.Remote1.Refused"
            && (1..=96).contains(&message.len())
            && message.as_bytes()[0].is_ascii_lowercase()
            && message
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Error(message);
        }
    }
    Error("operation-unavailable-or-outcome-unknown".into())
}
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid, getuid).")]
pub async fn execute(command: Command) -> Result<Value> {
    if command.name != "capabilities" {
        require(
            (1000..u32::MAX).contains(&unsafe { libc::getuid() })
                && unsafe { libc::getuid() } == unsafe { libc::geteuid() },
            "ordinary-account-required",
        )?;
    }
    let configuration = if let Some(path) = &command.configuration {
        let path =
            std::fs::canonicalize(path).map_err(|_| Error("invalid-local-configuration".into()))?;
        Some(
            json::decode(
                &files::read(&path, 65536, None, false)
                    .map_err(|_| Error("invalid-local-configuration".into()))?,
                65536,
            )
            .map_err(|_| Error("invalid-local-configuration".into()))?,
        )
    } else {
        None
    };
    // Fixed local system socket, independent of DBUS_SYSTEM_BUS_ADDRESS.
    let builder = zbus::connection::Builder::address("unix:path=/run/dbus/system_bus_socket")
        .map_err(|_| Error("remote-provider-unavailable".into()))?;
    let bus = crate::bus_adapter::bounded(builder.build(), 5).await?;
    let desktop = command.name.ends_with("desktop");
    match command.name.as_str() {
        "capabilities" => call(&bus, "GetCapabilities", None).await,
        "query" => call(&bus, "Query", None).await,
        "query-desktop" => call(&bus, "QueryDesktop", None).await,
        "review-disconnect" | "disconnect" | "review-stop-desktop" | "stop-desktop" => {
            let reviewed = call(
                &bus,
                if desktop {
                    "ReviewStopDesktop"
                } else {
                    "ReviewDisconnect"
                },
                Some(value!({"schema":1})),
            )
            .await?;
            if command.name.starts_with("review-") {
                return Ok(reviewed);
            }
            call(&bus, if desktop { "StopDesktop" } else { "Disconnect" }, Some(value!({"schema":1,"plan_sha256":reviewed["plan_sha256"],"allow_interaction":command.interaction,"valid_for_ms":150000}))).await
        }
        "review-unattended-desktop" | "set-unattended-desktop" => {
            let unattended = command
                .unattended
                .ok_or_else(|| Error("invalid-local-command".into()))?;
            let reviewed = call(
                &bus,
                "ReviewDesktopUnattended",
                Some(value!({"schema":1,"unattended":unattended})),
            )
            .await?;
            if command.name.starts_with("review-") {
                return Ok(reviewed);
            }
            call(&bus, "SetDesktopUnattended", Some(value!({"schema":1,"unattended":unattended,"plan_sha256":reviewed["plan_sha256"],"allow_interaction":command.interaction,"valid_for_ms":150000}))).await
        }
        "review" | "apply" | "review-desktop" | "apply-desktop" => {
            let configuration =
                configuration.ok_or_else(|| Error("invalid-local-configuration".into()))?;
            let reviewed = call(
                &bus,
                if desktop { "ReviewDesktop" } else { "Review" },
                Some(value!({"schema":1,"configuration":configuration})),
            )
            .await?;
            if command.name.starts_with("review") {
                return Ok(reviewed);
            }
            call(&bus, if desktop { "ApplyDesktop" } else { "Apply" }, Some(value!({"schema":1,"configuration":configuration,"plan_sha256":reviewed["plan_sha256"],"allow_interaction":command.interaction,"valid_for_ms":150000}))).await
        }
        _ => Err(Error("invalid-local-command".into())),
    }
}
