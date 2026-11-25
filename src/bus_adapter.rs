// SPDX-License-Identifier: MIT
//! A provider's well-known name never grants authority after its owner changes.
use enzimos_platform::{Error, Result, require};
use std::{future::Future, time::Duration};
use zbus::{
    Connection, Proxy,
    fdo::DBusProxy,
    names::{BusName, OwnedUniqueName},
    zvariant::{DynamicDeserialize, DynamicType},
};
/// Await `future` for at most `seconds`.
///
/// # Errors
///
/// Fails when the deadline passes or the call fails.
pub async fn bounded<T, E, F: Future<Output = std::result::Result<T, E>>>(
    future: F,
    seconds: u64,
) -> Result<T> {
    tokio::time::timeout(Duration::from_secs(seconds), future)
        .await
        .map_err(|_| Error("remote-provider-deadline".into()))?
        .map_err(|_| Error("remote-provider-unavailable".into()))
}
/// A system bus service pinned to the unique name that owned it when opened.
#[derive(Clone)]
pub struct Pinned {
    connection: Connection,
    name: &'static str,
    owner: OwnedUniqueName,
}
impl Pinned {
    /// Unique name of the pinned owner.
    pub fn owner(&self) -> &str {
        self.owner.as_str()
    }
    /// Pin the owner of `name`, activating it if needed.
    ///
    /// # Errors
    ///
    /// Fails when `name` is not an allowed service or is unavailable.
    pub async fn new(connection: Connection, name: &'static str) -> Result<Self> {
        require(
            matches!(
                name,
                "org.freedesktop.systemd1"
                    | "org.fedoraproject.FirewallD1"
                    | "org.freedesktop.login1"
            ),
            "remote-provider-name",
        )?;
        let daemon = bounded(DBusProxy::new(&connection), 2).await?;
        let owner = bounded(
            daemon.get_name_owner(
                BusName::try_from(name).map_err(|_| Error("remote-provider-name".into()))?,
            ),
            2,
        )
        .await?;
        Ok(Self {
            connection,
            name,
            owner,
        })
    }
    /// Pin the owner of `name` only when it is already running.
    ///
    /// # Errors
    ///
    /// Fails when `name` is not an allowed service or the bus fails.
    pub async fn if_running(connection: Connection, name: &'static str) -> Result<Option<Self>> {
        let daemon = bounded(DBusProxy::new(&connection), 2).await?;
        let bus_name = BusName::try_from(name).map_err(|_| Error("remote-provider-name".into()))?;
        match tokio::time::timeout(Duration::from_secs(2), daemon.get_name_owner(bus_name)).await {
            Ok(Ok(owner)) => Ok(Some(Self {
                connection,
                name,
                owner,
            })),
            Ok(Err(zbus::fdo::Error::NameHasNoOwner(_))) => Ok(None),
            _ => Err(Error("remote-provider-unavailable".into())),
        }
    }
    /// Require that the owner has not changed.
    ///
    /// # Errors
    ///
    /// Fails when the owner changed.
    pub async fn recheck(&self) -> Result<()> {
        let daemon = bounded(DBusProxy::new(&self.connection), 2).await?;
        let actual = bounded(
            daemon.get_name_owner(
                BusName::try_from(self.name).map_err(|_| Error("remote-provider-name".into()))?,
            ),
            2,
        )
        .await?;
        require(
            actual == self.owner,
            "remote-provider-owner-changed-no-retry",
        )
    }
    /// Call `method` on the pinned owner.
    ///
    /// # Errors
    ///
    /// Fails when the owner changed or the call fails.
    pub async fn call<B, R>(&self, path: &str, interface: &str, method: &str, body: &B) -> Result<R>
    where
        B: serde::Serialize + DynamicType,
        R: for<'d> DynamicDeserialize<'d>,
    {
        self.recheck().await?;
        let proxy = bounded(
            Proxy::new(&self.connection, self.owner.as_str(), path, interface),
            2,
        )
        .await?;
        let result = bounded(proxy.call(method, body), 5).await?;
        self.recheck().await?;
        Ok(result)
    }
}
