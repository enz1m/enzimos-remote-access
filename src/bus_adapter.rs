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
pub async fn bounded<T, E, F: Future<Output = std::result::Result<T, E>>>(
    future: F,
    seconds: u64,
) -> Result<T> {
    tokio::time::timeout(Duration::from_secs(seconds), future)
        .await
        .map_err(|_| Error("remote-provider-deadline".into()))?
        .map_err(|_| Error("remote-provider-unavailable".into()))
}
#[derive(Clone)]
pub struct Pinned {
    connection: Connection,
    name: &'static str,
    owner: OwnedUniqueName,
}
impl Pinned {
    pub fn owner(&self) -> &str {
        self.owner.as_str()
    }
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
