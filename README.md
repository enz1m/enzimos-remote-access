# enzimOS Remote Access

Remote Access lets an enzimOS machine host SSH and SFTP connections or share its
active Wayland desktop over encrypted VNC. Hosting is off by default. The service
manages its own OpenSSH instance and firewall rules, so an existing system SSH
configuration stays intact.

## Hosting a connection

Run `enzimos-remote capabilities` on an installed system to see which providers
are available. Use `enzimos-remote query` for SSH status and
`enzimos-remote query-desktop` for desktop sharing status.

For SSH, review the configuration with `enzimos-remote review FILE`, then apply
it with `enzimos-remote apply FILE --allow-interaction`. Choose the local
addresses to listen on and the client networks to allow. SSH uses key
authentication by default. Account password authentication is an explicit option.
Review records the interface, firewall zone and NetworkManager connection of each
listen address. SSH starts at boot only on that same network, and starts later if
the network connects after boot. Autostart requires a NetworkManager connection.
A firewall guard restores the SSH allowance after a firewalld reload or restart.
It checks the approval and the reviewed network on every firewalld or
NetworkManager change and at least every 15 seconds. While the listen address
is off the reviewed network, the firewall refuses new SSH connections. If it is
still off after 20 seconds, the guard stops SSH, and SSH starts again once that
network returns.
While firewalld is stopped or not answering, SSH keeps listening only on its
approved addresses and accepts connections from any network, and the guard
still stops it when the listen address leaves the reviewed network. See
[SSH approval state](docs/SSH_APPROVAL_STATE.md) for upgrade and downgrade behaviour.
Turning off the listener preserves established SSH sessions. Use
`review-disconnect` and `disconnect` to close them separately.

For desktop sharing, use `review-desktop FILE` and
`apply-desktop FILE --allow-interaction`. WayVNC runs as the desktop owner and
uses a separate sharing password and TLS certificate. You can grant view-only
access or allow input. Sharing ends when the session locks, becomes inactive or
logs out. With `set-unattended-desktop on --allow-interaction`, approved while
sharing runs, it starts again by itself after sign-in or unlock on the reviewed
network; it never runs before sign-in. Its firewall allowance follows firewalld
reloads, stops and restarts in the same way as SSH. To stop it yourself, use `review-stop-desktop` and
`stop-desktop --allow-interaction`. This closes desktop connections and leaves
SSH sessions running.

Separate remote desktop login and RDP are unavailable in this release. See the
[desktop sharing guide](docs/DESKTOP_SHARING.md), the
[listener lifecycle](docs/LISTENER_LIFETIME.md) and the
[optional RDP provider design](docs/RDP_PROVIDER.md) for implementation details.

## Build and test

Requires Linux, Rust 1.95 or newer, and OpenSSL development libraries.

```sh
cargo build --release --locked
cargo test --locked
```

The [packaging directory](packaging/) contains the systemd units, D-Bus policy,
polkit rules and firewall policy. Cargo tests use private buses, temporary state
and fixture processes. Use a disposable guest to validate installed hosting,
authorization, capture and network behavior.

## License

[MIT](LICENSE)
