# Current desktop sharing

The system-bus service is `org.enzimos.Remote1`, object
`/org/enzimos/Remote1`, interface `org.enzimos.Remote1`. Methods return one bounded
JSON string. Every request has `schema: 1`; extra fields are refused. Use
`GetCapabilities` before offering a protocol. Remote login and RDP are separate
capabilities and remain unavailable.

The [listener lifetime contract](LISTENER_LIFETIME.md) reserves the endpoint
before firewall admission and retains it through uncertain cleanup. `QueryDesktop`
reports `endpoint_reserved` and `cleanup_pending`; neither proves a working
encrypted provider. Validate installed lifecycle behavior against matching
service, compositor and provider versions before deployment.

## Configure

`ReviewDesktop` accepts `{schema, configuration}`. Configuration is:

```json
{
  "schema": 1,
  "enabled": true,
  "mode": "session-sharing",
  "listen_address": "192.0.2.1",
  "port": 5900,
  "allowed_networks": ["192.0.2.0/24"],
  "view_only": true,
  "max_fps": 15,
  "output": null
}
```

Choose a currently assigned, explicit address and matching client networks; there
is no wildcard exposure. `max_fps` is bounded and `output` optionally names a
current output. The example address is documentation, not a default. There is no
session-sharing autostart: locking, leaving or closing the session ends sharing.

The response contains `plan` and `plan_sha256`. Show its security and stop
consequences before calling `ApplyDesktop` with the same configuration,
`plan_sha256`, `allow_interaction: true` and `valid_for_ms` (1,000–150,000).
Administrator authentication is fresh, never cached by this service. Cancellation,
caller disappearance, deadline expiry or changed session/process/configuration
invalidates approval. A lost response means the outcome must be queried; do not
replay the mutation automatically. Changing configuration disconnects existing
desktop clients. It does not disconnect SSH clients.

`QueryDesktop` takes no arguments and reports configuration, actual verified
listener status, unit state and lifecycle consequences. Do not equate an active
systemd unit with a working listener. Missing providers and uncertain state must
remain visible. `ReviewStopDesktop` accepts only `{schema: 1}`; send the returned
digest to `StopDesktop` with the interaction/deadline fields. Stopping sharing
closes desktop connections and preserves SSH sessions.

`QueryDesktop.viewers` is `{status: "available", connected_count, clients}` when
the observation succeeds. Each client has a provider ID, address and username
(the latter two may be null). These are display-only values, never authorization
subjects. WayVNC's `client-list` enumerates initialized, authenticated clients;
pending TCP/TLS handshakes are not viewers. Observations use the current grant's
private control socket and require its kernel peer to be the retained installed
WayVNC process in the approved service cgroup. Replies are bounded to 64 clients,
64 KiB and one second. Failure returns `status: "unavailable"` with null count
and clients. An inactive service with no process reports zero.

A successful query registers its unique bus sender for the bodyless, directed
`DesktopChanged()` invalidation signal on the same object/interface. The service
checks changes every two seconds, reauthenticating each sender, and tracks at most
eight observers. Subscribe before querying, then requery on invalidation. Changes
to configuration, listener, lifecycle, uncertainty or viewer details invalidate
the result. Also invalidate on service owner loss/replacement; the service retains
its normal idle exit, so visible consumers should refresh periodically (for example
every ten seconds). Signals carry no account, address or credential data. Viewer
changes are deliberately excluded from reviewed mutation digests.

## Credentials and transport

WayVNC offers encrypted VeNCrypt X509Plain only. No unauthenticated, legacy DES
or plaintext fallback is enabled. The private owner files are under
`~/.local/share/enzimos/remote-desktop`; use the library's bounded, ownership-checked
`desktop_identity.read` to obtain the certificate fingerprint and generated
sharing password. These are separate from the administrator and disk passwords.
The service never puts the password in process arguments or public status.
Reveal/copy credentials only as an explicit local owner action; never log them.
Clients must verify the displayed certificate fingerprint. An incomplete identity
is refused rather than silently rotated.

The process runs as the verified desktop owner. Root approves an immutable
run-only systemd credential; capture remains unprivileged. Logind and the exact
compositor/socket identity are checked before and during the session. The event driven
firewall guard revokes sharing when scoped leases or firewalld authority disappear.
An installed firewall reload ended both an existing TLS client and the listener.

## Acceptance boundaries

Package14/source `0f831b0` passed an actual encrypted installed guest: native PAM
and two administrator approvals, decoded Full HD desktop capture, view-only
input refusal, remote input into the focused native Terminal and lock revocation
of the listener and existing TLS client. The decoded image and lock UI were
reviewed. The initial flat frame was followed by a bounded wait for actual pixels.

This used a private desktop overlay and loopback. It does not qualify a new
consistent default image, physical LAN, remote login, RDP or the Settings UI.
Package18 also passed broad-port, trusted-interface and source-zone negative
controls, retained capture/input/lock gates, and actual firewall reload revocation.
Package19 passed missing-provider/unavailable and signed-provider/available checks.
These remain private installed fixtures, not default-image acceptance.

## Firewall metadata authority

The sharing worker has no local seat, so firewalld does not normally authorize
its configuration-info reads. The packaged polkit rule permits only that read-only
action from the Root-managed `enzimos-desktop-sharing@UID.service` system unit
with `NoNewPrivileges` enabled. User units cannot satisfy this system-unit identity.
Firewall writes retain ordinary administrator authorization. The rule exposes
firewall metadata to the sharing unit, not credentials or configuration mutation.
The live guard subscribes before its initial read, rejects missing leases, and
stops on policy/provider changes; it does not poll. Native acceptance verified the actual worker unique bus owner against its
Root system unit MainPID/start ticks: read-only configuration-info was allowed
and configuration mutation was refused. The earlier read-denial is retained.
