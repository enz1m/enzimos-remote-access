# Desktop listener and firewall lifetime

Reserve the approved endpoint before adding a firewall allowance, and retain it
until allowance removal is confirmed. A port-free probe cannot prevent port reuse
from exposing an unrelated listener during that interval.

## Reservation

The existing fixed Root `ExecStartPre` validates the approved session/network,
binds the exact TCP address and port without address/port reuse, then sends the
listener to PID 1's descriptor store. The unit declares:

- `FileDescriptorStoreMax=1`
- `FileDescriptorStorePreserve=yes`
- `NotifyAccess=exec`

The descriptor has the fixed non-secret name `desktop-listener`; `FDPOLL=0`
prevents automatic disposal on socket error/hangup. A two-second libsystemd
notification barrier is followed by the manager's store-count check: successful
message delivery alone is not acceptance. Only then may the firewall allowance
and compositor grant be created. The Root preparation process retains its local
copy throughout preparation and rollback.

The worker receives exactly one descriptor at FD3 with its own `LISTEN_PID` and
the exact name. It validates Root ownership, TCP stream/listening state, address,
port, IPv6-only behavior and no `SO_REUSEPORT`; it sets CLOEXEC and passes only
that descriptor to the encrypted provider. It never binds a replacement socket.
The existing encrypted-provider PID/executable/cgroup/socket check still decides
whether sharing is actually listening; a reservation alone is not readiness.

## Teardown and uncertainty

The Root stop-post helper removes private approval, revokes compositor authority,
confirms removal of its owned firewall rules, and only then removes the retained
descriptor. Journal entries are not discarded if rule removal remains
unconfirmed. Borrowed rules remain untouched. If either grant cannot be revoked,
firewall/store cleanup is not entered, so uncertainty retains the reservation.

If cleanup is incomplete, revoke capture/input and private approval, retain the
endpoint and its journal, and require fresh explicit cleanup. Only after owned
rule absence is confirmed may the fixed failed unit be reset, verified inactive
with no main/control processes, and have its descriptor store cleaned. Never
clear a firewall journal or retry an uncertain mutation to make status look clean.

## Required installed checks

- Real PID 1 accepts the Root pre-start descriptor and passes the same inode to
  the unprivileged worker; a busy endpoint causes no new allowance.
- Normal public approval, encrypted connection and Stop succeed; no reservation
  or owned rule remains afterward.
- Provider exit, lock and startup failure do not release the endpoint before
  allowance removal. No automatic restart follows traffic.
- Failed/unconfirmed rule cleanup retains the endpoint, revokes private authority,
  reports pending cleanup and refuses stale reuse. Fresh explicit cleanup releases
  it only after rule absence is verified.
- Foreign unit/FD, wrong endpoint/type/ownership, stale session and malformed
  credential cases refuse; existing unrelated listeners/rules remain unchanged.

## Primary references

- [systemd.service: descriptor store and notification access](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
- [sd_notify: FDSTORE, FDPOLL, removal and barriers](https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html)
- [Descriptor store overview](https://systemd.io/FILE_DESCRIPTOR_STORE/)
- [Descriptor passing protocol](https://www.freedesktop.org/software/systemd/man/latest/sd_listen_fds.html)
- [Manager API: CleanUnit](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html)
- [fanotify permission responses and EPERM](https://man7.org/linux/man-pages/man7/fanotify.7.html)
