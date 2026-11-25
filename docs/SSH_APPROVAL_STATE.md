# SSH approval state

Root keeps the SSH approval in `/var/lib/enzimos/remote/ssh/`.

| File | Contents | Read by |
| --- | --- | --- |
| `approval.json` | Schema 1: `schema uid phase boot_id configuration detail`, exactly these fields | Every release |
| `approval-network.json` | Schema 1: `schema approval_sha256 network` | Releases with network review |
| `resume.json` | Schema 1: `schema boot_id`, written when the firewall guard stopped SSH this boot | Releases with network review |

`approval-network.json` holds the reviewed network identity: per listen
address, its interface, firewalld zone and NetworkManager connection UUID.
`approval_sha256` binds it to the `uid`, `boot_id` and `configuration` of
`approval.json`. A sidecar whose binding does not match, whose schema is
unknown, or which is not valid JSON is ignored. A bound sidecar whose identity
does not describe the approved listen addresses is refused.

## Upgrade

- A schema-1 approval without a matching sidecar is an approval made before
  network review. It starts SSH as before, including autostart on later boots.
  When SSH starts outside a configuration transaction with firewalld running
  and every listen address on an identified NetworkManager connection, the
  network it runs on is recorded in the sidecar. `approval.json` is not
  rewritten. From then on SSH starts only on that network.
- A schema-2 `approval.json` written by pre-release builds, which carries a
  `network` field, is read. The next start or configuration change rewrites it
  as a schema-1 record and a sidecar.
- New approvals are always written as a schema-1 record and a sidecar, the
  sidecar first. An interrupted write leaves the previous approval without a
  network identity, never with another approval's.

## Downgrade

- A release without network review reads `approval.json` unchanged and
  ignores the other files, so SSH keeps starting with the same approval.
- When that release writes a new approval, the sidecar no longer matches and is
  ignored after the next upgrade. The approval is treated as one made before
  network review, as described above.
- A schema-2 `approval.json` left by a pre-release build is refused by
  releases without network review. Start SSH once with a current release, or
  apply the configuration again, before downgrading.
