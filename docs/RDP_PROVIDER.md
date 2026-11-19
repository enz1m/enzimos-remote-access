# Optional RDP provider integration

RDP is unavailable. The source contains optional provider and protected-descriptor
integration work; it does not establish a qualified desktop-sharing or remote-login
implementation. Keep capability reporting false until the paired provider,
credential transport, compositor admission and installed tests all agree.

## Credential and process requirements

- Use a separate generated sharing identity. Administrator approval authorizes
  exposure; it does not disclose the administrator or disk password to clients.
- KRDP's configured users are read through QtKeychain. Integrate the existing
  login-unlocked Secret Service, or a separately audited protected credential
  input. Never use the README's password command-line example.
- Keep `SystemUserEnabled=false` for sharing. KRDP's PAM authentication/account
  checks do not open an account-bound desktop session and cannot qualify login.
- Require explicit address and client-network restrictions, validated TLS
  identity, fresh administrator approval and one Root-managed fixed unit for
  the authenticated local desktop owner. Reuse the approved-session, firewall
  lease and shutdown contracts in `DESKTOP_SHARING.md`.
- Keep the provider optional. Package the required server/library files and
  licences; omit KDE's settings application and desktop entry. Do not add a
  foreign GUI settings application or the entire Plasma desktop to the seed.
- No sharing autostart. Lock, logout, compositor replacement, approval expiry,
  provider loss and firewall reload must terminate the existing connection and
  revoke capture/input admission. A successful login alone is not sufficient.

## Installed acceptance before availability

Use a disposable installed guest with exact source and runtime receipts:

1. Provider absent, untrusted or ABI-incompatible: capability remains false.
2. Native approval cancellation and changed caller/session: no listener or lease.
3. Actual FreeRDP connection: decode a nonempty frame and verify the offered TLS
   fingerprint; input reaches only the approved session.
4. View-only grant, rejected devices and wrong credentials cannot inject input.
5. Lock and firewall reload end the client, listener and public capture grant.
   Observe complete systemd cleanup within its declared stop limit.
6. A fresh approved session after unlocking works; the old client cannot resume.
7. Malformed/provider-failure paths clean private credentials and owned firewall
   leases, preserve SSH connections and never enable account-bound remote login.

Producer portal tests establish a useful seam; they do not replace these server,
credential, packaging and native client tests.
