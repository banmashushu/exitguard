# Honor subscription-node certificate settings

The user explicitly superseded the earlier keep-verification preference: support the pictured nodes directly, with no extra confirmation switch. Honor the node's declared `skip-cert-verify` / native-converted `allowInsecure` setting. A missing or false flag retains the core's normal verification. This change is restricted to the subscription leaf and does not change final-proxy TLS, secure DNS, target probes, final-IP verification, or the existing endpoint/file/routing boundaries.

Global TLS disable and a new per-subscription permission schema are unnecessary for this request. Preserve the requested option in the existing private canonical configuration and identity; display its effect as node metadata, not as a new gate. Old rejected snapshots have no connection configuration and need a successful refresh.

- [x] Regression tests cover explicit true, false/default isolation, aliases, invalid values, private storage and core propagation.
- [x] Preserve the requested certificate option in native and legacy conversion while checking invalid TLS and other node capabilities.
- [x] Label eligible nodes that request skipped verification and tell users when old snapshots need re-importing.
- [x] Verify both certificate behaviors with the packaged Mihomo core and a local self-signed fixture. The full Go suite, vet, frontend checks and Mac package verification passed.
- [x] Back up and install the Mac update. The installed executable matches the verified bundle.
- [ ] Refresh the saved subscription through its configured active route. The existing fixed proxy failed two SOCKS5 handshakes, so the application preserved the old snapshot and showed the new refresh guidance. Real node eligibility remains pending a successful download.

No source URLs, credentials, raw provider configurations or raw core errors are printed. Do not commit, upload, or change system networking.
