# Windows / Mihomo Party Starter Plan

**Goal:** Give the user a safe, easy first Windows run: collect only the environment facts needed to configure ExitGuard, without installing filters or reading subscriptions/credentials.

**Authorization:** User changed priority to Windows and identified Mihomo Party. Existing strong-protection objective remains; this step is diagnostic preparation, not completed enforcement. Mac/NetDetour installation is not authorized and must not occur.

**Architecture:** Add an isolated read-only `doctor` CLI command and a Windows starter archive. Include an unapplied, tested Mihomo Party JavaScript override example for a future explicit fixed leaf node and dedicated loopback listener. Keep all current guard and enforcement gates unchanged.

## Interfaces and file ownership

- `internal/diagnostics/`: `Collect(context.Context) Report`, structured report with schema version, timestamp, platform/architecture, narrowly collected OS/BFE/elevation status, whitelisted relevant application facts, and bounded loopback port reachability.
- `cmd/exitguard/`: parse `doctor [--output PATH]` before loading any guard configuration. No `guard.New`, filter install/remove, proxy mutation, auto elevation, shell profile or public requests in this path.
- `platform/windows/starter/`: numbered CMD launchers and a short Chinese guide.
- `examples/mihomo-party-exitguard.js`: pure `main(config)` override, no network/credential access. Leaves existing rules/proxies/groups untouched and only adds `exitguard-in` HTTP listener on `127.0.0.1:17891`, `users: []`, `proxy` directly referencing the named leaf. Empty target is a no-op; reject DIRECT/REJECT/groups and conflicting listeners. Do not auto-import.
- `scripts/package-windows-starter.sh`: cross-build and package exe, launchers, guide, and example. `dist/ExitGuard-Windows-MihomoParty-starter.zip` is a new artifact; preserve previous development packages.

## Constraints

- No subscription URLs, tokens, passwords, proxy-node lists, browsing history, public/private network interface addresses, computer/domain names or complete environment dump.
- App discovery is a narrow allowlist (Mihomo Party/Clash Party, Claude, Chrome, Edge); never dump other installed apps or process command lines. Redact user-profile path prefixes in shareable reports. Preserve actual full paths only transiently if needed for local checks.
- Local TCP reachability probes only: literal `127.0.0.1`, short timeout, small fixed port list (7890, 7891, 7892, 7897, 9090, 17890, 17891). Send no protocol bytes/auth and never claim a listening port identifies its service.
- Windows metadata queries are read-only. Access denied becomes unknown; do not elevate automatically or change services/settings.
- No output flag means JSON to stdout; explicit output writes only that report with restricted permissions where supported. Report never claims protection is active.
- No fixed proxy or Claude login is required for diagnostics. The user need only run the first CMD file on Windows normally and review/share the generated report.

## Tasks

1. Write meaningful tests for redaction/whitelisting, localhost-only bounded probes, missing platform data, and `doctor` not loading malformed guard configs or entering privileged operations. Run RED then implement.
2. Add native Windows collection with standard library; non-Windows clearly reports unsupported Windows fields. Run portable tests, race and vet, and cross-build Windows. Do not call cross-build a native runtime test.
3. Test override semantics with Node: no-op default, preserves unrelated configuration, idempotence, refuses a group/built-in or conflicting port/name, rejects invalid target. Build pure example.
4. Create starter launchers: first read-only diagnosis, second opens existing panel. Neither installs filters, changes execution policy, clears rules, edits registry or imports the override.
5. Fresh scoped review, root verification, package archive listing/integrity, clear remaining Windows runtime and static-exit prerequisites in the guide.

## Official references

- https://clashparty.org/docs/guide/override
- https://clashparty.org/docs/guide/override/javascript
- https://wiki.metacubex.one/en/config/inbound/listeners/http/
- https://wiki.metacubex.one/en/config/inbound/listeners/
