# ExitGuard execution ledger

2026-10-26 proxy-first direction: user explicitly asks that the app itself serve as the proxy. Implement direct HTTP/HTTPS/SOCKS5 upstream support and an explicitly labeled proxy-only mode, independent of optional strict OS enforcement. Keep old strict configs strict; do not fake system protection. Plan: `docs/superpowers/plans/2026-10-26-proxy-first.md`. No vendor installs, corporate routing changes, paid accounts or credentials requested for development.

Proxy-first implementation and independent review complete for ordinary forwarding: authenticated HTTP/HTTPS/SOCKS5 route, in-memory endpoint-bound credentials, explicit proxy_ready/proxy_active without OS proof, preserved required-mode migration, cancellation/revision guards, and usable UI/launch workflow. Real local Service.Run/Arm integration proves HTTP/HTTPS forwarding and same-route DoH without a successful fake OS proof. Root full Go tests/race/vet + frontend + override tests passed. Actual third-party proxy and Claude/Windows behavior remain untested; strict full-traffic protection is still not complete. Build and visual QA evidence follows in delivery record.

Proxy-first delivery: Mac app and Windows x64 binaries rebuilt, code signature and starter ZIP checked. Native Mac UI reopened and inspected: default remote/proxy-only, protocol/host/port/session-credential/expected-IP controls visible, no automatic OS activation. New release archives use `-proxy` names. Quick start is `docs/proxy-quickstart.md`; independent review is preserved in `docs/reviews/2026-10-26-proxy-first-review.md`.

2026-10-26 browser scope confirmed: user wants both Chrome and Edge protected, in addition to Claude Desktop, on the Windows-first path. All instances of each selected browser executable are within OS-rule scope; separate user-data directories isolate browser data, not the OS filtering identity. Do not silently choose only one browser. Actual Windows paths/report and fixed-upstream credentials remain unavailable; no rules have been deployed. Existing launcher supports both browser executables, but full protection and any required chained upstream remain subject to configuration and real-device validation.

Latest steering (2026-10-24): user switched to Windows first; client is Mihomo Party (version not yet known). Mac preparation stays read-only; no consent to install NetDetour. Prepare a read-only Windows diagnostic/starter package under `docs/superpowers/plans/2026-10-24-windows-starter.md`. Static proxy is still pending; do not claim enforcement ready.

Windows starter delivery: isolated `doctor` command and numbered starter launchers implemented. Diagnostics use only allowlisted running-process metadata and seven literal loopback TCP probes; no subscription/config reads, public probes or system changes. Removed environment-based candidate file scans after review identified UNC/mapped-network side effects. Metadata is labeled limited/unknown, protection is not assessed. Optional Mihomo override is unapplied and defaults to no-op. Root independently reran full Go tests/race/vet, both Node suites, Windows cross-build/package and ZIP integrity successfully. Windows native runtime remains to be performed by the user; first action is ordinary `1-check-environment.cmd` with Mihomo Party open, without launching Claude or installing filters.

2026-10-24 steering: user prioritizes Mac and has no Apple developer signing account. Read-only inventory still finds CorpLink but no Claude Desktop. Evaluating an already-signed vendor backend before extending undeployable native code; no third-party filter installation authorized/executed yet. Details: `docs/macos-priority.md`.

Plan: `docs/superpowers/plans/2026-10-23-exit-guard.md`

User approval: 2026-10-23, strong disconnection blocking on Windows+macOS, separate fixed exits.

## Rulings

- New standalone repository on `codex/exit-guard`; no existing checkout to isolate or baseline application tests to run.
- Astra owns architecture and review, Sol owns implementation/test. Delegate nonoverlapping core, OS filtering and UI packages with explicit contracts; root alone handles git commits to avoid shared-index conflicts.
- Go standard library + a lightweight macOS shell replaces Tauri after checking available toolchain. This changes implementation tooling, not required protection scope.
- Missing Mac signing credentials, fixed upstream and Windows machine are real deployment/validation blockers. Keep code paths closed; do not add an override that falsely marks enforcement active.
- Do not run OS filter install/remove, disconnect Feilian, or change global routes during local development.
- Verified active shell Go is 1.23.12, despite earlier inventory report of 1.27.2. Use Go 1.23 standard library; avoid unnecessary toolchain downloads.
- Browser protection is opt-in by executable. UI must disclose all windows of that executable are filtered, while protected launches use a separate profile. Do not implement launch as permanently unsupported merely because the default Chrome is shared; user must explicitly select a supported program.
- Add `mode=proxy` for an explicitly configured fixed localhost relay (including a Mihomo listener bound directly to one concrete node). Public Clash API lacks enough evidence to infer listener-to-node binding, so ordinary Clash inspection cannot pretend to lock the upstream. No mutations to unrelated Clash rules.
- Candidate IP probing is allowed without OS enforcement, but always leaves the admission gate closed and never automatically approves an expected IP.
- Mac strict filtering drops an outbound socket flow if its process cannot be safely identified. This is stronger than fail-open but may affect unidentified non-target traffic; activation must disclose that scope and be tested before production use. No such filter is currently installed.
- Control UI shares the guard's fixed localhost port in production: origin-form requests with the exact local Host go to the authenticated control handler; CONNECT/absolute-form remain gated proxy traffic. This avoids locking the user out when the default browser is itself protected, without adding another OS-allowed endpoint. CLI only announces readiness after listener ownership succeeds.
- First version forwards target IPv4 TCP only. Target IPv6 and UDP are rejected rather than assuming an IPv4 probe validates them. Both routes resolve A records through HTTPS DNS using the same selected upstream; editable default Cloudflare DoH (1.1.1.1 bootstrap), never system DNS. This narrows protocol support without weakening enforcement.
- Review rulings: use providerless persistent WFP sublayer/filters to avoid conflicting Microsoft text on nil-service providers; preserve strict GUID/metadata ownership and actual rule readback. No Windows service or extra dependency added. Runtime reboot evidence still missing.
- Review findings fixed/in progress: full Mac Mach-O helper enumeration, invalid-signature identity rejection, target inbound-flow rejection, portable Windows test fixtures, Chromium resolver mapping with exact loopback exclusion, immediate UI pause during long operations.
- Unresolved strong-goal coverage: delegated Windows system-service DNS and newly introduced helper executables during app updates are not fully covered by static per-executable policies. Do not mislabel these as mere testing gaps or claim the complete strong-protection objective achieved. Deliverable is an unactivated development build pending further coverage engineering and deployment validation.

## Interface/preflight check

| Tasks | Boundary | Decision |
|---|---|---|
| 1,2 | Shared guard state / route engine | One core implementer owns both; review as admission + transport |
| 1,3 | enforce.Policy / Proof / functions | Native implementer creates API first; guard imports it |
| 1,4 | model types and Service methods | Core creates shared types first; UI follows exact signatures |
| 3,4 | elevated CLI vs local API | Native operations only explicit CLI; no unauthenticated install route |
| 1 | tests vs persistence | state never persisted, secrets memory-only |
| 2 | fixed upstream vs monitoring | polling limitations stated; sockets never use unbound fallback |
| 3 | active filters vs proof | read OS configuration, never trust receipt or UI input |
| 4 | browser profile vs executable filtering | report scope; do not launch normal browser as protected |
| 5 | local tests vs real platform | do not claim runtime verification from cross-build |

## Tasks

- Task 1/2: source and local tests complete — state/config, owned proxy, route checks; full system-service coverage remains open.
- Task 3: source, native compile and deterministic tests complete — Windows WFP and Mac filter/manager. No OS activation or live platform network verification.
- Task 4: source/build/UI QA complete — authenticated control, launch configuration and packaging. Mac actual unconfigured state and failed-action recovery verified.
- Task 5: independent security review and local tests complete for development delivery. Production strong-protection acceptance remains blocked by the explicitly documented implementation gaps, signing, fixed upstream and platform/client tests.

Final root verification: `go test ./... -count=1`, `go test -race ./... -count=1`, `go vet ./...`, frontend Node regression, Windows cross-build, Mac app build and native Swift filter build/tests all exit 0. No system filters installed, no VPN disruption. Source review fixes incorporated; strict filterBrowsers=false checks retain documented SDK deprecation warnings.
