# ExitGuard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a cross-platform fixed-egress controller that refuses protected traffic when the required route or OS enforcement is unavailable, with macOS Feilian and Windows Clash adapters.

**Architecture:** A Go standard-library core owns a localhost HTTP/CONNECT proxy, upstream route, expected-IP checks and a strict admission gate. Native platform enforcement restricts selected executable traffic to the guard proxy; a local authenticated control panel configures and reports actual readiness. macOS packages a Swift WebKit shell and Network Extension source; Windows builds the Go binary with persistent WFP filter support.

**Tech Stack:** Go 1.23+ standard library (verified shell toolchain: 1.23.12), HTML/CSS/JavaScript without external assets, Swift/AppKit/WebKit/NetworkExtension on macOS, Windows WFP via native system calls. No Tauri/Electron dependency.

**Spec:** `/Users/zhangchuan/Documents/ExitGuard-design-2026-10-23.md`, copied into this repository's `docs/superpowers/specs/` during setup.

## Global Constraints

- Two devices have independent expected public IPs; Mac uses company Feilian, Windows uses Clash and has no fixed node yet.
- Never promise account-ban prevention. Never label an IP probe as proof that all target processes are protected.
- No changes to Feilian, private company APIs, global proxy, DNS, or default routes; no TLS interception.
- Build and test code now under existing authorization. OS-filter installation, live VPN disconnection and workplace-network-impacting tests are not performed silently.
- Current Mac has no usable developer signing identity. Missing signing/filter/target-client means not ready; do not replace enforcement with process-killing or monitoring.
- Only localhost listeners. Authenticate every control API with a fresh process token; same-origin checks and request-size bounds. No tokens/passwords in logs or exported configuration.
- Production control panel shares the guard's fixed localhost port, with exact Host and origin-form routing to a separate authenticated handler. This supersedes the initial random-control-port plan because the selected browser's OS policy only allows the guard endpoint. Proxy-form requests never receive control-handler privileges.
- Windows real-device tests and Mac signed-extension tests remain explicitly unverified until performed.
- A fixed public IP requires an actual fixed upstream. IP polling has a detection window and cannot prove that an external gateway never changes NAT addresses.

## File Structure and Interfaces

- `cmd/exitguard/main.go`: CLI server/startup/filter subcommands, machine-readable ready URL, graceful shutdown.
- `internal/model/model.go`: shared JSON config/status types.
- `internal/guard/*`: admission gate, localhost proxy, config persistence, route and probe logic, tests.
- `internal/enforce/*`: platform enforcement. Public API:
  - `type Policy struct { Port uint16; Programs []string; BundleIDs []string }`
  - `type Proof struct { Active bool; PolicyHash string; Reason string }`
  - `func Hash(Policy) string`
  - `func Inspect(context.Context, Policy) (Proof,error)`
  - `func Install(context.Context, Policy) error`
  - `func Remove(context.Context, Policy) error`
  - `func Supported() bool`
- `internal/ui/*`: embedded HTML/CSS/JS and authenticated localhost HTTP API.
- `platform/macos/*`: Swift window shell, filter manager CLI, filter extension, entitlements, signing instructions.
- `scripts/*`: local build/package and cross-platform checks; no automatic filter activation.
- `.github/workflows/*`: Windows native compile/tests; no publish/deploy.
- `README.md`, `docs/validation.md`: setup and exact verification evidence/remaining blockers.

`model.Config` fields: `Mode string`, `ExpectedIPs []string`, `ProxyURL string` (localhost http only in Clash mode), `ClashControllerURL string` (localhost), `ClashSelector string`, `ClashNode string`, `TunnelInterface string`, `DNSResolverURL string`, `DNSBootstrapIP string`, `ProbeURL string`, `ProxyPort uint16`, `Programs []string`, `BundleIDs []string`. Secrets are session-memory only in this version, supplied separately, never persisted or echoed. Config JSON uses lowerCamelCase. Default proxy port 17890. Default probe `https://api.ipify.org?format=json`; no expected IP default. Mode default is OS-specific but starts unconfigured.

Core interface to UI: `guard.New(configPath string) (*Service,error)`, `Config() model.Config`, `SaveConfig(model.Config) error`, `Status() model.Status`, `Check(context.Context) error`, `Arm(context.Context) error`, `Disarm()`, `SetSecret(string)`, `Events() []model.Event`, `Run(context.Context) error`. `model.Status` fields `State string`, `Reason string`, `ObservedIP string`, `FilterActive bool`, `PolicyHash string`, `ProxyAddress string`, `Platform string`, `CheckedAt string`. States `unconfigured`, `checking`, `blocked`, `ready`, `armed`, `stopped`; only `armed` admits target traffic. Native filter activation remains explicit CLI, never a UI shortcut that flips a flag.

Implementation rulings: add `ProbeCandidate(context.Context) (string,error)` to identify a route's candidate IP without pretending OS filtering exists; it disarms and cannot transition to ready. Add `Mode="proxy"` for a user-configured fixed local relay; unlike ordinary Clash mode it does not claim controller selection proves inbound binding. Mac unresolved outbound-flow identity is dropped and reported, with deployment disclosure about possible collateral denial. See WORKLOG.md for reasons.

## Review Focus

1. A denied or missing OS proof cannot be replaced by an optimistic UI checkbox; target proxy stays closed (Task 1).
2. A malicious webpage must not reconfigure the localhost service through CSRF or DNS rebinding (Task 4).
3. Killing proxy/upstream/interface must close active tunnels and deny new connections, with no direct retry (Task 2).
4. A policy change, interface reuse, dynamic Clash subgroup, or reconnect invalidates readiness (Tasks 1–3).
5. IPv6/UDP/DNS and helper-process paths must not escape declared coverage; unimplemented paths are blocked/unsupported (Tasks 2–3).

### Task 1: Shared configuration and admission state

**Files:** `go.mod`, `internal/model/model.go`, `internal/guard/service.go`, `internal/guard/config.go`, matching tests.

- [ ] Write tests asserting missing expected IP, missing targets, absent filter proof, mismatched policy hash and failed probe cannot arm; config changes immediately disarm.
- [ ] Run those tests before implementation and record the failure.
- [ ] Implement validation, atomic permission-restricted config persistence, bounded redacted events, injectable route/enforcement dependencies and status snapshot locking. No persisted `armed` state.
- [ ] Rerun tests and `go test -race ./internal/guard/...`; shutdown closes owned connections and startup remains closed.
- [ ] Commit task files after integration tests pass (only implementer-owned files).

### Task 2: Fail-closed route and proxy

**Files:** `internal/guard/proxy.go`, `route.go`, platform socket-binding files, `clash.go`, `probe.go`, associated tests.

- [ ] Add local-network integration tests: CONNECT only admitted after valid proof, origin request untouched, failed upstream never calls direct dialer, disarm closes established tunnels, malformed/oversize request rejected.
- [ ] Clash mode: only dial the configured localhost upstream; validate a dedicated selector's exact leaf node, reject DIRECT/REJECT/dynamic/nested groups; never mutate unrelated groups. Watch changes and fail closed; document the polling window.
- [ ] Mac Feilian mode: every outbound IPv4/IPv6 socket binds to a user-confirmed tunnel index using IP_BOUND_IF/IPV6_BOUND_IF before connect. Binding/interface failure is terminal; no unbound fallback. Resolve targets via HTTPS DNS with a literal bootstrap address over the same bound path, not the system resolver. If implementation cannot safely support a family, reject it explicitly.
- [ ] Probe public IP over the exact owned route; compare normalized IPs against explicit expectations. Interface fingerprint changes, selector changes, probe errors or mismatch disarm and close connections.
- [ ] Verify local deterministic tests and race tests. Do not run a live company-VPN disconnection test.

### Task 3: Native process enforcement

**Files:** `internal/enforce/*`, `platform/macos/FilterDataProvider.swift`, `FilterManager.swift`, bundle templates and entitlements, platform tests.

- [ ] Write policy hashing/validation tests including duplicate/case-sensitive paths, empty target list, invalid port, nonabsolute paths, and policy changes.
- [ ] Windows: implement persistent WFP filters in the product's own provider/sublayer, with transactions and stable identifiers. Selected executable flows must be restricted to TCP 127.0.0.1 at the guard port; block other IPv4 destinations/ports/protocols and all IPv6 until an explicitly supported IPv6 local listener exists. Read back exact rules to attest; do not use broad firewall resets or block-all/allow-rule precedence assumptions.
- [ ] Make install/remove explicit elevated CLI operations, limited to this product's rules. Inspect only reports active after matching actual OS filters; no receipt-file-only proof.
- [ ] Mac: implement NEFilterDataProvider restricted to explicitly selected application identities/paths and TCP loopback guard port; deny other protected flows. Manager inspects enabled configuration and exact policy hash. Unsigned/unavailable manager or extension returns inactive. Never imply ad-hoc signing enables NE.
- [ ] Compile Windows code with `GOOS=windows GOARCH=amd64 go build`; compile Swift components against available SDK. Report runtime paths untested. Include exact signing/deployment prerequisites; do not install filters.

### Task 4: Local control panel and launch setup

**Files:** `internal/ui/*`, `cmd/exitguard/main.go`, `platform/macos/App.swift`, build scripts, UI tests.

- [ ] Add HTTP tests for missing/wrong token, foreign Origin/Host, request bounds, config validation, secret exclusion, and never trusting client-supplied active/protected flags.
- [ ] Implement a polished Chinese control panel: platform/source, expected and observed IP, readiness reason, target executable configuration, diagnostics, enable/disable controls, bounded events, clear required setup actions. External assets and analytics prohibited.
- [ ] Bind control server to 127.0.0.1 random port, expose random token only in launch URL fragment and required API bearer header, keep token out of logs. Escape all config/events when rendering.
- [ ] Protected browser launch uses explicit local proxy and separate profile, with no DIRECT fallback; only allow launch while armed. Existing ordinary browser processes are not repurposed. Explain that OS filtering by executable may affect all instances of the same executable; refuse automatic protection if scope cannot be isolated safely. Missing Claude client is a setup blocker, not a fake launch success.
- [ ] Package Mac local `.app` with WebKit shell and Go binary. Build Windows executable that opens its own local panel; provide native platform CI for actual builds/tests. Do not call a cross-compiled build fully tested.

### Task 5: Integration, review, and delivery

- [ ] Run `go test ./...`, `go test -race ./...`, `go vet ./...`, native Mac compile and Windows cross-compile; fix actual failures before expanding tests.
- [ ] Smoke-test only local endpoints/app UI in unconfigured state; verify missing OS filter and missing fixed IP prevent protected launch and proxy connections.
- [ ] Fresh reviewer checks network fallback, enforcement authenticity, subprocess/security boundaries, platform build behavior and stated limitations; resolve actionable defects.
- [ ] Copy approved spec into repo, document executable outputs, signing and fixed-node blockers, and tests not performed. Package build artifacts without secrets.
- [ ] Deliver the current built app and source with explicit statement that system protection remains inactive until required platform installation and real-device validation are complete. Do not mark entire strong-protection goal complete while those dependencies remain.

## Execution authorization

User approved the strong-protection direction and requested implementation. Use Astra/Sol delegation under the standing workflow; no second plan-approval gate is needed. Only privilege-bearing deployment or live disruptive tests wait until concrete artifacts are ready for review.
