# Proxy-first ExitGuard Implementation Plan

> **For agentic workers:** Apply the standing Astra/Sol workflow and test-driven implementation; work only within the assigned package boundaries. Steps use checkbox syntax for tracking.

**Goal:** Make ExitGuard a usable local HTTP/CONNECT proxy that can connect directly to an authenticated remote HTTP, HTTPS or SOCKS5 proxy, independently of optional OS-level enforcement.

**Architecture:** Keep the existing localhost listener and bounded forwarding gate. Introduce explicit proxy-only and required-enforcement modes, plus a remote-upstream route. Remote credentials are held only in process memory. A separate state and UI vocabulary distinguish successful proxy forwarding from OS-protected traffic.

**Tech Stack:** Existing Go 1.23+ standard-library core, embedded HTML/CSS/JS, Swift macOS shell. No new system extension, firewall deployment, root certificate installation or vendor software installation.

**Spec/authorization:** The user explicitly asks to make the existing app itself a proxy. This refines the approved project: deliver normal proxy functionality now and retain strict enforcement separately. It does not authorize silently weakening an existing strict configuration or claiming all application traffic is protected.

## Global constraints

- Preserve Windows-first testing readiness, but the ordinary proxy must also build/run on Mac without Apple developer credentials.
- Existing `internal/enforce` implementations remain unchanged. No real filter install/remove and no VPN/DNS/global-route modifications.
- Only localhost listen; UI token/Host/Origin/size protections stay intact.
- First version still forwards target IPv4 TCP only. Target names are resolved through the selected upstream using existing DoH/A-only logic. UDP and app connections that ignore this proxy are outside proxy-only mode, never claimed blocked by it.
- Remote proxy endpoint hostname resolution may use system DNS solely to locate that proxy; document this distinction. Pin an IPv4 endpoint for the active route, never retry directly to a target.
- HTTP/SOCKS5 transport has no inherent TLS. Show that property plainly; HTTPS proxy transport must validate certificates normally, with no insecure flag or automatic downgrade.
- No usernames/passwords in URLs, config files, snapshots, events or error text. Credentials travel only to the configured upstream during authentication; never to target origins.
- No paid proxy or real account is required for deterministic tests. Actual customer proxy/Claude validation remains explicitly pending.

## Contract

- Add `Config.EnforcementMode string` (`enforcementMode`): `proxy-only` or `required`.
- `Mode=remote` enables authenticated remote upstream; use existing `ProxyURL` without userinfo for schemes `http`, `https`, `socks5`, with explicit port, no path/query/fragment. Existing `Mode=proxy` remains loopback-only HTTP relay, `clash` remains compatibility-only, `feilian` remains available.
- Missing-config fresh default: `Mode=remote`, `EnforcementMode=proxy-only`. Existing saved config without the new field, and explicit legacy config objects, normalize to `required`; preserve old strict behavior.
- Add `Status.EnforcementMode`, `Status.UpstreamCredentialsSet bool`, `Status.SessionRevision uint64`. Status never reveals credential values; revision binds launch to the exact activation generation.
- Keep strict states `ready`/`armed`. Add `proxy_ready`/`proxy_active`; these MUST have `FilterActive=false` and no OS proof claim.
- Add `Service.SetProxyCredentials(username, password string) error`: memory-only; invalidates readiness/connections. Empty pair clears credentials. Changes to source mode or upstream endpoint clear remote credentials. Preserve separate existing Clash secret handling.
- UI API: authenticated POST `/api/proxy-credentials` with `{username,password}`. Include only credential-present flag in snapshots. Keep all previous API compatibility and immediate Disarm behavior.

## Task 1 — core and remote protocols

Ownership: `internal/model`, `internal/guard`, their tests. Do not edit UI/CLI/native packages.

- [ ] Write failing tests for proxy-only operation without OS proof, strict mode still requiring actual proof, legacy config migration, credential redaction/clearing and activation revision.
- [ ] Implement mode-specific configuration validation: proxy-only needs explicit expected IPv4 and valid route but does not require an installed target application to run a proxy. Launch targets remain explicit when using launch buttons.
- [ ] Implement remote upstream HTTP CONNECT with optional Basic authentication; HTTPS adds verified TLS to the proxy before sending credentials; SOCKS5 implements bounded method selection, RFC1929 auth and IPv4 CONNECT.
- [ ] Resolve/pin the proxy endpoint using IPv4. Refuse self-recursion into own guard listener, malformed credentials/URLs, unsupported methods, invalid replies and TLS failures. No direct-to-target fallback under any protocol failure.
- [ ] Preserve same-route DoH for target hostnames, HTTP origin headers and opaque HTTPS tunnels. Use safe dependency injection for local certificate fixtures, never a production insecure switch.
- [ ] `Check`/`Arm`/health/admission/connection tracking accept explicit proxy-only states but never silently downgrade required mode. Both modes close owned tunnels on pause, route/IP/config/credential failures. Health skips OS checks only in explicit proxy-only mode.
- [ ] Run real local protocol fixture tests for success/auth rejection/truncation/timeouts, TLS trust/rejection, credentials not reaching origins or output, closed upstream no direct fallback, live tunnel close on Disarm. At least one integration test must activate real forwarding in proxy-only mode without substituting a successful OS proof.
- [ ] Report exact interfaces to UI implementer immediately; run tests/race and whole-suite before handoff.

## Task 2 — usable setup and launch behavior

Ownership: `internal/ui`, UI tests/assets, README, packaging documentation, `platform/macos/App.swift` only if wording needs updating. Do not edit core/model/enforcement.

- [ ] Extend API service contract and tests for memory-only credential entry, no echo, mode/state mismatch and failure/paused UI recovery.
- [ ] Main setup supports remote proxy type, server, port, optional username/password, candidate-IP test and explicit expected-IP entry. The config stores only sanitized endpoint information; submission clears credential form fields.
- [ ] Present two clearly named modes: “代理转发” and “严格阻断”. Proxy mode shows “代理运行中，系统防绕行未启用”; no green/all-protected claim. Required mode never becomes usable because a user simply selected proxy-ready status.
- [ ] In proxy-only mode allow explicitly selected Chrome/Edge/Claude launcher entries once proxy_active; no certificate/OS rule prerequisite. Describe that only traffic honoring proxy settings is covered. Strict launch retains exact path/OS proof/helper checks and all-window scope acknowledgement.
- [ ] Browser profiles remain separate and proxy switches have no public DIRECT fallback. Preserve localhost panel exception, QUIC/WebRTC restrictions. Recheck SessionRevision immediately before exec; no stale launch after reconfiguration/pause.
- [ ] Keep Mac missing Claude as only that launch entry's limitation, not a blocker to starting the proxy or using Chrome. Keep optional local-Mihomo mode for users who need their existing transport; no automatic corporate-network bypass or unverified chaining.
- [ ] Update onboarding copy and documentation: normal proxy functionality vs remaining strict-coverage gaps; session-only credentials; HTTP/SOCKS5 transport property; no actual third-party node claimed tested.

## Task 3 — review, integration and delivery

- [ ] Root and fresh reviewer inspect mode separation, legacy behavior, credential lifetime/leaks, proxy endpoint versus target DNS, protocol fallback, UI claims and launch revision.
- [ ] Run Go unit/integration/race/vet, frontend tests, Windows cross-build and native Mac app build. Real Windows OS filtering remains untested and is not needed to prove normal proxy forwarding.
- [ ] Run a controlled end-to-end local proxy demonstration: real listener, remote-protocol fixture, HTTP/HTTPS data path, upstream failure and pause behavior. Clearly label local fixtures; no user proxy/Claude account is used.
- [ ] Visually check Mac setup and proxy-only labels. Do not modify live corporate settings or start proxy traffic to unknown endpoints.
- [ ] Package new proxy-capable Mac/Windows artifacts and document exactly what was verified and what still needs a real upstream. Existing strict development artifacts are not relabeled as fully protected.

## Review focus

- Legacy strict configs must not silently become proxy-only.
- Proxy-only must be genuinely usable without Native Extension/WFP activation, while never setting FilterActive=true.
- TLS/auth/CONNECT/SOCKS errors must not trigger direct fallback or credential forwarding to target servers.
- Proxy endpoint changes must clear credentials and revoke existing connections before any new endpoint is contacted.
- Cached UI state or a racing launch must not reopen a paused/reconfigured session.
