# Native Mihomo Subscription Import Implementation Plan

> **For agentic workers:** Use the existing Astra/Sol workflow and regression-first implementation. The user's existing authorization covers implementing the requested Mihomo integration. Do not create commits, contact third parties, or change system networking.

**Goal:** Remove ExitGuard's URI parameter/protocol bottleneck and use the pinned Mihomo conversion implementation before validating and running one selected proxy leaf.

**Architecture:** A separate GPL executable links only Mihomo v1.19.33's conversion package and exchanges bounded JSON over stdin/stdout. The application extracts nodes, validates the fixed-exit capability boundary, and preserves native protocol fields. Only explicit Check/Arm starts the selected node in the existing owned core; import never constructs network adapters.

**Tech Stack:** Existing Go 1.27.3 / MyGo application, pinned Mihomo v1.19.33 source and vendor, existing per-platform bundle verifiers.

**Spec:** Existing `2026-11-03-managed-subscription.md` and the user's November 12 correction that native core capability must not be blocked by the application's narrow importer. The implementation choices below are engineering decisions within that requested integration.

## Global Constraints

- Preserve fixed-final-proxy verification, per-profile credentials, owned supervisor lifetime, public IPv4 pinning, immutable route identity, explicit activation, and no direct fallback.
- No real subscription URL, password, raw node configuration, server address, or arbitrary core error in command arguments, public diagnostics, or test output.
- Do not modify private user stores while implementing. Re-fetch/re-import is required to replace old unsupported summaries; they contain no recoverable connection configuration.
- Do not import an entire provider/root configuration into a running core. No system proxy, TUN, external provider, script, interface, or routing override.
- Keep TLS verification enforced. Native public-key/pin-based protocols may retain their own authenticated configuration; never silently drop a requested pin or authentication field.
- Preserve native single-endpoint proxy fields rather than reimplement every protocol schema. Multi-endpoint, external-control, and file-dependent nodes must receive a specific capability rejection until those capabilities are implemented.
- This is source and local desktop repair, not a public release or a claim that every protocol/transport combination is live-tested.
- Review ruling: retain the unchanged official core. Its Reality/JLS authentication-failure HTTP fallbacks can follow redirects through a default dialer outside the selected server; reject `reality-opts`, `jls-opts`, SS plugin `jls`, and Snell `obfs-opts.mode: jls` as additional-endpoint capabilities until separately confined. Ordinary VLESS/SS/Snell remain eligible.

## Review Focus

- Native converter logging or malformed input must not expose a URI, including panic/error paths.
- Generated random defaults must not change node identity on an identical re-import.
- Native options that can read files or create extra connections must not escape the selected-leaf boundary through spelling aliases or nested maps.
- Existing v1/v2 libraries and canonical identities must remain readable without an automatic rewrite or activation.
- A node eligible for core checking must not be presented as already connectivity-tested.

## Task 1: Native converter executable and packaged launcher

**Owner/files:** managed_core; `third_party/mihomo-importer/`, `internal/managedproxy/importer.go` and tests, build/stage/package/verification scripts and notices.

**Interface:** Implements `NativeURIConverter(options Options) subscription.URIConverter`. `URIConverter` is `func(context.Context, []string) ([]URIConversion, error)`, where `URIConversion` has `Config map[string]any` and `Error string` (fixed `invalid_uri` only). Exactly one result per input line. No credentials in argv/environment; one bounded stdin payload and private captured stdout.

- [x] Add failing controlled fixtures proving native conversion accepts representative Trojan metadata and converts SS/SSR/VMess/VLESS/Hy2/TUIC/AnyTLS, without starting adapters or dialing.
- [x] Build a separate GPL helper offline from the pinned source/vendor. Call `common/convert.ConvertsV2Ray` per line, silence all logs, recover conversion panics to a fixed error, and stabilize generated defaults. Do not link the GPL library into the main application.
- [x] Implement bounded/cancelable subprocess invocation, strict version/count/JSON checks, and package-relative executable validation. Missing/tampered helper produces a fixed actionable error, never fallback to the legacy URI parser.
- [x] Package helper, corresponding wrapper source/license/build instructions, and verify exact bundle/ZIP contents on both platforms. Keep the existing official core bytes unchanged.
- [x] Run converter/launcher tests and report the audit of file/external-network fields to Task 2 before widening the native-leaf boundary.

## Task 2: Native import pipeline and selected-leaf boundary

**Owner/files:** preproxy_facts; `internal/subscription/native.go`, parser/store and tests, `internal/guard/subscriptions.go` / `service.go` and tests.

**Interface:** Owns `URIConverter` and `URIConversion` above. Add `ParseWithURIConverter(ctx, content, converter)` and a parser injection/prepare entry point so the real Service import path always calls the packaged native converter for URI/Base64 input. Keep legacy pure-parser APIs only where existing callers/tests require them; never silently fallback in production when native conversion fails.

- [x] Write red regressions for native URI conversion in the real service import path and stable private persistence. Test literal native maps for protocols previously rejected by the canonical whitelist.
- [x] Preserve current YAML structure/size validation and extract only `proxies` leaves. Native URI conversion must retain per-line invalid placeholders and safe reasons without raw input reflection.
- [x] Replace per-protocol field allowlists with bounded native-leaf normalization and capability validation. Preserve effective options for the pinned core's audited single-endpoint remote proxy types, including ordinary TLS/QUIC proxy transports and audited built-in SS plugins. Audit and explicitly reject file paths, external control/multiple endpoints, root/routing overrides, unverified TLS, and the Reality/JLS fallbacks identified above. Validate core-supported capability rather than guessing unsupported protocol fields.
- [x] Retain legacy canonical defaults and key normalization for existing identities. Validate aliases/duplicate keys and preserve explicit native authentication/pin fields.
- [x] Wire `Service.New` to Task 1's converter. Download, conversion, parsing, cancellation, and stale-candidate failures before commit keep the previous library and session. Preserve the existing conservative close before committing an update to an active subscription: storage errors can occur after atomic replacement, so commit/storage failure may leave the connection paused rather than continuing against an indeterminate persisted snapshot.
- [x] Run subscription/guard focused tests, race and vet. Do not touch private user files or run live subscription requests.

## Task 3: Accurate capability copy and final integration

**Owner/files:** preproxy_ui for native labels/tests/README; root review and installation coordination.

- [x] Change node-count/row copy from implying live availability to eligibility for core checking; keep the existing explicit node selection and Check/Arm flow. Show capability rejection as ExitGuard's boundary, not as unsupported by Mihomo.
- [x] Run targeted UI tests and review normal/narrow layout if layout changed.
- [x] Once implementation is frozen, run the full normal suite, affected race/vet, frontend tests, Windows compilation and the real owned-core chain regression needed by the changed leaf boundary.
- [x] Build and validate the Mac bundle, back up the installed application and private data, then replace the app and restore the previously selected fixed route through normal controls.
- [x] Attempt one explicit update through the subscription's currently saved route. Report actual eligible-node count and any remaining capability failures; do not change supported flags without connection data or claim all protocols were tested.

## Live acceptance outcome

Implementation and installation are complete. Native refresh obtained 35 nodes (4 eligible; 31 require disabled certificate verification). The user chose to retain certificate verification. The eligible candidates did not establish a working first-hop chain in the bounded checks; the underlying connectivity cause is not yet isolated, and live interoperability is not claimed. The original fixed-proxy configuration was restored exactly and its latest health probes succeeded. No insecure override was added.
