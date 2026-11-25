# Standalone Managed Subscription Front Hop

> **For agentic workers:** astra-sol-workflow: root Astra designs/reviews; Sol workers own disjoint implementation ranges and do not delegate.

**Goal:** ExitGuard imports the user's subscription and runs its own dedicated proxy core. The selected subscription node is only the first hop; the original fixed proxy and expected exit IP remain authoritative.

**Accepted clarification:** The user explicitly selected `subscription node -> original fixed exit`, and wants no separate Clash desktop client. The prior explicit pre-proxy feature is implemented and installed but inactive; it is the transport foundation for this phase.

## Architecture and invariant

`selected apps -> ExitGuard -> private managed core / selected subscription node -> fixed upstream -> destination`.

No system proxy, TUN, VPN, corporate policy, DNS listener, other proxy instance or other app is modified. There is no automatic node selection, direct fallback, proxy-group fallback or direct subscription-node final exit. Changes to subscription/node/route revoke the active session and require the existing check/start workflow. Existing check budgets and IP validation remain unchanged.

## Subscription boundary

- Add a private config-adjacent `PATH.subscriptions.json` library, bounded to 5 MiB, at most 8 subscriptions / 500 nodes each. Reuse existing private atomic file/ACL protections. URLs and node credentials never appear in public models, logs, process arguments or errors.
- Add `model.SubscriptionInput{ID, Name string; URL string json:"-"; Content []byte json:"-"}`; exactly one source for import. Refresh uses stored URL. Source file import reads an explicitly chosen local file with the same bound.
- Public `SubscriptionSummary{ID,Name,SourceKind,UpdatedAt string;NodeCount,SupportedNodeCount int}` and `SubscriptionNode{ID,Name,Type string;Supported bool;Reason string}` contain no endpoint/credential configuration. Names are bounded UTF-8 without control characters. Node IDs derive from canonical validated connection settings, not display names.
- Service API: `Subscriptions() ([]model.SubscriptionSummary,error)`, `SubscriptionNodes(id string) ([]model.SubscriptionNode,error)`, `ImportSubscription(ctx context.Context,input model.SubscriptionInput) (model.SubscriptionSummary,error)`, `RefreshSubscription(ctx context.Context,id string) (model.SubscriptionSummary,error)`, `DeleteSubscription(id string) error`.
- Only parse node content: Clash YAML `proxies`, URI lines and Base64 URI text. Never execute/import downloaded root config, scripts, TUN, DNS settings, rules, groups, nested provider URLs or external configuration files. Bounds apply before decode and after Base64; reject duplicate YAML keys, aliases, custom tags, multiple documents and excessive depth.
- Use typed protocol/field allowlists, rejecting unsupported nodes with a safe reason. Initial common formats: HTTP/SOCKS5, SS without executable plugins, VMess, VLESS, Trojan; TCP/WS/gRPC and ordinary TLS. Extend other modern transports only with corresponding safe-config fixtures; explicitly show unsupported types instead of silently changing them. DIRECT/reject/groups, dialer-proxy, interface/routing overrides, file-based keys/certificates, shell/plugin executable paths, and enabled skip-cert-verify are never accepted. An explicit boolean false may be normalized away for supported TLS types.
- HTTPS downloads only, finite timeout/redirect/body limits, no proxy env inheritance, no logs of URLs/tokens. Validate/pin public IPv4 destination per request/redirect; TLS hostname verification remains normal. If bootstrap cannot reach the subscription, offer local file import. Never use a third-party conversion service.
- Import/refresh builds and validates a candidate before replacing the private store. Failed updates retain the old snapshot. A successful update of an actively used subscription pauses the route and stops its managed process; node selection is retained only if its exact immutable ID still exists, otherwise explicit reselection is required. Never silently choose another node. Referenced subscriptions cannot be deleted until profiles detach them.

## Profile and native UI contract

- Add `ManagedSubscriptionID` and `ManagedNodeID` to Config, public RemoteProfile and RemoteProfileInput. Both must be present together; they are mutually exclusive with explicit PreProxyURL/account.
- Read old strict v1/v2 profiles; write strict v3 on profile mutation. An unchanged old library need not be rewritten. Old versions must fail closed on the new format.
- Profile editor first-hop source becomes none / explicit HTTP(S)/SOCKS5 endpoint / managed subscription node. Add a native subscription-management page for private URL/file import, update, delete and safe node listing. No secret refill. Source input is cleared after submission; late save completion must preserve later edits.
- Subscriptions/node lists refresh on explicit changes, not every UI status poll. Profile saves preserve fixed-proxy account/IP and the existing dirty/busy/revision semantics. Advanced settings and old Web public-config round-trip preserve managed IDs.

## Dedicated core and lifecycle

- Use a separate, unmodified, pinned official Mihomo executable, not an external installed client's process. Verify version/SHA against a bundled manifest. Include GPL license and exact corresponding source/version information; do not change this repository's license or upload releases.
- Only the selected, already validated node enters a generated minimal configuration with an internal fixed node name. A dedicated authenticated HTTP listener binds only loopback and pins that leaf using listener.proxy. No auto refresh/provider/group/DIRECT rule exists in generated runtime config.
- Dedicated private runtime directory, generated random proxy authentication, strict file permissions; no subscription URL in runtime config. Keep node credentials in the private config file only. A minimal child environment excludes CLASH_POST_UP/DOWN, config/controller overrides and inherited proxy/injection variables.
- Package an owned supervisor executable. It launches only the bundled verified core and watches a parent-owned stdin pipe; EOF or normal stop terminates only its own core child with a bounded graceful/kill sequence. The core must not inherit the lifetime pipe. Parent crash must not leave an independent egress process indefinitely.
- Core startup/readiness must verify the owned expected listener/config; use a random-secret loopback controller for read-only identity/readiness if needed, never an unauthenticated/public controller. Raw child output is discarded or bounded/redacted, not persisted.
- Package contract: `internal/managedproxy` exposes Manager/Lease primitives agreed with the core worker; no dependency on native UI. Lease includes loopback URL + ephemeral username/password, immutable node/core identity, and liveness/Done. Only explicit manual check/start may launch a core; recovery may reuse a live exact lease but never silently restart/change the selected node. Managed mode requires an owned running ExitGuard service.
- Core unexpected exit immediately revokes matching active generation; ignore stale exit notifications. Route fingerprint includes selected node configuration digest and pinned core identity in addition to first/final endpoints. Stop and profile mutation revoke routes before process cleanup; no process wait under the service mutex.
- Child/helper exit, cancellation and changing selection must invalidate old lease references. Never scan/kill external Clash/Mihomo processes or borrow their control API.

## Ownership and acceptance

- Backend worker: model, subscription parser/store/downloader, guard integration/profile v3, legacy round-trip and tests.
- Runtime/package worker: internal/managedproxy, owned supervisor, fixed generated core config, pinned official artifacts, build/package/validation/third-party notices and tests.
- Native worker: internal/desktop subscription page/profile selection and tests; consumes exact model/Service API above. File dialog may use existing MyGo facility; no user's live subscription or GUI operations.
- Root: review immutable identities, no fallback, secret handling, process isolation and package boundaries; coordinate interfaces before implementation and final local delivery.
- Required proof: malicious/full config ignored or rejected; no secret public/log/argv; bounded fetch/storage; safe updates; real selected-node core local fixture through final authenticated proxy/DoH/probe; wrong TLS/auth/protocol and core death stay closed; parent-crash cleanup; old settings compatibility; no node or fixed-IP substitution.
- Full Go/race/vet/frontend and cross-platform compile, controlled native render, real pinned-core smoke and package verification. No user subscription download, network activation or actual fixed-exit claim until the user enters an actual source/chooses a node and verification succeeds.
