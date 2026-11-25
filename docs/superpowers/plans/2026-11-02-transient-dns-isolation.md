# Transient DNS and Upstream Failure Repair

> **For agentic workers:** Use superpowers:executing-plans with the existing Astra/Sol role split; no recursive delegation.

**Goal:** Prevent a transient DNS exchange from disconnecting unrelated application connections, and recover known upstream transport failures through the existing verified-original-exit worker.

**Architecture:** Preserve safe typed failure stage/cause across upstream negotiation, DNS and public-IP probes. A per-request `httptrace.GotConn` marker permits DNS exchange isolation only after the configured upstream tunnel and resolver TLS are established. Probe failures still revoke admission and use bounded recovery.

**Tech Stack:** Go 1.27.3, existing guard service, MyGo desktop.

**Spec:** Accepted request-isolation and original-exit recovery contract in `2026-10-30-request-isolation-recovery.md`, plus the user's current request to repair recurring unexplained disconnects.

## Global Constraints

- Preserve the previous uncommitted Claude launch repair and installed Claude-only policy.
- No direct fallback, alternate resolver, provider change, expectation change or system networking changes.
- Current downstream cancellation remains request-local. Pause/config changes still invalidate late work.
- Only known transport interruptions/timeouts and DNS HTTP 429/5xx are transient. Unknown failures remain closed.
- Explicit authentication refusal, invalid protocol, TLS/certificate failure, invalid DNS response and changed route/IP remain blocking.
- Existing recovery requires opt-in and a previously active ordinary-proxy session; 2/5/15 second delays, at most three 15-second validations, exact prior fingerprint and IP.
- Diagnostics contain only fixed stage/cause strings and HTTP status, never hostnames, credentials, bodies or raw errors.
- Reuse the current checkout on a dedicated branch; retain the previous app backup and verify the installed replacement.

## Review Focus

- A DoH client timeout while proxy negotiation is still running must not be classified as a completed DNS exchange.
- A hard HTTP status/MIME error followed by body timeout must remain hard.
- Partial SOCKS/CONNECT replies must not become recoverable simply because the socket closes.
- DNS failures reached through a public-IP probe must still revoke admission and revalidate, even when request-local for ordinary browsing.
- Recovery must not reactivate after pause/config changes or resume another allowed-but-different IP.

## Task 1: Failure stages, isolation and recovery

**Files:** `internal/guard/{dns.go,route.go,remote.go,probe.go,proxy.go,recovery.go}`, a focused safe-error helper, and related tests.

- [x] Write a local SOCKS/DoH regression: transient DoH failures preserve an existing echo tunnel and session; hard DNS/auth/protocol failures still close the entry.
- [x] Run the regression against current code and observe the failure.
- [x] Add safe typed errors and a per-query completed-connection marker; isolate only recognized post-connection DNS transients.
- [x] Distinguish upstream negotiation transport from explicit authentication/protocol failures and route recognized transport to existing verified recovery.
- [x] Cover early client timeout, partial replies, hard HTTP/MIME precedence, probe propagation, cancellation, retry success and failure cases.
- [x] Run focused tests, the full Go suite, guard/UI race tests and vet. Astra reviews the final diff and acceptance boundaries.

## Task 2: Local delivery and acceptance

- [x] Update the operator-facing behavior description and execution ledger with measured evidence and limits.
- [x] Build and verify a Mac bundle, back up the installed repair, close ExitGuard, replace and check the installed binary hash.
- [x] Restore the same saved proxy through check/start and verify bounded live requests while Claude stays open. Report controlled recovery evidence separately from live-provider stability.
- [x] Leave source uncommitted unless the user requests integration; no release upload.

## Evidence and rulings

- Historical events show a successful exit check followed by a generic forwarding failure; the discarded raw cause cannot be reconstructed.
- A fresh nine-query measurement through the selected SOCKS proxy returned successful DoH responses; this does not establish continuous provider availability.
- Astra confirmed request-local transport requires `GotConn`; pre-connection transient failures revoke and revalidate, hard TLS/protocol failures remain blocking.

- Final validation: full Go suite, guard/UI race and vet pass. Both material review findings (NXDOMAIN and unclassified binding retry) were reproduced and fixed; final Astra acceptance passed.
- Installed binary SHA-256: `8d0361f445bf2ba8f534225d4bd0d91ccc059a89a877525114440bfd20e63fad`; review ZIP SHA-256: `233b48acc562456e36d0c2b2899ec91a3c1cbbe489784b68ff02d65178048eb0`.
- Live acceptance: restored the same selected profile, remained active for more than three minutes with periodic checks, three matching selected-profile IP checks and three HTTP204 web checks. CLI Claude requests received403; no account or client-task acceptance is claimed. Detailed local measurements and prior app backup are under `.work/disconnect-fix`.

## QQ Mail follow-up acceptance

- [x] Capture the same-upstream QQ login DNS reply and replay the valid loopback answer to reproduce the exact hard failure.
- [x] Preserve address restrictions, validate complete/consistent related records, and classify disallowed-address replies as target-only refusals; reject whole mixed targets.
- [x] Cover HTTP/CONNECT, unrelated echo tunnel survival, no loopback proxy dial, later malformed records, NXDOMAIN contradiction and CNAME ordering.
- [x] Full Go tests, guard race, vet and narrow independent Astra review pass; install and hash-verify the rebuilt app.
- [x] Actual local proxy refuses QQ loopback HTTP/CONNECT, then serves QQ Mail HTTP200 and the selected expected exit. User refreshed the correct isolated QQ window and confirmed continued connectivity; native events show only target refusals with active forwarding. No account login or mail access.
