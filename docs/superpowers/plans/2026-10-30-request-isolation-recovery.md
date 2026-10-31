# Request Isolation and Verified Recovery Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans with the existing Astra/Sol role split. No recursive delegation.

**Goal:** Stop normal website failures from disconnecting every application, and automatically recover an explicitly enabled ordinary proxy only after re-verifying the same route and public IP.

**Architecture:** Separate individual HTTP exchanges from the verified upstream route. A transient route-check failure closes admission and all current connections first, then a generation-bound recovery worker validates a fresh candidate before any forwarding resumes. This is not an automatic call to Arm and cannot approve a new exit.

**Tech Stack:** Existing Go 1.23 guard/model code and the local HTML/JS panel.

**Accepted requirement:** The user explicitly selected automatic retry with forwarding stopped until the same exit is verified. The current task is Mac ordinary-proxy debugging; no full OS application-enforcement claim is added.

## Global Constraints

- Never add direct routing, alternative proxy providers, alternative probe services, or automatically change ExpectedIPs.
- Add opt-in `Config.AutoRecover` / JSON `autoRecover`, default false for old configs. Only proxy-only mode supports this option; strict required mode retains manual recovery and must not silently downgrade.
- Restarting the application never automatically starts forwarding. Recovery requires a previously active session resulting from an explicit successful Arm.
- Default recovery: at most three attempts, delayed 2, 5 and 15 seconds; each validation has a 15-second upper bound. Then remain blocked with an explicit exhausted-retries reason.
- Only known transient failures are eligible: actual probe timeouts, recognized network transport/read interruption, HTTP 429/5xx, and a classified upstream TCP-unreachable failure. The current generic `probeNetworkFailure` mapping for unknown errors is NOT by itself sufficient evidence of a transient failure; preserve a safe typed classification if necessary.
- Authentication, certificate validation, protocol violations, actual IP mismatch, route fingerprint change, invalid probe content, native-filter failures and unknown hard failures remain blocked for manual action.
- Pause, SaveConfig, manual Check, credential/secret changes, and service shutdown cancel recovery intent and invalidate any late worker. Never retain credentials in logs or files.
- No live user config, credentials, browser/process/window data, GUI, VPN or system proxy changes by the implementer. Root handles explicit local deployment and live acceptance.

## Failure-domain contract

Before a verified upstream tunnel exists, route fingerprint and known upstream auth/TLS/protocol failures can invalidate the route. A validated target-specific negative response only fails its request.

After successful fingerprint validation and DialContext (including proxy negotiation), HTTP request-body/serialization failures, origin response parsing/EOF/timeout and response-body copy failures are individual exchanges. Close their connections, return 413/502/504 when headers have not been sent, or abort the incomplete downstream response after headers. Preserve other requests and the session revision. Do not manufacture a second status after a partially sent response.

## Recovery identity and concurrency contract

Capture the exact old route fingerprint, last successfully verified public IP, and current config/credential generation before revoking admission. Close the old route and all tracked connections immediately; show `recovering`, not an active/armed state.

Use the service lifetime context, not the expiring health-check or HTTP request context, for the bounded worker. Permit only one worker per recovery episode. Each candidate must pass all of:

1. Still-current generation, recovery intent, configuration and running listener.
2. Fingerprint before probing equals the captured original fingerprint.
3. Probe yields a valid IP equal to the captured original IP AND accepted by the unchanged configured expectation. Another IP in a multi-value expected list is insufficient.
4. Fingerprint after probing still equals the original fingerprint.
5. Atomic final state check before installing the candidate and reopening admission.

Every unsuccessful or stale candidate is closed. A hard failure during retry ends automatic recovery. Timer/backoff behavior must have a deterministic test seam; no tests wait through real minute-long retries.

## UI contract

Expose the opt-in checkbox in ordinary proxy settings with plain Chinese wording. Strict mode makes the unsupported option unavailable and requires a compatible submitted config. Show retry attempt/max and next retry time via additive status fields (`recoveryAttempt`, `recoveryMaxAttempts`, `nextRetryAt`). Keep application launch and Arm unavailable while recovering; **Pause remains available and cancels recovery immediately**. The control panel remains reachable. Successful recovery states that the original exit was re-verified, without claiming system-wide protection.

## Review Focus

- A late successful probe after manual pause/config/credential change must never reactivate traffic.
- A request-local origin failure must not close an unrelated active tunnel or change the session revision.
- An allowed but different IP, or identical IP through a changed fingerprint, must not resume automatically.
- Unknown transport errors must not be accidentally treated as transient by a generic error-message sanitizer.
- Retry exhaustion, shutdown and immediate subsequent episodes must leave no overlapping workers, timers or retained candidate connections.

## Tasks

- [x] Reproduce and correct all post-tunnel HTTP failure paths with a real local origin and an independent active echo tunnel. Checkpoint `577184c`.
- [x] Implement opt-in config/status and generation-bound verified recovery with deterministic tests for the full contract above.
- [x] Add the checkbox, recovering display and enabled Pause behavior; extend frontend action-state tests and config migration tests.
- [x] Run covering tests, race tests, vet and existing frontend checks. Review the final failure-domain/state-machine diff.
- [x] Build one final Mac bundle, publish only after root closes current product instances, preserve the prior canonical bundle and verify the stable archive.
- [x] Root enables the user-requested option, restores session authentication, and runs bounded live acceptance. Do not intentionally disrupt the company VPN or external provider to manufacture a failure.

Root acceptance and limits are recorded in `docs/reviews/2026-10-30-verified-recovery-review.md`.

## Ownership and progress

Sol worker `/root/proxy_destination_failure` owns implementation and tests, including frontend/config edits sequentially. Astra root owns this plan, review, deployment coordination and live UI acceptance. The request-boundary checkpoint is complete; recovery implementation is authorized by the user's explicit selection.

Implementation: `577184c` isolates complete HTTP exchanges; `a04524e` adds opt-in verified recovery. Full test/race/vet/frontend checks passed. Astra reviewed the final state-machine/UI diff with no outstanding material finding. Deployment and live acceptance remain pending.
