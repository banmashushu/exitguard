# Remote Profile Management Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development with the astra-sol-workflow role split. No recursive delegation.

**Goal:** Save and switch independent named remote proxies through a clear native form.

**Architecture:** A private profile library owns per-profile settings/accounts. The existing guard remains a single verified route; the native controller distinguishes editing from selecting an active profile.

**Tech Stack:** Go 1.27.3, MyGo v0.7.3, current Darwin/Windows private-file adapters.

**Spec:** `docs/superpowers/specs/2026-10-31-remote-profiles-design.md`.

## Global constraints and review focus

- Preserve dirty/untracked source and `.idea`; no unrequested commit or push.
- Only fixture data for implementers; root owns actual installed app and user-data acceptance.
- Never send old-account credentials to a changed endpoint, including same-host alternate accounts.
- Incomplete/failed migration and restart must retain recoverable data and remain closed.
- Profile switches/active deletion must invalidate pending check/recovery; inactive edits must not close the active route.
- Polling and delayed completions must not replace profile drafts, credential choices or newer user intent.
- No secret-bearing summaries/errors/AX values, direct fallback, auto-failover, or automatic candidate-IP adoption.

### Task 1: Profile storage and service operations

**Files:** `internal/model/model.go`, new `internal/guard/profiles*.go`, narrow changes to `internal/guard/config.go` and `service.go`, profile tests.

**Interfaces:** Produce the DTOs and six typed methods listed in the spec. Reuse `openCredentialRecord` / `writeCredentialFile` platform mechanics without changing their security contract.

- [x] Add failing fixture tests for CRUD/restart, partial legacy import, independent saved accounts, endpoint-change credential rejection, private storage/limits and corrupted selected libraries.
- [x] Implement strict bounded storage, explicit initialization and migration, profile-aware startup/global settings and atomic association of runtime route/account.
- [x] Add failure-injection and stale-operation tests: interrupted migration writes; active edit/delete; select while checking/recovering; invalid/canceled operations cannot restore old traffic.
- [x] Run guard regressions and Windows test compilation; report actual results and runtime-only limits.

### Task 2: Native list and structured form

**Files:** `internal/desktop/controller.go`, `view.go`, new profile controller/view helpers and tests; minimal native startup integration in `app.go`.

**Interfaces:** Consume Task 1 DTOs/methods. Initialize with Ensure then summary loading, not an implicit list-side mutation.

- [x] Add failing tests for endpoint split/assembly, name/port/account validation, saved versus active profile state, dirty discard, confirmation and poll preservation.
- [x] Implement named rows, single-save structured form, explicit use/delete, overview active selection, and advanced settings disclosure.
- [x] Exercise native input/select/buttons plus credential masking and late completion ordering. Export fixture-only headless screenshots for review.
- [x] Run desktop tests/race checks, MyGo vet, and both desktop cross-builds after core integration.

### Task 3: Review, package and installed Mac acceptance

**Files:** Existing packaging scripts/config; current user-facing readme as needed; review/acceptance reports under `.work`.

- [x] Independently review the final source against the spec, especially storage failure states and cancellation.
- [x] Run integrated checks once sources settle; fix justified failures and rebuild the native Mac package without user data.
- [x] Root closes installed app, keeps a recoverable old bundle until acceptance, installs the verified replacement, and verifies real native profile UI, migration and restart.
- [x] Publish current Mac ZIP/hash and retain one installed app. Windows compilation is required; Windows runtime acceptance remains separate.

## Progress

Implementation, independent review, package verification and installed Mac acceptance are complete for v0.2.0. All three tasks above are delivered; checklists describe the implementation sequence. Full Go regressions, targeted race checks, MyGo vet and Windows cross-builds passed. Review-driven fixes cover interrupted migration and asynchronous save/delete/select settlement. A real-GUI protocol-selector overlap was corrected and revalidated before final packaging.

Root installed `/Applications/ExitGuard.app`, verified the actual native list/form and successful restart, and compared migrated route, account and all other saved settings against the private upgrade backup without logging their values. The existing proxy became one selected profile, its account remained saved, and the obsolete single-account file was removed. One installed app remains; generated staging bundles were cleaned. The current Mac ZIP and Windows ZIP/installer are published under `dist` with SHA-256 files. User source remains in GolandProjects; no commit or push was performed.

Actual upstream connectivity was not retried during this storage/UI change. The pre-existing SOCKS5 handshake/authentication issue is not claimed resolved. Windows GUI, ACL and real traffic runtime acceptance still require a Windows host.
