# Remember Proxy Account and Discover Desktop Clients

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans with Astra/Sol roles. No recursive delegation.

**Goal:** On the current Mac, restore the selected proxy's saved account after restart and automatically list installed Chrome and Claude Desktop, including its Code tab, without manual executable-path entry.

**Architecture:** A separate endpoint-bound plaintext credential record is owned by the guard; configuration/API/status remain credential-free. Read-only typed app discovery supplies UI choices, while existing launch-time validation and session checks remain authoritative.

**Tech Stack:** Existing Go core, local HTML/JS UI and macOS app wrapper. No Keychain dependency.

## User decisions and scope

- User explicitly requested remembering the proxy account/password and then explicitly chose plaintext local storage instead of Keychain.
- User selected Claude Desktop's Code tab, not terminal `claude`. Current read-only inventory found official `/Applications/Claude.app`, Chrome, and a separate CLI/URL handler; only the actual desktop application belongs in the requested desktop choice.
- Do not execute/discover-by-running Claude, run user code, install clients, or modify Claude settings/auth/provider configuration. Desktop Code traffic is not proven by Electron flags alone; retain truthful coverage text.
- No changes to VPN, system proxy/DNS, system filters, or auto-start behavior. Previously opted-in verified recovery is preserved.

## Credential contract

- Store at `configPath + ".credentials.json"`, separate from the ordinary config. Default Mac location is `~/Library/Application Support/ExitGuard/config.json.credentials.json`.
- Bounded strict JSON record: version1, exact validated remote proxy URL, username, password. No userinfo embedded in the proxy URL. Match current remote mode and exact endpoint before restoring.
- Use a private 0600 file on macOS, private atomic temporary write, sync and rename; reject unsafe final symlinks/nonregular files. Do not write outside the intended owned location through a link. No secret in argv, environment, events, errors, API snapshot, UI values or package.
- Add `*.credentials.json` to repository ignore rules. Production credentials remain outside the repository; tests use synthetic accounts.
- Restoration leaves admission closed and recovery intent unset. Check/manual start remains required; fields stay empty and UI reports only restored/saved status.
- Missing file is normal. Corrupt/unreadable/mismatched storage must not crash the control panel or send a stored secret to another endpoint. Give a bounded, sanitized re-entry/clear message.
- Explicit remember submission writes successfully before claiming saved. Explicit session-only submission or clear removes saved credentials; deletion failure must not claim forgotten. All credential mutations stop current connections/recovery. Failures leave an honest closed state.
- Changing endpoint/source clears saved and in-memory credentials before accepting the change. If deletion fails, do not silently commit a new endpoint. Endpoint binding also prevents cross-endpoint restoration after partial failures.
- Existing callers of SetProxyCredentials remain compatible/session-only. The UI/API gains an explicit remember choice and clear action. Do not map filesystem errors to a misleading credential-format message or reflect raw errors.
- The supported deliverable is macOS. Other platforms must retain usable session-only behavior if private persistence is unsupported; do not pretend Windows POSIX0600 proves a private DACL.

## Discovery contract

- Typed results distinguish browser and Claude Desktop. Do not infer the CLI as desktop via case-insensitive basename matching, and do not list Claude Code URL Handler as the desktop client.
- Use a bounded read-only search of known installed-app locations (`/Applications`, `~/Applications`) and supported bundle identities/metadata, with regular executable checks. No recursive home scan, shell-profile execution, subscription/auth/history reads or client execution.
- Return only supported usable candidates for Chrome/Edge and actual Claude Desktop. Do not add unsupported Chromium or CLI execution as part of this task.
- Query discovery once on UI startup and on an explicit refresh, not on every 3-second status poll. Merge discovered choices with configured manual choices; preserve selection when choices are unchanged and keep manual fallback.
- Never automatically launch an application or add it to strict OS filter policy. Revalidate the chosen executable at launch and preserve revision/state checks. Strict mode still requires its own explicit policy coverage.
- Prefer friendly labels (Chrome, Claude Desktop / Code); retain optional path detail. No found app is represented as an enforcement proof.

## Review Focus

- An endpoint change, malformed record or storage failure must never cause credentials to be sent to the wrong server.
- Store/clear errors must close admission and accurately reflect whether data remains saved.
- No API/event/error/package can reveal the stored account/password; old config migration still works.
- A missing or changed app must not crash discovery or fall back to a different program; no URL handler or CLI masquerades as Claude Desktop.
- Periodic status rendering must not reset discovery options or explicit selection.

## Tasks

- [x] Implement private endpoint-bound plaintext store and service lifecycle, with restart/mismatch/write/delete/corruption/redaction tests.
- [x] Implement bounded typed macOS discovery with fixture-based metadata tests and no application execution.
- [x] Integrate remember/clear UI and detected client choices, preserving manual and strict paths; test errors, restored status and option identity.
- [x] Run covering/full/race/vet/frontend checks, cross-build supported artifacts, and review final source.
- [x] Build staged Mac bundle; publish canonical only after root closes current product instances and confirms port free. Preserve the previous bundle and update the stable archive.
- [ ] Root explicitly saves the authorized account in plaintext, verifies mode without printing contents, restarts once to confirm automatic loading, verifies discovered Chrome/Claude Desktop, checks/starts the same exit and runs a bounded live request.

Actual plaintext save, permissions, restart restore, desktop dropdown discovery and exit check are accepted. The final connection activation is pending manual unlock of the Mac; see the dated review. Do not repeat saving or request the password again merely to activate the stored account.

## Ownership

Sol implementer owns credential/discovery/core/UI source and tests sequentially. Root Astra owns this plan, review, private live data, canonical deployment and acceptance. No new approval is needed for the already-requested plaintext storage; any actual OS credential/access prompt is handled separately if encountered.
