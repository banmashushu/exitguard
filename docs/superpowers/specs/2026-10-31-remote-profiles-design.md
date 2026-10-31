# Named remote proxy profiles

The user confirmed multiple independent proxies, each with its own address, port and account. Replace the native remote-proxy URL/account workflow with named saved profiles and separate protocol, server, port, username, password and expected-exit fields. Retain native MyGo, the current icon, macOS/Windows support and existing fixed-exit verification. This does not introduce concurrent routes, automatic failover, new system filters or a claim about Claude Code coverage.

## Interface and interaction

The settings page shows saved profiles and a form. Each row identifies name, protocol/address, expected exit, whether credentials are saved, and whether it is currently used. Selecting a row edits it; using it is a separate explicit action. Provide new, save, delete with confirmation, and use actions. Saving a new profile does not automatically select or start it. Keep drafts and selected rows stable during polling; require explicit discard before replacing dirty drafts. Never populate or expose saved passwords in the UI, accessibility, logs or public snapshots. Blank account fields retain an existing pair; replacing requires both fields; clearing is explicit. Changing an endpoint requires replacement or explicit clearing of its old credentials.

Store each complete account with its profile as local plaintext using the already requested private file permissions. One save submits the profile and account, avoiding the former address-save/account-submit sequence. Expected exits may be initially blank; candidates are never automatically trusted. Advanced global settings remain available behind an explicit section. Overview identifies the profile actually in use and permits an explicit switch, followed by check and manual start.

## Core contract

- `model.Config.RemoteProfileID string` identifies an active named profile.
- `model.RemoteProfile` exposes ID, Name, ProxyURL, ExpectedIPs and HasCredentials only.
- `model.RemoteProfileInput` adds CredentialAction (`keep`, `replace`, `clear`) and Username/Password excluded from JSON serialization.
- `EnsureRemoteProfiles() error` is called explicitly during native initialization. It performs an idempotent migration of valid legacy remote configuration, including partial configurations missing an expected IP. `guard.New` retains legacy behavior when no profile is selected, and restores selected profiles from their store without enabling forwarding.
- `RemoteProfiles() ([]model.RemoteProfile, error)` reads summaries without writes.
- `SaveRemoteProfile(model.RemoteProfileInput) (model.RemoteProfile, error)` creates or updates a record.
- `SelectRemoteProfile(id string) error` closes the old session and loads only that profile's configuration/account. Empty ID explicitly cancels selection and clears runtime remote fields/account while retaining saved records.
- `DeleteRemoteProfile(id string) error` deletes one record. Deleting the active record first closes admission and cancels checks/recovery.

The bounded private library at `configPath + ".profiles.json"` is authoritative for named-profile parameters/accounts: at most 32 records and 128 KiB. Reuse existing Darwin owner/0600/no-follow operations and Windows handle/DACL operations. Strict versioned decoding rejects unknown, duplicate, missing/null and oversized data. Preserve the v1 legacy account until migration and active reference persistence succeed. Missing/corrupt selected-profile data must not fall back to an old account or another proxy. A failed mutation remains closed with a sanitized error and recoverable data. Different accounts sharing a server remain distinct profile IDs.

Global settings must not silently change a named profile's endpoint. Changing advanced outlet mode explicitly cancels profile selection first. Legacy credential mutation methods must not update a selected profile through the old single-account file. Switching, active editing/deletion, and errors cannot revive an old in-flight check/recovery or automatically arm a new route. Inactive edits/deletion do not disturb a healthy active route.

## Delivery and validation

Preserve all existing uncommitted migration code, `.idea`, user data and Git history. Do not commit/push unrelated work. Implementers use fixture accounts and local tests only. Verify migration/restart and failure consistency, profile isolation, stale validators/recovery, deletion, strict parsing and redaction; test actual native control interactions and race-sensitive controller state. Cross-compile Windows without claiming Windows runtime acceptance. Review fresh headless screenshots, build the Mac package and replace the single installed `/Applications/ExitGuard.app` only after validation. Root alone performs real GUI acceptance and user-data migration. Existing upstream SOCKS5 handshake/authorization failure is a known external acceptance limitation, not permission to change the user's proxy credentials or expected IP.
