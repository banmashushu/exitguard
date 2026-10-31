# Remember account and desktop discovery review

Production implementation: `1f4c0f9`; temporary-file ignore hardening: `0c5e4b7`.

User explicitly requested plaintext local storage instead of Keychain and selected Claude Desktop's Code tab rather than the terminal CLI. The implementation follows those choices and does not alter Claude settings, provider/auth configuration, company networking or native filtering.

Root reviewed endpoint binding, private-file read/write/delete, truthful failure states, credential-free responses, bounded desktop metadata discovery, typed client choices and UI polling behavior. Duplicate credential keys and discovery through linked bundles were reproduced and rejected; binary metadata conversion consumes already-bounded bytes via stdin. Both final credential records and transient write names are ignored by Git. Root's independent targeted credential/discovery race tests passed; implementer full test/race/vet/frontend and Mac/Windows builds passed.

The actual canonical Mac app was updated only after its old instance exited and its port was free. Root enabled the explicit plaintext-remember checkbox and saved the currently selected provider account through the app. The real file was verified as a regular file, mode0600, owned by the current user, version1 and bound to the current endpoint. Account/password values were not printed or added to this repository.

Root cleared its temporary credential variables, quit and reopened the app, then observed `已从本机恢复账户` without submitting credentials again. Both actual dropdowns displayed friendly discovered choices: Chrome and Claude Desktop / Code. No Claude task or desktop client was started. The restored account passed a real exit check with the user's current expected IP. A subsequent startup verification encountered a transient probe timeout; retry and final activation were interrupted by the Mac locking. Activation was not falsely reported as complete.

After the user unlocked the Mac, root observed the verified ready state and started forwarding without entering credentials again. The app reported proxy_active. A real Google request through the local proxy returned200. One ipify request timed out, so root independently checked the same proxy through Cloudflare's literal-IP HTTPS diagnostic endpoint; it returned the unchanged expected exit. The probe configuration was not changed.

Persistence/restart, actual desktop discovery and current connection activation are accepted. Restoring an account does not automatically arm the proxy. Claude Code-tab network coverage and full macOS system enforcement are not established by discovery.

Canonical app: `dist/ExitGuard.app`.
Stable archive: `dist/ExitGuard-macOS-arm64-latest.zip`.
Archive SHA256: `720965640002c446fcd1de12d5a7f7d0e89f0ff16e6d19a717ff3e38bb5b2cf3`.
Root verified archive integrity and absence of credential-record files in the archive.
