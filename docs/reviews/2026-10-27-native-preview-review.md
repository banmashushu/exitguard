# Native Windows trial review

Reviewed implementation: `d91c86f`, relative to ordinary-proxy baseline `6b11f79`.

Disposition: suitable to deliver as a Windows native trial with explicit prerequisites and incomplete acceptance. **The user's complete application-protection objective is not yet achieved.** No Windows machine, static provider or real application session has been exercised in this environment.

## Scope confirmed

The user rejected virtual machines and whole-machine routing. The Hyper-V experiment was parked under ignored `.work/parked-hyperv-2026-10-26`; its tracked changes were restored before native implementation. No VM, driver or vendor software was installed. The current route uses separately installed Sandboxie Plus v1.18.8 and the existing ExitGuard proxy, with product-owned groups for native Chrome, Edge and Claude. Only newly launched grouped windows are covered by the trial workflow; ordinary shortcuts are not captured automatically.

## Material review findings addressed

- Effective settings must include vendor default templates and globals. The adapter queries the live driver and pins the exact reviewed baseline; inherited network allows, unknown IPC relaxations and breakout triggers are rejected. The stock inert document selector ruling and regression are recorded in the plan.
- A vendor WFP feature flag is intent, not proof. The adapter reads actual registered callouts and exact associated BFE filters. That remains a prerequisite rather than a complete protection certificate.
- Runtime publisher identity was initially unsubstantiated. Actual same-release official shared-core certificate extraction established the exact identities; installed files must separately pass Windows Authenticode validation before DLL loading. Dependency search is confined to the vendor directory and System32.
- Windows POSIX file mode 0600 would not protect a full private INI backup. A protected restrictive DACL is now supplied at file creation before any content is written. The original INI ACL and bytes are retained. This Windows-specific behavior has a cross-compiled test but still needs execution on Windows.
- Unknown membership errors cannot prove an ordinary outside-group control. The probe now requires a definite unboxed status and reports receiver counts for its TCP/UDP controls; failures alone never become successful blocking evidence.
- A browser-hosted control panel conflicted with requiring that browser to be stopped. The same-process numbered control window now operates all three application launches and pause/resume after the configuration browser is closed. It does not expose the ready token or require another browser.
- The initial ZIP encoded Chinese names without the UTF-8 flag. The final packager writes Unicode filenames correctly and preserves Windows CRLF launchers.

## Independent root verification

On final product source, root observed successful `go test ./... -count=1`, `go test -race ./cmd/exitguard ./internal/guard ./internal/nativeapp ./internal/ui -count=1 -timeout=45s`, Node frontend regression and `git diff --check`. Implementer evidence additionally records full race/vet, Windows-target vet and both Windows x64 builds.

Root independently checked the final archive CRC, exact Chinese filenames and UTF-8 flags, all eight launchers' CRLF, the console entry, every manifest hash, PE AMD64 machine fields for both executables, absence of vendor DLL/driver binaries, and the pinned 15-key/100-value data fixture.

Artifact: `dist/ExitGuard-Windows-Native-Preview.zip`

SHA256: `26ae6c5a39377a751079341e731088757c0b93309c8ddc11243bc2f633bf0976`

The archive was built from the final implementation contents before its Git commit, so embedded Go VCS metadata can refer to the previous revision with a dirty marker. This does not substitute for the recorded source review or artifact digest.

## Remaining acceptance

Actual Windows signatures/API behavior, effective filtering, DNS broker containment, renamed children, pause/crash/upstream failure, unaffected ordinary applications and real Chrome/Edge/Claude compatibility remain unverified. The DNS IPC closure is a concrete candidate, not a universal proof for all broker routes. No report import, mock result or user-provided boolean can grant `armed` status. Compatibility failures must not be repaired by silently adding direct-network or breakout exceptions.

The next user step is separately installing the pinned official runtime, then running the packaged read-only native check on Windows. Actual installation of the scoped product groups remains an explicit user-run operation after its concrete change plan is available.
