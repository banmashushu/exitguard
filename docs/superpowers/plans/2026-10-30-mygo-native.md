# MyGo Native Desktop Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans with Astra/Sol role split; no recursive delegation.

**Goal:** Replace the Swift/web desktop shell with native MyGo UI and deliver usable macOS and Windows desktop packages.

**Architecture:** A single Go desktop process owns MyGo native controls and the existing guard. A small shared facade reuses client discovery/launch operations. Windows storage/discovery are platform adapters, not UI-specific implementations.

**Tech Stack:** MyGo v0.7.3, Go1.27.3, CGO disabled, native Metal/Direct3D/CPU rendering; local NSIS3.13 for Windows installer generation.

**Spec:** `docs/superpowers/specs/2026-10-30-mygo-native-design.md`.

## Global Constraints

- Work only from `/Users/zhangchuan/GolandProjects/exit-guard`; the old path is only a temporary compatibility link, not a second checkout.
- Native `WindowOptions.Content` only. No Page, WebView, HTML/JS renderer, frontend build or MyGo IPC binding in the desktop entry.
- Preserve existing configs/credentials, core validation/recovery, strict mode and launch checks. No user credential reads or live GUI/network changes by implementers.
- No silent direct fallback, expected-IP change, system networking changes or claim of full Claude Code/system protection.
- Pin module/toolchain; use invocation-scoped build settings, no global SDK/package installation.
- No WebView2 dependency for native Windows UI. Runtime verification is distinct from cross-compilation.

## Available verified tools

- Go: `/Users/zhangchuan/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.3.darwin-arm64/bin/go`.
- MyGo CLI: `.work/mygo-preflight/bin/mygo` (v0.7.3).
- NSIS: `.work/mygo-preflight/makensis/3.13/bin/makensis`; set `NSISDIR` to the same prefix's `share/nsis` for that invocation.
- MyGo and dependencies passed checksum verification; its official native sample cross-built for Mac/Windows and headless input/privacy/accessibility tests passed. No GUI was started.

## Review Focus

- UI polling or late background completion must not overwrite drafts/selections or undo manual pause.
- Native desktop startup must not expose legacy HTTP control endpoints or leak a control token/secret.
- Only one process owns the proxy; close/quit/startup errors must not leave an orphan listener or start another browser UI.
- Windows files need actual DACL/handle checks, not POSIX mode claims; MSIX discovery must not invent a working proxy-aware launch.
- Packages must target the new GUI, preserve private data outside install folders and avoid obsolete/duplicate app outputs.

### Task 1: Native desktop and reusable operations

Files: new `cmd/exitguard-desktop/`, new native/controller package; narrow exported/shared launch/discovery facade; `go.mod`/`go.sum`; targeted core cancellation entry guard only if needed for native action ordering; headless tests.

- [x] Map native controls to the spec and write controller/state/privacy/lifetime tests.
- [x] Implement native overview/settings/diagnostics/client controls, native password masking and asynchronous action dispatch.
- [x] Reuse the guard directly without HTTP UI/control handler; add lifecycle and second-instance focus behavior without weakening port ownership.
- [x] Preserve CLI behavior and verify native desktop never opens a web page or default browser for its own UI.
- [x] Run covering/headless/core tests and native MyGo vet; provide code review evidence before deployment.

### Task 2: Windows feature parity

Files: platform credential file operations and tests; Windows app discovery and tests; corresponding shared facade/model details where required.

- [x] Split platform filesystem mechanics from shared credential JSON/service semantics without changing existing Mac records.
- [x] Implement private Windows create/open/ACL verification/replace/delete with local-path and reparse checks; cross-compile Windows tests and document runtime-only checks.
- [x] Implement bounded registry/Known Folder/current-user Claude MSIX discovery; preserve explicit unsupported/manual outcomes and launcher gates.
- [x] Run existing Mac regressions and both-platform compilation; keep doctor inventory narrow and separate. Windows runtime acceptance remains pending without a Windows host.

### Task 3: Packaging, actual Mac acceptance and cleanup

Files: `mygo.json`, build/package scripts, resources/helper scripts, docs and optional CI configuration. Retire only the old Swift GUI entry/build use, not optional filter sources.

- [x] Use one pinned MyGo build flow for native Mac and Windows. The GUI-only Windows release includes no CLI/probe-dependent helper scripts.
- [x] Produce and inspect Mac bundle/archive, Windows GUI executable/portable archive and NSIS installer with the new icon. No private data is included.
- [ ] Root reviews code and verifies actual Mac native controls, saved-account restoration, discovery, start/pause/recovery and clean quit. Native UI, reopen/account restoration, Chrome/Claude discovery and clean exit/listener ownership passed. Real upstream forwarding and recovery acceptance remain pending: the configured SOCKS5 proxy fails handshake/authentication in both the native app and the legacy comparison. Windows runtime limitations remain explicit.
- [x] Install the sole canonical app at /Applications/ExitGuard.app after closing the legacy instance; move the old dist app and old Mac archive to Trash, publish the new stable archive and remove temporary staged app copies.
- [x] Run the new canonical app with the GolandProjects source checkout; remove the old-root compatibility symlink and verify one physical source checkout/current app.

## Ownership / progress

Root Astra owns architecture/review and private live deployment. Sol implementers own source/tests/packaging with explicit file scopes. User explicitly chose native mode and GolandProjects location, so do not reopen those decisions.

- Task 1: native desktop implementation and targeted/headless/core tests are complete; MyGo vet and native race checks passed. Source is frozen for Windows packaging.
- Task 2: Windows credential/discovery adapters are implemented; Windows cross-compilation and Mac regressions passed. Windows ACL, MSIX/discovery and GUI runtime acceptance remain unexecuted without a Windows host.
- Task 3: implementation, new icon, packaging, Mac installation and cleanup are complete. The sole active app is /Applications/ExitGuard.app, with the verified native arm64 archive published at dist/ExitGuard-macOS-arm64-latest.zip. Root verified native UI, reopen/account restoration, Chrome/Claude discovery, quit/listener ownership, strict signing and archive consistency. Old dist app/archive were moved to Trash; temporary staging and the compatibility symlink were removed. Existing Windows artifacts and their hashes are unchanged. Real upstream forwarding/recovery acceptance remains pending because the existing SOCKS5 endpoint fails handshake/authentication in both native and legacy apps. The native app stays blocked and its loopback proxy returns HTTP503, confirming fail-closed behavior. Code delivery is complete; external-network acceptance remains open, and Windows runtime acceptance still requires a Windows host.
