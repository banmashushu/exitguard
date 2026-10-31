# ExitGuard native MyGo migration

## User decisions

Use `github.com/egoist/mygo` for macOS and Windows packaging. The user explicitly rejected WebView mode: the desktop UI must be native Go UI (`WindowOptions.Content`, package `ui`), with no HTML/JS renderer, Page, WebView2 or browser-hosted primary control window. Source is now `/Users/zhangchuan/GolandProjects/exit-guard`; Git history was moved intact. The old source path is a temporary compatibility symlink only, to be removed after the new canonical app is validated.

## Product contract

Preserve the tested Go proxy core and its failure boundaries, same-exit recovery, endpoint-bound remembered account, manual initial activation, candidate-IP confirmation, safe browser/client launch checks and honest protection status. The GUI migration is not a new system network filter. Never change system proxy, DNS, VPN, Claude configuration or installed vendor filters. No real client tasks or account sessions are used by implementers.

Native UI exposes overview, settings and diagnostics in a coherent Chinese desktop layout. Overview shows active/paused/recovering/blocked, configured and observed IP, retry information, and check/start/pause actions. Settings support remote HTTP/HTTPS/SOCKS5, optional local/Feilian/Clash advanced modes, account save/clear, expected IP, auto-recovery, app paths and advanced probe settings. Clients show typed discovered Chrome/Edge/Claude Desktop choices, manual fallback, strict-policy acknowledgments and the existing Windows native trial where applicable. Discovery/launch never claims Claude Code-tab coverage or complete OS enforcement.

Use native labelled controls and stable keys. Password input is masked on every render and never appears in accessibility values, diagnostics or logs. Clear entered credentials after submission. Polling status must not replace dirty configuration, entered credentials, pending remember choice or explicit client selection. Long operations run off the UI thread and publish results through `Window.Update`. Pause cancels an in-flight validation without waiting behind the ordinary action queue; late results cannot revive a paused session or overwrite newer user intent.

## Runtime architecture

Pin MyGo **v0.7.3** and Go **1.27.3**, with `CGO_ENABLED=0`. Use one desktop process containing the native UI and `guard.Service`; no Swift GUI or detached core child. The existing CLI remains available separately for diagnostics/native tools and its optional legacy web panel. The desktop process does not call `ui.NewControl`, set a control HTTP handler, generate a bearer URL, bind MyGo IPC or create a Page. Its loopback port remains only the guarded HTTP/CONNECT proxy.

Reuse/export existing launch and discovery behavior through a small shared Go facade; avoid rewriting security-critical launch checks just to remove HTTP transport. The main UI invokes typed Go methods. Initial app startup restores saved matching credentials but leaves forwarding off. Configuration remains at the existing per-OS `os.UserConfigDir()/ExitGuard/config.json`, with its existing credentials sibling.

MyGo's single-instance lock improves focus behavior but is not security proof (its error path can fail open). Acquire it before starting the guard; retain exclusive proxy-port binding as the final authority. A second instance only restores/shows/focuses the first window, ignoring arbitrary arguments. Normal quit/window close cancels service lifetime, closes admission/connections and waits boundedly for cleanup. Startup/core failure is shown in a native window/dialog using sanitized text, never a raw secret or command line.

## Windows parity

Native UI needs no WebView2. Target Windows10+ amd64; existing native filtering remains preview/unverified until actual Windows testing. Add Windows remembered-account file operations with creation-time protected DACL for current user, SYSTEM and Administrators. Verify the opened file's owner/DACL through its handle before reading secrets. Reject network/device/ADS paths, remote drives, reparse ancestors/targets and nonregular files. Keep strict bounded JSON, endpoint binding, error redaction, clear and migration semantics. Use same-directory protected temporary files and a no-copy same-volume replacement; do not let ReplaceFile preserve a permissive old ACL. Darwin behavior and stored records remain compatible; unsupported targets keep explicit session-only fallback.

Windows app discovery reads only exact Chrome/Edge/Claude App Paths values, bounded standard Known Folder candidates, and current-user MSIX package named `Claude`. It must not scan browser data, all installed software, shell profiles or remote paths. MSIX manifest metadata may supply a contained local Claude.exe; do not invent paths/AUMIDs or replace a failed launch with a URL handler/CLI/default-browser launch. Discovery is inventory, not proof of package activation or proxy coverage; inaccessible metadata retains manual fallback.

## Packaging and validation

MyGo native config omits frontend/bindings/buildCommand fields. Identifier stays `com.exitguard.app`, app name ExitGuard; minimum macOS is13.0 (Go1.27 requires it). Build macOS arm64 first and Windows amd64 GUI; universal Mac is optional only if bounded and verified. Produce a stable Mac app/archive and Windows portable archive plus an NSIS installer with the local verified toolchain. No WebView2 bootstrapper, updater, telemetry, login item or certificate changes are added.

Keep one canonical app in `dist/ExitGuard.app`. Stage outside it; a failed build leaves the current app intact. Retire the Swift GUI build path, preserve optional macOS network-filter source, and keep CLI/native-probe tools clearly distinct from the primary GUI exe. Windows helper scripts must not pass CLI subcommands to a GUI-only entry. Do not bundle user configs/credentials. Preserve a single rollback archive instead of accumulating indexed .app copies; clean temporary app bundles when validation finishes.

Test native/controller action ordering, masking, draft/selection preservation, startup/quit/port-conflict behavior and that desktop mode exposes no web control API. Run core regressions under Go1.27.3, headless native UI tests, MyGo vet, both cross-builds, archive/installer checks and actual Mac native AX/GUI acceptance. Windows ACL/MSIX/GUI runtime tests must be labelled unexecuted when no Windows host is available. Preserve existing production configuration and verify saved credentials load after the native migration without printing them.
