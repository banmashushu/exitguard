# Verified recovery and HTTP exchange isolation review

Reviewed source checkpoints: `577184c`, `a04524e`; implementation plan `6608b01`.

The request failure boundary is now consistent: after upstream tunnel establishment, malformed/truncated origin responses, response timeouts, request body failures and interrupted response copying fail only that exchange. An unrelated active tunnel and subsequent healthy request survive. Known upstream authentication/protocol/identity failures retain the global gate.

Automatic recovery is explicit opt-in for ordinary proxy mode. It immediately revokes forwarding, preserves a private generation-bound snapshot of the original route fingerprint and verified IP, and attempts at most three fresh validations. Only the exact original path and IP can reactivate admission. Pause/config/credentials/manual checks/lifetime changes cancel intent and prevent late validation from reopening traffic. Unknown errors, TLS alerts, authentication failures, IP mismatch and path drift remain manual. No direct fallback or alternative exit was added.

Root reviewed the concurrency, candidate cleanup, error classification, migration and UI contracts. A review finding about TLS alerts wrapped in net.OpError was reproduced and corrected. Root independently ran the focused race suite covering Recovery, Exchange, Upstream, TargetFailure and CancelledDownstream; it passed. Implementer full test/race/vet/frontend checks also passed.

One composed real-socket local integration stops and restores only an owned authenticated SOCKS5 endpoint, including real TLS DNS/probe fixtures, immediate gate/tunnel closure, fresh identity validation and successful subsequent forwarding. This verifies recovery without altering the user's company VPN or deliberately disrupting an external provider.

After the old GUI exited and the port was verified free, the signed-as-built local app was published to canonical `dist/ExitGuard.app`. Root opened this entry, explicitly enabled and saved the user's requested auto-recovery checkbox through the UI, restored the existing session authentication, verified the expected exit and manually started forwarding.

Live acceptance through the user's actual proxy: valid IP control; nonexistent target returned only 502; immediate IP control still succeeded; deliberate client cancellation returned curl28; another immediate IP control still succeeded; Google and HTTP Baidu returned200. The same expected IP was observed throughout. Final UI remained proxy_active with exactly one running ExitGuard instance. No actual external-provider outage was induced; its recovery evidence is the controlled real-socket test.

Stable ZIP SHA256: `dff6d49313ed5112d6f199c6567cc50e6c79628932c7bf7812433866e4d5cee8`.

This repairs proxy reliability and bounded recovery. It does not establish full macOS system-level application enforcement or account-ban protection. Authentication remains session-only, and a restarted app does not automatically start forwarding.
