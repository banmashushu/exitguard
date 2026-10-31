# Native Windows application protection

## Accepted constraints

User has explicitly rejected virtual machines and whole-machine routing. Protect only native Chrome, Edge and Claude, while other Windows applications keep ordinary networking. Applications must open on the existing Windows desktop. Earlier Hyper-V experiments were parked under ignored `.work/parked-hyperv-2026-10-26`; none were deployed. Existing proxy implementation remains baseline `6b11f79`.

## Design decision

Use the separately installed, official Sandboxie Plus Windows runtime to group target application processes and their descendants. ExitGuard remains the authenticated-upstream HTTP/CONNECT proxy. This is an external Windows driver dependency, not a VM; do not silently install it, purchase a license, enable whole-machine proxying, or alter host DNS/VPN/firewall defaults. Support the reviewed stable runtime v1.18.8 initially; another version requires explicit revalidation. Packaging must not include vendor binaries or credentials.

Create product-owned boxes for the three targets. Launch via the vendor's supported Start.exe /box entry with explicit proxy flags and dedicated profiles. Never fall back to launching a protected target outside the box. No claim covers existing unboxed windows; prompt users to close them. Descendants must inherit box membership through the driver rather than a polling path watcher.

Expected box network policy is broad deny plus only 127.0.0.1:guard-port TCP allow; AllowNetworkAccess=y, PromptForInternetAccess=n, BlockLocalLoop=n. Explicitly close the box's `\\RPC Control\\DNSResolver` IPC endpoint; normal website DNS is handled inside ExitGuard via its existing remote resolver. This closure needs actual Windows GetAddrInfoW/DnsQueryEx validation, not a claim based solely on a configuration line. Disable application breakout/direct-access relaxations in product-owned boxes; do not widen policy to make a failing application appear to work.

Sandboxie NetworkEnableWFP is a global runtime option. Do not silently change it on an existing installation or alter existing boxes/templates. Setup must detect existing configuration and present exact changes. Configuration readback alone is never kernel proof: runtime WFP flag reflects intent and can be set despite callback install failure. Check actual four authorization callouts and filters, then perform controlled live negative tests. If a complete current effective policy cannot be verified, report incomplete and withhold full protection status.

## Delivery and safety

Deliver a practical Windows native integration and acceptance workflow, keeping existing ordinary proxy available with its original honest scope. A preview/runtime-not-verified state must never become an `armed`/fully protected claim based on supplied report files, mock tests or cross-compilation. Actual unknowns remain visible; no absolute anti-ban or per-connection fixed-IP guarantee (upstream provider must supply genuinely static egress).

Local implementation must strictly validate configuration, invocation paths and target identity; avoid shell interpolation, program-name-only substitution and user-supplied executable commands. Preserve all existing vendor settings, boxes and user profiles. Prefer new configuration artifacts and explicit one-time apply over silently rewriting whole INI. Secrets remain solely in existing proxy session memory.

## Required evidence

Local tests: policy conflict/inheritance rejection, injection/path rejection, target mapping, no direct launch fallback, stale session prevention, no credentials in artifacts, setup effects scoped to owned boxes, existing regression suite and Windows cross-build.

Actual Windows acceptance: driver signature/version, real installed WFP filters, group membership for parent and newly named child, explicit proxy positive control, other loopback port/IPv4/IPv6/UDP direct negatives, DNS broker tests with observation, proxy pause/crash/upstream failure, other applications unaffected, Chrome/Edge/Claude login and updates. Missing observations are incomplete, never pass.

## Primary references

- https://github.com/sandboxie-plus/Sandboxie/blob/v1.18.8/Sandboxie/core/drv/wfp.c
- https://github.com/sandboxie-plus/Sandboxie/blob/v1.18.8/Sandboxie/common/netfw.c
- https://sandboxie-plus.github.io/sandboxie-docs/PlusContent/WFPSupport.html
- https://sandboxie-plus.github.io/sandboxie-docs/Content/ClosedIpcPath/
- https://sandboxie-plus.github.io/sandboxie-docs/Content/StartCommandLine/

