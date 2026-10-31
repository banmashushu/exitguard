# Native Application Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** Provide a native Windows integration for Chrome/Edge/Claude groups and ExitGuard, with executable acceptance checks and honest incomplete states.

**Architecture:** Separately installed Sandboxie Plus owns process grouping and WFP/IPC boundaries; ExitGuard owns proxy forwarding. Product-owned group settings and explicit boxed launch never downgrade to ordinary direct execution.

**Tech Stack:** Existing Go 1.23 application, Windows APIs and vendor-supported interfaces, HTML/JS panel.

**Spec:** `docs/superpowers/specs/2026-10-27-native-app-protection-design.md`.

## Global Constraints

- No virtual machine, whole-machine proxy/DNS/VPN changes, automatic vendor install or license purchase.
- Only product-owned groups; preserve all existing vendor configuration and user profiles.
- Runtime config and cross-build are not complete Windows protection evidence.
- No direct target launch fallback, no credentials in scripts or reports.
- Do not convert unresolved native proof into green protected status.

## Review Focus

- Existing broad allow rules, templates and runtime exemptions must not silently weaken the product group.
- Missing/outdated runtime, WFP intent true but callbacks absent, or failed setup must block protected launch.
- Parent/child attribution and DNS broker verification must be observations, not just JSON booleans accepted from a file.
- A previously running unboxed app can absorb a new launch; do not claim the resulting window is boxed without proof.
- User's other application traffic and existing vendor boxes must remain unchanged.

### Task 1: Concrete native adapter and acceptance workflow

- [x] Read supported vendor interfaces and existing proxy/native code; document implementation-critical limitations immediately.
- [x] Write meaningful tests for policy generation/verification, scoped setup, invocation and no direct fallback.
- [x] Implement coherent native adapter, read-only preflight, explicit owned-box setup artifacts, safe boxed launch and Windows acceptance probe. Prefer smallest supported interface; no invented API signatures.
- [x] Integrate the application so unsupported/unverified is a first-class state; do not loosen existing strict enforcement.
- [x] Build Windows native package with numbered Chinese entry points and concise guide; leave Windows-dependent checks pending.
- [x] Run covering tests/race/vet/frontend/cross-build and report precise remaining blockers for root review.

### Task 2: Independent review and delivery

- [x] Root reviews evidence, scope and native safety claims; fix material defects before delivery.
- [x] Run final relevant tests and package integrity checks.
- [x] Prepare actionable files and the smallest actual Windows next step, without claiming unperformed validation.

These checks complete the local native-trial implementation scope only. Full protection, deployment and real Windows acceptance remain pending; see the dated review.

## State

User correction is authoritative: no VM; only three native target applications. Native implementation work is authorized, actual Windows installation is not performed from this Mac.

Ruling: accept the pinned v1.18.8 stock `BreakoutDocumentProcess=explorer.exe,y` selector only while the runtime-effective `BreakoutDocument`, `BreakoutProcess` and `BreakoutFolder` sets are empty. The selector alone is inert: `core/dll/proc.c` and `sh.c` require a matched document pattern before host UserProxy breakout. A per-box `explorer.exe,n` is not a reliable override because the consumer replaces equal-rank matches with later inherited values. This is an explicitly reviewed stock baseline, not permission for arbitrary global rules; any breakout trigger must reject launch. Cost if the pinned vendor implementation changes: protection must stay unavailable until the new version and effective defaults are reviewed.
