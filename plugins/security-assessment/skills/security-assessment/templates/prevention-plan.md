# Prevention & CI/CD Plan — <customer / system>

<!-- Companion to the findings report. Derived via `modules/prevention-cicd.md`.
     Every finding class in the report maps to at least one control below; where a class has no
     automated control, say so explicitly. Snippets must be real and runnable for THIS stack. -->

**Date**: <yyyy-mm-dd>  ·  **Stack**: <lang / framework / data layer / CI / host>

## Why these got in

<!-- One paragraph: the findings are evidence of missing detection points, not isolated bugs.
     Name the stages that had no guardrail (dependency scanning, authz SAST, data-layer invariant
     tests, secret scanning, cross-tenant tests). -->

## Class → control map

| Finding class | Findings | Why it slipped through | Control to add | Stage |
|---|---|---|---|---|
| <e.g. missing authorization> | <F-002, F-004…> | <no SAST/authz test> | <Semgrep rule + cross-tenant test convention> | PR |

## Controls (copy-pastable)

### 1. Dependency vulnerabilities
<!-- automated updates config + SCA gate in CI + scheduled SAST. Real files for this repo. -->

### 2. Authorization / tenant isolation
<!-- SAST rule(s) for the exact anti-pattern seen; the required-wrapper refactor; the
     cross-tenant negative-test helper + convention. -->

### 3. Data-layer invariants (if applicable)
<!-- throwaway-DB test asserting isolation invariants: RLS/row-scoping enabled, no over-permissive
     policy, write policies carry a tenant predicate. -->

### 4. Secret scanning
<!-- scanner workflow + push protection + full-history scan once. -->

### 5. Other classes present in this engagement
<!-- injection SAST, crypto lints, IaC scanning, auth-flow unit tests — only those that apply. -->

## Process guardrails

- [ ] Branch protection: new security jobs are **required** checks; direct pushes blocked; review required
- [ ] PR checklist added (authz, cross-tenant test, data-layer tenant predicate, privileged-client justification, clean deps)
- [ ] Pre-commit mirror of cheapest checks (lint, typecheck, staged-secret scan)
- [ ] Repo-setting toggles on (dependency alerts + security updates, secret scanning + push protection)
- [ ] Periodic re-assessment scheduled; seeded from open UNKNOWNs

## Adoption order (cost × coverage)

| Priority | Control | Prevents (finding classes) | Effort |
|---|---|---|---|
| 1 | <repo-setting toggles> | <deps, secrets> | minutes |
| 2 | <SCA gate + secret workflow> | <deps, secrets> | ~half day |
| 3 | <data-layer invariant test> | <tenant isolation> | ~1 day |
| 4 | <authz SAST + cross-tenant test convention> | <authz classes> | ~1–2 days |
| 5 | <type-level enforcement / privileged-client allowlist> | <structural root cause> | days |
