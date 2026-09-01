# Module: Prevention & CI/CD Guardrails

> **Load when** you have confirmed findings and are writing deliverables (Phase 9+).
> A finding tells the customer what is broken today. A **preventive control** tells them why the
> class of bug got in and what mechanism stops the next one. Deliver both.

An assessment that only lists findings hands the customer a fix list and a guarantee that the same
class of bug returns the moment attention moves elsewhere. The findings you confirmed are evidence of
a **missing detection point**, not just isolated defects. This module turns each confirmed finding
into a durable guardrail so the same class fails CI the next time it is introduced.

**Rule: every finding class in the report maps to at least one preventive control here.** If a class
has no control, say so and say why (e.g. "no cheap automated check exists; mitigated by review
checklist only") — an honest gap beats a silent one.

## The method

1. **Cluster findings by root cause, not by location.** Twelve missing-authz handlers are one class,
   not twelve. The control is what would have caught the *class*.
2. **For each class, ask: at which stage could a machine have caught this?** Commit, PR/CI, pre-deploy,
   runtime. Earlier is cheaper.
3. **Prefer enforcement over advice.** A lint rule that fails the build beats a wiki page. A type that
   makes the unsafe state unrepresentable beats a lint rule.
4. **Rank by cost × coverage.** A repo-setting toggle that catches a whole class in minutes outranks a
   bespoke test suite. Lead the plan with those.

```bash
sa coverage set --surface prevention --state assessed --reason "controls mapped to finding classes X,Y,Z"
```

## Finding-class → control map

Use this to derive the controls. It is stack-agnostic; name the concrete tool for the customer's
stack (examples in brackets are common choices, not requirements). Cite the exact tool that fits what
you saw in `recon.md`.

| Finding class (what you confirmed) | Stage | Preventive control |
|---|---|---|
| **Vulnerable / outdated dependency** (a known CVE shipped) | PR + scheduled | Automated dependency updates + alerts [Dependabot / Renovate]; a `audit`/SCA gate that fails on ≥High [npm/pip/cargo audit, osv-scanner]; scheduled SAST re-scan [CodeQL] |
| **Missing authorization / IDOR / BOLA / BFLA** (handler or tool skips ownership/role) | PR | SAST rule that flags a single-object fetch with no ownership predicate [Semgrep custom rule]; **make the safe path the only path** — a required auth wrapper that takes the role as a mandatory argument; a **cross-tenant negative test** convention (see below) |
| **Broken tenant isolation at the data layer** (RLS/row-scoping missing or over-permissive) | PR | An **invariant test** run against a throwaway DB: every table has row security enabled; no `USING(true)`-style policy open to untrusted roles; every write policy carries a tenant/owner predicate [pgTAP / SQL assertions] |
| **Privileged client bypasses the data layer** (service-role / admin key used in request paths) | PR | Lint the privileged client / key to an **allowlist of files** [ESLint `no-restricted-imports`, Semgrep]; forbid `SERVICE_KEY || PUBLIC_KEY` fallbacks |
| **Missing authentication on a sensitive route** (unauth reachability, key fallback) | PR | SAST rule: request handlers must pass through the auth wrapper; forbid server-secret fallback when the caller is unauthenticated; ban raw handler exports that skip the wrapper |
| **Hardcoded secret / credential** | Commit + PR + history | Secret scanning with push protection [gitleaks, GitHub/GitLab secret scanning]; scan full history once |
| **Injection (SQLi/XSS/SSRF/command)** | PR | SAST taint rules [Semgrep, CodeQL]; parameterized-query / output-encoding lints; allowlist for outbound fetch destinations |
| **Weak crypto / token handling** (predictable, plaintext, non-constant-time) | PR | Lint for `Math.random` in security contexts, plaintext secret columns, non-constant-time compare; unit tests asserting hashing/expiry/rotation |
| **OAuth / auth-flow flaw** (redirect_uri, PKCE, state) | PR | Unit tests for the exact BCP invariants (default-deny redirect allowlist, PKCE required, single-use code); checklist for auth-flow changes |
| **IaC / cloud misconfiguration** | PR | IaC scanning [tfsec, checkov, KICS]; policy-as-code gate [OPA/Conftest] |

## Cross-tenant negative test (the highest-yield convention)

Most authorization findings share one missing test: *"a valid but different tenant is denied."* Make
it a **required convention**, not a suggestion — every new route/handler/tool that touches a
tenant-scoped resource ships with one negative test where the actor is authenticated but not
authorized, asserting `403`/`404`/empty. Provide the customer a small helper so the cost is one line,
and add it to the PR checklist. The negative tests you seeded while verifying findings are the first
examples.

## Process guardrails (where automation cannot reach)

- **Branch protection**: make the new security jobs *required* status checks; block direct pushes to
  the release branch; require review.
- **PR checklist**: authz on new routes/tools, cross-tenant negative test present, data-layer write
  policies carry a tenant predicate, new privileged-client use justified, dependency additions clean.
- **Pre-commit**: fast local mirror of the cheapest checks (lint, typecheck, staged-secret scan) so
  feedback lands before CI.
- **Periodic re-assessment**: re-run this skill quarterly or on major auth/authz/data-layer change;
  seed the next run from the open `UNKNOWN`s.

## Deliverable

Write the prevention plan with `templates/prevention-plan.md`. It is a **standalone section of the
report**, ordered by cost × coverage, with copy-pastable config for the customer's actual stack and
CI. Every snippet must be real and runnable — a wrong config that silently no-ops is worse than none.
Ground each control in the finding IDs it would have caught, so the customer sees the payoff.

**Keep it generalized in `knowledge/`, specific in the workspace.** Customer repo names, hostnames and
pipeline internals stay in the engagement workspace; only the reusable class→control mapping is
promoted (via `sa retro promote`, which runs the sanitizer).
