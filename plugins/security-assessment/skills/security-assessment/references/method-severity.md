# Method: Severity

Severity is **computed**, not asserted. CVSS alone is rejected: it has no idea whether the affected
endpoint is internet-facing or whether the data behind it is a marketing blog or a payroll table.
Two identical injection bugs deserve different severities in different systems, and the customer
prioritises by *their* risk, not by a base score.

## The four factors

Each is scored 1–4 against the definitions below. Score against **what the evidence supports**, not
the worst imaginable case.

### T — Technical impact

| | |
|---|---|
| 4 | Full compromise: RCE, auth bypass to admin, full DB read/write, cloud account takeover |
| 3 | Substantial: cross-tenant data access, privilege escalation, mass PII read, credential theft |
| 2 | Contained: single-object unauthorized read/write, limited info disclosure, session fixation |
| 1 | Marginal: version disclosure, verbose errors, missing hardening header |

### E — Exploitability

| | |
|---|---|
| 4 | Trivial and unauthenticated. Single request, no special knowledge, scriptable |
| 3 | Requires a normal authenticated account (self-signup counts) or trivially guessable identifiers |
| 2 | Requires meaningful preconditions: elevated role, a race window, user interaction, known IDs |
| 1 | Theoretical: needs an unlikely chain, physical/network position, or an unreleased precondition |

### B — Business impact

Derived from the asset classification in the threat model, not from intuition.

| | |
|---|---|
| 4 | Regulated data (PCI/PHI/個人情報), funds movement, or existential trust loss |
| 3 | Customer data breach, contractual/SLA breach, notifiable incident |
| 2 | Internal data exposure, degraded service, remediation cost |
| 1 | Negligible business consequence |

### X — Exposure

| | |
|---|---|
| 4 | Internet-facing, unauthenticated |
| 3 | Internet-facing, authenticated |
| 2 | Internal network / VPN / service-to-service only |
| 1 | Restricted admin plane, break-glass, or requires an existing compromise |

## Formula

```
score = 0.35·T + 0.25·E + 0.25·B + 0.15·X          (range 1.00 – 4.00)
```

| Band | Score |
|---|---|
| **Critical** | ≥ 3.50 |
| **High** | ≥ 2.80 |
| **Medium** | ≥ 2.00 |
| **Low** | ≥ 1.40 |
| **Informational** | < 1.40 |

T is weighted highest because it bounds everything; X is weighted lowest because internal-only
issues still chain. `sa finding rate F-003 --T 4 --E 3 --B 4 --X 4` computes and stores the band
along with the four inputs, so every severity in the report is auditable and re-derivable.

## Guardrails

Enforced by `sa validate`:

1. **Critical requires E1 or E2 evidence** and confidence `CONFIRMED` or `SUSPECTED`.
   No Critical from an unverified code-reading or a tool hit.
2. **`NEEDS-VERIFICATION` caps at High**, and those findings are reported in their own section so the
   customer never mistakes an open question for a proven breach.
3. **A tool's severity is never a rationale.** `"severity_rationale"` containing only a tool name and
   its rating fails validation.
4. **Manual override is allowed but bounded**: one band, with a written justification stored in
   `severity_override_reason`. Use it for the cases the formula cannot see — a bug that is technically
   Medium but sits on the payment flow of a fintech, or a Critical whose exploitation the customer's
   architecture already detects and blocks within seconds. Overrides are listed in the report appendix.
5. **Chained findings**: if two findings are only severe in combination, rate them individually and
   add a separate chain finding that references both. Do not inflate the components.

## Aggregation

Severity is per finding. Do not sum. "12 Mediums" is not a High — but a *systemic* pattern (the same
missing tenant predicate in 12 handlers) is **one finding** at the severity of the pattern, with the
12 locations listed as instances. Reporting it 12 times inflates the count and buries the root cause,
which is the actual thing that needs fixing.

## Likelihood

Report likelihood separately from severity, in words the customer can act on: what an attacker needs,
how long it would take, and whether it is opportunistically discoverable (an enumerable ID on a public
endpoint) or requires targeting. `E` and `X` feed the score; the narrative feeds the decision.
