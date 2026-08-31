# Remediation Plan — <customer / system>

<!-- `sa report remediation` generates this. Buckets are driven by severity × exploitability ×
     effort — not by severity alone. A Critical needing a three-month migration and a High fixable
     in an afternoon do not belong in the same bucket. -->

**Date**: <yyyy-mm-dd>  ·  **Findings**: <n>  ·  **Owner**: <>

## Immediate — start today

Actively exploitable, or a live credential exposure.

| ID | Severity | Issue | Action | Effort | Owner | Verification |
|---|---|---|---|---|---|---|

**Live credentials must be rotated before anything else on this list.** Rotation, then audit for
prior use, then the code fix.

## Within 7 days

Exploitable with meaningful impact; the fix is bounded.

| ID | Severity | Issue | Action | Effort | Owner | Verification |
|---|---|---|---|---|---|---|

## Within 30 days

Real risk, or a Critical/High whose correct fix is structural rather than local.

| ID | Severity | Issue | Action | Effort | Owner | Verification |
|---|---|---|---|---|---|---|

## Within 90 days

Hardening, defence in depth, and systemic improvements.

| ID | Severity | Issue | Action | Effort | Owner | Verification |
|---|---|---|---|---|---|---|

## Structural recommendations

Fixes that prevent a **class** of finding rather than an instance. These usually outperform the
individual fixes above over the following year.

| Recommendation | Prevents | Effort |
|---|---|---|
| e.g. enforce tenant scoping at the data layer (RLS / repository) rather than per handler | AZ-1, AZ-4, AZ-6 | M |
| e.g. pin all CI actions to commit SHAs and restrict `permissions:` | CI-3, CI-4 | S |

## Human review queue

Do not action these without a security engineer's review.

| ID | Severity | AI confidence | The specific question for the reviewer |
|---|---|---|---|

## Re-assessment

Once fixes land, run `modules/remediation-review.md`. Evidence is re-collected at the new commit;
the original evidence is stale by definition and is not re-used.

| Trigger | Scope of re-assessment |
|---|---|
| Immediate + 7-day items complete | Those findings, plus a regression check on refuted hypotheses |
| All items complete | Full delta review |
