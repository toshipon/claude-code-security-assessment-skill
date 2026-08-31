# Method: Hypothesis Lifecycle

The engine of the assessment. Load once at the start of Phase 4.

## Why hypotheses instead of checklists

A checklist asks "is `eval()` present?" and finds what a linter finds. A hypothesis asks
"can an unauthenticated user read another tenant's invoices?" — a question about *this* system that
has an answer, and whose answer is worth money to the customer.

Checklists also cannot be falsified, so they generate false positives: `eval()` is present, therefore
report it. A hypothesis carries its own refutation condition, so it can be *closed* honestly.

## Anatomy

Every hypothesis is one falsifiable statement about attacker capability.

```
H-007
  surface:      POST /api/v1/invoices/:id/download
  statement:    An authenticated user of tenant A can download an invoice belonging to tenant B
                by substituting the invoice ID.
  attacker:     authenticated low-privilege user (any paid tenant)
  precondition: knows or can guess an invoice ID from another tenant
  evidence_required:
    - the handler's authorization check, or its absence           (E2)
    - how invoice IDs are generated (sequential? UUIDv4?)         (E2)
    - whether a tenant scope is applied at the query layer        (E2)
    - whether middleware/RLS enforces tenancy independently       (E2)
  falsifier:    a tenant predicate applied to the query, or an ownership assertion before
                the response is built, on every path reaching this handler
  verification: trace handler → service → repository → SQL; check ORM default scopes;
                check RLS policy on `invoices`; check middleware ordering
  status:       OPEN | REFUTED | SUPPORTED | INCONCLUSIVE
  outcome:      <what you actually found, with evidence IDs>
```

**A hypothesis without a `falsifier` is not a hypothesis.** Write the falsifier before you look for
evidence: it is the commitment that stops you from pattern-matching your way to a foregone conclusion.

```bash
sa hypothesis add --surface "POST /api/v1/invoices/:id/download" \
  --statement "..." --falsifier "..." --evidence-required "..." --module authz
```

## Generating hypotheses

Derive them from the threat model, not from a vulnerability list. For each attack surface, walk
these six generators. They are ordered by historical yield in Web/SaaS assessments.

| # | Generator | Question |
|---|---|---|
| 1 | **Boundary crossing** | What trust boundary does this input cross, and who validates it on the far side? |
| 2 | **Ownership** | Every object reference in the request — who proves the caller owns it? |
| 3 | **Privilege** | What can a low-privilege actor reach that was designed for a high-privilege one? |
| 4 | **State** | What sequence of legitimate calls reaches an illegitimate state? |
| 5 | **Assumption** | What does this code assume about its caller that the caller can violate? |
| 6 | **Asymmetry** | Where does one cheap request cause expensive or irreversible work? |

Then, for each generator, ask the inverse: **what would have to be true for this to be safe?**
That inverse is your falsifier and usually names the exact control to go look for.

### Prioritise

Order hypotheses by `(reachability × impact) / verification cost`. Assess in that order, because you
will run out of budget before you run out of hypotheses. Record what you did not get to as coverage
gaps, never as "clean".

## Falsification first

**Search for the refuting evidence before the confirming evidence.** This ordering is the single
highest-leverage anti-false-positive mechanism in this skill.

Reason: confirming evidence is easy to find and easy to over-read. A missing check in one handler
"confirms" a hypothesis until you notice the middleware two layers up, the ORM default scope, or the
database row-level policy. If you look for the control *first*, you either find it (hypothesis
REFUTED — cheap, correct, no report noise) or you establish its absence deliberately, which is a far
stronger claim than not having noticed it.

Concretely, for each hypothesis:

1. Enumerate every place the control *could* live: framework middleware, decorators/guards, route
   config, service layer, ORM scope, database policy, gateway/WAF, network boundary.
2. Check each one. Record what you checked — including where you found nothing. "Checked, absent" and
   "did not check" are different claims and the report must distinguish them.
3. Only then look for the vulnerable path.

```bash
sa hypothesis refute H-007 --evidence EV-031 --note "RLS policy tenant_isolation on invoices covers this path"
sa hypothesis support H-007 --evidence EV-032,EV-033
sa hypothesis inconclusive H-007 --unknown U-004
```

## Statuses

| Status | Meaning | Next |
|---|---|---|
| `OPEN` | Stated, evidence not yet gathered | Collect evidence |
| `REFUTED` | A control demonstrably prevents it | Close. Record the control — it may be load-bearing elsewhere, and it belongs in the report's positive observations |
| `SUPPORTED` | Evidence shows it holds | Promote to candidate → FP triage → finding |
| `INCONCLUSIVE` | Blocked by an UNKNOWN or lack of access | Register the UNKNOWN. Report as an assessment gap, **never** as a finding and **never** as safe |

`INCONCLUSIVE` is a legitimate, valuable outcome. A report that says "we could not verify tenant
isolation on the reporting service because we had no access to it" tells the customer something true
and actionable. A report that silently omits it does not.

## Refuted hypotheses are deliverable content

Record them. They tell the customer which of their controls are actually working, they justify the
assessment's depth, and at re-assessment time they are the regression suite: if a refuted hypothesis
becomes supported after a refactor, the control was removed.

## Coverage ledger

Every attack surface ends in exactly one state: `assessed` (hypotheses resolved), `partial`
(some INCONCLUSIVE), `not-assessed` (with a reason). `sa status` reports the split, and the reason
is required — "ran out of time" is an acceptable reason, silence is not.
