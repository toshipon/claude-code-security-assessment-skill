# Module: Remediation Review

> **Load when** the customer reports that fixes have landed.
> **Do not trust the claim, do not trust the diff, and do not re-use the original evidence.**

Re-assessment is where an assessment earns its second half of value — and where the most damaging
possible error lives: telling a customer something is fixed when it is not. A finding you close
incorrectly stops being tracked by anyone.

## Rules

1. **Re-collect evidence at the new commit.** Original evidence was taken at a different SHA and is
   stale by definition (`references/method-evidence.md` §Staleness).
2. **Re-run the original hypothesis, not the original grep.** The hypothesis is the question; the fix
   may have moved the code without answering it.
3. **A fix is verified only when the original attack scenario, replayed step by step, now fails —
   and you can say at which step it fails and why.**
4. **Assess the fix as new code.** Fixes are written under time pressure, often by whoever was
   available, frequently in security-sensitive paths. They introduce new bugs at an above-average
   rate. Every fix diff goes through `repo-assessment.md` and `authz-assessment.md` as if it were a
   fresh feature.

## Procedure per finding

```bash
sa finding reopen F-003 --reason "..."     # or
sa finding fix F-003 --commit <sha> --evidence EV-101 --verification "..."
```

1. **Read the diff.** `git log --oneline <old>..<new> -- <affected paths>`, then the full diff of the
   fix. Understand what was actually changed, not what the ticket says was changed.
2. **Re-run the hypothesis.** Trace the same path from the same entry point at the new commit.
3. **Check completeness** — the most common failure mode:
   - Was the fix applied to **every instance** listed in the finding, or only the one in the title?
   - Every HTTP verb, not just the one demonstrated?
   - The asynchronous/background twin of the operation?
   - The bulk, export and legacy-version routes?
   - Other places with the same root cause that were not in the original finding?
4. **Check the layer.** A fix at the handler is weaker than one at the service, ORM or database layer.
   If the root cause was "authorization is enforced per handler and gets forgotten", a fix in one
   handler does not address it. Say so: the finding is *mitigated at this location*, and the systemic
   issue remains open.
5. **Look for regressions.** Does the fix break something, or open something new? Common: an
   authorization check added but placed after the data is loaded (fixing disclosure, leaving a
   timing/existence oracle); input validation added that breaks a legitimate flow, which someone will
   revert next sprint; a rate limit added that enables account denial.
6. **Assign an outcome.**

| Outcome | Meaning |
|---|---|
| `fixed` | Hypothesis re-run, refuted, evidence re-collected at the new commit, all instances covered |
| `partially-fixed` | Some instances or paths remain. **Stays open**, severity re-rated for what remains |
| `mitigated` | Exploitation is harder but the root cause remains. Stays open at reduced severity, with the residual risk stated |
| `not-fixed` | No effective change |
| `regressed` | The fix introduced a new issue → **a new finding**, cross-referenced |
| `risk-accepted` | The customer accepts it. Record who accepted, when, and the stated compensating control |

`partially-fixed` and `mitigated` are the honest answers most of the time, and using them is what
makes the report trustworthy.

## Regression protection

For each verified fix, give the customer something that keeps it fixed:

- A test that fails if the vulnerability returns — the highest-value artifact this module produces.
  A request that must return 403, a query that must return zero rows, an assertion in CI.
- Where possible, a control at a layer that cannot be forgotten: a database constraint, a FORCEd RLS
  policy, a base class or middleware rather than a per-handler check, a lint rule.
- A note in the report that the refuted hypothesis is now part of the regression suite.

## Report

Produce a delta report, not a new assessment:

```markdown
## Remediation Review — <date>, commit <sha>

| ID | Finding | Original | Outcome | Now |
|----|---------|----------|---------|-----|
| F-001 | Cross-tenant invoice download | Critical | fixed | closed |
| F-002 | Mass assignment on user update | High | partially-fixed | Medium — `/api/v2/users` fixed, `/api/v1/users` unchanged |
| F-003 | Weak reset token | High | mitigated | Medium — entropy raised, still not single-use |
| F-009 | — | — | regressed | New: F-012, authorization check placed after data load |

Verified fixed: N   Still open: N   New: N
Residual risk: <one paragraph the customer can take to their board>
```

Then update `coverage.json`, re-run `sa validate`, and run the retrospective
(`references/retrospective.md`) — remediation review is the best available signal about which of your
original findings were real, which were false positives, and which hypotheses you missed entirely.
