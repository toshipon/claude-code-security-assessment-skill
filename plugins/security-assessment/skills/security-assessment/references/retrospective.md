# Continuous Improvement

The point: assessment N+1 should be better than assessment N, without customer information ever
leaking into the shared knowledge base.

Run at the end of every engagement, and again after remediation review.

## 1. Engagement-local retrospective

Stays in the workspace. May contain customer specifics.

```bash
sa retro draft     # scaffolds <workspace>/retrospective.md from templates/retrospective.md
```

Answer honestly — this file exists to record what went wrong:

| Question | Why it matters |
|---|---|
| **Missed hypotheses** — what did the customer, a later test, or the remediation review find that we did not? | The single most valuable input. Which generator in `method-hypothesis.md` *should* have produced it? |
| **False positives** — what did we report that was wrong? At which pipeline stage should it have died? | Every FP that reached the report is a pipeline defect |
| **Near-misses** — what did we nearly kill for a bad reason? | The FP pipeline can be too aggressive; that failure is invisible unless recorded |
| **Detection patterns that worked** — which greps, queries, traces paid off? | Becomes a verification recipe |
| **Verification methods that worked** — how did we settle a hard hypothesis cheaply? | The most reusable artifact |
| **UNKNOWNs** — what blocked us, and what access would have unblocked it? | Feeds the next engagement's scoping request |
| **Effort** — where did time actually go vs. where did findings come from? | Reprioritises the module order |
| **Customer-specific exceptions** — accepted risks, intended behaviours that look like bugs | Stays local. Prevents re-reporting next time |

## 2. Promotion to shared knowledge

Only **generalized** lessons leave the workspace.

```bash
sa retro promote --entry <id> --target detection-patterns|verification-recipes|false-positive-catalog
```

The promotion gate:

1. **Sanitizer (automatic, blocking)** — rejects customer/org names from `engagement.json`, domains,
   hostnames, IPs, repo and bucket names, ARNs and account IDs, email addresses, person names,
   ticket/PR IDs, absolute paths containing the workspace, and anything matching a credential shape.
2. **Generality test (you)** — would this help on a system built by a different company on a
   different stack? If it only makes sense with the customer's architecture in mind, it does not
   promote. Rewrite it until it does, or drop it.
3. **Human approval (required)** — a person confirms before the entry is written. The sanitizer is a
   safety net for mistakes, not a substitute for judgement.

### Rewriting for promotion

```
LOCAL   Acme's /api/v2/orders/:id returned other tenants' orders because OrderService.find()
        bypassed the tenant scope added in OrderRepository.
                                    ↓
SHARED  Where tenant scoping lives in a repository layer, service-layer methods that call the
        underlying ORM directly bypass it. Enumerate every caller of the raw ORM handle, not
        just the repository's public methods.
        Detection: grep for the ORM entry symbol, subtract known repository files.
```

The shared entry keeps the *mechanism* and the *detection method*, and loses the customer.

## 3. Knowledge base

```
knowledge/
├── detection-patterns.md        where a class of weakness tends to hide, and how to look
├── verification-recipes.md      how to settle a hypothesis cheaply and conclusively
└── false-positive-catalog.md    patterns that look bad and are not, with the reason
```

Each entry: **Pattern → Why it matters → How to check → How to falsify → Common FP cause.**
Entries carry a hit/miss count, updated at each engagement. An entry whose misses exceed its hits is
a bad entry — fix it or delete it.

## 4. Improving this skill

If a retrospective shows a *structural* gap — a module missing a whole hypothesis class, a severity
guardrail that produced a wrong band, a pipeline stage that keeps letting FPs through — change the
skill itself, not just the knowledge base. Record the change and its motivating engagement (by
engagement ID, never by customer name) in `CHANGELOG.md`.
