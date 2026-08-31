# Method: False Positive Reduction

Every lead — from a tool, from a subagent, from your own reading — enters as a **candidate** and must
survive this pipeline before it can become a finding. The customer's trust in the whole report is set
by the worst finding in it.

```
candidate → [1] reachability → [2] controls → [3] exploitability → [4] impact → [5] classification
```

A candidate may be killed at any stage. **Record the kill and its reason** — the false-positive
catalog in `knowledge/false-positive-catalog.md` is built from these, and it is what stops the next
assessment from re-litigating the same pattern.

```bash
sa candidate add --source semgrep --raw "sqli in reports.py:88" --module repo
sa candidate advance C-012 --stage reachability --result pass --note "reachable from GET /reports?q="
sa candidate kill C-013 --stage controls --reason "parameterised by SQLAlchemy; the f-string is the ORDER BY allowlist key, values validated against a literal tuple at reports.py:71"
sa candidate promote C-012 --finding-title "SQL injection in report search"
```

## Stage 1 — Reachability

*Can attacker-controlled data actually get here?*

- Trace **source → sink**. Name the entry point: route + method, queue consumer, cron, webhook, CLI.
- Is the code reachable at all? Dead code, an unreferenced export, a `dev`-only branch, a feature
  flag that is off in production, a route not mounted — all kill the candidate.
- Does the tainted value actually reach the dangerous parameter, or only a neighbouring one?
- What authentication is required to reach it? Unauthenticated reachability changes everything downstream.

**Kill if:** unreachable, not attacker-controlled, or the taint does not reach the sink.
**Do not kill for:** "it needs authentication". Authenticated users are attackers too — that is an
exploitability input, not a refutation.

## Stage 2 — Existing controls

*What already defends this, and does it actually hold?*

Enumerate every layer, then verify each is genuinely in effect on **this** path:

| Layer | Verify |
|---|---|
| Input validation / schema | Applied to *this* field? Allowlist or denylist? Runs before the sink? |
| Framework default | Version-correct, not overridden, not bypassed by the API used here (e.g. `dangerouslySetInnerHTML`, `raw`, `mark_safe`, `text/html` responses) |
| ORM / query builder | Parameter binding on this call, not string interpolation into it |
| Middleware / guard / decorator | In the chain for this route, and **ordered before** the handler |
| Database policy | RLS enabled *and* forced, policy covers this operation and this role |
| Encoding on output | Contextually correct (HTML vs attribute vs JS vs URL) |
| Network / gateway | Genuinely unreachable, not merely undocumented |
| WAF / rate limit | Treat as **mitigating, never eliminating**. Never kill a candidate on a WAF alone |

**Kill if** a control demonstrably prevents exploitation on every path. Cite the control's location —
this is the most common place where a *wrong* kill happens, so the citation is mandatory and
`sa validate` requires it on kills at this stage.

**Do not kill for:** a control that exists somewhere else in the codebase, a control on the
*happy path* only, or a control you assume the framework provides (that is E6 — go verify it).

## Stage 3 — Exploitability

*Construct the attack. Can the preconditions actually be met?*

Write the concrete sequence: attacker position → required knowledge → steps → result. Then check
each precondition against reality:

- Needs a valid object ID? Are IDs sequential/guessable, or UUIDv4 with no enumeration oracle?
- Needs a privileged role? Can a low-privilege user obtain it, or is self-signup limited?
- Needs a race window? Is it microseconds or seconds — and is there a lock, transaction isolation
  level, or idempotency key?
- Needs a specific header, content type, or parser quirk? Does the stack actually accept it?

**Kill if** a precondition cannot be met by the modelled attacker.
Downgrade — do not kill — if it merely makes exploitation harder.

## Stage 4 — Business impact

*What does the attacker actually get?*

- Which asset from the threat model is affected, and what is its classification?
- Read, modify, delete, escalate, persist, pivot?
- Blast radius: one record, one tenant, all tenants, the whole account?
- Would the customer notice? (detection is not prevention, but it is an impact input)

**Kill or drop to Informational if** the impact is nil: exposing already-public data, a "secret" that
is a public key, self-XSS with no delivery path, a CSRF on a non-state-changing endpoint.

## Stage 5 — Classification

| Class | Criteria |
|---|---|
| `CONFIRMED` | Passed all stages. E1/E2 evidence. No open UNKNOWN on the path |
| `SUSPECTED` | Passed all stages but evidence is E3, or one control could not be fully verified |
| `NEEDS-VERIFICATION` | Blocked by an UNKNOWN or missing access. State exactly what would resolve it |
| `NOT-EXPLOITABLE` | Real weakness, no viable attack path today. Report as Informational if it is one refactor away from being live |
| `FALSE-POSITIVE` | The candidate was wrong. Log to the FP catalog with the reason |
| `OUT-OF-SCOPE` | Real, but outside the engagement. Tell the customer it exists |

## Tool output specifically

Tool output enters at Stage 1 with grade E5 and **no severity**. Discard the tool's severity entirely
until Stage 5 — anchoring on it is the dominant cause of mis-rated reports.

| Tool | Its systematic blind spot |
|---|---|
| Semgrep / CodeQL | No business context; cannot see whether the tenant predicate two layers up is load-bearing |
| Dependency scanners | Flag CVEs in code paths the app never calls; no reachability |
| Cloud posture scanners | No compensating-control awareness (SCP, network isolation, permission boundary) |
| Secret scanners | Test fixtures, public keys, example values, already-rotated keys |
| LLM review (including you) | Confident narration of plausible-but-absent code. **Re-read the actual file before every claim** |

## Anti-rationalisations

Kill candidates for real reasons. These are not real reasons:

- "It's behind authentication" — authenticated users are attackers
- "It's internal only" — verify network isolation, or it is an assumption (E6)
- "The framework handles it" — verify the version, the config, and this call site
- "It's only staging" — verify staging has no production data and no path to production
- "No one would find this" — enumeration is cheap and automated

And do not manufacture findings for their own sake. A short report with six real findings is worth
more than thirty of which twenty are noise — and the customer will fix six.
