# Claude Code Security Assessment Skill

A **hypothesis-driven** security assessment skill for [Claude Code](https://claude.com/claude-code),
aimed at Web/SaaS systems.

Most security tooling asks *"does this pattern appear?"*. This skill asks *"given how this system
actually works, what could an attacker achieve — and can I prove it?"* It refuses to publish a
finding it cannot back with evidence.

> **Not a scanner.** If you want a fast full-stack pattern sweep, use the companion
> [security-audit skill](https://github.com/toshipon/claude-code-security-audit-skill).
> This one is for customer engagements, pre-launch reviews, and pre-audit work — where a false
> positive costs credibility and a silent gap costs more.

## Why

Two failure modes make a security deliverable worthless. Everything here is built to prevent both.

| Failure | How it happens | Countermeasure |
|---|---|---|
| **False positives** | A pattern is reported without proving reachability, exploitability, or the absence of a control | A falsifier is written *before* evidence is collected · a five-stage triage pipeline · six evidence grades · a `validate` gate that refuses to publish |
| **Silent gaps** | An area is assumed safe because nobody looked at it | An `UNKNOWN` registry with resolution paths · a coverage ledger every report must carry |

An honest *"not assessed"* beats a confident guess. Reports state what was **not** examined, because
a customer who believes they were assessed when they were not is worse off than one who knows.

## Install

```
/plugin marketplace add toshipon/claude-code-security-assessment-skill
/plugin install security-assessment@toshipon-security
```

Optionally add the companion pattern library — the skill works without it, but detection is sharper
with it:

```
/plugin marketplace add toshipon/claude-code-security-audit-skill
```

Then start an assessment by asking Claude for one, or invoke `/security-assessment` directly.

## What you get

| Component | |
|---|---|
| **`security-assessment` skill** | Orchestrator + 15 assessment modules + method references + report templates |
| **`security-assessor` agent** | Per-module evidence collection, dispatchable in parallel |
| **`sa` CLI** | The engagement workspace: assessment stack, ledgers, severity computation, publication gate |

## How it works

```
 [0] Engagement gate      authorization + scope recorded, or STOP
 [1] Recon                system model  (+ UNKNOWNs)
 [2] Attack surface       enumerated entry points, prioritised
 [3] Threat model         assets · actors · trust boundaries · data flows
  ↓
 ┌─[4] Hypothesise     one falsifiable statement per surface
 │  [5] Collect        dispatch modules, record graded evidence
 │  [6] Falsify first  try to DISPROVE before you try to confirm
 │  [7] Triage         reachability → controls → exploitability → impact
 │  [8] Rate           T × E × B × X, guardrails applied
 └──← next surface
  ↓
 [9] Report               technical · executive · remediation plan
 [10] Remediation review  re-assess after fixes, at the new commit
 [11] Retrospective       improve the skill, sanitized
```

**Falsification first** is the highest-leverage idea here. Confirming evidence is easy to find and
easy to over-read: a missing check in one handler "confirms" a bug until you notice the middleware
two layers up, the ORM default scope, or the row-level policy. Looking for the *control* first either
refutes the hypothesis cheaply, or establishes its absence deliberately — a far stronger claim than
not having noticed it.

## The assessment stack

State lives in an engagement workspace outside the skill, driven by the `sa` CLI. Like `pstack` for a
process, `sa stack dump` shows exactly where the assessment is at any moment — so it is resumable
across sessions, delegable to subagents, and cannot silently drop an open thread.

```bash
SA="python3 <skill>/scripts/sa.py --workspace ./assessment-acme-20260831"

$SA init --name "Acme SaaS assessment"
$SA stack dump      # what is still open?
$SA status          # coverage, counts, blockers
$SA validate        # publication gate
$SA report technical && $SA report executive && $SA report remediation
```

## The publication gate

`sa validate` refuses to generate reports when a finding:

- has no evidence, or only **E5/E6** (tool output and inference)
- claims **Critical** without E1/E2 evidence
- claims **CONFIRMED** while an `UNKNOWN` is open on its exploitation path
- cites a **tool's rating** as its severity rationale
- records no `controls_checked` — no account of where a defence was looked for
- is Critical/High without a human-review flag
- rates `NEEDS-VERIFICATION` as Critical

It also fails on open stack frames, attack surfaces left in a `pending` coverage state, and
credential-shaped strings anywhere in the workspace.

### Evidence grades

| | |
|---|---|
| **E1** | Observed directly in an authorized environment |
| **E2** | Full code path traced, every intervening control checked |
| **E3** | Sink located, one link inferred rather than read |
| **E4** | Configuration read from the authoritative source |
| **E5** | Tool output, unverified |
| **E6** | Inference or framework convention |

E5 and E6 can never, alone, support a finding. They are candidates — they tell you where to spend
E2/E4 effort. Promoting a scanner hit to a finding is precisely what a customer is paying you not to
do; they can run the scanner themselves.

### Severity is computed, not asserted

```
score = 0.35·T + 0.25·E + 0.25·B + 0.15·X        # each factor 1–4
        Critical ≥ 3.50 · High ≥ 2.80 · Medium ≥ 2.00 · Low ≥ 1.40
```

`T` technical impact · `E` exploitability · `B` business impact · `X` exposure.

Every finding stores its four factors, so any rating can be re-derived or challenged. CVSS alone is
rejected: it cannot know whether the endpoint is internet-facing or whether the data behind it is a
blog or a payroll table. Manual override is allowed by **one band**, with a recorded reason that
appears in the report appendix.

## Coverage

| Area | Module |
|---|---|
| System understanding, attack surface | `recon` |
| Assets, actors, trust boundaries, data flows | `threat-model` |
| Injection and unsafe sinks | `repo-assessment` |
| Browser trust model, CSP, CSRF, uploads | `web-assessment` |
| OWASP API Top 10, GraphQL, webhooks | `api-assessment` |
| Sessions, MFA, reset, OAuth/OIDC, JWT | `auth-assessment` |
| **IDOR/BOLA, tenant isolation, privilege boundaries** | `authz-assessment` |
| Workflow bypass, race conditions, pricing, replay | `business-logic-assessment` |
| Secrets, git history, crypto, key management | `secrets-crypto-assessment` |
| Reachability-triaged CVEs, supply chain | `dependency-assessment` |
| Public exposure, network, encryption, logging | `cloud-assessment` |
| Privilege escalation paths, OIDC trust conditions | `iam-assessment` |
| Terraform/CFN/K8s, drift against deployed state | `iac-assessment` |
| Untrusted input in pipelines, secrets, OIDC | `cicd-assessment` |
| Re-assessment after fixes | `remediation-review` |

`authz-assessment` has the highest yield in SaaS work and is never skipped — authorization bugs are
invisible to scanners because the code looks correct and the tests pass.

## Safety

Default posture is **PASSIVE**: read code, configuration and IaC; read-only API calls with supplied
credentials. No traffic to the target application.

`sa` refuses to record runtime evidence collected above the authorized posture. Data deletion, denial
of service, credential attacks, persistence, destructive exploitation and anything touching third
parties are **never** automatic — they require written, per-technique authorization.

Where a hypothesis cannot be settled passively, the skill prefers asking a customer engineer to run
the command and share the output: E1 evidence, zero risk, and usually faster than obtaining approval.

## Human review

This does not replace a security engineer. Severity ("how bad if real") and AI confidence ("how sure
am I that it is real") are reported as **separate** numbers, because conflating them is how a real
Critical gets ignored. Human review is always flagged for Critical/High, authorization,
authentication, business logic, cloud IAM, and cryptography.

## Continuous improvement

After each engagement, a retrospective captures missed hypotheses, false positives, and verification
methods that worked. Only **generalized** lessons reach the shared knowledge base, through a gate
that blocks customer names, domains, IPs, ARNs, account IDs, repository references and credential
shapes — and requires human approval. Customer-specific information never leaves the engagement
workspace.

## Development

```bash
python plugins/security-assessment/skills/security-assessment/tests/test_sa.py   # 46 tests
python scripts/check-references.py                                              # cross-reference check
```

Standard library only, no dependencies. CI runs both on Python 3.9 / 3.11 / 3.13.

## License

MIT © toshipon
