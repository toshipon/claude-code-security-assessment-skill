---
name: security-assessment
description: Hypothesis-driven security assessment for Web/SaaS systems. Builds a system model, maps attack surface, threat-models, generates and falsifies vulnerability hypotheses, collects evidence from code/config/cloud, then produces evidence-backed findings, an executive summary and a remediation plan. Use for "security assessment", "セキュリティアセスメント", "threat model", "attack surface", "脅威モデリング", pre-launch/pre-audit security review, or remediation re-assessment. Not for quick pattern scans — use security-audit for that.
allowed-tools: Read, Grep, Glob, Bash, WebFetch, WebSearch, Task, TodoWrite
references:
  - method-hypothesis
  - method-evidence
  - method-false-positive
  - method-severity
  - method-safety
---

# Security Assessment

You are running a **hypothesis-driven security assessment**, not a vulnerability scan.

A scan asks *"does this pattern appear?"*. An assessment asks *"given how this system actually
works, what could an attacker achieve, and can I prove it?"*. The deliverable is a small number
of findings the customer can act on, each backed by evidence — not a long list of maybes.

**The two failure modes this skill exists to prevent:**

| Failure | Cause | Countermeasure in this skill |
|---------|-------|------------------------------|
| False positives | Reporting a pattern without proving reachability, exploitability, or absence of controls | Falsification requirement + FP triage pipeline + evidence grades |
| Silent gaps | Assuming a component is safe because you did not look at it | UNKNOWN registry + explicit coverage ledger |

Both are worse than finding nothing. **An honest "not assessed" beats a confident guess.**

---

## 0. Read this before anything else

1. **Never guess safe or unsafe.** If you cannot establish a fact, register it as an `UNKNOWN`
   (`sa unknown add`). An UNKNOWN on a code path blocks any finding on that path from reaching
   `CONFIRMED`. This is enforced by `sa validate`.
2. **Never run intrusive tests without written authorization.** See `references/method-safety.md`.
   Default posture is **PASSIVE** (read code, read config, read-only API calls to systems you were
   given credentials for). Anything else needs an explicit, recorded approval.
3. **Never promote a tool's verdict to a finding.** Semgrep/CodeQL/Trivy/Dependabot/cloud scanner
   output enters as a *candidate* and must survive `references/method-false-positive.md`.
   "The tool said Critical" is not a severity justification and is rejected by `sa validate`.
4. **Every finding needs an attack scenario you can narrate end-to-end**, from an entry point an
   attacker can actually reach, through the preconditions, to the impact. If you cannot narrate it,
   you do not understand it yet — it is `NEEDS-VERIFICATION`, not a finding.

---

## 1. The assessment stack

The assessment is driven by an explicit **stack of open investigation frames**, persisted on disk.
Like `pstack` for a process, `sa stack dump` shows you exactly where the assessment is at any moment,
and the assessment is resumable across sessions and delegatable to subagents.

```
frame kinds:  engagement → surface → hypothesis → verification → candidate
```

You **push** a frame when you start investigating something and **pop** it when it reaches a terminal
state. A frame may only be popped with a recorded outcome. The stack is the anti-drift mechanism:
long assessments fail because the agent chases an interesting thread and forgets nine others.

Paths in this skill (`modules/…`, `references/…`, `templates/…`) are relative to the skill root,
`${CLAUDE_SKILL_DIR}`.

```bash
SA="python3 ${CLAUDE_SKILL_DIR}/scripts/sa.py"          # engagement workspace CLI
$SA --help                                              # full command reference
$SA stack dump                                          # where am I? what is still open?
$SA status                                              # coverage, counts, blockers
```

**Rule: at the end of every phase, run `sa stack dump`. Never end a session with open frames
without listing them to the user.**

---

## 2. Engagement workspace

All state lives in one directory, outside this skill. Customer data never enters the skill directory.

```
<workspace>/
├── engagement.json        scope, authorization, ROE, data-handling  (the safety gate)
├── stack.json             the assessment stack
├── system-model.md        what the system is and does
├── attack-surface.md      enumerated entry points
├── threat-model.md        assets, actors, trust boundaries, data flows
├── unknowns.jsonl         U-nnn — facts you could not establish
├── hypotheses.jsonl       H-nnn — the assessment engine
├── candidates.jsonl       C-nnn — tool output and leads, pre-triage
├── findings.jsonl         F-nnn — survivors, with evidence
├── evidence/              raw artifacts (code excerpts, responses, configs)
├── coverage.json          what was assessed vs. deliberately skipped
└── reports/               technical / executive / remediation-plan
```

```bash
$SA init --workspace ./assessment-<customer>-<yyyymmdd> --name "<engagement name>"
```

---

## 3. The loop

Phases 1–3 are always run. Phase 4 onward loops per attack surface.

```
  [0] Engagement gate      → authorization + scope recorded, or STOP
  [1] Recon                → system-model.md    (+ UNKNOWNs)
  [2] Attack surface       → attack-surface.md
  [3] Threat model         → threat-model.md
   ↓
  ┌─[4] Hypothesise ────→ H-nnn per surface, each with a falsifier
  │  [5] Collect evidence → dispatch modules (§4), record artifacts
  │  [6] Falsify first ──→ try to DISPROVE before you try to confirm
  │  [7] Triage ─────────→ FP pipeline: reachability → controls → exploitability → impact
  │  [8] Rate ───────────→ T × E × B × X, guardrails applied
  └──← more surfaces? loop
   ↓
  [9] Report              → technical + executive + remediation plan
  [10] Remediation review → re-assess after fixes
  [11] Retrospective      → improve this skill, sanitized
```

### Phase 0 — Engagement gate (blocking)

Do not proceed until `engagement.json` records: **who authorized this**, **what is in scope**
(repos, domains, cloud accounts, environments), **what is explicitly out of scope**, **the allowed
test posture** (PASSIVE / ACTIVE-SAFE / INTRUSIVE), and **how customer data must be handled**.

If authorization is absent, run the assessment in PASSIVE mode against code and configuration only,
say so plainly, and record every check that was skipped for lack of authorization.

```bash
$SA init --workspace <dir> --name "<name>"
$SA scope set --posture passive --in-scope "repo:acme/api,env:staging" --out-of-scope "prod,third-party"
$SA scope authorize --by "<name/role>" --ref "<ticket/email/SOW>" --posture active-safe   # only with real approval
```

### Phase 1–3 — Understanding before hunting

Run `modules/recon.md`, then `modules/threat-model.md`. Do not skip to pattern matching.
An assessment that starts at Phase 4 finds only what a linter finds.

### Phase 4–8 — The engine

Read `references/method-hypothesis.md` once, at the start of Phase 4. It defines the hypothesis
lifecycle and the falsification requirement that the rest of the loop depends on.

### Phase 9–11 — Deliverables and learning

`templates/report-technical.md`, `templates/report-executive.md`, `templates/remediation-plan.md`,
then `modules/remediation-review.md` and `references/retrospective.md`.

---

## 4. Module routing

Load **only** the modules the system actually has. Each module is a self-contained brief: it can be
read inline, or dispatched to a subagent with the module path and the workspace path.

| Load when the system has… | Module |
|---|---|
| *(always, Phase 1–2)* | `modules/recon.md` |
| *(always, Phase 3)* | `modules/threat-model.md` |
| source code you can read | `modules/repo-assessment.md` |
| a browser-facing app | `modules/web-assessment.md` |
| HTTP/GraphQL/gRPC APIs | `modules/api-assessment.md` |
| login, sessions, tokens, SSO | `modules/auth-assessment.md` |
| roles, tenants, object ownership | `modules/authz-assessment.md` ← **highest yield, never skip** |
| workflows, payments, quotas, state machines | `modules/business-logic-assessment.md` |
| secrets, crypto, tokens, logging | `modules/secrets-crypto-assessment.md` |
| package manifests / lockfiles | `modules/dependency-assessment.md` |
| AWS/GCP/Azure accounts you can read | `modules/cloud-assessment.md` |
| IAM policies, roles, cross-account trust | `modules/iam-assessment.md` |
| Terraform / CloudFormation / Pulumi / k8s | `modules/iac-assessment.md` |
| GitHub Actions / GitLab CI / CD pipelines | `modules/cicd-assessment.md` |
| *(after fixes land)* | `modules/remediation-review.md` |

**Technology-specific detection patterns are not duplicated here.** They live in the companion
`security-audit` skill — an **optional dependency**
([`toshipon/claude-code-security-audit-skill`](https://github.com/toshipon/claude-code-security-audit-skill)).
Modules cite it as `security-audit/references/<topic>-security.md`, meaning *that skill's references
directory, wherever it is installed* — this skill does not assume a path.

That library says **where to look**; this skill governs **how to conclude**. A pattern from it enters
as a candidate at grade E5 and goes through `references/method-false-positive.md` like any other lead.

**If `security-audit` is not installed, nothing breaks**: retrieve the equivalent guidance from the
authoritative sources in `references/knowledge-sources.md` instead.

### Parallel dispatch

Independent modules are independent investigations — run them concurrently, one subagent per module,
each writing to the shared workspace:

```
Task(subagent) × N:
  "Read <skill>/modules/<module>.md and <skill>/references/method-{hypothesis,evidence,false-positive}.md.
   Workspace: <workspace>. Posture: <posture>. Scope: <scope>.
   Register hypotheses with `sa hypothesis add`, evidence with `sa evidence add`,
   candidates with `sa candidate add`. Do NOT create findings — the orchestrator triages.
   Anything you cannot establish → `sa unknown add`. Report the frame IDs you opened."
```

Subagents produce **hypotheses, evidence and candidates**. Only the orchestrator promotes a candidate
to a finding, because promotion requires cross-module context (a control in one layer can neutralise a
weakness in another — that is exactly where naive per-module reviews generate false positives).

---

## 5. Finding bar

A finding is only publishable when all of these hold. `sa validate` enforces the mechanical parts.

- [ ] Attack scenario narrates end-to-end from a reachable entry point
- [ ] Evidence attached, graded `E1`–`E4` (`E5`/`E6` alone is never a finding — see `method-evidence.md`)
- [ ] Reachability established: entry point → sink, with auth preconditions stated
- [ ] Existing controls enumerated and shown not to neutralise it
- [ ] No open UNKNOWN on the exploitation path (or confidence is capped)
- [ ] Severity computed via `method-severity.md`, not asserted
- [ ] Remediation is specific to this codebase and this framework
- [ ] Verification method stated: how the customer proves the fix worked
- [ ] Confidence recorded: `CONFIRMED` / `SUSPECTED` / `NEEDS-VERIFICATION`
- [ ] `human_review` flagged where `references/method-human-review.md` requires it

```bash
$SA finding new --title "..." --module authz --cwe CWE-639 --owasp "API1:2023"   # scaffolds, then edit
$SA validate                                                                      # gate before reporting
```

`sa validate` fails the run if any finding lacks evidence, cites a tool as its severity rationale,
claims `CONFIRMED` with an open UNKNOWN on its path, or claims Critical without `E1`/`E2` evidence.

---

## 6. Reporting

| Deliverable | Audience | Template |
|---|---|---|
| Technical Assessment Report | Engineers | `templates/report-technical.md` |
| Executive Summary | Execs / PM | `templates/report-executive.md` |
| Remediation Plan | Eng management | `templates/remediation-plan.md` |

```bash
$SA report technical && $SA report executive && $SA report remediation
```

Every report carries an **Assessment Coverage** section: what was assessed, what was *not*, and why
(out of scope / no authorization / no access / UNKNOWN). A report without it overstates its own
assurance, which is the most damaging thing a security deliverable can do.

Remediation buckets: **Immediate** / **7 days** / **30 days** / **90 days** — driven by severity ×
exploitability × effort, not severity alone.

Write deliverables in the customer's language (default: 日本語 for this repo's engagements);
keep finding IDs, CWE/OWASP references and code excerpts verbatim.

---

## 7. Human review

This skill does not replace a security engineer. Mark `Human Review Required` on every finding in
the classes listed in `references/method-human-review.md` — always for Critical/High, authorization,
authentication, business logic, cloud IAM, and cryptography — and state your own confidence
separately from the finding's severity.

---

## 8. Retrospective

After each engagement run `references/retrospective.md`. Missed hypotheses, false positives, and
verification recipes that worked are what make the next assessment better.

```bash
$SA retro draft                    # engagement-local, may contain customer specifics
$SA retro promote --entry <id>     # sanitizer blocks customer identifiers; requires human approval
```

Generalized lessons land in `knowledge/`. **Customer-specific information never leaves the
engagement workspace** — the sanitizer is a hard gate, not a reminder.
