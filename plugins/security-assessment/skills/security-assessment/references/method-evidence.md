# Method: Evidence

No evidence, no finding. This file defines what counts and how strongly.

## Evidence grades

| Grade | What it is | Example |
|---|---|---|
| **E1** | Direct observation of the behaviour in an authorized environment | A staging request returning another tenant's record, with request/response captured |
| **E2** | Complete code path traced end-to-end: entry point → sink, with every intervening control checked | Route → middleware chain → handler → service → SQL, showing no tenant predicate anywhere |
| **E3** | Dangerous sink located and a source shown to reach it, but one link is inferred rather than read | Raw SQL concatenation in a helper called by a handler whose full call graph was not traced |
| **E4** | Configuration or metadata read directly from the authoritative source | `aws s3api get-public-access-block` output; a Terraform resource in the applied state |
| **E5** | Third-party tool output, unverified | A Semgrep hit, a Dependabot alert, a cloud posture scanner row |
| **E6** | Inference, convention, or prior belief about the framework | "Rails escapes this by default"; "this library is usually configured safely" |

### Rules

- **E5 and E6 can never, alone, support a finding.** They are candidates. They point you at where to
  spend E2/E4 effort. Promoting an E5 to a finding is exactly what the customer is paying you not
  to do — they can run the scanner themselves.
- **`CONFIRMED` requires E1 or E2**, plus no open UNKNOWN on the exploitation path.
- **Critical severity requires E1 or E2.** Enforced by `sa validate`.
- **E3 caps confidence at `SUSPECTED`.** Name the unread link explicitly in the finding.
- **E4 is sufficient for configuration findings** (a public bucket, a wildcard IAM policy, disabled
  logging) because the configuration *is* the vulnerability. It is not sufficient for anything whose
  impact depends on application behaviour.
- E6 belongs in the reasoning, never in the evidence list. If a framework default is doing the
  defending, **verify the default is actually in effect in this codebase** — version, config flag,
  and no override — and that verification is E2 or E4.

## Recording

Evidence is an artifact, not a sentence. Store the artifact; reference it by ID.

```bash
sa evidence add --grade E2 --kind code \
  --locator "src/api/invoices/download.ts:41-78" \
  --summary "handler resolves invoice by id with no tenant predicate; no guard decorator" \
  --artifact ./excerpt.txt
```

| Field | Requirement |
|---|---|
| `grade` | E1–E6 |
| `kind` | `code` / `config` / `runtime` / `network` / `db` / `tool` / `doc` / `interview` |
| `locator` | `path:line-range`, resource ARN, endpoint + method, or query — must be re-checkable by the customer |
| `summary` | What it shows, in one sentence, in your own words |
| `artifact` | The excerpt, response, or command output. Redacted per §Handling customer data |
| `collected_at` | Auto. Evidence goes stale — the code moves |
| `command` | For `kind=tool`/`config`/`db`: the exact command run, so the customer can reproduce |

Anything a customer cannot re-check independently is not evidence. **Always cite `file:line`** — a
finding that says "in the invoice service" costs the customer an hour before they can even start.

## Absence of evidence

Recording that a control is *missing* requires showing where you looked. A finding that claims
"no authorization check" must enumerate the checked locations:

```
searched for authorization on POST /api/v1/invoices/:id/download:
  - route definition            src/api/routes.ts:112          — no guard
  - global middleware chain     src/app.ts:34-52               — authn only, no authz
  - handler                     src/api/invoices/download.ts   — no ownership assertion
  - service layer               src/services/invoice.ts:88     — no tenant predicate
  - ORM default scope           src/models/invoice.ts          — none defined
  - database RLS                \d+ invoices                   — RLS not enabled
```

This is the difference between "we found no check" and "there is no check", and the customer will
test that difference during triage. Six checked locations is a defensible claim; one is not.

## Handling customer data

- Redact secrets, PII, tokens and customer records **at capture time**, in the artifact itself.
  Keep enough to prove the point: `Authorization: Bearer eyJ…<redacted>`, `email: a***@example.com`.
- A leaked credential is proven by its location and shape, never by its value. Record
  `.env.production:12 — Stripe live secret key (sk_live_…, 107 chars)`, not the key.
- Evidence stays in the engagement workspace. It never enters `knowledge/`, this skill, or any commit.
- `sa validate` scans the workspace for high-entropy strings and common credential shapes before
  reports are generated, and fails on a hit.

## Staleness

Every evidence record carries the commit SHA or resource version it was taken from
(`sa evidence add` captures `git rev-parse HEAD` when the locator is inside a repo). At remediation
review, evidence taken against a different SHA must be re-collected, not re-used. Re-testing a fix
against stale evidence is how a "verified fixed" finding gets reopened by a real attacker.
