# Finding Schema

Canonical record. `findings.jsonl` holds this shape; `templates/finding.md` renders it.
`sa validate` checks every rule marked **required**.

```jsonc
{
  "id": "F-003",                          // required, assigned by `sa finding new`
  "title": "Cross-tenant invoice download via unvalidated object reference",
  "status": "open",                       // open | fixed | risk-accepted | wont-fix | withdrawn
  "confidence": "CONFIRMED",              // required: CONFIRMED | SUSPECTED | NEEDS-VERIFICATION
  "ai_confidence": "High",                // required: High | Medium | Low
  "ai_confidence_reason": "",             // required unless High
  "human_review_required": true,          // required; see method-human-review.md

  "severity": "Critical",                 // computed — never hand-written
  "severity_factors": { "T": 4, "E": 3, "B": 4, "X": 4 },   // required
  "severity_score": 3.60,                 // computed
  "severity_rationale": "…",              // required; must not be only a tool name + rating
  "severity_override_reason": null,       // required if the band was overridden

  "cwe": ["CWE-639"],                     // required, ≥1
  "owasp": ["API1:2023", "ASVS-4.2.1"],   // required, ≥1
  "module": "authz",

  "affected": [                           // required, ≥1
    { "component": "invoice-api",
      "locator": "src/api/invoices/download.ts:41-78",
      "environment": "all",
      "commit": "a1b2c3d" }
  ],
  "instances": [],                        // other locations of the same root cause

  "preconditions": [                      // required
    "Attacker holds any authenticated account on any tenant",
    "Attacker knows or can enumerate an invoice ID from another tenant"
  ],
  "attack_scenario": "…",                 // required, end-to-end narrative
  "entry_point": "POST /api/v1/invoices/:id/download",   // required
  "attacker_profile": "authenticated low-privilege user",// required

  "evidence": ["EV-031", "EV-032"],       // required, ≥1
  "controls_checked": [                   // required — where you looked for a defence
    { "layer": "middleware", "locator": "src/app.ts:34-52", "result": "authn only, no authz" },
    { "layer": "database-rls", "locator": "\\d+ invoices", "result": "RLS not enabled" }
  ],
  "unknowns": [],                         // open UNKNOWN ids on the exploitation path

  "impact": "…",                          // required — business consequence, not restated technical
  "likelihood": "…",                      // required — narrative: what an attacker needs

  "remediation": {                        // required
    "summary": "Scope invoice lookup by the authenticated tenant.",
    "steps": ["…"],
    "code": "…",                          // diff or snippet, in this codebase's idiom
    "effort": "S",                        // S | M | L
    "bucket": "immediate",                // immediate | 7d | 30d | 90d
    "defence_in_depth": ["Enable RLS on invoices"],
    "risks": "Breaks support tooling that queries cross-tenant; see src/admin/…"
  },
  "verification": {                       // required — how the customer proves the fix
    "method": "…",
    "expected_result": "403 for cross-tenant id",
    "regression_test": "…"
  },

  "references": ["https://owasp.org/API-Security/…"],
  "candidate_id": "C-012",
  "hypothesis_id": "H-007",
  "created_at": "…", "updated_at": "…"
}
```

## Field notes

**`title`** — states the vulnerability and its consequence. "Cross-tenant invoice download via
unvalidated object reference", not "IDOR" and not "Security issue in invoices".

**`impact` vs technical severity** — `impact` is what the *business* loses. "Any customer can read
any other customer's invoices, including billing addresses and amounts — a notifiable personal-data
breach under APPI." Not "an attacker can access unauthorized data".

**`controls_checked`** — the anti-false-positive field, and the one reviewers read first. Every layer
you inspected, including the ones where you found nothing. Required even when the finding is obvious.

**`instances`** — one root cause reported once. Twelve handlers missing the same predicate is one
finding with twelve instances. See `method-severity.md` §Aggregation.

**`remediation.code`** — must match the codebase's framework, version and idiom. Generic advice
("validate user input") is not remediation and fails review. If you are not sure the fix compiles,
say so and describe it precisely instead of inventing an API.

**`remediation.risks`** — what the fix might break. A remediation that silently breaks support tooling
gets rolled back, and the finding comes back at the next assessment.

**`verification`** — the customer must be able to prove the fix independently. Prefer a test they can
keep: a request that must return 403, a query that must return zero rows, an assertion in CI.

**`status`** — `risk-accepted` requires who accepted it and when. `withdrawn` requires the reason,
and withdrawn findings feed `knowledge/false-positive-catalog.md`.

## ID conventions

| Prefix | Record |
|---|---|
| `U-` | Unknown |
| `H-` | Hypothesis |
| `C-` | Candidate |
| `EV-` | Evidence |
| `F-` | Finding |

IDs are permanent within an engagement and are reused across the technical report, executive summary,
remediation plan and the remediation-review, so the customer can track one issue through all four.
