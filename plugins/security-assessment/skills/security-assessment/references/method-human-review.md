# Method: Confidence and Human Review

This skill does not replace a security engineer. It does the enumeration, the tracing and the
bookkeeping — the parts that are slow and that humans skip when tired — and it hands a human a
short, evidence-backed queue.

Two distinct numbers must appear on every finding. They are routinely conflated, and conflating them
is how customers end up ignoring a real Critical.

| | Question | Values |
|---|---|---|
| **Severity** | How bad is this *if real*? | Critical / High / Medium / Low / Informational |
| **AI Confidence** | How sure am I that it *is* real? | High / Medium / Low |

A Critical/Low-confidence finding is a "verify this first thing tomorrow", not a "wake up the CTO".
Say which one it is.

## AI Confidence

| Level | Criteria |
|---|---|
| **High** | E1/E2 evidence, full path traced, all plausible control locations checked, attack scenario narrated end-to-end without gaps |
| **Medium** | E2/E3 with one inferred link, or one control whose effect could not be fully verified |
| **Low** | E3/E4 only, or an open UNKNOWN on the exploitation path, or heavy reliance on framework-behaviour assumptions |

State the reason for anything below High: *what exactly* you could not establish. "Medium confidence"
without a reason gives the reviewer nothing to work with.

## Always flag `Human Review Required`

Regardless of confidence:

- **Critical and High** — anything driving urgent, expensive action
- **Authorization** — IDOR/BOLA, tenant isolation, privilege boundaries. Correctness depends on
  business rules that are not written in the code
- **Authentication** — session, token, SSO/OIDC/SAML, password reset flows. Protocol subtleties and
  library-version behaviour decide these
- **Business logic** — by definition requires knowing what the business intends
- **Cloud IAM** — policy evaluation with SCPs, permission boundaries, resource policies and condition
  keys is genuinely hard to evaluate statically, and over-reporting here destroys credibility fast
- **Cryptography** — implementation subtleties; both false positives and false negatives are costly
- **Anything with a proposed fix that touches auth, money, or data deletion** — a wrong remediation
  is worse than the finding

## What the reviewer needs

Make review cheap. For each flagged finding provide:

1. The precise question the human must answer — *"is `admin_notes` intended to be visible to
   tenant-scoped support staff?"* — not "please review".
2. The evidence, with `file:line` links.
3. What you already ruled out, so they do not repeat it.
4. What would settle it: a specific command, a person to ask, or an environment to check.

## Assessment-level disclosure

Every report states, in the Coverage section:

- Which findings are AI-generated and not yet human-reviewed
- Which areas were assessed statically only, with no runtime verification
- Which UNKNOWNs remain open and what they block
- That absence of findings in an area is not evidence of its security unless that area was assessed

Overstating assurance is the most damaging error a security deliverable can make. A customer who
believes they were assessed when they were not is worse off than one who knows they were not.
