# Module: Threat Model

> **Phase 3. Always run.** Requires `system-model.md` and `attack-surface.md`.
> **Output:** `threat-model.md`

The threat model turns "here are the entry points" into "here is what an attacker would want and how
they would try to get it". It is what makes the hypotheses in Phase 4 *about this system* rather than
about web applications in general.

Keep it proportionate. For a typical SaaS this is one to three pages, produced in an hour or two —
not a formal STRIDE workshop. Its purpose is to direct the assessment, not to be a deliverable in
its own right (though customers usually value it highly).

## 1. Assets

What an attacker wants, and what the business cannot afford to lose. Rank them — the ranking becomes
the `B` factor in `method-severity.md`, so it must be explicit rather than intuited later.

| ID | Asset | Classification | Where it lives | Impact if breached |
|----|-------|----------------|----------------|--------------------|
| A-1 | Customer billing records | 個人情報 / PCI-adjacent | `invoices`, S3 `acme-invoices` | Notifiable breach, contractual penalties |
| A-2 | Authentication credentials | Secret | `users.password_hash`, session store | Full account takeover |
| A-3 | Payment execution capability | Critical function | Stripe API key, payout flow | Direct financial loss |
| A-4 | Tenant isolation itself | Integrity property | enforced in app + DB | Existential trust loss for a multi-tenant SaaS |

A-4 is not optional for multi-tenant systems. Treating tenant isolation as an asset in its own right
is what makes the authorization module's hypotheses concrete.

## 2. Actors

Model attackers by the **position they can reach**, not by persona archetypes. For each, state what
they start with — that is the precondition budget for every hypothesis you write.

| ID | Actor | Starts with | Motivation |
|----|-------|-------------|------------|
| T-1 | Unauthenticated internet | Public endpoints, published docs, the signup page | Opportunistic; mass scanning |
| T-2 | Self-registered user | A free/trial account on their own tenant | Data theft, quota abuse, escalation |
| T-3 | Legitimate customer user | A paid account, real data, API tokens | Cross-tenant access, price manipulation |
| T-4 | Malicious/compromised tenant admin | Full rights within one tenant, invite powers | Escalate beyond their tenant |
| T-5 | Compromised employee/CI credential | Repo access, deploy rights, cloud role | Supply chain, production access |
| T-6 | Compromised third party | A vendor's callback, a dependency, an OAuth app | Supply chain, SSRF pivot |

**T-2 and T-3 find the most real bugs in SaaS assessments.** Self-signup turns an "authenticated"
control into an open door: if anyone can obtain the credential, "requires authentication" is not a
meaningful barrier. Check whether self-signup is open before you score any `E` factor.

## 3. Trust boundaries

Where data or control crosses from one level of trust to another. Every crossing needs a named
validator; a crossing with no validator is a hypothesis before you finish writing the row.

| ID | Boundary | Crossing | Validated by | Verified? |
|----|----------|----------|--------------|-----------|
| TB-1 | Internet → API gateway | HTTP requests | WAF + TLS termination | `[UNKNOWN]` |
| TB-2 | API → application | Authenticated request | authn middleware | ✓ `src/app.ts:34` |
| TB-3 | Tenant A → tenant B | Object references in requests | `[nothing found]` | → **H-007** |
| TB-4 | Application → database | Queries | ORM binding; RLS not enabled | ✓ partial |
| TB-5 | CI → cloud | Deploy credentials | GitHub OIDC → IAM role | `[UNKNOWN]` scope |
| TB-6 | Third party → application | Webhooks | signature verification | ✓ `src/hooks/stripe.ts:12` |
| TB-7 | User content → other users | Stored data rendered to others | output encoding | check per sink |

## 4. Privilege boundaries

Distinct from trust boundaries: these are *within* the authenticated application.

- anonymous → authenticated
- user → tenant admin
- tenant admin → platform/support staff
- support staff → superuser
- application role → database role
- workload identity → cloud role

For each: **what enforces it, and where?** Boundaries enforced only in the UI are not enforced.
This list drives `authz-assessment.md` directly.

## 5. Data flows

Trace the two or three flows that carry the highest-ranked assets. Follow the data, not the code:
where does it enter, where is it validated, where is it stored, where does it leave, where is it
logged, and who can read it at each hop?

```
signup → POST /auth/register → validate → bcrypt → users table
                                       ↘ welcome email (SendGrid)   ← PII leaves the boundary
                                       ↘ analytics event (Segment)  ← PII leaves the boundary
                                       ↘ application log            ← does it log the password?
```

The `↘` branches are where assessments find things. Logging, analytics, error trackers and email are
the routine leak paths, and they are invisible if you only read the happy path.

## 6. External dependencies

For each third party: what data reaches it, what access it has *into* the system, and what happens if
it is compromised or impersonated. An OAuth provider, a webhook sender, a CDN with an active service
worker and an npm package in the build are all inbound trust relationships.

## 7. Administrative interfaces

Enumerate them explicitly — they are consistently the highest-yield surface and consistently the
least defended, because they were built for internal use and never re-reviewed.

Admin panels, impersonation ("log in as user"), support tooling, feature-flag consoles, database
consoles, metrics/tracing UIs, queue dashboards, `/actuator`, `/debug`, management commands, and any
"internal-only" service whose isolation you have not verified.

For each: exposure (`[UNKNOWN]` until proven), authentication, authorization, audit logging.

## Producing hypotheses

The threat model directly generates the Phase 4 hypothesis set:

| From | Generates |
|---|---|
| Every unvalidated trust boundary | "Can T-n cross TB-m without the intended control?" |
| Every privilege boundary | "Can T-n reach a capability of a higher level?" |
| Every asset | "What is the shortest path from each actor to this asset?" |
| Every `↘` in a data flow | "Does asset A reach a place it should not?" |
| Every admin interface | "Can T-2 reach it?" |
| Every external dependency | "What does a compromised vendor get?" |

```bash
sa hypothesis add --surface AS-01 --statement "T-3 can cross TB-3 by substituting an invoice id" \
  --falsifier "tenant predicate applied on every path to the invoice query" --module authz
```

## Exit criteria

- [ ] Assets ranked; the ranking is the `B` factor source
- [ ] Actors defined by starting position; self-signup availability determined
- [ ] Every trust and privilege boundary has a validator or an open hypothesis
- [ ] Top-asset data flows traced including logging/analytics/email branches
- [ ] Administrative interfaces enumerated with exposure stated
- [ ] Each high-priority surface has ≥1 hypothesis
