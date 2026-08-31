# Detection Patterns

Where weaknesses hide, and how to look. Seeded with patterns that recur across Web/SaaS assessments;
grown by `sa retro promote`.

---

## The async twin

**Pattern** — An operation exists twice: once in a request handler (with request context, including
the authenticated tenant) and once in a background job, queue consumer, or scheduled task (without
it). Authorization is applied to the first and forgotten on the second.

**Why it matters** — The background path usually has *more* access, not less, because it runs as a
service principal. Cross-tenant reads through report generators, exports, and digest emails are a
recurring high-severity class.

**How to check** — Enumerate every enqueue site and every consumer. For each consumer, ask what
tenant/user identity it uses and where that value comes from. Trace whether it is derived from the
job payload (attacker-influenceable if the payload is built from a request) or re-derived from a
trusted store.

**How to falsify** — Tenant scope enforced at the data layer (RLS, repository predicate) so both
paths inherit it regardless of context.

**Common FP cause** — The job runs per-tenant by construction (one job per tenant, tenant fixed at
enqueue from the session).

_Hits: 0 / Misses: 0_

---

## The un-bindable query fragment

**Pattern** — `ORDER BY`, `LIMIT`, table names and column names cannot be parameter-bound, so
developers concatenate them. The rest of the query is correctly parameterised, which makes the code
look safe at a glance and makes scanners quiet.

**Why it matters** — It is the most common surviving SQL injection in otherwise well-written
ORM-based codebases.

**How to check** — Grep for sort/order/filter parameter names, then read the query construction.
Look for an allowlist mapping the external name to a literal column.

**How to falsify** — An allowlist (dict, enum, or literal tuple) with a safe default for unknown values.

**Common FP cause** — The allowlist exists a few frames up, in a validation layer or a serializer.

_Hits: 0 / Misses: 0_

---

## The newest endpoint

**Pattern** — Authorization patterns established early in a codebase drift. By endpoint 40, the
convention is inconsistently applied, and the most recent endpoints are the least likely to follow it.

**Why it matters** — It concentrates search effort where the yield is highest.

**How to check** — `git log --diff-filter=A --format='%ad %H' --date=short -- <routes dir>` to find
the newest handlers, then assess those first against the convention the older ones follow.

**How to falsify** — Authorization enforced at a layer the developer cannot forget: middleware
applied by default, a base class, or a database policy.

**Common FP cause** — The new endpoints use a newer, stricter framework (a v2 router with guards by
default) while the old ones carry the manual checks.

_Hits: 0 / Misses: 0_

---

## The UI-only filter

**Pattern** — The server returns a complete object; the client renders a subset. The hidden fields
are in the network response.

**Why it matters** — Trivially exploitable, invisible in the browser, and it recurs wherever an ORM
entity is serialised directly. New sensitive columns leak automatically the day they are added.

**How to check** — Read the serializer, not the component. Where an entity is returned directly, list
its columns and ask which should not be visible to the least-privileged caller of that endpoint.

**How to falsify** — An explicit response allowlist per role.

**Common FP cause** — A response interceptor or a serializer group strips fields globally.

_Hits: 0 / Misses: 0_

---

## Trigger + checkout + secrets

**Pattern** — In CI, three individually reasonable settings compose into a full compromise:
a trigger that runs on untrusted input, a checkout of that untrusted code, and secrets in scope.

**Why it matters** — It is the canonical CI/CD compromise, it is Critical when present, and reading
the three settings separately hides it.

**How to check** — For every workflow, read trigger, checkout ref and secret usage **as one unit**.

**How to falsify** — The privileged trigger never checks out untrusted code, or the workflow holds
no secrets and no write token.

**Common FP cause** — `pull_request_target` used without checking out PR code — the safe pattern for
labelling and triage bots.

_Hits: 0 / Misses: 0_

---

## The wildcard subject in a federation trust

**Pattern** — An OIDC trust condition matches the subject with a prefix or a wildcard
(`repo:org/*`, `repo:org/repo:*`) instead of an exact value.

**Why it matters** — It silently widens a cloud role from one branch of one repository to every
repository in the organization, or every branch and pull request of one. Both sides must be read
together, so it is easy to miss and consistently high severity.

**How to check** — Read the cloud role's trust policy conditions alongside the workflow. Check the
condition operator, not just its presence: `StringLike` with a trailing wildcard is the bug.

**How to falsify** — `StringEquals` on a full subject including branch or environment, plus an
audience condition.

**Common FP cause** — A deliberately shared role for an organization-wide read-only workflow, with a
correspondingly minimal permission set.

_Hits: 0 / Misses: 0_
