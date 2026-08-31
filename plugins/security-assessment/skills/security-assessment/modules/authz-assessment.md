# Module: Authorization Assessment

> **Load when** the system has roles, tenants, or user-owned objects — i.e. almost always.
> **This module has the highest yield in Web/SaaS assessments. Never skip it.**
> Depends on: privilege boundaries from `threat-model.md`.

Authorization bugs dominate real-world SaaS breaches because they are invisible to scanners: the code
looks correct, the endpoint requires authentication, the tests pass. Only someone who knows *what the
business intends* can see that a check is missing. That is what this module systematises.

## The core question

For every request that references an object or invokes a capability:

> **Who proved that this caller may do this, to this object — and where?**

If the answer is "the UI only offers objects they own", the answer is *nobody*.

## Where authorization lives

Enumerate the layers in this system **first**, before assessing any endpoint. You cannot judge an
absence until you know where presence would look like.

| Layer | Examples | Failure mode |
|---|---|---|
| Gateway / route config | API Gateway authorizers, ingress rules | Applies to some routes only |
| Middleware / filter chain | Express/Rails/Django/Spring middleware | Ordering; path-pattern gaps; skipped on some verbs |
| Decorator / guard | NestJS guards, Django permission classes, Pundit policies | Missing on individual handlers; easy to forget on new ones |
| Handler | Explicit `if (obj.user_id !== me.id)` | Copy-paste drift; missing on newer endpoints |
| Service | Ownership assertion before the operation | Bypassed when a handler calls the repository directly |
| ORM scope | Default scopes, `current_tenant` | Bypassed by raw queries or a second ORM handle |
| Database | RLS policies, per-tenant roles | Enabled but not `FORCE`d; superuser/service role bypasses |
| Object store | S3 bucket/object policies, signed URLs | Signed URL scope too broad or too long-lived |

Then, for each endpoint, determine **which layer is load-bearing**. A system with defence at several
layers may still fail if the one layer that actually matters is missing on a given path.

## Hypothesis catalog

Instantiate per endpoint/object type. `EV` = evidence you must collect.

### AZ-1 · IDOR / BOLA — object-level authorization
- **Statement**: `T-3` can access another user's or tenant's object by substituting its identifier.
- **Falsifier**: an ownership/tenant predicate applied on **every** path reaching the data access, at
  a layer the caller cannot influence.
- **EV**: handler code (E2); service and repository call chain (E2); ORM default scope (E2); RLS
  policy and whether it is FORCEd (E4); ID format and enumerability (E2).
- **Trap**: the check exists on `GET` but not `PUT`/`DELETE`/`PATCH`, or on the detail endpoint but
  not the list, export, PDF, or "duplicate" endpoint. **Assess every verb and every sibling route.**
- CWE-639, CWE-284 · API1:2023 · ASVS 4.2.1

### AZ-2 · Function-level authorization (BFLA)
- **Statement**: a low-privilege user can invoke an admin-only operation by calling it directly.
- **Falsifier**: a role check enforced server-side on the handler, not only in the UI or the route
  the UI uses.
- **EV**: the full route table with each route's guard, side by side (E2). Enumerate routes from the
  **server's** route table, never from the frontend — the interesting ones are the ones the UI never
  calls.
- **Trap**: admin routes distinguished only by path prefix, with the guard applied to `/admin/*` but
  the same controller also mounted at `/api/*`.
- CWE-285 · API5:2023 · ASVS 4.1.3

### AZ-3 · Property-level authorization (mass assignment / excessive exposure)
- **Statement**: a user can set or read a field they should not — `role`, `tenant_id`, `is_admin`,
  `credit_balance`, `verified` — by including it in the request or reading it from the response.
- **Falsifier**: an explicit allowlist for writes (DTO/serializer/schema), and an explicit allowlist
  for reads, per role.
- **EV**: request binding code (E2); serializer/response shape (E2); a sample response body (E1).
- **Trap**: `Object.assign(user, req.body)`, `Model(**request.json)`, `permit!`, `@ModelAttribute`,
  spreading `...req.body`; and on the read side, returning the ORM entity directly so new columns
  leak automatically the day they are added.
- CWE-915, CWE-213 · API3:2023 · ASVS 5.1.2

### AZ-4 · Horizontal privilege escalation
- **Statement**: a user reaches a peer's resources through a path that does not check ownership —
  a shared-link endpoint, a search or export that ignores scoping, a notification, an activity feed.
- **Falsifier**: ownership scoping in the query itself, not applied as a post-filter in application code.
- **EV**: query construction for list/search/export endpoints (E2).
- **Trap**: aggregate and reporting endpoints. They are written by a different person, later, against
  the raw database, and almost never inherit the scoping.

### AZ-5 · Vertical privilege escalation
- **Statement**: a user can raise their own privilege level — self-assigning a role, inviting
  themselves to another tenant, accepting a stale invitation, exploiting an impersonation feature.
- **Falsifier**: role and membership mutations restricted to callers already holding the higher
  privilege, verified server-side, with the target scope validated.
- **EV**: every write path to the roles/memberships tables (E2); the invitation flow end-to-end (E2).
- **Trap**: the invite flow. Invitation tokens that do not bind to the invited email, do not expire,
  or let the accepter choose their own role.

### AZ-6 · Tenant isolation
- **Statement**: an operation crosses the tenant boundary — via a shared cache key, a background job
  that runs without tenant context, a report generator, a webhook handler, a search index, or an
  admin tool used by tenant-scoped staff.
- **Falsifier**: tenant scope derived from the **authenticated session** and enforced at the data
  layer, on every path including asynchronous ones.
- **EV**: how tenant context is established and propagated (E2); background job entry points (E2);
  cache key construction (E2); search index document scoping (E2); RLS policies (E4).
- **Trap**: tenant taken from a request header, body field, or path segment rather than the session.
  Also: async jobs, which lose request context by construction — enumerate every enqueue site and
  check what tenant identity the worker uses.
- CWE-1230 · ASVS 4.3.3

### AZ-7 · Missing authorization on non-obvious paths
- **Statement**: an operation is reachable through a path nobody reviewed — GraphQL field resolvers,
  a batch/bulk endpoint, a legacy v1 route still mounted, an internal service endpoint, a webhook
  replay, a file download served by a different service.
- **Falsifier**: authorization enforced at a layer common to **all** paths.
- **EV**: complete route/resolver inventory from the server (E2), diffed against the documented API.
- **Trap**: GraphQL. Object-level authorization must be enforced per resolver; a nested field can
  reach data the top-level query was authorized for but the field was not.

### AZ-8 · Role confusion
- **Statement**: two role systems disagree — application roles vs. database roles, or the IdP's
  groups vs. the local role table — and the weaker one governs.
- **Falsifier**: a single authoritative source of authorization decisions.
- **EV**: every place a role is read and every place one is written (E2).
- **Trap**: roles cached in a JWT and not re-checked after revocation, so a demoted user keeps their
  old rights until the token expires. Determine the token lifetime and whether revocation is checked.

## Evidence collection

```bash
# 1. Route table WITH its guards — build this table before assessing anything
rg -n -B3 -e '@(Get|Post|Put|Patch|Delete)\(' -e '(router|app)\.(get|post|put|patch|delete)\('
rg -n -e '@UseGuards|@Roles|@PreAuthorize|permission_classes|before_action|authorize|can\?|policy'

# 2. Ownership checks — and their absence
rg -n -e 'user_id\s*(==|===|!=|!==)' -e 'current_user\.' -e 'req\.user\.' -e 'tenant_id\s*(==|=)'
rg -n -e 'findById|findOne|get_object_or_404|find\(params\[:id\]\)|\.get\(pk=' -A4

# 3. Mass assignment sinks
rg -n -e 'Object\.assign|\.\.\.req\.body|permit!|\*\*request\.(json|data)|setattr\(' -e 'update\(req\.body\)'

# 4. Tenant context propagation
rg -n -i -e 'tenant|organization_id|workspace_id|account_id|current_tenant|RLS|set_config'
rg -n -i -e 'enqueue|perform_later|delay\(|\.send\(|publish\(|sqs|celery|sidekiq' -A5   # async loses context

# 5. Database-level isolation
#   psql: SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relkind='r';
#         SELECT schemaname, tablename, policyname, cmd, qual FROM pg_policies;
```

**Build the endpoint × authorization matrix.** It is the single most valuable artifact this module
produces, and customers act on it immediately:

| Endpoint | Verb | Authn | Role check | Ownership check | Tenant scope | Verdict |
|---|---|---|---|---|---|---|
| `/api/v1/invoices/:id` | GET | ✓ mw | — | ✓ handler:44 | ✓ query | ok |
| `/api/v1/invoices/:id` | DELETE | ✓ mw | — | **✗** | ✗ | **H-011** |
| `/api/v1/invoices/export` | GET | ✓ mw | — | **✗** | **✗** | **H-012** |

The gaps in this matrix are the findings. Its blank cells are the UNKNOWNs.

## Verification

- **Identifier enumerability**: sequential integers or a predictable pattern turns AZ-1 from
  "requires knowing an ID" (E=2) into "trivially scriptable" (E=4). Check the ID generator, and check
  whether IDs leak through any other endpoint, email, or export.
- **Read the query, not the handler.** The predicate that matters is the one that reaches the database.
- **Check the async twin.** Any operation with a background counterpart must be checked twice.
- **Check the newest endpoints.** Authorization drifts: the pattern established at the start is
  forgotten by endpoint 40. `git log --diff-filter=A` on the routes directory finds them.

## Common false positives

| Looks like | Actually |
|---|---|
| No check in the handler | Enforced by a guard, ORM default scope, or a FORCEd RLS policy |
| `findById(req.params.id)` | The repository injects a tenant predicate; read the repository |
| Admin route with no role check | Mounted only on an internal listener — **verify the network claim before dismissing** |
| Mass assignment sink | A DTO/serializer allowlists fields upstream |
| Missing tenant filter | Connection is per-tenant, or `SET app.tenant_id` drives an RLS policy |

Each of these requires you to *find and cite* the compensating control. "Probably handled by the
framework" is E6 and does not kill a candidate.
