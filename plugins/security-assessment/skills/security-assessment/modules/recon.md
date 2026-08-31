# Module: Recon — System Understanding & Attack Surface

> **Phase 1–2. Always run.** Everything downstream is only as good as this.
> **Outputs:** `system-model.md`, `attack-surface.md`, `unknowns.jsonl`, `coverage.json`

You cannot threat-model a system you do not understand, and you cannot assess what you have not
enumerated. Time spent here converts directly into finding quality — an assessment that skips recon
finds what a linter finds.

## Objective

Answer the fifteen questions below **with evidence**, and register every unresolved one as an UNKNOWN.
Half of them are usually answerable from the repository in under an hour; the rest need the customer.

## The system model

Record each answer with its source. `[UNKNOWN]` is a valid and expected answer — a system model with
six honest UNKNOWNs is far more useful than one with six guesses.

| # | Question | Where to look |
|---|---|---|
| 1 | **Business purpose** — what does this system do, for whom, and what would hurt if it broke? | README, docs, landing page, marketing copy, DB schema, admin UI |
| 2 | **Architecture** — services, datastores, queues, external calls, deployment topology | `docker-compose`, k8s manifests, IaC, service configs, ADRs |
| 3 | **Technology stack** — languages, frameworks and their **resolved** versions | lockfiles first, manifests second |
| 4 | **Authentication** — how does a caller prove identity? Sessions, JWT, OAuth/OIDC, SAML, API keys, mTLS? | auth middleware, IdP config, login routes |
| 5 | **Authorization model** — RBAC, ABAC, ownership checks, tenant scoping, policy engine? Where is it *enforced*? | guards, decorators, middleware, ORM scopes, DB policies |
| 6 | **User roles** — enumerate every role and what each may do | role enums, seed data, permission tables, admin UI |
| 7 | **Data classification** — what data exists, how sensitive, under which regulation? | schema, migrations, privacy policy, DPA |
| 8 | **Tenancy** — single-tenant, pooled multi-tenant, siloed? Where is the tenant boundary drawn? | schema (`tenant_id`?), row-level policies, connection routing |
| 9 | **External integrations** — payment, email, storage, analytics, webhooks, AI providers | SDK imports, outbound URLs, API keys in config |
| 10 | **Public endpoints** — everything reachable from the internet | route tables, ingress, API gateway, CDN config, `robots.txt`, OpenAPI |
| 11 | **Internal endpoints** — admin panels, health/metrics, debug routes, internal APIs | route tables, `/admin`, `/internal`, `/debug`, `/actuator`, `/metrics` |
| 12 | **Cloud environment** — accounts, regions, managed services, network boundaries | IaC, provider config, CLI if credentials supplied |
| 13 | **CI/CD** — what builds, tests and deploys this, with what permissions? | `.github/workflows`, `.gitlab-ci.yml`, deploy scripts |
| 14 | **Secrets management** — where do secrets live, who can read them, how are they rotated? | env handling, secret manager refs, CI secrets |
| 15 | **IaC & dependency management** — what is declared vs. clicked, what pins versions? | `*.tf`, CFN, Pulumi, Helm, lockfiles, Renovate/Dependabot config |

```bash
sa unknown add --question "Is /internal/* reachable from the internet?" \
  --blocks "H-014" --resolve-by "customer: share ingress/ALB rules, or curl from outside the VPC"
```

An UNKNOWN must state **what would resolve it**. "We don't know" is not actionable; "we need the ALB
listener rules" is, and it goes straight into the customer's task list.

## Orientation commands

Adapt to the stack. These are for orientation, not for finding vulnerabilities.

```bash
# shape and age
git log -1 --format='%H %ad'; git ls-files | wc -l
git ls-files | sed 's|.*\.||' | sort | uniq -c | sort -rn | head -20

# entry points — the highest-value enumeration in this module
rg -n --no-heading -g '!node_modules' \
  -e '@(Get|Post|Put|Patch|Delete|All)\(' \
  -e '(app|router)\.(get|post|put|patch|delete|use)\(' \
  -e '@app\.(route|get|post)|@router\.(get|post|put|delete)' \
  -e 'path\(|re_path\(|urlpatterns' \
  -e 'func \(.*\) ServeHTTP|http\.HandleFunc|r\.(Get|Post|Put|Delete)\(' \
  -e 'resources :|match .*=>|root to:'
# Next.js / file-router
fd -g '**/route.{ts,js}' -g '**/page.{tsx,jsx}' -g 'pages/api/**' 2>/dev/null
# schema-first
fd -e graphql -e proto -g 'openapi*' -g 'swagger*'

# trust boundaries and outbound calls
rg -n -e 'https?://' --glob '!*.lock' --glob '!node_modules' | grep -v -e example.com -e localhost | head -50

# admin / internal / debug surface
rg -n -i -e '/admin' -e '/internal' -e '/debug' -e '/actuator' -e '/metrics' -e '/health' -e 'swagger|graphiql|playground'

# auth wiring
rg -n -i -e 'passport|next-auth|authlib|devise|omniauth|pundit|cancan|casbin|oso|opa' \
        -e 'jwt|jsonwebtoken|jose|pyjwt' -e 'session' --glob '!*.lock' | head -40

# data classification signals
rg -n -i -e 'email|phone|address|ssn|passport|birth|card|iban|salary|health' --glob '*migration*' --glob '*schema*' | head -40
```

## Attack surface map

Every entry point gets one row. This is the work list for the rest of the assessment — its
completeness bounds the assessment's completeness.

| ID | Entry point | Type | Exposure | Authn required | Authz model | Data touched | Modules | Priority |
|----|-------------|------|----------|----------------|-------------|--------------|---------|----------|
| AS-01 | `POST /api/v1/invoices/:id/download` | REST | internet | yes | ownership? `[UNKNOWN]` | billing PII | api, authz | high |
| AS-02 | `GET /internal/metrics` | REST | `[UNKNOWN]` | no | none | ops | api, web | high |
| AS-03 | Stripe webhook `POST /hooks/stripe` | webhook | internet | signature | n/a | payments | api, business-logic | high |
| AS-04 | S3 `acme-uploads` | storage | `[UNKNOWN]` | IAM | bucket policy | user uploads | cloud, iam | high |

Do not stop at HTTP routes. Enumerate: webhooks, queue/topic consumers, cron and scheduled jobs,
file/object upload paths, email ingestion, WebSocket/SSE channels, GraphQL resolvers and subscriptions,
gRPC methods, admin CLIs and management commands, database access paths (direct connections, RLS
bypass roles), CI/CD triggers, third-party callbacks (OAuth redirect URIs), mobile/desktop clients,
public storage buckets, and support/impersonation tooling.

**Priority** = `(exposure × data sensitivity) / authentication strength`. Assess in that order.

Anything you enumerate but will not assess goes into `coverage.json` with a reason **now**, not at
report time when you have forgotten why.

```bash
sa surface add --id AS-01 --entry "POST /api/v1/invoices/:id/download" \
  --exposure internet --authn required --data "billing PII" --modules api,authz --priority high
sa coverage set --surface AS-07 --state not-assessed --reason "legacy admin app, out of scope per SOW §3"
```

## Exit criteria

- [ ] All 15 questions answered or registered as UNKNOWN with a resolution path
- [ ] Attack surface table complete, each row prioritised and routed to modules
- [ ] Every surface has a coverage state
- [ ] `sa status` shows no surface in an undefined state
