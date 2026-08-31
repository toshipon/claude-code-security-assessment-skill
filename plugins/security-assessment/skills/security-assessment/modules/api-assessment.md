# Module: API Assessment

> **Load when** the system exposes HTTP/REST, GraphQL, gRPC, or webhook endpoints.
> Structured on OWASP API Security Top 10 (2023). Object/property/function-level authorization
> (API1/API3/API5) is assessed in `authz-assessment.md` — do not duplicate it here.

## Hypothesis catalog

### AP-1 · Inventory (API9:2023)
- **Statement**: an endpoint exists that nobody is maintaining — an old version, a staging host, a
  debug route, an undocumented internal API — and it is weaker than its supported equivalent.
- **Falsifier**: the deployed route inventory matches the documented one, with no extra hosts or versions.
- **EV**: the **server's** route table (E2), diffed against the OpenAPI/GraphQL schema and the docs.
- **Traps**: `/api/v1` still mounted beside `/api/v2` with the old authorization model; `staging.` and
  `dev.` hosts reachable from the internet with production data; a debug router mounted behind an
  environment flag whose default is wrong.
- **This is the highest-yield hypothesis in the module.** Old versions are where deprecated
  authorization models keep running.
- CWE-1059 · API9:2023

### AP-2 · Unrestricted resource consumption (API4:2023)
- **Statement**: one cheap request causes disproportionate cost or an outage.
- **Falsifier**: pagination with an enforced maximum, request size limits, query depth/complexity
  limits, timeouts, and rate limits on expensive operations specifically.
- **EV**: pagination defaults and caps (E2); GraphQL depth/complexity config (E2); upload size limits
  (E2/E4); timeout config (E4).
- **Traps**: `?limit=` with no cap, or `limit=-1`/`limit=0` meaning "all"; GraphQL with no depth limit
  (nested self-referencing queries); N+1 amplified by a batch endpoint; unbounded exports; regex on
  user input (ReDoS); image/PDF processing on unvalidated uploads; an endpoint that sends email or SMS
  per request (cost amplification, and an abuse vector against third parties).
- **Do not test by attempting exhaustion.** Read the limits. DoS testing needs explicit authorization
  (`method-safety.md`).
- CWE-770 · API4:2023

### AP-3 · Sensitive business flows (API6:2023)
- **Statement**: an automated actor can abuse a legitimate flow at scale — bulk signup, coupon
  redemption, inventory reservation, referral rewards, scraping.
- **Falsifier**: the flow has abuse controls proportionate to its business value: rate limits per
  identity, idempotency keys, human verification where appropriate, anomaly detection.
- **EV**: the flow's write path and any abuse controls (E2).
- **Cross-reference** `business-logic-assessment.md`; this is the API-surface view of the same risk.
- API6:2023

### AP-4 · Unsafe consumption of third-party APIs (API10:2023)
- **Statement**: the system trusts a third party's response, redirect, or callback more than it should.
- **Falsifier**: third-party responses validated like user input; TLS verification on; redirects not
  followed blindly; webhook signatures verified before any processing.
- **EV**: outbound HTTP client config (E2); webhook handlers (E2); response deserialization (E2).
- **Traps**: `verify=False` / `rejectUnauthorized: false` / `InsecureSkipVerify: true`; following
  redirects from a vendor into internal address space; deserializing a vendor payload into an object
  graph; parsing a vendor's XML with entity resolution enabled; a webhook handler that acts before
  it verifies the signature, or that verifies with a non-constant-time comparison.
- CWE-295, CWE-345 · API10:2023

### AP-5 · Security misconfiguration (API8:2023)
- **Statement**: transport, CORS, headers, or error handling weaken the API.
- **Falsifier**: TLS-only with HSTS; CORS allowlist that does not reflect arbitrary origins; no stack
  traces in responses; correct `Content-Type` handling.
- **EV**: CORS config (E2), security headers (E2/E1), error handler (E2).
- **Traps**: `Access-Control-Allow-Origin` **reflected from the request** together with
  `Allow-Credentials: true` — a full cross-origin read primitive, and one of the most common real
  findings; `Origin: null` allowed; a permissive CORS regex (`/acme\.com/` matching `evil-acme.com`);
  debug mode on in production; verbose errors revealing queries or paths.
- CWE-16, CWE-942 · API8:2023

### AP-6 · Injection through API-specific channels
- **Statement**: a parameter reaches an interpreter — SQL, NoSQL, OS, LDAP, XPath, template.
- **Assessed in** `repo-assessment.md`; here, enumerate the API-specific entry points that
  static analysis of handlers misses: JSON body fields consumed by dynamic filters or sort
  parameters, GraphQL arguments passed to raw queries, and header values used in queries or logs.
- **Traps**: sort/filter/`order_by` parameters (they cannot be parameter-bound, so they are
  concatenated — check for an allowlist); NoSQL operator injection (`{"$gt": ""}` submitted where a
  string is expected); `LIKE` patterns built from user input.

### AP-7 · Webhook and callback integrity
- **Statement**: an attacker can forge or replay an inbound webhook.
- **Falsifier**: signature verified with a constant-time comparison over the **raw** body, timestamp
  checked against a window, and replay prevented by event ID.
- **EV**: the webhook handler, in full (E2).
- **Traps**: signature computed over the parsed-and-reserialized body (fails, so verification is
  quietly disabled); `==` comparison on the signature; no timestamp check, so an old signed request
  replays forever; the handler being idempotent in name only.
- CWE-345

### AP-8 · GraphQL specifics
When GraphQL is present, all of these apply and none are covered by REST-shaped checks:
- Introspection enabled in production (information disclosure; raises `E` for everything else).
- **Authorization enforced per resolver**, not only at the query root — a nested field can traverse
  into data the root query was authorized for but the field was not.
- Depth and complexity limits; aliasing used to multiply an expensive field in one request.
- Batching used to bypass per-request rate limits (many operations, one HTTP request).
- Error messages leaking schema or backend details.
- Mutations reachable without the authorization applied to the equivalent REST route.

## Evidence collection

```bash
# route inventory from the server, plus schemas
fd -g 'openapi*' -g 'swagger*' -e graphql -e proto
rg -n -e '@(Get|Post|Put|Patch|Delete)\(' -e '(router|app)\.(get|post|put|patch|delete)\('
rg -n -e 'v1|v2|deprecated|legacy' --glob '*rout*' --glob '*api*'      # old versions still mounted

# CORS — read the actual value, especially any reflection
rg -n -i -e 'cors|Access-Control-Allow-Origin|allowedOrigins|origin:' -A6

# limits
rg -n -i -e 'limit|page_size|per_page|maxDepth|complexity|bodyParser|body-parser|MAX_|timeout' -A3

# webhooks
rg -n -i -e 'webhook|signature|x-hub-signature|stripe-signature|constructEvent' -A10

# outbound client safety
rg -n -e 'verify\s*=\s*False|rejectUnauthorized:\s*false|InsecureSkipVerify:\s*true' \
       -e 'maxRedirects|allow_redirects|followRedirect'
```

## Verification

- Build the inventory from what the **server** mounts. Frontend code and documentation both understate it.
- For CORS, determine whether the origin is *reflected* or *matched against a list*. Reflection with
  credentials is the finding; a static allowlist usually is not.
- For rate limits, find the layer that enforces them and confirm it covers the endpoint in question —
  gateway rules are commonly path-prefixed and miss newer routes.

## Common false positives

| Looks like | Actually |
|---|---|
| Permissive CORS | On a public, unauthenticated, read-only endpoint with no credentials — low or no impact |
| No pagination cap | The underlying table is bounded by design (a lookup/reference table) |
| Introspection enabled | Only on a non-production host — **verify the host is not internet-reachable** |
| Missing rate limit | Enforced at CDN/WAF for this path — verify, then treat as mitigating, not eliminating |
| Unsigned webhook | The endpoint is mTLS-protected or IP-allowlisted — verify the allowlist is enforced |
