# False Positive Catalog

Patterns that look like vulnerabilities and are not. Consult before reporting; add to it at every
retrospective (`sa candidate kill` records the reason, `sa retro promote` generalizes it).

Each entry names the **control that must be cited** to dismiss the candidate. Dismissing without
citing it is how a real finding gets closed.

---

| Looks like | Usually is | Cite this to dismiss |
|---|---|---|
| Missing authorization in the handler | Enforced by middleware, a guard, an ORM default scope, or a FORCEd RLS policy | The control's `file:line` or the policy definition |
| `findById(req.params.id)` with no tenant filter | The repository injects the predicate | The repository method and its predicate |
| String-concatenated SQL | Values are internal constants or a validated enum | The origin of every interpolated value |
| `shell=True` | Arguments are static or allowlisted | The argument construction |
| `innerHTML` / `dangerouslySetInnerHTML` | Constant content, or DOMPurify immediately upstream | The sanitiser call |
| `jwt.decode()` without verify | Used for a non-security purpose after a real `verify()` upstream | The verifying call |
| MD5 / SHA-1 | Cache key, ETag, or checksum — not a security boundary | The use site |
| `Math.random()` | UI, jitter, or a non-security identifier | The use site |
| Critical CVE in a dependency | The vulnerable function is never called | The advisory's affected symbol + a call-graph search |
| CVE in `devDependencies` | Not in the production artifact | The build/packaging config |
| `0.0.0.0/0` security group | Instance has no public IP in a private subnet | Route table + subnet + ENI |
| Public S3 bucket | Static asset hosting by design | Bucket contents + intent |
| Wildcard IAM policy | Bounded by a permission boundary or an SCP | The boundary/SCP document |
| Cross-account trust | Intended vendor integration **with** `ExternalId` | The condition block |
| Missing security headers in code | Added at the CDN or edge | A response from the live host |
| Missing CSRF token | Token-authenticated API, no ambient cookie authority | The auth mechanism |
| Missing rate limit in code | Enforced at gateway/WAF **for this path** | The gateway rule and its path match |
| Missing CSP | Real hardening gap — but **not** a High on its own | — rate as defence in depth |
| `pull_request_target` | Used without checking out PR code | The checkout step's `ref` |
| Unpinned GitHub Action | First-party action in a workflow with no secrets | The workflow's `permissions` and secret usage |
| `NEXT_PUBLIC_`-prefixed key | A publishable key (Stripe `pk_`, Firebase config, Sentry DSN) | The vendor's key documentation |
| A sink in `tests/`, `examples/`, `scripts/` | Not in the deployed artifact | The build config excluding it |
| Secret-shaped string | Test fixture, public key, hash, UUID, or lockfile integrity digest | Its use site |
| `AKIAIOSFODNN7EXAMPLE` | AWS's documentation example key | — |
| Price in the request body | Validated server-side against the catalogue before charging | The validation call |
| Race window in application code | A unique index makes the second writer fail | The schema constraint |

---

## The rationalisations that are *not* valid dismissals

Listed here because they are the ones that get used. See `references/method-false-positive.md`.

- "It's behind authentication" — authenticated users are attackers, and self-signup may be open
- "It's internal only" — verify the network isolation, or it is an assumption (E6)
- "The framework handles it" — verify the resolved version, the config, and this call site
- "It's only staging" — verify staging holds no production data and has no path to production
- "No one would find this" — enumeration is cheap and automated
- "The WAF blocks it" — mitigating, never eliminating; never kill a candidate on a WAF alone
