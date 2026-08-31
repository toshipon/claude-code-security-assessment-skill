# Method: Safety and Authorization

Security assessment touches systems people depend on. The default is **do nothing that changes state
and nothing the customer did not authorize.**

## Posture levels

Recorded in `engagement.json`. `sa` refuses to record evidence from actions above the authorized level.

| Posture | Allowed | Requires |
|---|---|---|
| **PASSIVE** (default) | Read source, config, IaC, lockfiles, docs. Read-only cloud API calls with supplied credentials. Read-only DB queries. No traffic to the target application | Scope definition |
| **ACTIVE-SAFE** | Non-destructive requests to an authorized non-production target: crafted requests, authenticated enumeration with the customer's own test accounts, header/TLS inspection | Written authorization naming target, environment, window |
| **INTRUSIVE** | Everything else | Written authorization **per technique**, a named customer contact, a rollback plan, and a time window |

Absent authorization, run PASSIVE and say so. **Never** silently escalate because a check would be
"easier that way".

## Never automatic

Do not perform these without explicit, specific, recorded human approval — not even in staging, not
even when it would settle a hypothesis quickly:

- **Data deletion or modification** of any kind, including "test" records
- **Denial of service**: load testing, resource exhaustion, algorithmic complexity, connection floods
- **Credential attacks**: password spraying, brute force, stuffing, token brute-forcing
- **Persistence**: web shells, scheduled tasks, new IAM users/keys, backdoor accounts
- **Destructive exploitation**: writing files, executing commands, dropping tables — even to prove RCE
- **Lateral movement / pivoting** beyond the authorized boundary
- **Third-party systems**: SaaS vendors, payment processors, identity providers, CDNs. Their contracts
  and their other customers do not know about your engagement
- **Production**, unless production is explicitly, separately, in writing, in scope
- **Real user accounts or real customer data**, including reading it to "confirm impact"
- **Exfiltration** of data beyond the minimum needed to prove the finding, and only to the workspace

## Requesting approval

When a hypothesis genuinely cannot be resolved passively, stop and ask. Present exactly:

```
Verification request
  Hypothesis:   H-014 — unauthenticated access to /internal/metrics
  Action:       one HTTP GET to https://staging.example.com/internal/metrics, no auth header
  Environment:  staging
  Why needed:   the route is registered dynamically; static analysis cannot determine whether
                the auth middleware applies (U-006)
  Risk:         none — single read-only request, no state change
  Alternative:  customer engineer runs the request and shares the response headers + status
  Approval needed from: <name/role>
```

Prefer the alternative. **A customer engineer running the command and pasting the output is E1
evidence with zero risk**, and it is very often faster than getting an authorization decision.

If approval is refused or unavailable: register the UNKNOWN, mark the hypothesis `INCONCLUSIVE`, and
report it as a coverage gap with the exact verification the customer can run themselves. That is a
useful deliverable, not a failure.

## Blast-radius rules for authorized active testing

- One request at a time. No parallel fuzzing, no scanners with default thread counts.
- Use the customer's designated test accounts and test tenants only.
- Tag your traffic with an identifying `User-Agent` and, where possible, a header the customer's SOC
  can filter on. Tell them the source IP before you start.
- Stop on the first confirmation. You do not need 50 examples of the same IDOR — one is proof.
- Never chain an exploit further than the minimum that proves impact. Reaching the database is proof;
  reading it is not necessary.
- Log every request you send into `evidence/`, so the customer can reconcile with their own logs.

## Secrets you discover

- Do **not** test a discovered credential to see if it works. That is unauthorized access, even with
  the customer's own key, unless the scope covers it.
- Report it immediately and out-of-band — do not wait for the report. Live credentials in a public
  repo are a phone call, not a Medium finding in a PDF two weeks later.
- Tell the customer to rotate, then to audit for prior use.
- Never paste the secret into the report, chat, commit, or ticket. Location + shape + last-4 only.

## Reporting channel

Critical findings with active exploitation potential go to the customer's named contact immediately,
through the channel agreed at Phase 0, before the report exists. Agree that channel during scoping —
not after you find something.
