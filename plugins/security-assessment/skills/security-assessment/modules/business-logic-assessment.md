# Module: Business Logic Assessment

> **Load when** the system has workflows, payments, quotas, state machines, or anything with rules.
> Requires `system-model.md` (question 1: what does this system do?) and the asset ranking from
> `threat-model.md`.

No scanner finds these. They are the findings customers value most, because they are the ones their
own tooling cannot produce — and they are found by understanding what the system is *supposed* to do
and then asking how to violate it while staying inside the rules.

## Method

Business logic bugs are **legal moves in an illegal order**. Every request is individually
authorized and individually valid; the sequence is what is wrong. So:

1. **Model the intended flow.** Draw the state machine or the step sequence.
2. **List the invariants.** What must always be true? *An order ships only after payment clears. A
   coupon is used once. A user cannot exceed their plan's seat count. A balance never goes negative.*
3. **For each invariant, ask how to break it** using only operations the system offers you.
4. **Look for the enforcement.** Is the invariant enforced in the database (a constraint), in a
   transaction, in one service, or nowhere but the UI's ordering of screens?

Invariants enforced only by the *order in which the UI presents steps* are not enforced.

## Hypothesis catalog

### BL-1 · Workflow / step bypass
- **Statement**: a later step can be invoked directly, skipping an earlier one.
- **Falsifier**: each step verifies the prerequisite state server-side, from stored state rather than
  from a client-supplied token or hidden field.
- **EV**: each step's handler and its precondition check (E2).
- **Traps**: multi-step checkout, KYC/onboarding, approval chains, trial→paid conversion. The
  give-away is a step whose only precondition is a value the client sends back.

### BL-2 · State transition abuse
- **Statement**: an object can be moved into a state that should be unreachable from its current one —
  `refunded → shipped`, `cancelled → active`, `draft → published` skipping review.
- **Falsifier**: an explicit transition table validated on every mutation, not a settable `status` field.
- **EV**: every write to the status field (E2); the transition validation, if any (E2).
- **Traps**: a `status` column exposed through a generic update endpoint (see AZ-3, mass assignment —
  these two compound); admin-only transitions reachable through the normal update path.

### BL-3 · Race conditions on business state
- **Statement**: concurrent requests break an invariant — a coupon redeemed twice, a balance
  double-spent, a seat limit exceeded, an item over-sold.
- **Falsifier**: a database constraint (unique index, `CHECK`), `SELECT … FOR UPDATE`, an atomic
  update (`UPDATE … SET n = n - 1 WHERE n > 0`), or an idempotency key — not a read-then-write in
  application code.
- **EV**: the transaction boundary and isolation level (E2); the schema's constraints (E4).
- **Traps**: check-then-act across two statements; the check in a different service from the write;
  "the ORM handles it" (it does not); optimistic locking implemented without retry.
- **Do not race a live system to prove this.** The read of the transaction boundary is the evidence.
- CWE-362

### BL-4 · Pricing and quantity manipulation
- **Statement**: the client influences a value that determines what is charged or granted.
- **Falsifier**: price, discount, tax, currency and totals computed **server-side** from stored data;
  the client sends identifiers and quantities only, and quantities are range-checked.
- **EV**: the order/payment construction path (E2); the payment provider integration (E2).
- **Traps**: price or total in the request body; discount percentage from the client; **negative or
  fractional quantities** (a negative quantity in a cart that credits the customer is a real, recurring
  bug); currency substitution; integer overflow on totals; rounding in the attacker's favour repeated
  at scale; the confirmation webhook trusted for the amount without cross-checking the local order.

### BL-5 · Replay
- **Statement**: a captured request can be resubmitted for repeated effect.
- **Falsifier**: idempotency keys on state-changing operations; single-use, expiring, bound tokens;
  nonce tracking on signed callbacks.
- **EV**: idempotency handling on payment, invitation, reset and webhook endpoints (E2).
- **Traps**: payment confirmations; referral and reward claims; invitation acceptance; "resend"
  endpoints (email/SMS cost amplification); webhook replay (see `api-assessment.md` AP-7).

### BL-6 · Quota, limit and plan enforcement
- **Statement**: a user exceeds what their plan permits.
- **Falsifier**: limits enforced at the write path, server-side, atomically, and re-checked on every
  path that creates the limited resource.
- **EV**: every creation path for the limited resource (E2); where the count is maintained (E2).
- **Traps**: the limit checked on the UI's path but not on the API's, the bulk import's, or the
  integration's; a count cached and stale; a downgrade that does not reclaim resources; a trial that
  can be restarted by re-signup.

### BL-7 · Abuse of legitimate functionality
- **Statement**: a feature working exactly as designed causes harm at scale or against third parties.
- **Falsifier**: abuse controls proportionate to the feature's cost and reach.
- **EV**: the feature's rate limits and recipient validation (E2).
- **Traps**: invitation and "share" features used to send attacker-authored content from the
  customer's trusted domain; email/SMS triggers used for cost amplification or as a harassment relay;
  URL preview fetchers used as an SSRF proxy or a DDoS reflector; export features used for bulk
  scraping; a support-impersonation feature with insufficient audit.

### BL-8 · Trust in client-supplied context
- **Statement**: an authorization- or billing-relevant value is taken from the request rather than
  the session.
- **Falsifier**: identity, tenant, role, plan and pricing tier are always derived server-side from
  the authenticated session.
- **EV**: how each of those values is obtained in the handlers (E2).
- **Traps**: `X-Tenant-Id`, `X-User-Id`, `X-Role` headers; a `tenant` field in the JSON body; a plan
  tier in the JWT that is not re-validated after a downgrade.

### BL-9 · Time and ordering
- **Statement**: timestamps or ordering can be manipulated for advantage.
- **Traps**: client-supplied timestamps on events; expiry compared against a client clock; a
  scheduled action that runs with a stale permission snapshot; a promotion whose window is evaluated
  from a request parameter.

## Evidence collection

Reading order matters here: understand the domain first, then read the code.

```bash
# 1. Domain model — the invariants are usually visible in the schema
fd -g '*migration*' -g '*schema*' -e sql | head -30
rg -n -i -e 'CHECK \(|UNIQUE|FOREIGN KEY|NOT NULL|DEFAULT' --glob '*migration*' --glob '*schema*'

# 2. State machines
rg -n -i -e 'status|state|phase|stage' --glob '*model*' --glob '*entity*' --glob '*schema*'
rg -n -i -e 'aasm|state_machine|transition|workflow|xstate|statechart' -A5

# 3. Money
rg -n -i -e 'price|amount|total|discount|coupon|refund|currency|tax|invoice|charge|payout|balance|credit' -A3
rg -n -i -e 'stripe|braintree|paypal|adyen|square|payjp|komoju' -A5

# 4. Concurrency controls
rg -n -i -e 'transaction|BEGIN|FOR UPDATE|lock|mutex|isolation|SERIALIZABLE|optimistic|version' -A3
rg -n -i -e 'idempotenc|nonce|dedup' -A3

# 5. Quotas
rg -n -i -e 'quota|limit|plan|tier|subscription|seat|usage|max_' -A3
```

Then, for each of the top three flows by business value, **write the sequence of HTTP calls the UI
makes** and ask, at every step: what stops me from calling step N without step N-1, twice, with a
different object ID, or with modified values?

## Verification

- **Ask the customer what the rules are.** A single 15-minute conversation about "what must always be
  true about an order?" produces better hypotheses than a day of code reading. Invariants live in
  people's heads and in support tickets, not in the repository.
- Prefer database constraints as the falsifier. Application-level enforcement is bypassed by the next
  code path someone adds; a unique index is not.
- Read support/incident history if offered. Business logic bugs recur, and past incidents name the
  invariants that have already failed once.

## Common false positives

| Looks like | Actually |
|---|---|
| Price in the request body | Validated server-side against the catalogue before charging — find that check |
| No idempotency key | The provider enforces idempotency, or a unique constraint makes the duplicate fail |
| Missing quota check on a path | Enforced downstream at the resource-creation layer common to all paths |
| Status settable via update | A serializer allowlist excludes it, or a transition guard runs in a model hook |
| Race window in code | A unique index makes the second writer fail — check the schema before reporting |
