# Verification Recipes

How to settle a hypothesis cheaply and conclusively, without intrusive testing.
Grown by `sa retro promote`.

---

## Ask an engineer to run it

**Settles** — Anything requiring a live observation: header values, endpoint reachability, a response
body, a configuration read.

**Recipe** — Write the exact command and the exact output you need. Send it to the customer's
engineer. Their output is **E1 evidence with zero risk and zero authorization overhead**, and it is
usually faster than obtaining approval for active testing.

**Why it beats testing it yourself** — No authorization needed, no traffic to explain to their SOC,
and it involves the person who can also tell you whether what you found is intended.

---

## Enumerate the control locations, then check each

**Settles** — "Is authorization missing?" — the highest-false-positive question in an assessment.

**Recipe** — Before looking for the vulnerable path, list every layer where the control *could* live
in this stack (route config, middleware, guard, handler, service, ORM scope, database policy,
gateway). Check each and record the result, including where you found nothing.

**Result** — Either you find the control (hypothesis refuted cheaply, no report noise) or you have a
defensible enumeration proving absence. Both are wins; guessing is not.

---

## Read the query, not the handler

**Settles** — Tenant and ownership scoping.

**Recipe** — Follow the call chain to the statement that actually reaches the database, and read the
predicate there. Application-layer checks are frequently bypassed by a second path to the same
repository; the query is the ground truth.

**Bonus** — In PostgreSQL, `SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class` and
`SELECT * FROM pg_policies` settle the database-layer question definitively, read-only, in one query.

---

## Check the resolved version's changelog

**Settles** — "Does the framework handle this by default?"

**Recipe** — Read the lockfile for the resolved version, then that version's own security
documentation or changelog. Never the declared range, never the latest release, never memory.

**Why** — Defaults change between majors. This is the largest single source of both false positives
and false negatives in framework-related findings.

---

## Diff the deployed state against the IaC

**Settles** — Whether an IaC finding is real, latent, or drift.

**Recipe** — Read the effective configuration from the provider (read-only API), and compare with the
IaC. Insecure in both is a live finding; secure in IaC but insecure deployed is drift plus a process
gap; insecure in IaC but secure deployed is latent and will return at the next apply.

---

## Read the constraint before reporting a race

**Settles** — Race condition and double-spend hypotheses, without racing anything.

**Recipe** — Read the schema for a unique index or `CHECK` constraint on the invariant, and the
transaction boundary and isolation level around the write. A unique index makes the second writer
fail regardless of application logic.

**Why** — Racing a live system needs authorization, risks state corruption, and is slower than
reading the DDL.
