# Retrospective — <engagement>

**Engagement-local. May contain customer specifics. Never committed to the skill.**
Only sanitized, generalized entries reach `knowledge/` — via `sa retro promote`, which blocks on
customer identifiers and requires human approval.

**Date**: <>  ·  **Duration**: <>  ·  **Findings**: <n>  ·  **Candidates dismissed**: <n>

## Missed hypotheses

What did the customer, a later test, or the remediation review find that we did not?
The most valuable section — for each, name the generator in `references/method-hypothesis.md` that
*should* have produced it.

| What was missed | Why we missed it | Which generator should have caught it | Generalizable? |
|---|---|---|---|

## False positives that reached the report

Each one is a defect in the FP pipeline. At which stage should it have died?

| Finding | Why it was wrong | Stage that should have killed it | Catalog entry? |
|---|---|---|---|

## Near-misses

Candidates we nearly killed for a bad reason. Invisible unless recorded — an over-aggressive
pipeline fails silently.

| Candidate | Why we nearly dismissed it | What saved it |
|---|---|---|

## Detection patterns that worked

| Pattern | Where it applied | Generalizable? |
|---|---|---|

## Verification methods that worked

How did we settle a hard hypothesis cheaply? The most reusable artifact this retrospective produces.

| Hypothesis type | Verification method | Cost |
|---|---|---|

## Unknowns and access

| Unknown | What blocked us | What access would have resolved it |
|---|---|---|

→ Feeds the access request in the next engagement's scoping.

## Effort vs. yield

| Module | Time spent | Findings | Notes |
|---|---|---|---|

→ Reprioritises module order for the next assessment.

## Customer-specific exceptions

**Stays local.** Accepted risks and intended behaviours that look like bugs — so the next assessment
does not re-report them.

| Observation | Why it is intended / accepted | Accepted by | Date |
|---|---|---|---|

## Skill changes

Structural gaps found: a module missing a hypothesis class, a severity guardrail that produced a
wrong band, a pipeline stage letting FPs through.

| Gap | Change to make | File | Done |
|---|---|---|---|

## Promotion queue

```bash
sa retro add --kind detection-pattern --text "<generalized lesson, no customer>"
sa retro promote --entry R-00n --target detection-patterns --approved-by "<name>"
```

| Entry | Target | Rewritten for generality? | Approved by |
|---|---|---|---|
