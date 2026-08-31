# Executive Summary — <customer / system>

<!-- Audience: executives and product managers. One to two pages. No jargon, no CWE numbers,
     no code. Every claim must be traceable to a finding ID in the technical report. -->

**Date**: <yyyy-mm-dd>  ·  **Assessment period**: <>  ·  **Scope**: <one line, in business terms>

## Current risk

<One paragraph, plain language. What is the state of this system's security today, and what would a
motivated attacker most plausibly achieve? Be direct — this is the paragraph that gets read.>

| | |
|---|---|
| Critical issues | <n> |
| High issues | <n> |
| Requiring action within 7 days | <n> |
| Areas we could not assess | <n> |

## Most important findings

<Three at most. For each: one sentence on what it is, one on what it would let someone do.
No technical detail — that is what the technical report is for.>

1. **<F-ID> — <plain-language title>**
   <What it allows. Who could do it. What it would cost the business.>

## Business impact

<Translate technical severity into business consequence: regulatory exposure, customer data,
contractual obligations, financial loss, service availability, reputation. Name the specific
regulation or contract where one applies.>

## Priority actions

| When | Action | Why now |
|---|---|---|
| Immediately | | |
| Within 7 days | | |
| Within 30 days | | |
| Within 90 days | | |

## What we could not assess

**This section is as important as the findings.** These areas were not examined, so this report says
nothing about their security either way.

| Area | Why not assessed | What we would need |
|---|---|---|

## Confidence in this assessment

- Findings were verified against <code / configuration / live system>, at commit `<sha>`.
- <n> findings are marked as requiring verification, meaning we identified a likely issue but could
  not fully confirm it with the access available.
- <n> findings require review by a security engineer before action is taken.
- This assessment reflects the system as it was on <date>. Subsequent changes are not covered.
