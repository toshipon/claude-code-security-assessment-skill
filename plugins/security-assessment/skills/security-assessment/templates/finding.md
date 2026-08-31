# [<SEVERITY>] <F-ID> — <title>

<!-- Rendered from findings.jsonl; see references/finding-schema.md for field rules.
     `sa validate` must pass before this is published. -->

| | |
|---|---|
| **Severity** | <band> (score <n.nn>; T=<> E=<> B=<> X=<>) |
| **Confidence** | CONFIRMED / SUSPECTED / NEEDS-VERIFICATION |
| **AI confidence** | High / Medium / Low — *<what could not be established, if below High>* |
| **Human review** | **Required** / not required |
| **CWE** | |
| **OWASP** | |
| **Component** | `<path:line>` @ `<commit>` |
| **Entry point** | `<METHOD /path>` |
| **Attacker** | <starting position> |

## Preconditions

- 

## Attack scenario

<End-to-end narrative: attacker position → required knowledge → steps → result.
If you cannot narrate it without a gap, this is NEEDS-VERIFICATION, not a finding.>

## Evidence

| ID | Grade | Location | What it shows |
|----|-------|----------|---------------|

## Controls checked

Every layer inspected, including those where nothing was found. This is what separates
"there is no check" from "we did not find one".

| Layer | Location | Result |
|---|---|---|
| route / gateway | | |
| middleware | | |
| guard / decorator | | |
| handler | | |
| service | | |
| ORM scope | | |
| database policy | | |

## Impact

<Business consequence, not a restatement of the technical issue.>

## Likelihood

<What an attacker needs, how long it would take, whether it is opportunistically discoverable.>

## Remediation

**Summary**: 

**Steps**:
1. 

**Code** (this codebase's framework and idiom):
```diff
```

**Effort**: S / M / L    **Bucket**: Immediate / 7d / 30d / 90d

**Defence in depth**: 

**Risks of this fix**: <what it might break>

## Verification

**Method**: <how the customer proves the fix worked, independently>
**Expected result**: 
**Regression test**: <something they can keep>

## Severity rationale

<Why this band for this system. A tool's rating is not a rationale.>

## Other instances of this root cause

| Location | Verified |
|---|---|

## References
