# Technical Assessment Report — <customer / system>

<!-- `sa report technical` generates this from the ledgers. Use this template when writing
     by hand, or to extend the generated file. Write in the customer's language;
     keep IDs, CWE/OWASP references and code excerpts verbatim. -->

**Date**: <yyyy-mm-dd>  ·  **Assessed commit**: `<sha>`  ·  **Posture**: PASSIVE / ACTIVE-SAFE / INTRUSIVE
**In scope**: <>  ·  **Out of scope**: <>
**Authorized by**: <name, ref>

## 1. Summary

| Severity | Count |
|---|---|
| Critical | |
| High | |
| Medium | |
| Low | |
| Informational | |

<Two or three sentences: what this system is, what the assessment covered, and the headline result.>

## 2. Assessment coverage

**Absence of findings in an area that was not assessed is not evidence of its security.**

| Surface | Entry point | Exposure | State | Reason if not assessed |
|---|---|---|---|---|

### Open unknowns

| ID | Question | What would resolve it | What it blocks |
|---|---|---|---|

### Method and limitations

- Techniques used: <static code review / configuration review / read-only cloud API / authorized runtime testing>
- Not performed: <runtime testing / production / third-party systems / intrusive techniques> and why
- Findings marked *AI-generated, not yet human-reviewed*: <list>

## 3. Findings

<One section per finding — use `templates/finding.md`. Order by severity, then ID.>

## 4. Controls that are working

Hypotheses tested and refuted. These are the defences the customer should not remove, and they form
the regression suite for the next assessment.

| Hypothesis | Control that refuted it | Location |
|---|---|---|

## 5. Systemic observations

Patterns rather than instances — where the architecture makes a class of bug likely to recur, and
what structural change would prevent the class rather than the instance.

## 6. Appendix

### A. Severity model

`score = 0.35·T + 0.25·E + 0.25·B + 0.15·X`, banded at 3.50 / 2.80 / 2.00 / 1.40.
Each finding lists its T/E/B/X so any rating can be re-derived or challenged.

### B. Severity overrides

| ID | Computed | Reported | Reason |
|---|---|---|---|

### C. Candidates investigated and dismissed

Shows the work, and stops the same lead being re-raised at the next assessment.

| Source | Lead | Dismissed at | Reason |
|---|---|---|---|

### D. Evidence index

| ID | Grade | Kind | Locator | Commit |
|---|---|---|---|---|
