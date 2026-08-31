# Threat Model — <engagement>

## Assets

| ID | Asset | Classification | Where it lives | Impact if breached | Rank |
|----|-------|----------------|----------------|--------------------|------|

The rank column feeds the `B` factor in `references/method-severity.md`.

## Actors

| ID | Actor | Starts with | Motivation |
|----|-------|-------------|------------|
| T-1 | Unauthenticated internet | | |
| T-2 | Self-registered user | | |
| T-3 | Legitimate customer user | | |
| T-4 | Malicious tenant admin | | |
| T-5 | Compromised employee / CI credential | | |
| T-6 | Compromised third party | | |

## Trust boundaries

| ID | Boundary | What crosses | Validated by | Verified | Hypothesis |
|----|----------|--------------|--------------|----------|------------|

## Privilege boundaries

| From | To | Enforced by | Location | Verified |
|---|---|---|---|---|

## Data flows

```
<trace the top-ranked assets; include the logging, analytics, email and error-tracker branches>
```

## External dependencies

| Party | Data sent to them | Access they have inbound | If compromised |
|---|---|---|---|

## Administrative interfaces

| Interface | Exposure | Authn | Authz | Audit logged |
|---|---|---|---|---|

## Derived hypotheses

| ID | Surface | Statement | Falsifier | Priority |
|----|---------|-----------|-----------|----------|
