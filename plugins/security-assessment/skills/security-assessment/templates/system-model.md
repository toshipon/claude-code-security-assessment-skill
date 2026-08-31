# System Model — <engagement>

Every answer carries its source. `[UNKNOWN]` is a valid answer and must name what would resolve it
(`sa unknown add`). Do not guess safe or unsafe.

| # | Question | Answer | Source | Confidence |
|---|---|---|---|---|
| 1 | Business purpose | | | |
| 2 | Architecture | | | |
| 3 | Technology stack (resolved versions) | | | |
| 4 | Authentication mechanism | | | |
| 5 | Authorization model & enforcement point | | | |
| 6 | User roles | | | |
| 7 | Data classification | | | |
| 8 | Tenancy model & boundary | | | |
| 9 | External integrations | | | |
| 10 | Public endpoints | | | |
| 11 | Internal endpoints | | | |
| 12 | Cloud environment | | | |
| 13 | CI/CD | | | |
| 14 | Secrets management | | | |
| 15 | IaC & dependency management | | | |

## Architecture sketch

```
<components, datastores, queues, external calls, and where the trust boundaries fall>
```

## Roles and capabilities

| Role | Obtained how | May do | Enforced where |
|---|---|---|---|
| anonymous | — | | |
| user | self-signup? | | |
| tenant admin | | | |
| support / staff | | | |
| superuser | | | |

Whether **self-signup is open** determines the exploitability of every "requires authentication"
control in this assessment. Establish it explicitly.

## Data inventory

| Data | Classification | Store | Regulation | Leaves the boundary to |
|---|---|---|---|---|

## Open unknowns

| ID | Question | Blocks | What would resolve it |
|---|---|---|---|
