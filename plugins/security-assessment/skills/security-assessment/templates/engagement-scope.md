# Engagement Scope & Rules of Engagement

**Complete this before any assessment work. `sa init` + `sa scope` record the machine-readable half;
this document is the human agreement.**

## Engagement

| | |
|---|---|
| Customer | |
| Engagement name / ID | |
| Dates | |
| Assessor(s) | |
| Customer technical contact | |
| **Customer security contact for urgent findings** | *(name + channel — agree this now, not after you find something)* |

## Authorization

| | |
|---|---|
| Authorized by (name, role) | |
| Reference (SOW / ticket / email) | |
| Date recorded | |
| **Approved posture** | PASSIVE / ACTIVE-SAFE / INTRUSIVE |

Without a completed authorization block, the assessment runs **PASSIVE only** (code and configuration
reading, read-only API calls with supplied credentials). See `references/method-safety.md`.

## In scope

| Asset | Identifier | Environment | Notes |
|---|---|---|---|
| Repository | | | |
| Application | | | |
| API | | | |
| Cloud account | | | |
| CI/CD | | | |

## Out of scope — explicitly

- Production systems (unless named above)
- Third-party services and vendor systems
- Anything not listed in the in-scope table
-

## Prohibited actions

Never performed, regardless of posture, without a separate written approval per technique:
data deletion or modification · denial of service · credential attacks · persistence ·
destructive exploitation · lateral movement beyond the boundary · attacks on third parties ·
access to real user accounts or real customer data.

## Test windows and notification

| | |
|---|---|
| Permitted window | |
| Source IPs | |
| Traffic identification (User-Agent / header) | |
| Who to notify before active testing | |

## Data handling

- Evidence is stored in the engagement workspace only.
- Secrets, PII and customer records are redacted at capture time.
- Retention: ____ ; destruction: ____
- Deliverables are shared via: ____

## Access provided

| Access | Provided? | Notes |
|---|---|---|
| Source repository (read) | | |
| Cloud account (read-only role) | | |
| Staging environment | | |
| Test accounts (per role, per tenant) | | |
| Architecture documentation | | |
| Prior assessment reports | | |

**Access not provided becomes an assessment gap.** Record each as an UNKNOWN
(`sa unknown add`) and report it in the coverage section rather than silently working around it.
