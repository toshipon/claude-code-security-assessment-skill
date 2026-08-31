# Module: IAM Assessment

> **Load when** you can read cloud identity policies, or IaC that defines them.
> **Safety**: read policies. Never attempt privilege escalation to prove a path — the policy
> analysis *is* the evidence. See `references/method-safety.md`.
> **Always flag `Human Review Required`** — policy evaluation is genuinely hard and both
> over- and under-reporting here are costly (`references/method-human-review.md`).

IAM is where over-reporting destroys a report's credibility fastest. Every posture scanner flags
every wildcard, and most wildcards are either unreachable or constrained by something the scanner
cannot see. The question is never "is this policy broad?" — it is **"what can this principal
actually do, and who can become this principal?"**

## Method

1. **Enumerate principals** — users, roles, service accounts, workload identities, and anything
   external with a trust relationship.
2. **For each, compute effective permissions**: identity policies ∪ resource policies ∩ permission
   boundary ∩ SCP/org policy ∩ session policy. All five layers, or the answer is wrong.
3. **Ask who can assume it.** A powerful role nobody can reach is not a finding; a weak role anyone
   can reach may be.
4. **Look for escalation paths** — the permission that grants other permissions.

Step 2 is what distinguishes this from a scanner, and step 4 is what produces the finding.

## Hypothesis catalog

### IM-1 · Privilege escalation paths
- **Statement**: a principal can grant itself, or assume, more privilege than intended.
- **Falsifier**: no IAM-mutating or IAM-passing permission is reachable without an equivalent
  privilege already, and a permission boundary constrains what can be created.
- **EV**: the effective policy set for the principal (E4), plus the trust chain (E4).
- **The escalation primitives to search for specifically** — each is a well-known path:
  - `iam:CreatePolicyVersion` / `iam:SetDefaultPolicyVersion` — rewrite your own policy
  - `iam:AttachUserPolicy` / `AttachRolePolicy` / `PutUserPolicy` — attach `AdministratorAccess`
  - `iam:CreateAccessKey` on another user; `iam:UpdateLoginProfile`
  - **`iam:PassRole` combined with a compute service** (`ec2:RunInstances`, `lambda:CreateFunction` +
    `InvokeFunction`, `ecs:RunTask`, `glue:CreateDevEndpoint`, `cloudformation:CreateStack`,
    `codebuild:CreateProject`) — the single most common real escalation, and the one scanners
    consistently miss because neither permission is alarming alone
  - `sts:AssumeRole` with a permissive trust policy
  - `lambda:UpdateFunctionCode` on a function with a more privileged role
  - `ssm:SendCommand` / `ssm:StartSession` onto an instance with a better role
  - GCP: `iam.serviceAccounts.actAs`, `.getAccessToken`, `.signJwt`, `setIamPolicy` on a project
  - Azure: `Microsoft.Authorization/roleAssignments/write` (User Access Administrator)
- CWE-269

### IM-2 · Excessive permissions
- **Statement**: a principal holds permissions far beyond its function.
- **Falsifier**: policies scoped by action and resource, ideally evidenced by access-analyser or
  last-accessed data.
- **EV**: the policy (E4), plus **usage data** (`aws iam get-service-last-accessed-details`, GCP
  recommender) (E4) — usage evidence turns "this looks broad" into "this is broad *and unused*",
  which is what makes the finding actionable rather than arguable.
- **Traps**: `"Action": "*"` with `"Resource": "*"`; `AdministratorAccess` on a CI role; service
  wildcards (`s3:*`) on all resources; `NotAction` policies (they grant everything except a list —
  far broader than they read); managed policies used as a convenience (`PowerUserAccess`).
- **Prioritise by blast radius**: an over-permissioned role reachable from the internet or from CI is
  a finding; an over-permissioned role usable only by an existing admin is hygiene.

### IM-3 · Trust policy weaknesses
- **Statement**: an unintended party can assume a role.
- **Falsifier**: trust policies name specific principals, and every third-party trust carries an
  `sts:ExternalId` condition.
- **Traps**: `"Principal": {"AWS": "*"}`; a whole account trusted rather than a specific role; a
  vendor role without `ExternalId` (**confused deputy**); an OIDC trust whose `sub` condition is
  missing or wildcarded — see IM-4.

### IM-4 · Workload identity federation (OIDC)
- **Statement**: an external workload can assume a cloud role it should not.
- **Falsifier**: the trust condition pins **both** `aud` and a specific `sub`, and the `sub` is
  matched exactly rather than by prefix.
- **EV**: the role's trust policy conditions (E4).
- **Traps** — this is a high-yield, high-severity, frequently-wrong configuration:
  - `token.actions.githubusercontent.com:sub` set to `repo:org/*` — **any repository in the
    organization** can assume the role, including a fork-triggered workflow or a new repo any member
    can create.
  - `sub` matched with `StringLike` and a trailing wildcard: `repo:org/repo:*` trusts every branch,
    every tag and every pull request in that repo.
  - Missing `aud` condition entirely.
  - Correct: `repo:org/repo:ref:refs/heads/main` or `repo:org/repo:environment:production`, matched
    with `StringEquals`.
- Cross-reference `cicd-assessment.md`.

### IM-5 · Long-lived credentials
- **Falsifier**: no IAM users with access keys where a role would work; any remaining keys are
  rotated, scoped, and monitored.
- **EV**: credential report (E4).
- **Traps**: keys older than a year; unused keys still active; a shared "deploy" user with no
  attribution; root access keys; service account keys downloaded as JSON (GCP) and living in a repo
  or a CI variable.

### IM-6 · Missing guardrails
- **Falsifier**: SCPs / organization policies deny the actions no workload should ever perform
  (disabling CloudTrail, deleting log buckets, leaving the approved regions, making things public),
  and permission boundaries bound what self-service role creation can produce.
- **Impact framing**: a missing guardrail is not a vulnerability; it is the absence of containment.
  Report it as such — Medium at most on its own, but it raises the impact of every IM-1 finding.

### IM-7 · Human access model
- MFA on all console access, root included; break-glass procedure documented and monitored;
  identity-centre/SSO rather than per-account users; joiners-movers-leavers actually applied
  (check for principals belonging to people who have left).

## Evidence collection — read-only

```bash
# AWS
aws sts get-caller-identity
aws iam generate-credential-report >/dev/null; aws iam get-credential-report --query Content --output text | base64 -d
aws iam list-users; aws iam list-roles
aws iam list-attached-role-policies --role-name <r>; aws iam list-role-policies --role-name <r>
aws iam get-role --role-name <r> --query 'Role.AssumeRolePolicyDocument'    # trust policy
aws iam get-service-last-accessed-details --job-id <id>                     # usage evidence
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
aws accessanalyzer list-analyzers; aws accessanalyzer list-findings --analyzer-arn <a>   # external access

# search for escalation primitives across all policies
aws iam list-policies --scope Local --query 'Policies[].Arn' --output text | tr '\t' '\n' | while read a; do
  v=$(aws iam get-policy --policy-arn "$a" --query 'Policy.DefaultVersionId' --output text)
  aws iam get-policy-version --policy-arn "$a" --version-id "$v" --query 'PolicyVersion.Document'
done | rg -n -e 'iam:PassRole|iam:\*|iam:Create|iam:Attach|iam:Put|sts:AssumeRole|"\*"'

# GCP
gcloud projects get-iam-policy <p> --format=json | jq '.bindings[] | select(.role|test("owner|editor|admin"))'
gcloud iam service-accounts list; gcloud iam service-accounts keys list --iam-account <sa>

# Azure
az role assignment list --all --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor']"
```

In IaC: `rg -n -e '"Action":\s*"\*"|Action\s*=\s*\["\*"\]|"Principal":\s*"\*"|PassRole' --glob '*.tf' --glob '*.json' --glob '*.yaml'`

## Verification

- **Compute the effective permission, not the policy text.** Check for a permission boundary, an SCP,
  and a session policy before calling anything over-permissioned. Use the policy simulator
  (`aws iam simulate-principal-policy`) where available — it is read-only and authoritative.
- **Establish reachability**: who or what can act as this principal? Trace it back to a human, a
  workload, or an external party. An unreachable role is hygiene, not a finding.
- **Use last-accessed data.** "Grants `s3:*`, has used only `s3:GetObject` in 90 days" is a finding
  the customer will act on today; "grants `s3:*`" is one they will argue about.
- Never prove an escalation path by walking it.

## Common false positives

| Looks like | Actually |
|---|---|
| `Action: "*"` on a role | Constrained by a permission boundary or an SCP |
| An admin role | A break-glass role with MFA, alerting, and a documented procedure |
| A wildcard resource | The service has no resource-level permissions (some genuinely do not) |
| A cross-account trust | An intended vendor integration **with** an `ExternalId` — check for the condition |
| A broad CI role | Constrained by an OIDC `sub` condition to one repo and one branch — check the condition, then verify it is `StringEquals` and not a prefix |
