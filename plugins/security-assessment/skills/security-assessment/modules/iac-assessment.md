# Module: IaC Assessment

> **Load when** the repository contains Terraform, CloudFormation, Pulumi, CDK, Helm charts, or
> Kubernetes manifests.

IaC is the highest-leverage place to fix cloud problems — one change, permanently, reviewable — but
IaC is a *description*, not the running system. Findings here are about what will be built and about
what the codebase encourages, and they must be reconciled with reality.

## The drift rule

**IaC is E4 evidence about intent, not about the deployed state.** Three cases, three different findings:

| IaC | Deployed | Finding |
|---|---|---|
| Secure | Secure | None |
| Insecure | Insecure | The misconfiguration, fixed in IaC |
| Secure | Insecure | **Drift** — someone changed it by hand, and the next `apply` will not fix it. Report the drift *and* the process gap |
| Insecure | Secure | Latent — the next `apply` re-introduces it. Report as a real finding, because it will become live |

Where you have both, compare them. Where you have only IaC, say so and mark the deployed state UNKNOWN.
Also check whether **all** infrastructure is managed by IaC: resources created by hand are outside
every review process the customer has, and enumerating them is often the more valuable finding.

## Hypothesis catalog

### IC-1 · Public exposure by default
- **Traps**: `0.0.0.0/0` in security group or firewall rules; `publicly_accessible = true`;
  `map_public_ip_on_launch`; S3 without `aws_s3_bucket_public_access_block`; a Kubernetes `Service`
  of type `LoadBalancer` where `ClusterIP` was meant; an Ingress with no auth annotation;
  `authorization_type = "NONE"` on API Gateway or a Lambda function URL.

### IC-2 · IAM misconfiguration in IaC
- **Traps**: `"Action": ["*"]`, `"Resource": ["*"]`; `iam:PassRole` unconstrained; a trust policy
  with `"Principal": "*"`; an OIDC `sub` condition using a wildcard (see `iam-assessment.md` IM-4);
  a managed `AdministratorAccess` attachment. See `iam-assessment.md` for how to rate these.

### IC-3 · Encryption not enabled
- **Traps**: missing `server_side_encryption_configuration`, `storage_encrypted`, `encrypted = true`
  on EBS, `kms_key_id` absent so the default key is used for regulated data; no TLS enforcement
  (`ssl_policy`, a bucket policy denying `aws:SecureTransport = false`); Kubernetes secrets not
  encrypted at rest.

### IC-4 · Logging and retention
- **Traps**: no CloudTrail/audit-log resource; no access logging on buckets or load balancers; no
  VPC flow logs; a log group with no `retention_in_days` (defaults to never expire — a cost problem
  the customer will notice, and sometimes a compliance one); log destinations the workload's own role
  can delete.

### IC-5 · Network boundaries
- **Traps**: everything in one subnet or the default VPC; a database subnet with a route to an
  internet gateway; overly broad VPC peering; a Kubernetes cluster with a public API endpoint and no
  authorized-network restriction; no `NetworkPolicy` (pods can reach every other pod by default).

### IC-6 · Secrets in IaC
- **Traps**: literal values in `.tf` files; `default` values on sensitive variables; secrets in
  `terraform.tfvars` committed; **secrets in state** — Terraform state stores values in plaintext, so
  a state file in an unencrypted or world-readable bucket is a credential leak. Check the backend
  configuration: encryption, access policy, versioning, and state locking.
- Kubernetes `Secret` manifests are base64, which is encoding. A committed `Secret` is a committed
  credential.

### IC-7 · Dangerous defaults
- **Traps**: `skip_final_snapshot = true` on production databases; `force_destroy = true` on buckets
  holding data; `deletion_protection = false`; `prevent_destroy` absent on critical resources;
  `lifecycle { ignore_changes }` hiding drift on a security-relevant attribute; a provider version
  unpinned; a module sourced from a mutable git ref or an unverified registry.
- **Kubernetes defaults specifically**: containers running as root, no `securityContext`, privileged
  containers, `hostNetwork`/`hostPID`, missing resource limits, the default service account with a
  mounted token, no read-only root filesystem, and `latest` image tags.

### IC-8 · Module and provider supply chain
- **Traps**: modules from an unpinned source; a provider without a version constraint; a lockfile
  (`.terraform.lock.hcl`) not committed; a module fetched over plain HTTP.

## Evidence collection

```bash
fd -e tf -e tfvars; fd -g '*.yaml' -g '*.yml' . k8s manifests helm 2>/dev/null | head -30
fd -g 'template.yaml' -g 'cloudformation*' -g 'serverless.yml' -g 'Chart.yaml'

# high-signal greps
rg -n -e '0\.0\.0\.0/0|::/0' --glob '*.tf' --glob '*.yaml' --glob '*.json'
rg -n -e 'publicly_accessible\s*=\s*true|force_destroy\s*=\s*true|skip_final_snapshot\s*=\s*true'
rg -n -e '"Action":\s*"\*"|Action\s*=\s*\["\*"\]|"Principal":\s*(\{\s*"AWS":\s*)?"\*"'
rg -n -i -e 'encrypted\s*=\s*false|enable_key_rotation\s*=\s*false|ssl|tls|kms_key'
rg -n -i -e 'privileged:\s*true|runAsUser:\s*0|hostNetwork:\s*true|hostPID:\s*true|allowPrivilegeEscalation:\s*true'
rg -n -e 'image:.*:latest' --glob '*.yaml'
# secrets and state
rg -n -i -e 'password|secret|token|access_key' --glob '*.tf' --glob '*.tfvars'
rg -n -A8 -e 'backend\s+"s3"|backend\s+"gcs"|backend\s+"azurerm"'    # is state encrypted and locked?
git ls-files | rg -n -e 'terraform\.tfstate|\.tfvars$'                # state or vars committed?
# pinning
rg -n -e 'source\s*=\s*"git::|source\s*=\s*"http|version\s*=' --glob '*.tf' | head -30

# tools — output is E5, triage it
command -v checkov && checkov -d . --compact --quiet
command -v tfsec && tfsec . --no-color
command -v trivy && trivy config .
command -v kubescape && kubescape scan .
```

References: `security-audit/references/{terraform,container}-security.md`.

## Verification

- **Read the resource, not the tool's rule name.** Scanner rules are generic; the resource's context
  decides. `checkov` will flag a public bucket that is a public website by design.
- Determine whether the resource is actually deployed. Unused modules, commented resources, and
  `count = 0` all kill a candidate.
- Trace variables to their values — a security-relevant setting driven by `var.environment` may be
  correct in production and wrong only in a dev workspace, or vice versa. Check every workspace.
- Reconcile with the deployed state where you have access (`cloud-assessment.md`).

## Common false positives

| Looks like | Actually |
|---|---|
| `0.0.0.0/0` ingress | On port 443 of a public load balancer — intended |
| Public bucket | A static website bucket, by design — check its contents |
| Unencrypted resource | The provider encrypts by default now; the attribute is redundant |
| Wide IAM in a module | The module is not instantiated, or is bounded at the call site |
| A finding in `examples/` or `test/` | Not deployed — verify it is not referenced by a live workspace |
| Missing `NetworkPolicy` | A service mesh enforces mTLS and policy instead |
