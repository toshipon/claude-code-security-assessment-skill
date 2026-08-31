# Module: Cloud Assessment

> **Load when** you have read access to a cloud account, or IaC that describes one.
> **Safety**: read-only API calls only. Never create, modify or delete resources. Never
> assume a role you were not explicitly given. See `references/method-safety.md`.
> IAM is deep enough to have its own module: `iam-assessment.md`.

Cloud findings are frequently over-reported: a posture scanner flags 300 rows, most of which are
neutralised by a network boundary, an SCP, or the fact that the resource holds nothing. Exposure and
data sensitivity are what make a cloud finding real.

## Hypothesis catalog

### CL-1 · Unintended public exposure
- **Statement**: a resource is reachable from the internet when it was not meant to be.
- **Falsifier**: the resource is in a private subnet with no public IP and no permissive
  ingress/resource policy, verified at every layer that could expose it.
- **EV**: the actual effective configuration read from the provider (E4).
- **Traps**: S3 bucket or object ACLs and bucket policies (check both, plus the account and bucket
  public-access blocks); RDS/Redshift `PubliclyAccessible`; Elasticsearch/OpenSearch domains with an
  open access policy; unauthenticated Redis/Memcached/MongoDB/Elastic on a public IP; API Gateway
  with authorization `NONE`; Lambda function URLs with `AuthType: NONE`; public EBS/RDS snapshots and
  AMIs (a very common and very high-impact miss); public container registries; GCS bucket
  `allUsers`/`allAuthenticatedUsers`; Azure blob containers set to public.
- **Multiple layers must all be checked** — an S3 bucket can be public via ACL, bucket policy, or
  the absence of a public-access block, and checking only one produces a false negative.
- CWE-284

### CL-2 · Network boundaries
- **Falsifier**: security groups and firewall rules scoped to specific sources and ports; no
  `0.0.0.0/0` on administrative ports; segmentation between tiers.
- **EV**: security group / firewall rules (E4); route tables and subnet associations (E4).
- **Traps**: `0.0.0.0/0` on 22/3389/3306/5432/6379/27017; a security group referencing another that
  is itself wide open; a default VPC still in use; a NAT/bastion left from a migration; VPC peering
  or Transit Gateway routes that quietly join two trust zones; an internal ALB that is not internal.
- **Verify effective reachability**, not just rule text: a permissive SG on an instance with no
  public IP in a private subnet is not exposed. That distinction is where cloud false positives
  are killed.

### CL-3 · Encryption
- **Falsifier**: encryption at rest enabled on storage, databases, snapshots and backups; TLS enforced
  in transit; customer-managed keys where the data classification requires them.
- **EV**: encryption configuration per resource (E4).
- **Traps**: encryption on the primary but not on snapshots, replicas, or backups; S3 buckets without
  a default encryption policy; unencrypted EBS volumes attached to encrypted instances; TLS not
  *enforced* (available but not required) on RDS, S3 or the load balancer.

### CL-4 · Logging and detection
- **Falsifier**: CloudTrail (all regions, management + relevant data events) delivering to a
  protected bucket; VPC flow logs; service-level access logs; log integrity validation; retention
  matching the customer's requirements; GuardDuty/Security Command Center enabled.
- **EV**: trail/sink configuration (E4).
- **Traps**: a trail in one region only; data events not captured, so S3 object reads are invisible;
  logs written to a bucket the same compromised principal can delete (no MFA-delete, no object lock,
  no cross-account isolation); GuardDuty enabled but with no route to a human; alerts to an unmonitored
  mailbox.
- **Severity note**: logging gaps are rarely Critical alone. Their real cost is **incident response
  blindness** — say that explicitly in the impact rather than inflating the severity.

### CL-5 · Secrets in cloud configuration
- **Falsifier**: secrets in Secrets Manager / Parameter Store (SecureString) / Secret Manager / Key
  Vault, referenced at runtime with a scoped IAM policy.
- **Traps**: plaintext secrets in Lambda/ECS/Cloud Run environment variables (visible to anyone with
  `DescribeFunction`/`DescribeTaskDefinition` — a much wider audience than the customer expects); EC2
  user-data scripts (readable from the instance and from the metadata service); ECS task definitions;
  CloudFormation/Terraform parameters; a secret in a container image layer.

### CL-6 · Key management
- **Falsifier**: KMS/Cloud KMS keys with a resource policy scoped to specific principals, rotation
  enabled, and separation between environments.
- **Traps**: a key policy with `"Principal": "*"`; `kms:*` granted broadly; the AWS-managed default
  key used for regulated data (it cannot be policy-scoped per workload); no rotation; a single key
  shared across environments.

### CL-7 · Cross-account and external access
- **Falsifier**: every cross-account trust names a specific account **and** requires an `ExternalId`
  where a third party is involved; resource policies do not use `"Principal": "*"`.
- **EV**: role trust policies and resource policies (E4). See `iam-assessment.md`.
- **Traps**: the **confused deputy** — a vendor role with no `ExternalId` condition; `"AWS": "*"` in
  a resource policy with only a condition that is easy to satisfy; an organization-wide share;
  RAM/shared VPC arrangements nobody remembers approving.
- **Enumerate every principal outside the account that has access to anything.** This list is short,
  it is almost never maintained, and customers find it valuable on its own.

### CL-8 · Baseline account hygiene
- Root account: MFA on, no access keys, unused.
- Regions not in use: disabled or monitored (unused regions are where cryptomining lands).
- Account-level public-access blocks and default encryption enabled.
- Service control policies / organization policies as a backstop.
- No long-lived IAM users where a role would do (see `iam-assessment.md`).

## Evidence collection — read-only

```bash
# AWS — identity first; know what you are authorized as before anything else
aws sts get-caller-identity
aws s3api get-public-access-block --bucket <b>; aws s3api get-bucket-policy --bucket <b>
aws s3api get-bucket-acl --bucket <b>; aws s3api get-bucket-encryption --bucket <b>
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName]'
aws ec2 describe-snapshots --owner-ids self --restorable-by-user-ids all --query 'Snapshots[].SnapshotId'
aws ec2 describe-images --owners self --filters Name=is-public,Values=true
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,PubliclyAccessible,StorageEncrypted]'
aws cloudtrail describe-trails; aws cloudtrail get-trail-status --name <t>
aws guardduty list-detectors
aws lambda list-functions --query 'Functions[].[FunctionName,Environment]'
aws kms list-keys   # then get-key-policy per key

# GCP
gcloud projects get-iam-policy <p> --format=json
gsutil iam get gs://<b>
gcloud compute firewall-rules list --filter="sourceRanges:0.0.0.0/0"
gcloud logging sinks list

# Azure
az account show
az storage account list --query '[].[name,allowBlobPublicAccess,enableHttpsTrafficOnly]'
az network nsg list --query '[].securityRules[?sourceAddressPrefix==`*`]'
```

References: `security-audit/references/{aws,gcp,azure}-security.md`.

## Verification

- **Read the effective configuration from the provider, not from the IaC.** They drift, and the
  provider is the authority. Where they differ, that difference is itself a finding
  (see `iac-assessment.md`).
- Before reporting exposure, check every layer: resource policy, ACL, account-level block, network
  path, and any SCP or organization policy that overrides it.
- Determine what the resource actually holds. A public bucket of CSS files and a public bucket of
  invoices are not the same finding.

## Common false positives

| Looks like | Actually |
|---|---|
| Public S3 bucket | Intentional static asset hosting — verify the contents, then report only if it also holds non-public objects |
| `0.0.0.0/0` security group | On an instance with no public IP in a private subnet — not reachable |
| Unencrypted volume | The service encrypts by default at the platform layer — verify |
| No CloudTrail in this account | An organization trail covers it — check the management account |
| Wide IAM policy | Constrained by a permission boundary or an SCP — see `iam-assessment.md` |
