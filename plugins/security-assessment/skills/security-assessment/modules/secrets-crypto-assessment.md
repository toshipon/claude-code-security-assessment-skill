# Module: Secrets & Cryptography Assessment

> **Load when** the system handles credentials, tokens, encryption, or sensitive logging — always.
> **Safety**: never test a discovered credential. Report immediately, out of band.
> See `references/method-safety.md` §Secrets you discover.

## Hypothesis catalog

### SC-1 · Hardcoded secrets in source
- **Falsifier**: all credentials come from environment or a secret manager at runtime; nothing
  credential-shaped is committed.
- **EV**: the location and shape (E2). **Never record the value.**
- **Traps**: `.env` files committed; config files with real values "for local development" that are
  production credentials; test fixtures with live keys; a private key in the repo; a database URL
  with an embedded password; a Kubernetes Secret manifest with base64 (encoding, not encryption).
- CWE-798

### SC-2 · Secrets in git history
- **Statement**: a credential was committed and removed, but remains in history and remains valid.
- **Falsifier**: history is clean, or every historical secret has been rotated after removal.
- **EV**: history scan output (E2/E5 → verify each hit).
- **Trap**: **deleting a file does not remove it from history.** A secret removed in a later commit
  is still readable by anyone who can clone — including every fork and every CI cache. The only fix
  is rotation; history rewriting alone is not sufficient.
- **This is the single highest-severity finding class this module produces**, and it is routinely
  missed because reviewers look at the working tree.

### SC-3 · Secrets in logs, errors and telemetry
- **Falsifier**: structured logging with an explicit field allowlist or a redaction filter, verified
  against the sensitive fields in the data model.
- **EV**: logging calls on request/response objects (E2); the error handler (E2); APM/error-tracker
  configuration (E2).
- **Traps**: logging the whole request or headers (captures `Authorization` and `Cookie`); logging
  the request body on the login or payment endpoint; error trackers capturing local variables
  (Sentry's `send_default_pii`); tokens in URLs, which land in access logs, proxy logs and `Referer`;
  debug logging left enabled in production.
- CWE-532

### SC-4 · Secrets reaching the client
- **Falsifier**: only publishable values appear in client bundles or client-visible config.
- **EV**: grep the **built** bundle (E2/E1).
- **Traps**: `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` prefixes applied to a real secret; a server-only key
  imported into a shared module that the bundler pulls into client code; source maps in production;
  a secret in a mobile app binary (extractable — never a secret).

### SC-5 · Weak cryptography
- **Falsifier**: authenticated encryption (AES-GCM, ChaCha20-Poly1305) with a unique nonce per
  operation; SHA-256+ for integrity; a KDF for passwords (see `auth-assessment.md` AU-2); a CSPRNG
  for anything security-relevant.
- **EV**: the cryptographic calls, their modes and their parameters (E2).
- **Traps**: ECB mode (visible patterns); CBC without a MAC (padding oracle); a static or reused IV;
  `Math.random`/`rand()`/`random.random()` for tokens, session IDs, reset tokens or OTPs;
  home-grown encryption; MD5/SHA-1 where collision resistance matters; a non-constant-time comparison
  of secrets or signatures (`==` on an HMAC).
- CWE-327, CWE-330, CWE-338

### SC-6 · Key management
- **Falsifier**: keys live in a managed KMS or secret manager, are access-controlled, are rotatable,
  and are distinct per environment.
- **EV**: key storage and retrieval (E2/E4); IAM policy on the key (E4 — see `iam-assessment.md`).
- **Traps**: one key shared across dev/staging/production (a staging compromise becomes a production
  compromise); no rotation capability designed in (rotation is impossible if the key is used to
  encrypt without a key ID); keys in environment variables of a long-lived host; encryption keys
  stored next to the data they encrypt.

### SC-7 · Token and credential exposure paths
- **Falsifier**: tokens are transmitted in headers or bodies, never in URLs; stored with appropriate
  protection; scoped and expiring.
- **Traps**: session or API tokens as query parameters; tokens in redirect URLs (leak via `Referer`);
  long-lived personal access tokens with full scope; shared service accounts with no attribution;
  credentials passed as command-line arguments (visible in the process table).

### SC-8 · Sensitive data at rest and in transit
- **Falsifier**: TLS everywhere including internal hops; encryption at rest for regulated data; field
  level encryption where the threat model requires it; PII minimised and retained per policy.
- **EV**: TLS configuration (E4); storage encryption settings (E4); the schema's sensitive columns (E2).
- **Traps**: TLS terminated at the edge with plaintext internally (state the trust assumption
  explicitly rather than assuming it is fine); backups unencrypted; database snapshots shared or
  public; PII in analytics pipelines and data warehouses that inherit none of the app's controls.

## Evidence collection

```bash
# working tree — high signal patterns; then verify each hit is real
rg -n -i -e 'sk_live_|pk_live_|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_|gho_|github_pat_' \
        -e 'xox[baprs]-|AIza[0-9A-Za-z_-]{35}|SG\.[A-Za-z0-9_-]{22}' \
        -e '-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----' \
        -e '(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*["'"'"'][^"'"'"']{8,}' \
        -g '!*.lock' -g '!node_modules'

# committed env files, now or ever
git log --all --diff-filter=A --name-only --pretty=format: | sort -u | rg -i -e '\.env|\.pem$|\.p12$|credentials|secrets?\.(ya?ml|json)'

# history scan — prefer a real tool if available
command -v gitleaks && gitleaks detect --no-banner --redact -v
command -v trufflehog && trufflehog git file://. --only-verified

# crypto
rg -n -i -e 'AES|DES|RC4|ECB|CBC|createCipher\(|Cipher\.getInstance' -A3
rg -n -e 'Math\.random|random\.random\(|rand\(\)|mt_rand|Random\(\)' -A2
rg -n -i -e 'md5|sha1\(' -A2
rg -n -e '==\s*(signature|hmac|token|digest)|(signature|hmac|token|digest)\s*==' # non-constant-time

# logging
rg -n -i -e 'log\.(info|debug|error)|logger\.|console\.log|print\(' -A2 | rg -n -i -e 'req|request|body|headers|token|password|user'
rg -n -i -e 'send_default_pii|attachStacktrace|beforeSend|scrubFields|filter_parameters'

# client bundle
[ -d dist ] || [ -d build ] || [ -d .next ] && rg -n -i -e 'sk_live|secret|private[_-]key|password' dist build .next 2>/dev/null | head -20
```

Reference: `security-audit/references/secret-scanning.md`.

## Verifying a secret candidate

Scanner output is E5. For each hit, establish **without using the credential**:

1. **Is it real?** Shape, length, checksum/prefix conventions. `AKIAIOSFODNN7EXAMPLE` is AWS's
   documentation example. `password = "changeme"` in a test fixture is not a finding.
2. **Is it live?** Ask the customer — do not authenticate with it. Ownership of the key is theirs.
3. **What is its scope?** A read-only analytics key and a production database password differ by
   several severity bands.
4. **Who could have read it?** Public repo, private repo with N collaborators, CI logs, a fork.
   This sets exposure (`X`) and drives the urgency of rotation.
5. **Is it in history?** Working-tree absence proves nothing. See SC-2.

Then report it **immediately, out of band**, before the report exists.

## Common false positives

| Looks like | Actually |
|---|---|
| A long random string | A test fixture, a public key, a hash, a UUID, a lockfile integrity digest |
| `password = "..."` | A test value, a docker-compose local default, an example in documentation |
| `AKIAIOSFODNN7EXAMPLE` | AWS's documented example key |
| A "secret" in client config | A publishable key (Stripe `pk_`, Firebase config, a Sentry DSN) — public by design |
| MD5 | Used for a cache key, ETag or checksum, not for security |
| `Math.random` | Used for a UI animation, a jitter value, or a non-security identifier |
