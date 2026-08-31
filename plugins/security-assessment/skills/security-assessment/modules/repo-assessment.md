# Module: Repository Assessment — Injection & Unsafe Sinks

> **Load when** you can read source code.
> Covers input handling and injection classes. Authorization is in `authz-assessment.md`,
> secrets in `secrets-crypto-assessment.md`.

Injection findings are where pattern matching produces the most false positives, so this module is
organised around **source → sink → control**, never around the sink alone. A dangerous function is
not a finding; a dangerous function reachable with attacker-controlled data and no effective control
is a finding.

## Method

For every candidate sink:

1. **Sink** — locate it precisely (`file:line`).
2. **Source** — is the value attacker-controlled? Trace back to a request, header, queue message,
   file, or third-party response. If it is a constant or an internal enum, stop: not a finding.
3. **Path** — is there an actual call path from an entry point? Name it.
4. **Control** — what sanitises, escapes, binds, or validates in between? Read it; do not assume.
5. **Impact** — what does control of this value achieve?

Record the path. A finding that says "SQL injection at `reports.py:88`" without the route that
reaches it will be rejected during customer triage.

## Hypothesis catalog

### RP-1 · SQL injection
- **Falsifier**: parameter binding on this call, or an allowlist for the parts that cannot be bound.
- **Traps**: `ORDER BY` / `LIMIT` / table and column names **cannot be parameter-bound**, so they are
  concatenated — the allowlist is the only control, and it is often missing. Also: ORM escape hatches
  (`raw`, `execute`, `literal`, `Sequelize.literal`, `whereRaw`, `$queryRawUnsafe`), `LIKE` patterns,
  `IN` clauses built by joining, and dynamic filter builders.
- CWE-89 · ASVS 5.3.4

### RP-2 · Command injection
- **Falsifier**: no shell invocation (`shell=False`, `execFile`/`spawn` with an argument array), and
  arguments validated against an allowlist.
- **Traps**: `shell=True`, `exec()`, `system()`, backticks, `os.popen`; a filename or URL passed to
  `ffmpeg`/`imagemagick`/`git`/`curl`; argument injection where the value cannot break out of the
  argument but *can* introduce a new flag (`--upload-file`, `--output`).
- CWE-78 · ASVS 5.3.8

### RP-3 · XSS
- **Falsifier**: context-correct output encoding at every sink, or a sanitiser with a safe
  configuration; CSP as defence in depth, never as the primary control.
- **Traps**: `dangerouslySetInnerHTML`, `v-html`, `innerHTML`, `|safe`, `raw`, `html_safe`,
  `mark_safe`; encoding correct for HTML text but wrong for an attribute, a `javascript:` URL, or a
  `<script>` block; user-controlled `href`/`src`; markdown rendered without sanitisation; SVG upload
  served inline; a JSON API response served as `text/html`.
- **Assess DOM XSS separately** in `web-assessment.md`.
- CWE-79 · ASVS 5.3.3

### RP-4 · SSRF
- **Falsifier**: destination allowlist by host, resolved-IP checks that reject private ranges and
  link-local, redirects not followed, and an egress boundary that would contain a miss.
- **Traps**: webhook URLs, "import from URL", image/PDF fetchers, URL preview generators, PDF
  renderers, and any headless-browser or SVG/XML processor. Denylists are bypassable (`0.0.0.0`,
  `[::]`, decimal IPs, DNS rebinding, `169.254.169.254`, redirect chains). **Cloud metadata access is
  the impact that turns a Medium into a Critical** — check whether IMDSv2 is enforced
  (`cloud-assessment.md`).
- CWE-918 · ASVS 5.2.6

### RP-5 · Path traversal / arbitrary file access
- **Falsifier**: canonicalise, then verify the result is inside the intended base directory; or use
  an opaque ID mapped server-side to a path.
- **Traps**: user input in a file path, archive extraction (`zip-slip`), template/include paths,
  `../` normalised before decoding (or vice versa), symlinks in uploads.
- CWE-22 · ASVS 12.3.1

### RP-6 · XXE and unsafe parsing
- **Falsifier**: external entity resolution and DTD processing disabled; a parser configured securely
  for the resolved library version.
- **Traps**: XML from any source including third parties; SVG, DOCX/XLSX, SOAP, SAML assertions;
  YAML loaded with a full (non-safe) loader; a "safe by default" parser that a wrapper re-enables.
- CWE-611 · ASVS 5.5.2

### RP-7 · Template injection
- **Falsifier**: templates are never constructed from user input; user data is passed as *context*, not
  concatenated into the template source.
- **Traps**: user-editable email/notification/report templates (a genuine feature in many SaaS
  products — this is where SSTI actually appears); Jinja2/Twig/Freemarker/Handlebars rendering a
  user-supplied string; often escalates directly to RCE.
- CWE-1336

### RP-8 · Unsafe deserialization
- **Falsifier**: only data formats without code semantics (JSON with a schema); signed and verified
  payloads where objects must be serialized.
- **Traps**: `pickle`, `yaml.load`, PHP `unserialize`, Java `ObjectInputStream`, .NET
  `BinaryFormatter`, Ruby `Marshal`, `node-serialize`; session or cache data deserialized after
  passing through a store an attacker can influence.
- CWE-502 · ASVS 5.5.1

### RP-9 · Open redirect
- **Falsifier**: redirect targets validated against a relative-path rule or a host allowlist.
- **Traps**: `?next=`, `?returnUrl=`, `?redirect_uri=` in login flows. Low alone, but it amplifies
  phishing and can break OAuth (`auth-assessment.md` AU-7).
- CWE-601

### RP-10 · Race conditions / TOCTOU
- **Falsifier**: atomic operations, database constraints, or explicit locking; idempotency keys on
  state-changing operations.
- **Traps**: check-then-act on balances, quotas, coupon redemptions, invitations; "is it available?"
  followed by "reserve it" in separate transactions; file existence checks before writes.
- **Do not test by racing production.** Read the transaction boundaries and the constraints.
  See `business-logic-assessment.md`.
- CWE-367, CWE-362

## Evidence collection

```bash
# scope the search first — a hit in tests or vendored code is not a finding
FD_EX="-E node_modules -E vendor -E dist -E build -E .git -E '*.min.js'"

# SQL
rg -n $FD_EX -e 'execute\(|executemany\(|raw\(|\.query\(|queryRaw|whereRaw|Sequelize\.literal|find_by_sql|ActiveRecord::Base\.connection' -A3
rg -n $FD_EX -e 'f"[^"]*(SELECT|INSERT|UPDATE|DELETE)' -e '"\s*\+\s*.*(SELECT|WHERE|ORDER BY)' -e '\$\{.*\}.*(SELECT|WHERE|ORDER BY)'
rg -n $FD_EX -i -e 'order_by|orderBy|sort_by|sortBy' -A3        # the un-bindable ones

# command
rg -n $FD_EX -e 'shell\s*=\s*True|os\.system|subprocess\.(call|run|Popen)|child_process|exec\(|execSync|spawnSync|`.*\$\{' -A3
# xss sinks
rg -n $FD_EX -e 'dangerouslySetInnerHTML|innerHTML|outerHTML|v-html|\|safe|mark_safe|html_safe|render_template_string|document\.write'
# ssrf
rg -n $FD_EX -e 'requests\.(get|post)|urlopen|fetch\(|axios\.|http\.(get|request)|HttpClient|net/http' -A3
# path
rg -n $FD_EX -e 'open\(|readFile|sendFile|path\.join|os\.path\.join|File\.read|ZipFile|extractall|tarfile' -A3
# parsers / deserialization
rg -n $FD_EX -e 'pickle\.loads|yaml\.load\(|Marshal\.load|unserialize|ObjectInputStream|BinaryFormatter|node-serialize'
rg -n $FD_EX -e 'etree|minidom|SAXParser|DocumentBuilder|XmlReader|libxml' -A3
# redirect
rg -n $FD_EX -i -e 'redirect\(' -A2 | rg -n -i -e 'next|return|url|param|query'
```

Then load the language- and framework-specific pattern files from the sibling skill for sinks
particular to this stack:
`security-audit/references/{nextjs,python,go,rails,rust}-security.md`.

## Verification

- **Re-read the actual file before writing any finding.** The most common LLM failure in this module
  is narrating code that is nearly, but not exactly, what is there.
- Confirm the sink is in shipped code, not tests, fixtures, examples, scripts, or vendored trees.
- Confirm the framework's escaping is genuinely bypassed at this call site, at the resolved version.
- Name the entry point. If you cannot, the candidate stays at Stage 1 of the FP pipeline.

## Common false positives

| Looks like | Actually |
|---|---|
| String-built SQL | Values are internal constants or an already-validated enum |
| `shell=True` | Arguments are static, or built from a validated allowlist |
| `innerHTML` | Content is a template literal with no interpolation, or already sanitised by DOMPurify |
| Outbound `fetch(url)` | `url` is a configured constant, not request-derived |
| `pickle.loads` | Input comes from a trusted internal cache no external party can write |
| A sink in `scripts/`, `tests/`, `examples/` | Not in the deployed artifact — **verify it is excluded from the build** |
