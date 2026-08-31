# Module: Dependency Assessment

> **Load when** the project has package manifests or lockfiles.
> **This module is dominated by false positives.** Scanner output is E5 and means only "a CVE exists
> in a version you have installed" — never "you are vulnerable".

Customers can run `npm audit` themselves. The value you add is **reachability**: which of the 200
alerts actually matter for this application. A dependency report that reproduces the scanner's
output has negative value, because it buries the two that matter.

## Hypothesis catalog

### DP-1 · Reachable known vulnerability
- **Statement**: a known-vulnerable code path in a dependency is reachable with attacker-controlled input.
- **Falsifier**: the vulnerable function is never called, or is called only with trusted input, or a
  configuration disables the affected feature.
- **EV**: the advisory's affected function/feature (E4 from the vendor advisory), plus a call-path
  trace in this codebase (E2).
- **Method**: for each CVE, read the advisory to learn **which function or feature is affected**, then
  grep for its use. Most alerts die here — and the surviving few are the deliverable.
- CWE-1395

### DP-2 · Direct vs. transitive
- Direct dependencies are upgradable by the customer today; transitive ones need the intermediate
  package to move. The remediation differs completely, so classify every finding.
- For a transitive vulnerability with no upstream fix: overrides/`resolutions`, a patch
  (`patch-package`, `pnpm patch`), or removing the parent. State which applies.

### DP-3 · Unmaintained / unsupported dependencies
- **Statement**: a dependency will not receive a security fix when one is needed.
- **EV**: last release date, archived status, single-maintainer status, open security issues (E4).
- Includes the **runtime**: an EOL Node/Python/Ruby/PHP/Java version receives no security patches at
  all, which is usually a bigger finding than anything in the package list.
- **Traps**: a package that looks alive because of dependency-bump commits but has had no real
  maintenance in two years.

### DP-4 · Supply-chain risk
- **Statement**: an attacker can get code into the build.
- **Falsifier**: lockfiles committed and enforced (`npm ci`, `--frozen-lockfile`), integrity hashes
  present, internal packages scoped and the registry pinned, install scripts understood.
- **Traps**: **dependency confusion** — an internal package name that is unclaimed on the public
  registry, with a resolver that prefers the public one; typosquats; a package added recently by an
  unfamiliar author; `postinstall` scripts; git or URL dependencies pointing at a mutable ref; a
  private registry configured without `always-auth`.
- CWE-1357

### DP-5 · Lockfile integrity
- **Statement**: what gets installed is not what was reviewed.
- **Falsifier**: lockfile committed, in sync with the manifest, with integrity hashes, and CI installs
  from it.
- **Traps**: lockfile missing or gitignored; CI running `npm install` (which mutates it) instead of
  `npm ci`; manifest and lockfile out of sync; multiple lockfiles from different package managers;
  a `resolved` URL pointing at a non-default registry.

### DP-6 · Suspicious packages
- Signals worth investigating, none conclusive alone: recently published with a version number
  implying maturity; a name one character from a popular package; an install script that fetches
  remote content; obfuscated or minified source in a source package; a maintainer change immediately
  followed by a release; network or filesystem access unrelated to the package's purpose.
- **Any real hit here is Critical and reported out of band immediately.**

### DP-7 · License and provenance
- Out of security scope unless the customer asked, but note copyleft obligations and packages with no
  license if you see them. Provenance (npm attestations, Sigstore) is a positive control worth noting.

## Evidence collection

```bash
# resolved versions — the manifest range is not what is installed
fd -g 'package-lock.json' -g 'yarn.lock' -g 'pnpm-lock.yaml' -g 'poetry.lock' -g 'Pipfile.lock' \
   -g 'Gemfile.lock' -g 'go.sum' -g 'Cargo.lock' -g 'composer.lock' -g '*.csproj'

# advisories (each hit is a CANDIDATE, grade E5)
npm audit --json 2>/dev/null | head -c 4000
pip-audit -f json 2>/dev/null || safety check --json 2>/dev/null
bundle audit check --update 2>/dev/null
govulncheck ./... 2>/dev/null          # Go's is reachability-aware — its output is stronger than E5
cargo audit --json 2>/dev/null
osv-scanner --format json -r . 2>/dev/null

# runtime EOL
cat .nvmrc .node-version .python-version .ruby-version 2>/dev/null
rg -n -e '"node"|"engines"|python_requires|^ruby |^go [0-9]' package.json setup.py pyproject.toml Gemfile go.mod 2>/dev/null

# supply chain
rg -n -e '"postinstall"|"preinstall"|"prepare"' package.json
rg -n -e 'git\+https|github:|file:|http://' package.json requirements.txt Gemfile
rg -n -e '"@[a-z0-9-]+/' package.json | head           # internal scopes → check they are claimed publicly
cat .npmrc 2>/dev/null; cat pip.conf 2>/dev/null       # registry config
git log --oneline -5 -- package-lock.json yarn.lock pnpm-lock.yaml
```

Reference: `security-audit/references/supply-chain-security.md`.

## Triage — mandatory for every alert

Do not pass scanner output through to the report. For each alert:

| Step | Question | Kills the alert? |
|---|---|---|
| 1 | Is the package in the **production** dependency tree, or only `devDependencies`/test? | Yes — dev-only is Low at most, unless the CI threat model matters (see `cicd-assessment.md`) |
| 2 | Which function or feature does the advisory affect? | — read the vendor advisory, not the NVD summary |
| 3 | Does this codebase call it? | Yes — unreachable |
| 4 | Is attacker-controlled input reaching it? | Yes — no taint, no finding |
| 5 | Does a configuration or a wrapper mitigate it? | Downgrade |
| 6 | KEV listed? EPSS score? | Raises `E` — actively exploited moves it up sharply |

Then group the survivors. "Upgrade `lodash` to 4.17.21" is one action, not seven findings.

## Reporting shape

Report **actions**, not alerts. Customers act on upgrades:

| Action | Fixes | Severity | Breaking? |
|---|---|---|---|
| `next` 13.4.1 → 13.5.6 | CVE-…-x (SSRF, reachable via image optimizer at `next.config.js:12`) | High | patch |
| Node 16 → 20 | EOL runtime, unpatched since 2023-09 | High | major |
| `lodash` 4.17.15 → 4.17.21 | 3 CVEs, none reachable | Low | patch |

Include the unreachable ones at Low — the customer should still patch, and listing them shows the
work was done — but never let them set the headline severity.

## Common false positives

| Looks like | Actually |
|---|---|
| Critical CVE in a package | The vulnerable function is never called |
| A vulnerable transitive dep | Only reachable through a code path this app does not use |
| A CVE in `devDependencies` | Not in the production artifact — Low unless the build pipeline is in scope |
| A ReDoS advisory | The regex is applied to bounded, internal input |
| A prototype-pollution advisory | No user-controlled object merge in this application |
| "Package unmaintained" | Small, complete, stable package with no attack surface (a leftpad-shaped one) |
