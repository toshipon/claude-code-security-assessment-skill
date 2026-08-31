# Module: CI/CD Assessment

> **Load when** the repository has GitHub Actions, GitLab CI, CircleCI, Jenkins, or any deploy pipeline.

CI/CD is the shortest path from "can open a pull request" to "runs code with production credentials".
It is under-assessed because it is not the product, and it is high-impact because a compromise here
bypasses every application control at once.

**The framing that produces good findings**: treat the pipeline as an application whose *input* is a
pull request, and whose *privilege* is the deploy credential. Then ask the same questions as any
other application — who can supply input, what does it reach, and what does it run as?

## Hypothesis catalog

### CI-1 · Untrusted input reaching a privileged workflow
- **Statement**: an outside contributor's pull request causes code to run with repository secrets.
- **Falsifier**: `pull_request` (not `pull_request_target`) for untrusted PRs; no checkout of PR code
  in a privileged workflow; required approval for first-time contributors.
- **EV**: the workflow trigger, its checkout step, and its secret usage, read together (E2).
- **Traps** — the canonical CI compromise:
  - **`pull_request_target` + checking out the PR head.** This runs the fork's code with the base
    repository's secrets and a write token. If you find this combination, it is a Critical.
  - `workflow_run` triggered by an untrusted workflow, then downloading its artifacts.
  - `issue_comment` / `issues` triggers that act on comment content.
  - Self-hosted runners on public repositories: any fork's PR can execute code on the runner, and
    non-ephemeral runners retain state between jobs.
- CWE-829

### CI-2 · Script injection through workflow expressions
- **Statement**: attacker-controlled text is interpolated into a shell command by the workflow engine.
- **Falsifier**: untrusted values passed via `env:` and referenced as shell variables, never
  interpolated with `${{ }}` directly into a `run:` block.
- **EV**: every `run:` block containing `${{ github.event.* }}` (E2).
- **Traps**: `${{ github.event.issue.title }}`, `.pull_request.title`, `.body`, `.head_ref`,
  `.comment.body`, `.head.repo.description` — all attacker-controlled, all commonly interpolated.
  `${{ github.head_ref }}` is a branch name and can contain shell metacharacters.
- CWE-78

### CI-3 · Excessive workflow permissions
- **Falsifier**: `permissions:` declared explicitly at the minimum needed, ideally
  `permissions: read-all` at the top with per-job elevation.
- **Traps**: no `permissions:` key at all (inherits the repository default, historically
  read/write on everything); `permissions: write-all`; `GITHUB_TOKEN` with `contents: write` in a
  workflow that only needs to read; `id-token: write` present where OIDC is not used.

### CI-4 · Third-party actions
- **Falsifier**: actions pinned to a **full commit SHA**, from known publishers, reviewed on update.
- **EV**: every `uses:` reference (E2).
- **Traps**: `uses: some/action@v1` — a mutable tag the publisher (or anyone who compromises them)
  can repoint at new code, which then runs inside your pipeline with your secrets; `@main`; an action
  from an unmaintained or personal repository in a privileged workflow; a Docker action pulling a
  mutable image tag.
- **Severity framing**: an unpinned action in a workflow with no secrets is Low. The same in a
  deploy workflow with production credentials is High. Rate by what the workflow can reach.

### CI-5 · Secret exposure in pipelines
- **Falsifier**: secrets injected only into the steps that need them, never echoed, masked in logs,
  not passed to forks or to third-party actions unnecessarily.
- **Traps**: secrets set as workflow-level `env:` (available to every step, including third-party
  actions); `set -x` or debug logging printing them; secrets in build arguments baked into image
  layers; secrets in artifacts or test output; a secret decoded in a step (masking only matches the
  literal value, so a base64-decoded secret prints in the clear); PR workflows with access to
  production secrets when they only need test ones.

### CI-6 · OIDC configuration
- **Statement**: the cloud role a pipeline assumes can be assumed by a workflow it should not be.
- **Falsifier**: the cloud-side trust condition pins `aud` **and** an exact `sub` — repo, and branch
  or environment.
- **EV**: the cloud role's trust policy (E4) read together with the workflow (E2). **Both sides are
  required** — the workflow alone cannot show this, which is why it is so often missed.
- See `iam-assessment.md` IM-4 for the exact trap patterns. This is a high-severity, frequently-wrong
  configuration and worth checking explicitly on every engagement that has OIDC.

### CI-7 · Branch protection and review integrity
- **Falsifier**: protected default branch, required review from someone other than the author,
  required status checks, no force-push, admin included in the rules.
- **Traps**: protection on `main` but the deploy workflow triggers from any branch or tag; tags
  unprotected while the release pipeline builds from them; bots able to self-approve; `CODEOWNERS`
  not required; the deploy environment lacking required reviewers.
- **EV**: branch protection settings (E4) — needs repository admin access; if unavailable, register
  an UNKNOWN with the exact setting to check rather than assuming.

### CI-8 · Artifact and deployment integrity
- **Falsifier**: builds produce attested, immutable artifacts; deployments reference digests rather
  than mutable tags; the registry is access-controlled.
- **Traps**: deploying `:latest`; a registry allowing overwrite of an existing tag; no signing or
  provenance; the deploy job pulling a build artifact from an untrusted workflow run;
  `curl … | bash` in a build step (fetching mutable remote code into the pipeline).

### CI-9 · Runner and environment isolation
- **Traps**: self-hosted runners shared across repositories or trust levels; non-ephemeral runners
  retaining credentials and caches between jobs; runners with cloud instance profiles broader than
  the pipeline needs (the workload can call the metadata service and inherit them); caches poisoned
  from a PR branch and restored into a trusted build.

## Evidence collection

```bash
fd -g '*.yml' -g '*.yaml' .github/workflows .gitlab-ci.yml .circleci 2>/dev/null

# the critical trigger/checkout combination
rg -n -B2 -A15 -e 'pull_request_target|workflow_run|issue_comment' .github/workflows/
# script injection
rg -n -e 'run:' -A6 .github/workflows/ | rg -n -e '\$\{\{\s*github\.event\.'
rg -n -e '\$\{\{\s*(github\.head_ref|github\.event\.(issue|pull_request|comment)\.)' .github/workflows/
# permissions and secrets
rg -n -e 'permissions:' -A6 .github/workflows/
rg -n -e 'secrets\.|env:' -A4 .github/workflows/
# unpinned actions — a SHA is 40 hex chars
rg -n -e 'uses:\s*[^ ]+@' .github/workflows/ | rg -v -e '@[0-9a-f]{40}'
# oidc
rg -n -e 'id-token:\s*write|configure-aws-credentials|google-github-actions/auth|azure/login' -A6 .github/workflows/
# self-hosted runners and remote code
rg -n -e 'runs-on:.*self-hosted' .github/workflows/
rg -n -e 'curl.*\|\s*(ba)?sh|wget.*\|\s*(ba)?sh' .github/workflows/
```

Reference: `security-audit/references/cicd-security.md`.

## Verification

- Read trigger, checkout and secret usage **as one unit**. Each is harmless alone; the combination is
  the vulnerability, and reading them separately is why this class gets missed.
- Determine whether the repository is public or accepts outside contributions. `pull_request_target`
  in a private repository with no external contributors is a latent risk, not an active one — say so
  and rate it accordingly rather than reporting a Critical that the customer will dismiss.
- For OIDC, you must read the cloud side. Without it, register an UNKNOWN naming the exact trust
  policy to retrieve.

## Common false positives

| Looks like | Actually |
|---|---|
| `pull_request_target` | Used without checking out PR code — the safe pattern for labelling and triage bots |
| Unpinned action | First-party (`actions/checkout@v4`) in a workflow with no secrets — Low, still worth pinning |
| A secret in a workflow | A test/staging credential with no production reach — verify its scope |
| No `permissions:` | The organization default is already restricted — verify at the org level |
| Self-hosted runner | Private repository, no outside contributors, ephemeral runners |
