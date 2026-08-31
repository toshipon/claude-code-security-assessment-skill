# Knowledge Sources

**Do not copy standards into this skill.** They are long, they change, and a stale copy is worse than
a link. Retrieve when you need specifics; rely on baked-in knowledge only for orientation.

Your training data has a cutoff. CVEs, framework defaults, cloud service behaviours and OWASP
category numbering all move. **When this skill and an upstream source disagree, the source wins.**

## Priority order

| # | Source | Use for | Retrieve |
|---|---|---|---|
| 1 | **OWASP ASVS** | Requirement-level verification criteria; the best checklist for "what should exist" | https://owasp.org/www-project-application-security-verification-standard/ |
| 2 | **OWASP WSTG** | Concrete test procedures per vulnerability class | https://owasp.org/www-project-web-security-testing-guide/ |
| 3 | **OWASP API Security Top 10** | API-specific categories (API1–API10:2023) | https://owasp.org/API-Security/ |
| 4 | **CWE** | Precise weakness classification for findings | https://cwe.mitre.org/data/definitions/{id}.html |
| 5 | **NIST** SP 800-53 / 800-63 / CSF | Control framework mapping; 800-63B for authenticator requirements | https://csrc.nist.gov/ |
| 6 | **AWS / GCP / Azure security best practices** | Cloud service specifics, IAM evaluation logic | provider docs + `aws`/`gcloud`/`az` CLI |
| 7 | **Framework/library security docs** | The authoritative statement of what a default actually does | the project's own docs for the **installed version** |

Also: **CISA KEV** for "is this CVE actually being exploited", **EPSS** for exploitation probability,
and the vendor advisory (never only the NVD summary) for CVE impact.

## Companion pattern library (optional)

The `security-audit` skill holds technology-specific detection patterns
([`toshipon/claude-code-security-audit-skill`](https://github.com/toshipon/claude-code-security-audit-skill)).
It is an **optional dependency** — install it to sharpen detection, or work without it and retrieve
from the sources above. Paths below are relative to that skill's own directory, wherever it is
installed. Reuse it — do not duplicate it.

```
security-audit/references/
  nextjs-security.md      python-security.md    go-security.md       rails-security.md
  rust-security.md        supabase-security.md  vercel-security.md
  aws-security.md         gcp-security.md       azure-security.md    terraform-security.md
  cicd-security.md        container-security.md supply-chain-security.md
  secret-scanning.md      llm-security.md       web-testing.md
  ios-testing.md          android-security.md   flutter-security.md  react-native-security.md
  compliance-financial.md compliance-privacy.md best-practices-analysis.md
```

Division of responsibility: that library tells you **where to look**; this skill governs **how to
conclude**. A pattern from that library enters here as a *candidate* (grade E5) and goes through
`method-false-positive.md` like any other lead. If the skill is not installed, retrieve from the
sources above.

## Version-specific facts

Framework security behaviour is version-specific, and this is a top source of both false positives
and false negatives. Before relying on any default:

```bash
cat package.json requirements.txt go.mod Gemfile Cargo.toml 2>/dev/null   # declared
cat package-lock.json yarn.lock poetry.lock go.sum Gemfile.lock 2>/dev/null | head   # resolved
```

Then check the **resolved** version's docs and changelog — not the declared range, not the latest
release. "Django escapes template output" is true; "this Django version escapes this filter in this
context" is the question you actually need answered.

## Retrieval discipline

- Cite the URL and the retrieval date in the finding's `references`.
- Prefer the primary source over a blog summarising it.
- For CVEs: vendor advisory → NVD → KEV → EPSS. Then determine reachability yourself; the advisory
  cannot know whether the customer's code calls the affected function.
- If retrieval is unavailable, say which claims are from memory and mark them for human verification.
