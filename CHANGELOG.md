# Changelog

Structural changes to this skill. Motivating engagements are referenced by engagement ID only —
never by customer name (`references/retrospective.md`).

## 2026-08-31 — initial

- Orchestrator `SKILL.md`: 11-phase loop, module routing table, publication bar, assessment stack.
- 15 modules: recon, threat-model, repo, web, api, auth, authz, business-logic, secrets-crypto,
  dependency, cloud, iam, iac, cicd, remediation-review.
- Method references: hypothesis lifecycle with a mandatory falsifier, six evidence grades,
  five-stage false-positive pipeline, T×E×B×X severity model, posture-based safety rules,
  confidence/human-review separation.
- `scripts/sa.py`: engagement workspace CLI — stack, ledgers, severity computation, publication
  gate, retrospective sanitizer. 46 tests.
- Knowledge base seeded with six detection patterns, six verification recipes, and a
  false-positive catalog.
