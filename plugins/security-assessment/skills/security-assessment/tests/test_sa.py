"""Tests for the security-assessment engagement CLI (sa.py).

Red-first: these encode the guarantees the skill depends on. If a guarantee here
regresses, findings stop being trustworthy.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SA = Path(__file__).resolve().parent.parent / "scripts" / "sa.py"


class SaTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"

    def tearDown(self):
        self._tmp.cleanup()

    def sa(self, *args, expect_ok=True):
        proc = subprocess.run(
            [sys.executable, str(SA), "--workspace", str(self.ws), *args],
            capture_output=True, text=True,
        )
        if expect_ok:
            self.assertEqual(proc.returncode, 0, f"expected success:\n{proc.stdout}\n{proc.stderr}")
        return proc

    def init(self, name="acme-assessment"):
        proc = subprocess.run(
            [sys.executable, str(SA), "--workspace", str(self.ws), "init", "--name", name],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc

    def jsonl(self, name):
        p = self.ws / name
        if not p.exists():
            return []
        return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


class TestInit(SaTestCase):
    def test_init_creates_workspace_layout(self):
        self.init()
        for f in ("engagement.json", "stack.json", "coverage.json"):
            self.assertTrue((self.ws / f).exists(), f"missing {f}")
        self.assertTrue((self.ws / "evidence").is_dir())
        self.assertTrue((self.ws / "reports").is_dir())

    def test_init_defaults_to_passive_posture(self):
        self.init()
        eng = json.loads((self.ws / "engagement.json").read_text())
        self.assertEqual(eng["posture"], "passive")
        self.assertIsNone(eng["authorization"])

    def test_init_is_idempotent(self):
        self.init()
        self.init()  # must not raise or wipe state


class TestStack(SaTestCase):
    def test_push_pop_dump(self):
        self.init()
        out = self.sa("stack", "push", "--kind", "hypothesis", "--ref", "H-001").stdout
        frame = out.strip().split()[-1]
        self.assertIn(frame, self.sa("stack", "dump").stdout)
        self.sa("stack", "pop", frame, "--outcome", "refuted")
        self.assertNotIn(frame, self.sa("stack", "dump").stdout)

    def test_pop_requires_outcome(self):
        self.init()
        frame = self.sa("stack", "push", "--kind", "surface", "--ref", "AS-01").stdout.strip().split()[-1]
        proc = self.sa("stack", "pop", frame, expect_ok=False)
        self.assertNotEqual(proc.returncode, 0)

    def test_dump_reports_empty_stack(self):
        self.init()
        self.assertIn("no open frames", self.sa("stack", "dump").stdout.lower())


class TestSeverity(SaTestCase):
    """score = 0.35T + 0.25E + 0.25B + 0.15X"""

    def rate(self, t, e, b, x):
        self.init()
        self.sa("finding", "new", "--title", "t", "--module", "authz", "--cwe", "CWE-639", "--owasp", "API1:2023")
        self.sa("finding", "rate", "F-001", "--T", str(t), "--E", str(e), "--B", str(b), "--X", str(x),
                "--rationale", "traced end to end from a public endpoint")
        return self.jsonl("findings.jsonl")[-1]

    def test_max_vector_is_critical(self):
        f = self.rate(4, 4, 4, 4)
        self.assertAlmostEqual(f["severity_score"], 4.0, places=2)
        self.assertEqual(f["severity"], "Critical")

    def test_min_vector_is_informational(self):
        f = self.rate(1, 1, 1, 1)
        self.assertAlmostEqual(f["severity_score"], 1.0, places=2)
        self.assertEqual(f["severity"], "Informational")

    def test_mid_vector_is_medium(self):
        f = self.rate(2, 2, 2, 2)
        self.assertAlmostEqual(f["severity_score"], 2.0, places=2)
        self.assertEqual(f["severity"], "Medium")

    def test_high_band(self):
        f = self.rate(4, 2, 4, 3)  # 1.4 + .5 + 1.0 + .45 = 3.35
        self.assertAlmostEqual(f["severity_score"], 3.35, places=2)
        self.assertEqual(f["severity"], "High")

    def test_factors_are_stored_for_audit(self):
        f = self.rate(4, 3, 4, 4)
        self.assertEqual(f["severity_factors"], {"T": 4, "E": 3, "B": 4, "X": 4})

    def test_factor_out_of_range_is_rejected(self):
        self.init()
        self.sa("finding", "new", "--title", "t", "--module", "authz", "--cwe", "CWE-1", "--owasp", "A01")
        proc = self.sa("finding", "rate", "F-001", "--T", "5", "--E", "1", "--B", "1", "--X", "1",
                       "--rationale", "r", expect_ok=False)
        self.assertNotEqual(proc.returncode, 0)

    def test_override_limited_to_one_band(self):
        self.init()
        self.sa("finding", "new", "--title", "t", "--module", "authz", "--cwe", "CWE-1", "--owasp", "A01")
        # computed Informational (1.0); overriding to Critical skips three bands
        proc = self.sa("finding", "rate", "F-001", "--T", "1", "--E", "1", "--B", "1", "--X", "1",
                       "--rationale", "r", "--override", "Critical",
                       "--override-reason", "fintech payment flow", expect_ok=False)
        self.assertNotEqual(proc.returncode, 0)

    def test_override_one_band_allowed_with_reason(self):
        self.init()
        self.sa("finding", "new", "--title", "t", "--module", "authz", "--cwe", "CWE-1", "--owasp", "A01")
        self.sa("finding", "rate", "F-001", "--T", "2", "--E", "2", "--B", "2", "--X", "2",
                "--rationale", "r", "--override", "High", "--override-reason", "sits on the payment flow")
        self.assertEqual(self.jsonl("findings.jsonl")[-1]["severity"], "High")

    def test_override_requires_reason(self):
        self.init()
        self.sa("finding", "new", "--title", "t", "--module", "authz", "--cwe", "CWE-1", "--owasp", "A01")
        proc = self.sa("finding", "rate", "F-001", "--T", "2", "--E", "2", "--B", "2", "--X", "2",
                       "--rationale", "r", "--override", "High", expect_ok=False)
        self.assertNotEqual(proc.returncode, 0)


class ValidateMixin(SaTestCase):
    def make_finding(self, **kw):
        """A finding that passes validate, so each test can break exactly one rule."""
        self.init()
        self.sa("evidence", "add", "--grade", "E2", "--kind", "code",
                "--locator", "src/api/invoices.ts:41-78",
                "--summary", "no tenant predicate on the invoice query")
        self.sa("finding", "new", "--title", "Cross-tenant invoice read",
                "--module", "authz", "--cwe", "CWE-639", "--owasp", "API1:2023")
        self.sa("finding", "rate", "F-001", "--T", "4", "--E", "3", "--B", "4", "--X", "4",
                "--rationale", "traced from a public endpoint to the query with no predicate")
        args = {
            "confidence": "CONFIRMED", "ai-confidence": "High",
            "attack-scenario": "authenticated user substitutes an invoice id and receives another tenant's invoice",
            "entry-point": "GET /api/v1/invoices/:id", "attacker-profile": "authenticated user",
            "impact": "any customer can read any other customer's billing records",
            "likelihood": "ids are sequential and trivially enumerable",
            "evidence": "EV-001", "remediation": "scope the query by the session tenant",
            "verification": "cross-tenant id must return 403",
        }
        args.update(kw)
        flat = []
        for k, v in args.items():
            if v is not None:
                flat += [f"--{k}", v]
        self.sa("finding", "set", "F-001", *flat)
        self.sa("finding", "control", "F-001", "--layer", "middleware",
                "--locator", "src/app.ts:34-52", "--result", "authn only, no authz")


class TestValidate(ValidateMixin):
    def test_complete_finding_passes(self):
        self.make_finding()
        proc = self.sa("validate")
        self.assertIn("PASS", proc.stdout.upper())

    def test_finding_without_evidence_fails(self):
        self.make_finding(evidence=None)
        proc = self.sa("validate", expect_ok=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("evidence", proc.stdout.lower() + proc.stderr.lower())

    def test_critical_requires_e1_or_e2_evidence(self):
        self.init()
        self.sa("evidence", "add", "--grade", "E5", "--kind", "tool",
                "--locator", "semgrep", "--summary", "sqli rule hit")
        self.sa("finding", "new", "--title", "t", "--module", "repo", "--cwe", "CWE-89", "--owasp", "A03")
        self.sa("finding", "rate", "F-001", "--T", "4", "--E", "4", "--B", "4", "--X", "4", "--rationale", "r")
        self.sa("finding", "set", "F-001", "--confidence", "SUSPECTED", "--ai-confidence", "Low",
                "--attack-scenario", "s", "--entry-point", "e", "--attacker-profile", "a",
                "--impact", "i", "--likelihood", "l", "--evidence", "EV-001",
                "--remediation", "r", "--verification", "v")
        self.sa("finding", "control", "F-001", "--layer", "orm", "--locator", "x", "--result", "none")
        proc = self.sa("validate", expect_ok=False)
        self.assertIn("E1", proc.stdout + proc.stderr)

    def test_confirmed_with_open_unknown_on_path_fails(self):
        self.make_finding()
        self.sa("unknown", "add", "--question", "is /api reachable externally?",
                "--resolve-by", "customer shares ALB rules")
        self.sa("finding", "set", "F-001", "--unknowns", "U-001")
        proc = self.sa("validate", expect_ok=False)
        self.assertIn("U-001", proc.stdout + proc.stderr)

    def test_resolved_unknown_does_not_block(self):
        self.make_finding()
        self.sa("unknown", "add", "--question", "q", "--resolve-by", "r")
        self.sa("finding", "set", "F-001", "--unknowns", "U-001")
        self.sa("unknown", "resolve", "U-001", "--answer", "yes, internet reachable")
        self.sa("validate")

    def test_tool_rating_as_severity_rationale_fails(self):
        self.make_finding()
        self.sa("finding", "rate", "F-001", "--T", "4", "--E", "3", "--B", "4", "--X", "4",
                "--rationale", "Semgrep rated this CRITICAL")
        proc = self.sa("validate", expect_ok=False)
        self.assertIn("rationale", (proc.stdout + proc.stderr).lower())

    def test_missing_controls_checked_fails(self):
        self.init()
        self.sa("evidence", "add", "--grade", "E2", "--kind", "code", "--locator", "a:1", "--summary", "s")
        self.sa("finding", "new", "--title", "t", "--module", "authz", "--cwe", "CWE-1", "--owasp", "A01")
        self.sa("finding", "rate", "F-001", "--T", "2", "--E", "2", "--B", "2", "--X", "2", "--rationale", "r")
        self.sa("finding", "set", "F-001", "--confidence", "SUSPECTED", "--ai-confidence", "Medium",
                "--ai-confidence-reason", "one link inferred",
                "--attack-scenario", "s", "--entry-point", "e", "--attacker-profile", "a",
                "--impact", "i", "--likelihood", "l", "--evidence", "EV-001",
                "--remediation", "r", "--verification", "v")
        proc = self.sa("validate", expect_ok=False)
        self.assertIn("control", (proc.stdout + proc.stderr).lower())

    def test_ai_confidence_below_high_requires_reason(self):
        self.make_finding(**{"ai-confidence": "Medium"})
        proc = self.sa("validate", expect_ok=False)
        self.assertIn("ai_confidence", (proc.stdout + proc.stderr).lower())

    def test_needs_verification_caps_at_high(self):
        self.make_finding(**{"confidence": "NEEDS-VERIFICATION", "ai-confidence": "Low",
                             "ai-confidence-reason": "no runtime access"})
        proc = self.sa("validate", expect_ok=False)
        self.assertIn("NEEDS-VERIFICATION", proc.stdout + proc.stderr)

    def test_human_review_auto_flagged_for_critical(self):
        self.make_finding()
        self.assertTrue(self.jsonl("findings.jsonl")[-1]["human_review_required"])

    def test_human_review_auto_flagged_for_sensitive_module(self):
        self.init()
        self.sa("finding", "new", "--title", "t", "--module", "business-logic",
                "--cwe", "CWE-840", "--owasp", "A04")
        self.sa("finding", "rate", "F-001", "--T", "1", "--E", "1", "--B", "1", "--X", "1", "--rationale", "r")
        self.assertTrue(self.jsonl("findings.jsonl")[-1]["human_review_required"])

    def test_secret_in_evidence_artifact_fails_validate(self):
        self.make_finding()
        (self.ws / "evidence" / "leak.txt").write_text("aws_key = AKIAIOSFODNN7REALKEY1\n")
        proc = self.sa("validate", expect_ok=False)
        self.assertIn("secret", (proc.stdout + proc.stderr).lower())

    def test_validate_reports_open_stack_frames(self):
        self.make_finding()
        self.sa("stack", "push", "--kind", "hypothesis", "--ref", "H-009")
        proc = self.sa("validate", expect_ok=False)
        self.assertIn("open frame", (proc.stdout + proc.stderr).lower())


class TestHypothesisAndCandidate(SaTestCase):
    def test_hypothesis_requires_falsifier(self):
        self.init()
        proc = self.sa("hypothesis", "add", "--surface", "AS-01", "--statement", "s",
                       "--module", "authz", expect_ok=False)
        self.assertNotEqual(proc.returncode, 0)

    def test_hypothesis_lifecycle(self):
        self.init()
        self.sa("hypothesis", "add", "--surface", "AS-01", "--statement", "s",
                "--falsifier", "tenant predicate on every path", "--module", "authz")
        self.sa("hypothesis", "refute", "H-001", "--note", "RLS covers it")
        self.assertEqual(self.jsonl("hypotheses.jsonl")[-1]["status"], "REFUTED")

    def test_candidate_kill_requires_reason(self):
        self.init()
        self.sa("candidate", "add", "--source", "semgrep", "--raw", "sqli", "--module", "repo")
        proc = self.sa("candidate", "kill", "C-001", "--stage", "controls", expect_ok=False)
        self.assertNotEqual(proc.returncode, 0)

    def test_killed_candidate_records_stage_and_reason(self):
        self.init()
        self.sa("candidate", "add", "--source", "semgrep", "--raw", "sqli", "--module", "repo")
        self.sa("candidate", "kill", "C-001", "--stage", "controls", "--reason", "parameterised at db.py:20")
        c = self.jsonl("candidates.jsonl")[-1]
        self.assertEqual(c["status"], "killed")
        self.assertEqual(c["killed_at_stage"], "controls")

    def test_candidate_promote_creates_finding(self):
        self.init()
        self.sa("candidate", "add", "--source", "manual", "--raw", "idor", "--module", "authz")
        self.sa("candidate", "promote", "C-001", "--finding-title", "IDOR on invoices",
                "--cwe", "CWE-639", "--owasp", "API1:2023")
        findings = self.jsonl("findings.jsonl")
        self.assertEqual(findings[-1]["candidate_id"], "C-001")


class TestScopeAndSafety(SaTestCase):
    def test_authorize_records_who_and_ref(self):
        self.init()
        self.sa("scope", "authorize", "--by", "CTO", "--ref", "SOW-2026-014", "--posture", "active-safe")
        eng = json.loads((self.ws / "engagement.json").read_text())
        self.assertEqual(eng["posture"], "active-safe")
        self.assertEqual(eng["authorization"]["by"], "CTO")

    def test_intrusive_posture_requires_authorization(self):
        self.init()
        proc = self.sa("scope", "set", "--posture", "intrusive", expect_ok=False)
        self.assertNotEqual(proc.returncode, 0)

    def test_e1_evidence_rejected_under_passive_posture(self):
        self.init()
        proc = self.sa("evidence", "add", "--grade", "E1", "--kind", "runtime",
                       "--locator", "GET /x", "--summary", "returned another tenant record",
                       expect_ok=False)
        self.assertIn("posture", (proc.stdout + proc.stderr).lower())

    def test_e1_evidence_allowed_once_authorized(self):
        self.init()
        self.sa("scope", "authorize", "--by", "CTO", "--ref", "SOW-1", "--posture", "active-safe")
        self.sa("evidence", "add", "--grade", "E1", "--kind", "runtime",
                "--locator", "GET /x", "--summary", "observed")


class TestCoverageAndReports(ValidateMixin):
    def test_report_includes_coverage_section(self):
        self.make_finding()
        self.sa("surface", "add", "--id", "AS-01", "--entry", "GET /api/v1/invoices/:id",
                "--exposure", "internet", "--priority", "high")
        self.sa("coverage", "set", "--surface", "AS-01", "--state", "assessed")
        self.sa("report", "technical")
        text = (self.ws / "reports" / "technical.md").read_text()
        self.assertIn("Coverage", text)
        self.assertIn("F-001", text)

    def test_not_assessed_surface_requires_reason(self):
        self.init()
        self.sa("surface", "add", "--id", "AS-02", "--entry", "GET /internal", "--exposure", "unknown")
        proc = self.sa("coverage", "set", "--surface", "AS-02", "--state", "not-assessed", expect_ok=False)
        self.assertNotEqual(proc.returncode, 0)

    def test_executive_summary_lists_unassessed_areas(self):
        self.make_finding()
        self.sa("surface", "add", "--id", "AS-02", "--entry", "GET /internal", "--exposure", "unknown")
        self.sa("coverage", "set", "--surface", "AS-02", "--state", "not-assessed",
                "--reason", "no access to the internal network")
        self.sa("report", "executive")
        text = (self.ws / "reports" / "executive.md").read_text()
        self.assertIn("AS-02", text)
        self.assertIn("no access to the internal network", text)

    def test_remediation_plan_buckets_by_urgency(self):
        self.make_finding()
        self.sa("report", "remediation")
        text = (self.ws / "reports" / "remediation-plan.md").read_text()
        for bucket in ("Immediate", "7 days", "30 days", "90 days"):
            self.assertIn(bucket, text)

    def test_status_reports_counts(self):
        self.make_finding()
        out = self.sa("status").stdout
        self.assertIn("findings", out.lower())


class TestRetroSanitizer(SaTestCase):
    def test_promotion_blocks_customer_name(self):
        self.init(name="Acme Financial")
        self.sa("scope", "set", "--customer", "Acme Financial", "--in-scope", "repo:acme/api")
        self.sa("retro", "add", "--kind", "detection-pattern",
                "--text", "Acme Financial's OrderService bypassed the repository tenant scope")
        proc = self.sa("retro", "promote", "--entry", "R-001", "--target", "detection-patterns",
                       "--approved-by", "lead", expect_ok=False)
        self.assertIn("sanitiz", (proc.stdout + proc.stderr).lower())

    def test_promotion_blocks_domains_and_ips(self):
        self.init()
        self.sa("retro", "add", "--kind", "detection-pattern",
                "--text", "check api.customer-prod.co.jp and 10.0.4.17 for the bypass")
        proc = self.sa("retro", "promote", "--entry", "R-001", "--target", "detection-patterns",
                       "--approved-by", "lead", expect_ok=False)
        self.assertNotEqual(proc.returncode, 0)

    def test_promotion_requires_human_approval(self):
        self.init()
        self.sa("retro", "add", "--kind", "detection-pattern", "--text", "generic reusable lesson")
        proc = self.sa("retro", "promote", "--entry", "R-001", "--target", "detection-patterns",
                       expect_ok=False)
        self.assertIn("approv", (proc.stdout + proc.stderr).lower())

    def test_clean_generalized_entry_promotes(self):
        self.init()
        self.sa("retro", "add", "--kind", "detection-pattern",
                "--text", "Where tenant scoping lives in a repository layer, service methods that "
                          "call the ORM directly bypass it; enumerate every caller of the raw handle.")
        proc = self.sa("retro", "promote", "--entry", "R-001", "--target", "detection-patterns",
                       "--approved-by", "lead")
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
