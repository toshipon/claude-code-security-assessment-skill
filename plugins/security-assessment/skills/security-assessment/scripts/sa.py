#!/usr/bin/env python3
"""sa — engagement workspace CLI for the security-assessment skill.

Holds the deterministic parts of a hypothesis-driven security assessment: the
assessment stack, the hypothesis/candidate/evidence/finding ledgers, the severity
computation, the publication gate, and the retrospective sanitizer.

The agent does the thinking; this tool makes the bookkeeping reproducible and
enforces the rules that keep findings trustworthy.

Python 3.8+, standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------- model

BANDS = ["Informational", "Low", "Medium", "High", "Critical"]
BAND_FLOOR = [("Critical", 3.50), ("High", 2.80), ("Medium", 2.00), ("Low", 1.40)]
WEIGHTS = {"T": 0.35, "E": 0.25, "B": 0.25, "X": 0.15}

POSTURES = ["passive", "active-safe", "intrusive"]
GRADES = ["E1", "E2", "E3", "E4", "E5", "E6"]
CONFIDENCE = ["CONFIRMED", "SUSPECTED", "NEEDS-VERIFICATION"]
AI_CONFIDENCE = ["High", "Medium", "Low"]

# Findings in these areas always need a human reviewer — see
# references/method-human-review.md.
HUMAN_REVIEW_MODULES = {
    "authz", "auth", "business-logic", "cloud", "iam", "secrets-crypto", "crypto",
}

LEDGERS = {
    "unknown": ("unknowns.jsonl", "U"),
    "hypothesis": ("hypotheses.jsonl", "H"),
    "candidate": ("candidates.jsonl", "C"),
    "evidence": ("evidence.jsonl", "EV"),
    "finding": ("findings.jsonl", "F"),
    "surface": ("surfaces.jsonl", "AS"),
    "retro": ("retro.jsonl", "R"),
}

SCANNER_NAMES = [
    "semgrep", "codeql", "snyk", "dependabot", "trivy", "checkov", "tfsec",
    "gitleaks", "trufflehog", "npm audit", "sonarqube", "burp", "zap", "nessus",
    "prowler", "scoutsuite", "scanner", "osv-scanner", "bandit", "brakeman",
]
SEVERITY_WORDS = ["critical", "high", "medium", "low", "severe"]

# Credential shapes. Deliberately narrow: a noisy gate gets disabled, and a
# disabled gate protects nobody.
SECRET_PATTERNS = [
    # No trailing \b: detection should stay permissive when a key is embedded in a
    # longer token. A missed credential costs far more than an extra manual check.
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}"), "Stripe live key"),
    (re.compile(r"\bgh[pousr]_[0-9A-Za-z]{30,}"), "GitHub token"),
    (re.compile(r"\bgithub_pat_[0-9A-Za-z_]{50,}"), "GitHub fine-grained token"),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"), "Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"), "SendGrid key"),
]
# Values published by vendors as documentation examples.
SECRET_ALLOWLIST = re.compile(r"AKIAIOSFODNN7EXAMPLE|EXAMPLEKEY|sk_live_EXAMPLE", re.I)

DOMAIN_RE = re.compile(
    r"\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+"
    r"\.(?:com|net|org|io|jp|co|dev|ai|cloud|app|internal|local|xyz|sh|me)\b", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
ARN_RE = re.compile(r"\barn:aws[\w-]*:[\w-]+:[\w-]*:\d{0,12}:", re.I)
ACCOUNT_RE = re.compile(r"\b\d{12}\b")
REPO_RE = re.compile(r"\b(?:repo|github\.com)[:/][\w.-]+/[\w.-]+\b", re.I)


class SaError(Exception):
    """A rule was violated. Message goes to stderr; exit code 1."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ----------------------------------------------------------------------- workspace


class Workspace:
    def __init__(self, root: Path):
        self.root = Path(root)

    # -- files

    @property
    def engagement_path(self) -> Path:
        return self.root / "engagement.json"

    @property
    def stack_path(self) -> Path:
        return self.root / "stack.json"

    @property
    def coverage_path(self) -> Path:
        return self.root / "coverage.json"

    def require(self) -> None:
        if not self.engagement_path.exists():
            raise SaError(f"no engagement workspace at {self.root} — run `sa init` first")

    # -- json helpers

    def read_json(self, path: Path, default):
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))

    def write_json(self, path: Path, data) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # -- ledgers (rewrite-in-place so a record has exactly one current state)

    def ledger_path(self, kind: str) -> Path:
        return self.root / LEDGERS[kind][0]

    def load(self, kind: str) -> list:
        path = self.ledger_path(kind)
        if not path.exists():
            return []
        return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]

    def save(self, kind: str, records: list) -> None:
        path = self.ledger_path(kind)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records), encoding="utf-8")

    def next_id(self, kind: str) -> str:
        prefix = LEDGERS[kind][1]
        return f"{prefix}-{len(self.load(kind)) + 1:03d}"

    def append(self, kind: str, record: dict) -> dict:
        records = self.load(kind)
        records.append(record)
        self.save(kind, records)
        return record

    def get(self, kind: str, rid: str) -> dict:
        for r in self.load(kind):
            if r["id"] == rid:
                return r
        raise SaError(f"{rid} not found in {LEDGERS[kind][0]}")

    def update(self, kind: str, rid: str, **changes) -> dict:
        records = self.load(kind)
        for r in records:
            if r["id"] == rid:
                r.update(changes)
                r["updated_at"] = now()
                self.save(kind, records)
                return r
        raise SaError(f"{rid} not found in {LEDGERS[kind][0]}")

    # -- engagement

    def engagement(self) -> dict:
        self.require()
        return self.read_json(self.engagement_path, {})

    def posture(self) -> str:
        return self.engagement().get("posture", "passive")


# ------------------------------------------------------------------------ severity


def compute_severity(t: int, e: int, b: int, x: int) -> tuple:
    for name, value in (("T", t), ("E", e), ("B", b), ("X", x)):
        if not isinstance(value, int) or not 1 <= value <= 4:
            raise SaError(f"severity factor {name} must be an integer 1-4, got {value!r}")
    score = round(WEIGHTS["T"] * t + WEIGHTS["E"] * e + WEIGHTS["B"] * b + WEIGHTS["X"] * x, 4)
    band = "Informational"
    for name, floor in BAND_FLOOR:
        if score >= floor:
            band = name
            break
    return score, band


def looks_like_tool_attribution(rationale: str) -> bool:
    """A rationale that only relays a scanner's verdict is not a rationale.

    Heuristic: a tool name plus a severity word, with too few words to carry any
    reasoning of its own. See references/method-severity.md guardrail 3.
    """
    low = rationale.lower()
    has_tool = any(t in low for t in SCANNER_NAMES)
    has_severity = any(w in low for w in SEVERITY_WORDS)
    return has_tool and has_severity and len(rationale.split()) < 15


def scan_secrets(root: Path) -> list:
    hits = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "engagement.json":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern, label in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                if SECRET_ALLOWLIST.search(match.group(0)):
                    continue
                hits.append((path.relative_to(root).as_posix(), label))
                break
    return hits


# ------------------------------------------------------------------------ commands


def cmd_init(ws: Workspace, args) -> int:
    ws.root.mkdir(parents=True, exist_ok=True)
    for sub in ("evidence", "reports", "promoted"):
        (ws.root / sub).mkdir(exist_ok=True)
    if not ws.engagement_path.exists():
        ws.write_json(ws.engagement_path, {
            "name": args.name,
            "customer": None,
            "created_at": now(),
            "posture": "passive",
            "in_scope": [],
            "out_of_scope": [],
            "authorization": None,
            "data_handling": "Evidence stays in this workspace. Redact secrets and PII at capture.",
        })
    if not ws.stack_path.exists():
        ws.write_json(ws.stack_path, {"frames": [], "seq": 0})
    if not ws.coverage_path.exists():
        ws.write_json(ws.coverage_path, {})
    print(f"engagement workspace ready at {ws.root}")
    print("posture: passive (read-only). Run `sa scope authorize` before any active testing.")
    return 0


def cmd_scope_set(ws: Workspace, args) -> int:
    eng = ws.engagement()
    if args.posture:
        if args.posture != "passive" and not eng.get("authorization"):
            raise SaError(
                f"posture '{args.posture}' requires recorded authorization — "
                "run `sa scope authorize --by <name> --ref <ticket>` first")
        eng["posture"] = args.posture
    if args.customer:
        eng["customer"] = args.customer
    if args.in_scope:
        eng["in_scope"] = [s.strip() for s in args.in_scope.split(",") if s.strip()]
    if args.out_of_scope:
        eng["out_of_scope"] = [s.strip() for s in args.out_of_scope.split(",") if s.strip()]
    if args.data_handling:
        eng["data_handling"] = args.data_handling
    ws.write_json(ws.engagement_path, eng)
    print(f"scope updated; posture={eng['posture']}")
    return 0


def cmd_scope_authorize(ws: Workspace, args) -> int:
    eng = ws.engagement()
    eng["authorization"] = {
        "by": args.by, "ref": args.ref, "recorded_at": now(), "note": args.note,
    }
    eng["posture"] = args.posture
    ws.write_json(ws.engagement_path, eng)
    print(f"authorization recorded (by {args.by}, ref {args.ref}); posture={args.posture}")
    return 0


def cmd_stack_push(ws: Workspace, args) -> int:
    stack = ws.read_json(ws.stack_path, {"frames": [], "seq": 0})
    stack["seq"] += 1
    frame = {
        "id": f"FR-{stack['seq']:03d}", "kind": args.kind, "ref": args.ref,
        "note": args.note, "opened_at": now(),
    }
    stack["frames"].append(frame)
    ws.write_json(ws.stack_path, stack)
    print(f"pushed {frame['id']}")
    return 0


def cmd_stack_pop(ws: Workspace, args) -> int:
    stack = ws.read_json(ws.stack_path, {"frames": [], "seq": 0})
    remaining = [f for f in stack["frames"] if f["id"] != args.frame]
    if len(remaining) == len(stack["frames"]):
        raise SaError(f"{args.frame} is not on the stack")
    popped = next(f for f in stack["frames"] if f["id"] == args.frame)
    stack["frames"] = remaining
    stack.setdefault("closed", []).append({**popped, "outcome": args.outcome, "closed_at": now()})
    ws.write_json(ws.stack_path, stack)
    print(f"popped {args.frame}: {args.outcome}")
    return 0


def cmd_stack_dump(ws: Workspace, args) -> int:
    stack = ws.read_json(ws.stack_path, {"frames": [], "seq": 0})
    frames = stack.get("frames", [])
    if not frames:
        print("no open frames")
        return 0
    print(f"{len(frames)} open frame(s):")
    for depth, f in enumerate(frames):
        note = f" — {f['note']}" if f.get("note") else ""
        print(f"  {'  ' * depth}{f['id']}  {f['kind']:<12} {f.get('ref') or '':<10}{note}")
    return 0


def cmd_unknown_add(ws: Workspace, args) -> int:
    rid = ws.next_id("unknown")
    ws.append("unknown", {
        "id": rid, "question": args.question, "blocks": _csv(args.blocks),
        "resolve_by": args.resolve_by, "status": "open", "answer": None,
        "created_at": now(),
    })
    print(f"{rid} recorded (open)")
    return 0


def cmd_unknown_resolve(ws: Workspace, args) -> int:
    ws.update("unknown", args.uid, status="resolved", answer=args.answer)
    print(f"{args.uid} resolved")
    return 0


def cmd_surface_add(ws: Workspace, args) -> int:
    records = ws.load("surface")
    records.append({
        "id": args.id, "entry": args.entry, "exposure": args.exposure,
        "authn": args.authn, "data": args.data, "modules": _csv(args.modules),
        "priority": args.priority, "created_at": now(),
    })
    ws.save("surface", records)
    coverage = ws.read_json(ws.coverage_path, {})
    coverage.setdefault(args.id, {"state": "pending", "reason": None})
    ws.write_json(ws.coverage_path, coverage)
    print(f"{args.id} added to the attack surface map (coverage: pending)")
    return 0


def cmd_coverage_set(ws: Workspace, args) -> int:
    if args.state in ("not-assessed", "partial") and not args.reason:
        raise SaError(f"state '{args.state}' requires --reason; silence overstates assurance")
    coverage = ws.read_json(ws.coverage_path, {})
    coverage[args.surface] = {"state": args.state, "reason": args.reason, "updated_at": now()}
    ws.write_json(ws.coverage_path, coverage)
    print(f"{args.surface}: {args.state}")
    return 0


def cmd_hypothesis_add(ws: Workspace, args) -> int:
    rid = ws.next_id("hypothesis")
    ws.append("hypothesis", {
        "id": rid, "surface": args.surface, "statement": args.statement,
        "falsifier": args.falsifier, "evidence_required": _csv(args.evidence_required),
        "module": args.module, "attacker": args.attacker, "precondition": args.precondition,
        "verification": args.verification, "status": "OPEN", "outcome": None,
        "evidence": [], "unknowns": [], "created_at": now(),
    })
    print(f"{rid} OPEN")
    return 0


def _hypothesis_close(ws: Workspace, args, status: str) -> int:
    changes = {"status": status, "outcome": args.note}
    if getattr(args, "evidence", None):
        changes["evidence"] = _csv(args.evidence)
    if getattr(args, "unknown", None):
        changes["unknowns"] = _csv(args.unknown)
    ws.update("hypothesis", args.hid, **changes)
    print(f"{args.hid} {status}")
    return 0


def cmd_evidence_add(ws: Workspace, args) -> int:
    posture = ws.posture()
    if args.grade == "E1" and posture == "passive":
        raise SaError(
            "E1 evidence is a runtime observation, which the current posture "
            f"('{posture}') does not permit. Either have a customer engineer run the check "
            "and share the output, or record authorization with `sa scope authorize`.")
    rid = ws.next_id("evidence")
    record = {
        "id": rid, "grade": args.grade, "kind": args.kind, "locator": args.locator,
        "summary": args.summary, "command": args.command, "artifact": None,
        "commit": _git_head(), "collected_at": now(),
    }
    if args.artifact:
        src = Path(args.artifact)
        if not src.exists():
            raise SaError(f"artifact not found: {src}")
        dest = ws.root / "evidence" / f"{rid}{src.suffix or '.txt'}"
        dest.write_bytes(src.read_bytes())
        record["artifact"] = dest.relative_to(ws.root).as_posix()
    ws.append("evidence", record)
    print(f"{rid} ({args.grade}) recorded")
    return 0


def cmd_candidate_add(ws: Workspace, args) -> int:
    rid = ws.next_id("candidate")
    ws.append("candidate", {
        "id": rid, "source": args.source, "raw": args.raw, "module": args.module,
        "status": "open", "stages": [], "killed_at_stage": None, "kill_reason": None,
        "finding_id": None, "created_at": now(),
    })
    print(f"{rid} open (grade E5 until verified)")
    return 0


def cmd_candidate_advance(ws: Workspace, args) -> int:
    record = ws.get("candidate", args.cid)
    stages = record["stages"] + [
        {"stage": args.stage, "result": args.result, "note": args.note, "at": now()}]
    ws.update("candidate", args.cid, stages=stages)
    print(f"{args.cid} {args.stage}: {args.result}")
    return 0


def cmd_candidate_kill(ws: Workspace, args) -> int:
    record = ws.get("candidate", args.cid)
    stages = record["stages"] + [
        {"stage": args.stage, "result": "kill", "note": args.reason, "at": now()}]
    ws.update("candidate", args.cid, status="killed", killed_at_stage=args.stage,
              kill_reason=args.reason, stages=stages)
    print(f"{args.cid} killed at {args.stage}: {args.reason}")
    print("Log this in knowledge/false-positive-catalog.md at retrospective time.")
    return 0


def cmd_candidate_promote(ws: Workspace, args) -> int:
    ws.get("candidate", args.cid)
    finding = _new_finding(ws, args.finding_title, args.module or "", args.cwe, args.owasp)
    finding["candidate_id"] = args.cid
    _save_finding(ws, finding)
    ws.update("candidate", args.cid, status="promoted", finding_id=finding["id"])
    print(f"{args.cid} promoted to {finding['id']}")
    return 0


def _new_finding(ws: Workspace, title: str, module: str, cwe: str, owasp: str) -> dict:
    return {
        "id": ws.next_id("finding"), "title": title, "module": module,
        "cwe": _csv(cwe), "owasp": _csv(owasp),
        "status": "open", "confidence": None, "ai_confidence": None,
        "ai_confidence_reason": None, "human_review_required": module in HUMAN_REVIEW_MODULES,
        "severity": None, "severity_factors": None, "severity_score": None,
        "severity_rationale": None, "severity_override_reason": None,
        "affected": [], "instances": [], "preconditions": [], "attack_scenario": None,
        "entry_point": None, "attacker_profile": None, "evidence": [],
        "controls_checked": [], "unknowns": [], "impact": None, "likelihood": None,
        "remediation": None, "remediation_bucket": None, "verification": None,
        "references": [], "candidate_id": None, "hypothesis_id": None,
        "created_at": now(), "updated_at": now(),
    }


def _save_finding(ws: Workspace, finding: dict) -> None:
    records = [r for r in ws.load("finding") if r["id"] != finding["id"]]
    records.append(finding)
    records.sort(key=lambda r: r["id"])
    ws.save("finding", records)


def cmd_finding_new(ws: Workspace, args) -> int:
    finding = _new_finding(ws, args.title, args.module, args.cwe, args.owasp)
    _save_finding(ws, finding)
    print(f"{finding['id']} created — now `sa finding rate` and `sa finding set`")
    return 0


def cmd_finding_rate(ws: Workspace, args) -> int:
    score, computed = compute_severity(args.T, args.E, args.B, args.X)
    severity = computed
    override_reason = None
    if args.override:
        if args.override not in BANDS:
            raise SaError(f"--override must be one of {', '.join(BANDS)}")
        if not args.override_reason:
            raise SaError("--override requires --override-reason; overrides appear in the report appendix")
        distance = abs(BANDS.index(args.override) - BANDS.index(computed))
        if distance > 1:
            raise SaError(
                f"override {computed} -> {args.override} spans {distance} bands; "
                "at most one is allowed. Re-check the T/E/B/X factors instead.")
        severity = args.override
        override_reason = args.override_reason
    finding = ws.get("finding", args.fid)
    finding.update({
        "severity": severity, "severity_score": score,
        "severity_factors": {"T": args.T, "E": args.E, "B": args.B, "X": args.X},
        "severity_rationale": args.rationale, "severity_override_reason": override_reason,
        "human_review_required": (
            severity in ("Critical", "High") or finding["module"] in HUMAN_REVIEW_MODULES),
        "updated_at": now(),
    })
    finding["remediation_bucket"] = finding.get("remediation_bucket") or {
        "Critical": "immediate", "High": "7d", "Medium": "30d",
        "Low": "90d", "Informational": "90d"}[severity]
    _save_finding(ws, finding)
    print(f"{args.fid}: {severity} (score {score:.2f}) T={args.T} E={args.E} B={args.B} X={args.X}")
    if finding["human_review_required"]:
        print("human review required")
    return 0


FINDING_FIELDS = [
    "confidence", "ai-confidence", "ai-confidence-reason", "attack-scenario",
    "entry-point", "attacker-profile", "impact", "likelihood", "remediation",
    "verification", "status", "remediation-bucket", "hypothesis-id",
]
FINDING_LIST_FIELDS = ["evidence", "unknowns", "preconditions", "instances", "references", "affected"]


def cmd_finding_set(ws: Workspace, args) -> int:
    finding = ws.get("finding", args.fid)
    for opt in FINDING_FIELDS:
        value = getattr(args, opt.replace("-", "_"))
        if value is not None:
            finding[opt.replace("-", "_")] = value
    for opt in FINDING_LIST_FIELDS:
        value = getattr(args, opt)
        if value is not None:
            finding[opt] = _csv(value)
    if finding.get("confidence") and finding["confidence"] not in CONFIDENCE:
        raise SaError(f"--confidence must be one of {', '.join(CONFIDENCE)}")
    if finding.get("ai_confidence") and finding["ai_confidence"] not in AI_CONFIDENCE:
        raise SaError(f"--ai-confidence must be one of {', '.join(AI_CONFIDENCE)}")
    finding["updated_at"] = now()
    _save_finding(ws, finding)
    print(f"{args.fid} updated")
    return 0


def cmd_finding_control(ws: Workspace, args) -> int:
    finding = ws.get("finding", args.fid)
    finding["controls_checked"].append(
        {"layer": args.layer, "locator": args.locator, "result": args.result})
    finding["updated_at"] = now()
    _save_finding(ws, finding)
    print(f"{args.fid}: recorded control check at {args.layer}")
    return 0


def cmd_finding_fix(ws: Workspace, args) -> int:
    finding = ws.get("finding", args.fid)
    finding.update({
        "status": args.outcome, "fixed_commit": args.commit,
        "fix_verification": args.verification, "updated_at": now(),
    })
    if args.evidence:
        finding["fix_evidence"] = _csv(args.evidence)
    _save_finding(ws, finding)
    print(f"{args.fid}: {args.outcome}")
    if args.outcome == "fixed" and not args.evidence:
        print("WARNING: 'fixed' without re-collected evidence at the new commit. "
              "See modules/remediation-review.md rule 1.")
    return 0


def cmd_finding_reopen(ws: Workspace, args) -> int:
    ws.update("finding", args.fid, status="open", reopen_reason=args.reason)
    print(f"{args.fid} reopened: {args.reason}")
    return 0


# -------------------------------------------------------------------------- validate


def validate(ws: Workspace) -> list:
    """The publication gate. Returns a list of blocking problems."""
    problems = []
    findings = ws.load("finding")
    evidence = {e["id"]: e for e in ws.load("evidence")}
    unknowns = {u["id"]: u for u in ws.load("unknown")}

    for f in findings:
        fid = f["id"]
        if f.get("status") in ("withdrawn", "risk-accepted"):
            continue

        for field in ("confidence", "ai_confidence", "attack_scenario", "entry_point",
                      "attacker_profile", "impact", "likelihood", "remediation",
                      "verification", "severity"):
            if not f.get(field):
                problems.append(f"{fid}: missing required field '{field}'")

        if not f.get("cwe"):
            problems.append(f"{fid}: at least one CWE is required")
        if not f.get("owasp"):
            problems.append(f"{fid}: at least one OWASP mapping is required")

        refs = f.get("evidence") or []
        if not refs:
            problems.append(f"{fid}: no evidence attached — no evidence, no finding")
        grades = {evidence[r]["grade"] for r in refs if r in evidence}
        for r in refs:
            if r not in evidence:
                problems.append(f"{fid}: evidence {r} does not exist")
        if refs and grades and grades <= {"E5", "E6"}:
            problems.append(
                f"{fid}: only E5/E6 evidence — tool output and inference are candidates, not findings")

        if not f.get("controls_checked"):
            problems.append(
                f"{fid}: no controls_checked recorded — enumerate where you looked for a defence")

        if f.get("ai_confidence") and f["ai_confidence"] != "High" and not f.get("ai_confidence_reason"):
            problems.append(
                f"{fid}: ai_confidence '{f['ai_confidence']}' requires ai_confidence_reason "
                "naming what you could not establish")

        if f.get("severity") == "Critical" and not (grades & {"E1", "E2"}):
            problems.append(f"{fid}: Critical severity requires E1 or E2 evidence")

        if f.get("confidence") == "CONFIRMED":
            if not (grades & {"E1", "E2"}):
                problems.append(f"{fid}: CONFIRMED requires E1 or E2 evidence")
            for uid in f.get("unknowns") or []:
                if unknowns.get(uid, {}).get("status") == "open":
                    problems.append(
                        f"{fid}: CONFIRMED with open unknown {uid} on the exploitation path")

        if f.get("confidence") == "NEEDS-VERIFICATION" and f.get("severity") == "Critical":
            problems.append(
                f"{fid}: NEEDS-VERIFICATION caps at High — an open question is not a proven breach")

        rationale = f.get("severity_rationale") or ""
        if rationale and looks_like_tool_attribution(rationale):
            problems.append(
                f"{fid}: severity_rationale relays a tool's verdict; state why this system "
                "warrants this band")

        if f.get("severity") in ("Critical", "High") and not f.get("human_review_required"):
            problems.append(f"{fid}: {f['severity']} findings require human_review_required")

    stack = ws.read_json(ws.stack_path, {"frames": []})
    if stack.get("frames"):
        ids = ", ".join(fr["id"] for fr in stack["frames"])
        problems.append(f"{len(stack['frames'])} open frame(s) on the assessment stack: {ids}")

    coverage = ws.read_json(ws.coverage_path, {})
    for sid, entry in coverage.items():
        if entry.get("state") == "pending":
            problems.append(f"{sid}: coverage state is still 'pending' — assess it or record why not")

    for path, label in scan_secrets(ws.root):
        problems.append(f"possible secret in the workspace ({label}) at {path} — redact it")

    return problems


def cmd_validate(ws: Workspace, args) -> int:
    problems = validate(ws)
    if not problems:
        print("PASS — all findings meet the publication bar")
        return 0
    print(f"FAIL — {len(problems)} blocking problem(s):")
    for p in problems:
        print(f"  - {p}")
    return 1


def cmd_status(ws: Workspace, args) -> int:
    eng = ws.engagement()
    findings = ws.load("finding")
    by_band = {b: sum(1 for f in findings if f.get("severity") == b) for b in reversed(BANDS)}
    hyps = ws.load("hypothesis")
    by_status = {}
    for h in hyps:
        by_status[h["status"]] = by_status.get(h["status"], 0) + 1
    coverage = ws.read_json(ws.coverage_path, {})
    cov = {}
    for entry in coverage.values():
        cov[entry["state"]] = cov.get(entry["state"], 0) + 1
    open_unknowns = [u for u in ws.load("unknown") if u["status"] == "open"]
    frames = ws.read_json(ws.stack_path, {"frames": []}).get("frames", [])

    print(f"engagement: {eng.get('name')}   posture: {eng.get('posture')}")
    print(f"authorization: {'recorded' if eng.get('authorization') else 'NONE (passive only)'}")
    print(f"findings: {len(findings)}  " + "  ".join(f"{b}={n}" for b, n in by_band.items() if n))
    print(f"hypotheses: {len(hyps)}  " + "  ".join(f"{k}={v}" for k, v in by_status.items()))
    print(f"candidates: {len(ws.load('candidate'))}   evidence: {len(ws.load('evidence'))}")
    print(f"coverage: " + ("  ".join(f"{k}={v}" for k, v in cov.items()) or "no surfaces recorded"))
    print(f"open unknowns: {len(open_unknowns)}   open stack frames: {len(frames)}")
    for u in open_unknowns:
        print(f"  {u['id']}: {u['question']}  → {u['resolve_by']}")
    return 0


# --------------------------------------------------------------------------- reports


def _coverage_table(ws: Workspace) -> str:
    coverage = ws.read_json(ws.coverage_path, {})
    surfaces = {s["id"]: s for s in ws.load("surface")}
    if not coverage:
        return "_No attack surfaces were recorded. This assessment has no coverage statement, " \
               "which means its findings cannot be read as an assurance statement._\n"
    lines = ["| Surface | Entry point | State | Reason |", "|---|---|---|---|"]
    for sid, entry in sorted(coverage.items()):
        surface = surfaces.get(sid, {})
        lines.append(
            f"| {sid} | {surface.get('entry', '')} | {entry['state']} | {entry.get('reason') or ''} |")
    return "\n".join(lines) + "\n"


def _unknown_table(ws: Workspace) -> str:
    open_u = [u for u in ws.load("unknown") if u["status"] == "open"]
    if not open_u:
        return "_No open unknowns._\n"
    lines = ["| ID | Question | What would resolve it | Blocks |", "|---|---|---|---|"]
    for u in open_u:
        lines.append(f"| {u['id']} | {u['question']} | {u['resolve_by']} | {', '.join(u['blocks'])} |")
    return "\n".join(lines) + "\n"


def _sorted_findings(ws: Workspace) -> list:
    order = {b: i for i, b in enumerate(reversed(BANDS))}
    return sorted(ws.load("finding"), key=lambda f: (order.get(f.get("severity"), 99), f["id"]))


def cmd_report(ws: Workspace, args) -> int:
    eng = ws.engagement()
    findings = _sorted_findings(ws)
    evidence = {e["id"]: e for e in ws.load("evidence")}
    out = ws.root / "reports"
    out.mkdir(exist_ok=True)

    if args.kind == "technical":
        path = out / "technical.md"
        parts = [
            f"# Technical Assessment Report — {eng.get('name')}",
            f"\n**Date**: {now()[:10]}  \n**Posture**: {eng.get('posture')}  "
            f"\n**In scope**: {', '.join(eng.get('in_scope') or []) or 'see engagement.json'}  "
            f"\n**Out of scope**: {', '.join(eng.get('out_of_scope') or []) or '—'}\n",
            "## Summary\n",
            "| Severity | Count |", "|---|---|",
        ]
        for band in reversed(BANDS):
            parts.append(f"| {band} | {sum(1 for f in findings if f.get('severity') == band)} |")
        parts += ["\n## Assessment Coverage\n",
                  "What was assessed, and what was not. Absence of findings in an area that was not "
                  "assessed is not evidence of its security.\n",
                  _coverage_table(ws), "\n### Open unknowns\n", _unknown_table(ws), "\n## Findings\n"]
        for f in findings:
            parts.append(_render_finding(f, evidence))
        overrides = [f for f in findings if f.get("severity_override_reason")]
        if overrides:
            parts.append("\n## Appendix: severity overrides\n")
            for f in overrides:
                parts.append(f"- **{f['id']}** → {f['severity']}: {f['severity_override_reason']}")
        path.write_text("\n".join(parts) + "\n", encoding="utf-8")

    elif args.kind == "executive":
        path = out / "executive.md"
        crit = [f for f in findings if f.get("severity") in ("Critical", "High")]
        coverage = ws.read_json(ws.coverage_path, {})
        gaps = {k: v for k, v in coverage.items() if v["state"] in ("not-assessed", "partial")}
        parts = [
            f"# Executive Summary — {eng.get('name')}",
            f"\n**Date**: {now()[:10]}\n",
            "## Current risk\n",
            f"We assessed {len(coverage)} attack surface(s) and raised {len(findings)} finding(s): "
            + ", ".join(f"{sum(1 for f in findings if f.get('severity') == b)} {b}"
                        for b in reversed(BANDS)) + ".\n",
            "_Replace this paragraph with a plain-language statement of where the business stands._\n",
            "## Most important findings\n",
        ]
        if crit:
            for f in crit:
                parts.append(f"- **{f['id']} · {f['severity']} — {f['title']}**  \n  {f.get('impact') or ''}")
        else:
            parts.append("- No Critical or High findings.")
        parts += [
            "\n## Business impact\n",
            "\n".join(f"- **{f['id']}**: {f.get('impact') or ''}" for f in crit) or "- —",
            "\n## Priority actions\n",
            "\n".join(f"- **{f['id']}** ({f.get('remediation_bucket') or '—'}): "
                      f"{(f.get('remediation') or '')}" for f in crit) or "- —",
            "\n## Areas we could not assess\n",
            "These are not statements that the areas are secure. They were not examined.\n",
        ]
        if gaps:
            parts.append("| Surface | State | Why |")
            parts.append("|---|---|---|")
            for sid, entry in sorted(gaps.items()):
                parts.append(f"| {sid} | {entry['state']} | {entry.get('reason') or ''} |")
        else:
            parts.append("_All recorded surfaces were assessed._")
        parts += ["\n### Open questions blocking certainty\n", _unknown_table(ws)]
        path.write_text("\n".join(parts) + "\n", encoding="utf-8")

    elif args.kind == "remediation":
        path = out / "remediation-plan.md"
        buckets = [("immediate", "Immediate"), ("7d", "Within 7 days"),
                   ("30d", "Within 30 days"), ("90d", "Within 90 days")]
        parts = [f"# Remediation Plan — {eng.get('name')}", f"\n**Date**: {now()[:10]}\n",
                 "Ordered by severity, exploitability and effort — not by severity alone.\n"]
        for key, label in buckets:
            parts.append(f"\n## {label}\n")
            rows = [f for f in findings if (f.get("remediation_bucket") or "90d") == key]
            if not rows:
                parts.append("_Nothing in this bucket._")
                continue
            parts.append("| ID | Severity | Finding | Action | Verification |")
            parts.append("|---|---|---|---|---|")
            for f in rows:
                parts.append(
                    f"| {f['id']} | {f.get('severity')} | {f['title']} | "
                    f"{(f.get('remediation') or '')} | {(f.get('verification') or '')} |")
        parts += ["\n## Human review queue\n",
                  "These require a security engineer before action is taken:\n"]
        hr = [f for f in findings if f.get("human_review_required")]
        parts.append("\n".join(
            f"- **{f['id']}** ({f.get('severity')}, AI confidence {f.get('ai_confidence')}): "
            f"{f['title']}" for f in hr) or "- —")
        path.write_text("\n".join(parts) + "\n", encoding="utf-8")
    else:
        raise SaError(f"unknown report kind {args.kind}")

    print(f"wrote {path}")
    return 0


def _render_finding(f: dict, evidence: dict) -> str:
    lines = [
        f"\n### [{f.get('severity')}] {f['id']} — {f['title']}\n",
        f"| | |", "|---|---|",
        f"| Severity | {f.get('severity')} (score {f.get('severity_score')}, "
        f"T/E/B/X {f.get('severity_factors')}) |",
        f"| Confidence | {f.get('confidence')} |",
        f"| AI confidence | {f.get('ai_confidence')}"
        + (f" — {f['ai_confidence_reason']}" if f.get("ai_confidence_reason") else "") + " |",
        f"| Human review | {'**required**' if f.get('human_review_required') else 'not required'} |",
        f"| CWE | {', '.join(f.get('cwe') or [])} |",
        f"| OWASP | {', '.join(f.get('owasp') or [])} |",
        f"| Entry point | `{f.get('entry_point')}` |",
        f"| Attacker | {f.get('attacker_profile')} |",
        f"\n**Preconditions**\n",
        "\n".join(f"- {p}" for p in (f.get("preconditions") or [])) or "- —",
        f"\n**Attack scenario**\n\n{f.get('attack_scenario')}\n",
        "**Evidence**\n",
    ]
    for eid in f.get("evidence") or []:
        e = evidence.get(eid, {})
        lines.append(f"- `{eid}` ({e.get('grade')}) `{e.get('locator')}` — {e.get('summary')}")
    lines += ["\n**Controls checked**\n", "| Layer | Location | Result |", "|---|---|---|"]
    for c in f.get("controls_checked") or []:
        lines.append(f"| {c['layer']} | `{c['locator']}` | {c['result']} |")
    lines += [
        f"\n**Impact**\n\n{f.get('impact')}\n",
        f"**Likelihood**\n\n{f.get('likelihood')}\n",
        f"**Remediation** ({f.get('remediation_bucket')})\n\n{f.get('remediation')}\n",
        f"**Verification**\n\n{f.get('verification')}\n",
        f"**Severity rationale**\n\n{f.get('severity_rationale')}\n",
    ]
    return "\n".join(lines)


# ----------------------------------------------------------------------- retrospective


def cmd_retro_add(ws: Workspace, args) -> int:
    rid = ws.next_id("retro")
    ws.append("retro", {
        "id": rid, "kind": args.kind, "text": args.text, "status": "local",
        "created_at": now(),
    })
    print(f"{rid} recorded (engagement-local; may contain customer specifics)")
    return 0


def blocked_terms(ws: Workspace) -> list:
    eng = ws.engagement()
    terms = []
    for value in [eng.get("customer"), eng.get("name")]:
        if value:
            terms.append(value)
    for entry in (eng.get("in_scope") or []) + (eng.get("out_of_scope") or []):
        terms.append(entry)
        # "repo:acme/api" also blocks "acme" and "api"
        for part in re.split(r"[:/,]", entry):
            if len(part) >= 4:
                terms.append(part)
    if eng.get("customer"):
        for token in re.split(r"[\s_-]+", eng["customer"]):
            if len(token) >= 4:
                terms.append(token)
    return [t for t in dict.fromkeys(terms) if t]


def sanitize(text: str, terms: list) -> list:
    """Return the reasons this text may not leave the engagement workspace."""
    reasons = []
    low = text.lower()
    for term in terms:
        if term.lower() in low:
            reasons.append(f"customer/scope identifier: '{term}'")
    for pattern, label in (
        (DOMAIN_RE, "domain or hostname"), (IPV4_RE, "IP address"),
        (EMAIL_RE, "email address"), (ARN_RE, "AWS ARN"),
        (ACCOUNT_RE, "12-digit account id"), (REPO_RE, "repository reference"),
    ):
        match = pattern.search(text)
        if match:
            reasons.append(f"{label}: '{match.group(0)}'")
    for pattern, label in SECRET_PATTERNS:
        if pattern.search(text):
            reasons.append(f"credential shape: {label}")
    return list(dict.fromkeys(reasons))


def cmd_retro_promote(ws: Workspace, args) -> int:
    entry = ws.get("retro", args.entry)
    if not args.approved_by:
        raise SaError(
            "promotion to shared knowledge requires human approval — pass --approved-by <name>. "
            "The sanitizer is a safety net, not a substitute for judgement.")
    reasons = sanitize(entry["text"], blocked_terms(ws))
    if reasons:
        print("sanitizer BLOCKED promotion:", file=sys.stderr)
        for r in reasons:
            print(f"  - {r}", file=sys.stderr)
        print("\nRewrite the entry to keep the mechanism and drop the customer, "
              "then promote again. See references/retrospective.md.", file=sys.stderr)
        return 1
    target_dir = Path(args.knowledge_dir) if args.knowledge_dir else ws.root / "promoted"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{args.target}.md"
    with target.open("a", encoding="utf-8") as fh:
        fh.write(f"\n## {entry['kind']} ({entry['id']})\n\n{entry['text']}\n\n"
                 f"_Promoted {now()[:10]}, approved by {args.approved_by}. Hits: 0 / Misses: 0._\n")
    ws.update("retro", args.entry, status="promoted", approved_by=args.approved_by)
    print(f"{args.entry} promoted to {target}")
    return 0


def cmd_retro_draft(ws: Workspace, args) -> int:
    skill_root = Path(__file__).resolve().parent.parent
    template = skill_root / "templates" / "retrospective.md"
    dest = ws.root / "retrospective.md"
    if dest.exists():
        print(f"{dest} already exists")
        return 0
    dest.write_text(
        template.read_text(encoding="utf-8") if template.exists()
        else "# Retrospective\n\nSee references/retrospective.md.\n", encoding="utf-8")
    print(f"wrote {dest} — engagement-local, never committed to the skill")
    return 0


# ----------------------------------------------------------------------------- util


def _csv(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [v.strip() for v in value.split(",") if v.strip()]


def _git_head():
    try:
        import subprocess
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=5)
        return out.stdout.strip() or None
    except Exception:
        return None


# ------------------------------------------------------------------------------ cli


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sa", description="Engagement workspace CLI for the security-assessment skill.")
    p.add_argument("--workspace", default=os.environ.get("SA_WORKSPACE", "."),
                   help="engagement workspace directory (default: $SA_WORKSPACE or .)")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("init", help="create the engagement workspace")
    sp.add_argument("--name", required=True)
    sp.set_defaults(func=cmd_init, needs_ws=False)

    # scope
    scope = sub.add_parser("scope", help="scope, posture and authorization").add_subparsers(
        dest="sub", required=True)
    sp = scope.add_parser("set")
    sp.add_argument("--posture", choices=POSTURES)
    sp.add_argument("--customer")
    sp.add_argument("--in-scope")
    sp.add_argument("--out-of-scope")
    sp.add_argument("--data-handling")
    sp.set_defaults(func=cmd_scope_set)
    sp = scope.add_parser("authorize")
    sp.add_argument("--by", required=True)
    sp.add_argument("--ref", required=True, help="ticket, email or SOW reference")
    sp.add_argument("--posture", choices=POSTURES, default="active-safe")
    sp.add_argument("--note")
    sp.set_defaults(func=cmd_scope_authorize)

    # stack
    stack = sub.add_parser("stack", help="the assessment stack").add_subparsers(
        dest="sub", required=True)
    sp = stack.add_parser("push")
    sp.add_argument("--kind", required=True,
                    choices=["engagement", "surface", "hypothesis", "verification", "candidate"])
    sp.add_argument("--ref")
    sp.add_argument("--note")
    sp.set_defaults(func=cmd_stack_push)
    sp = stack.add_parser("pop")
    sp.add_argument("frame")
    sp.add_argument("--outcome", required=True, help="a frame may only be popped with an outcome")
    sp.set_defaults(func=cmd_stack_pop)
    sp = stack.add_parser("dump")
    sp.set_defaults(func=cmd_stack_dump)

    # unknown
    unknown = sub.add_parser("unknown", help="facts you could not establish").add_subparsers(
        dest="sub", required=True)
    sp = unknown.add_parser("add")
    sp.add_argument("--question", required=True)
    sp.add_argument("--resolve-by", required=True, help="what would settle this")
    sp.add_argument("--blocks")
    sp.set_defaults(func=cmd_unknown_add)
    sp = unknown.add_parser("resolve")
    sp.add_argument("uid")
    sp.add_argument("--answer", required=True)
    sp.set_defaults(func=cmd_unknown_resolve)

    # surface / coverage
    surface = sub.add_parser("surface", help="attack surface map").add_subparsers(
        dest="sub", required=True)
    sp = surface.add_parser("add")
    sp.add_argument("--id", required=True)
    sp.add_argument("--entry", required=True)
    sp.add_argument("--exposure", required=True)
    sp.add_argument("--authn")
    sp.add_argument("--data")
    sp.add_argument("--modules")
    sp.add_argument("--priority", default="medium")
    sp.set_defaults(func=cmd_surface_add)

    coverage = sub.add_parser("coverage", help="what was assessed").add_subparsers(
        dest="sub", required=True)
    sp = coverage.add_parser("set")
    sp.add_argument("--surface", required=True)
    sp.add_argument("--state", required=True, choices=["assessed", "partial", "not-assessed"])
    sp.add_argument("--reason")
    sp.set_defaults(func=cmd_coverage_set)

    # hypothesis
    hyp = sub.add_parser("hypothesis", help="the assessment engine").add_subparsers(
        dest="sub", required=True)
    sp = hyp.add_parser("add")
    sp.add_argument("--surface", required=True)
    sp.add_argument("--statement", required=True)
    sp.add_argument("--falsifier", required=True,
                    help="what would DISPROVE this; a hypothesis without one is not a hypothesis")
    sp.add_argument("--module", required=True)
    sp.add_argument("--evidence-required")
    sp.add_argument("--attacker")
    sp.add_argument("--precondition")
    sp.add_argument("--verification")
    sp.set_defaults(func=cmd_hypothesis_add)
    for name, status in (("refute", "REFUTED"), ("support", "SUPPORTED"),
                         ("inconclusive", "INCONCLUSIVE")):
        sp = hyp.add_parser(name)
        sp.add_argument("hid")
        sp.add_argument("--note", required=(name != "support"))
        sp.add_argument("--evidence")
        sp.add_argument("--unknown")
        sp.set_defaults(func=lambda w, a, s=status: _hypothesis_close(w, a, s))

    # evidence
    ev = sub.add_parser("evidence", help="artifacts backing findings").add_subparsers(
        dest="sub", required=True)
    sp = ev.add_parser("add")
    sp.add_argument("--grade", required=True, choices=GRADES)
    sp.add_argument("--kind", required=True,
                    choices=["code", "config", "runtime", "network", "db", "tool", "doc", "interview"])
    sp.add_argument("--locator", required=True, help="path:lines, ARN, endpoint — must be re-checkable")
    sp.add_argument("--summary", required=True)
    sp.add_argument("--artifact", help="file to copy into the workspace")
    sp.add_argument("--command")
    sp.set_defaults(func=cmd_evidence_add)

    # candidate
    cand = sub.add_parser("candidate", help="leads, pre-triage").add_subparsers(
        dest="sub", required=True)
    sp = cand.add_parser("add")
    sp.add_argument("--source", required=True)
    sp.add_argument("--raw", required=True)
    sp.add_argument("--module", required=True)
    sp.set_defaults(func=cmd_candidate_add)
    sp = cand.add_parser("advance")
    sp.add_argument("cid")
    sp.add_argument("--stage", required=True,
                    choices=["reachability", "controls", "exploitability", "impact"])
    sp.add_argument("--result", required=True, choices=["pass", "downgrade"])
    sp.add_argument("--note")
    sp.set_defaults(func=cmd_candidate_advance)
    sp = cand.add_parser("kill")
    sp.add_argument("cid")
    sp.add_argument("--stage", required=True,
                    choices=["reachability", "controls", "exploitability", "impact", "classification"])
    sp.add_argument("--reason", required=True, help="cite the control or the reason; kills are audited")
    sp.set_defaults(func=cmd_candidate_kill)
    sp = cand.add_parser("promote")
    sp.add_argument("cid")
    sp.add_argument("--finding-title", required=True)
    sp.add_argument("--module")
    sp.add_argument("--cwe", default="")
    sp.add_argument("--owasp", default="")
    sp.set_defaults(func=cmd_candidate_promote)

    # finding
    find = sub.add_parser("finding", help="findings").add_subparsers(dest="sub", required=True)
    sp = find.add_parser("new")
    sp.add_argument("--title", required=True)
    sp.add_argument("--module", required=True)
    sp.add_argument("--cwe", required=True)
    sp.add_argument("--owasp", required=True)
    sp.set_defaults(func=cmd_finding_new)
    sp = find.add_parser("rate")
    sp.add_argument("fid")
    for factor, help_text in (("T", "technical impact"), ("E", "exploitability"),
                              ("B", "business impact"), ("X", "exposure")):
        sp.add_argument(f"--{factor}", type=int, required=True, help=f"{help_text} (1-4)")
    sp.add_argument("--rationale", required=True)
    sp.add_argument("--override", choices=BANDS)
    sp.add_argument("--override-reason")
    sp.set_defaults(func=cmd_finding_rate)
    sp = find.add_parser("set")
    for opt in FINDING_FIELDS:
        sp.add_argument(f"--{opt}")
    for opt in FINDING_LIST_FIELDS:
        sp.add_argument(f"--{opt}", help="comma separated")
    sp.add_argument("fid")
    sp.set_defaults(func=cmd_finding_set)
    sp = find.add_parser("control", help="record where you looked for a defence")
    sp.add_argument("fid")
    sp.add_argument("--layer", required=True)
    sp.add_argument("--locator", required=True)
    sp.add_argument("--result", required=True)
    sp.set_defaults(func=cmd_finding_control)
    sp = find.add_parser("fix")
    sp.add_argument("fid")
    sp.add_argument("--outcome", default="fixed",
                    choices=["fixed", "partially-fixed", "mitigated", "not-fixed",
                             "regressed", "risk-accepted"])
    sp.add_argument("--commit")
    sp.add_argument("--evidence", help="re-collected at the new commit")
    sp.add_argument("--verification")
    sp.set_defaults(func=cmd_finding_fix)
    sp = find.add_parser("reopen")
    sp.add_argument("fid")
    sp.add_argument("--reason", required=True)
    sp.set_defaults(func=cmd_finding_reopen)

    # validate / status / report
    sp = sub.add_parser("validate", help="publication gate")
    sp.set_defaults(func=cmd_validate)
    sp = sub.add_parser("status", help="where the assessment stands")
    sp.set_defaults(func=cmd_status)
    sp = sub.add_parser("report", help="generate a deliverable")
    sp.add_argument("kind", choices=["technical", "executive", "remediation"])
    sp.set_defaults(func=cmd_report)

    # retro
    retro = sub.add_parser("retro", help="continuous improvement").add_subparsers(
        dest="sub", required=True)
    sp = retro.add_parser("draft")
    sp.set_defaults(func=cmd_retro_draft)
    sp = retro.add_parser("add")
    sp.add_argument("--kind", required=True,
                    choices=["missed-hypothesis", "false-positive", "near-miss",
                             "detection-pattern", "verification-recipe", "customer-exception"])
    sp.add_argument("--text", required=True)
    sp.set_defaults(func=cmd_retro_add)
    sp = retro.add_parser("promote")
    sp.add_argument("--entry", required=True)
    sp.add_argument("--target", required=True,
                    choices=["detection-patterns", "verification-recipes", "false-positive-catalog"])
    sp.add_argument("--approved-by")
    sp.add_argument("--knowledge-dir",
                    help="where to append (default: <workspace>/promoted, so nothing leaves by accident)")
    sp.set_defaults(func=cmd_retro_promote)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    ws = Workspace(Path(args.workspace))
    try:
        if getattr(args, "needs_ws", True):
            ws.require()
        return args.func(ws, args)
    except SaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
