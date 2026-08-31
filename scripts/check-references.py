#!/usr/bin/env python3
"""Fail CI if a skill document points at a file that does not exist.

Paths inside the skill are written relative to the skill root. References to the
optional `security-audit` companion skill are intentionally unresolvable here and
are skipped.
"""
import re
import sys
from pathlib import Path

SKILL = Path(__file__).resolve().parent.parent / "plugins/security-assessment/skills/security-assessment"
INSKILL = re.compile(
    r"(?<!/)\b((?:modules|references|templates|knowledge|scripts|tests)/[A-Za-z0-9_.,{}-]+\.(?:md|py))")
COMPANION = re.compile(r"security-audit/references/[A-Za-z0-9_.{},<>-]+\.md")

def main() -> int:
    broken = []
    for path in sorted(SKILL.rglob("*.md")):
        text = COMPANION.sub("", path.read_text(encoding="utf-8"))
        for match in INSKILL.finditer(text):
            ref = match.group(1)
            if "{" in ref:
                continue
            if not (SKILL / ref).exists():
                broken.append(f"{path.relative_to(SKILL)}: {ref}")
    if broken:
        print("broken references:")
        for b in broken:
            print(f"  - {b}")
        return 1
    print("all in-skill references resolve")
    return 0

if __name__ == "__main__":
    sys.exit(main())
