"""Lightweight compliance check for bundled third-party material.

Run in CI to catch accidental bundling of rules with restrictive licenses
(the Semgrep Rules License incident). This is a guardrail, not legal advice.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "localguard" / "rules" / "security-extended.json"
NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"


def main() -> int:
    errors = []
    if not NOTICES.is_file():
        errors.append("THIRD_PARTY_NOTICES.md is missing")

    if not RULES.is_file():
        errors.append(f"{RULES.relative_to(ROOT)} is missing")
    else:
        try:
            data = json.loads(RULES.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError) as exc:
            errors.append(f"rule pack is not valid UTF-8 JSON: {exc}")
        else:
            rules = data.get("rules", [])
            if not isinstance(rules, list) or not rules:
                errors.append("rule pack has no rules")
            # Every bundled rule must carry our curated prefix: unbundled
            # upstream rules (e.g. Semgrep's) must not slip into the pack.
            bare = [r.get("id") for r in rules
                    if isinstance(r, dict) and not str(r.get("id", "")).startswith("lg.ext.")]
            if bare:
                errors.append(f"{len(bare)} rule(s) without 'lg.ext.' provenance prefix: {bare[:3]}")
            # Known restrictive-license rule id families must never appear.
            restricted = ("python.lang.", "python.django.", "javascript.lang.",
                          "generic.", "flask.")
            bad = [r.get("id") for r in rules if isinstance(r, dict)
                   and any(str(r.get("id", "")).startswith(p) or p in str(r.get("id", ""))
                           for p in restricted)]
            if bad:
                errors.append(f"restrictively licensed Semgrep rules detected: {bad[:3]}")

    if errors:
        print("License compliance check FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("License compliance check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
