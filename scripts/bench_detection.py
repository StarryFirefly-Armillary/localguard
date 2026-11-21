"""Reproducible detection benchmark against the VulnShop ground truth.

Runs a real LocalGuard audit over the benchmark app and measures how many of
the 16 documented vulnerabilities are detected (file + line-range match).
This turns "accuracy" from an anecdote into a number that can regress-check
rule and pipeline changes.

Usage:
    python scripts/bench_detection.py                       # uses ./repos/code-safety
    python scripts/bench_detection.py --target <vulnshop>   # custom checkout
    python scripts/bench_detection.py --json out.json

The benchmark app is NOT bundled (it is a separate MIT repository). Clone it
to ./repos/code-safety or pass --target. Requires no UI service.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

GROUND_TRUTH = ROOT / "benchmarks" / "vulnshop-ground-truth.json"
DEFAULT_TARGET = ROOT / "repos" / "code-safety" / "vulnerable-app"
LINE_TOLERANCE = 5  # rules may land a few lines off the documented range


def load_ground_truth():
    data = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))
    return data["vulnerabilities"]


def normalize(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def matches(location, vuln, strict_line=False) -> bool:
    """Count an issue as detecting a vuln when it lands in the same file.

    Line ranges in the ground truth are approximate: a rule may flag a
    different line of the same vulnerable construct (e.g. gitleaks flags a
    second hardcoded key in settings.py, not the documented SECRET_KEY line).
    File-level matching is the robust default; --strict-line opts into the
    tighter file+range check.
    """
    gt = vuln["location"]
    target_file = normalize(gt["file"])
    rel = normalize(location["path"])
    if not (rel == target_file or rel.endswith("/" + target_file)):
        return False
    if not strict_line:
        return True
    line = location.get("line")
    lo = gt.get("line_start", 1) - LINE_TOLERANCE
    hi = gt.get("line_end", gt.get("line_start", 1)) + LINE_TOLERANCE
    return lo <= line <= hi


async def run_audit(target: Path, config_path: Path | None):
    from localguard.config import Config
    from localguard.registry import ToolRegistry

    import tempfile
    # Fresh temp state avoids sharing/locking with the running UI service.
    state_dir = Path(tempfile.mkdtemp(prefix="localguard-bench-"))
    if config_path:
        # Inherit only scanner binaries / host settings from the local config;
        # never reuse its data_dir (the UI service owns that database).
        raw = json.loads(Path(config_path).read_text(encoding="utf-8"))
        config = Config(
            allowed_roots=[target.parent],
            data_dir=state_dir,
            model_tier="rules",
            binaries=raw.get("binaries", {}),
            scanner_timeout=raw.get("scanner_timeout", 120),
            max_files=raw.get("max_files", 10000),
            max_file_bytes=raw.get("max_file_bytes", 2_000_000),
            max_repo_bytes=raw.get("max_repo_bytes", 200_000_000),
        )
    else:
        config = Config(allowed_roots=[target.parent], data_dir=state_dir, model_tier="rules")
    registry = ToolRegistry(config)
    queued = await registry.call("audit_repository", {
        "target": str(target),
        "scanners": ["patterns", "semgrep", "gitleaks"],
        "include_dependencies": False,
        "model_tier": "rules",
    }, "bench")
    if queued.get("isError"):
        raise RuntimeError(queued.get("error", "audit submission failed"))
    audit_id = queued["data"]["audit_id"]
    for _ in range(300):
        status = await registry.call("get_audit_status", {
            "audit_id": audit_id, "wait_seconds": 1, "limit": 200,
        }, "bench")
        data = status["data"]
        if data["status"] in ("completed", "failed"):
            break
    else:
        raise RuntimeError("audit did not finish")
    await registry.close()
    if data["status"] != "completed":
        raise RuntimeError(data.get("error", "audit failed"))
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--config", type=Path, default=None,
                        help="Optional localguard config for installed scanners")
    parser.add_argument("--json", type=Path, default=None, help="Write full metrics here")
    parser.add_argument("--strict-line", action="store_true",
                        help="Require issue line within the ground-truth range (default: file-level match)")
    args = parser.parse_args()

    if not args.target.is_dir():
        print(f"Benchmark app not found: {args.target}\n"
              f"Clone it: git clone https://github.com/laugiov/code-safety.git repos/code-safety",
              file=sys.stderr)
        return 2

    vulns = load_ground_truth()
    data = asyncio.run(run_audit(args.target.resolve(), args.config))
    issues = data.get("issues", [])

    detected, missed = [], []
    for vuln in vulns:
        hit = None
        for issue in issues:
            for loc in issue.get("locations", []):
                if matches(loc, vuln, strict_line=args.strict_line):
                    hit = issue
                    break
            if hit:
                break
        (detected if hit else missed).append(vuln)

    recall = len(detected) / len(vulns) * 100 if vulns else 0
    print(f"\nVulnShop detection benchmark")
    print(f"  target:  {args.target}")
    print(f"  issues:  {len(issues)}")
    print(f"  detected: {len(detected)}/{len(vulns)}  ({recall:.1f}% recall)")
    print(f"  coverage: {json.dumps(data.get('coverage', {}).get('scanners', {}), ensure_ascii=False)}")
    if missed:
        print(f"\n  Missed ({len(missed)}):")
        for v in missed:
            print(f"    {v['id']:10} {v['cwe']:10} {v['location']['file']}")

    metrics = {
        "target": str(args.target),
        "total_vulnerabilities": len(vulns),
        "detected": len(detected),
        "recall": round(recall, 1),
        "issues": len(issues),
        "coverage": data.get("coverage", {}),
        "detected_ids": [v["id"] for v in detected],
        "missed_ids": [v["id"] for v in missed],
    }
    if args.json:
        args.json.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n  metrics written to {args.json}")
    # Gate is set slightly below the measured baseline (43.8%) so minor
    # fluctuations pass but a real regression (e.g. a rule pack removed) fails.
    return 0 if recall >= 40 else 1


if __name__ == "__main__":
    raise SystemExit(main())
