import json
import subprocess
import sys
from pathlib import Path

from scripts.bench_detection import matches


ROOT = Path(__file__).resolve().parents[1]
VULN = {"location": {"file": "authentication/views.py", "line_start": 25, "line_end": 35}}


def test_matches_file_level():
    assert matches({"path": "vulnerable-app/authentication/views.py", "line": 999}, VULN)
    assert matches({"path": "authentication/views.py", "line": 1}, VULN)


def test_matches_strict_line():
    assert matches({"path": "authentication/views.py", "line": 30}, VULN, strict_line=True)
    assert not matches({"path": "authentication/views.py", "line": 200}, VULN, strict_line=True)


def test_matches_rejects_other_files():
    assert not matches({"path": "catalog/views.py", "line": 30}, VULN)


def test_ground_truth_shape():
    data = json.loads((ROOT / "benchmarks" / "vulnshop-ground-truth.json").read_text(encoding="utf-8"))
    vulns = data["vulnerabilities"]
    assert len(vulns) == 16
    for v in vulns:
        assert v["id"].startswith("VULN-")
        assert v["location"]["file"]
        assert v["cwe"].startswith("CWE-")


def test_license_check_passes():
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "check_licenses.py")],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
