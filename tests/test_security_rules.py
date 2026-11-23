"""Bundled security-rule contract and REAL, offline Semgrep fixture regression.

Fixtures are read as text only: never import, execute, compile, serve, or deploy
anything in fixtures/security. A match proves only the asserted rule behavior.
The integration class runs the existing project .venv Semgrep, or an explicit
absolute LOCALGUARD_SEMGREP_TEST_EXE. It skips only when no executable exists;
an installed scanner's errors, missed controls, and parse failures FAIL tests.
No package installation, registry rules, version check, or telemetry is requested.
This tests the real CLI, NOT the LocalGuard process-isolation/normalization adapter.

Run: python -B -m unittest discover -s tests -p test_security_rules.py -v
Validated initially with official Semgrep OSS 1.186.0.
"""
from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
RULE_FILE = ROOT / "localguard" / "rules" / "security.json"
FIXTURES = ROOT / "fixtures" / "security"
SOURCE_SUFFIXES = {".py", ".js", ".ts", ".java", ".go", ".rs", ".c", ".cpp", ".php", ".rb", ".sol"}
LANGUAGES = {"python", "javascript", "typescript", "java", "go", "rust", "c", "cpp", "php", "ruby", "solidity"}
ANNOTATION = re.compile(r"^\s*(?://|#)\s*(ruleid|ok):\s*(localguard\.security\.[\w-]+)\s*$")


def source_files():
    return sorted(path for path in FIXTURES.iterdir() if path.suffix in SOURCE_SUFFIXES)


def expected_locations():
    """Language-neutral annotation reader; scanner alone understands the code."""
    positive, negative = set(), set()
    for path in source_files():
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            annotation = ANNOTATION.fullmatch(line)
            if not annotation:
                continue
            if index + 1 >= len(lines) or not lines[index + 1].strip():
                raise AssertionError(f"Annotation must immediately precede source: {path}:{index + 1}")
            kind, rule_id = annotation.groups()
            target = positive if kind == "ruleid" else negative
            location = (path.name, rule_id, index + 2)
            if location in target:
                raise AssertionError(f"Duplicate fixture annotation: {location}")
            target.add(location)
    return positive, negative


def semgrep_executable():
    explicit = os.environ.get("LOCALGUARD_SEMGREP_TEST_EXE")
    if explicit:
        binary = Path(explicit)
        if not binary.is_absolute() or not binary.is_file():
            raise AssertionError("LOCALGUARD_SEMGREP_TEST_EXE must name an existing absolute executable")
        return binary
    # Resolve the scanner relative to the interpreter running the tests, not a
    # hard-coded ROOT/.venv path. A project move (or running the suite from a
    # different venv) otherwise breaks the console-script launcher embedded
    # shebang, which silently exits 1. sys.executable's Scripts/bin directory
    # is always the matching one.
    scripts = Path(sys.executable).resolve().parent
    candidates = (scripts / "semgrep.exe", scripts / "semgrep",
                  ROOT / ".venv" / "Scripts" / "semgrep.exe", ROOT / ".venv" / "bin" / "semgrep")
    return next((path for path in candidates if path.is_file()), None)


class SecurityRuleContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = json.loads(RULE_FILE.read_text(encoding="utf-8"))["rules"]
        cls.positive, cls.negative = expected_locations()

    def test_bounded_declarative_language_aware_bundle(self):
        self.assertGreaterEqual(len(self.rules), 12)
        self.assertLessEqual(len(self.rules), 18)
        self.assertEqual({language for rule in self.rules for language in rule["languages"]}, LANGUAGES)
        self.assertEqual(len({rule["id"] for rule in self.rules}), len(self.rules))
        self.assertGreaterEqual(sum(rule.get("mode") == "taint" for rule in self.rules), 10)
        for rule in self.rules:
            with self.subTest(rule=rule["id"]):
                self.assertTrue(rule["id"].startswith("localguard.security."))
                self.assertNotIn("pattern-regex", json.dumps(rule))
                self.assertNotIn("generic", rule["languages"])
                if rule.get("mode") == "taint":
                    self.assertTrue(rule["pattern-sources"])
                    self.assertTrue(rule["pattern-sinks"])
                    for sink in rule["pattern-sinks"]:
                        self.assertTrue(any("focus-metavariable" in pattern for pattern in sink["patterns"]))

    def test_metadata_remediation_and_limits_are_explicit(self):
        for rule in self.rules:
            with self.subTest(rule=rule["id"]):
                metadata = rule["metadata"]
                self.assertIn(metadata["category"], {"injection", "misconfig", "other"})
                self.assertRegex(metadata["cwe"], r"^CWE-\d+$")
                self.assertEqual(metadata["confidence"], "HIGH")
                self.assertTrue(metadata["remediation"].strip())
                self.assertTrue(metadata["limitations"].strip())
                self.assertTrue(rule["message"].strip())
                self.assertIn(rule["severity"], {"ERROR", "WARNING"})

    def test_every_rule_has_vulnerable_and_clean_controls(self):
        ids = {rule["id"] for rule in self.rules}
        self.assertEqual({rule for _, rule, _ in self.positive}, ids)
        self.assertEqual({rule for _, rule, _ in self.negative}, ids)
        self.assertFalse(self.positive & self.negative)
        self.assertEqual({path.suffix for path in source_files()}, SOURCE_SUFFIXES)
        for path in source_files():
            with self.subTest(file=path.name):
                self.assertIn("ARTIFICIAL STATIC FIXTURE - DO NOT EXECUTE", path.read_text(encoding="utf-8"))
                self.assertTrue(any(name == path.name for name, _, _ in self.positive))
                self.assertTrue(any(name == path.name for name, _, _ in self.negative))


class RealSemgrepSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = semgrep_executable()
        if binary is None:
            raise unittest.SkipTest("Real Semgrep unavailable; structural tests are not scanner integration evidence")
        # Do not inherit a registry config, login token, telemetry switch, or
        # output destination. Semgrep atomically rewrites its settings even for
        # offline scans (a null device cannot be the Windows rename target).
        # Keep transient tool state inside the fixture area and remove it.
        environment = {key: value for key, value in os.environ.items() if not key.startswith("SEMGREP_")}
        environment.update({
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "SEMGREP_LOG_FILE": os.devnull,
            "SEMGREP_VERSION_CACHE_PATH": os.devnull,
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        command = [
            str(binary), "scan", "--config", str(RULE_FILE), "--json",
            "--oss-only", "--metrics=off", "--disable-version-check",
            "--no-rewrite-rule-ids", "--disable-nosem", "--no-git-ignore",
            "--strict", "--jobs=1", "--timeout=15", "--max-target-bytes=1048576",
            *(str(path) for path in source_files()),
        ]
        # Semgrep drops read-only OCaml temp files (ocaml_sp_*) into TMPDIR.
        # Keep them outside the fixtures tree and remove them best-effort so a
        # Windows permission artifact in teardown cannot fail rule assertions.
        import stat
        scratch = tempfile.mkdtemp(prefix="localguard-semgrep-")
        try:
            environment.update({
                "SEMGREP_SETTINGS_FILE": str(Path(scratch) / "settings.yml"),
                "TEMP": scratch, "TMP": scratch, "TMPDIR": scratch,
            })
            completed = subprocess.run(
                command, cwd=FIXTURES, env=environment, shell=False,
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
            )
        finally:
            for directory, _, files in os.walk(scratch):
                for name in files:
                    file = Path(directory) / name
                    try:
                        file.chmod(file.stat().st_mode | stat.S_IWRITE)
                    except OSError:
                        pass
            shutil.rmtree(scratch, ignore_errors=True)
        if completed.returncode != 0:
            raise AssertionError(
                f"Real Semgrep exited {completed.returncode}\n{completed.stdout}\n{completed.stderr}"
            )
        try:
            cls.raw = json.loads(completed.stdout)
        except ValueError as error:
            raise AssertionError(f"Real Semgrep returned invalid JSON: {completed.stdout}") from error
        cls.positive, cls.negative = expected_locations()
        cls.findings = [
            (cls.relative_name(item["path"]), item["check_id"], item["start"]["line"])
            for item in cls.raw["results"]
        ]

    @staticmethod
    def relative_name(value):
        path = Path(value)
        if not path.is_absolute():
            path = FIXTURES / path
        return path.resolve().relative_to(FIXTURES.resolve()).as_posix()

    def test_real_scanner_parsed_all_eleven_fixture_files(self):
        self.assertTrue(self.raw.get("version"))
        self.assertEqual(self.raw.get("errors"), [], self.raw.get("errors"))
        self.assertEqual(
            {self.relative_name(path) for path in self.raw["paths"]["scanned"]},
            {path.name for path in source_files()},
        )
        self.assertTrue(all(finding.get("extra", {}).get("engine_kind") == "OSS" for finding in self.raw["results"]))

    def test_real_scanner_exact_vulnerable_locations_no_extra_matches(self):
        self.assertEqual(
            Counter(self.findings), Counter(self.positive),
            f"Missing: {sorted(self.positive - set(self.findings))}; "
            f"unexpected: {sorted(set(self.findings) - self.positive)}",
        )

    def test_real_scanner_clean_controls_do_not_match(self):
        self.assertFalse(set(self.findings) & self.negative)

    def test_real_scanner_preserves_rule_metadata(self):
        rules = {rule["id"]: rule for rule in json.loads(RULE_FILE.read_text(encoding="utf-8"))["rules"]}
        for finding in self.raw["results"]:
            with self.subTest(rule=finding["check_id"], path=finding["path"]):
                expected = rules[finding["check_id"]]
                self.assertEqual(finding["extra"]["metadata"], expected["metadata"])
                self.assertEqual(finding["extra"]["severity"], expected["severity"])


if __name__ == "__main__":
    unittest.main()
