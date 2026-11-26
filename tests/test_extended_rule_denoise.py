"""Extended-rule additive denoise regression (real offline Semgrep).

Fixtures are ARTIFICIAL STATIC text: never import, execute, or install them.
This verifies that additive exclusions preserve every original detection while
suppressing the documented safe contexts. No model, no data writes.

Known limitation (NOT asserted here): django-ssti-template still reports a
source line for multi-line taint patterns; sink localization needs a separate
taint-mode rewrite and is intentionally out of scope for this additive change.
"""
from __future__ import annotations

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
sys.path.insert(0, str(ROOT / 'scripts'))
from test_security_rules import semgrep_executable  # noqa: E402

RULES = ROOT / 'localguard/rules/security-extended.json'
FIXTURES = ROOT / 'fixtures/extended_denoise'
ANNOTATION = re.compile(r'^\s*#\s*(ruleid|ok):\s*(lg\.ext\.[\w-]+)(?:\s+.*)?$')
TARGETS = {'lg.ext.weak-crypto-random', 'lg.ext.weak-crypto-sha1',
           'lg.ext.code-injection-eval-exec', 'lg.ext.xxe-lxml-etree',
           'lg.ext.django-ssti-template', 'lg.ext.jinja2-ssti-from-string'}


def expectations():
    src = (FIXTURES / 'denoise_controls.py').read_text(encoding='utf-8').splitlines()
    positive, negative = set(), set()
    for i, line in enumerate(src):
        m = ANNOTATION.fullmatch(line)
        if m:
            (positive if m.group(1) == 'ruleid' else negative).add((m.group(2), i + 2))
    return positive, negative


class ExtendedRuleDenoiseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = semgrep_executable()
        if binary is None:
            raise unittest.SkipTest('Real Semgrep unavailable; scanner integration evidence required')
        cls.positive, cls.negative = expectations()
        env = {k: v for k, v in os.environ.items() if not k.startswith('SEMGREP_')}
        env.update({'SEMGREP_SEND_METRICS': 'off', 'SEMGREP_ENABLE_VERSION_CHECK': '0',
                    'SEMGREP_LOG_FILE': os.devnull, 'SEMGREP_VERSION_CACHE_PATH': os.devnull,
                    'PYTHONDONTWRITEBYTECODE': '1'})
        scratch = tempfile.mkdtemp(prefix='localguard-ext-denoise-')
        try:
            env.update({'SEMGREP_SETTINGS_FILE': str(Path(scratch) / 'settings.yml'),
                        'TEMP': scratch, 'TMP': scratch, 'TMPDIR': scratch})
            proc = subprocess.run([str(binary), 'scan', '--config', str(RULES), '--json',
                                   '--oss-only', '--metrics=off', '--disable-version-check',
                                   '--no-rewrite-rule-ids', '--disable-nosem', '--no-git-ignore',
                                   '--strict', '--jobs=1', '--timeout=15',
                                   str(FIXTURES / 'denoise_controls.py')],
                                  cwd=FIXTURES, env=env, capture_output=True, text=True,
                                  encoding='utf-8', errors='replace', timeout=120)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        if proc.returncode != 0:
            raise AssertionError(f'Semgrep exited {proc.returncode}: {proc.stderr[:500]}')
        cls.raw = json.loads(proc.stdout)
        cls.hits = {(r['check_id'], r['start']['line']) for r in cls.raw.get('results', [])
                    if r['check_id'] in TARGETS}

    def test_target_rules_have_positive_and_negative_controls(self):
        for rid in TARGETS:
            with self.subTest(rule=rid):
                self.assertTrue(any(k == rid for k, _ in self.positive), rid)
                self.assertTrue(any(k == rid for k, _ in self.negative), rid)

    def test_no_missing_positive_detections(self):
        missing = sorted(self.positive - self.hits)
        self.assertEqual(missing, [], f'lost detections: {missing}')

    def test_no_new_false_positives(self):
        fp = sorted(self.hits - self.positive - self.negative)
        self.assertEqual(fp, [], f'unexpected hits: {fp}')

    def test_original_calls_still_detected(self):
        # P0 regression guard: random.random/shuffle and compile() must stay.
        for _, line in sorted(self.positive):
            self.assertIn(line, {ln for _, ln in self.hits})


if __name__ == '__main__':
    unittest.main()
