"""Triage status UI mapping, legacy schema compatibility, no fabricated confidence.

Pre-submit regressions from review: scored records must stay filterable by
verdict, legacy audit records must still validate, abstained must not invent
a 0.5 confidence.
"""
import json
import subprocess
from pathlib import Path

import pytest
from jsonschema import ValidationError, validate

from localguard.schemas import STATUS

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / 'localguard/static/triage-status.js'


def _js(fn, arg):
    script = (f"const api=require({json.dumps(str(JS))});"
              f"process.stdout.write(JSON.stringify(api.{fn}({json.dumps(arg)})));")
    # Windows locale may be GBK; decode Node's UTF-8 output explicitly.
    return json.loads(subprocess.check_output(['node', '-e', script], encoding='utf-8'))


def test_ui_filter_scored_uses_verdict_not_status():
    assert _js('filterKeyOf', {'triage_status': 'scored', 'verdict': 'likely_true'}) == 'likely_true'
    assert _js('filterKeyOf', {'triage_status': 'scored', 'verdict': 'likely_false'}) == 'likely_false'
    assert _js('filterKeyOf', {'triage_status': 'uncertain', 'verdict': 'uncertain'}) == 'uncertain'
    assert _js('filterKeyOf', {'triage_status': 'abstained', 'verdict': None}) == 'abstained'
    assert _js('filterKeyOf', None) == 'none'


def test_ui_legacy_records_still_filterable_and_badged():
    legacy_true = {'verdict': 'likely_true', 'reason': 'r', 'tier': '8gb', 'confidence': 0.8}
    legacy_unc = {'verdict': 'uncertain', 'reason': 'r', 'tier': '8gb', 'confidence': 0.5}
    legacy_missing = {'explanation': 'e', 'remediation': 'r'}  # no verdict at all
    assert _js('statusOf', legacy_true) == 'scored'
    assert _js('filterKeyOf', legacy_true) == 'likely_true'
    assert _js('badgeOf', legacy_true)['key'] == 'likely_true'
    assert _js('badgeOf', legacy_true)['label'] == '模型：可能是真的'
    assert _js('filterKeyOf', legacy_unc) == 'uncertain'
    assert _js('badgeOf', legacy_unc)['label'] == '模型：不确定'
    assert _js('statusOf', legacy_missing) == 'abstained'
    assert _js('badgeOf', legacy_missing)['label'] == '模型未判定，需人工复核'


def test_ui_new_badge_uses_verdict_for_scored():
    new_false = {'triage_status': 'scored', 'verdict': 'likely_false', 'reason': 'r', 'tier': '8gb'}
    badge = _js('badgeOf', new_false)
    assert badge['key'] == 'likely_false'  # CSS class triage-likely_false exists
    assert badge['label'] == '模型：可能误报'
    abst = _js('badgeOf', {'triage_status': 'abstained', 'verdict': None})
    assert abst['key'] == 'abstained' and '人工复核' in abst['label']


def _legacy_status(triage):
    return {'audit_id': 'a' * 32, 'status': 'completed', 'queue_position': 0, 'progress': 100,
            'completed_modules': [], 'warnings': [], 'target': 't', 'root': 'r', 'truncated': False,
            'issues': [{'id': 'I-1', 'title': 't', 'severity': 'high', 'category': 'injection',
                        'cwe': 'CWE-89', 'confidence': 0.9,
                        'locations': [{'path': 'a.py', 'line': 1, 'snippet_hash': 'b' * 64}],
                        'evidence': [{'tool': 'patterns'}],
                        'explanation': 'e', 'remediation': 'r',
                        'needs_human_review': False, 'review': 'unreviewed',
                        'triage': triage, 'ai_explanation': 'done'}]}


def test_legacy_triage_schema_still_validates():
    legacy = _legacy_status({'verdict': 'likely_true', 'confidence': 0.9,
                             'reason': 'why', 'tier': '8gb'})
    validate(legacy, STATUS)  # no ValidationError => backward compatible


def test_new_abstained_triage_schema_validates_with_null_confidence():
    new = _legacy_status({'triage_status': 'abstained', 'verdict': None, 'confidence': None,
                          'reason': '', 'tier': '8gb', 'abstain_reason': 'placeholder',
                          'high_priority_review': True})
    validate(new, STATUS)
    assert new['issues'][0]['triage']['confidence'] is None


def test_invalid_confidence_still_rejected():
    bad = _legacy_status({'triage_status': 'scored', 'verdict': 'likely_true',
                          'confidence': 2, 'reason': 'why', 'tier': '8gb'})
    with pytest.raises(ValidationError):
        validate(bad, STATUS)
