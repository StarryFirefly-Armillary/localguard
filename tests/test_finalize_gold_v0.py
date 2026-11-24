"""Gold v0 finalization must deduplicate, preserve confirmed labels, and avoid split leakage."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from finalize_gold_v0 import dedupe, finalize, group_key, split_records


def _record(source, *, rule=None, cwe=None, path='a.py', line=1, cve=None, fix=None):
    finding = {'rule_id': rule, 'cwe': cwe, 'path': path, 'line': line}
    if source in {'real_cve_tool_call', 'vulnshop_current_scan'}:
        finding = {
            'rule_id': rule, 'cwe': cwe,
            'locations': [{'path': path, 'line': line, 'snippet_hash': f'snip-{line}'}],
        }
    return {
        'id': f'{source}:{rule or cwe}:{path}:{line}',
        'source': source,
        'proposed_label': 'likely_false',
        'needs_review': True,
        'human_label': None,
        'human_reason': None,
        'provenance': {'cve': cve, 'fix_commit': fix},
        'finding': finding,
    }


def test_dedupe_collapses_identical_findings():
    row = _record('old_rule_fp_v2', rule='lg.ext.weak-crypto-random', path='app.py', line=217, fix='852ed77')
    unique, duplicates = dedupe([row, dict(row), dict(row)])
    assert len(unique) == 1
    assert duplicates == 2
    assert unique[0]['duplicate_count'] == 3


def test_captcha_answer_is_true_but_render_noise_is_false():
    answer = _record('old_rule_fp_v2', rule='lg.ext.weak-crypto-random', path='app.py', line=247, fix='852ed77')
    noise = _record('old_rule_fp_v2', rule='lg.ext.weak-crypto-random', path='app.py', line=217, fix='852ed77')
    rows, _ = finalize([answer, noise], confirmed_at='2026-11-24T00:00:00+00:00')
    labels = {r['finding']['line']: r['human_label'] for r in rows}
    assert labels == {247: 'likely_true', 217: 'likely_false'}
    assert all(r['needs_review'] is False and r['confirmed_by'] == 'user' for r in rows)
    assert all('lg-fp-v2-' not in json.dumps(r) for r in rows)


def test_grouped_split_has_no_leakage():
    records = [
        _record('real_cve_tool_call', cwe='CWE-89', path='a.py', line=1, cve='CVE-1'),
        _record('real_cve_tool_call', cwe='CWE-89', path='a.py', line=2, cve='CVE-2'),
        _record('old_rule_fp_v2', rule='lg.ext.weak-crypto-random', path='app.py', line=247, fix='852ed77'),
        _record('old_rule_fp_v2', rule='lg.ext.weak-crypto-random', path='app.py', line=217, fix='852ed77'),
        _record('old_rule_fp_v2', rule='lg.ext.xxe-xml-etree', path='scanners.py', line=601, fix='bfc9807'),
        _record('vulnshop_current_scan', cwe='CWE-89', path='views.py', line=73),
    ]
    records, _ = finalize(records, confirmed_at='2026-11-24T00:00:00+00:00')
    train, evaluation = split_records(records)
    assert {r['group_key'] for r in train}.isdisjoint({r['group_key'] for r in evaluation})
    assert group_key(records[2]) == group_key(records[3]) == 'blog:captcha-random'
