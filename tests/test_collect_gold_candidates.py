"""Gold candidate collection must de-duplicate findings and never pre-fill labels."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from collect_gold_candidates import align_positives, make_candidate


def _issue(iid, path, line):
    return {'id': iid, 'title': 'SQL Injection', 'severity': 'high', 'category': 'other',
            'cwe': 'CWE-89', 'confidence': 0.9,
            'locations': [{'path': path, 'line': line, 'snippet_hash': 'x', 'stale': False}],
            'evidence': [{'tool': 'semgrep', 'raw_ref': '#/results/24'}]}


def test_align_never_attaches_cwe_inconsistent_vuln():
    # A CWE-89 finding in catalog/views.py lines 45-55 must align to VULN-002
    # (SQLi) ONLY — never to VULN-003 (XSS) just because it is the same file.
    data = {'target': 'x', 'issues': [_issue('ISSUE-A', 'catalog/views.py', 50)]}
    rows = align_positives(data)
    assert len(rows) == 1
    r = rows[0]
    assert r['provenance']['ground_truth_ids'] == ['VULN-002']
    assert r['provenance']['match_quality'] == 'strict_file_cwe_line'
    assert r['proposed_label'] == 'likely_true'
    assert all(c == 'CWE-89' for c in r['provenance']['ground_truth_cwes'])


def test_align_marks_file_only_as_uncertain():
    # Same file + CWE but far outside the line range -> uncertain, not positive.
    data = {'target': 'x', 'issues': [_issue('ISSUE-B', 'catalog/views.py', 119)]}
    rows = align_positives(data)
    assert len(rows) == 1
    r = rows[0]
    assert r['provenance']['match_quality'] == 'file_cwe_only_uncertain'
    assert r['proposed_label'] == 'uncertain'


def test_candidate_is_unlabelled_and_review_ready():
    c = make_candidate(_issue('ISSUE-B', 'a.py', 1), 'probe', {}, 'likely_false')
    assert c['needs_review'] is True
    assert c['human_label'] is None
    assert c['proposed_label'] == 'likely_false'
    assert set(c['finding']) >= {'title', 'severity', 'cwe', 'locations', 'evidence'}
