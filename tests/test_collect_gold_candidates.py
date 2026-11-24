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


def test_align_deduplicates_one_finding_hitting_two_vulns():
    # catalog/views.py appears in both VULN-002 (45-55) and VULN-003 (60-65);
    # a single finding must yield ONE candidate with two provenance ids.
    data = {'target': 'x', 'issues': [_issue('ISSUE-A', 'catalog/views.py', 119)]}
    rows = align_positives(data)
    ids = [r['id'] for r in rows]
    assert ids.count('ISSUE-A') == 1
    provenance = [r['provenance'] for r in rows if r['id'] == 'ISSUE-A'][0]
    assert set(provenance['ground_truth_ids']) >= {'VULN-002', 'VULN-003'}


def test_candidate_is_unlabelled_and_review_ready():
    c = make_candidate(_issue('ISSUE-B', 'a.py', 1), 'probe', {}, 'likely_false')
    assert c['needs_review'] is True
    assert c['human_label'] is None
    assert c['proposed_label'] == 'likely_false'
    assert set(c['finding']) >= {'title', 'severity', 'cwe', 'locations', 'evidence'}
