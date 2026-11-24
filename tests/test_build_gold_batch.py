"""The human review batch must carry evidence and never pre-fill labels."""
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def test_review_batch_shape():
    path = ROOT / '.workbuddy' / 'gold' / 'review_batch_v0.jsonl'
    if not path.exists():
        import pytest
        pytest.skip('batch not generated in this environment')
    rows = [json.loads(l) for l in path.read_text(encoding='utf-8').splitlines() if l.strip()]
    assert len(rows) >= 40
    for r in rows:
        assert r['needs_review'] is True
        assert r['human_label'] is None and r['human_reason'] is None
        assert r['proposed_label'] in {'likely_true', 'likely_false', 'uncertain'}
        assert 'rule_id' in r['finding']
        assert r['provenance']
        # every row has either code commit or a CVE/replay provenance
        p = r['provenance']
        assert p.get('code_commit') or p.get('cve') or p.get('replay_file') or p.get('fix_commit')
