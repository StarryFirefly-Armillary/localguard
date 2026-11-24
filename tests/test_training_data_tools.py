"""Training-data collectors must preserve provenance, labels, and split isolation."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from apply_ai_review_labels import annotate, real_repo_reason
from build_training_dataset_v1 import grouped_split, normalize_finding, sft_messages
from collect_cve_function_pairs import functions, node_name
from collect_training_findings import raw_index
from rebuild_dataset_v2 import apply_review, dedupe_sinks, split_v2
from merge_remaining_v3 import DUPLICATES, SINK_LINES, context_from_text, group_key
from freeze_gold_v1 import clean_record
from repair_gold_evidence import repair_record
from confirm_gold_labels import confirm_record


def test_raw_evidence_rule_id_extraction():
    raw = {'results': [{'check_id': 'rule.one', 'extra': {'message': 'message'}}]}
    assert raw_index('semgrep', '#/results/0', raw) == ('rule.one', 'message')
    assert raw_index('patterns', '#/matches/0', {'matches': [{'rule_id': 'p1'}]}) == ('p1', None)


def test_c_function_name_and_changed_span():
    data = b'int f(int x) {\n  return x + 1;\n}\n'
    found = functions(Path('a.c'), data, {2})
    assert [item['name'] for item in found] == ['f']
    assert found[0]['start_line'] == 1 and found[0]['end_line'] == 3


def test_ai_annotation_never_writes_human_label():
    row = {
        'id': 'X', 'source': 'current_scanner', 'human_label': None,
        'provenance': {'rule_id': 'jwt'},
        'finding': {'path': 'docs/example.md', 'title': 'example'},
    }
    annotate([row], 'real_repo')
    assert row['ai_label'] == 'likely_false'
    assert row['annotator'] == 'AI'
    assert row['human_label'] is None
    assert row['needs_user_confirmation'] is True
    assert 'documentation' in real_repo_reason(row).lower()


def test_normalize_finding_preserves_label_origin():
    row = {
        'id': 'X', 'human_label': None, 'ai_label': 'likely_true', 'ai_reason': 'flow',
        'annotator': 'AI', 'provenance': {'code_commit': 'abc'},
        'finding': {'title': 't', 'cwe': 'CWE-89', 'path': 'a.py', 'line': 3,
                    'source_full_code_only': [{'line': 3, 'text': 'x'}]},
    }
    normalized = normalize_finding(row)
    assert normalized['label'] == 'likely_true'
    assert normalized['label_origin'] == 'ai_assisted'
    assert normalized['needs_user_confirmation'] is True
    messages = sft_messages(normalized)
    assert json.loads(messages[-1]['content'])['verdict'] == 'likely_true'


def test_grouped_split_has_no_leakage():
    rows = [
        {'id': 'A', 'sample_kind': 'triage_finding', 'label': 'likely_true',
         'provenance': {'repo_url': 'r'}, 'finding': {'rule_id': 'x', 'path': 'a.py'}},
        {'id': 'B', 'sample_kind': 'triage_finding', 'label': 'likely_false',
         'provenance': {'repo_url': 'r'}, 'finding': {'rule_id': 'x', 'path': 'a.py'}},
        {'id': 'C', 'sample_kind': 'cve_function_pair', 'label': 'vulnerable_fixed_pair',
         'provenance': {'repo_url': 'r2', 'cve': 'CVE-1'}},
    ]
    train, evaluation = grouped_split(rows)
    train_ids = {row['id'] for row in train}
    eval_ids = {row['id'] for row in evaluation}
    assert not train_ids & eval_ids
    assert train_ids | eval_ids == {'A', 'B', 'C'}


def test_review_relabel_and_reason_fix_are_applied():
    record = {
        'id': 'FINDING-ec7f1a643a512aa7', 'sample_kind': 'triage_finding',
        'label': 'uncertain', 'reason': 'old', 'label_origin': 'ai_assisted',
        'provenance': {'repo_url': 'r'},
        'finding': {'rule_id': 'jwt', 'path': 'settings.py', 'line': 237},
    }
    review = {
        'review_decision': 'relabel', 'reviewed_label': 'likely_false',
        'review_reason': 'No reachable JWT security use.', 'quality_flags': '',
        'review_evidence': 'settings.py:237',
    }
    updated = apply_review(record, review)
    assert updated['label'] == 'likely_false'
    assert updated['reason'] == 'No reachable JWT security use.'
    assert updated['label_origin'] == 'ai_assisted_reviewed'
    assert updated['needs_user_confirmation'] is True


def test_duplicate_sink_dedupe_prefers_corrected_sink_line():
    rows = [
        {'id': 'A', 'quality_flags': ['duplicate_sink:sink1'],
         'finding': {'sink_group': 'sink1', 'line': 12}},
        {'id': 'B', 'quality_flags': ['reported_line_not_sink', 'duplicate_sink:sink1'],
         'finding': {'sink_group': 'sink1', 'line': 72}},
    ]
    kept, removed = dedupe_sinks(rows)
    assert removed == 1
    assert [row['id'] for row in kept] == ['B']


def test_v2_split_uses_sink_group_and_has_no_leakage():
    rows = [
        {'id': 'A', 'sample_kind': 'triage_finding', 'label': 'likely_true',
         'provenance': {'repo_url': 'r'}, 'finding': {'sink_group': 'sink1', 'path': 'a.py'}},
        {'id': 'B', 'sample_kind': 'triage_finding', 'label': 'likely_true',
         'provenance': {'repo_url': 'r'}, 'finding': {'sink_group': 'sink1', 'path': 'a.py'}},
        {'id': 'C', 'sample_kind': 'triage_finding', 'label': 'likely_false',
         'provenance': {'repo_url': 'r'}, 'finding': {'sink_group': 'sink2', 'path': 'b.py'}},
    ]
    train, evaluation = split_v2(rows)
    train_ids = {row['id'] for row in train}
    eval_ids = {row['id'] for row in evaluation}
    assert not train_ids & eval_ids
    assert train_ids | eval_ids == {'A', 'B', 'C'}
    assert ({'A', 'B'} <= train_ids) or ({'A', 'B'} <= eval_ids)


def test_materialized_context_strips_labels_but_keeps_guards():
    text = 'def render(x):\n    # VULNERABLE: sink below\n    safe = escape(x)\n    return safe\n'
    window, full = context_from_text(text, 3, 'python')
    assert [row['line'] for row in window] == [1, 2, 3, 4]
    joined = '\n'.join(row['text'] for row in full)
    assert 'VULNERABLE' not in joined
    assert 'escape(x)' in joined


def test_v3_family_group_controls_split_identity():
    row = {
        'id': 'A', 'sample_kind': 'triage_finding',
        'provenance': {'repo_url': 'r'},
        'finding': {'family_group': 'minimist_setKey', 'path': 'index.js'},
    }
    assert group_key(row) == 'family:minimist_setKey'
    assert len(DUPLICATES) == 5
    assert SINK_LINES['ISSUE-5c78f1ddc609'] == 72
    assert SINK_LINES['ISSUE-7bd670d24709'] == 142


def test_gold_cleanup_separates_hashes_and_revalidation(monkeypatch):
    import freeze_gold_v1 as freeze
    monkeypatch.setattr(freeze, 'pinned_bytes', lambda record: b'pinned-source')
    record = {
        'id': 'X', 'sample_kind': 'triage_finding',
        'label_origin': 'human_confirmed_revalidated',
        'quality_flags': ['missing_embedded_source', 'reported_line_not_sink'],
        'training_action': 'keep_after_source_materialization',
        'provenance': {'file_sha256': 'materialized'},
        'finding': {'path': 'a.py'},
    }
    cleaned = clean_record(record)
    assert cleaned['provenance']['materialized_source_sha256'] == 'materialized'
    assert cleaned['provenance']['pinned_file_sha256'] == freeze.sha(b'pinned-source')
    assert 'file_sha256' not in cleaned['provenance']
    assert cleaned['quality_flags'] == ['reported_line_not_sink']
    assert cleaned['training_action'] == 'keep'
    assert cleaned['original_label_origin'] == 'human_confirmed'
    assert cleaned['revalidated_by'] == 'AI'


def test_non_python_repair_preserves_ruby_interpolation(monkeypatch):
    import repair_gold_evidence as repair
    source = b'def log(request)\n  q = request.query_string.empty? ? "" : "?#{request.query_string}"\nend\n'
    monkeypatch.setattr(repair, 'pinned_bytes', lambda record: source)
    record = {
        'id': 'R', 'sample_kind': 'triage_finding',
        'provenance': {},
        'finding': {'path': 'logger.rb', 'line': 2, 'source': []},
    }
    repaired, changed = repair_record(record)
    text = '\n'.join(item['text'] for item in repaired['finding']['source'])
    assert changed is True
    assert '#{request.query_string}' in text
    assert repaired['gold_status'] == 'frozen'
    assert repaired['provenance']['pinned_file_sha256'] == repair.sha(source)


def test_user_confirmation_preserves_original_ai_provenance():
    record = {
        'id': 'X', 'sample_kind': 'triage_finding', 'label': 'likely_false',
        'label_origin': 'ai_assisted_reviewed', 'annotator': 'AI',
        'needs_user_confirmation': True,
    }
    confirmed = confirm_record(record, '2026-11-24T00:00:00+00:00')
    assert confirmed['needs_user_confirmation'] is False
    assert confirmed['human_label'] == 'likely_false'
    assert confirmed['confirmed_by'] == 'user'
    assert confirmed['original_label_origin'] == 'ai_assisted_reviewed'
    assert confirmed['previous_annotator'] == 'AI'
    assert confirmed['annotator'] == 'user'





