"""Pure unit tests using explicitly synthetic fixtures and fake Git/parser data.
These fixtures are NOT real CVEs, upstream objects, training data or metrics.
No model loader, network, subprocess, or training operation is run.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from localguard import training
from localguard.model import LocalModel
from localguard.schemas import TOOLS


def sha(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


@pytest.fixture(autouse=True)
def forbid_training_io(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Pure unit test attempted real Git subprocess/model training')
    monkeypatch.setattr(training.subprocess, 'run', forbidden)


@pytest.fixture
def patch_record(tmp_path, monkeypatch):
    """Fake upstream object store and AST; not a real vulnerability example."""
    commit, parent = 'a' * 40, 'b' * 40
    before = 'def changed():\n    return 1\n\ndef control():\n    return 0\n'
    after = 'def changed():\n    return 2\n\ndef control():\n    return 0\n'
    upstream = 'https://github.com/localguard-unit-fixtures/NOT-REAL'
    def fake_git(repo, *args):
        if args == ('remote', 'get-url', 'origin'):
            return upstream
        if args == ('rev-parse', '--verify', commit + '^{commit}'):
            return commit
        if args == ('rev-parse', '--verify', commit + '^'):
            return parent
        if args == ('show', '-s', '--format=%B', commit):
            return 'Explicit fake test message referencing CVE-2099-999999'
        if args == ('show', parent + ':sample.py'):
            return before
        if args == ('show', commit + ':sample.py'):
            return after
        raise AssertionError(f'Unexpected fake Git query: {args}')
    monkeypatch.setattr(training, '_git', fake_git)
    monkeypatch.setattr(training.SourceParser, 'summary', lambda *args: {'parse_error': False, 'nodes': [
        {'type': 'function_definition', 'start_line': 1, 'end_line': 2},
        {'type': 'function_definition', 'start_line': 4, 'end_line': 5},
    ]})
    return {'id': 'explicit-unit-fixture-patch', 'source': 'cve_patch',
            'provenance': {'repository': str(tmp_path), 'upstream_url': upstream, 'commit': commit, 'cve': 'CVE-2099-999999'},
            'functions': {
                'vulnerable': {'path': 'sample.py', 'start_line': 1, 'end_line': 2, 'code': 'def changed():\n    return 1'},
                'fixed': {'path': 'sample.py', 'start_line': 1, 'end_line': 2, 'code': 'def changed():\n    return 2'},
                'unchanged': {'path': 'sample.py', 'start_line': 4, 'end_line': 5, 'fixed_start_line': 4, 'fixed_end_line': 5, 'code': 'def control():\n    return 0'},
            }}


@pytest.fixture
def dialogue_record(tmp_path):
    reference = 'https://security.localguard-fixtures.org/NOT-A-REAL-ADVISORY'
    text = f'Explicit unit fixture, not a real event. CVE-2099-999999 {reference}'
    artifact = tmp_path / 'fixture-advisory.txt'
    artifact.write_text(text, encoding='utf-8')
    return {'id': 'explicit-unit-fixture-dialogue', 'source': 'security_dialogue',
            'provenance': {'reference': reference, 'cve': 'CVE-2099-999999', 'artifact': str(artifact), 'sha256': sha(text)},
            'cwe': 'CWE-89', 'owasp': 'A03:2021', 'language': 'python',
            'vulnerable_implementation': 'query = user_text', 'safe_implementation': 'query = parameterized_query',
            'attack_demo': {'text': 'Nonexecuting fixture demonstration only', 'nonexecuting': True},
            'remediation': 'Use parameterized queries.'}


@pytest.fixture
def tool_record(tmp_path):
    """Fake local log artifacts explicitly stand in for real runtime evidence."""
    source = tmp_path / 'sample.py'
    source.write_text('fixture_code()', encoding='utf-8')
    session = 'unit-test-session'
    result = {'path': str(source), 'start_line': 1, 'end_line': 1, 'total_lines': 1,
              'hash': sha('fixture_code()'), 'lines': [{'line': 1, 'text': 'fixture_code()', 'tokens': []}],
              'language': 'python', 'parse_error': False, 'truncated': False}
    call = {'name': 'view_file', 'arguments': {'path': str(source), 'start_line': 1, 'end_line': 1}}
    logs = []
    class FakeStore:
        def log(self, **payload):
            logs.append(payload)
    model = LocalModel(None, FakeStore())
    model._interaction('view_file', call['arguments'], {'isError': False, 'data': result}, session, 0.01)
    location = {'path': 'sample.py', 'line': 1, 'snippet_hash': sha('fixture_code()'), 'stale': False}
    issue = {'id': 'unit-issue', 'title': 'Explicit test finding', 'severity': 'low', 'category': 'other', 'cwe': 'CWE-20', 'confidence': 0.5,
             'locations': [location], 'evidence': [{'tool': 'view_file', 'range': [1, 1]}], 'explanation': 'Synthetic fixture only', 'remediation': 'Review input handling', 'needs_human_review': True}
    logs.append({'event': 'location_validated', 'session': session, 'validation': 'passed', 'issue_id': 'unit-issue', 'locations': [location]})
    database = tmp_path / 'fixture.sqlite3'
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE logs(id INTEGER PRIMARY KEY, payload TEXT)')
        db.executemany('INSERT INTO logs(payload) VALUES (?)', [(json.dumps(log),) for log in logs])
    return {'id': 'explicit-unit-fixture-tool', 'source': 'tool_call', 'root': str(tmp_path),
            'provenance': {'database': str(database), 'call_log_id': 1, 'validation_log_ids': [2], 'session': session},
            'call': call, 'result': result, 'issues': [issue]}


def test_patch_validates_local_objects_and_whole_function_triple(patch_record):
    assert training.validate_record(patch_record) is patch_record
    broken = deepcopy(patch_record)
    broken['functions']['unchanged']['code'] = 'fabricated control'
    with pytest.raises(training.DatasetError, match='does not match'):
        training.validate_record(broken)
    broken = deepcopy(patch_record)
    del broken['functions']['unchanged']
    with pytest.raises(training.DatasetError, match='triple'):
        training.validate_record(broken)


def test_patch_requires_upstream_full_commit_and_actual_diff(patch_record):
    for key, value in [('upstream_url', 'https://example.com/fake/repo'), ('commit', 'HEAD')]:
        broken = deepcopy(patch_record)
        broken['provenance'][key] = value
        with pytest.raises(training.DatasetError):
            training.validate_record(broken)
    broken = deepcopy(patch_record)
    broken['functions']['fixed']['code'] = broken['functions']['vulnerable']['code']
    with pytest.raises(training.DatasetError, match='must differ'):
        training.validate_record(broken)


def test_dialogue_requires_pinned_event_and_all_fields(dialogue_record):
    assert training.validate_record(dialogue_record) is dialogue_record
    for key in ('cwe', 'owasp', 'safe_implementation', 'remediation', 'attack_demo'):
        broken = deepcopy(dialogue_record)
        del broken[key]
        with pytest.raises(training.DatasetError):
            training.validate_record(broken)
    broken = deepcopy(dialogue_record)
    broken['provenance']['sha256'] = '0' * 64
    with pytest.raises(training.DatasetError, match='hash'):
        training.validate_record(broken)
    broken = deepcopy(dialogue_record)
    broken['attack_demo']['nonexecuting'] = False
    with pytest.raises(training.DatasetError, match='nonexecuting'):
        training.validate_record(broken)


def test_tool_source_requires_logged_call_hash_range_and_valid_locations(tool_record):
    assert training.validate_record(tool_record) is tool_record
    mutations = [
        lambda r: r['result'].update(hash='0' * 64),
        lambda r: r['result']['lines'][0].update(text='fabricated code'),
        lambda r: r['issues'][0]['locations'][0].update(line=47),
        lambda r: r['provenance'].update(session='different-session'),
        lambda r: r['call']['arguments'].update(start_line=2),
        lambda r: r['provenance'].update(validation_log_ids=[]),
        lambda r: r['issues'][0]['locations'][0].update(stale=True),
    ]
    for mutate in mutations:
        broken = deepcopy(tool_record)
        mutate(broken)
        with pytest.raises(training.DatasetError):
            training.validate_record(broken)


@pytest.mark.parametrize('prose', ['problem at line 47', 'Lines 2-3 contain the issue', '在第 47 行', 'sample.py:47', 'See L47'])
def test_natural_language_positions_forbidden(tool_record, prose):
    tool_record['issues'][0]['explanation'] = prose
    with pytest.raises(training.DatasetError, match='Natural-language'):
        training.validate_record(tool_record)


def test_synthetic_flag_and_negative_examples_never_positive(dialogue_record):
    dialogue_record['synthetic'] = True
    with pytest.raises(training.DatasetError, match='Synthetic'):
        training.validate_record(dialogue_record)
    del dialogue_record['synthetic']
    dialogue_record['negative'] = True
    with pytest.raises(training.DatasetError, match='negatives'):
        training.validate_record(dialogue_record)


def test_dataset_requires_all_sources_and_unique_ids(tmp_path, patch_record, dialogue_record, tool_record):
    path = tmp_path / 'synthetic-fixtures.jsonl'
    path.write_text(json.dumps(patch_record) + '\n', encoding='utf-8')
    with pytest.raises(training.DatasetError, match='All three'):
        training.load_dataset([path])
    records = [patch_record, dialogue_record, tool_record]
    path.write_text('\n'.join(json.dumps(r) for r in records), encoding='utf-8')
    assert len(training.load_dataset([path])) == 3
    path.write_text('\n'.join(json.dumps(r) for r in records + [dialogue_record]), encoding='utf-8')
    with pytest.raises(training.DatasetError, match='Duplicate'):
        training.load_dataset([path])


def test_sqlite_negatives_separate_and_secrets_never_exported(tool_record):
    database = Path(tool_record['provenance']['database'])
    with sqlite3.connect(database) as db:
        db.execute('INSERT INTO logs(payload) VALUES (?)', (json.dumps({'event': 'location_rejected', 'negative_sample': {'explanation': 'TEST_SECRET_VALUE', 'locations': [{'path': 'secret-file.py', 'line': 999}]}}),))
    result = training.ingest_logs(database)
    assert len(result['negative_examples']) == 1
    assert result['positive_targets'] == []
    assert len(result['interactions']) == 2
    assert 'TEST_SECRET_VALUE' not in json.dumps(result)
    assert 'secret-file.py' not in json.dumps(result)
    assert all(not row['training_ready'] for row in result['negative_examples'])


def rows():
    """Explicit fake measured predictions for testing metric arithmetic only."""
    return [
        {'id': 'positive', 'label': True, 'predicted': True, 'score': 0.9, 'cwe': 'CWE-89', 'predicted_cwe': 'CWE-89', 'locations': [{'path': 'a.py', 'line': 2}], 'predicted_locations': [{'path': 'a.py', 'line': 2}], 'tool_format_valid': True},
        {'id': 'negative-one', 'label': False, 'predicted': True, 'score': 0.6, 'cwe': '', 'predicted_cwe': 'CWE-89', 'locations': [], 'predicted_locations': [{'path': 'b.py', 'line': 1}], 'tool_format_valid': True},
        {'id': 'negative-two', 'label': False, 'predicted': False, 'score': 0.1, 'cwe': '', 'predicted_cwe': '', 'locations': [], 'predicted_locations': [], 'tool_format_valid': True},
    ]


def test_metrics_exact_arithmetic_and_tied_auc():
    metrics = training.evaluate(rows())
    assert metrics['detection_precision'] == 0.5
    assert metrics['false_positive_rate'] == 0.5
    assert metrics['cwe_accuracy'] == metrics['exact_line_accuracy'] == metrics['tool_format_success'] == metrics['auc'] == 1.0
    tied = rows()
    for row in tied:
        row['score'] = 0.5
    assert training.evaluate(tied)['auc'] == 0.5


def test_gate_requires_paired_no_regression_and_fpr_improvement():
    before, after = rows(), rows()
    assert not training.compare_evaluations(before, after)['passed']
    after[1].update(predicted=False, score=0.2, predicted_cwe='', predicted_locations=[])
    assert training.compare_evaluations(before, after)['passed']
    after[0]['predicted_locations'] = [{'path': 'a.py', 'line': 47}]
    gate = training.compare_evaluations(before, after)
    assert not gate['passed']
    assert 'exact_line_accuracy: regression' in gate['reasons']
    after[0]['id'] = 'different-evaluation-sample'
    with pytest.raises(training.DatasetError, match='identical held-out'):
        training.compare_evaluations(before, after)


def test_undefined_metrics_and_bad_scores_fail_closed():
    one_class = rows()[:1]
    assert training.evaluate(one_class)['auc'] is None
    assert not training.compare_evaluations(one_class, one_class)['passed']
    invalid = rows()
    invalid[0]['score'] = float('nan')
    with pytest.raises(training.DatasetError, match='finite'):
        training.evaluate(invalid)
    with pytest.raises(training.DatasetError, match='positive'):
        training.compare_evaluations(rows(), rows(), min_fpr_improvement=0)


def test_tool_training_preserves_read_before_citation(tool_record):
    messages = training.training_messages(tool_record)
    assert [m['role'] for m in messages] == ['system', 'user', 'assistant', 'tool', 'assistant']
    assert messages[2]['tool_calls'][0]['function']['name'] == 'view_file'
    assert json.loads(messages[-1]['content'])['issues'][0]['locations']


class TemplateTokenizer:
    chat_template = 'test-template'
    pad_token = None
    eos_token = '</end>'
    padding_side = 'right'

    def apply_chat_template(self, messages, add_generation_prompt=False, **options):
        assert options['enable_thinking'] is False
        rendered = ''.join(message['role'] + ':' + json.dumps(message.get('content', ''), ensure_ascii=False) + '\n' for message in messages)
        return rendered + ('assistant:' if add_generation_prompt else '')

    def __call__(self, text, **options):
        return {'input_ids': [ord(character) for character in text]}


def test_token_preflight_masks_inputs_without_wasted_padding(dialogue_record):
    examples, lengths = training.prepare_training_examples(TemplateTokenizer(), [dialogue_record])
    assert len(examples) == len(lengths) == 2
    for example, length in zip(examples, lengths):
        assert len(example['input_ids']) == length['tokens'] < 4096
        assert example['labels'].count(-100) + length['supervised_tokens'] == length['tokens']
        assert example['labels'][0] == -100
        assert example['labels'][-1] != -100


def test_token_preflight_rejects_oversized_turns(dialogue_record):
    dialogue_record['vulnerable_implementation'] = 'x' * 4097
    with pytest.raises(training.DatasetError, match='exceeds seq4096'):
        training.prepare_training_examples(TemplateTokenizer(), [dialogue_record])


def test_train_rejects_bad_settings_and_hub_id_before_import_or_load(tmp_path):
    with pytest.raises(training.DatasetError, match='rank'):
        training.train_adapter(tmp_path, [], tmp_path / 'output', rank=8)
    with pytest.raises(training.DatasetError, match='absolute local'):
        training.train_adapter(Path('organization/model'), [], tmp_path / 'output')
    with pytest.raises(training.DatasetError, match='all three'):
        training.train_adapter(tmp_path, [], tmp_path / 'output')
