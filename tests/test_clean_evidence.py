"""Clean-evidence training records cannot be fabricated.

The optional fourth training layer must be corroborated by a genuine view_file
log and a genuine logged zero-finding patterns scan with a matching artifact.
These tests use explicit unit fixtures only; they are never promoted to data.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from copy import deepcopy

import pytest

from localguard.training import validate_record


def _sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture
def clean_record(tmp_path):
    source = tmp_path / 'clean.py'
    source.write_text('api_key = os.environ["API_KEY"]\nauth_bypass = False\n', encoding='utf-8')
    session = 'unit-clean-session'
    path = str(source.resolve())
    result = {'path': path, 'start_line': 1, 'end_line': 2, 'total_lines': 2,
              'hash': _sha('api_key = os.environ["API_KEY"]\nauth_bypass = False'),
              'language': 'python', 'parse_error': False, 'truncated': False,
              'lines': [
                  {'line': 1, 'text': 'api_key = os.environ["API_KEY"]',
                   'tokens': [{'start': 0, 'end': 7, 'type': 'identifier'}]},
                  {'line': 2, 'text': 'auth_bypass = False', 'tokens': []},
              ]}
    args = {'path': path, 'start_line': 1, 'end_line': 2}
    expected_args = {'path_hash': _sha(path), 'start_line': 1, 'end_line': 2}
    expected_result = {key: result[key] for key in ('hash', 'start_line', 'end_line', 'total_lines')}
    expected_result['path_hash'] = _sha(path)
    expected_result['line_hashes'] = [
        {'line': row['line'], 'snippet_hash': _sha(row['text'])} for row in result['lines']]
    scan = {'scanner': 'patterns', 'status': 'completed', 'findings': [], 'raw': {},
            'warnings': [], 'truncated': False}
    raw = json.dumps(scan, ensure_ascii=False).encode('utf-8')
    artifact = tmp_path / 'scan.json'
    artifact.write_bytes(raw)
    database = tmp_path / 'state.sqlite3'
    logs = [
        {'event': 'tool_evidence', 'genuine': True, 'isError': False, 'tool_name': 'view_file',
         'session_hash': _sha(session), 'arguments': expected_args, 'result': expected_result},
        {'event': 'tool_call', 'tool_name': 'run_scanner', 'validation': 'passed',
         'session': session, 'arguments': {'scanner': 'patterns', 'target': str(tmp_path)},
         'summary': {'isError': False, 'issues': 0, 'error': None, 'keys': [], 'issues': 0}},
    ]
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE logs(id INTEGER PRIMARY KEY, payload TEXT)')
        db.executemany('INSERT INTO logs(payload) VALUES (?)', [(json.dumps(log),) for log in logs])
    return {'id': 'unit-clean-evidence', 'source': 'clean_evidence', 'root': str(tmp_path),
            'call': {'name': 'view_file', 'arguments': args}, 'result': result, 'issues': [],
            'explanation': 'Unit fixture with a genuine logged zero-finding scan',
            'provenance': {'database': str(database), 'call_log_id': 1, 'scan_log_id': 2,
                           'scan_artifact': str(artifact.resolve()),
                           'scan_sha256': hashlib.sha256(raw).hexdigest(), 'session': session}}


def test_clean_evidence_requires_genuine_logs(clean_record):
    assert validate_record(clean_record) is clean_record


@pytest.mark.parametrize('mutate', [
    lambda r: r['issues'].append({'id': 'fake'}),
    lambda r: r['provenance'].__setitem__('scan_sha256', '0' * 64),
    lambda r: r['provenance'].__setitem__('scan_log_id', 1),
    lambda r: r['provenance'].__setitem__('session', 'another-session'),
    lambda r: r['call']['arguments'].__setitem__('end_line', 99),
])
def test_fabricated_clean_evidence_is_rejected(clean_record, mutate):
    broken = deepcopy(clean_record)
    mutate(broken)
    with pytest.raises(Exception):
        validate_record(broken)
