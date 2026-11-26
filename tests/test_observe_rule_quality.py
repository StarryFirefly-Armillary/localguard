"""READ-ONLY observation stats: dedupe, exclusions, N/A, review denominators."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from scripts.observe_rule_quality import (
    DEFAULT_DB, ROOT, collect, connect_ro, summarize)


def make_db(tmp_path: Path, logs: list[tuple], jobs: list[tuple], reviews=()) -> Path:
    db = tmp_path / 'state.sqlite3'
    con = sqlite3.connect(db)
    con.executescript('''
        CREATE TABLE logs(id INTEGER PRIMARY KEY, time REAL, payload TEXT);
        CREATE TABLE jobs(id TEXT PRIMARY KEY, session TEXT, created REAL, state TEXT,
                          args TEXT, result TEXT, pid INTEGER, started REAL, configuration TEXT);
        CREATE TABLE reviews(audit_id TEXT, issue_id TEXT, decision TEXT, PRIMARY KEY(audit_id,issue_id));
    ''')
    for lid, payload in logs:
        con.execute('INSERT INTO logs(id,time,payload) VALUES(?,?,?)',
                    (lid, 0, payload if isinstance(payload, str) else json.dumps(payload)))
    for jid, session, args, result in jobs:
        con.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)',
                    (jid, session, 0, 'completed', json.dumps(args), json.dumps(result), 0, 0, 'default'))
    for aid, iid, decision in reviews:
        con.execute('INSERT INTO reviews VALUES(?,?,?)', (aid, iid, decision))
    con.commit()
    con.close()
    return db


def issue(iid, rule='patterns.reverse-shell', path='a.py', line=4, reviewed='unreviewed'):
    return {'id': iid, 'title': 'finding', 'review': reviewed,
            'evidence': [{'tool': 'patterns', 'rule_id': rule, 'raw_ref': '#/matches/2'}],
            'locations': [{'path': path, 'line': line, 'snippet_hash': 'x' * 64, 'stale': False}]}


def job(jid, issues, target='E:/real/repo'):
    return (jid, 's', {'target': target},
            {'audit_id': jid, 'status': 'completed', 'issues': issues})


def test_dedupe_and_exclusions_and_review_denominator(tmp_path):
    logs = [
        (30645, {'event': 'location_validated', 'issue_id': 'ISSUE-1'}),
        (30646, {'event': 'human_review', 'issue_id': 'ISSUE-1', 'audit_id': 'A1'}),
        (30647, {'event': 'location_validated', 'issue_id': 'ISSUE-1'}),  # duplicate
        (30648, {'event': 'location_validated', 'issue_id': 'ISSUE-SMOKE'}),
        (30649, {'event': 'location_validated', 'issue_id': 'ISSUE-2'}),
    ]
    jobs = [job('A1', [issue('ISSUE-1')]),
            job('65dcb65d663c47ebb900d70a4f706e59', [issue('ISSUE-SMOKE')]),
            job('A2', [issue('ISSUE-2', rule='lg.ext.x', path='b.py', line=9)])]
    db = make_db(tmp_path, logs, jobs, [('A1', 'ISSUE-1', 'confirmed')])
    c = collect(db, 30644)
    d = summarize(c)
    assert d['distinct_real_issue_ids'] == 2  # deduped + smoke excluded
    assert len(c['exclusions']) == 1 and 'smoke' in c['exclusions'][0]['reason']
    assert d['reviewed_total'] == 1 and d['unreviewed_total'] == 1
    r1 = next(r for r in d['rules'] if r['rule_id'] == 'patterns.reverse-shell')
    assert r1['finding_count'] == 1 and r1['reviewed_count'] == 1
    assert r1['human_confirmation_rate'] == 1.0 and r1['false_positive_rate'] == 0.0
    assert d['remaining_to_target'] == 48


def test_missing_fields_are_na_not_zero(tmp_path):
    logs = [(30645, {'event': 'location_validated', 'issue_id': 'ISSUE-X'})]
    # issue missing evidence.rule_id and locations -> rule/path/line unavailable
    bare = {'id': 'ISSUE-X', 'title': 'x', 'review': 'unreviewed', 'evidence': [], 'locations': []}
    db = make_db(tmp_path, logs, [job('A', [bare])])
    d = summarize(collect(db, 30644))
    assert d['distinct_real_issue_ids'] == 1
    r = d['rules'][0]
    assert r['rule_id'] is None
    assert r['human_confirmation_rate'] == 'N/A'  # no reviewed denominator
    assert r['false_positive_rate'] == 'N/A'
    assert r['field_completeness']['rule_id'] == 'N/A'
    assert r['field_completeness']['path'] == 'N/A'


def test_location_error_event_level_and_scanner_only_completed(tmp_path):
    logs = [
        (30645, {'event': 'location_validated', 'issue_id': 'ISSUE-1'}),
        (30646, {'event': 'location_rejected', 'negative_sample': {'id': 'ISSUE-1'}}),
        (30647, {'event': 'scanner_completed', 'scanner': 'gitleaks', 'status': 'failed'}),
        (30648, {'event': 'scanner_completed', 'scanner': 'patterns', 'status': 'completed'}),
        (30649, {'event': 'model_triage_failed', 'audit_id': 'A'}),
        (30650, {'event': 'audit_failed', 'audit_id': 'A'}),
    ]
    db = make_db(tmp_path, logs, [job('A', [issue('ISSUE-1')])])
    d = summarize(collect(db, 30644))
    # Event-level location rate: rejected/(validated+rejected) = 1/2.
    assert d['location_error_events'] == 1 and d['location_validated_events'] == 1
    assert d['location_error_event_rate'] == 0.5
    # negative_sample carries an id, so it is attributed (not unattributed).
    assert d['location_rejected_unattributed'] == 0
    # Per-rule metric is explicitly N/A, never a fabricated per-issue rate.
    assert d['rules'][0]['location_error_rate'] == 'N/A'
    # Scanner failures: only scanner_completed with status != completed.
    assert d['scanner_completed_events'] == 2
    assert d['scanner_failures'] == 1 and d['scanner_failure_rate'] == 0.5
    # model_triage_failed/audit_failed reported separately, never in scanner rate.
    assert d['other_pipeline_failures'] == {'model_triage_failed': 1, 'audit_failed': 1}


def test_unattributed_rejection_and_no_scanner_events_are_na(tmp_path):
    logs = [
        (30645, {'event': 'location_rejected', 'reason': 'bad'}),
        (30646, {'event': 'location_validated', 'issue_id': 'ISSUE-1'}),
    ]
    db = make_db(tmp_path, logs, [job('A', [issue('ISSUE-1')])])
    d = summarize(collect(db, 30644))
    assert d['location_rejected_unattributed'] == 1
    assert d['location_error_event_rate'] == 0.5
    assert d['scanner_completed_events'] == 0
    assert d['scanner_failures'] == 0 and d['scanner_failure_rate'] == 'N/A'


def test_explicit_exclusions_only_and_real_title_not_dropped(tmp_path):
    # Titles/paths containing review/eval/test- are REAL findings and must stay.
    real = issue('ISSUE-review-sqli', path='src/review_api.py')
    real['title'] = 'SQL injection in review endpoint (eval route)'
    evalish = issue('ISSUE-test-token', path='tests/test_auth.py')
    evalish['title'] = 'hardcoded token in test helper'
    excluded = issue('ISSUE-explicit', path='x.py')
    logs = [(30645 + i, {'event': 'location_validated', 'issue_id': x['id']})
            for i, x in enumerate((real, evalish, excluded))]
    jobs = [job('REAL', [real, evalish, excluded])]
    db = make_db(tmp_path, logs, jobs)
    # Without explicit flags: all three are real findings (no substring kill).
    d = summarize(collect(db, 30644))
    assert d['distinct_real_issue_ids'] == 3 and d['exclusion_count'] == 0
    # Explicit audit_id / target exclusions are honored with reasons.
    d2 = summarize(collect(db, 30644, exclude_audit_ids={'REAL'}))
    assert d2['distinct_real_issue_ids'] == 0
    reason = d2['excluded_samples'][0]['reason']
    assert reason == 'excluded_audit_id'
    d3 = summarize(collect(db, 30644, exclude_targets={'E:/real/repo'}))
    assert d3['exclusion_count'] == 3
    assert d3['excluded_samples'][0]['reason'] == 'excluded_target'


def test_default_db_and_report_db_are_absolute(tmp_path):
    assert DEFAULT_DB.is_absolute()
    assert DEFAULT_DB == (ROOT / '.localguard/state.sqlite3').resolve()
    db = make_db(tmp_path, [(30645, {'event': 'x'})], [])
    c = collect(db, 30644)  # db from tmp_path is already absolute
    assert Path(c['db']).is_absolute() and c['db'] == str(db.resolve())
    assert isinstance(c['max_log_id'], int)


def test_read_only_connection_never_writes(tmp_path):
    db = make_db(tmp_path, [(30645, {'event': 'x'})], [])
    before = db.stat().st_mtime_ns
    con = connect_ro(db)
    with pytest.raises(sqlite3.OperationalError):
        con.execute('INSERT INTO logs(id,time,payload) VALUES(1,0,"{}")')
    con.close()
    assert db.stat().st_mtime_ns == before


def test_since_log_id_filters_old_events(tmp_path):
    logs = [(30644, {'event': 'location_validated', 'issue_id': 'ISSUE-OLD'}),
            (30645, {'event': 'location_validated', 'issue_id': 'ISSUE-NEW'})]
    db = make_db(tmp_path, logs, [job('A', [issue('ISSUE-OLD'), issue('ISSUE-NEW')])])
    d = summarize(collect(db, 30644))
    assert d['distinct_real_issue_ids'] == 1


def test_structured_log_fields_take_priority_over_empty_issue_evidence(tmp_path):
    # Issue has NO evidence/location identity; structured log carries the truth.
    bare = {'id': 'ISSUE-LOG', 'title': 'finding', 'review': 'unreviewed',
            'evidence': [], 'locations': []}
    logs = [
        (30645, {'event': 'location_validated', 'issue_id': 'ISSUE-LOG', 'audit_id': 'A',
                 'rule_id': 'lg.ext.sqli', 'scanner': 'semgrep',
                 'path': 'src/app.py', 'line': 77, 'engine': 'semgrep'}),
        (30646, {'event': 'model_triage', 'audit_id': 'A', 'verdicts': [
            {'issue_id': 'ISSUE-LOG', 'verdict': 'likely_true',
             'rule_id': 'lg.ext.sqli', 'scanner': 'semgrep',
             'path': 'src/app.py', 'line': 77, 'engine': 'semgrep'}]}),
    ]
    db = make_db(tmp_path, logs, [job('A', [bare])])
    f = collect(db, 30644)['findings']['ISSUE-LOG']
    assert f['rule_id'] == 'lg.ext.sqli'
    assert f['scanner'] == 'semgrep' and f['path'] == 'src/app.py' and f['line'] == 77
    assert f['from_structured_log'] is True
    d = summarize(collect(db, 30644))
    assert d['rules'][0]['rule_id'] == 'lg.ext.sqli'  # grouping uses merged identity


def test_review_matches_audit_id_and_ignores_unreviewed(tmp_path):
    # Two audits share an issue_id; only (audit, issue) exact match is valid.
    iid = 'ISSUE-SHARED'
    logs = [(30645, {'event': 'location_validated', 'issue_id': iid})]
    jobs = [job('A1', [issue(iid)]), job('A2', [issue(iid)])]
    # review for A2 only; another row uses unreviewed (must not count).
    db = make_db(tmp_path, logs, jobs,
                 [('A2', iid, 'confirmed'), ('A1', iid, 'unreviewed')])
    d = summarize(collect(db, 30644))
    # by_issue keeps first job (A1) -> A2 review must NOT leak; unreviewed rejected.
    assert d['reviewed_total'] == 0 and d['unreviewed_total'] == 1
    assert d['rules'][0]['human_confirmation_rate'] == 'N/A'


def test_review_confirmed_and_false_positive_count_as_reviewed(tmp_path):
    logs = [(30645, {'event': 'location_validated', 'issue_id': 'ISSUE-A'}),
            (30646, {'event': 'location_validated', 'issue_id': 'ISSUE-B'})]
    jobs = [job('A', [issue('ISSUE-A'), issue('ISSUE-B')])]
    db = make_db(tmp_path, logs, jobs,
                 [('A', 'ISSUE-A', 'confirmed'), ('A', 'ISSUE-B', 'false_positive')])
    d = summarize(collect(db, 30644))
    assert d['reviewed_total'] == 2 and d['unreviewed_total'] == 0
    r = d['rules'][0]
    assert r['human_confirmation_rate'] == 0.5 and r['false_positive_rate'] == 0.5


def test_excluded_audit_events_do_not_pollute_global_rates(tmp_path):
    # Smoke audit emits a failed scan + rejected location; explicit exclude A2
    # must drop ALL its events before computing global metrics.
    logs = [
        (30645, {'event': 'scanner_completed', 'audit_id': 'A1',
                 'scanner': 'patterns', 'status': 'completed'}),
        (30646, {'event': 'location_validated', 'issue_id': 'I1', 'audit_id': 'A1'}),
        (30647, {'event': 'scanner_completed', 'audit_id': 'SMOKE',
                 'scanner': 'semgrep', 'status': 'failed'}),
        (30648, {'event': 'location_rejected', 'audit_id': 'SMOKE',
                 'negative_sample': {'id': 'I-SMOKE'}}),
    ]
    jobs = [job('A1', [issue('I1')]), job('SMOKE', [issue('I-SMOKE')])]
    db = make_db(tmp_path, logs, jobs)
    c = collect(db, 30644, exclude_audit_ids={'SMOKE'})
    d = summarize(c)
    assert d['scanner_completed_events'] == 1 and d['scanner_failures'] == 0
    assert d['scanner_failure_rate'] == 0.0
    assert d['location_error_events'] == 0 and d['location_error_event_rate'] == 0.0
    assert any(e.get('reason') == 'excluded_audit_event' for e in d['excluded_samples'])


def test_unattributed_events_are_listed_not_silently_counted(tmp_path):
    logs = [
        (30645, {'event': 'scanner_completed', 'scanner': 'patterns', 'status': 'completed'}),
        (30646, {'event': 'location_rejected', 'negative_sample': {'id': 'x'}}),
    ]
    db = make_db(tmp_path, logs, [job('A', [issue('I1')])])
    d = summarize(collect(db, 30644))
    assert d['unattributed_event_count'] == 2
    assert d['unattributed_note'] and d['unattributed_events'][0]['event'] == 'scanner_completed'


def test_orphan_log_issue_not_counted_as_finding(tmp_path):
    logs = [(30645, {'event': 'location_validated', 'issue_id': 'ISSUE-ORPHAN'}),
            (30646, {'event': 'location_validated', 'issue_id': 'ISSUE-REAL'})]
    db = make_db(tmp_path, logs, [job('A', [issue('ISSUE-REAL')])])
    d = summarize(collect(db, 30644))
    assert d['distinct_real_issue_ids'] == 1
    assert 'ISSUE-ORPHAN' in d['orphan_issue_ids'] and d['orphan_count'] == 1
    assert 'ISSUE-ORPHAN' not in {f['issue_id'] for f in collect(db, 30644)['findings'].values()}
