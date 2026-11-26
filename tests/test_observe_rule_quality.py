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
    # smoke event has no audit_id but resolves via issue -> excluded_audit_event
    assert len(c['exclusions']) == 1
    assert c['exclusions'][0]['reason'] == 'excluded_audit_event'
    assert c['exclusions'][0]['issue_id'] == 'ISSUE-SMOKE'
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
    assert d['scanner_failures'] == 1 and d['scanner_failure_rate_all'] == 0.5
    assert d['scanner_failure_rate_clean'] == 'N/A'  # scanner events lack audit_id -> unattributed
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
    assert d['location_error_event_rate_all'] == 0.5
    # validated resolves to a job -> clean denominator exists; rejected does not
    assert d['location_error_event_rate_clean'] == 0.0
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
    assert d2['distinct_real_issue_ids'] == 0
    assert all(x['reason'] == 'excluded_audit_event' for x in d2['excluded_samples'])
    d3 = summarize(collect(db, 30644, exclude_targets={'E:/real/repo'}))
    assert d3['distinct_real_issue_ids'] == 0
    assert d3['excluded_audits'] == sorted(['REAL']) or 'REAL' in d3['excluded_audits']


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
    # Issue hash repeats across audits: collect all non-excluded audits;
    # A1 unreviewed ignored, A2 confirmed is a valid decision.
    assert d['reviewed_total'] == 1 and d['unreviewed_total'] == 0
    assert d['rules'][0]['human_confirmation_rate'] == 1.0


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
        (30645, {'event': 'scanner_completed', 'audit_id': 'A1', 'session': 'A1',
                 'scanner': 'patterns', 'status': 'completed'}),
        (30646, {'event': 'location_validated', 'issue_id': 'I1', 'audit_id': 'A1', 'session': 'A1'}),
        (30647, {'event': 'scanner_completed', 'audit_id': 'SMOKE',
                 'scanner': 'semgrep', 'status': 'failed', 'session': 'SMOKE'}),
        (30648, {'event': 'location_rejected', 'audit_id': 'SMOKE', 'session': 'SMOKE',
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


def test_no_audit_id_location_event_resolves_to_excluded_audit(tmp_path):
    # location_validated has NO audit_id in real engine; its issue belongs to a
    # known smoke audit -> must be excluded before global rates are computed.
    logs = [
        (30645, {'event': 'location_validated', 'issue_id': 'I-SMOKE'}),
        (30646, {'event': 'location_validated', 'issue_id': 'I-REAL', 'audit_id': 'A1'}),
    ]
    jobs = [job('A1', [issue('I-REAL')]),
            job('65dcb65d663c47ebb900d70a4f706e59', [issue('I-SMOKE')])]
    db = make_db(tmp_path, logs, jobs)
    c = collect(db, 30644)
    d = summarize(c)
    assert any(e.get('issue_id') == 'I-SMOKE' and e['reason'] == 'excluded_audit_event'
               for e in c['exclusions'])
    assert d['location_validated_events'] == 1  # smoke event excluded entirely
    assert d['distinct_real_issue_ids'] == 1


def test_unattributed_events_excluded_from_clean_metrics(tmp_path):
    # scanner_completed with no audit_id and no issue -> cannot be attributed.
    logs = [
        (30645, {'event': 'scanner_completed', 'scanner': 'patterns', 'status': 'failed'}),
        (30646, {'event': 'scanner_completed', 'audit_id': 'A1',
                 'scanner': 'semgrep', 'status': 'completed'}),
    ]
    db = make_db(tmp_path, logs, [job('A1', [issue('I1')])])
    d = summarize(collect(db, 30644))
    assert d['scanner_completed_events'] == 2 and d['scanner_failures'] == 1
    assert d['scanner_failure_rate_all'] == 0.5
    # Unattributed failed event is NOT in clean metrics.
    # Explicit audit_id event is clean; pointer-less event is unattributed.
    assert d['scanner_completed_events_clean'] == 1 and d['scanner_failures_clean'] == 0
    assert d['scanner_failure_rate_clean'] == 0.0
    assert d['unattributed_event_count'] == 1
    assert 'ALL' in d['scanner_failure_data_source'] and 'CLEAN' in d['scanner_failure_data_source']


def test_markdown_cli_with_excluded_events_succeeds(tmp_path):
    import subprocess
    import sys
    logs = [
        (30645, {'event': 'scanner_completed', 'audit_id': 'SMOKE', 'session': 'SMOKE',
                 'scanner': 'semgrep', 'status': 'failed'}),
        (30646, {'event': 'location_validated', 'issue_id': 'I1', 'audit_id': 'A1', 'session': 'A1'}),
    ]
    db = make_db(tmp_path, logs, [job('A1', [issue('I1')]), job('SMOKE', [issue('I-S')])])
    md = tmp_path / 'report.md'
    script = Path(__file__).resolve().parents[1] / 'scripts/observe_rule_quality.py'
    proc = subprocess.run([sys.executable, str(script), '--db', str(db),
                           '--since-log-id', '30644',
                           '--exclude-audit-id', 'SMOKE', '--md-out', str(md)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert md.is_file() and '排除清单' in md.read_text(encoding='utf-8')
    assert 'log#' in md.read_text(encoding='utf-8')  # event-type record rendered


def test_cross_audit_issue_hash_aggregates_fields_and_reviews(tmp_path):
    # Same issue_id (path:line:rule hash) in two audits: A2 has richer
    # structured fields and the only valid review. Must aggregate, not keep A1.
    iid = 'ISSUE-SHARED'
    bare = {'id': iid, 'title': 'finding', 'review': 'unreviewed',
            'evidence': [], 'locations': []}
    logs = [
        (30645, {'event': 'location_validated', 'issue_id': iid, 'audit_id': 'A1',
                 'rule_id': 'lg.ext.old', 'scanner': 'patterns', 'path': 'old.py', 'line': 1}),
        (30646, {'event': 'location_validated', 'issue_id': iid, 'audit_id': 'A2',
                 'rule_id': 'lg.ext.new', 'scanner': 'semgrep', 'path': 'new.py', 'line': 9}),
    ]
    jobs = [job('A1', [bare]), job('A2', [bare])]
    db = make_db(tmp_path, logs, jobs, [('A2', iid, 'confirmed')])
    c = collect(db, 30644)
    d = summarize(c)
    f = c['findings'][iid]
    assert f['occurrence_count'] == 2 and set(f['audit_ids']) == {'A1', 'A2'}
    # Conflicting structured fields are explicitly reported, not silently lost.
    assert f['field_conflicts'].get('rule_id') == ['lg.ext.new', 'lg.ext.old']
    assert any(x['issue_id'] == iid for x in d['field_conflicts'])
    # Valid review from A2 is honored (not tied to arbitrary first occurrence).
    assert d['reviewed_total'] == 1
    assert iid in d['conflicted_findings']  # conflicted -> not in any concrete rule
    assert d['rules'] == []  # no non-conflicted findings in this fixture


def test_conflicting_reviews_are_listed_not_silently_overwritten(tmp_path):
    iid = 'ISSUE-CONFLICT'
    logs = [(30645, {'event': 'location_validated', 'issue_id': iid, 'audit_id': 'A1'}),
            (30646, {'event': 'location_validated', 'issue_id': iid, 'audit_id': 'A2'})]
    jobs = [job('A1', [issue(iid)]), job('A2', [issue(iid)])]
    db = make_db(tmp_path, logs, jobs,
                 [('A1', iid, 'confirmed'), ('A2', iid, 'false_positive')])
    d = summarize(collect(db, 30644))
    assert d['reviewed_total'] == 0  # conflicting -> not resolved
    assert len(d['review_conflicts']) == 1
    assert d['review_conflicts'][0]['issue_id'] == iid
    assert set(d['review_conflicts'][0]['decisions'].values()) == {'confirmed', 'false_positive'}


def test_session_preferred_for_audit_resolution(tmp_path):
    # Same issue in REAL and SMOKE; event session points to REAL exactly.
    iid = 'ISSUE-SHARED'
    logs = [(30645, {'event': 'location_validated', 'issue_id': iid,
                     'session': 'base:REAL', 'audit_id': None})]
    jobs = [job('REAL', [issue(iid)]),
            job('65dcb65d663c47ebb900d70a4f706e59', [issue(iid)])]
    db = make_db(tmp_path, logs, jobs)
    c = collect(db, 30644)
    d = summarize(c)
    assert not c['exclusions']  # session resolved to REAL, no exclusion
    assert d['distinct_real_issue_ids'] == 1
    assert c['findings'][iid]['audit_ids'] == ['REAL']


def test_ambiguous_issue_audit_is_not_force_excluded(tmp_path):
    iid = 'ISSUE-AMB'
    logs = [(30645, {'event': 'location_validated', 'issue_id': iid})]  # no session
    jobs = [job('REAL', [issue(iid)]),
            job('65dcb65d663c47ebb900d70a4f706e59', [issue(iid)])]
    db = make_db(tmp_path, logs, jobs)
    c = collect(db, 30644)
    assert not c['exclusions']  # candidates {REAL, SMOKE}: ambiguous, not force-excluded
    assert len(c['ambiguous_events']) == 1
    assert set(c['ambiguous_events'][0]['candidate_audits']) == {
        'REAL', '65dcb65d663c47ebb900d70a4f706e59'}
    assert c['findings'][iid]['audit_ids'] == ['REAL']  # SMOKE not in occurrences


def test_structured_value_beats_fallback(tmp_path):
    iid = 'ISSUE-PRIO'
    logs = [(30645, {'event': 'location_validated', 'issue_id': iid, 'audit_id': 'A',
                     'session': 'A', 'rule_id': 'z.new', 'scanner': 'semgrep',
                     'path': 'new.py', 'line': 9})]
    # issue evidence/fallback says a.old / patterns / old.py / 1
    db = make_db(tmp_path, logs, [job('A', [issue(iid, rule='a.old', path='old.py', line=1)])])
    c = collect(db, 30644)
    f = c['findings'][iid]
    assert f['rule_id'] == 'z.new' and f['scanner'] == 'semgrep'
    assert f['path'] == 'new.py' and f['line'] == 9
    assert not f['field_conflicts']  # no conflict: structured wins cleanly


def test_review_from_unrelated_audit_does_not_leak(tmp_path):
    iid = 'ISSUE-LEAK'
    logs = [(30645, {'event': 'location_validated', 'issue_id': iid,
                     'audit_id': 'REAL', 'session': 'REAL'})]
    db = make_db(tmp_path, logs, [job('REAL', [issue(iid)])],
                 [('UNRELATED', iid, 'confirmed')])  # UNRELATED audit has no such issue
    d = summarize(collect(db, 30644))
    assert d['reviewed_total'] == 0 and d['unreviewed_total'] == 1
    assert d['rules'][0]['human_confirmation_rate'] == 'N/A'


def test_conflicted_finding_excluded_from_rule_metrics(tmp_path):
    iid = 'ISSUE-CONF'
    logs = [
        (30645, {'event': 'location_validated', 'issue_id': iid, 'audit_id': 'A1',
                 'session': 'A1', 'rule_id': 'r.one'}),
        (30646, {'event': 'location_validated', 'issue_id': iid, 'audit_id': 'A2',
                 'session': 'A2', 'rule_id': 'r.two'}),
    ]
    db = make_db(tmp_path, logs, [job('A1', [issue(iid)]), job('A2', [issue(iid)])])
    d = summarize(collect(db, 30644))
    assert d['conflicted_finding_count'] == 1 and iid in d['conflicted_findings']
    assert d['rules'] == []  # no concrete rule gets the conflicted finding
    assert d['distinct_real_issue_ids'] == 1  # still a real finding overall


def test_nonmetric_unattributed_noise_is_separated(tmp_path):
    logs = [
        (30645, {'event': 'tool_call', 'tool_name': 'view_file'}),
        (30646, {'event': 'tool_evidence', 'genuine': True}),
        (30647, {'event': 'model_explanations', 'count': 1}),
        (30648, {'event': 'location_validated', 'issue_id': 'I1',
                 'audit_id': 'A', 'session': 'A'}),
    ]
    db = make_db(tmp_path, logs, [job('A', [issue('I1')])])
    d = summarize(collect(db, 30644))
    assert d['nonmetric_unattributed_count'] == 3
    assert d['unattributed_event_count'] == 0  # only metric-relevant events listed
    assert d['location_validated_events_clean'] == 1


def test_full_history_diagnostic_has_no_tool_noise(tmp_path):
    # A full-history style fixture: many tool events, few metric events with
    # resolvable sessions; clean denominator must keep the session-resolved ones.
    logs = []
    lid = 30645
    for _ in range(20):
        logs.append((lid, {'event': 'tool_call'})); lid += 1
        logs.append((lid, {'event': 'tool_evidence'})); lid += 1
    for i in range(5):
        logs.append((lid, {'event': 'location_validated', 'issue_id': f'I{i}',
                           'session': 'A', 'audit_id': 'A'})); lid += 1
    jobs = [job('A', [issue(f'I{i}') for i in range(5)])]
    db = make_db(tmp_path, logs, jobs)
    d = summarize(collect(db, 30644))
    assert d['nonmetric_unattributed_count'] == 40
    assert d['unattributed_event_count'] == 0
    assert d['location_validated_events_clean'] == 5  # not dropped by tool noise


def test_explicit_audit_id_beats_missing_session_and_issue(tmp_path):
    # scanner_completed with explicit audit_id but no session/issue must be
    # resolved and counted in CLEAN metrics (highest priority).
    logs = [(30645, {'event': 'scanner_completed', 'audit_id': 'A1',
                     'scanner': 'patterns', 'status': 'completed'})]
    db = make_db(tmp_path, logs, [job('A1', [issue('I1')])])
    c = collect(db, 30644)
    d = summarize(c)
    assert c['unattributed_events'] == []
    assert d['scanner_completed_events'] == 1
    assert d['scanner_completed_events_clean'] == 1
    assert d['scanner_failure_rate_clean'] == 0.0


def test_failed_audit_fields_do_not_pollute_completed_finding(tmp_path):
    iid = 'ISSUE-POLLUTE'
    logs = [
        (30645, {'event': 'location_validated', 'issue_id': iid, 'audit_id': 'REAL',
                 'session': 'REAL', 'rule_id': 'rule.real', 'scanner': 'semgrep'}),
        (30646, {'event': 'location_validated', 'issue_id': iid, 'audit_id': 'FAILED',
                 'session': 'FAILED', 'rule_id': 'rule.bad', 'scanner': 'gitleaks'}),
    ]
    # Only REAL is allowed (FAILED is not a completed job in jobs list).
    db = make_db(tmp_path, logs, [job('REAL', [issue(iid, rule='fallback.old')])])
    c = collect(db, 30644)
    f = c['findings'][iid]
    assert f['rule_id'] == 'rule.real' and f['scanner'] == 'semgrep'
    assert not f['field_conflicts']  # failed-audit fields must not create conflict


def test_two_nonexcluded_audits_same_issue_are_ambiguous(tmp_path):
    iid = 'ISSUE-AMB2'
    logs = [(30645, {'event': 'location_validated', 'issue_id': iid})]  # no session/audit_id
    jobs = [job('A1', [issue(iid)]), job('A2', [issue(iid)])]
    c = collect(make_db(tmp_path, logs, jobs), 30644)
    assert len(c['ambiguous_events']) == 1
    assert set(c['ambiguous_events'][0]['candidate_audits']) == {'A1', 'A2'}
    assert not c['exclusions']  # neither audit excluded
    d = summarize(c)
    # Ambiguous metric event is kept unclean -> clean denominator excludes it.
    assert d['location_validated_events'] == 1
    assert d['location_validated_events_clean'] == 0


def test_full_history_explicit_scanner_audit_ids_are_clean(tmp_path):
    # 75 explicit-audit scanner_completed events: none may be unattributed.
    logs = []
    lid = 30645
    for i in range(75):
        logs.append((lid, {'event': 'scanner_completed', 'audit_id': f'A{i}',
                           'scanner': 'patterns', 'status': 'completed'})); lid += 1
    jobs = [job(f'A{i}', [issue(f'I{i}')]) for i in range(75)]
    d = summarize(collect(make_db(tmp_path, logs, jobs), 30644))
    assert d['scanner_completed_events'] == 75
    assert d['scanner_completed_events_clean'] == 75
    assert d['unattributed_event_count'] == 0
    assert d['scanner_failure_rate_clean'] == 0.0
