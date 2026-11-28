"""Offline rule-candidate evaluator: redacted, recomputable, store-free."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import evaluate_rule_candidates as ev  # noqa: E402


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _source(tmp_path: Path, name: str, marker: str) -> Path:
    path = tmp_path / 'src' / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'# rule fixture\n{marker}\n', encoding='utf-8')
    return path


def _labeled_item(issue_id: str, rule_id: str, scanner: str, source: Path,
                  decision: str, *, path: str | None = None, line: int = 2) -> dict:
    scope = ('cross_function_required' if issue_id in ev.CONFIRMED_CROSS_FUNCTION_IDS
             else 'file_local')
    return {
        'issue_id': issue_id,
        'rule_id': rule_id,
        'scanner': scanner,
        'path': path or source.name,
        'line': line,
        'human_decision': decision,
        'canonical_location': str(source),
        'file_sha256': _sha(source.read_bytes()),
        'scope': scope,
    }


def _write_json(path: Path, document: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return path


def _make_fixtures(tmp_path: Path) -> dict:
    rp = tmp_path / 'inputs'
    rp.mkdir(exist_ok=True)
    representative = []
    for issue_id in ev.FORCED_REPRESENTATIVE_IDS:
        source = _source(tmp_path, f'{issue_id}.py', 'HIT forced')
        representative.append(_labeled_item(issue_id, 'lg.ext.ssrf-urllib-user-input',
                                            'semgrep', source, 'confirmed'))
    fp_source = _source(tmp_path, 'rep_fp.py', 'HIT false positive')
    representative.append(_labeled_item('ISSUE-REP-FP', 'generic-api-key', 'gitleaks',
                                        fp_source, 'false_positive'))
    fn_source = _source(tmp_path, 'rep_fn.py', 'NO_HIT missed')
    representative.append(_labeled_item('ISSUE-REP-FN', 'lg.ext.command-injection-subprocess-shell',
                                        'semgrep', fn_source, 'confirmed'))
    tn_source = _source(tmp_path, 'rep_tn.py', 'NO_HIT benign')
    representative.append(_labeled_item('ISSUE-REP-TN', 'generic-api-key', 'gitleaks',
                                        tn_source, 'false_positive'))

    offline = []
    off_tp = _source(tmp_path, 'off_tp.py', 'HIT offline true')
    offline.append(_labeled_item('ISSUE-OFF-TP', 'lg.ext.ssrf-urllib-user-input',
                                 'semgrep', off_tp, 'confirmed'))
    off_fp = _source(tmp_path, 'off_fp.py', 'HIT offline false')
    offline.append(_labeled_item('ISSUE-OFF-FP', 'generic-api-key', 'gitleaks',
                                 off_fp, 'false_positive'))

    records, recovery_entries = [], []
    specs = [
        ('generic-api-key', 'gitleaks', 12, 'g'),
        ('lg.ext.ssrf-requests-user-input', 'semgrep', 4, 's'),
        ('lg.ext.command-injection-subprocess-shell', 'semgrep', 1, 'c'),
    ]
    counter = 0
    for rule_id, scanner, count, prefix in specs:
        for _ in range(count):
            counter += 1
            record_id = (ev.GOLD_COMMAND_ID if prefix == 'c' else f'FINDING-{prefix}{counter:03d}')
            source = _source(tmp_path, f'{record_id}.src', 'HIT gold')
            records.append({
                'id': record_id,
                'label': 'likely_true',
                'finding': {'rule_id': rule_id, 'path': source.name, 'line': 2},
                'provenance': {'scanner': scanner, 'target': str(source.parent),
                               'materialized_source_sha256': _sha(source.read_bytes())},
                'scope': 'file_local',
            })
            recovery_entries.append({
                'record_id': record_id,
                'status': 'recovered_network_verified',
                'recovered_file': str(source),
                'expected_sha256': _sha(source.read_bytes()),
            })

    rep_path = _write_json(rp / 'representative.json', {'findings': representative})
    off_path = _write_json(rp / 'offline.json', offline)
    records_path = rp / 'gold_records.jsonl'
    records_path.write_text('\n'.join(json.dumps(row) for row in records) + '\n', encoding='utf-8')
    recovery_path = _write_json(rp / 'recovery.json', {'entries': recovery_entries})
    semgrep_cfg = rp / 'semgrep-candidate.yml'
    semgrep_cfg.write_text('rules:\n  - id: candidate\nSUPPRESS_FP\n', encoding='utf-8')
    gitleaks_cfg = rp / 'gitleaks-candidate.toml'
    gitleaks_cfg.write_text('# SUPPRESS_FP\n', encoding='utf-8')
    return {
        'representative': rep_path,
        'offline': off_path,
        'records': records_path,
        'recovery': recovery_path,
        'semgrep_cfg': semgrep_cfg,
        'gitleaks_cfg': gitleaks_cfg,
    }


def _rule_for_file(path: Path) -> str:
    name = path.name.lower()
    if name.startswith('finding-g') or 'fp' in name or 'tn' in name:
        return 'generic-api-key'
    if 'fn' in name:
        return 'lg.ext.command-injection-subprocess-shell'
    if name.startswith('finding-c'):
        return 'lg.ext.command-injection-subprocess-shell'
    if name.startswith('finding-s'):
        return 'lg.ext.ssrf-requests-user-input'
    return 'lg.ext.ssrf-urllib-user-input'


def _fake_runner(*, suppress_fp: bool = False):
    def runner(scanner: str, root: Path, configs: list[Path], scratch: Path):
        suppress = suppress_fp or any('SUPPRESS_FP' in p.read_text(encoding='utf-8') for p in configs)
        hits = []
        for path in sorted(root.rglob('*')):
            if not path.is_file():
                continue
            for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
                if not line.strip().startswith('HIT '):
                    continue
                if suppress and 'false positive' in line:
                    continue
                rule = _rule_for_file(path)
                if scanner == 'semgrep':
                    hits.append({'check_id': rule, 'path': path.relative_to(root).as_posix(),
                                 'start': {'line': number}})
                else:
                    hits.append({'RuleID': rule, 'File': path.relative_to(root).as_posix(),
                                 'StartLine': number, 'Secret': 'SUPERSECRET_VALUE_123',
                                 'Match': 'password = SUPERSECRET_VALUE_123'})
        if scanner == 'semgrep':
            stdout = json.dumps({'results': hits, 'errors': []}).encode('utf-8')
        else:
            stdout = json.dumps(hits).encode('utf-8')
        return stdout, 0, 0
    return runner


def _run(tmp_path: Path, fixtures: dict, **kwargs):
    return ev.evaluate(
        representative_path=fixtures['representative'],
        offline_path=fixtures['offline'],
        gold_records_path=fixtures['records'],
        gold_recovery_path=fixtures['recovery'],
        output_path=tmp_path / 'out' / 'report.json',
        raw_dir=tmp_path / 'out' / 'raw',
        runner=kwargs.pop('runner', _fake_runner()),
        **kwargs,
    )


def test_tp_fp_fn_and_recomputable_raw(tmp_path):
    fixtures = _make_fixtures(tmp_path)
    report = _run(tmp_path, fixtures)
    baseline = next(v for v in report['variants'] if v['label'] == 'semgrep-baseline')
    rows = {row['issue_id']: row for row in baseline['cases']}

    assert rows['ISSUE-REP-FN']['status'] == 'FN'
    assert rows['ISSUE-OFF-TP']['status'] == 'TP'
    assert report['input_row_count'] == 34
    assert report['unique_case_count'] == 28
    assert report['duplicate_row_count'] == 6
    assert 'overall' not in baseline['metrics']

    raw_text = Path(baseline['raw_file']).read_bytes()
    assert _sha(raw_text) == baseline['raw_sha256']
    hits = json.loads(raw_text)
    recomputed = {'TP': 0, 'FP': 0, 'FN': 0, 'TN': 0}
    for row in baseline['cases']:
        if 'representative50' not in row['cohorts'] or row['evaluation_scope'] != 'file_local':
            continue
        matched = any(hit['path'] == row['materialized_path'] and hit['line'] == row['line']
                      and ev.normalize_rule_id(hit['rule_id']) == ev.normalize_rule_id(row['rule_id'])
                      for hit in hits)
        if row['label'] == 'positive':
            recomputed['TP' if matched else 'FN'] += 1
        else:
            recomputed['FP' if matched else 'TN'] += 1
    cohort_overall = baseline['metrics']['cohorts']['representative50']['overall']
    assert all(recomputed[key] == cohort_overall[key] for key in ('TP', 'FP', 'FN', 'TN'))


def test_candidate_config_changes_result_and_stays_redacted(tmp_path):
    fixtures = _make_fixtures(tmp_path)
    baseline_report = _run(tmp_path / 'base', fixtures)
    candidate_report = _run(tmp_path / 'cand', fixtures,
                            semgrep_candidates=[str(fixtures['semgrep_cfg'])],
                            gitleaks_candidates=[str(fixtures['gitleaks_cfg'])])
    base_g = next(v for v in baseline_report['variants'] if v['label'] == 'gitleaks-baseline')
    cand_g = next(v for v in candidate_report['variants'] if v['label'] == 'gitleaks-candidate-1')
    base_fp = base_g['metrics']['cohorts']['representative50']['overall']['FP']
    cand_fp = cand_g['metrics']['cohorts']['representative50']['overall']['FP']
    assert base_fp > cand_fp
    assert base_g['raw_sha256'] != cand_g['raw_sha256']

    report_text = (tmp_path / 'cand' / 'out' / 'report.json').read_text(encoding='utf-8')
    markdown_text = (tmp_path / 'cand' / 'out' / 'report.md').read_text(encoding='utf-8')
    for text in (report_text, markdown_text):
        assert 'SUPERSECRET_VALUE_123' not in text
        assert 'password =' not in text
        assert '# rule fixture' not in text
        assert 'HIT' not in text


def _offline_with_representative_copy(tmp_path: Path, fixtures: dict, *, flip_label: bool = False) -> Path:
    offline = json.loads(fixtures['offline'].read_text(encoding='utf-8'))
    representative = json.loads(fixtures['representative'].read_text(encoding='utf-8'))['findings']
    copied = dict(representative[0])
    if flip_label:
        copied['human_decision'] = 'false_positive'
    offline.append(copied)
    return _write_json(tmp_path / 'offline_duplicate.json', offline)


def test_location_duplicate_merges_and_keeps_aliases(tmp_path):
    fixtures = _make_fixtures(tmp_path)
    cases = ev.load_labeled_cohort(fixtures['representative'], 'representative50')
    original = next(case for case in cases if case.issue_id == 'ISSUE-REP-FP')
    alias = ev.Case(**{**original.__dict__, 'issue_id': 'ISSUE-LOCATION-ALIAS',
                       'cohorts': ['offline27']})
    result = ev.deduplicate_cases([original, alias], [])
    assert len(result.cases) == 1
    assert result.duplicate_ids[0]['kind'] == 'location'
    assert 'ISSUE-LOCATION-ALIAS' in result.cases[0].aliases
    assert 'ISSUE-LOCATION-ALIAS' in result.duplicate_ids[0]['aliases']
    assert set(result.cases[0].cohorts) == {'representative50', 'offline27'}


def test_cross_cohort_duplicate_counts_once(tmp_path):
    fixtures = _make_fixtures(tmp_path)
    offline = _offline_with_representative_copy(tmp_path, fixtures)
    report = ev.evaluate(
        representative_path=fixtures['representative'],
        offline_path=offline,
        gold_records_path=fixtures['records'],
        gold_recovery_path=fixtures['recovery'],
        output_path=tmp_path / 'out' / 'report.json',
        raw_dir=tmp_path / 'out' / 'raw',
        runner=_fake_runner(),
    )
    assert report['input_row_count'] == 35
    assert report['unique_case_count'] == 28
    assert report['duplicate_row_count'] == 7
    duplicated = [item for item in report['duplicate_ids']
                  if item['issue_id'] == ev.FORCED_REPRESENTATIVE_IDS[0]]
    assert duplicated
    assert set(duplicated[0]['cohorts']) == {'representative50', 'offline27'}


def test_label_conflict_on_duplicate_fails(tmp_path):
    fixtures = _make_fixtures(tmp_path)
    offline = _offline_with_representative_copy(tmp_path, fixtures, flip_label=True)
    with pytest.raises(ev.EvalInputError, match='Label conflict'):
        ev.evaluate(
            representative_path=fixtures['representative'],
            offline_path=offline,
            gold_records_path=fixtures['records'],
            gold_recovery_path=fixtures['recovery'],
            output_path=tmp_path / 'out' / 'report.json',
            raw_dir=tmp_path / 'out' / 'raw',
            runner=_fake_runner(),
        )


def test_forced_references_are_not_summarized(tmp_path):
    fixtures = _make_fixtures(tmp_path)
    report = _run(tmp_path, fixtures)
    assert len(report['forced_references']) == 6
    assert all(item['status'] == 'reference_verified' for item in report['forced_references'])
    assert 'gold_v1_forced_ref' not in report['cohort_counts']
    for variant in report['variants']:
        assert set(variant['metrics']['cohorts']) == set(ev.SUMMARY_COHORTS)
        summary_ids = set()
        for summary in variant['metrics']['cohorts'].values():
            summary_ids.update(summary['false_positive_issue_ids'])
            summary_ids.update(summary['false_negative_issue_ids'])
        assert not summary_ids.intersection(ev.FORCED_REPRESENTATIVE_IDS)
        for issue_id in ev.FORCED_REPRESENTATIVE_IDS:
            rows = [row for row in variant['cases'] if row['issue_id'] == issue_id]
            if rows:
                expected_status = ('N/A_cross_function' if issue_id in ev.CONFIRMED_CROSS_FUNCTION_IDS
                                   else 'TP')
                assert all(row['status'] == expected_status for row in rows)


def test_gold_ssrf_evaluated_and_only_known_cross_function_excluded(tmp_path):
    fixtures = _make_fixtures(tmp_path)
    report = _run(tmp_path, fixtures)
    semgrep = next(v for v in report['variants'] if v['label'] == 'semgrep-baseline')
    gold_summary = semgrep['metrics']['cohorts']['gold_v1']

    assert gold_summary['supported_case_count'] == 5
    assert set(gold_summary['unsupported_case_ids']) == set()
    gold_ssrf_ids = {
        row['issue_id'] for row in semgrep['cases']
        if row['issue_id'].startswith('FINDING-s')
    }
    assert len(gold_ssrf_ids) == 4
    statuses = {row['issue_id']: row['status'] for row in semgrep['cases']}
    assert all(statuses[issue_id] == 'TP' for issue_id in gold_ssrf_ids)

    excluded = set(semgrep['metrics']['unsupported_case_ids'])
    assert excluded == set(ev.CONFIRMED_CROSS_FUNCTION_IDS)
    for issue_id in excluded:
        assert issue_id in ev.FORCED_REPRESENTATIVE_IDS
    excluded_g = set(next(v for v in report['variants']
                          if v['label'] == 'gitleaks-baseline')['metrics']['unsupported_case_ids'])
    assert excluded_g == set()


def test_scope_missing_fails(tmp_path):
    fixtures = _make_fixtures(tmp_path)
    document = json.loads(fixtures['representative'].read_text(encoding='utf-8'))
    document['findings'][8].pop('scope', None)
    bad = _write_json(tmp_path / 'no_scope.json', document)
    with pytest.raises(ev.EvalInputError, match='Missing evaluation scope'):
        ev.load_labeled_cohort(bad, 'representative50')


def test_absolute_scanner_paths_are_stripped_inside_scan_root(tmp_path):
    root = (tmp_path / 'scan').resolve()
    hits, errors = ev.parse_raw_hits(
        'semgrep',
        json.dumps({'results': [{'check_id': 'rules.lg.ext.x', 'path': str(root / 'a.py'),
                                 'start': {'line': 3}}], 'errors': []}).encode('utf-8'),
        scan_root=root,
    )
    assert errors == 0
    assert hits == [{'path': 'a.py', 'line': 3, 'rule_id': 'lg.ext.x'}]


def test_missing_duplicate_and_illegal_path_fail(tmp_path):
    fixtures = _make_fixtures(tmp_path)
    with pytest.raises(ev.EvalInputError, match='Missing input'):
        ev.evaluate(
            representative_path=tmp_path / 'missing.json',
            offline_path=fixtures['offline'],
            gold_records_path=fixtures['records'],
            gold_recovery_path=fixtures['recovery'],
            output_path=tmp_path / 'out' / 'report.json',
            raw_dir=tmp_path / 'out' / 'raw',
            runner=_fake_runner(),
        )

    document = json.loads(fixtures['representative'].read_text(encoding='utf-8'))
    duplicate = dict(document['findings'][0])
    document['findings'].append(duplicate)
    bad = _write_json(tmp_path / 'duplicate.json', document)
    with pytest.raises(ev.EvalInputError, match='Duplicate issue_id'):
        ev.load_labeled_cohort(bad, 'representative50')

    document = json.loads(fixtures['representative'].read_text(encoding='utf-8'))
    document['findings'][0]['path'] = '../escape.py'
    bad = _write_json(tmp_path / 'escape.json', document)
    with pytest.raises(ev.EvalInputError, match='Path traversal'):
        ev.load_labeled_cohort(bad, 'representative50')


def test_evaluator_never_opens_production_store(tmp_path, monkeypatch):
    fixtures = _make_fixtures(tmp_path)
    store = ROOT / '.localguard' / 'state.sqlite3'
    before = _sha(store.read_bytes()) if store.is_file() else None

    def forbidden(*args, **kwargs):
        raise AssertionError('sqlite3.connect must never be called by the evaluator')

    monkeypatch.setattr(sqlite3, 'connect', forbidden)
    report = _run(tmp_path, fixtures)
    after = _sha(store.read_bytes()) if store.is_file() else None
    assert before == after
    assert report['kind'] == 'offline_rule_candidate_eval'
