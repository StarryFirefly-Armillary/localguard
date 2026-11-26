"""READ-ONLY observation-period rule quality statistics.

Open SQLite with mode=ro (never write). Collect real findings from audit logs
with id > --since-log-id and jobs.result, dedupe by issue_id, exclude smoke /
synthetic / eval / review samples with an explicit exclusion list, and report
per-rule quality with N/A (never 0) when a denominator is missing.

No model, no rule changes, no data migration.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = (ROOT / '.localguard' / 'state.sqlite3').resolve()
DEFAULT_SINCE = 30644
# Exclusion is EXPLICIT ONLY: never substring-match title/path/target, which
# would kill real findings such as "SQL injection in review endpoint".
KNOWN_SMOKE_AUDIT_IDS = {'65dcb65d663c47ebb900d70a4f706e59'}


def connect_ro(db: Path) -> sqlite3.Connection:
    """Open a strictly read-only SQLite connection (no writes, no create)."""
    path = Path(db).resolve()
    if not path.is_file():
        raise FileNotFoundError(f'SQLite database not found: {path}')
    con = sqlite3.connect(f'file:{path.as_posix()}?mode=ro', uri=True)
    con.execute('PRAGMA query_only=ON')
    return con


def rule_from_evidence(evidence: list | None) -> str | None:
    """Real rule id: evidence.rule_id first; legacy raw_ref if non-pointer."""
    for ev in evidence or []:
        if not isinstance(ev, dict):
            continue
        rule = ev.get('rule_id')
        if isinstance(rule, str) and rule and not rule.startswith('#/'):
            return rule[:200]
        ref = ev.get('raw_ref')
        if isinstance(ref, str) and ref and not ref.startswith('#/'):
            return ref[:200]
    return None


def scanner_from_evidence(evidence: list | None) -> str | None:
    for ev in evidence or []:
        if not isinstance(ev, dict):
            continue
        tool = ev.get('tool')
        if isinstance(tool, str) and tool and tool != 'view_file':
            return tool[:100]
    return None


def is_excluded(issue: dict, meta: dict, smoke_ids=KNOWN_SMOKE_AUDIT_IDS,
                exclude_audit_ids=(), exclude_targets=()) -> str | None:
    """Return exclusion reason, or None for a real finding.

    Only explicit identifiers are honored: known smoke audit ids, CLI-provided
    audit ids, and CLI-provided exact target matches. Titles, paths and other
    free text are NEVER substring-matched — 'review'/'eval'/'test' in a real
    finding's title must not silently drop it.
    """
    aid = meta.get('audit_id')
    if aid in smoke_ids:
        return 'known_smoke_audit_id'
    if aid in set(exclude_audit_ids):
        return 'excluded_audit_id'
    target = str(meta.get('target') or '')
    if target and target in set(exclude_targets):
        return 'excluded_target'
    return None


def _fields_from_logs(iid: str, log_events: list) -> dict:
    """Structured identity fields from log events for one issue_id."""
    fields = {}
    for _, event in log_events:
        candidates = [event]
        candidates.extend(v for v in (event.get('verdicts') or []) if isinstance(v, dict))
        for candidate in candidates:
            if candidate.get('issue_id') != iid:
                continue
            for k in ('issue_id', 'rule_id', 'scanner', 'path', 'line', 'engine'):
                if candidate.get(k) is not None:
                    fields[k] = candidate[k]
    return fields


def collect(db: Path, since_log_id: int = DEFAULT_SINCE,
            exclude_audit_ids=(), exclude_targets=()) -> dict:
    """Read logs/jobs REVERSE-ONLY. Exclusions apply to ALL log events."""
    db = Path(db).resolve()
    con = connect_ro(db)
    try:
        max_log_id = con.execute('SELECT MAX(id) FROM logs').fetchone()[0]
        raw_events = []
        for log_id, payload in con.execute(
                'SELECT id, payload FROM logs WHERE id > ? ORDER BY id', (since_log_id,)):
            try:
                event = json.loads(payload)
            except (ValueError, TypeError):
                continue
            if isinstance(event, dict):
                raw_events.append((log_id, event))
        jobs = {}
        for jid, session, args, result in con.execute(
                "SELECT id, session, args, result FROM jobs WHERE state='completed'"):
            try:
                a = json.loads(args) if args else {}
                r = json.loads(result) if result else {}
            except (ValueError, TypeError):
                continue
            jobs[jid] = {'audit_id': r.get('audit_id') or jid, 'session': session,
                         'target': str(a.get('target') or r.get('target') or ''),
                         'source': str(a.get('source') or ''), 'result': r}
        reviews = {}
        for aid, iid, decision in con.execute(
                'SELECT audit_id, issue_id, decision FROM reviews'):
            reviews[(aid, iid)] = decision
    finally:
        con.close()

    # 1) Determine exclusion audit set FIRST (explicit only), then filter every
    #    log event — otherwise excluded audits pollute global scanner/location rates.
    excluded_audits = set(KNOWN_SMOKE_AUDIT_IDS) | set(exclude_audit_ids)
    excluded_targets = set(exclude_targets)
    for job in jobs.values():
        if job['target'] and job['target'] in excluded_targets:
            excluded_audits.add(job['audit_id'])

    log_events = []
    unattributed_events = []
    exclusions = []
    for lid, event in raw_events:
        aid = event.get('audit_id')
        if aid and aid in excluded_audits:
            exclusions.append({'log_id': lid, 'event': event.get('event'),
                               'audit_id': aid, 'reason': 'excluded_audit_event'})
            continue
        # Events with no audit_id cannot be tied to an excluded audit — report
        # them explicitly instead of silently counting them in cleaned metrics.
        if not aid and event.get('event') in ('scanner_completed', 'location_rejected',
                                              'location_validated', 'human_review',
                                              'model_triage', 'model_triage_abstained',
                                              'model_triage_failed', 'audit_failed'):
            unattributed_events.append({'log_id': lid, 'event': event.get('event')})
        log_events.append((lid, event))

    # 2) Authoritative issue registry: ONLY issues from completed jobs.
    by_issue = {}
    for job in jobs.values():
        for issue in job['result'].get('issues') or []:
            if isinstance(issue, dict) and issue.get('id'):
                by_issue.setdefault(issue['id'], (issue, job))

    # 3) Only log issue ids that resolve to a completed-job issue are real.
    seen_log_issue_ids = set()
    orphan_issue_ids = set()
    for _, event in log_events:
        ids = [event.get('issue_id')]
        ids.extend(v.get('issue_id') for v in (event.get('verdicts') or [])
                   if isinstance(v, dict))
        for iid in ids:
            if not iid:
                continue
            if iid in by_issue:
                seen_log_issue_ids.add(iid)
            else:
                orphan_issue_ids.add(iid)

    findings = {}
    for iid in sorted(seen_log_issue_ids):
        issue, job = by_issue[iid]
        reason = is_excluded(issue, job, smoke_ids=KNOWN_SMOKE_AUDIT_IDS,
                             exclude_audit_ids=exclude_audit_ids,
                             exclude_targets=exclude_targets)
        if reason:
            exclusions.append({'issue_id': iid, 'reason': reason,
                               'audit_id': job.get('audit_id')})
            continue
        loc = (issue.get('locations') or [{}])[0] if issue.get('locations') else {}
        ev = issue.get('evidence') or []
        structured = _fields_from_logs(iid, log_events)
        merged = {'rule_id': structured.get('rule_id') or rule_from_evidence(ev),
                  'scanner': structured.get('scanner') or scanner_from_evidence(ev),
                  'path': structured.get('path') or (loc.get('path') if isinstance(loc, dict) else None),
                  'line': structured.get('line') if structured.get('line') is not None
                          else (loc.get('line') if isinstance(loc, dict) else None)}
        findings[iid] = {'issue_id': iid, **merged,
                         'audit_id': job['audit_id'],
                         'from_structured_log': bool(structured),
                         'structured_log_fields': structured}

    return {'findings': findings, 'log_events': log_events,
            'unattributed_events': unattributed_events,
            'orphan_issue_ids': orphan_issue_ids,
            'reviews': reviews, 'exclusions': exclusions, 'jobs': jobs,
            'excluded_audits': excluded_audits,
            'since_log_id': since_log_id, 'db': str(db), 'max_log_id': max_log_id}


def _rate(numerator: int, denominator: int):
    """N/A (never 0) when the denominator is unavailable or zero."""
    return round(numerator / denominator, 4) if denominator else 'N/A'


def summarize(collected: dict) -> dict:
    findings = collected['findings']
    reviews = collected['reviews']
    log_events = collected['log_events']
    FIELDS = ('issue_id', 'rule_id', 'scanner', 'path', 'line', 'engine')

    # Review decisions must match (audit_id, issue_id) exactly. Only
    # confirmed/false_positive count as reviewed; unreviewed stays unreviewed.
    VALID_DECISIONS = {'confirmed', 'false_positive'}
    decisions = {}
    for (aid, iid), decision in reviews.items():
        if iid in findings and findings[iid]['audit_id'] == aid and decision in VALID_DECISIONS:
            decisions[iid] = decision

    # Location errors are an EVENT-LEVEL metric: current engine often logs
    # location_rejected with only negative_sample and no issue_id, so per-issue
    # attribution is not reliable. Count unattributable rejections separately.
    location_validated = 0
    location_rejected = 0
    location_rejected_unattributed = 0
    for _, event in log_events:
        if event.get('event') == 'location_validated':
            location_validated += 1
        elif event.get('event') == 'location_rejected':
            location_rejected += 1
            sample = event.get('negative_sample')
            iid = event.get('issue_id') or (sample.get('id') if isinstance(sample, dict) else None)
            if not iid:
                location_rejected_unattributed += 1

    # Scanner failures: ONLY scanner_completed events with status != completed.
    # model_triage_failed / audit_failed are reported separately, never mixed.
    scanner_failures = 0
    scanner_events = 0
    other_pipeline_failures = Counter()
    for _, event in log_events:
        if event.get('event') == 'scanner_completed':
            scanner_events += 1
            if event.get('status') != 'completed':
                scanner_failures += 1
        elif event.get('event') in ('model_triage_failed', 'audit_failed'):
            other_pipeline_failures[event['event']] += 1

    by_rule = defaultdict(lambda: {'findings': set(), 'reviewed': set(),
                                   'confirmed': set(), 'false_positive': set(),
                                   'fields': defaultdict(set)})
    for iid, f in findings.items():
        rid = f['rule_id'] or '(missing rule_id)'
        d = by_rule[rid]
        d['findings'].add(iid)
        decision = decisions.get(iid)
        if decision:
            d['reviewed'].add(iid)
            if decision == 'confirmed':
                d['confirmed'].add(iid)
            elif decision == 'false_positive':
                d['false_positive'].add(iid)
        for k in FIELDS:
            if f['structured_log_fields'].get(k) is not None or f.get(k) is not None:
                d['fields'][k].add(iid)

    rules = []
    for rid, d in sorted(by_rule.items()):
        total, reviewed = len(d['findings']), len(d['reviewed'])
        rules.append({
            'rule_id': rid if rid != '(missing rule_id)' else None,
            'finding_count': total,
            'reviewed_count': reviewed,
            'unreviewed_count': total - reviewed,
            'human_confirmation_rate': _rate(len(d['confirmed']), reviewed),
            'false_positive_rate': _rate(len(d['false_positive']), reviewed),
            # Per-issue location errors are NOT available: location_rejected
            # frequently lacks issue_id. See global event-level metric below.
            'location_error_rate': 'N/A',
            'location_error_rate_note': 'not attributable per issue_id; use global location_error_event_rate',
            'field_completeness': {
                k: (_rate(len(d['fields'][k]), total) if d['fields'][k] else 'N/A')
                for k in FIELDS},
            'field_completeness_note': 'N/A = field not present in any collected record (data unavailable), not zero coverage',
            'denominator_note': ('review rates: reviewed findings only; '
                                 'location/field rates: all findings; '
                                 'N/A means denominator=0 or field unavailable'),
            'data_sources': ['logs.id>since (structured events)', 'jobs.result.issues',
                             'reviews table'],
        })

    total = len(findings)
    return {
        'kind': 'observation_rule_quality_stats',
        'status': 'READONLY_OBSERVATION',
        'since_log_id': collected['since_log_id'],
        'db': collected['db'],
        'warning': 'READ-ONLY. No model, no rule changes, no data writes. N/A = missing denominator/field, never zero.',
        'distinct_real_issue_ids': total,
        'target_findings': 50,
        'remaining_to_target': max(0, 50 - total),
        'excluded_samples': collected['exclusions'],
        'exclusion_count': len(collected['exclusions']),
        'excluded_audits': sorted(collected['excluded_audits']),
        'orphan_issue_ids': sorted(collected['orphan_issue_ids']),
        'orphan_count': len(collected['orphan_issue_ids']),
        'orphan_note': 'log issue_ids with no completed-job issue; excluded from distinct finding count and 50-item threshold',
        'unattributed_events': collected['unattributed_events'],
        'unattributed_event_count': len(collected['unattributed_events']),
        'unattributed_note': 'events without audit_id cannot be tied to excluded audits; listed, not silently counted',
        'reviewed_total': len(decisions),
        'unreviewed_total': total - len(decisions),
        'max_log_id': collected['max_log_id'],
        'scanner_completed_events': scanner_events,
        'scanner_failures': scanner_failures,
        'scanner_failure_rate': _rate(scanner_failures, scanner_events),
        'scanner_failure_data_source': 'logs scanner_completed only; numerator=status != completed; denominator=all scanner_completed; N/A if none',
        'other_pipeline_failures': dict(other_pipeline_failures),
        'other_pipeline_failures_note': 'model_triage_failed/audit_failed are NOT scanner failures; excluded from scanner metrics',
        'location_error_events': location_rejected,
        'location_validated_events': location_validated,
        'location_error_event_rate': _rate(location_rejected, location_validated + location_rejected),
        'location_rejected_unattributed': location_rejected_unattributed,
        'location_error_data_source': 'event-level logs location_rejected/(location_validated+location_rejected); per-issue attribution unavailable when only negative_sample is logged',
        'rules': rules,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--db', type=Path, default=DEFAULT_DB)
    ap.add_argument('--since-log-id', type=int, default=DEFAULT_SINCE)
    ap.add_argument('--exclude-audit-id', action='append', default=[],
                    help='exact audit_id to exclude (repeatable)')
    ap.add_argument('--exclude-target', action='append', default=[],
                    help='exact target string to exclude (repeatable)')
    ap.add_argument('--json-out', type=Path)
    ap.add_argument('--md-out', type=Path)
    args = ap.parse_args()
    data = summarize(collect(args.db, args.since_log_id,
                             exclude_audit_ids=args.exclude_audit_id,
                             exclude_targets=args.exclude_target))
    text = json.dumps(data, ensure_ascii=False, indent=2)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(text + '\n', encoding='utf-8')
    if args.md_out:
        args.md_out.parent.mkdir(parents=True, exist_ok=True)
        lines = ['# 观察期规则质量统计（只读）', '',
                 f"- 基线 log id: {data['since_log_id']}（当前 max log id: {data['max_log_id']}）",
                 f"- 数据库: {data['db']}",
                 f"- 真实 distinct issue_id: **{data['distinct_real_issue_ids']}**",
                 f"- 距 50 条还差: **{data['remaining_to_target']}**",
                 f"- 已复核: {data['reviewed_total']} / 未复核: {data['unreviewed_total']}",
                 f"- 排除样本: {data['exclusion_count']}",
                 f"- 扫描失败: {data['scanner_failures']} / scanner_completed {data['scanner_completed_events']}（率 {data['scanner_failure_rate']}）",
                 f"- 定位错误(事件级): {data['location_error_events']} / (validated+rejected {data['location_validated_events'] + data['location_error_events']})（率 {data['location_error_event_rate']}），无 issue_id 的 rejected: {data['location_rejected_unattributed']}", '',
                 '| rule_id | findings | 已复核 | 确认率 | 误报率 | 定位错误率 |',
                 '|---|---:|---:|---:|---:|---:|']
        for r in data['rules']:
            lines.append(f"| {r['rule_id'] or '(missing)'} | {r['finding_count']} | "
                         f"{r['reviewed_count']} | {r['human_confirmation_rate']} | "
                         f"{r['false_positive_rate']} | {r['location_error_rate']} |")
        if data['excluded_samples']:
            lines += ['', '## 排除清单', '']
            for x in data['excluded_samples']:
                lines.append(f"- {x['issue_id']}: {x['reason']} (audit_id={x.get('audit_id')})")
        args.md_out.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(text)


if __name__ == '__main__':
    main()
