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


def _event_issue_ids(event: dict) -> list[str]:
    """All issue ids referenced by an event (direct, sample, verdicts)."""
    ids = []
    if event.get('issue_id'):
        ids.append(event['issue_id'])
    sample = event.get('negative_sample')
    if isinstance(sample, dict) and sample.get('id'):
        ids.append(sample['id'])
    for v in (event.get('verdicts') or []):
        if isinstance(v, dict) and v.get('issue_id'):
            ids.append(v['issue_id'])
    return ids


def _fields_from_logs(iid: str, log_events: list, allowed_audit_ids: set) -> dict:
    """Structured identity fields from THIS finding's occurrence audits only.

    Failed/unrelated audits with the same deterministic issue_id must not
    pollute a completed finding's identity.
    """
    fields = {}
    for _, event, resolved_aid in log_events:
        if resolved_aid not in allowed_audit_ids:
            continue
        candidates = [event] + [v for v in (event.get('verdicts') or []) if isinstance(v, dict)]
        for c in candidates:
            if c.get('issue_id') != iid:
                continue
            for k in ('issue_id', 'rule_id', 'scanner', 'path', 'line', 'engine'):
                if c.get(k) is not None:
                    fields.setdefault(k, set()).add(c[k])
    return {'values': {k: sorted(v, key=str) for k, v in fields.items()}}


METRIC_EVENTS = {'scanner_completed', 'location_validated', 'location_rejected',
                 'model_triage_failed', 'audit_failed', 'human_review',
                 'model_triage', 'model_triage_abstained'}


def collect(db: Path, since_log_id: int = DEFAULT_SINCE,
            exclude_audit_ids=(), exclude_targets=()) -> dict:
    """Read logs/jobs READ-ONLY. Explicit exclusions apply to ALL events."""
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

    excluded_audits = set(KNOWN_SMOKE_AUDIT_IDS) | set(exclude_audit_ids)
    for job in jobs.values():
        if job['target'] and job['target'] in set(exclude_targets):
            excluded_audits.add(job['audit_id'])

    # session -> audit_id: exact mapping from completed jobs. Real log sessions
    # look like 'base_session:audit_id'; also index the raw session value.
    session_to_audits = {}
    for job in jobs.values():
        aids = {job['audit_id'], job['session'].split(':')[-1] if job['session'] else None}
        aids.discard(None)
        session_to_audits[job['session']] = aids
        for aid in aids:
            session_to_audits.setdefault(aid, set()).add(aid)

    issue_occurrences = defaultdict(list)
    all_issue_audits = defaultdict(set)
    for job in jobs.values():
        for issue in job['result'].get('issues') or []:
            if not isinstance(issue, dict) or not issue.get('id'):
                continue
            all_issue_audits[issue['id']].add(job['audit_id'])
            if job['audit_id'] not in excluded_audits:
                issue_occurrences[issue['id']].append((issue, job))

    log_events = []
    unattributed_events = []
    nonmetric_unattributed_count = 0
    exclusions = []
    ambiguous_events = []
    for lid, event in raw_events:
        event_name = event.get('event')
        # 1) EXPLICIT audit_id always wins (highest priority).
        aid = event.get('audit_id')
        resolved_by = 'explicit' if aid else None
        # 2) session resolution only when audit_id absent.
        session = event.get('session')
        if not aid and session:
            candidates = session_to_audits.get(session) or set()
            if not candidates and ':' in session:
                candidates = session_to_audits.get(session.split(':')[-1]) or set()
            if len(candidates) == 1:
                aid = next(iter(candidates)); resolved_by = 'session'
            elif len(candidates) > 1:
                ambiguous_events.append({'log_id': lid, 'event': event_name,
                                         'candidate_audits': sorted(candidates),
                                         'resolved_by': 'session',
                                         'note': 'multiple session candidates; unresolved'})
        # 3) issue reverse-lookup only when still unresolved.
        if not aid:
            candidates = set()
            for iid in _event_issue_ids(event):
                candidates |= all_issue_audits.get(iid, set())
            if len(candidates) == 1:
                aid = next(iter(candidates)); resolved_by = 'issue'
            elif len(candidates) > 1:
                excluded_here = candidates & excluded_audits
                ambiguous_events.append({'log_id': lid, 'event': event_name,
                                         'candidate_audits': sorted(candidates),
                                         'excluded_candidates': sorted(excluded_here),
                                         'resolved_by': 'issue',
                                         'note': 'multiple audit candidates; kept unclean, never force-excluded'})
        if aid and aid in excluded_audits:
            exclusions.append({'log_id': lid, 'event': event_name, 'audit_id': aid,
                               'reason': 'excluded_audit_event',
                               'resolved_by': resolved_by,
                               'issue_id': next((i for i in _event_issue_ids(event)), None)})
            continue
        if not aid and event_name in METRIC_EVENTS:
            unattributed_events.append({'log_id': lid, 'event': event_name,
                                        'issue_ids': _event_issue_ids(event),
                                        'reason': 'no_session_or_issue_audit_match'})
        elif not aid:
            nonmetric_unattributed_count += 1  # tool_call/tool_evidence/model_explanations...
        log_events.append((lid, event, aid))  # (log_id, event, resolved_audit_id)

    seen_ids = set()
    orphan_issue_ids = set()
    for _, event, _aid in log_events:
        for iid in _event_issue_ids(event):
            (seen_ids if iid in issue_occurrences else orphan_issue_ids).add(iid)

    findings = {}
    field_conflicts = []
    for iid in sorted(seen_ids):
        occs = issue_occurrences[iid]
        occurrence_audits = {j['audit_id'] for _, j in occs}
        structured_all = _fields_from_logs(iid, log_events, occurrence_audits)
        merged = {}
        conflicts = {}
        for k in ('rule_id', 'scanner', 'path', 'line'):
            # STRUCTURED LOG WINS. Only use fallback when NO structured value.
            structured_values = {v for v in structured_all['values'].get(k, []) if v is not None}
            if structured_values:
                ordered = sorted(structured_values, key=str)
                merged[k] = ordered[0]
                if len(ordered) > 1:
                    conflicts[k] = ordered
                continue
            fallbacks = set()
            for issue, _ in occs:
                loc = (issue.get('locations') or [{}])[0] if issue.get('locations') else {}
                ev = issue.get('evidence') or []
                fb = {'rule_id': rule_from_evidence(ev),
                      'scanner': scanner_from_evidence(ev),
                      'path': loc.get('path') if isinstance(loc, dict) else None,
                      'line': loc.get('line') if isinstance(loc, dict) else None}[k]
                if fb is not None:
                    fallbacks.add(fb)
            if fallbacks:
                ordered = sorted(fallbacks, key=str)
                merged[k] = ordered[0]
                if len(ordered) > 1:
                    conflicts[k] = ordered
        finding = {'issue_id': iid, **merged,
                   'audit_ids': sorted({j['audit_id'] for _, j in occs}),
                   'occurrence_count': len(occs),
                   'from_structured_log': any(structured_all['values'].values()),
                   'structured_log_fields': structured_all['values'],
                   'field_conflicts': conflicts}
        findings[iid] = finding
        if conflicts:
            field_conflicts.append({'issue_id': iid, 'conflicts': conflicts,
                                    'note': 'structured values preferred; conflicts listed; excluded from rule-level metrics'})

    # Reviews ONLY from audits that actually contain this issue.
    review_conflicts = []
    decisions = {}
    for iid, finding in findings.items():
        occurrence_audits = set(finding['audit_ids'])
        choices = {}
        for (aid, riid), decision in reviews.items():
            if riid != iid or aid not in occurrence_audits or aid in excluded_audits:
                continue
            if decision in ('confirmed', 'false_positive'):
                choices[aid] = decision
        distinct = sorted(set(choices.values()))
        if len(distinct) > 1:
            review_conflicts.append({'issue_id': iid, 'decisions': choices,
                                     'note': 'conflicting review decisions; not counted as resolved'})
        elif distinct:
            decisions[iid] = distinct[0]

    return {'findings': findings, 'log_events': log_events,
            'unattributed_events': unattributed_events,
            'nonmetric_unattributed_count': nonmetric_unattributed_count,
            'ambiguous_events': ambiguous_events,
            'orphan_issue_ids': orphan_issue_ids,
            'reviews': reviews, 'decisions': decisions,
            'review_conflicts': review_conflicts, 'field_conflicts': field_conflicts,
            'exclusions': exclusions, 'jobs': jobs,
            'excluded_audits': excluded_audits,
            'since_log_id': since_log_id, 'db': str(db), 'max_log_id': max_log_id}


def _rate(numerator: int, denominator: int):
    """N/A (never 0) when the denominator is unavailable or zero."""
    return round(numerator / denominator, 4) if denominator else 'N/A'


def summarize(collected: dict) -> dict:
    findings = collected['findings']
    log_events = collected['log_events']
    FIELDS = ('issue_id', 'rule_id', 'scanner', 'path', 'line', 'engine')

    # Decisions were resolved per issue across non-excluded audits in collect
    # (exact (audit_id, issue_id), confirmed/false_positive only, conflicts listed).
    decisions = collected['decisions']

    # Location errors are an EVENT-LEVEL metric: current engine often logs
    # location_rejected with only negative_sample and no issue_id, so per-issue
    # attribution is not reliable. Count unattributable rejections separately.
    unattributed_ids = {x['log_id'] for x in collected['unattributed_events']}
    location_validated = 0
    location_rejected = 0
    location_rejected_unattributed = 0
    clean_validated = 0
    clean_rejected = 0
    unclean_ids = unattributed_ids | {x['log_id'] for x in collected['ambiguous_events']}
    for lid, event, _aid in log_events:
        clean = lid not in unclean_ids
        if event.get('event') == 'location_validated':
            location_validated += 1
            clean_validated += clean
        elif event.get('event') == 'location_rejected':
            location_rejected += 1
            clean_rejected += clean
            sample = event.get('negative_sample')
            iid = event.get('issue_id') or (sample.get('id') if isinstance(sample, dict) else None)
            if not iid:
                location_rejected_unattributed += 1

    # Scanner failures: ONLY scanner_completed events with status != completed.
    # model_triage_failed / audit_failed are reported separately, never mixed.
    scanner_failures = 0
    scanner_events = 0
    clean_scanner_failures = 0
    clean_scanner_events = 0
    other_pipeline_failures = Counter()
    for lid, event, _aid in log_events:
        clean = lid not in unclean_ids
        if event.get('event') == 'scanner_completed':
            scanner_events += 1
            clean_scanner_events += clean
            if event.get('status') != 'completed':
                scanner_failures += 1
                clean_scanner_failures += clean
        elif event.get('event') in ('model_triage_failed', 'audit_failed'):
            other_pipeline_failures[event['event']] += 1

    by_rule = defaultdict(lambda: {'findings': set(), 'reviewed': set(),
                                   'confirmed': set(), 'false_positive': set(),
                                   'fields': defaultdict(set)})
    conflicted_ids = {x['issue_id'] for x in collected['field_conflicts']}
    for iid, f in findings.items():
        if iid in conflicted_ids:
            continue  # conflicting identity must not enter any concrete rule metric
        rid = f.get('rule_id') or '(missing rule_id)'
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
            if f.get('structured_log_fields', {}).get(k) is not None or f.get(k) is not None:
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
        'nonmetric_unattributed_count': collected['nonmetric_unattributed_count'],
        'nonmetric_unattributed_note': 'tool_call/tool_evidence/model_explanations etc. without audit_id; never enter cleaned metrics',
        'ambiguous_events': collected['ambiguous_events'],
        'ambiguous_event_count': len(collected['ambiguous_events']),
        'unattributed_note': 'events with no resolvable audit_id; listed and EXCLUDED from all CLEAN metrics (ALL metrics still include them)',
        'field_conflicts': collected['field_conflicts'],
        'conflicted_findings': sorted(conflicted_ids),
        'conflicted_finding_count': len(conflicted_ids),
        'conflicted_findings_note': 'identity conflicts listed separately; excluded from per-rule confirmation/false-positive denominators',
        'review_conflicts': collected['review_conflicts'],
        'conflict_note': 'issue_id is a path:line:rule hash and can repeat across audits; conflicts are listed, never silently overwritten',
        'reviewed_total': len(decisions),
        'unreviewed_total': total - len(decisions),
        'max_log_id': collected['max_log_id'],
        'scanner_completed_events': scanner_events,
        'scanner_failures': scanner_failures,
        'scanner_failure_rate_all': _rate(scanner_failures, scanner_events),
        'scanner_completed_events_clean': clean_scanner_events,
        'scanner_failures_clean': clean_scanner_failures,
        'scanner_failure_rate_clean': _rate(clean_scanner_failures, clean_scanner_events),
        'scanner_failure_rate': _rate(clean_scanner_failures, clean_scanner_events),
        'scanner_failure_data_source': 'logs scanner_completed only; ALL=all events incl. unattributed, CLEAN=excludes unattributed events; numerator=status != completed; N/A if denominator=0',
        'other_pipeline_failures': dict(other_pipeline_failures),
        'other_pipeline_failures_note': 'model_triage_failed/audit_failed are NOT scanner failures; excluded from scanner metrics',
        'location_error_events': location_rejected,
        'location_validated_events': location_validated,
        'location_error_event_rate_all': _rate(location_rejected, location_validated + location_rejected),
        'location_error_events_clean': clean_rejected,
        'location_validated_events_clean': clean_validated,
        'location_error_event_rate_clean': _rate(clean_rejected, clean_validated + clean_rejected),
        'location_error_event_rate': _rate(clean_rejected, clean_validated + clean_rejected),
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
                 f"- 扫描失败(全量): {data['scanner_failures']}/{data['scanner_completed_events']} 率 {data['scanner_failure_rate_all']}；(已清洗): {data['scanner_failures_clean']}/{data['scanner_completed_events_clean']} 率 {data['scanner_failure_rate_clean']}",
                 f"- 定位错误(事件级, 全量): {data['location_error_events']}/{data['location_validated_events'] + data['location_error_events']} 率 {data['location_error_event_rate_all']}；(已清洗): {data['location_error_events_clean']}/{data['location_validated_events_clean'] + data['location_error_events_clean']} 率 {data['location_error_event_rate_clean']}",
                 f"- 无归属(指标相关): {data['unattributed_event_count']}；非指标噪声: {data['nonmetric_unattributed_count']}；归属歧义: {data['ambiguous_event_count']}（均不进入已清洗指标）",
                 f"- 孤儿 issue_id: {data['orphan_count']}；字段冲突 finding: {data['conflicted_finding_count']}（不进入具体规则指标）；复核冲突: {len(data['review_conflicts'])}", '',
                 '| rule_id | findings | 已复核 | 确认率 | 误报率 | 定位错误率 |',
                 '|---|---:|---:|---:|---:|---:|']
        for r in data['rules']:
            lines.append(f"| {r['rule_id'] or '(missing)'} | {r['finding_count']} | "
                         f"{r['reviewed_count']} | {r['human_confirmation_rate']} | "
                         f"{r['false_positive_rate']} | {r['location_error_rate']} |")
        if data['excluded_samples']:
            lines += ['', '## 排除清单', '']
            for x in data['excluded_samples']:
                if x.get('issue_id'):
                    lines.append(f"- issue {x['issue_id']}: {x.get('reason')} (audit_id={x.get('audit_id')})")
                else:
                    # excluded_audit_event records have log_id/event, no issue_id.
                    lines.append(f"- log#{x.get('log_id')} event={x.get('event')}: "
                                 f"{x.get('reason')} (audit_id={x.get('audit_id')})")
        if data['field_conflicts']:
            lines += ['', '## 结构化字段冲突（跨审计）', '']
            for x in data['field_conflicts']:
                lines.append(f"- {x['issue_id']}: {x['conflicts']}")
        if data['review_conflicts']:
            lines += ['', '## 复核决定冲突（跨审计）', '']
            for x in data['review_conflicts']:
                lines.append(f"- {x['issue_id']}: {x['decisions']}")
        args.md_out.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(text)


if __name__ == '__main__':
    main()
