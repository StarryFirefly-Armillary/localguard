from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

from .lines import source_lines
from .paths import BoundaryError, safe_relative

SEVERITIES = {'critical':0,'high':1,'medium':2,'low':3,'info':4}


def snippet_hash(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def read_evidence_metadata(arguments, result):
    args = {'path_hash': snippet_hash(arguments['path'])}
    args.update({key: arguments[key] for key in ('start_line', 'end_line') if key in arguments})
    evidence = {key: result[key] for key in ('hash', 'start_line', 'end_line', 'total_lines')}
    evidence['path_hash'] = snippet_hash(result['path'])
    evidence['line_hashes'] = [{'line': row['line'], 'snippet_hash': snippet_hash(row['text'])} for row in result['lines']]
    return args, evidence


class EvidenceError(ValueError):
    pass


class Validator:
    def __init__(self, store, policy):
        self.store,self.policy = store,policy

    def validate(self, issue, session, root: Path):
        try:
            for location in issue['locations']:
                path = self.policy.resolve(str(root / safe_relative(location['path'])),directory=False)
                read = self.store.latest(session,path)
                if not read:
                    raise EvidenceError('Unread location: call view_file before citing this path')
                _,data,digest = self.policy.read(str(path))
                if digest != read['hash']:
                    location['stale'] = True
                    raise EvidenceError('Stale location: file hash changed; call view_file again')
                line = location['line']
                if not read['start'] <= line <= read['end']:
                    raise EvidenceError('Location is outside the latest view_file range; reread the required lines')
                lines = source_lines(data)
                if not 1 <= line <= len(lines) or snippet_hash(lines[line-1]) != location['snippet_hash']:
                    raise EvidenceError('Location snippet_hash does not match the verified source line')
                location['stale'] = False
                if not any(e['tool']=='view_file' and e.get('range')==[read['start'],read['end']] for e in issue['evidence']):
                    issue['evidence'].append({'tool':'view_file','range':[read['start'],read['end']]})
        except (EvidenceError, BoundaryError) as exc:
            self.store.log(event='location_rejected',session=session,validation='rejected',reason=str(exc),negative_sample=issue)
            raise EvidenceError(str(exc)) from exc
        self.store.log(event='location_validated',session=session,validation='passed',issue_id=issue['id'],locations=issue['locations'])
        return issue


def rank(issues):
    merged = {}
    for source in issues:
        issue = deepcopy(source)
        locations = tuple(sorted((loc['path'], loc['line'], loc['snippet_hash']) for loc in issue['locations']))
        key = (issue['id'], locations, issue['category'], issue['cwe'])
        if key in merged:
            previous = merged[key]
            previous['evidence'] += [e for e in issue['evidence'] if e not in previous['evidence']]
            previous['confidence'] = max(previous['confidence'],issue['confidence'])
            for field in ('explanation', 'remediation'):
                previous[field] = '\n\n'.join(dict.fromkeys(part for value in (previous[field], issue[field]) for part in value.split('\n\n') if part))
            if SEVERITIES[issue['severity']] < SEVERITIES[previous['severity']]:
                previous['severity'] = issue['severity']
        else:
            merged[key] = issue
    for issue in merged.values():
        issue['needs_human_review'] = issue['severity'] in ('critical','high') or issue.get('needs_human_review',False)
    return sorted(merged.values(),key=lambda i:(SEVERITIES[i['severity']],-i['confidence'],i['locations'][0]['path'],i['locations'][0]['line'],i['id']))


def issue_signature(issue):
    """Stable identity across audits (issue ids are regenerated each run)."""
    location = issue.get('locations', [{}])[0]
    return (location.get('path', ''), location.get('line', 0),
            issue.get('category', ''), issue.get('title', '')[:80])


def compare_baseline(current, baseline):
    """New / resolved / persisted findings against a previous audit.

    Comparison uses content signatures, never volatile issue ids. Reviews are
    carried over only for identical signatures so a resolved item is not
    mistaken for a still-open one.
    """
    if not baseline or not baseline.get('issues'):
        return None
    before = {issue_signature(i): i for i in baseline['issues']}
    after = {issue_signature(i): i for i in current}
    added = [i for sig, i in after.items() if sig not in before]
    resolved = [i for sig, i in before.items() if sig not in after]
    persisted = sum(1 for sig in after if sig in before)
    return {
        'baseline_audit_id': baseline.get('audit_id'),
        'added': [i['id'] for i in added],
        'resolved': [i['id'] for i in resolved],
        'persisted': persisted,
    }


def reorder_by_feedback(issues):
    """Advisory reordering from past human reviews — never drops or edits findings.

    Rules repeatedly marked false_positive sink a bounded number of places;
    critical/high findings are never demoted (safety first). Severity,
    confidence and the original order fallback are all preserved.
    """
    ordered = list(issues)
    for index, issue in enumerate(ordered):
        feedback = issue.get('feedback') or {}
        confirmed = feedback.get('rule_confirmed', 0)
        false_positive = feedback.get('rule_false_positive', 0)
        demote = 0
        if SEVERITIES.get(issue['severity'], 9) > 1 and false_positive > confirmed:
            # Bounded: one place per net false positive, capped at 2.
            demote = min(2, false_positive - confirmed)
        # Model triage ordering is handled once in the engine (penalty sort).
        # Do not apply it again here: that would double-demote the same hint.
        issue['_feedback_rank'] = (index + demote, index)
    ordered.sort(key=lambda i: (i['_feedback_rank'][0], i['_feedback_rank'][1]))
    for issue in ordered:
        issue.pop('_feedback_rank', None)
    return ordered


def from_finding(finding, text):
    identity = f"{finding['path']}:{finding['line']}:{finding.get('rule_id',finding['title'])}"
    if finding['category'] == 'dependency_cve':
        identity += ':' + finding['title']
    return {'id':'ISSUE-'+hashlib.sha256(identity.encode()).hexdigest()[:12],
            'title':finding['title'],'severity':finding['severity'],'category':finding['category'],
            'cwe':finding.get('cwe',''),'confidence':finding.get('confidence',0.7),
            'locations':[{'path':finding['path'],'line':finding['line'],'snippet_hash':snippet_hash(text),'stale':False}],
            'evidence':[{'tool':finding['tool'],'raw_ref':finding.get('raw_ref',finding.get('rule_id',''))}],
            'explanation':finding.get('explanation',''),'remediation':finding.get('remediation',''),
            'needs_human_review':True,'review':'unreviewed'}


def export_report(result, format):
    if format=='json':
        return json.dumps(result,ensure_ascii=False,indent=2),'application/json','json'
    if format=='markdown':
        lines = [f"# LocalGuard audit {result['audit_id']}",f"Status: {result['status']}", '']
        lines += [f'> Coverage warning: {w}' for w in result.get('warnings',[])]
        for issue in result['issues']:
            lines += ['',f"## {issue['severity'].upper()} — {issue['title']}",issue['explanation'],'',issue['remediation']]
            lines += [f"- `{loc['path']}:{loc['line']}` (hash `{loc['snippet_hash']}`, stale={loc.get('stale',False)})" for loc in issue['locations']]
            lines += [f"- Evidence: {json.dumps(issue['evidence'],ensure_ascii=False)}",f"- Human review: {issue.get('review','unreviewed')}"]
        return '\n'.join(lines),'text/markdown','md'
    if format=='sarif':
        entries = []
        for issue in result['issues']:
            entries.append({'ruleId':issue['cwe'] or issue['category'],
                'level':'error' if issue['severity'] in ('critical','high') else 'warning' if issue['severity']=='medium' else 'note',
                'message':{'text':issue['title']+'\n'+issue['explanation']},
                'locations':[{'physicalLocation':{'artifactLocation':{'uri':Path(loc['path']).as_posix()},'region':{'startLine':loc['line']}}} for loc in issue['locations']],
                'properties':{'confidence':issue['confidence'],'evidence':issue['evidence'],'needs_human_review':issue['needs_human_review'],'review':issue.get('review','unreviewed')}})
        return json.dumps({'version':'2.1.0','runs':[{'tool':{'driver':{'name':'LocalGuard','version':'0.1.0'}},'results':entries,'invocations':[{'executionSuccessful':result['status']=='completed','toolExecutionNotifications':[{'level':'warning','message':{'text':w}} for w in result.get('warnings',[])]}]}]},ensure_ascii=False,indent=2),'application/sarif+json','sarif'
    raise ValueError('Unsupported report format')
