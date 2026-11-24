from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, contextmanager
import json
from pathlib import Path
import os
import sqlite3
import time
import uuid

import psutil


def alive(pid, started):
    try:
        return abs(psutil.Process(pid).create_time() - started) < 1
    except psutil.Error:
        return False


class Store:
    def __init__(self, directory: Path, configuration: str = 'default'):
        self.configuration = configuration
        self.directory = directory
        self.path = directory / 'state.sqlite3'
        with self.connect() as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, session TEXT, created REAL, state TEXT, args TEXT, result TEXT, pid INTEGER, started REAL, configuration TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS reads(session TEXT, path TEXT, hash TEXT, start INTEGER, end INTEGER, PRIMARY KEY(session,path));
                CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY, time REAL, payload TEXT);
                CREATE TABLE IF NOT EXISTS resource(name TEXT PRIMARY KEY, owner TEXT, pid INTEGER, started REAL);
                CREATE TABLE IF NOT EXISTS reviews(audit_id TEXT, issue_id TEXT, decision TEXT, PRIMARY KEY(audit_id,issue_id));
                CREATE TABLE IF NOT EXISTS scan_cache(key TEXT PRIMARY KEY, created REAL, payload TEXT);
            ''')
            if 'configuration' not in {row['name'] for row in db.execute('PRAGMA table_info(jobs)')}:
                db.execute("ALTER TABLE jobs ADD COLUMN configuration TEXT NOT NULL DEFAULT ''")
                for row in db.execute("SELECT id,result FROM jobs WHERE state='queued'").fetchall():
                    result = json.loads(row['result'])
                    result.update(status='failed', queue_position=0, error='Unbound legacy job; resubmit under the current configuration')
                    db.execute("UPDATE jobs SET state='failed',result=? WHERE id=?", (json.dumps(result), row['id']))
            # Human-review feedback columns (added later; keep old DBs working).
            review_cols = {row['name'] for row in db.execute('PRAGMA table_info(reviews)')}
            if 'rule_id' not in review_cols:
                db.execute("ALTER TABLE reviews ADD COLUMN rule_id TEXT NOT NULL DEFAULT ''")
            if 'model_verdict' not in review_cols:
                db.execute("ALTER TABLE reviews ADD COLUMN model_verdict TEXT NOT NULL DEFAULT ''")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def log(self, **payload):
        # Each log is one independent INSERT, safe to retry. On Windows a WAL
        # write can transiently report SQLITE_READONLY while the file is
        # briefly held by an antivirus/indexer; retry instead of failing the
        # whole audit over a diagnostic record.
        import time as _time
        record = json.dumps(payload, ensure_ascii=False)
        for attempt in range(8):
            try:
                with self.connect() as db:
                    db.execute('INSERT INTO logs(time,payload) VALUES (?,?)', (time.time(), record))
                return
            except sqlite3.OperationalError as exc:
                message = str(exc).lower()
                if attempt < 7 and ('readonly' in message or 'locked' in message or 'busy' in message):
                    _time.sleep(min(1.5, 0.1 * (2 ** attempt)))
                    continue
                raise

    def remember(self, session, path, digest, start, end):
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO reads VALUES(?,?,?,?,?)', (session,str(path),digest,start,end))

    def latest(self, session, path):
        with self.connect() as db:
            row = db.execute('SELECT * FROM reads WHERE session=? AND path=?', (session,str(path))).fetchone()
            return dict(row) if row else None

    def latest_map(self, session):
        """All view_file read records for a session in one query. Callers that
        stale-check many locations avoid opening a SQLite connection per path."""
        with self.connect() as db:
            return {row['path']: dict(row) for row in
                    db.execute('SELECT * FROM reads WHERE session=?', (session,))}

    def recent_logs(self, audit_id, since_id=0, limit=100):
        """Incremental audit-event log for the UI console.

        Returns entries with id/time/event/message/level, newest-last, so the
        client can pass the last id as `since_id` and append only new rows.
        Tool evidence (raw source snippets) is intentionally excluded — the
        console shows progress/diagnostics, not untrusted source data.
        """
        ERROR_EVENTS = {'audit_failed', 'report_rejected', 'location_rejected',
                        'model_triage_failed', 'warning_explanation_failed',
                        'baseline_failed'}
        SILENT_EVENTS = {'tool_evidence'}
        # UI polling noise: the console should show audit progress, not the
        # client's own status refreshes.
        SILENT_TOOLS = {'get_audit_status', 'list_audits', 'view_file',
                        'list_tree', 'get_ast', 'run_scanner'}
        # Filter UI-noise in SQL, not after LIMIT. Otherwise a page filled by
        # silent rows returns nothing and the client never advances its cursor,
        # so later real events are starved forever.
        silent_placeholders = ','.join('?' for _ in SILENT_TOOLS)
        sql = (
            "SELECT id, time, payload FROM logs WHERE id>? "
            "AND json_extract(payload,'$.audit_id')=? "
            "AND json_extract(payload,'$.event') NOT IN (" + ','.join('?' for _ in SILENT_EVENTS) + ") "
            "AND NOT (json_extract(payload,'$.event')='tool_call' "
            "         AND json_extract(payload,'$.tool_name') IN (" + silent_placeholders + ")) "
            "ORDER BY id ASC LIMIT ?"
        )
        params = (int(since_id), audit_id, *SILENT_EVENTS, *SILENT_TOOLS, int(limit))
        with self.connect() as db:
            rows = db.execute(sql, params).fetchall()
        entries = []
        for row in rows:
            try:
                data = json.loads(row['payload'])
            except (TypeError, ValueError):
                continue
            event = data.get('event', '')
            if event in SILENT_EVENTS:
                continue
            if event == 'tool_call' and data.get('tool_name') in SILENT_TOOLS:
                continue
            message = self._log_message(event, data)
            if not message:
                continue
            level = 'error' if event in ERROR_EVENTS else 'info'
            if event == 'tool_call' and data.get('validation') not in (None, 'passed'):
                level = 'warn'
            if event == 'scanner_completed' and data.get('status') not in (None, 'completed'):
                level = 'warn'
            entries.append({'id': row['id'], 'time': row['time'],
                            'event': event, 'message': message, 'level': level})
        return entries

    @staticmethod
    def _log_message(event, data):
        if event == 'scanner_completed':
            status = data.get('status', '')
            suffix = '' if status == 'completed' else f' · {status}（覆盖不可用，非扫描通过）'
            return f"扫描器 {data.get('scanner', '')} 完成：{data.get('findings', 0)} 条发现 · 进度 {data.get('progress', 0)}%{suffix}"
        if event == 'tool_call':
            name = data.get('tool_name', 'tool')
            validation = data.get('validation', '')
            return f'调用工具 {name}' + (f' · {validation}' if validation else '')
        if event == 'location_validated':
            return '发现位置已通过校验' if data.get('validation') == 'passed' else '发现位置校验未通过'
        if event == 'location_rejected':
            return f'拒绝不可信定位：{str(data.get("reason", ""))[:200]}'
        if event == 'model_explanations':
            return f'AI 解释完成 {data.get("count", 0)} 条（{data.get("tier", "")}）'
        if event == 'model_triage':
            return f'模型分诊已记录 {len(data.get("verdicts", []))} 条判断'
        if event == 'model_triage_failed':
            return f'模型分诊失败，保留确定性发现：{str(data.get("reason", ""))[:160]}'
        if event == 'warning_explanation_failed':
            return f'覆盖提示翻译失败，保留原文：{str(data.get("reason", ""))[:160]}'
        if event == 'baseline_failed':
            return f'基线对比跳过：{str(data.get("reason", ""))[:160]}'
        if event == 'report_rejected':
            return f'报告校验失败：{str(data.get("error", ""))[:200]}'
        if event == 'audit_failed':
            return f'审查失败：{str(data.get("error", ""))[:200]}'
        if event == 'human_review':
            return f'人工复核：{data.get("decision", "")}'
        return event

    def enqueue(self, session, args):
        audit_id = uuid.uuid4().hex
        result = {'audit_id':audit_id,'status':'queued','queue_position':0,'progress':0,'completed_modules':[],
                  'issues':[],'warnings':[],'truncated':False,'target':args['target'],'model_tier':args.get('model_tier','rules')}
        with self.connect() as db:
            db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,NULL,NULL,?)', (audit_id,session,time.time(),'queued',json.dumps(args),json.dumps(result),self.configuration))
            result['queue_position'] = db.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','running')").fetchone()[0]
        return result

    def claim(self):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            running = db.execute("SELECT * FROM jobs WHERE state='running'").fetchall()
            for row in running:
                if alive(row['pid'], row['started']):
                    return None
                result = json.loads(row['result'])
                result.update(status='failed',error='Audit worker stopped. Submit a new audit.',queue_position=0)
                db.execute('UPDATE jobs SET state=?,result=? WHERE id=?', ('failed',json.dumps(result),row['id']))
            row = db.execute("SELECT * FROM jobs WHERE state='queued' AND configuration=? ORDER BY created LIMIT 1", (self.configuration,)).fetchone()
            if not row:
                return None
            db.execute("UPDATE jobs SET state='running',pid=?,started=? WHERE id=?", (os.getpid(),psutil.Process().create_time(),row['id']))
            return dict(row)

    def update(self, audit_id, result):
        # A report save is the final step of a long audit. Retry a transient
        # WAL/SQLITE_READONLY (antivirus/indexer holding the file on Windows)
        # rather than throwing away the whole result.
        import time as _time
        payload = json.dumps(result, ensure_ascii=False)
        for attempt in range(8):
            try:
                with self.connect() as db:
                    db.execute('UPDATE jobs SET state=?,result=? WHERE id=?',
                               (result['status'], payload, audit_id))
                return
            except sqlite3.OperationalError as exc:
                message = str(exc).lower()
                if attempt < 7 and ('readonly' in message or 'locked' in message or 'busy' in message):
                    _time.sleep(min(1.5, 0.1 * (2 ** attempt)))
                    continue
                raise

    def get(self, audit_id, session=None):
        with self.connect() as db:
            row = db.execute('SELECT * FROM jobs WHERE id=?', (audit_id,)).fetchone()
            if not row or (session is not None and row['session'] != session):
                raise ValueError('Unknown audit_id for this session')
            result = json.loads(row['result'])
            result['status'] = row['state']
            result['queue_position'] = db.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','running') AND created<=?",(row['created'],)).fetchone()[0] if row['state']=='queued' else 0
            decisions = {r['issue_id']:r['decision'] for r in db.execute('SELECT * FROM reviews WHERE audit_id=?',(audit_id,))}
            # Historical feedback per rule, shown as advisory context only —
            # never used to auto-suppress a finding.
            rule_stats = {}
            for row in db.execute(
                "SELECT rule_id, decision, COUNT(*) n FROM reviews "
                "WHERE rule_id != '' GROUP BY rule_id, decision"):
                entry = rule_stats.setdefault(row['rule_id'], {'confirmed': 0, 'false_positive': 0})
                entry[row['decision']] = row['n']
            for issue in result['issues']:
                issue['review'] = decisions.get(issue['id'],'unreviewed')
                ref = ''
                for evidence in issue.get('evidence', []):
                    if isinstance(evidence, dict) and isinstance(evidence.get('raw_ref'), str):
                        ref = evidence['raw_ref']
                        break
                if ref and ref in rule_stats:
                    stats = rule_stats[ref]
                    issue['feedback'] = {
                        'rule_confirmed': stats.get('confirmed', 0),
                        'rule_false_positive': stats.get('false_positive', 0),
                    }
            from .reporting import reorder_by_feedback
            result['issues'] = reorder_by_feedback(result['issues'])
            return result

    def recent(self, session, limit=10):
        """Lightweight audit summaries for one session, newest first.

        Used by the UI to reconnect to in-flight/recent audits after a page
        reload. Deliberately excludes full findings — call get()/get_audit_status
        for the complete, validated report.
        """
        with self.connect() as db:
            rows = db.execute(
                'SELECT id, state, created, result FROM jobs WHERE session=? ORDER BY created DESC LIMIT ?',
                (session, int(limit))).fetchall()
        audits = []
        for row in rows:
            try:
                result = json.loads(row['result'])
            except (TypeError, ValueError):
                continue
            target = result.get('target', '')
            progress = result.get('progress', 0)
            if not isinstance(progress, int):
                progress = 0
            audits.append({
                'audit_id': row['id'],
                'status': row['state'],
                'target': target if isinstance(target, str) else '',
                'progress': progress,
                'issue_count': len(result.get('issues', [])),
                'created': int(row['created']),
            })
        return audits

    def review(self, audit_id, session, issue_id, decision):
        result = self.get(audit_id,session)
        if decision not in ('confirmed','false_positive','unreviewed'):
            raise ValueError('Invalid review decision')
        issue = next((i for i in result['issues'] if i['id'] == issue_id), None)
        if issue is None:
            raise ValueError('Unknown issue_id')
        triage = issue.get('triage')
        overridden = bool(triage and (
            (decision == 'false_positive' and triage['verdict'] == 'likely_true') or
            (decision == 'confirmed' and triage['verdict'] == 'likely_false')))
        if triage and overridden:
            triage['overridden'] = True
            issue['triage'] = triage
        rule_id = ''
        for evidence in issue.get('evidence', []):
            ref = evidence.get('raw_ref') if isinstance(evidence, dict) else None
            if isinstance(ref, str):
                rule_id = ref
                break
        verdict = triage['verdict'] if triage else ''
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO reviews(audit_id,issue_id,decision,rule_id,model_verdict) '
                       'VALUES(?,?,?,?,?)', (audit_id, issue_id, decision, rule_id, verdict))
        self.log(event='human_review',audit_id=audit_id,issue_id=issue_id,decision=decision,
                 session=session, overruled_model=overridden,
                 rule_id=rule_id, model_verdict=verdict or None)

    def baseline_for(self, target: str, exclude_id: str):
        """Most recent completed audit of the same target, for change review."""
        with self.connect() as db:
            for row in db.execute(
                "SELECT id, args, result FROM jobs WHERE state='completed' AND id!=? ORDER BY created DESC LIMIT 30",
                (exclude_id,)):
                args = json.loads(row['args'])
                if args.get('target') != target:
                    continue
                result = json.loads(row['result'])
                if result.get('issues') is not None:
                    result['audit_id'] = row['id']
                    return result
        return None

    def cache_get(self, key: str, ttl: int = 86400):
        # Enforce TTL on read as well as on put: a stale entry must never be
        # served just because cache_put() has not run again to sweep it.
        with self.connect() as db:
            row = db.execute('SELECT payload, created FROM scan_cache WHERE key=?', (key,)).fetchone()
            if not row or time.time() - row['created'] > ttl:
                return None
            return json.loads(row['payload'])

    def cache_put(self, key: str, payload: dict, ttl: int = 86400) -> None:
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO scan_cache(key,created,payload) VALUES(?,?,?)',
                       (key, time.time(), json.dumps(payload, ensure_ascii=False)))
            db.execute('DELETE FROM scan_cache WHERE created<?', (time.time() - ttl,))

    def triage_accuracy(self) -> dict:
        """How often the model's verdict agreed with a human decision."""
        with self.connect() as db:
            correct = total = 0
            for row in db.execute(
                "SELECT model_verdict, decision, COUNT(*) n FROM reviews "
                "WHERE model_verdict != '' AND decision IN ('confirmed','false_positive') "
                "GROUP BY model_verdict, decision"):
                verdict, decision, n = row['model_verdict'], row['decision'], row['n']
                total += n
                if (verdict == 'likely_true' and decision == 'confirmed') or \
                   (verdict == 'likely_false' and decision == 'false_positive'):
                    correct += n
        return {'agreements': correct, 'decided': total,
                'accuracy': round(correct / total * 100, 1) if total else None}

    @asynccontextmanager
    async def resource(self):
        owner = uuid.uuid4().hex
        while True:
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                row = db.execute("SELECT * FROM resource WHERE name='host'").fetchone()
                if row and not alive(row['pid'],row['started']):
                    db.execute("DELETE FROM resource WHERE name='host'")
                    row = None
                if not row:
                    db.execute('INSERT INTO resource VALUES(?,?,?,?)',('host',owner,os.getpid(),psutil.Process().create_time()))
                    break
            await asyncio.sleep(0.15)
        try:
            yield
        finally:
            with self.connect() as db:
                db.execute('DELETE FROM resource WHERE owner=?',(owner,))
