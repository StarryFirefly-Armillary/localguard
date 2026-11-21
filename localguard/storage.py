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
            ''')
            if 'configuration' not in {row['name'] for row in db.execute('PRAGMA table_info(jobs)')}:
                db.execute("ALTER TABLE jobs ADD COLUMN configuration TEXT NOT NULL DEFAULT ''")
                for row in db.execute("SELECT id,result FROM jobs WHERE state='queued'").fetchall():
                    result = json.loads(row['result'])
                    result.update(status='failed', queue_position=0, error='Unbound legacy job; resubmit under the current configuration')
                    db.execute("UPDATE jobs SET state='failed',result=? WHERE id=?", (json.dumps(result), row['id']))

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
        for attempt in range(4):
            try:
                with self.connect() as db:
                    db.execute('INSERT INTO logs(time,payload) VALUES (?,?)', (time.time(), record))
                return
            except sqlite3.OperationalError as exc:
                message = str(exc).lower()
                if attempt < 3 and ('readonly' in message or 'locked' in message or 'busy' in message):
                    _time.sleep(0.05 * (2 ** attempt))
                    continue
                raise

    def remember(self, session, path, digest, start, end):
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO reads VALUES(?,?,?,?,?)', (session,str(path),digest,start,end))

    def latest(self, session, path):
        with self.connect() as db:
            row = db.execute('SELECT * FROM reads WHERE session=? AND path=?', (session,str(path))).fetchone()
            return dict(row) if row else None

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
        with self.connect() as db:
            db.execute('UPDATE jobs SET state=?,result=? WHERE id=?', (result['status'],json.dumps(result,ensure_ascii=False),audit_id))

    def get(self, audit_id, session=None):
        with self.connect() as db:
            row = db.execute('SELECT * FROM jobs WHERE id=?', (audit_id,)).fetchone()
            if not row or (session is not None and row['session'] != session):
                raise ValueError('Unknown audit_id for this session')
            result = json.loads(row['result'])
            result['status'] = row['state']
            result['queue_position'] = db.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','running') AND created<=?",(row['created'],)).fetchone()[0] if row['state']=='queued' else 0
            decisions = {r['issue_id']:r['decision'] for r in db.execute('SELECT * FROM reviews WHERE audit_id=?',(audit_id,))}
            for issue in result['issues']:
                issue['review'] = decisions.get(issue['id'],'unreviewed')
            return result

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
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO reviews VALUES(?,?,?)',(audit_id,issue_id,decision))
        self.log(event='human_review',audit_id=audit_id,issue_id=issue_id,decision=decision,
                 session=session, overruled_model=overridden,
                 model_verdict=triage['verdict'] if triage else None)

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
