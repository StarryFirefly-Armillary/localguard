from __future__ import annotations

import asyncio
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import tempfile
from urllib.parse import urlsplit

from .git_evidence import OID, REF, diff_changes, git_command, revision_tree, write_revision_snapshot
from .paths import BoundaryError, PathPolicy, safe_relative
from .process import run
from .reporting import EvidenceError, from_finding, rank


class AuditEngine:
    def __init__(self, registry):
        self.registry = registry
        self.config = registry.config
        self.store = registry.store
        self.worker = None
        self.closed = False

    def start(self):
        if not self.worker or self.worker.done():
            self.worker = asyncio.create_task(self.work())

    async def close(self):
        self.closed = True
        if self.worker:
            self.worker.cancel()
            try:
                await self.worker
            except asyncio.CancelledError:
                pass

    def submit(self, args, session):
        target = args['target']
        self.registry.validate_target(target)
        import psutil
        estimate = args.get('resource_estimate', {})
        if estimate.get('ram_mb', 0) > psutil.virtual_memory().total / 1024**2 * 0.8:
            raise BoundaryError('Requested RAM exceeds the host scheduling limit (80% of physical RAM)')
        args = {**args, 'model_tier': args.get('model_tier', self.config.model_tier)}
        self.start()
        return self.store.enqueue(session,args)

    async def resolve_target(self, target, audit_id):
        if not target.startswith('https://'):
            return self.registry.policy.resolve(target,directory=True)
        parsed = urlsplit(target)
        if self.config.offline or parsed.hostname not in self.config.git_hosts or parsed.username or parsed.port:
            raise BoundaryError('Git retrieval is disabled or the remote host is not allowed by this worker')
        binary = self.config.binaries.get('git')
        if not binary:
            raise ValueError('Git is unavailable')
        destination = self.config.data_dir / 'repositories' / audit_id
        destination.parent.mkdir(exist_ok=True)
        code,_,_ = await run([binary,'-c','protocol.file.allow=never','-c','protocol.ext.allow=never',
                            '-c','core.symlinks=false','-c',f'core.hooksPath={self.config.data_dir / "no-hooks"}',
                            'clone','--depth','2','--no-recurse-submodules','--',target,str(destination)],
                           self.config.data_dir,self.config.scanner_timeout)
        if code:
            raise ValueError('Unable to clone the allowed Git repository')
        self.registry.policy.roots.append(destination.resolve())
        return destination.resolve()

    @contextmanager
    def snapshot(self, root, revision=None):
        with tempfile.TemporaryDirectory(prefix='scan-',dir=self.config.data_dir) as temp:
            snapshot = Path(temp)
            if revision is not None:
                hashes, skipped = write_revision_snapshot(root,snapshot,revision,self.registry.policy,self.config)
                yield snapshot,hashes,skipped
                return
            hashes = {}
            skipped = []
            total = 0
            for path in self.registry.policy.files(root,self.config.max_files,respect_gitignore=False):
                if path.is_relative_to(self.config.data_dir) and not root.is_relative_to(self.config.data_dir / 'repositories'):
                    continue
                if path.stat().st_size > self.config.max_file_bytes:
                    skipped.append(f'Excluded oversized file: {path.relative_to(root)}')
                    continue
                try:
                    real,data,digest = self.registry.policy.read(str(path))
                except BoundaryError as exc:
                    if str(exc).startswith('Binary file'):
                        skipped.append(f'Excluded binary file: {path.relative_to(root)}')
                        continue
                    raise
                total += len(data)
                if total > self.config.max_repo_bytes:
                    raise BoundaryError('Repository exceeds max_repo_bytes')
                relative = real.relative_to(root)
                destination = snapshot / relative
                destination.parent.mkdir(parents=True,exist_ok=True)
                destination.write_bytes(data)
                hashes[relative.as_posix()] = digest
            yield snapshot,hashes,skipped

    async def scanner(self, scanner, target, ruleset='default'):
        from .scanners import run_scanner
        root = self.registry.policy.resolve(target,directory=True)
        async with self.store.resource():
            with self.snapshot(root) as (snapshot,_,skipped):
                result = await run_scanner(scanner,snapshot,ruleset,binaries=self.config.binaries,
                                           timeout=self.config.scanner_timeout,offline=self.config.offline)
                result['warnings'] += skipped
                return result

    async def diff(self, repo, base='HEAD~1', head='HEAD'):
        root = self.registry.policy.resolve(repo,directory=True)
        binary = self.config.binaries.get('git')
        if not binary:
            raise ValueError('Git is unavailable')
        metadata = await asyncio.to_thread(self.registry.policy.git_metadata, root)
        command = git_command(binary,metadata,self.config.data_dir)
        commits = []
        for ref in (base,head):
            if not REF.fullmatch(ref):
                raise ValueError('Invalid Git revision')
            code,out,_ = await run(command+['rev-parse','--verify','--end-of-options',ref+'^{commit}'],self.config.data_dir,20)
            if code:
                raise ValueError(f'Cannot resolve Git revision: {ref}')
            commit = out.decode().strip()
            if not OID.fullmatch(commit):
                raise ValueError('Invalid resolved Git commit')
            commits.append(commit)
        code,out,_ = await run(command+['diff','--no-ext-diff','--no-textconv','--no-renames','--unified=0',*commits,'--'],
                              self.config.data_dir,30,self.config.max_output_bytes)
        if code:
            raise ValueError('Git diff failed')
        return {'diff':out.decode('utf-8',errors='replace'),'changes':diff_changes(out),
                'base_commit':commits[0],'head_commit':commits[1],'truncated':False}

    async def work(self):
        while not self.closed:
            job = self.store.claim()
            if job:
                await self.execute(job)
            else:
                await asyncio.sleep(0.2)

    async def execute(self, job):
        from .scanners import run_scanner
        args = json.loads(job['args'])
        result = self.store.get(job['id'])
        result.update(status='running',progress=1,queue_position=0)
        self.store.update(job['id'],result)
        session = job['session'] + ':' + job['id']
        root = None
        hashes = {}
        try:
            estimate = args.get('resource_estimate',{})
            if estimate:
                import psutil
                deadline = asyncio.get_running_loop().time() + 30
                while psutil.virtual_memory().available / 1024**2 < estimate.get('ram_mb',0):
                    if asyncio.get_running_loop().time() >= deadline:
                        raise BoundaryError('RAM scheduling wait exceeded 30 seconds; retry with a smaller estimate')
                    result['warnings'] = ['Waiting up to 30 seconds for the requested RAM budget']
                    self.store.update(job['id'],result)
                    await asyncio.sleep(1)
            root = await self.resolve_target(args['target'],job['id'])
            result['root'] = str(root)
            changed = None
            revision = None
            if args.get('incremental'):
                diff = await self.diff(str(root),args.get('base','HEAD~1'),args.get('head','HEAD'))
                changed = diff['changes']
                revision = await revision_tree(self.registry.policy,root,diff['head_commit'],self.config,run)
                result['completed_modules'].append('git_diff')
            depth = args.get('depth','standard')
            selected = args.get('scanners') or (['patterns'] if depth=='quick' else ['patterns','semgrep','gitleaks'])
            if depth=='deep' and 'scanners' not in args:
                selected += ['gosec','cppcheck']
            selected = list(selected)
            if args.get('include_dependencies',True):
                selected += [s for s in ('pip-audit','grype') if s not in selected]
            issues = []
            contexts = {}
            coverage = {}
            async with self.store.resource():
                with self.snapshot(root,revision) as (snapshot,hashes,skipped):
                    result['warnings'] += skipped
                    result['coverage'] = {'files':len(hashes),'excluded_files':len(skipped),'scanners':coverage,'depth':depth}
                    for index,scanner in enumerate(selected):
                        output = await run_scanner(scanner,snapshot,'security',binaries=self.config.binaries,
                                                   timeout=self.config.scanner_timeout,offline=self.config.offline)
                        coverage[scanner] = output['status']
                        result['warnings'] += [f'{scanner}: {w}' for w in output.get('warnings',[])]
                        if output['status'] != 'completed':
                            result['warnings'].append(f'{scanner}: {output["status"]}; this coverage is unavailable')
                        evidence_dir = self.config.data_dir / 'evidence' / job['id']
                        evidence_dir.mkdir(parents=True,exist_ok=True)
                        (evidence_dir / f'{scanner}.json').write_text(json.dumps(output,ensure_ascii=False),encoding='utf-8')
                        for finding in output.get('findings',[]):
                            relative = safe_relative(finding['path']).as_posix()
                            finding = dict(finding,path=relative,tool=scanner)
                            if changed is not None and not any(c['path']==relative and c['start_line']<=finding['line']<=c['end_line'] for c in changed):
                                continue
                            try:
                                original,data,digest = self.registry.policy.read(str(root / relative))
                                if hashes.get(relative) != digest:
                                    raise EvidenceError('Source changed after scanner snapshot; rerun this audit')
                                line = finding['line']
                                read = await self.registry.call('view_file',{'path':str(original),'start_line':max(1,line-3),'end_line':line+3},session,'pipeline')
                                if read['isError']:
                                    raise EvidenceError(read['error'])
                                source = next((row['text'] for row in read['data']['lines'] if row['line']==line),None)
                                if source is None:
                                    raise EvidenceError('Scanner reported a nonexistent line')
                                issue = from_finding(finding,source)
                                issues.append(self.registry.validator.validate(issue,session,root))
                                contexts[issue['id']] = {
                                    'id': issue['id'], 'title': issue['title'][:300], 'severity': issue['severity'],
                                    'category': issue['category'], 'cwe': issue['cwe'], 'language': read['data']['language'],
                                    'source': [{'line': row['line'], 'text': row['text'][:100]} for row in read['data']['lines']],
                                    'source_truncated': any(len(row['text']) > 100 for row in read['data']['lines']),
                                }
                            except (ValueError,StopIteration) as exc:
                                result['warnings'].append(f'Rejected location {relative}:{finding["line"]}: {exc}')
                                self.store.log(event='location_rejected',session=session,audit_id=job['id'],validation='rejected',reason=str(exc),negative_sample=finding)
                        result['issues'] = rank(issues)
                        result['completed_modules'].append(scanner)
                        result['progress'] = int(90*(index+1)/len(selected))
                        await self.registry.publish_report(job['id'], result, session, root, hashes)
            result['issues'] = rank(issues)
            tier = args.get('model_tier', self.config.model_tier)
            if result['issues'] and (tier == '8gb' or (tier == '4gb' and self.config.model_4gb_path)):
                try:
                    records = [contexts[issue['id']] for issue in result['issues']]
                    explanations = await self.registry.get_model().explain_issues(records, tier)
                    for issue in result['issues']:
                        update = explanations[issue['id']]
                        issue.update(explanation=update['explanation'], remediation=update['remediation'])
                    result['coverage']['model_explanation'] = 'completed'
                    result['completed_modules'].append('model_explanation')
                except (ValueError, OSError, RuntimeError) as exc:
                    result['coverage']['model_explanation'] = 'unavailable'
                    message = 'Model files could not be accessed' if isinstance(exc, OSError) else str(exc)
                    result['warnings'].append('Local model explanation unavailable; deterministic findings retained. ' + message[:600])
            result['warnings'] = list(dict.fromkeys(result['warnings']))
            result['completed_modules'].append('locations_validation')
            result.update(status='completed',progress=100)
        except asyncio.CancelledError:
            result.update(status='failed',error='Audit interrupted during server shutdown')
            raise
        except Exception as exc:
            result.update(status='failed',error=f'{type(exc).__name__}: {str(exc)[:1000]}')
            self.store.log(event='audit_failed',audit_id=job['id'],validation='failed',error=result['error'])
        finally:
            try:
                await self.registry.publish_report(job['id'], result, session, root, hashes)
            except (ValueError, OSError) as exc:
                result.update(status='failed', issues=[], error='Report validation failed: ' + str(exc)[:1000])
                self.store.log(event='report_rejected', audit_id=job['id'], session=session, validation='rejected', error=result['error'])
                self.store.update(job['id'], result)
