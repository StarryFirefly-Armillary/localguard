from __future__ import annotations

import asyncio
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from urllib.parse import urlsplit

from .git_evidence import OID, REF, diff_changes, git_command, revision_tree, write_revision_snapshot
from .model import abstain_reason_for, triage_status_for
from .paths import BoundaryError, PathPolicy, safe_relative
from .process import run
from .reporting import SEVERITIES, EvidenceError, compare_baseline, from_finding, rank

# Critical CWEs whose abstained/uncertain triage is promoted to high-priority
# human review. Advisory only — never changes severity or deterministic order.
CRITICAL_TRIAGE_CWE = frozenset({'CWE-78', 'CWE-89', 'CWE-502', 'CWE-611', 'CWE-918', 'CWE-22'})


def needs_high_priority_review(issue: dict) -> bool:
    """Critical-CWE abstained/uncertain findings get high-priority review.

    Pure helper so the promotion rule can be unit-tested without an audit run.
    Never changes severity, location, source, or deterministic ordering.
    """
    triage = issue.get('triage') or {}
    return (triage.get('triage_status') in ('abstained', 'uncertain')
            and issue.get('cwe') in CRITICAL_TRIAGE_CWE)

# Files the dependency scanners (grype/pip-audit) need to locate exact package
# versions. discovery.classify() treats them as non-source; keep them in the
# snapshot when dependency scanning is requested so unlocated CVEs are not
# silently dropped. Code scanners on these files are harmless (verified: zero
# patterns/semgrep findings on lockfiles).
DEPENDENCY_MANIFESTS = frozenset({
    'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
    'poetry.lock', 'gemfile.lock', 'go.sum', 'cargo.lock', 'composer.lock',
})


def scan_cache_key(scanner: str, hashes: dict, config, rules_dir: Path) -> str:
    """Stable fingerprint of everything that can change a scanner result.

    Includes the scanner id, the exact snapshot digests, ALL rule/config files
    (not just *.json — gitleaks.toml and grype.yaml matter too), the scanner
    binary's path/size/mtime, and the Grype DB fingerprint when applicable.
    Missing tools/files use a stable marker so they do not collide with a
    real fingerprint.
    """
    def stamp(path: Path) -> str:
        try:
            st = path.stat()
            return f'{path.name}:{st.st_size}:{st.st_mtime_ns}'
        except OSError:
            return f'{path.name}:missing'

    rule_stamp = '|'.join(stamp(p) for p in sorted(rules_dir.iterdir()) if p.is_file())
    binary = config.binaries.get(scanner, '')
    binary_stamp = stamp(Path(binary)) if binary else 'no-binary'
    db_stamp = ''
    if scanner == 'grype':
        # Same source of truth as scanners.py: the DB cache dir is supplied
        # via this env var, not a Config field.
        env_db = os.environ.get('GRYPE_DB_CACHE_DIR')
        db_root = Path(env_db) if env_db else None
        if db_root and db_root.is_dir():
            try:
                db_stamp = '|'.join(stamp(p) for p in sorted(db_root.iterdir()))
            except OSError:
                db_stamp = 'db-unreadable'
        else:
            db_stamp = 'no-db'
    material = '|'.join((scanner, rule_stamp, binary_stamp, db_stamp,
                         '|'.join(f'{k}:{v}' for k, v in sorted(hashes.items()))))
    return hashlib.sha256(material.encode('utf-8')).hexdigest()


class AuditEngine:
    def __init__(self, registry):
        self.registry = registry
        self.config = registry.config
        self.store = registry.store
        self.worker = None
        self.active = {}  # audit_id -> asyncio.Task for the currently running audit(s)
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
    def snapshot(self, root, revision=None, exclude_paths=None, auto_exclude=True,
                 keep_manifests=False):
        # Cleanup of the throwaway scan snapshot must never abort an audit. On
        # Windows an OCaml scanner may leave read-only temp files, and a
        # host-level rmtree shim can refuse bulk deletes. Neither affects the
        # evidence already produced from the snapshot, so cleanup failures are
        # contained here instead of escaping into the audit event loop.
        temp = tempfile.mkdtemp(prefix='scan-',dir=self.config.data_dir)
        snapshot = Path(temp)
        try:
            if revision is not None:
                hashes, skipped = write_revision_snapshot(root,snapshot,revision,self.registry.policy,self.config)
                yield snapshot,hashes,skipped
                return
            hashes = {}
            skipped = []
            total = 0
            from .discovery import classify, is_test_root
            # If the audit target itself is a fixture/test directory, the user
            # deliberately chose it (e.g. scanner regression fixtures). Do not
            # auto-exclude its contents; only nested targets inside a larger
            # project get the discovery policy.
            auto_active = bool(auto_exclude) and not is_test_root(root)
            candidates = list(self.registry.policy.files(
                root,self.config.max_files,respect_gitignore=False,exclude=exclude_paths)) if auto_active else []
            # A target whose files are almost all self-declared fixtures is a
            # sample library the user deliberately chose to review. Trust that
            # intent instead of emptying the report.
            if candidates:
                declared = sum(1 for p in candidates
                               if classify(Path(p),root,trust_declarations=True,
                                           skip_tests=False,skip_generated=False,skip_nonsource=False))
                if declared and declared / len(candidates) >= 0.8:
                    auto_active = False
                    candidates = []
            auto_reasons = {}
            paths = candidates if auto_active else self.registry.policy.files(
                root,self.config.max_files,respect_gitignore=False,exclude=exclude_paths)
            for path in paths:
                path = Path(path)
                if auto_active:
                    try:
                        reason = classify(path,root)
                    except (ValueError,OSError):
                        reason = None
                    # Keep dependency manifests when dependency scanning is on;
                    # otherwise grype cannot locate a CVE to an exact manifest
                    # line and drops the match (unlocated-CVE omission).
                    if reason and keep_manifests and path.name.lower() in DEPENDENCY_MANIFESTS:
                        reason = None
                    if reason:
                        auto_reasons[path.relative_to(root).as_posix()] = reason
                        continue
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
            if auto_active and auto_reasons:
                by_reason = {}
                for rel, reason in auto_reasons.items():
                    by_reason.setdefault(reason, []).append(rel)
                parts = [f'{reason}: {len(rels)} file(s) e.g. {rels[0]}'
                         for reason, rels in sorted(by_reason.items())]
                skipped.append('Auto-excluded non-review targets (disable with auto_exclude=false): '
                               + '; '.join(parts))
            yield snapshot,hashes,skipped
        finally:
            try:
                shutil.rmtree(temp,ignore_errors=True)
            except BaseException:
                # BaseException also covers SystemExit from host deletion shims.
                pass

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
                audit_id = job['id']
                task = asyncio.create_task(self.execute(job), name=f'audit-{audit_id}')
                self.active[audit_id] = task
                try:
                    await task
                except asyncio.CancelledError:
                    # Cancelling the worker on shutdown propagates here; let
                    # it bubble up so close() can finish cleanly.
                    raise
                finally:
                    self.active.pop(audit_id, None)
            else:
                await asyncio.sleep(0.2)

    def cancel(self, audit_id, session):
        """Request cancellation of a running audit owned by this session.

        Cancelling the task unwinds execute() into its finally block: the
        per-scanner subprocess (if any) is terminated by _execute's cleanup
        kill_tree(), and the job is marked cancelled. Returns the job state.
        """
        result = self.store.get(audit_id, session)  # session ownership check
        if result['status'] in ('completed', 'failed', 'cancelled', 'canceled'):
            return result
        task = self.active.get(audit_id)
        if task and not task.done():
            task.cancel()
            result.update(status='cancelled', error='Cancelled by user', queue_position=0)
            self.store.update(audit_id, result)
        else:
            # Queued but not yet running: mark it so claim()/execute skip it.
            result.update(status='cancelled', error='Cancelled by user', queue_position=0)
            self.store.update(audit_id, result)
        return result

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
                with self.snapshot(root,revision,args.get('exclude_paths'),
                                   args.get('auto_exclude',True),
                                   keep_manifests=args.get('include_dependencies',True)) as (snapshot,hashes,skipped):
                    result['warnings'] += skipped
                    result['coverage'] = {'files':len(hashes),'excluded_files':len(skipped),'scanners':coverage,'depth':depth}
                    for index,scanner in enumerate(selected):
                        # Result cache: key = scanner + rule files + exact file
                        # digests. A hit skips only the slow subprocess; evidence
                        # is still rewritten below so raw_ref links stay valid.
                        cache_key = None
                        output = None
                        try:
                            rules_dir = Path(__file__).parent / 'rules'
                            cache_key = scan_cache_key(scanner, hashes, self.config, rules_dir)
                            output = self.store.cache_get(cache_key)
                        except Exception:
                            output = None
                        if output is None:
                            output = await run_scanner(scanner, snapshot, 'security',
                                                       binaries=self.config.binaries,
                                                       timeout=self.config.scanner_timeout,
                                                       offline=self.config.offline)
                            if cache_key and output.get('status') == 'completed':
                                try:
                                    self.store.cache_put(cache_key, output)
                                except Exception:
                                    pass
                        else:
                            result.setdefault('cache_hits', []).append(scanner)
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
                                    'origin_hint': Path(original).parent.relative_to(root).as_posix()[:200],
                                    'source': [{'line': row['line'], 'text': row['text'][:100]} for row in read['data']['lines']],
                                    'source_truncated': any(len(row['text']) > 100 for row in read['data']['lines']),
                                }
                            except (ValueError,StopIteration) as exc:
                                result['warnings'].append(f'Rejected location {relative}:{finding["line"]}: {exc}')
                                self.store.log(event='location_rejected',session=session,audit_id=job['id'],validation='rejected',reason=str(exc),negative_sample=finding)
                        result['issues'] = rank(issues)
                        result['completed_modules'].append(scanner)
                        result['progress'] = int(90*(index+1)/len(selected))
                        # Progress event for the live log console (audit-scoped).
                        self.store.log(event='scanner_completed', audit_id=job['id'],
                                       scanner=scanner, status=output['status'],
                                       findings=len(output.get('findings', [])),
                                       progress=result['progress'])
                        # Publish progress WITHOUT writing findings: the full
                        # location gate is expensive (per-issue view_file) and
                        # only needs to run once, on the final report in the
                        # finally block. Writing issues here would both waste
                        # ~N full validations and bypass the shared gate.
                        progress = {k: v for k, v in result.items() if k != 'issues'}
                        progress['issues'] = []
                        self.store.update(job['id'], progress)
            result['issues'] = rank(issues)
            tier = args.get('model_tier', self.config.model_tier)
            if result['issues'] and (tier == '8gb' or (tier == '4gb' and self.config.model_4gb_path)):
                want_triage = args.get('model_triage', True)
                # Only the top-N highest-risk findings get an AI explanation;
                # result['issues'] is already severity/confidence sorted by
                # rank(). The rest keep their full deterministic evidence and
                # location — no finding is removed and no severity is touched.
                limit = args.get('max_explanations', self.config.max_model_explanations)
                if not isinstance(limit, int) or limit < 0:
                    limit = self.config.max_model_explanations
                chosen = result['issues'][:limit] if limit else result['issues']
                chosen_ids = {issue['id'] for issue in chosen}
                for issue in result['issues']:
                    if issue['id'] not in chosen_ids:
                        issue['ai_explanation'] = 'skipped_budget'
                try:
                    records = [contexts[issue['id']] for issue in chosen]
                    model = self.registry.get_model()
                    try:
                        explanations = await model.explain_issues(records, tier, triage=want_triage)
                    except (ValueError, OSError, RuntimeError) as triage_exc:
                        # Triage is advisory; never sacrifice explanations for it.
                        if not want_triage:
                            raise
                        self.store.log(event='model_triage_failed', audit_id=job['id'],
                                       session=session, reason=str(triage_exc)[:300], tier=tier)
                        want_triage = False
                        explanations = await model.explain_issues(records, tier, triage=False)
                    triage_records = []
                    for issue in chosen:
                        update = explanations.get(issue['id'])
                        if not update:
                            issue['ai_explanation'] = 'unavailable'
                            continue
                        issue['ai_explanation'] = 'done'
                        issue.update(explanation=update['explanation'], remediation=update['remediation'])
                        if want_triage:
                            status = triage_status_for(update)
                            # Do NOT fabricate confidence for abstained entries —
                            # a default 0.5 would imply the model scored them.
                            confidence = (update.get('confidence') if status != 'abstained' else None)
                            triage = {
                                'triage_status': status,
                                'verdict': update.get('verdict'),
                                'confidence': confidence,
                                'reason': str(update.get('reason', '')),
                                'tier': tier,
                                'overridden': False,
                            }
                            issue['triage'] = triage
                            if status in ('abstained', 'uncertain'):
                                # Advisory only: retain the finding, never convert
                                # to likely_false, never lower severity, never
                                # touch location/source or the deterministic rank.
                                issue['needs_human_review'] = True
                                if needs_high_priority_review(issue):
                                    triage['high_priority_review'] = True
                            if status == 'abstained':
                                reason = abstain_reason_for(update) or 'missing_verdict'
                                triage['abstain_reason'] = reason
                                self.store.log(event='model_triage_abstained', audit_id=job['id'],
                                               session=session, tier=tier, issue_id=issue['id'],
                                               cwe=issue.get('cwe'), reason=reason)
                            else:
                                triage_records.append({'issue_id': issue['id'],
                                                       'verdict': update['verdict'],
                                                       'triage_status': status,
                                                       'confidence': update.get('confidence'),
                                                       'reason': str(update.get('reason', ''))[:300]})
                    if triage_records:
                        # One batched write: per-issue log calls can hit a
                        # transient SQLITE_READONLY under WAL lock contention.
                        self.store.log(event='model_triage', audit_id=job['id'], session=session,
                                       tier=tier, verdicts=triage_records)
                    # Model triage is ADVISORY ONLY: it never reorders findings.
                    # Deterministic rank() order (severity, scanner confidence,
                    # path, line, id) is preserved so verified high-risk findings
                    # cannot be demoted by a model verdict — including a
                    # high-confidence false positive. The verdict stays on the
                    # issue ('triage' field), in the audit log, and in the UI as
                    # a badge / filter / review aid.
                    result['coverage']['model_explanation'] = 'completed'
                    result['coverage']['explained_count'] = sum(
                        1 for i in result['issues'] if i.get('ai_explanation') == 'done')
                    if want_triage:
                        result['coverage']['model_triage'] = 'completed'
                    result['completed_modules'].append('model_explanation')
                except (ValueError, OSError, RuntimeError) as exc:
                    for issue in chosen:
                        issue.setdefault('ai_explanation', 'unavailable')
                    result['coverage']['model_explanation'] = 'unavailable'
                    result['coverage']['explained_count'] = 0
                    if want_triage:
                        result['coverage']['model_triage'] = 'unavailable'
                    message = 'Model files could not be accessed' if isinstance(exc, OSError) else str(exc)
                    result['warnings'].append('Local model explanation unavailable; deterministic findings retained. ' + message[:600])
            result['warnings'] = list(dict.fromkeys(result['warnings']))
            # Chinese explanations for coverage warnings are presentation-only.
            # A model tier must be active; in rules mode the verbatim warnings
            # remain unchanged. Any failure is advisory and never fails the audit.
            if result['warnings'] and tier in ('4gb', '8gb') and (tier != '4gb' or self.config.model_4gb_path):
                try:
                    model = self.registry.get_model()
                    translations = await model.explain_warnings(result['warnings'], tier)
                    result['warning_explanations'] = {
                        result['warnings'][int(wid[1:])]: explanation
                        for wid, explanation in translations.items()
                        if wid.startswith('W') and wid[1:].isdigit()
                        and 0 <= int(wid[1:]) < len(result['warnings'])
                    }
                except (ValueError, OSError, RuntimeError) as exc:
                    self.store.log(event='warning_explanation_failed', audit_id=job['id'],
                                   session=session, reason=str(exc)[:300], tier=tier)
            # Change review against the previous audit of the same target.
            # Purely advisory: any failure is swallowed so it can never fail
            # an otherwise valid audit.
            try:
                baseline = self.store.baseline_for(args['target'], job['id'])
                comparison = compare_baseline(result['issues'], baseline)
                if comparison:
                    result['baseline'] = comparison
            except Exception as exc:
                # Advisory feature: never fail an audit, but do not hide a
                # broken baseline either (past bug went unnoticed this way).
                self.store.log(event='baseline_failed', audit_id=job['id'],
                               session=session, reason=f'{type(exc).__name__}: {str(exc)[:300]}')
            result['completed_modules'].append('locations_validation')
            result.update(status='completed',progress=100)
        except asyncio.CancelledError:
            # Distinguish a user-requested cancel (already written as
            # 'cancelled' by engine.cancel) from a shutdown-driven cancel.
            current = self.store.get(job['id'])
            cancelled_by_user = current.get('status') in ('cancelled', 'canceled')
            if not cancelled_by_user:
                result.update(status='failed', error='Audit interrupted during server shutdown')
                self.store.update(job['id'], result)
            raise
        except Exception as exc:
            result.update(status='failed',error=f'{type(exc).__name__}: {str(exc)[:1000]}')
            self.store.log(event='audit_failed',audit_id=job['id'],validation='failed',error=result['error'])
        finally:
            # A cancelled audit must not run the final gate (no complete
            # report exists) — leave the 'cancelled' state intact. Do NOT use
            # `return` here: it would swallow the in-flight CancelledError.
            current_status = self.store.get(job['id']).get('status')
            if current_status not in ('cancelled', 'canceled'):
                try:
                    await self.registry.publish_report(job['id'], result, session, root, hashes)
                except (ValueError, OSError) as exc:
                    # Never destroy verified findings because the final gate failed.
                    # result['issues'] at this point already passed per-finding
                    # validator.validate + view_file checks in the pipeline; keep
                    # them visible with an explicit failure reason so the user can
                    # see what happened and rerun. No *unverified* issue is written.
                    retained = len(result.get('issues', []))
                    result.update(status='failed', error='Report validation failed: ' + str(exc)[:1000])
                    result['warnings'] = list(dict.fromkeys([
                        *result.get('warnings', []),
                        f'最终校验未完成；已保留 {retained} 条通过逐项校验的发现，请按提示重审以刷新证据。',
                    ]))
                    self.store.log(event='report_rejected', audit_id=job['id'], session=session,
                                   validation='rejected', error=result['error'], retained_issues=retained)
                    self.store.update(job['id'], result)
