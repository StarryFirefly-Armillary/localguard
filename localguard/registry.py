from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import time
from urllib.parse import urlsplit

import jsonschema

from .config import Config
from .engine import AuditEngine
from .lines import source_lines
from .parser import SourceParser
from .paths import BoundaryError, PathPolicy, safe_relative
from .reporting import EvidenceError, Validator, rank, read_evidence_metadata
from .schemas import TARGET, TOOLS
from .serialization import result_bytes
from .storage import Store


class ToolRegistry:
    def __init__(self, config: Config):
        self.config = config
        configuration = hashlib.sha256(json.dumps(asdict(config), sort_keys=True, default=str).encode()).hexdigest()
        self.store = Store(config.data_dir, configuration)
        self.policy = PathPolicy(list(config.allowed_roots),config.max_file_bytes)
        self.parser = SourceParser(config.grammars)
        self.validator = Validator(self.store,self.policy)
        self.engine = AuditEngine(self)
        self.model = None
        self.uploads = {}
        self.limit = config.max_output_bytes - 2048

    def validate_target(self, target):
        try:
            jsonschema.Draft202012Validator(TARGET).validate(target)
        except jsonschema.ValidationError as exc:
            raise BoundaryError('Target must be an absolute local directory or a valid HTTPS Git URL') from exc
        if target.startswith('https://'):
            parsed = urlsplit(target)
            if self.config.offline:
                raise BoundaryError('Git URL retrieval is disabled in offline mode; clone locally first')
            if parsed.hostname not in self.config.git_hosts or parsed.username or parsed.port:
                raise BoundaryError('Git host is not allowlisted')
        else:
            self.policy.resolve(target, directory=True)

    def describe(self):
        return [{'name':name,**{k:deepcopy(v) for k,v in definition.items() if k!='exposed'}}
                for name,definition in TOOLS.items() if definition['exposed']]

    def get_model(self):
        if self.model is None:
            from .model import LocalModel
            self.model = LocalModel(self.config,self.store)
        return self.model

    async def close(self):
        await self.engine.close()
        if self.model:
            await self.model.close()

    def bounded(self, data):
        data = deepcopy(data)
        def size():
            return result_bytes(data)
        if size() <= self.limit:
            return data
        data['truncated'] = True
        if 'raw' in data:
            data['raw'] = {'omitted':True,'reason':'Original scanner output exceeds the tool response budget'}
        for key in ('diff','description'):
            if key in data and len(data[key]) > self.limit//4:
                data[key] = data[key][:self.limit//4]
        for key in ('warnings','issues','findings','nodes','entries','lines'):
            values = data.get(key)
            if isinstance(values,list):
                while values and size() > self.limit:
                    values.pop()
        if size() > self.limit:
            raise ValueError('Tool output exceeded the safe limit; narrow the request')
        return data

    async def call(self, name, args, session, client_name='local'):
        started = time.monotonic()
        outcome = 'passed'
        result = None
        try:
            definition = TOOLS.get(name)
            if not definition or not definition['exposed']:
                raise ValueError('Unknown or internal-only tool')
            jsonschema.Draft202012Validator(definition['inputSchema']).validate(args)
            data = await self.execute(name,args,session)
            data = self.bounded(data)
            if name=='view_file':
                if not data['lines'] and data['total_lines']:
                    raise ValueError('A source line exceeds the tool output limit')
                data['end_line'] = data['lines'][-1]['line'] if data['lines'] else 0
                self.store.remember(session,Path(data['path']),data['hash'],data['start_line'],data['end_line'])
            if name=='get_audit_status':
                returned = args.get('offset',0)+len(data['issues'])
                if returned < data['total_issues']:
                    if not data['issues']:
                        raise ValueError('One issue exceeds the response budget; inspect local evidence or narrow the audit')
                    data.update(truncated=True,next_offset=returned)
                else:
                    data.pop('next_offset', None)
            jsonschema.Draft202012Validator(definition['outputSchema']).validate(data)
            if name == 'run_scanner' and data['status'] != 'completed':
                outcome = 'execution_failed'
                error = f"{data['scanner']}: {data['status']}. " + ' '.join(data.get('warnings', []))
                result = {'isError':True, 'data':data, 'error':error[:1500]}
                return result
            if name == 'view_file':
                logged_args, evidence = read_evidence_metadata(args, data)
                self.store.log(event='tool_evidence', genuine=True, client_name=client_name,
                               session_hash=hashlib.sha256(session.encode()).hexdigest(), tool_name=name,
                               arguments=logged_args, result=evidence, isError=False)
            result = {'isError':False,'data':data}
            return result
        except asyncio.CancelledError:
            outcome = 'cancelled'
            raise
        except Exception as exc:
            outcome = 'rejected'
            message = exc.message if isinstance(exc,jsonschema.ValidationError) else str(exc)
            result = {'isError':True,'data':{},'error':message[:1500] or type(exc).__name__}
            return result
        finally:
            self.store.log(event='tool_call',client_name=str(client_name)[:100],session=session,tool_name=name,
                           target=args.get('target',args.get('path',args.get('repo',args.get('image_path','')))),
                           audit_id=args.get('audit_id',result.get('data',{}).get('audit_id','') if result else ''),
                           duration_ms=round((time.monotonic()-started)*1000),validation=outcome,
                           arguments=args,summary={'isError':result['isError'],'error':result.get('error'),
                           'keys':list(result.get('data',{})),'issues':len(result.get('data',{}).get('issues',[]))} if result else {})

    async def execute(self, name, args, session):
        if name=='view_file':
            path,data,digest = self.policy.read(args['path'])
            start = args.get('start_line',1)
            end = args.get('end_line',start+199)
            if end-start>=400:
                raise ValueError('view_file is limited to 400 lines per call')
            result = await asyncio.to_thread(self.parser.slice,path,data,start,end)
            result['hash'] = digest
            return result
        if name=='get_ast':
            path,data,_ = self.policy.read(args['path'])
            return await asyncio.to_thread(self.parser.summary,path,data,args.get('node_type'))
        if name=='list_tree':
            root = self.policy.resolve(args['path'],directory=True)
            entries = []
            seen = set()
            truncated = False
            for path in self.policy.files(root,self.config.max_files):
                if path.is_relative_to(self.config.data_dir) and not root.is_relative_to(self.config.data_dir / 'repositories'):
                    continue
                rel = path.relative_to(root)
                parts = rel.parts
                for depth in range(1,min(len(parts),args.get('max_depth',4))+1):
                    relative = Path(*parts[:depth]).as_posix()
                    if relative not in seen:
                        seen.add(relative)
                        entries.append({'path':relative,'name':parts[depth-1],'depth':depth,
                                        'type':'file' if depth==len(parts) else 'directory'})
                    if len(entries)>=3000:
                        truncated = True
                        break
                if truncated:
                    break
            return {'entries':sorted(entries,key=lambda x:x['path']),'truncated':truncated}
        if name=='run_scanner':
            return await self.engine.scanner(args['scanner'],args['target'],args.get('ruleset','default'))
        if name=='git_diff':
            async with self.store.resource():
                return await self.engine.diff(args['repo'],args.get('base','HEAD~1'),args.get('head','HEAD'))
        if name=='clone_repository':
            # Single explicit network action. host allowlist enforced twice
            # (schema pattern + here); no credentials, ports, query or fragment.
            from .process import run
            parsed = urlsplit(args['url'])
            if parsed.scheme != 'https' or parsed.hostname not in self.config.git_hosts \
                    or parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
                raise BoundaryError('Repository URL is not an allowlisted plain HTTPS Git URL')
            binary = self.config.binaries.get('git')
            if not binary or not Path(binary).is_file():
                raise ValueError('Git is unavailable; configure a local git binary')
            async with self.store.resource():
                clone_id = hashlib.sha256(args['url'].encode()).hexdigest()[:16]
                destination = (self.config.data_dir / 'repositories' / clone_id).resolve()
                if not destination.is_relative_to(self.config.data_dir):
                    raise BoundaryError('Clone destination escapes the local state directory')
                if not (destination / '.git').exists():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    code, _, stderr = await run(
                        [binary, '--no-pager', '-c', 'protocol.file.allow=never',
                         '-c', 'protocol.ext.allow=never', '-c', 'protocol.submodule.allow=never',
                         '-c', 'core.symlinks=false', '-c', f'core.hooksPath={self.config.data_dir / "no-hooks"}',
                         'clone', '--depth', '2', '--no-recurse-submodules', '--', args['url'], str(destination)],
                        self.config.data_dir, self.config.scanner_timeout)
                    if code or not (destination / '.git').exists():
                        # A failed clone leaves a partial directory behind;
                        # remove it so a retry starts clean.
                        import shutil as _shutil
                        try:
                            if destination.exists():
                                _shutil.rmtree(destination, ignore_errors=True)
                        except BaseException:
                            pass
                        diagnostic = (stderr or b'').decode('utf-8', errors='replace').strip()
                        lines = [line.strip() for line in diagnostic.splitlines() if line.strip()]
                        last = lines[-1][:300] if lines else f'git exited with code {code}'
                        if any(k in diagnostic.lower() for k in ('502', 'schannel', 'tunnel', 'proxy', 'Could not resolve')):
                            hint = '网络代理或 DNS 问题；检查代理设置后重试，或手动 clone 到本地目录后填本地路径。'
                        elif 'not found' in diagnostic.lower() or 'repository' in diagnostic.lower() and '404' in diagnostic:
                            hint = '仓库不存在或不可访问；确认 URL 与权限。'
                        else:
                            hint = '可重试，或手动 clone 到本地目录后填本地路径。'
                        raise ValueError(f'克隆失败：{last}。{hint}')
                if destination not in self.policy.roots:
                    self.policy.roots.append(destination)
                return {'path': str(destination), 'url': args['url'], 'cloned': True}
        if name=='audit_repository':
            return self.engine.submit(args,session)
        if name=='get_audit_status':
            result = self.store.get(args['audit_id'],session)
            deadline = time.monotonic()+args.get('wait_seconds',0)
            while result['status'] not in ('completed','failed') and time.monotonic()<deadline:
                await asyncio.sleep(min(0.2,max(0,deadline-time.monotonic())))
                result = self.store.get(args['audit_id'],session)
            root = Path(result.get('root',''))
            if result.get('target','').startswith('https://') and root.is_relative_to(self.config.data_dir / 'repositories'):
                if root not in self.policy.roots:
                    self.policy.roots.append(root)
            hashes = {}
            for issue in result['issues']:
                for location in issue['locations']:
                    path = str(root / safe_relative(location['path']))
                    if path not in hashes:
                        try:
                            _,data,_ = self.policy.read(path)
                            hashes[path] = source_lines(data)
                        except (OSError,ValueError):
                            hashes[path] = []
                    lines = hashes[path]
                    line = location['line']
                    read = self.store.latest(session+':'+args['audit_id'],root / safe_relative(location['path']))
                    try:
                        _,_,current = self.policy.read(path)
                    except (OSError,ValueError):
                        current = None
                    location['stale'] = not read or current!=read['hash'] or line>len(lines) or hashlib.sha256(lines[line-1].encode()).hexdigest()!=location['snippet_hash']
            offset,limit = args.get('offset',0),args.get('limit',100)
            result['total_issues'] = len(result['issues'])
            result['issues'] = result['issues'][offset:offset+limit]
            result['truncated'] = offset+limit < result['total_issues']
            if result['truncated']:
                result['next_offset'] = offset+len(result['issues'])
            return result
        if name=='analyze_image':
            upload_roots = [path.parent for path in self.uploads.get(session, set())]
            policy = PathPolicy([*self.policy.roots, *upload_roots], self.config.max_file_bytes)
            path = policy.resolve(args['image_path'],directory=False)
            return await self.get_model().analyze_image(path,args['question'],args.get('model_tier',self.config.model_tier))
        raise ValueError('Tool is not implemented')

    def rank_and_report(self, issues, session, root):
        jsonschema.Draft202012Validator(TOOLS['rank_and_report']['inputSchema']).validate({'issues':issues})
        for issue in issues:
            self.validator.validate(issue,session,root)
        result = {'issues':rank(issues),'truncated':False}
        jsonschema.Draft202012Validator(TOOLS['rank_and_report']['outputSchema']).validate(result)
        return result

    async def publish_report(self, audit_id, result, session, root, snapshot_hashes):
        """Final location gate. Two failure classes are handled differently:

        - A single issue with an invalid location (no snapshot evidence, range
          too wide, unreadable file) is dropped with a logged negative sample
          and a visible warning; every other verified finding is preserved.
          This honours the "never silently delete findings" contract: the bad
          finding is accounted for, valid ones survive.
        - A stale snapshot (source changed after scanning) invalidates the
          whole evidence basis and still raises EvidenceError, so callers can
          mark the audit failed. No *unverified* issue is ever written back.
        """
        def drop(issue, reason, validation='rejected'):
            self.store.log(event='location_rejected', session=session, audit_id=audit_id,
                           validation=validation, reason=reason, negative_sample=issue)
            return reason

        validated = []
        rejected = []
        checked_paths = set()
        for issue in rank(result['issues']):
            ranges = {}
            reason = None
            for location in issue['locations']:
                relative = safe_relative(location['path']).as_posix()
                if relative not in snapshot_hashes:
                    reason = drop(issue, 'Location has no scanner snapshot evidence')
                    break
                ranges.setdefault(relative, []).append(location['line'])
            if reason is None:
                for relative, lines in ranges.items():
                    if max(lines) - min(lines) >= 400:
                        reason = drop(issue, 'Locations in one file exceed the readable range; split them into separate issues')
                        break
                    read = await self.call('view_file', {'path':str(root / relative), 'start_line':min(lines), 'end_line':max(lines)}, session, 'report-gate')
                    if read['isError']:
                        reason = drop(issue, read['error'])
                        break
                    if read['data']['hash'] != snapshot_hashes[relative]:
                        for location in issue['locations']:
                            if location['path'] == relative:
                                location['stale'] = True
                        self.store.log(event='location_rejected', session=session, audit_id=audit_id,
                                       validation='stale', reason='Source changed after scanning; rerun the audit: ' + relative,
                                       negative_sample=issue)
                        raise EvidenceError('Source changed after scanning; rerun the audit: ' + relative)
                    checked_paths.add(relative)
            if reason is not None:
                rejected.append(f'Dropped {issue.get("id", "issue")}: {reason}')
                continue
            validated.extend(self.rank_and_report([issue], session, root)['issues'])
        for relative in checked_paths:
            _, _, digest = self.policy.read(str(root / relative))
            if digest != snapshot_hashes[relative]:
                self.store.log(event='location_rejected', session=session, audit_id=audit_id,
                               validation='stale', reason='Source changed during report validation', path=relative)
                raise EvidenceError('Source changed during report validation; rerun the audit: ' + relative)
        result['issues'] = validated
        if rejected:
            result['warnings'] = list(dict.fromkeys([*result.get('warnings', []), *rejected]))
        self.store.update(audit_id, result)
