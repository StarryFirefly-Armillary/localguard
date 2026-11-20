from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid

from .config import Config


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(prog='localguard',description='Local evidence-first security audit and native MCP server')
    parser.add_argument('--config',help='Trusted local JSON configuration (or LOCALGUARD_CONFIG)')
    sub = parser.add_subparsers(dest='command',required=True)
    sub.add_parser('mcp',help='Run the stdio MCP server; stdout is protocol-only')
    ui = sub.add_parser('ui',help='Run the loopback-only web UI')
    ui.add_argument('--port',type=int)
    audit = sub.add_parser('audit',help='Audit through the same registry and print JSON')
    audit.add_argument('target')
    audit.add_argument('--depth',choices=['quick','standard','deep'],default='standard')
    audit.add_argument('--scanners',nargs='+',choices=['patterns','semgrep','gitleaks','gosec','cppcheck','pip-audit','grype'])
    audit.add_argument('--no-dependencies',action='store_true')
    audit.add_argument('--model-tier',choices=['rules','4gb','8gb'])
    sub.add_parser('doctor',help='Inspect offline dependencies and configured paths without modifying them')
    args = parser.parse_args()
    try:
        config = Config.load(args.config)
        if args.command=='mcp':
            from .mcp_server import serve
            asyncio.run(serve(config))
        elif args.command=='ui':
            import uvicorn
            from .web import create_app
            uvicorn.run(create_app(config),host='127.0.0.1',port=args.port or config.port)
        elif args.command=='audit':
            asyncio.run(run_audit(config,args))
        else:
            from .parser import GRAMMARS,SourceParser
            from pathlib import Path
            grammars = {}
            for language in sorted(set(GRAMMARS.values())):
                try:
                    SourceParser().parse(language,b'')
                    grammars[language] = 'available'
                except Exception as exc:
                    grammars[language] = str(exc)
            print(json.dumps({'offline':config.offline,'allowed_roots':[str(r) for r in config.allowed_roots],
                'data_dir':str(config.data_dir),'scanners':{s:config.binaries.get(s,'unavailable') for s in ['semgrep','gitleaks','gosec','cppcheck','pip-audit','grype']},
                'grammars':grammars,'model_tier':config.model_tier,'model_exists':bool(config.model_path and Path(config.model_path).is_file()),
                'keep_model_resident':config.keep_model_resident},ensure_ascii=False,indent=2))
    except (ValueError,OSError) as exc:
        print(f'LocalGuard: {exc}',file=sys.stderr)
        raise SystemExit(1)


async def run_audit(config,args):
    from .registry import ToolRegistry
    registry = ToolRegistry(config)
    session = uuid.uuid4().hex
    try:
        inputs = {'target':args.target,'depth':args.depth,'include_dependencies':not args.no_dependencies}
        if args.scanners:
            inputs['scanners'] = args.scanners
        if args.model_tier:
            inputs['model_tier'] = args.model_tier
        result = await registry.call('audit_repository',inputs,session,'LocalGuard CLI')
        if result['isError']:
            print(json.dumps(result,ensure_ascii=False))
            raise SystemExit(1)
        audit_id = result['data']['audit_id']
        while True:
            result = await registry.call('get_audit_status',{'audit_id':audit_id,'wait_seconds':2},session,'LocalGuard CLI')
            if result['isError'] or result['data']['status'] in ('completed','failed'):
                break
        print(json.dumps(result,ensure_ascii=False,indent=2))
        if result['isError'] or result['data']['status']=='failed':
            raise SystemExit(1)
    finally:
        await registry.close()


if __name__=='__main__':
    main()
