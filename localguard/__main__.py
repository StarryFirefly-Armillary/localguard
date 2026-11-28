from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
import uuid

from .config import Config
from . import diagnostics

DATA_DIR_HELP = (
    'Explicit writable working directory; overrides config data_dir and never falls back. '
    'If blocked, use a system temporary workspace such as localguard-work in the OS temp directory.'
)


def selected_config_path(args):
    """Prefer the doctor subcommand flag; fall back to global config or env."""
    return getattr(args, 'doctor_config', None) or args.config or os.environ.get('LOCALGUARD_CONFIG')


def load_config(args):
    """Load config; doctor stays read-only, audit/ui/mcp preflight writable data_dir."""
    config_path = selected_config_path(args)
    if args.command == 'doctor':
        return diagnostics.load_config_readonly(config_path)

    command = args.command
    target = getattr(args, 'target', None)
    override = getattr(args, 'data_dir', None)
    try:
        if override:
            directory = Path(override).resolve(strict=False)
            if directory.exists() and not directory.is_dir():
                raise diagnostics.DiagnosticsError(diagnostics.writable_error(
                    directory, config_path=config_path, target=target, command=command))
            directory.mkdir(parents=True, exist_ok=True)
            diagnostics.ensure_writable_data_dir(
                directory, config_path=config_path, target=target, command=command)
            os.environ['LOCALGUARD_DATA_DIR'] = str(directory)
        config = Config.load(args.config)
        if command in ('audit', 'ui', 'mcp'):
            diagnostics.ensure_writable_data_dir(
                config.data_dir, config_path=config_path, target=target, command=command)
        return config
    except (OSError, ValueError) as exc:
        if command in ('audit', 'ui', 'mcp'):
            shown = Path(override).resolve(strict=False) if override else Path('(configured data_dir)')
            raise diagnostics.DiagnosticsError(diagnostics.writable_error(
                shown, config_path=config_path, target=target, command=command)) from exc
        raise


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(prog='localguard',description='Local evidence-first security audit and native MCP server')
    parser.add_argument('--config',help='Trusted local JSON configuration (or LOCALGUARD_CONFIG)')
    sub = parser.add_subparsers(dest='command',required=True)
    mcp = sub.add_parser('mcp',help='Run the stdio MCP server; stdout is protocol-only')
    mcp.add_argument('--data-dir',help=DATA_DIR_HELP)
    ui = sub.add_parser('ui',help='Run the loopback-only web UI')
    ui.add_argument('--port',type=int)
    ui.add_argument('--data-dir',help=DATA_DIR_HELP)
    audit = sub.add_parser('audit',help='Audit through the same registry and print JSON')
    audit.add_argument('target')
    audit.add_argument('--depth',choices=['quick','standard','deep'],default='standard')
    audit.add_argument('--scanners',nargs='+',choices=['patterns','semgrep','gitleaks','gosec','cppcheck','pip-audit','grype'])
    audit.add_argument('--no-dependencies',action='store_true')
    audit.add_argument('--model-tier',choices=['rules','4gb','8gb'])
    audit.add_argument('--data-dir',help=DATA_DIR_HELP)
    doctor = sub.add_parser('doctor',help='Inspect offline dependencies and configured paths without modifying them')
    doctor.add_argument('--config',dest='doctor_config',default=argparse.SUPPRESS,
                        help='Trusted local JSON configuration (alternative to the global --config)')
    doctor.add_argument('--json',action='store_true',help='Emit machine-readable JSON')
    doctor.add_argument('--probe-write',action='store_true',help='Create and delete one temporary file in data_dir to verify write access')
    args = parser.parse_args()
    try:
        config = load_config(args)
        if args.command=='mcp':
            from .mcp_server import serve
            asyncio.run(serve(config))
        elif args.command=='ui':
            import uvicorn
            from .web import create_app
            uvicorn.run(create_app(config),host='127.0.0.1',port=args.port or config.port)
        elif args.command=='audit':
            asyncio.run(run_audit(config,args))
        elif args.command == 'doctor':
            report = diagnostics.collect(config, probe=args.probe_write,
                                         config_path=selected_config_path(args))
            if args.json:
                print(json.dumps(report, ensure_ascii=False, indent=2))
            else:
                print(diagnostics.format_text(report))
    except (ValueError, OSError, diagnostics.DiagnosticsError) as exc:
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
