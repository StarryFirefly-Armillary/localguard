from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import sys
import time

import jsonschema
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import Implementation

import localguard


async def verify(installation, target):
    assert Path(localguard.__file__).resolve().is_relative_to(installation.resolve()), localguard.__file__
    python = installation/'app-env/Scripts/python.exe'
    params = StdioServerParameters(command=str(python), args=['-I','-m','localguard','--config',str(installation/'localguard.json'),'mcp'],
                                  env={'GRYPE_DB_CACHE_DIR':str(installation/'grype-db'),'PYTHONIOENCODING':'utf-8'})
    started = time.monotonic()
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write, client_info=Implementation(name='offline-install-verifier',version='1.0')) as client:
            await client.initialize()
            tools = {tool.name:tool for tool in (await client.list_tools()).tools}
            # Assert the capabilities this verifier actually exercises instead
            # of a hardcoded count that goes stale whenever the protocol grows.
            for required in ('audit_repository', 'get_audit_status', 'view_file',
                             'list_audits', 'cancel_audit'):
                assert required in tools, f'missing MCP tool: {required}'
            # Dependency CVEs are asserted below, so dependency scanning must
            # be enabled — a False here used to make that assertion impossible.
            queued = await client.call_tool('audit_repository', {'target':str(target),'scanners':['patterns','semgrep','gitleaks','cppcheck','grype'],
                'include_dependencies':True,'depth':'standard','model_tier':'4gb'})
            assert not queued.isError, queued
            audit_id = queued.structuredContent['audit_id']
            assert queued.structuredContent['status'] == 'queued'
            for _ in range(60):
                response = await client.call_tool('get_audit_status', {'audit_id':audit_id,'wait_seconds':3,'limit':200})
                assert not response.isError, response
                result = response.structuredContent
                jsonschema.validate(result,tools['get_audit_status'].outputSchema)
                if result['status'] in ('completed','failed'):
                    break
            assert result['status'] == 'completed', result
            assert all(state == 'completed' for state in result['coverage']['scanners'].values()), result['coverage']
            locations = {(location['path'],location['line']) for issue in result['issues'] for location in issue['locations']}
            assert ('vulnerable.py',5) in locations and ('vulnerable.c',4) in locations
            assert any(issue['category']=='dependency_cve' for issue in result['issues'])
            read = await client.call_tool('view_file', {'path':str(target/'vulnerable.c'),'start_line':4,'end_line':4})
            assert not read.isError and read.structuredContent['lines'][0]['line']==4
            report = {'installed_module':localguard.__file__,'audit_id':audit_id,'initial_status':'queued',
                      'final_status':result['status'],'tools_discovered':len(tools),'total_issues':result['total_issues'],
                      'coverage':result['coverage'],'validated_location':{'path':'vulnerable.c','line':4},
                      'elapsed_seconds':round(time.monotonic()-started,2),'offline':True,'model_tier':'4gb',
                      'limitations':['No GPU model is loaded by the 4gb rules route.', 'This check does not attest OS-level network sandboxing.']}
    path = installation/'offline-verification.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(report,ensure_ascii=True,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--installation',type=Path,required=True)
    parser.add_argument('--target',type=Path,required=True)
    args=parser.parse_args()
    asyncio.run(verify(args.installation.resolve(),args.target.resolve()))
