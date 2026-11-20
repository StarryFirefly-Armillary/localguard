import json
from pathlib import Path
import sys

import pytest
from mcp import ClientSession,StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import Implementation

from localguard.schemas import TOOLS


@pytest.mark.anyio
async def test_real_stdio_discovery_errors_queue_poll_and_schema(tmp_path):
    repo = tmp_path/'repo'
    repo.mkdir()
    source = repo/'evidence.txt'
    source.write_text('hello\nsecond line\n')
    config = tmp_path/'config.json'
    config.write_text(json.dumps({'allowed_roots':[str(repo)],'data_dir':str(tmp_path/'state'),'model_tier':'rules'}))
    params = StdioServerParameters(command=sys.executable,args=['-m','localguard','--config',str(config),'mcp'],
                                  env={'PYTHONPATH':str(Path(__file__).resolve().parents[1])})
    async with stdio_client(params) as (read,write):
        async with ClientSession(read,write,client_info=Implementation(name='LocalGuard protocol integration test',version='1.0')) as client:
            await client.initialize()
            listing = await client.list_tools()
            discovered = {tool.name:tool for tool in listing.tools}
            assert set(discovered)=={name for name,t in TOOLS.items() if t['exposed']}
            for name,tool in discovered.items():
                assert tool.inputSchema==TOOLS[name]['inputSchema']
                assert tool.outputSchema==TOOLS[name]['outputSchema']
            result = await client.call_tool('view_file',{'path':str(source),'start_line':2,'end_line':2})
            assert not result.isError
            assert result.structuredContent['lines'][0]['line']==2
            rejected = await client.call_tool('run_scanner',{'target':str(repo),'scanner':'cmd.exe'})
            assert rejected.isError
            assert 'Traceback' not in rejected.content[0].text
            unavailable = await client.call_tool('run_scanner', {'target':str(repo),'scanner':'pip-audit'})
            assert unavailable.isError
            assert unavailable.structuredContent['status'] == 'unavailable'
            assert 'Traceback' not in unavailable.content[0].text
            queued = await client.call_tool('audit_repository',{'target':str(repo),'depth':'quick','scanners':['patterns'],'include_dependencies':False})
            assert not queued.isError
            assert queued.structuredContent['status']=='queued'
            assert queued.structuredContent['issues']==[]
            audit_id = queued.structuredContent['audit_id']
            for _ in range(10):
                status = await client.call_tool('get_audit_status',{'audit_id':audit_id,'wait_seconds':2})
                assert not status.isError
                if status.structuredContent['status'] in ('completed','failed'):
                    break
            assert status.structuredContent['status']=='completed',status
            assert status.structuredContent['progress']==100
            assert 'locations_validation' in status.structuredContent['completed_modules']
