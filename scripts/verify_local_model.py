import argparse
import asyncio
import json
import subprocess
import time
import uuid

from localguard.config import Config
from localguard.registry import ToolRegistry


def gpu_memory():
    result = subprocess.run(['nvidia-smi','--query-gpu=memory.used','--format=csv,noheader,nounits'],capture_output=True,text=True,timeout=10)
    return result.stdout.strip() if result.returncode==0 else 'unavailable'


async def verify(args):
    config = Config.load(args.config)
    registry = ToolRegistry(config)
    session = uuid.uuid4().hex
    baseline = gpu_memory()
    started = time.monotonic()
    try:
        result = await registry.get_model().chat(
            '请调用 audit_repository，进行 quick 审查，scanners 仅选择 patterns，include_dependencies=false。不要先列目录或读取文件。',
            args.target,args.tier,registry,session)
        if 'audit_id' in result:
            while True:
                status = await registry.call('get_audit_status',{'audit_id':result['audit_id'],'wait_seconds':2},session,'model-smoke')
                if status['isError'] or status['data']['status'] in ('completed','failed'):
                    break
            result['audit_status'] = status
        result.update(tier=args.tier,elapsed_seconds=round(time.monotonic()-started,2),
                      gpu_used_mb_before=baseline,gpu_used_mb_after=gpu_memory(),
                      native_tool_format_success=registry.model.format_success,native_tool_format_failure=registry.model.format_failure)
        print(json.dumps(result,ensure_ascii=True,indent=2))
        if 'audit_id' not in result:
            raise SystemExit(1)
    finally:
        await registry.close()


if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config',default='localguard.local.json')
    parser.add_argument('--target',required=True)
    parser.add_argument('--tier',choices=['rules','4gb','8gb'],default='8gb')
    asyncio.run(verify(parser.parse_args()))
