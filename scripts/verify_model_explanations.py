import asyncio
import json
from pathlib import Path
import uuid

from localguard.config import Config
from localguard.registry import ToolRegistry
from localguard.reporting import from_finding


async def main():
    config = Config.load('localguard.local.json')
    registry = ToolRegistry(config)
    session = uuid.uuid4().hex
    diagnostics = []
    try:
        scanned = await registry.call('run_scanner',{'scanner':'patterns','target':str(config.allowed_roots[0])},session,'explanation-test')
        finding = scanned['data']['findings'][0]
        view = await registry.call('view_file',{'path':str(config.allowed_roots[0]/finding['path'])},session,'explanation-test')
        text = next(row['text'] for row in view['data']['lines'] if row['line']==finding['line'])
        issue = from_finding(finding,text)
        registry.validator.validate(issue,session,config.allowed_roots[0])
        model = registry.get_model()
        infer = model._infer
        async def capture(*args,**kwargs):
            response = await infer(*args,**kwargs)
            choice = response.get('choices',[{}])[0]
            message = choice.get('message',{})
            diagnostics.append({'finish_reason':choice.get('finish_reason'),'content':message.get('content'),
                                'message_keys':list(message),'usage':response.get('usage')})
            return response
        model._infer = capture
        record = {'id':issue['id'],'title':issue['title'],'category':issue['category'],'severity':issue['severity'],
                  'cwe':issue['cwe'],'language':view['data']['language'],'source':view['data']['lines']}
        updates = await model.explain_issues([record])
        print(json.dumps({'passed':True,'explanations':updates,'diagnostics':diagnostics},ensure_ascii=True,indent=2))
    except Exception as exc:
        print(json.dumps({'passed':False,'error':str(exc),'diagnostics':diagnostics},ensure_ascii=True,indent=2))
        raise SystemExit(1)
    finally:
        await registry.close()


if __name__=='__main__':
    asyncio.run(main())
