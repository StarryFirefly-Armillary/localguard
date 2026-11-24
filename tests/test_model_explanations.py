import json

import pytest

from localguard.config import Config
from localguard.model import LocalModel, ModelUnavailable
from localguard.storage import Store


def explanation(id='ISSUE-1',**extra):
    return {'id':id,'explanation':'工具发现外部输入到达危险操作，需人工确认数据来源。','remediation':'使用安全接口并限制输入。',**extra}


@pytest.mark.anyio
async def test_explanations_use_json_and_non_thinking_request(tmp_path,monkeypatch):
    config = Config(allowed_roots=[tmp_path],data_dir=tmp_path/'state')
    model = LocalModel(config,Store(config.data_dir))
    payloads=[]
    async def request(endpoint,method,route,payload=None):
        if route=='/models':
            return {'data':[{'id':'Qwen3.5-4B-Q4_K_M'}]}
        payloads.append(payload)
        return {'choices':[{'message':{'content':json.dumps({'explanations':[explanation()]})}}]}
    monkeypatch.setattr(model,'_request',request)
    result = await model.explain_issues([{'id':'ISSUE-1','source':[{'line':4,'text':'validated evidence'}]}])
    assert result['ISSUE-1']['id']=='ISSUE-1'
    assert payloads[0]['chat_template_kwargs']=={'enable_thinking':False}
    assert payloads[0]['response_format']=={'type':'json_object'}
    await model.close()


@pytest.mark.anyio
@pytest.mark.parametrize('updates',[
    [explanation('unknown')],
    [explanation(),explanation()],
    [explanation(locations=[{'path':'invented.py','line':999}])],
    [{**explanation(),'explanation':'漏洞位于第47行'}],
    [{**explanation(),'remediation':'Change invented.py:999'}],
])
async def test_explanation_gate_rejects_unknown_ids_fields_and_locations(tmp_path,monkeypatch,updates):
    config=Config(allowed_roots=[tmp_path],data_dir=tmp_path/'state')
    model=LocalModel(config,Store(config.data_dir))
    async def infer(*args,**kwargs):
        return {'choices':[{'message':{'content':json.dumps({'explanations':updates})}}]}
    monkeypatch.setattr(model,'_infer',infer)
    with pytest.raises(ModelUnavailable,match='schema or location'):
        await model.explain_issues([{'id':'ISSUE-1','source':[]}])
    await model.close()


@pytest.mark.anyio
async def test_conservative_triage_prompt_is_opt_in(tmp_path,monkeypatch):
    config=Config(allowed_roots=[tmp_path],data_dir=tmp_path/'state')
    model=LocalModel(config,Store(config.data_dir))
    prompts=[]
    async def infer(messages,*args,**kwargs):
        prompts.append(messages[0]['content'])
        return {'choices':[{'message':{'content':json.dumps({'explanations':[explanation()]})}}]}
    monkeypatch.setattr(model,'_infer',infer)
    records=[{'id':'ISSUE-1','source':[]}]
    await model.explain_issues(records,triage=True)
    await model.explain_issues(records,triage=True,conservative=True)
    assert 'Conservative triage' not in prompts[0]
    assert 'Conservative triage' in prompts[1]
    await model.close()
