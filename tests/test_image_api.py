import base64
import json

from fastapi.testclient import TestClient

from localguard.config import Config
from localguard.model import ModelUnavailable
from localguard.web import create_app


def test_upload_uses_shared_registry_and_cleans_up(tmp_path,monkeypatch):
    repo=tmp_path/'repo'
    repo.mkdir()
    app=create_app(Config(allowed_roots=[repo],data_dir=tmp_path/'state'))
    registry=app.state.registry
    calls=[]
    async def vision(path,question,tier='8gb'):
        assert path.is_file() and path.is_relative_to(registry.config.data_dir/'uploads')
        calls.append((str(path),question,tier))
        return {'description':'A test diagram','auxiliary':True,'truncated':False}
    monkeypatch.setattr(registry.get_model(),'analyze_image',vision)
    with TestClient(app) as client:
        boot=client.get('/api/bootstrap').json()
        headers={'x-csrf-token':boot['csrf_token']}
        response=client.post('/api/image',headers=headers,json={'name':'../diagram.png','data':base64.b64encode(b'\x89PNG\r\n\x1a\nfixture').decode(),'question':'Describe','model_tier':'8gb'})
        assert response.status_code==200 and response.json()['auxiliary']
        assert calls and registry.uploads=={}
        assert not list((registry.config.data_dir/'uploads').rglob('*.png'))
        assert 'blob:' in response.headers['content-security-policy']
        with registry.store.connect() as db:
            logs=[json.loads(row[0]) for row in db.execute('SELECT payload FROM logs')]
        assert any(log.get('tool_name')=='analyze_image' and log.get('client_name')=='LocalGuard UI' and log.get('validation')=='passed' for log in logs)
        denied=client.post('/api/tools/analyze_image',headers=headers,json={'image_path':calls[0][0],'question':'Describe'})
        assert denied.json()['isError']


def test_image_tier_error_is_readable_content(tmp_path,monkeypatch):
    app=create_app(Config(allowed_roots=[tmp_path],data_dir=tmp_path/'state'))
    async def reject(*args):
        raise ModelUnavailable('Vision requires the 8gb local tier')
    monkeypatch.setattr(app.state.registry.get_model(),'analyze_image',reject)
    with TestClient(app) as client:
        headers={'x-csrf-token':client.get('/api/bootstrap').json()['csrf_token']}
        payload={'name':'diagram.png','data':base64.b64encode(b'\x89PNG\r\n\x1a\nfixture').decode(),'question':'Describe','model_tier':'4gb'}
        response=client.post('/api/image',headers=headers,json=payload)
        assert response.status_code==400 and response.json()['isError']
        assert '8gb' in response.json()['error']
        assert not list((tmp_path/'state'/'uploads').rglob('*.png'))
        assert client.post('/api/image',headers=headers,json={**payload,'name':'bad.exe'}).status_code==400
        assert client.post('/api/image',headers=headers,json={**payload,'data':'invalid!'}).status_code==400
