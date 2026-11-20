import asyncio
import base64
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from localguard.config import Config
from localguard.model import LocalModel, ModelUnavailable
from localguard.web import create_app


@pytest.fixture(autouse=True)
def no_live_model_or_process(monkeypatch):
    async def prohibited(*args, **kwargs):
        raise AssertionError('Test attempted real model, network, or scanner execution')
    monkeypatch.setattr(LocalModel, '_request', prohibited)
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', prohibited)


@pytest.fixture
def chat_client(tmp_path, monkeypatch):
    app = create_app(Config(allowed_roots=[tmp_path], data_dir=tmp_path/'state'))
    calls = []
    async def chat(message, target, tier, registry, session, history=None):
        calls.append({'message': message, 'target': target, 'tier': tier, 'history': history})
        return {'isError': False, 'message': 'Test-only reply', 'tool_calls': []}
    monkeypatch.setattr(app.state.registry, 'get_model', lambda: SimpleNamespace(chat=chat))
    with TestClient(app) as client:
        token = client.get('/api/bootstrap').json()['csrf_token']
        client.headers['x-csrf-token'] = token
        yield client, app.state.registry, str(tmp_path), calls


def run_ui(script, payload=None):
    node = shutil.which('node')
    if not node:
        pytest.skip('Node.js is required for isolated UI logic tests')
    app_js = Path(__file__).resolve().parents[1] / 'localguard' / 'static' / 'app.js'
    runner = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const source = fs.readFileSync(process.argv[1], 'utf8');
const startup = source.indexOf("  $('form-tab').addEventListener");
if (startup < 0) throw new Error('UI startup boundary not found');
const sandbox = { input: input.payload, TextEncoder, AbortController, setTimeout: () => 0, clearTimeout: () => {} };
Promise.resolve(vm.runInNewContext(source.slice(0, startup) + '\n' + input.script + '\n})();', sandbox))
  .then((result) => process.stdout.write(JSON.stringify(result)))
  .catch((error) => { console.error(error); process.exitCode = 1; });
"""
    result = subprocess.run([node, '-e', runner, str(app_js)], input=json.dumps({'script': script, 'payload': payload}),
                            capture_output=True, text=True, encoding='utf-8', timeout=15)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize('messages', [
    [{'role': 'user', 'content': '中' * 2700}],
    [{'role': 'assistant', 'content': '\U00020000' * 4000}],
    [{'role': 'user', 'content': 'a' * 3999 + '\U00020000'}],
    [{'role': 'user', 'content': str(index)} for index in range(20)],
    [{'role': 'user', 'content': '\\"\n' * 2000}] * 12,
    [{'role': 'user' if index % 2 else 'assistant', 'content': str(index) + '中' * 3000} for index in range(20)],
])
def test_ui_history_fits_backend_budget_without_splitting_unicode(chat_client, messages):
    history = run_ui('return boundedHistory(input);', messages)
    encoded = json.dumps({'history': history}, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    assert len(encoded) <= 16000
    assert 1 <= len(history) <= 12
    assert all(len(item['content']) <= 4000 for item in history)
    assert history[-1]['role'] == messages[-1]['role']
    expected = messages[-1]['content'][:4000]
    assert history[-1]['content'] and expected.startswith(history[-1]['content'])
    if history[-1]['content'] != expected:
        assert len(history) == 1
        larger = [{'role': history[-1]['role'], 'content': expected[:len(history[-1]['content']) + 1]}]
        assert len(json.dumps({'history': larger}, ensure_ascii=False, separators=(',', ':')).encode('utf-8')) > 16000
    client, registry, target, calls = chat_client
    response = client.post('/api/chat', json={'message': 'Review', 'target': target, 'history': history})
    assert response.status_code == 200, response.text
    assert calls[0]['history'] == history


def test_ui_chat_failure_is_announced_and_preserves_tool_diagnostics():
    result = run_ui(r"""
const elements = new Map();
function element() {
  const item = {
    children: [], className: '', textContent: '', attributes: {},
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
    remove() {}, addEventListener() {},
    setAttribute(name, value) { this.attributes[name] = value; },
    querySelector(selector) { return this.children.find((child) => child.className.split(' ').includes(selector.slice(1))); },
  };
  item.classList = {
    add(name) { item.className += ' ' + name; },
    remove(name) { item.className = item.className.split(' ').filter((value) => value !== name).join(' '); },
  };
  return item;
}
globalThis.document = {
  getElementById(id) { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); },
  createElement: element, querySelectorAll: () => [],
};
globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => input });
state.ready = true;
state.csrf = 'test-only-token';
return (async () => {
  await sendChat({ message: 'Review', target: 'C:/test', history: [] });
  const reply = elements.get('chat-log').children[1];
  return { body: reply.querySelector('.chat-body').textContent,
    author: reply.querySelector('.chat-author').textContent, role: reply.attributes.role,
    tools: reply.querySelector('.chat-tools')?.children.map((item) => item.textContent),
    announcement: elements.get('announcement')?.textContent, history: state.history };
})();
""", {'isError': True, 'error': 'Local model ran out of memory.', 'message': 'Local model ran out of memory.',
      'tool_calls': [{'name': 'list_tree', 'result': {'untrusted_data': {'isError': True, 'error': 'Target denied.'}}}]})
    assert 'out of memory' in result['body']
    assert '失败' in result['author']
    assert result['role'] == 'alert'
    assert '失败' in result['announcement']
    assert 'list_tree' in result['tools'][0] and 'Target denied.' in result['tools'][0]
    assert result['history'] == []


@pytest.mark.parametrize('content', ['中' * 2700, '\U00020000' * 2700])
def test_chat_history_budget_counts_utf8_not_ascii_escapes(chat_client, content):
    client, registry, target, calls = chat_client
    history = [{'role': 'user', 'content': content}]
    response = client.post('/api/chat', json={'message': 'Review', 'target': target, 'history': history})
    assert response.status_code == 200, response.text
    assert calls[0]['history'] == history


@pytest.mark.parametrize('history', [
    None, {}, [None], ['message'], [{'role': 'system', 'content': 'instructions'}],
    [{'role': 'user'}], [{'content': 'missing role'}],
    *([{'role': 'user', 'content': content}] for content in (None, {}, [], 123, True, 'a' * 4001)),
    [{'role': 'user', 'content': 'hello', 'metadata': {'extra': 'not context'}}],
    [{'role': 'user', 'content': ''}] * 13,
])
def test_chat_rejects_history_outside_bounded_role_content_schema(chat_client, history):
    client, registry, target, calls = chat_client
    response = client.post('/api/chat', json={'message': 'Review', 'target': target, 'history': history})
    assert response.status_code == 400, response.text
    assert response.json()['isError'] is True
    assert response.json()['error']
    assert not calls


@pytest.mark.parametrize('data', [[], 'not an object', 123, True, {'message': 'Review', 'target': None}])
def test_chat_rejects_nonobject_requests_and_invalid_target_types(chat_client, data):
    client, registry, target, calls = chat_client
    response = client.post('/api/chat', json=data)
    assert response.status_code == 400
    assert response.json()['isError'] is True
    assert not calls


@pytest.mark.parametrize('remote, offline, allowed', [
    ('https://github.com/example/repo.git', False, True),
    ('https://github.com/example/repo', False, True),
    ('https://github.com/example/repo', True, False),
    ('https://unlisted.example/example/repo', False, False),
])
def test_chat_uses_shared_target_validation_without_submitting_jobs(chat_client, monkeypatch, remote, offline, allowed):
    client, registry, target, calls = chat_client
    registry.config.offline = offline
    registry.config.git_hosts = ['github.com']
    validated = []
    validate_target = registry.validate_target
    def validate(value):
        validated.append(value)
        return validate_target(value)
    def prohibited(*args, **kwargs):
        raise AssertionError('Target validation must not submit or enqueue a job')
    monkeypatch.setattr(registry, 'validate_target', validate)
    monkeypatch.setattr(registry.engine, 'submit', prohibited)
    monkeypatch.setattr(registry.store, 'enqueue', prohibited)
    response = client.post('/api/chat', json={'message': 'Review', 'target': remote})
    assert response.status_code == (200 if allowed else 400), response.text
    assert validated == [remote]
    if allowed:
        assert calls[0]['target'] == remote
    else:
        assert response.json()['isError'] is True
        assert not calls


@pytest.mark.parametrize('content', ['a' * 4000, '中' * 1333, '\U00020000' * 1000])
def test_chat_history_exact_utf8_envelope_limit(chat_client, content):
    client, registry, target, calls = chat_client
    history = [{'role': 'user', 'content': content}] * 3 + [{'role': 'assistant', 'content': ''}]
    size = len(json.dumps({'history': history}, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
    history[-1]['content'] = 'x' * (16000 - size)
    assert len(history[-1]['content']) <= 4000
    response = client.post('/api/chat', json={'message': 'Review', 'target': target, 'history': history})
    assert response.status_code == 200, response.text
    history[-1]['content'] += 'x'
    response = client.post('/api/chat', json={'message': 'Review', 'target': target, 'history': history})
    assert response.status_code == 400
    assert '16000-byte' in response.json()['error']
    assert len(calls) == 1


def test_chat_rejects_invalid_unicode_history_as_error_content(chat_client):
    client, registry, target, calls = chat_client
    data = {'message': 'Review', 'target': target, 'history': [{'role': 'user', 'content': '\ud800'}]}
    response = client.post('/api/chat', content=json.dumps(data), headers={'content-type': 'application/json'})
    assert response.status_code == 400
    assert response.json()['isError'] is True
    assert 'Unicode' in response.json()['error']
    assert not calls


@pytest.mark.parametrize('outcome', ['oom', 'malformed', 'success'])
def test_chat_api_preserves_model_error_contract(chat_client, monkeypatch, outcome):
    client, registry, target, calls = chat_client
    model = LocalModel(registry.config, registry.store)
    attempts = []
    async def infer(*args, **kwargs):
        attempts.append(True)
        if outcome == 'oom':
            raise ModelUnavailable('Local model ran out of memory.')
        return {'choices': [{'message': None if outcome == 'malformed' else {'content': 'Unverified model prose'}}]}
    monkeypatch.setattr(model, '_infer', infer)
    monkeypatch.setattr(registry, 'get_model', lambda: model)
    response = client.post('/api/chat', json={'message': 'Review', 'target': target, 'model_tier': '8gb'})
    assert response.status_code == 200
    result = response.json()
    assert result['isError'] is (outcome != 'success')
    if outcome != 'success':
        assert result['error'] == result['message']
    assert 'Unverified model prose' not in response.text
    assert result['tool_calls'] == []
    assert len(attempts) == (3 if outcome == 'malformed' else 1)


@pytest.mark.parametrize('failed', [False, True])
def test_image_upload_registration_and_cleanup_are_preserved(chat_client, monkeypatch, failed):
    client, registry, target, calls = chat_client
    observed = []
    async def analyze(path, question, tier):
        observed.append(path)
        assert path.is_absolute() and path.is_file()
        assert path in next(iter(registry.uploads.values()))
        assert question == 'Describe diagram' and tier == '8gb'
        if failed:
            raise ModelUnavailable('Vision unavailable in this test.')
        return {'description': 'Test-only diagram', 'auxiliary': True, 'truncated': False}
    monkeypatch.setattr(registry, 'get_model', lambda: SimpleNamespace(analyze_image=analyze))
    response = client.post('/api/image', json={
        'name': 'diagram.png', 'data': base64.b64encode(b'\x89PNG\r\n\x1a\nTEST_ONLY').decode('ascii'),
        'question': 'Describe diagram', 'model_tier': '8gb',
    })
    assert response.status_code == (400 if failed else 200), response.text
    assert len(observed) == 1 and not observed[0].exists()
    assert registry.uploads == {}
    if failed:
        assert response.json()['isError'] is True
    else:
        assert response.json()['auxiliary'] is True


def test_shared_registry_csrf_and_source(tmp_path):
    root = tmp_path/'repo'
    root.mkdir()
    file = root/'example.txt'
    file.write_text('<script>alert(1)</script>\nsecond line\n')
    config = Config(allowed_roots=[root],data_dir=tmp_path/'state')
    app = create_app(config)
    with TestClient(app) as client:
        bootstrap = client.get('/api/bootstrap').json()
        headers = {'x-csrf-token':bootstrap['csrf_token']}
        assert client.post('/api/tools/view_file',json={'path':str(file)}).status_code==403
        response = client.post('/api/tools/view_file',json={'path':str(file)},headers=headers)
        assert response.status_code==200
        assert response.json()['data']['lines'][0]['text']=='<script>alert(1)</script>'
        assert bootstrap['tools']==app.state.registry.describe()
        assert 'script-src' in response.headers['content-security-policy']
        assert client.post('/api/tools/view_file',json={'path':str(file)},headers={**headers,'origin':'https://evil.example'}).status_code==403
        assert client.get('/api/bootstrap',headers={'host':'evil.example'}).status_code==400
        assert client.post('/api/tools/run_scanner',json={'scanner':'shell','target':str(root)},headers=headers).json()['isError']
