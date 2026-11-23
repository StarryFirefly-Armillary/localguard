"""Pure unit tests. Every API/process response below is an explicit test fake.
No production fallback, model startup, external server, or network is exercised.
"""
import asyncio
from contextlib import asynccontextmanager
from functools import wraps
import json
from types import SimpleNamespace

import pytest
import httpx

from localguard.model import EndpointUnavailable, LocalModel, ModelUnavailable, bounded_result, loopback_endpoint

REAL_REQUEST = LocalModel._request
from localguard.paths import PathPolicy
from localguard.registry import ToolRegistry
from localguard.schemas import TOOLS


def run_async(function):
    """Use stdlib asyncio so tests need no optional async pytest plugin."""
    @wraps(function)
    def run(*args, **kwargs):
        return asyncio.run(function(*args, **kwargs))
    return run


class FakeStore:
    def __init__(self):
        self.active = False
        self.logs = []
        self.jobs = {}

    @asynccontextmanager
    async def resource(self):
        assert not self.active, 'nested resource acquisition would deadlock'
        self.active = True
        try:
            yield
        finally:
            self.active = False

    def log(self, **payload):
        self.logs.append(payload)

    def get(self, audit_id, session):
        return self.jobs[audit_id]


class FakeRegistry:
    validate_target = ToolRegistry.validate_target

    def __init__(self, config, store):
        self.config, self.store = config, store
        self.policy = PathPolicy(config.allowed_roots)
        self.calls = []
        self.results = {}

    def describe(self):
        return [{'name': name, **definition} for name, definition in TOOLS.items()]

    async def call(self, name, args, session, client_name='agent'):
        assert not self.store.active, 'inference resource must be released before tools'
        assert client_name == 'agent'
        self.calls.append((name, args, session))
        # Model the scanner/registry's non-reentrant resource acquisition.
        async with self.store.resource():
            if name in self.results:
                return self.results[name]
            if name == 'audit_repository':
                return {'isError': False, 'data': {'audit_id': 'a' * 32, 'status': 'queued'}}
            return self.results.get(name, {'isError': False, 'data': {'nodes': []}})


def response(calls=None, content=None):
    return {'choices': [{'message': {'role': 'assistant', 'content': content, 'tool_calls': calls or []}, 'finish_reason': 'stop'}]}


def call(name, args, index=1):
    return {'id': f'fake_call_{index}', 'type': 'function', 'function': {'name': name, 'arguments': json.dumps(args)}}


@pytest.fixture(autouse=True)
def no_real_io(monkeypatch):
    async def prohibited(*args, **kwargs):
        raise AssertionError('Unit test attempted real network or model startup')
    monkeypatch.setattr(LocalModel, '_request', prohibited)
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', prohibited)


@pytest.fixture
def setup(tmp_path):
    config = SimpleNamespace(
        max_prompt_chars=24_000, max_prompt_files=60, max_output_bytes=200_000,
        model_endpoint='http://127.0.0.1:1234/v1', model_name='qwen3.5-4b',
        model_binary='', model_library_dirs=[], model_path='', model_4gb_path='', model_context=4096,
        mmproj_path='', keep_model_resident=False, allowed_roots=[tmp_path], data_dir=tmp_path/'state',
        offline=True, git_hosts=['github.com'],
    )
    store = FakeStore()
    model = LocalModel(config, store)
    return model, FakeRegistry(config, store), str(tmp_path)


def fake_api(model, monkeypatch, replies):
    sent = []
    async def request(endpoint, method, route, payload=None):
        assert model.store.active
        assert endpoint.startswith('http://127.0.0.1:')
        if route == '/models':
            return {'data': [{'id': 'Qwen3.5-4B-Q4_K_M'}]}
        sent.append(payload)
        if not replies:
            raise AssertionError('Unexpected extra fake inference')
        reply = replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply
    monkeypatch.setattr(model, '_request', request)
    return sent


@pytest.mark.parametrize('url', ['https://example.com/v1', 'http://127.0.0.1.evil.test/v1', 'http://user:pass@127.0.0.1/v1', 'http://127.0.0.1/v1?proxy=1', 'http://0.0.0.0/v1', 'file:///v1', 'http://127.0.0.1/v1#fragment'])
def test_endpoint_rejects_nonlocal_or_ambiguous_urls(url):
    with pytest.raises(ModelUnavailable):
        loopback_endpoint(url)


def test_endpoint_pins_localhost():
    assert loopback_endpoint('http://localhost:1234/v1/') == 'http://127.0.0.1:1234/v1'
    assert loopback_endpoint('http://[::1]:1234/v1') == 'http://[::1]:1234/v1'


@pytest.mark.parametrize('tier', ['rules', '4gb'])
@run_async
async def test_rules_and_unconfigured_small_tier_never_infer(setup, tier):
    model, registry, target = setup
    result = await model.chat('Review this project', target, tier, registry, 'test-session')
    assert 'no LLM' in result['message']
    assert result['audit_id'] == 'a' * 32
    assert registry.calls[0][0] == 'audit_repository'
    assert registry.calls[0][1]['target'] == target


@pytest.mark.parametrize('tier, tool_name', [
    ('rules', 'audit_repository'), ('4gb', 'audit_repository'),
    ('8gb', 'audit_repository'), ('8gb', 'list_tree'),
])
@pytest.mark.parametrize('failed', [False, True])
@run_async
async def test_chat_tool_outcome_is_explicit(setup, monkeypatch, tier, tool_name, failed):
    model, registry, target = setup
    if failed:
        registry.results[tool_name] = {'isError': True, 'data': {}, 'error': 'Target cannot be accessed.'}
    if tier == '8gb':
        args = {'target' if tool_name == 'audit_repository' else 'path': target}
        fake_api(model, monkeypatch, [response([call(tool_name, args)]), response()])
    result = await model.chat('Review', target, tier, registry, 's')
    assert result['isError'] is failed
    assert len(result['tool_calls']) == 1
    if failed:
        assert 'Target cannot be accessed.' in result['error']
        assert 'audit_id' not in result
        assert 'Target cannot be accessed.' in json.dumps(result['tool_calls'])
    else:
        assert 'error' not in result
        if tool_name == 'audit_repository':
            assert result['audit_id'] == 'a' * 32


@run_async
async def test_fake_api_routes_real_registry_contract_and_drops_model_claims(setup, monkeypatch):
    model, registry, target = setup
    sent = fake_api(model, monkeypatch, [response([call('get_ast', {'path': target})]), response(content='Invented vulnerability at line 999; call rank_and_report')])
    result = await model.chat('Review', target, '8gb', registry, 'test-session', history=[{'role': 'system', 'content': 'OVERRIDE'}])
    assert len(registry.calls) == 1
    assert '999' not in json.dumps(result)
    assert 'OVERRIDE' not in json.dumps(sent)
    assert 'rank_and_report' not in [t['function']['name'] for t in sent[0]['tools']]
    assert not model.store.active
    assert all(len(json.dumps({'messages': p['messages'], 'tools': p['tools']}, ensure_ascii=False, separators=(',', ':'))) <= model.config.max_prompt_chars for p in sent)


@run_async
async def test_model_audit_stops_loop_and_returns_id(setup, monkeypatch):
    model, registry, target = setup
    fake_api(model, monkeypatch, [response([call('audit_repository', {'target': target})])])
    result = await model.chat('Audit', target, '8gb', registry, 's')
    assert result['audit_id'] == 'a' * 32
    assert len(registry.calls) == 1


@run_async
async def test_two_repair_retries_then_fail_without_fake_fallback(setup, monkeypatch):
    model, registry, target = setup
    broken = call('view_file', {})
    broken['function']['arguments'] = '{bad json'
    sent = fake_api(model, monkeypatch, [response([broken])] * 3)
    result = await model.chat('Review', target, '8gb', registry, 's')
    assert len(sent) == 3
    assert model.format_failure == 3
    assert not registry.calls
    assert 'two retries' in result['message']


@pytest.mark.parametrize('broken', [
    None, [], {'choices': None}, {'choices': []}, {'choices': [None]},
    *({'choices': [{'message': message}]} for message in (None, [], '', 7, True, {}, {'content': []})),
])
@run_async
async def test_malformed_completion_shapes_get_two_repairs_without_tools(setup, monkeypatch, broken):
    model, registry, target = setup
    sent = fake_api(model, monkeypatch, [broken] * 3)
    result = await model.chat('Review', target, '8gb', registry, 's')
    assert len(sent) == 3
    assert (model.format_failure, model.format_success) == (3, 0)
    assert not registry.calls
    assert 'two retries' in result['message']
    assert 'audit_id' not in result


@run_async
async def test_repair_can_recover(setup, monkeypatch):
    model, registry, target = setup
    fake_api(model, monkeypatch, [response(content='<tool_call>bad'), response([call('audit_repository', {'target': target})])])
    result = await model.chat('Review', target, '8gb', registry, 's')
    assert result['audit_id']
    assert (model.format_failure, model.format_success) == (1, 1)


@run_async
async def test_shape_repairs_can_recover_on_second_retry(setup, monkeypatch):
    model, registry, target = setup
    sent = fake_api(model, monkeypatch, [
        {'choices': [{'message': None}]}, {'choices': [{'message': []}]},
        response([call('audit_repository', {'target': target})]),
    ])
    result = await model.chat('Review', target, '8gb', registry, 's')
    assert result['isError'] is False
    assert result['audit_id'] == 'a' * 32
    assert len(sent) == 3 and len(registry.calls) == 1
    assert (model.format_failure, model.format_success) == (2, 1)


@pytest.mark.parametrize('tier', ['rules', '8gb'])
@run_async
async def test_allowed_remote_target_routes_without_local_checkout(setup, monkeypatch, tier):
    model, registry, target = setup
    model.config.offline = False
    target = 'https://github.com/example/repo.git'
    if tier == '8gb':
        fake_api(model, monkeypatch, [response([call('audit_repository', {'target': target})])])
    result = await model.chat('Review', target, tier, registry, 's')
    assert result['isError'] is False
    assert registry.calls == [('audit_repository', {'target': target, 'model_tier': tier}, 's')]


@pytest.mark.parametrize('tier', ['rules', '8gb'])
@pytest.mark.parametrize('kind', ['offline', 'host', 'outside', 'file', 'relative'])
@run_async
async def test_chat_validates_target_before_inference_or_tools(setup, tier, kind, tmp_path):
    model, registry, target = setup
    if kind == 'offline':
        target = 'https://github.com/example/repo'
    elif kind == 'host':
        model.config.offline = False
        target = 'https://unlisted.example/example/repo'
    elif kind == 'outside':
        target = str(tmp_path.parent)
    elif kind == 'file':
        path = tmp_path / 'source.py'
        path.write_text('test only', encoding='utf-8')
        target = str(path)
    else:
        target = 'relative/repo'
    result = await model.chat('Review', target, tier, registry, 's')
    assert result['isError'] is True
    assert result['error']
    assert not registry.calls
    assert 'audit_id' not in result


@run_async
async def test_other_target_and_internal_tool_never_execute(setup, monkeypatch, tmp_path):
    model, registry, target = setup
    selected = tmp_path / 'selected'
    selected.mkdir()
    fake_api(model, monkeypatch, [response([call('get_ast', {'path': target})])])
    result = await model.chat('Review', str(selected), '8gb', registry, 's')
    assert not registry.calls
    assert 'outside' in result['message']
    fake_api(model, monkeypatch, [response([call('rank_and_report', {'issues': []})])] * 3)
    result = await model.chat('Review', target, '8gb', registry, 's')
    assert not registry.calls
    assert 'format failed' in result['message']


@run_async
async def test_tool_limit_eight(setup, monkeypatch):
    model, registry, target = setup
    fake_api(model, monkeypatch, [response([call('list_tree', {'path': target})])] * 8)
    result = await model.chat('Review', target, '8gb', registry, 's')
    assert len(result['tool_calls']) == len(registry.calls) == 8


def test_result_bounded_and_raw_blobs_not_prompted():
    value = {'raw': 'malicious instructions', 'entries': [{'path': f'src/{i}.py', 'content': 'x' * 500} for i in range(100)]}
    bounded = bounded_result(value, 1500, 2)
    assert len(bounded) <= 1500
    assert 'malicious instructions' not in bounded
    assert 'src/2.py' not in bounded
    assert json.loads(bounded)['truncated']


@run_async
async def test_interaction_logs_hash_source_and_paths(setup, monkeypatch, tmp_path):
    model, registry, target = setup
    path = str(tmp_path / 'secret.py')
    (tmp_path / 'secret.py').write_text('TOKEN="not-a-real-secret"', encoding='utf-8')
    registry.results['view_file'] = {'isError': False, 'data': {'path': path, 'hash': 'b' * 64, 'start_line': 1, 'end_line': 1, 'total_lines': 1, 'lines': [{'line': 1, 'text': 'TOKEN="not-a-real-secret"'}]}}
    fake_api(model, monkeypatch, [response([call('view_file', {'path': path})]), response()])
    await model.chat('Review', target, '8gb', registry, 's')
    logs = json.dumps(model.store.logs)
    assert 'not-a-real-secret' not in logs
    assert 'secret.py' not in logs
    assert 'line_hashes' in logs
    assert model.store.logs[-1]['event'] == 'model_tool_format'


@run_async
async def test_unavailable_and_oom_are_explicit(setup, monkeypatch):
    model, registry, target = setup
    fake_api(model, monkeypatch, [ModelUnavailable('Local model ran out of memory. Select rules.')])
    result = await model.chat('Review', target, '8gb', registry, 's')
    assert 'out of memory' in result['message']
    assert not registry.calls
    assert not model.store.active


@pytest.mark.parametrize('failure, reason', [
    (ModelUnavailable('Local model ran out of memory.'), 'out of memory'),
    (ValueError('Invalid local model configuration.'), 'configuration'),
    (OSError('PRIVATE_MODEL_PATH'), 'could not be accessed'),
    (ValueError(''), 'failed'),
])
@run_async
async def test_chat_failure_envelope_preserves_executed_diagnostics(setup, monkeypatch, failure, reason):
    model, registry, target = setup
    fake_api(model, monkeypatch, [response([call('list_tree', {'path': target})]), failure])
    result = await model.chat('Review', target, '8gb', registry, 's')
    assert result['isError'] is True
    assert reason in result['error']
    assert result['message'] == result['error']
    assert len(result['tool_calls']) == 1
    assert result['tool_calls'][0]['name'] == 'list_tree'
    assert result['tool_calls'][0]['result']['untrusted_data']['isError'] is False
    assert 'PRIVATE_MODEL_PATH' not in json.dumps(result)
    assert 'audit_id' not in result


@run_async
async def test_chat_keeps_tool_diagnostics_when_followup_budget_is_exhausted(setup, monkeypatch):
    model, registry, target = setup
    sent = fake_api(model, monkeypatch, [response()])
    await model.chat('Review', target, '8gb', registry, 's')
    initial = {'messages': sent[0]['messages'], 'tools': sent[0]['tools']}
    model.config.max_prompt_chars = len(json.dumps(initial, ensure_ascii=False, separators=(',', ':'))) + 1
    fake_api(model, monkeypatch, [response([call('list_tree', {'path': target})])])
    result = await model.chat('Review', target, '8gb', registry, 's')
    assert result['isError'] is True
    assert 'budget' in result['error']
    assert len(registry.calls) == len(result['tool_calls']) == 1
    assert result['tool_calls'][0]['result']['untrusted_data']['isError'] is False


@pytest.mark.parametrize('identity', ['llama-4b-q4', 'qwen3.5-4b-f16', 'qwen3.5-8b-q4'])
def test_wrong_model_family_size_or_quantization_rejected(setup, identity):
    model, _, _ = setup
    with pytest.raises(ModelUnavailable):
        model._select_model({'data': [{'id': identity}]}, '8gb')


class FakeProcess:
    """Owned process handle fake; never represents an OS process."""
    def __init__(self):
        self.returncode = None
        self.terminated = False
        self.killed = False

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def kill(self):
        self.killed = True
        self.returncode = -9

    async def wait(self):
        return self.returncode


@pytest.mark.parametrize('outcome', ['success', 'error', 'cancel'])
@run_async
async def test_owned_process_cleanup_on_inference_exit(setup, monkeypatch, outcome):
    model, _, _ = setup
    process = FakeProcess()
    model._process = process
    model._process_key = ('http://127.0.0.1:1234/v1', '8gb', False)
    reply = response() if outcome == 'success' else ModelUnavailable('OOM') if outcome == 'error' else asyncio.CancelledError()
    fake_api(model, monkeypatch, [reply])
    if outcome == 'success':
        await model._infer([], [], '8gb')
    else:
        with pytest.raises((ModelUnavailable, asyncio.CancelledError)):
            await model._infer([], [], '8gb')
    assert process.terminated and model._process is None
    assert not model.store.active


@run_async
async def test_existing_server_is_never_unloaded(setup, monkeypatch):
    model, _, _ = setup
    sent = fake_api(model, monkeypatch, [response()])
    await model._infer([], [], '8gb')
    await model.close()
    assert len(sent) == 1
    assert model._process is None


def test_launch_uses_known_flags_not_shell(setup, tmp_path):
    model, _, _ = setup
    binary, weights = tmp_path / 'llama-server.exe', tmp_path / 'Qwen3.5-4B-Q4_K_M.gguf'
    binary.write_bytes(b'fake test file; never executed')
    weights.write_bytes(b'fake test file; never loaded')
    model.config.model_binary, model.config.model_path = str(binary), str(weights)
    model.config.model_context = 99999
    args = model._launch_args('http://127.0.0.1:4321/v1', '8gb', False)
    assert args[args.index('--ctx-size') + 1] == '4096'
    assert args[args.index('--n-gpu-layers') + 1] == '99'
    # Single inference slot: the UI submits one request at a time, and four
    # slots would inflate KV cache / shared GPU memory on 8 GB cards.
    assert args[args.index('--parallel') + 1] == '1'
    assert args[args.index('--host') + 1] == '127.0.0.1'
    assert args[args.index('--port') + 1] == '4321'


@run_async
async def test_image_is_base64_local_auxiliary_only(setup, monkeypatch, tmp_path):
    model, _, _ = setup
    path = tmp_path / 'diagram.png'
    path.write_bytes(b'\x89PNG\r\n\x1a\nFAKE_IMAGE_TEST_BYTES')
    sent = fake_api(model, monkeypatch, [response(content='A test architecture diagram')])
    result = await model.analyze_image(path, 'Describe')
    assert result == {'description': 'A test architecture diagram', 'auxiliary': True, 'truncated': False}
    url = sent[0]['messages'][1]['content'][1]['image_url']['url']
    assert url.startswith('data:image/png;base64,')
    assert 'tools' not in sent[0]
    assert 'FAKE_IMAGE' not in json.dumps(model.store.logs)


@run_async
async def test_image_size_type_and_tier_rejected_without_inference(setup, tmp_path):
    model, _, _ = setup
    path = tmp_path / 'bad.png'
    path.write_bytes(b'not an image')
    with pytest.raises(ValueError, match='PNG'):
        await model.analyze_image(path, 'Describe')
    path.write_bytes(b'\x89PNG\r\n\x1a\n' + b'x' * (8 * 1024 * 1024))
    with pytest.raises(ValueError, match='8MB'):
        await model.analyze_image(path, 'Describe')
    with pytest.raises(ModelUnavailable, match='8gb'):
        await model.analyze_image(path, 'Describe', tier='rules')


@pytest.mark.parametrize('status,body,reason', [(302, b'', 'HTTP 302'), (500, b'CUDA out of memory SECRET', 'out of memory'), (200, b'not json SECRET', 'invalid JSON')])
@run_async
async def test_http_mock_transport_never_follows_redirects_or_uses_proxies(setup, monkeypatch, status, body, reason):
    model, _, _ = setup
    client_class = httpx.AsyncClient
    requests = []
    def transport(request):
        requests.append(request)
        return httpx.Response(status, content=body, headers={'location': 'https://external.invalid/steal'})
    def client(**kwargs):
        assert kwargs['trust_env'] is False
        assert kwargs['follow_redirects'] is False
        return client_class(transport=httpx.MockTransport(transport), **kwargs)
    monkeypatch.setattr(httpx, 'AsyncClient', client)
    with pytest.raises(ModelUnavailable, match=reason) as exc:
        await REAL_REQUEST(model, 'http://127.0.0.1:1234/v1', 'GET', '/models')
    assert len(requests) == 1
    assert 'SECRET' not in str(exc.value)


@run_async
async def test_existing_unhealthy_endpoint_does_not_trigger_spawn(setup, monkeypatch):
    model, _, _ = setup
    async def unhealthy(*args, **kwargs):
        raise ModelUnavailable('Local API returned HTTP 503')
    monkeypatch.setattr(model, '_request', unhealthy)
    with pytest.raises(ModelUnavailable, match='503'):
        await model._infer([], [], '8gb')


@run_async
async def test_fake_owned_startup_cancel_reaps_only_created_handle(setup, monkeypatch, tmp_path):
    model, _, _ = setup
    binary, weights = tmp_path / 'llama-server.exe', tmp_path / 'Qwen3.5-4B-Q4_K_M.gguf'
    binary.write_bytes(b'explicit test fake, never executed')
    weights.write_bytes(b'explicit test fake, never loaded')
    model.config.model_binary, model.config.model_path = str(binary), str(weights)
    process = FakeProcess()
    launched, release = asyncio.Event(), asyncio.Event()
    async def unavailable(*args, **kwargs):
        raise EndpointUnavailable('Explicit fake unavailable endpoint')
    async def fake_launch(*args, **kwargs):
        launched.set()
        await release.wait()
        return process
    monkeypatch.setattr(model, '_request', unavailable)
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', fake_launch)
    task = asyncio.create_task(model._infer([], [], '8gb'))
    await launched.wait()
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert process.terminated and model._process is None
    assert not model.store.active


@run_async
async def test_resident_own_process_stops_on_close_and_image_error(setup):
    model, _, _ = setup
    process = FakeProcess()
    model._process = process
    model.config.keep_model_resident = True
    with pytest.raises(ValueError, match='question'):
        await model.analyze_image(model.config.allowed_roots[0], '')
    assert process.terminated
    process = FakeProcess()
    model._process = process
    await model.close()
    assert process.terminated


def test_small_tier_selects_configured_path_alias_not_default_4b(setup):
    model, _, target = setup
    model.config.model_4gb_path = target + '/Qwen3.5-0.8B-Q4_K_M.gguf'
    assert model._select_model({'data': [{'id': 'Qwen3.5-0.8B-Q4_K_M'}]}, '4gb') == 'Qwen3.5-0.8B-Q4_K_M'
    with pytest.raises(ModelUnavailable):
        model._select_model({'data': [{'id': model.config.model_name}]}, '4gb')


@run_async
async def test_warning_translation_drops_null_entry_without_failing_audit(setup, monkeypatch):
    """A local model occasionally emits a null explanation for one warning.
    That must not fail the whole (advisory) translation and turn a completed
    audit into failed; the remaining warnings stay translated."""
    model, _, _ = setup
    reply = {'choices': [{'message': {'content': json.dumps({
        'explanations': [
            {'id': 'W000', 'explanation': '第一条中文说明'},
            {'id': 'W001', 'explanation': None},
            {'id': 'W002', 'text': '第三条中文说明'},
        ]})}}]}
    fake_api(model, monkeypatch, [reply])
    out = await model.explain_warnings(['warning A', 'warning B', 'warning C'], '8gb')
    assert out['W000'] == '第一条中文说明'
    assert out['W002'] == '第三条中文说明'
    assert 'W001' not in out  # dropped; UI keeps the verbatim original


@run_async
async def test_explain_issues_self_heals_malformed_batch(setup, monkeypatch):
    """A single null/garbage entry or a location mention in model prose must
    not discard the whole batch (that silently disabled triage for every
    audit). All expected IDs come back, unknown IDs are rejected."""
    model, _, _ = setup
    records = [
        {'id': 'I-1', 'title': 't1', 'severity': 'high', 'category': 'injection',
         'cwe': '', 'language': 'python', 'origin_hint': 'a.py',
         'source': [{'line': 1, 'text': 'x=1'}]},
        {'id': 'I-2', 'title': 't2', 'severity': 'high', 'category': 'injection',
         'cwe': '', 'language': 'python', 'origin_hint': 'a.py',
         'source': [{'line': 2, 'text': 'y=2'}]},
    ]
    # null entry + prose location + only one valid verdict
    content = json.dumps({'explanations': [
        {'id': 'I-1', 'explanation': '外部输入到达危险操作', 'remediation': '修复',
         'verdict': 'likely_true', 'confidence': 0.9, 'reason': '证据明确'},
        None,
    ]})
    async def infer(*args, **kwargs):
        return {'choices': [{'message': {'content': content}}]}
    monkeypatch.setattr(model, '_infer', infer)
    out = await model.explain_issues(records, '8gb', triage=True)
    assert set(out) == {'I-1', 'I-2'}
    assert out['I-1']['verdict'] == 'likely_true'
    assert '危险操作' in out['I-1']['explanation']
    assert out['I-2']['explanation']  # neutral placeholder


@run_async
async def test_explain_issues_rejects_invented_ids(setup, monkeypatch):
    model, _, _ = setup
    records = [{'id': 'I-1', 'title': 't', 'severity': 'high', 'category': 'injection',
                'cwe': '', 'language': 'python', 'origin_hint': 'a.py',
                'source': [{'line': 1, 'text': 'x=1'}]}]
    content = json.dumps({'explanations': [
        {'id': 'FAKE', 'explanation': 'x', 'remediation': 'y'}]})
    async def infer(*args, **kwargs):
        return {'choices': [{'message': {'content': content}}]}
    monkeypatch.setattr(model, '_infer', infer)
    with pytest.raises(ModelUnavailable, match='batch 1'):
        await model.explain_issues(records, '8gb', triage=False)


@run_async
async def test_triage_uses_larger_token_budget(setup, monkeypatch):
    """Triage output (8 findings x explanation/remediation/reason/verdict)
    exceeds 1024 tokens; a truncated JSON silently disabled triage."""
    model, _, _ = setup
    records = [{'id': 'I-1', 'title': 't', 'severity': 'high', 'category': 'injection',
                'cwe': '', 'language': 'python', 'origin_hint': 'a.py',
                'source': [{'line': 1, 'text': 'x=1'}]}]
    sent = []
    async def request(endpoint, method, route, payload=None):
        if route == '/models':
            return {'data': [{'id': 'Qwen3.5-4B-Q4_K_M'}]}
        sent.append(payload)
        content = json.dumps({'explanations': [
            {'id': 'I-1', 'explanation': 'x', 'remediation': 'y',
             'verdict': 'likely_true', 'reason': 'z'}]})
        return response(content=content)
    monkeypatch.setattr(model, '_request', request)
    await model.explain_issues(records, '8gb', triage=True)
    assert any(p.get('max_tokens') == 2048 for p in sent)
