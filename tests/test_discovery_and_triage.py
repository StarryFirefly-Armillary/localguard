import json

import pytest

from localguard.config import Config
from localguard.discovery import classify, is_test_root
from localguard.model import LocalModel, ModelUnavailable
from localguard.storage import Store


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    return path


def test_discovery_is_generic_and_reports_reasons(tmp_path):
    root = tmp_path / 'project'
    tests = [
        ('tests/test_api.py', 'assert True', 'conventional'),
        ('src/app.py', 'print("hi")', None),
        ('src/__tests__/x.test.js', 'test()', 'conventional'),
        ('docs/guide.md', 'text', None),
        ('package-lock.json', '{}', 'non-source'),
        ('weird/notes.txt', '# STATIC FIXTURE ONLY, never execute\nsecret = "x"', 'declares'),
    ]
    for rel, text, expected in tests:
        p = write(root / rel, text)
        reason = classify(p, root)
        if expected is None:
            assert reason is None, (rel, reason)
        else:
            assert reason and expected in reason, (rel, reason)


def test_generated_and_nested_test_dirs(tmp_path):
    root = tmp_path / 'project'
    for rel in ['coverage/report.html', 'dist/bundle.js', '.pytest_cache/x', 'a/b/spec/y.py']:
        assert classify(write(root / rel, 'data'), root) is not None
    assert is_test_root(tmp_path / 'repo' / 'fixtures')
    assert not is_test_root(tmp_path / 'repo' / 'src')


def triage_item(verdict='likely_true', **extra):
    return {'id': 'ISSUE-1', 'explanation': '工具发现可疑模式，需人工确认。',
            'remediation': '限制输入并使用安全接口。', 'verdict': verdict,
            'confidence': 0.8, 'reason': '证据来自实际调用路径，非测试样本。', **extra}


@pytest.mark.anyio
async def test_triage_schema_and_non_thinking_request(tmp_path, monkeypatch):
    config = Config(allowed_roots=[tmp_path], data_dir=tmp_path / 'state')
    model = LocalModel(config, Store(config.data_dir))
    payloads = []

    async def request(endpoint, method, route, payload=None):
        if route == '/models':
            return {'data': [{'id': 'Qwen3.5-4B-Q4_K_M'}]}
        payloads.append(payload)
        return {'choices': [{'message': {'content': json.dumps({'explanations': [triage_item()]})}}]}

    monkeypatch.setattr(model, '_request', request)
    result = await model.explain_issues([{'id': 'ISSUE-1', 'source': []}], triage=True)
    assert result['ISSUE-1']['verdict'] == 'likely_true'
    assert result['ISSUE-1']['confidence'] == 0.8
    assert payloads[0]['chat_template_kwargs'] == {'enable_thinking': False}
    await model.close()


@pytest.mark.anyio
async def test_triage_gate_rejects_unknown_fields(tmp_path, monkeypatch):
    config = Config(allowed_roots=[tmp_path], data_dir=tmp_path / 'state')
    model = LocalModel(config, Store(config.data_dir))

    async def infer(*args, **kwargs):
        bad = {**triage_item(), 'invented': 'field'}
        return {'choices': [{'message': {'content': json.dumps({'explanations': [bad]})}}]}

    monkeypatch.setattr(model, '_infer', infer)
    with pytest.raises(ModelUnavailable, match='schema or location'):
        await model.explain_issues([{'id': 'ISSUE-1', 'source': []}], triage=True)
    await model.close()


@pytest.mark.anyio
@pytest.mark.parametrize('item,expect_triage,expect_conf', [
    (triage_item('definitely_true'), False, None),
    (triage_item(confidence=2), True, None),
])
async def test_malformed_triage_is_dropped_not_fatal(tmp_path, monkeypatch, item, expect_triage, expect_conf):
    config = Config(allowed_roots=[tmp_path], data_dir=tmp_path / 'state')
    model = LocalModel(config, Store(config.data_dir))

    async def infer(*args, **kwargs):
        return {'choices': [{'message': {'content': json.dumps({'explanations': [item]})}}]}

    monkeypatch.setattr(model, '_infer', infer)
    result = await model.explain_issues([{'id': 'ISSUE-1', 'source': []}], triage=True)
    assert ('verdict' in result['ISSUE-1']) is expect_triage
    assert result['ISSUE-1'].get('confidence') == expect_conf
    await model.close()


@pytest.mark.anyio
async def test_triage_reason_location_is_sanitized_not_fatal(tmp_path, monkeypatch):
    config = Config(allowed_roots=[tmp_path], data_dir=tmp_path / 'state')
    model = LocalModel(config, Store(config.data_dir))
    item = triage_item(reason='证据位于 vulnerable.py:47，第47行')

    async def infer(*args, **kwargs):
        return {'choices': [{'message': {'content': json.dumps({'explanations': [item]})}}]}

    monkeypatch.setattr(model, '_infer', infer)
    result = await model.explain_issues([{'id': 'ISSUE-1', 'source': []}], triage=True)
    assert result['ISSUE-1']['verdict'] == 'likely_true'
    assert '47' not in result['ISSUE-1']['reason']
    await model.close()
