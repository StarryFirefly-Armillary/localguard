import hashlib
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from localguard import engine, scanners
from localguard.config import Config
from localguard.registry import ToolRegistry


BASE = '1' * 40
HEAD = '2' * 40


def blob_id(data, algorithm='sha1'):
    return hashlib.new(algorithm, b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()


def tree_entry(path, data, mode='100644', kind='blob', algorithm='sha1'):
    return f'{mode} {kind} {blob_id(data, algorithm)}\t'.encode() + path.encode('utf-8') + b'\0'


@pytest.fixture
def registry(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    (root / '.git').mkdir()
    instance = ToolRegistry(Config(allowed_roots=[root], data_dir=tmp_path / 'state', model_tier='rules'))
    instance.config.binaries['git'] = 'trusted-git-test-double'
    return instance


def mock_git(monkeypatch, patch=b'', tree=b'', commits=(BASE, HEAD)):
    calls = []
    refs = iter(commits)

    async def run(command, cwd, timeout=60, max_bytes=2_000_000):
        calls.append(command)
        if 'rev-parse' in command:
            return 0, next(refs).encode() + b'\n', b''
        if 'diff' in command:
            return 0, patch, b''
        if 'ls-tree' in command:
            return 0, tree, b''
        raise AssertionError(f'Unexpected process invocation: {command}')

    monkeypatch.setattr(engine, 'run', run)
    return calls


async def execute(registry, **args):
    root = registry.config.allowed_roots[0]
    queued = registry.store.enqueue('incremental-test', {
        'target': str(root), 'incremental': True, 'scanners': ['patterns'],
        'include_dependencies': False, 'model_tier': 'rules', **args,
    })
    await registry.engine.execute(registry.store.claim())
    return registry.store.get(queued['audit_id'], 'incremental-test')


@pytest.mark.anyio
async def test_diff_decodes_quoted_paths_and_resets_each_block(registry, monkeypatch):
    names = [b'b/plain.py', b'b/with spaces.py\t', b'"b/quote\\\"name.py"',
             b'"b/tab\\tname.py"', b'"b/\\344\\270\\255\\346\\226\\207.py"']
    patch = b''
    for index, name in enumerate(names, 1):
        patch += (b'diff --git ignored ignored\n--- a/old.py\n+++ ' + name
                  + f'\n@@ -0,0 +{index} @@\n+new\n'.encode())
    patch += b'diff --git a/deleted.py b/deleted.py\n--- a/deleted.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n'
    mock_git(monkeypatch, patch)
    result = await registry.engine.diff(str(registry.config.allowed_roots[0]))
    assert result['changes'] == [
        {'path': name, 'start_line': index, 'end_line': index}
        for index, name in enumerate(['plain.py', 'with spaces.py', 'quote"name.py', 'tab\tname.py', '中文.py'], 1)
    ]


@pytest.mark.anyio
async def test_diff_ignores_header_like_added_source_after_first_hunk(registry, monkeypatch):
    patch = (b'diff --git a/real.py b/real.py\n--- a/real.py\n+++ b/real.py\n'
             b'@@ -0,0 +1,4 @@\n+++ b/forged.py\n+diff --git a/x b/x\n+--- a/x\n+@@ -0,0 +500 @@\n'
             b'@@ -10 +14 @@\n-old\n+new\n')
    mock_git(monkeypatch, patch)
    result = await registry.engine.diff(str(registry.config.allowed_roots[0]))
    assert result['changes'] == [
        {'path': 'real.py', 'start_line': 1, 'end_line': 4},
        {'path': 'real.py', 'start_line': 14, 'end_line': 14},
    ]


@pytest.mark.anyio
async def test_incremental_rejects_worktree_different_from_requested_head(registry, monkeypatch):
    root = registry.config.allowed_roots[0]
    (root / 'app.py').write_bytes(b'auth_bypass = True\n')
    mock_git(monkeypatch, tree=tree_entry('app.py', b'auth_bypass = False\n'))
    scanner = AsyncMock(return_value={'status': 'completed', 'findings': [], 'warnings': []})
    monkeypatch.setattr(scanners, 'run_scanner', scanner)
    result = await execute(registry, head='older-head')
    assert result['status'] == 'failed', result
    assert 'requested head' in result['error'] and 'app.py' in result['error']
    scanner.assert_not_awaited()
    assert (root / 'app.py').read_bytes() == b'auth_bypass = True\n'


@pytest.mark.anyio
async def test_incremental_snapshot_excludes_untracked_files(registry, monkeypatch):
    root = registry.config.allowed_roots[0]
    (root / 'app.py').write_bytes(b'pass\n')
    (root / 'untracked.py').write_bytes(b'auth_bypass = True\n')
    mock_git(monkeypatch, tree=tree_entry('app.py', b'pass\n'))
    seen = []

    async def scanner(name, snapshot, *args, **kwargs):
        seen.extend(path.relative_to(snapshot).as_posix() for path in snapshot.rglob('*') if path.is_file())
        return {'status': 'completed', 'findings': [], 'warnings': []}

    monkeypatch.setattr(scanners, 'run_scanner', scanner)
    result = await execute(registry)
    assert result['status'] == 'completed', result
    assert seen == ['app.py']
    assert result['coverage']['files'] == 1


@pytest.mark.anyio
async def test_remote_clone_requests_two_commits(registry, monkeypatch):
    registry.config.offline = False
    calls = []

    async def clone(command, *args):
        calls.append(command)
        Path(command[-1]).mkdir()
        return 0, b'', b''

    monkeypatch.setattr(engine, 'run', clone)
    root = await registry.engine.resolve_target('https://github.com/example/repo', 'mock-clone')
    assert root.is_dir()
    assert calls[0][calls[0].index('--depth') + 1] == '2'
