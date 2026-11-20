import asyncio
import json
import os
from pathlib import Path
import sys
import time

import psutil
import pytest

from localguard import process, scanners


PYTHON = str(Path(sys.executable).resolve())
MAX_DURATION = 5


def command(code):
    return [PYTHON, '-I', '-c', code]


def alive(pid):
    try:
        child = psutil.Process(pid)
        return child.is_running() and child.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


@pytest.fixture
def spawned(monkeypatch):
    processes = []
    original = asyncio.create_subprocess_exec
    async def capture(*args, **kwargs):
        child = await original(*args, **kwargs)
        processes.append((child, kwargs))
        return child
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', capture)
    yield processes
    for child, _ in processes:
        if child.returncode is None:
            try:
                parent = psutil.Process(child.pid)
                for descendant in parent.children(recursive=True):
                    descendant.kill()
                parent.kill()
            except psutil.NoSuchProcess:
                pass
        child._transport.close()


async def bounded(task, spawned):
    done, _ = await asyncio.wait({task}, timeout=MAX_DURATION)
    if not done:
        # Release paused pipes even when testing the pre-fix implementation.
        for child, _ in spawned:
            try:
                parent = psutil.Process(child.pid)
                for descendant in parent.children(recursive=True):
                    descendant.kill()
                parent.kill()
            except psutil.NoSuchProcess:
                pass
            child._transport.close()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        pytest.fail('Process cleanup exceeded the maximum duration')
    return await task


@pytest.mark.anyio
async def test_separate_streams_exit_code_and_exact_total_cap(tmp_path, spawned):
    code = 'import os,sys; os.write(1,b"out"); os.write(2,b"err"); sys.exit(7)'
    started = time.monotonic()
    assert await bounded(asyncio.create_task(process.run(command(code), tmp_path, max_bytes=6)), spawned) == (7, b'out', b'err')
    assert time.monotonic() - started < MAX_DURATION
    kwargs = spawned[0][1]
    assert kwargs['stdin'] == asyncio.subprocess.DEVNULL
    if os.name == 'nt':
        assert kwargs['creationflags'] & 0x00000004
    else:
        assert kwargs['start_new_session'] is True


@pytest.mark.anyio
async def test_cap_is_combined_not_per_stream(tmp_path, spawned):
    code = 'import os; os.write(1,b"x"*600); os.write(2,b"y"*600)'
    started = time.monotonic()
    with pytest.raises(ValueError, match='output exceeded'):
        await bounded(asyncio.create_task(process.run(command(code), tmp_path, max_bytes=1024)), spawned)
    assert time.monotonic() - started < MAX_DURATION


@pytest.mark.anyio
@pytest.mark.parametrize('fd', (1, 2))
async def test_flood_releases_lock_and_joins_collectors(tmp_path, spawned, fd):
    lock = asyncio.Lock()
    baseline = asyncio.all_tasks()
    code = f'import os\nwhile True: os.write({fd},b"x"*262144)'
    async def locked_run():
        async with lock:
            return await process.run(command(code), tmp_path, timeout=30, max_bytes=1024)
    started = time.monotonic()
    with pytest.raises(ValueError, match='output exceeded'):
        await bounded(asyncio.create_task(locked_run()), spawned)
    assert time.monotonic() - started < MAX_DURATION
    assert not lock.locked()
    assert not (asyncio.all_tasks() - baseline)
    assert all(child.returncode is not None for child, _ in spawned)
    assert await process.run(command('print("after")'), tmp_path, timeout=2) == (0, b'after\r\n' if os.name == 'nt' else b'after\n', b'')


def tree_command(pidfile, ending):
    return command('import json,os,subprocess,sys,time; from pathlib import Path; '
        'child=subprocess.Popen([sys.executable,"-I","-c","import time; time.sleep(60)"]); '
        f'Path({str(pidfile)!r}).write_text(json.dumps([os.getpid(),child.pid])); ' + ending)


async def wait_for_pids(pidfile):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            return json.loads(pidfile.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            await asyncio.sleep(0.01)
    pytest.fail('Trusted child harness did not start')


async def assert_tree_stopped(pids):
    deadline = time.monotonic() + 1
    while any(alive(pid) for pid in pids) and time.monotonic() < deadline:
        await asyncio.sleep(0.01)
    assert not any(alive(pid) for pid in pids)


@pytest.mark.anyio
@pytest.mark.parametrize('cancel', (False, True))
async def test_timeout_and_cancellation_kill_child_tree(tmp_path, spawned, cancel):
    pidfile = tmp_path / 'pids.json'
    task = asyncio.create_task(process.run(tree_command(pidfile, 'time.sleep(60)'), tmp_path, timeout=1.5 if not cancel else 30))
    started = time.monotonic()
    pids = await wait_for_pids(pidfile)
    if cancel:
        task.cancel()
    with pytest.raises(asyncio.CancelledError if cancel else TimeoutError):
        await bounded(task, spawned)
    await assert_tree_stopped(pids)
    assert time.monotonic() - started < MAX_DURATION


@pytest.mark.anyio
async def test_exited_parent_does_not_escape_tree_cleanup(tmp_path, spawned):
    pidfile = tmp_path / 'pids.json'
    started = time.monotonic()
    task = asyncio.create_task(process.run(tree_command(pidfile, 'sys.exit(0)'), tmp_path, timeout=1.5))
    pids = await wait_for_pids(pidfile)
    with pytest.raises(TimeoutError):
        await bounded(task, spawned)
    await assert_tree_stopped(pids)
    assert time.monotonic() - started < MAX_DURATION


@pytest.mark.anyio
async def test_output_error_kills_child_tree(tmp_path, spawned):
    pidfile = tmp_path / 'pids.json'
    started = time.monotonic()
    task = asyncio.create_task(process.run(tree_command(pidfile, 'os.write(1,b"x"*1048576); time.sleep(60)'), tmp_path, timeout=30, max_bytes=1024))
    pids = await wait_for_pids(pidfile)
    with pytest.raises(ValueError, match='output exceeded'):
        await bounded(task, spawned)
    await assert_tree_stopped(pids)
    assert time.monotonic() - started < MAX_DURATION


@pytest.mark.anyio
@pytest.mark.skipif(os.name != 'nt', reason='Windows suspended-start containment')
async def test_job_failure_never_executes_uncontained_code(tmp_path, spawned, monkeypatch):
    marker = tmp_path / 'started.txt'
    def reject_job(pid):
        raise OSError('job assignment rejected')
    monkeypatch.setattr(scanners, '_WindowsJob', reject_job)
    code = f'from pathlib import Path; Path({str(marker)!r}).write_text("started")'
    started = time.monotonic()
    with pytest.raises(OSError, match='job assignment rejected'):
        await bounded(asyncio.create_task(process.run(command(code), tmp_path)), spawned)
    assert not marker.exists()
    assert all(child.returncode is not None for child, _ in spawned)
    assert time.monotonic() - started < MAX_DURATION


@pytest.mark.anyio
async def test_scanner_executor_accepts_explicit_combined_cap(tmp_path, spawned):
    started = time.monotonic()
    result = await bounded(asyncio.create_task(scanners._execute(command('import os\nwhile True: os.write(2,b"x"*262144)'), tmp_path, process.clean_environment(), 30, max_bytes=1024)), spawned)
    assert result['status'] == 'error' and result['truncated']
    assert len(result['stdout']) + len(result['stderr']) == 1024
    assert time.monotonic() - started < MAX_DURATION


def test_clean_environment_drops_injection_settings(monkeypatch):
    for key in ('PYTHONPATH', 'LD_PRELOAD', 'GIT_CONFIG', 'NODE_OPTIONS'):
        monkeypatch.setenv(key, 'untrusted')
    env = process.clean_environment()
    assert not {'PYTHONPATH', 'LD_PRELOAD', 'GIT_CONFIG', 'NODE_OPTIONS'} & env.keys()
    assert env['GIT_TERMINAL_PROMPT'] == '0'
    assert env['PYTHONNOUSERSITE'] == '1'
