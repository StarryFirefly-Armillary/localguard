"""Explicit working-directory selection for audit/ui/mcp CLI commands."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from localguard import __main__ as cli
from localguard.storage import Store

ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_FILES = ('state.sqlite3', 'state.sqlite3-wal', 'state.sqlite3-shm')


def run_cli(*args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, '-m', 'localguard', *[str(arg) for arg in args]],
        cwd=ROOT, capture_output=True, text=True, encoding='utf-8', timeout=60,
    )


def write_config(tmp_path: Path, data_dir: Path, root: Path) -> Path:
    path = tmp_path / 'config.json'
    path.write_text(json.dumps({
        'allowed_roots': [str(root)],
        'data_dir': str(data_dir),
        'model_tier': 'rules',
        'offline': True,
    }, ensure_ascii=False), encoding='utf-8')
    return path


def make_production(tmp_path: Path) -> Path:
    production = tmp_path / 'production'
    production.mkdir()
    Store(production)
    return production


def state(production: Path) -> dict[str, tuple | None]:
    result = {}
    for name in PRODUCTION_FILES:
        path = production / name
        if not path.exists():
            result[name] = None
            continue
        info = path.stat()
        result[name] = (info.st_size, info.st_mtime_ns,
                        hashlib.sha256(path.read_bytes()).hexdigest())
    return result


@pytest.fixture(autouse=True)
def clean_data_dir_env(monkeypatch):
    monkeypatch.setenv('LOCALGUARD_DATA_DIR', '')


@pytest.mark.parametrize('command', ['ui', 'mcp'])
def test_help_exposes_data_dir(command):
    result = run_cli(command, '--help')
    assert result.returncode == 0, result.stderr
    assert '--data-dir' in result.stdout
    assert 'temporary workspace' in result.stdout
    assert 'localguard-work' in result.stdout


@pytest.mark.parametrize('command', ['ui', 'mcp'])
def test_load_config_uses_explicit_temp_data_dir(command, tmp_path, monkeypatch):
    root = tmp_path / 'repo'
    root.mkdir()
    production = make_production(tmp_path)
    work = tmp_path / 'work-state'
    config = write_config(tmp_path, production, root)
    before = state(production)

    args = SimpleNamespace(command=command, config=str(config), data_dir=str(work))
    loaded = cli.load_config(args)

    assert loaded.data_dir.resolve() == work.resolve()
    assert work.is_dir()
    assert state(production) == before


@pytest.mark.parametrize('command', ['ui', 'mcp'])
def test_unwritable_data_dir_fails_without_stdout_or_production_changes(command, tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    production = make_production(tmp_path)
    blocked = tmp_path / 'blocked'
    blocked.write_text('not a directory\n', encoding='utf-8')
    config = write_config(tmp_path, production, root)
    before = state(production)

    result = run_cli('--config', config, command, '--data-dir', blocked)

    assert result.returncode != 0
    assert result.stdout == ''
    assert 'data_dir is not writable' in result.stderr
    assert 'system temporary working directory' in result.stderr
    assert f'{command} --data-dir' in result.stderr
    assert state(production) == before
