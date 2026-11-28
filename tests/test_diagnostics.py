"""Doctor diagnostics and explicit audit working directories."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from localguard import diagnostics
from localguard.storage import Store

ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, '-m', 'localguard', *[str(arg) for arg in args]],
        cwd=ROOT, capture_output=True, text=True, encoding='utf-8', timeout=180,
    )


def write_config(tmp_path: Path, data_dir: Path, root: Path, **extra: object) -> Path:
    path = tmp_path / 'config.json'
    values = {
        'allowed_roots': [str(root)],
        'data_dir': str(data_dir),
        'offline': True,
        'model_tier': 'rules',
        **extra,
    }
    path.write_text(json.dumps(values, ensure_ascii=False), encoding='utf-8')
    return path


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / 'repo'
    repo.mkdir(exist_ok=True)
    (repo / 'sample.txt').write_text('benign fixture\n', encoding='utf-8')
    return repo


def state(paths: list[Path]) -> dict[str, tuple | None]:
    result = {}
    for path in paths:
        if not path.exists():
            result[str(path)] = None
            continue
        info = path.stat()
        result[str(path)] = (info.st_size, info.st_mtime_ns,
                             hashlib.sha256(path.read_bytes()).hexdigest())
    return result


def test_doctor_json_is_readonly_and_reports_environment(tmp_path):
    repo = make_repo(tmp_path)
    missing_data = tmp_path / 'missing-data'
    config = write_config(tmp_path, missing_data, repo)
    config_mtime = config.stat().st_mtime_ns

    result = run_cli('--config', config, 'doctor', '--json')
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report['kind'] == 'localguard_doctor'
    assert report['data_dir']['configured_path'] == str(missing_data.resolve())
    assert report['data_dir']['readonly']['exists'] is False
    assert report['database']['integrity_check'] == {'exists': False, 'result': 'N/A'}
    assert set(report['scanners']) == {'semgrep', 'gitleaks', 'gosec', 'cppcheck', 'pip-audit', 'grype'}
    assert report['model']['tier'] == 'rules'
    assert report['model']['status'] == 'not_required'
    assert report['model']['started'] is False
    assert 'acl' in report['database'] and 'readonly' in report['database']
    assert not missing_data.exists()
    assert config.stat().st_mtime_ns == config_mtime


def test_doctor_accepts_config_after_subcommand(tmp_path):
    repo = make_repo(tmp_path)
    data = tmp_path / 'state'
    data.mkdir()
    config = write_config(tmp_path, data, repo)

    result = run_cli('doctor', '--config', config, '--json')
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report['kind'] == 'localguard_doctor'
    assert report['data_dir']['configured_path'] == str(data.resolve())


def test_doctor_reports_missing_allowed_root_without_crashing(tmp_path):
    repo = make_repo(tmp_path)
    missing = tmp_path / 'missing-root'
    data = tmp_path / 'state'
    config = write_config(tmp_path, data, repo, allowed_roots=[str(repo), str(missing)])

    result = run_cli('--config', config, 'doctor', '--json')
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    entries = {item['path']: item for item in report['allowed_roots']}
    assert str(missing.resolve()) in entries
    assert entries[str(missing.resolve())]['exists'] is False
    assert entries[str(missing.resolve())]['is_dir'] is False
    assert not missing.exists()


def test_probe_write_reports_residual_path_when_cleanup_fails(tmp_path, monkeypatch):
    data = tmp_path / 'state'
    data.mkdir()
    original_unlink = Path.unlink

    def blocking_unlink(path: Path, *args, **kwargs):
        if path.name.startswith('.localguard-doctor-'):
            raise PermissionError('cleanup blocked by test')
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'unlink', blocking_unlink)
    result = diagnostics.probe_write(data)
    assert result['ok'] is False
    assert 'cleanup failed' in result['error']
    residual = Path(result['residual_path'])
    assert residual.exists()
    original_unlink(residual)


def test_doctor_probe_write_creates_and_removes_temp_file(tmp_path):
    repo = make_repo(tmp_path)
    data = tmp_path / 'state'
    data.mkdir()
    config = write_config(tmp_path, data, repo)

    result = run_cli('--config', config, 'doctor', '--json', '--probe-write')
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report['write_probe']['ok'] is True
    assert report['write_probe']['path'] == str(data.resolve())
    assert not list(data.glob('.localguard-doctor-*'))


def test_audit_data_dir_writes_temp_store_without_touching_production(tmp_path):
    repo = make_repo(tmp_path)
    production = tmp_path / 'production'
    production.mkdir()
    Store(production)
    work = tmp_path / 'work-state'
    config = write_config(tmp_path, production, repo)
    production_files = [production / 'state.sqlite3', production / 'state.sqlite3-wal',
                        production / 'state.sqlite3-shm']
    before = state(production_files)

    result = run_cli('--config', config, 'audit', '--data-dir', work, repo,
                     '--scanners', 'patterns', '--no-dependencies', '--model-tier', 'rules')
    assert result.returncode == 0, result.stderr
    assert (work / 'state.sqlite3').is_file()
    assert state(production_files) == before


def test_audit_unwritable_data_dir_fails_with_temp_workspace_hint(tmp_path):
    repo = make_repo(tmp_path)
    production = tmp_path / 'production'
    production.mkdir()
    blocked = tmp_path / 'blocked'
    blocked.write_text('not a directory\n', encoding='utf-8')
    config = write_config(tmp_path, production, repo)

    result = run_cli('--config', config, 'audit', '--data-dir', blocked, repo,
                     '--scanners', 'patterns', '--no-dependencies')
    assert result.returncode != 0
    assert 'data_dir is not writable' in result.stderr
    assert 'system temporary working directory' in result.stderr
    assert 'audit --data-dir' in result.stderr


def test_ensure_writable_data_dir_rejects_unwritable_database(tmp_path):
    data = tmp_path / 'state'
    data.mkdir()
    (data / 'state.sqlite3').mkdir()
    with pytest.raises(diagnostics.DiagnosticsError, match='system temporary working directory'):
        diagnostics.ensure_writable_data_dir(data, config_path='cfg.json', target='repo')
