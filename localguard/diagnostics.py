"""Read-only LocalGuard environment diagnostics.

This module deliberately avoids ``Config.load`` for ``doctor`` because that
constructor creates the data directory. Doctor must inspect without writing.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import uuid
from dataclasses import MISSING, fields
from urllib.parse import quote

from .config import Config

SCANNER_NAMES = ('semgrep', 'gitleaks', 'gosec', 'cppcheck', 'pip-audit', 'grype')
BINARY_KEYS = ('semgrep', 'gitleaks', 'gosec', 'cppcheck', 'pip-audit', 'grype', 'git')


class DiagnosticsError(RuntimeError):
    """Raised when diagnostic input is invalid or a required write probe fails."""


def load_config_readonly(path: str | None = None) -> Config:
    """Build a Config without creating or modifying any directory."""
    source = path or os.environ.get('LOCALGUARD_CONFIG')
    raw: dict = {}
    if source:
        config_path = Path(source).resolve(strict=True)
        raw = json.loads(config_path.read_text(encoding='utf-8'))
        if not isinstance(raw, dict):
            raise DiagnosticsError(f'Config must be a JSON object: {config_path}')
    if roots := os.environ.get('LOCALGUARD_ROOTS'):
        raw['allowed_roots'] = roots.split(os.pathsep)
    if data := os.environ.get('LOCALGUARD_DATA_DIR'):
        raw['data_dir'] = data

    config = Config.__new__(Config)
    for field in fields(Config):
        if field.name in raw:
            value = raw[field.name]
        elif field.default_factory is not MISSING:
            value = field.default_factory()
        elif field.default is not MISSING:
            value = field.default
        else:
            raise DiagnosticsError(f'Config field has no default: {field.name}')
        setattr(config, field.name, value)

    # Doctor reports missing roots instead of failing on them.
    config.allowed_roots = [Path(item).resolve(strict=False) for item in config.allowed_roots]
    config.data_dir = Path(config.data_dir).resolve()
    for name in BINARY_KEYS:
        binary = config.binaries.get(name)
        if binary:
            candidate = Path(binary)
            config.binaries[name] = str(candidate.resolve(strict=True)) if candidate.exists() else str(candidate)
        else:
            found = shutil.which(name)
            if found:
                config.binaries[name] = str(Path(found).resolve(strict=True))
    if config.max_output_bytes < 4096 or config.max_output_bytes > 200_000:
        raise DiagnosticsError('max_output_bytes must be between 4096 and 200000')
    if not 1 <= config.max_prompt_files <= 60:
        raise DiagnosticsError('max_prompt_files must be between 1 and 60')
    if not 0 <= config.max_model_explanations <= 500:
        raise DiagnosticsError('max_model_explanations must be between 0 and 500')
    if config.model_tier not in ('rules', '4gb', '8gb'):
        raise DiagnosticsError('Invalid model_tier')
    return config


def _readonly_summary(path: Path) -> dict:
    result = {'path': str(path), 'exists': False, 'kind': 'missing'}
    if not path.exists():
        return result
    info = path.stat()
    readonly_flag = getattr(stat, 'FILE_ATTRIBUTE_READONLY', 0)
    attributes = getattr(info, 'st_file_attributes', 0)
    result.update({
        'exists': True,
        'kind': 'directory' if path.is_dir() else 'file',
        'mode': oct(stat.S_IMODE(info.st_mode)),
        'owner_writable': bool(info.st_mode & stat.S_IWUSR),
        'readonly_attribute': bool(attributes & readonly_flag) if readonly_flag else None,
        'os_access_writable': os.access(path, os.W_OK),
        'size': info.st_size if path.is_file() else None,
    })
    return result


def _acl_summary(path: Path) -> dict:
    if not path.exists():
        return {'available': False, 'reason': 'path does not exist'}
    if os.name == 'nt':
        try:
            completed = subprocess.run(['icacls', str(path)], capture_output=True,
                                       timeout=8, check=False)
            raw = completed.stdout or completed.stderr or b''
            summary = raw.decode('utf-8', errors='replace').strip()[:600]
            return {
                'available': True,
                'tool': 'icacls',
                'returncode': completed.returncode,
                'summary': summary,
            }
        except (OSError, subprocess.SubprocessError) as exc:
            return {'available': False, 'tool': 'icacls', 'reason': str(exc)[:300]}
    info = path.stat()
    return {
        'available': True,
        'tool': 'stat',
        'mode': oct(stat.S_IMODE(info.st_mode)),
        'uid': info.st_uid,
        'gid': info.st_gid,
    }


def _file_report(path: Path) -> dict:
    return {'readonly': _readonly_summary(path), 'acl': _acl_summary(path)}


def _integrity_check(path: Path) -> dict:
    if not path.is_file():
        return {'exists': False, 'result': 'N/A'}
    uri = 'file:' + quote(path.resolve().as_posix()) + '?mode=ro'
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=5)
        try:
            rows = connection.execute('PRAGMA integrity_check').fetchall()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        return {'exists': True, 'result': 'error', 'error': str(exc)[:300]}
    values = [str(row[0]) for row in rows]
    return {'exists': True, 'result': 'ok' if values == ['ok'] else ' | '.join(values)[:600]}


def _binary_report(config: Config) -> dict:
    report = {}
    for name in SCANNER_NAMES:
        value = config.binaries.get(name)
        if value:
            path = Path(value)
            report[name] = {
                'configured': True,
                'path': str(path),
                'exists': path.is_file(),
                'executable': os.access(path, os.X_OK) if path.is_file() else False,
            }
        else:
            found = shutil.which(name)
            report[name] = {
                'configured': False,
                'path': found or None,
                'exists': bool(found),
                'executable': bool(found),
            }
    return report


def _model_report(config: Config) -> dict:
    def state(value: str) -> dict:
        path = Path(value) if value else None
        return {'configured': bool(value), 'path': str(path) if path else None,
                'exists': bool(path and path.is_file())}

    if config.model_tier == 'rules':
        status = 'not_required'
    else:
        status = 'ok' if config.model_path and Path(config.model_path).is_file() else 'missing'
    return {
        'tier': config.model_tier,
        'status': status,
        'model': state(config.model_path),
        'mmproj': state(config.mmproj_path),
        'server_binary': state(config.model_binary),
        'keep_model_resident': config.keep_model_resident,
        'max_model_explanations': config.max_model_explanations,
        'started': False,
        'note': 'Doctor inspects files only; it never starts or loads a model.',
    }


def _grammar_report() -> dict:
    from .parser import GRAMMARS, SourceParser
    grammars = {}
    parser = SourceParser()
    for language in sorted(set(GRAMMARS.values())):
        try:
            parser.parse(language, b'')
            grammars[language] = 'available'
        except Exception as exc:
            grammars[language] = str(exc)[:300]
    return grammars


def probe_write(directory: Path) -> dict:
    """Create and delete one temporary file; report the real write capability."""
    if not directory.is_dir():
        return {'ok': False, 'path': str(directory), 'error': 'data_dir is not a directory'}
    # A single explicit create avoids NamedTemporaryFile's repeated random-name
    # retries, which can appear to hang on ACL-denied directories.
    created = directory / f'.localguard-doctor-{uuid.uuid4().hex}'
    problems: list[str] = []
    try:
        with created.open('xb') as stream:
            stream.write(b'doctor-write-probe')
    except OSError as exc:
        problems.append(f'create/write failed: {exc}')
    finally:
        try:
            created.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            problems.append(f'cleanup failed: {exc}')
    if problems:
        result = {
            'ok': False,
            'path': str(directory),
            'error': ' | '.join(problems)[:600],
        }
        if created.exists():
            result['residual_path'] = str(created)
        return result
    return {'ok': True, 'path': str(directory), 'created_and_removed': str(created)}


def writable_error(data_dir: Path, *, config_path: str | None = None,
                   target: str | None = None) -> str:
    temp = os.environ.get('TEMP') or os.environ.get('TMPDIR') or tempfile.gettempdir()
    work = str(Path(temp) / 'localguard-work')
    config = config_path or '<config path>'
    audit_target = target or '<target>'
    return (
        f'data_dir is not writable: {data_dir}. '
        'LocalGuard will not silently fall back to a production store. '
        f'Use a system temporary working directory, for example: '
        f'python -m localguard --config "{config}" audit --data-dir "{work}" "{audit_target}"'
    )


def ensure_writable_data_dir(directory: Path, *, config_path: str | None = None,
                             target: str | None = None) -> None:
    result = probe_write(directory)
    if not result['ok']:
        raise DiagnosticsError(writable_error(directory, config_path=config_path, target=target))
    database = directory / 'state.sqlite3'
    for path in (database, Path(str(database) + '-wal'), Path(str(database) + '-shm')):
        if not path.exists():
            continue
        try:
            with path.open('r+b'):
                pass
        except OSError as exc:
            raise DiagnosticsError(writable_error(
                directory, config_path=config_path, target=target)) from exc


def collect(config: Config, *, probe: bool = False, config_path: str | None = None) -> dict:
    data_dir = config.data_dir
    db_path = data_dir / 'state.sqlite3'
    report = {
        'kind': 'localguard_doctor',
        'offline': config.offline,
        'allowed_roots': [
            {'path': str(root), 'exists': root.exists(), 'is_dir': root.is_dir()}
            for root in config.allowed_roots
        ],
        'data_dir': {
            **_file_report(data_dir),
            'configured_path': str(data_dir),
        },
        'database': {
            **_file_report(db_path),
            'path': str(db_path),
            'integrity_check': _integrity_check(db_path),
        },
        'wal': _file_report(Path(str(db_path) + '-wal')),
        'shm': _file_report(Path(str(db_path) + '-shm')),
        'scanners': _binary_report(config),
        'model': _model_report(config),
        'grammars': _grammar_report(),
        'write_probe': None,
    }
    if probe:
        report['write_probe'] = probe_write(data_dir)
    return report


def format_text(report: dict) -> str:
    lines = ['LocalGuard doctor', '']
    lines.append(f"data_dir: {report['data_dir']['configured_path']}")
    lines.append(f"database: {report['database']['path']} exists={report['database']['readonly']['exists']}")
    lines.append(f"integrity_check: {report['database']['integrity_check']['result']}")
    lines.append('scanners:')
    for name, item in report['scanners'].items():
        lines.append(f"  {name}: {item['path'] or 'unavailable'} exists={item['exists']}")
    lines.append(f"model tier: {report['model']['tier']} status={report['model']['status']} (not started)")
    if report['write_probe'] is not None:
        lines.append(f"write_probe: ok={report['write_probe']['ok']}")
    return '\n'.join(lines)
