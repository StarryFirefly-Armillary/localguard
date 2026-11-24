"""Scan cache must invalidate when the running environment changes, and must
never serve an expired entry. Cached results are security evidence."""
import os
import time
from pathlib import Path

import pytest

from localguard.config import Config
from localguard.engine import scan_cache_key
from localguard.storage import Store


@pytest.fixture
def rules_dir(tmp_path):
    d = tmp_path / 'rules'
    d.mkdir()
    (d / 'security.json').write_text('{}', encoding='utf-8')
    (d / 'gitleaks.toml').write_text('title = "v1"', encoding='utf-8')
    return d


def key_for(scanner, rules_dir, binaries=None, hashes=None):
    cfg = Config(allowed_roots=[rules_dir.parent], data_dir=rules_dir.parent / 'state',
                 binaries=binaries or {})
    return scan_cache_key(scanner, hashes or {'a.py': 'digest'}, cfg, rules_dir)


def test_non_json_config_changes_invalidate(rules_dir):
    original = key_for('gitleaks', rules_dir)
    time.sleep(0.01)
    (rules_dir / 'gitleaks.toml').write_text('title = "v2"', encoding='utf-8')
    os.utime(rules_dir / 'gitleaks.toml', ns=(time.time_ns(), time.time_ns() + 1000))
    assert key_for('gitleaks', rules_dir) != original


def test_binary_version_change_invalidates(rules_dir, tmp_path):
    binary = tmp_path / 'semgrep.exe'
    binary.write_bytes(b'v1')
    original = key_for('semgrep', rules_dir, {'semgrep': str(binary)})
    time.sleep(0.01)
    binary.write_bytes(b'v2 longer binary')
    os.utime(binary, ns=(time.time_ns(), time.time_ns() + 1000))
    assert key_for('semgrep', rules_dir, {'semgrep': str(binary)}) != original


def test_grype_db_fingerprint_changes_invalidate(rules_dir, tmp_path, monkeypatch):
    db = tmp_path / 'grype-db'
    db.mkdir()
    (db / 'vulnerability.db').write_bytes(b'old')
    monkeypatch.setenv('GRYPE_DB_CACHE_DIR', str(db))
    original = key_for('grype', rules_dir)
    time.sleep(0.01)
    (db / 'vulnerability.db').write_bytes(b'new')
    os.utime(db / 'vulnerability.db', ns=(time.time_ns(), time.time_ns() + 1000))
    assert key_for('grype', rules_dir) != original


def test_snapshot_digest_still_part_of_key(rules_dir):
    a = key_for('patterns', rules_dir, hashes={'a.py': '1'})
    b = key_for('patterns', rules_dir, hashes={'a.py': '2'})
    assert a != b


def test_cache_get_enforces_ttl(tmp_path):
    store = Store(tmp_path)
    store.cache_put('k', {'status': 'completed'})
    assert store.cache_get('k') == {'status': 'completed'}
    assert store.cache_get('k', ttl=-1) is None  # expired
