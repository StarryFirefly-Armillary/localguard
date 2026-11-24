"""Dependency manifests must survive auto-exclusion when dependency scanning
is enabled, otherwise grype cannot locate CVEs and drops them silently."""
from pathlib import Path

import pytest

from localguard.config import Config
from localguard.registry import ToolRegistry

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures'


@pytest.mark.anyio
async def test_lockfile_kept_for_dependency_scan_excluded_otherwise(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    (root / 'app.js').write_text('const x = 1;', encoding='utf-8')
    lock = root / 'package-lock.json'
    lock.write_text('{"name":"app","lockfileVersion":2,"packages":{}}', encoding='utf-8')
    cfg = Config(allowed_roots=[root], data_dir=tmp_path / 'state', model_tier='rules')
    registry = ToolRegistry(cfg)
    try:
        with registry.engine.snapshot(root, keep_manifests=True) as (snap, hashes, skipped):
            assert 'package-lock.json' in hashes
        with registry.engine.snapshot(root, keep_manifests=False) as (snap, hashes, skipped):
            assert 'package-lock.json' not in hashes
            assert any('package-lock.json' in s for s in skipped)
    finally:
        await registry.close()
