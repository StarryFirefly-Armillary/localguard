"""Cross-project discovery policy: decide which paths are review targets.

This is deliberately generic. No project-specific directory is hardcoded.
Three independent, auditable signals are combined:

1. Conventional directory names used by test/sample/generated content across
   ecosystems (pytest, jest, Go, Rust, Maven, ...).
2. In-file self declarations such as "STATIC FIXTURE ONLY / DO NOT EXECUTE"
   in the first lines -- works even when a fixture lives outside a test dir.
3. Known non-source artifacts (lockfiles, minified bundles, snapshots).

Every exclusion is returned with a reason so the report can show exactly what
was skipped and why. Nothing here decides whether a finding is a real issue;
it only decides whether a path is a meaningful review target.
"""
from __future__ import annotations

import re
from pathlib import Path


# Conventional names, lowercased. Broad enough for common ecosystems, narrow
# enough not to swallow production code (e.g. a real `source/` or `src/`).
TEST_DIRS = frozenset({
    'test', 'tests', '__tests__', 'spec', 'specs', '__specs__',
    'testdata', 'test-data', 'test_data', 'fixture', 'fixtures',
    'mock', 'mocks', '__mocks__', 'stub', 'stubs',
    'sample', 'samples', 'example', 'examples',
    'golden', 'snapshots', '__snapshots__',
})
GENERATED_DIRS = frozenset({
    'coverage', 'htmlcov', '.coverage', '.tox', '.pytest_cache', '.mypy_cache',
    '.ruff_cache', '.next', '.nuxt', '.svelte-kit', 'out', 'target',
    'obj', 'bin', 'dist', 'build', 'release', 'debug', 'site-packages', 'egg-info',
})

# Non-source files that produce noise in lexical scanners. Dependency
# scanners (grype/pip-audit) still need manifests, so these are only skipped
# for code-oriented review and are reported as such.
NON_SOURCE_NAMES = frozenset({
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock',
    'pipfile.lock', 'gemfile.lock', 'go.sum', 'cargo.lock', 'composer.lock',
})
NON_SOURCE_SUFFIXES = ('.min.js', '.min.css', '.map')

# A file declaring itself inert is skipped regardless of its directory.
# Match only near the top of the file to avoid prose/code false positives.
SELF_DECLARED = re.compile(
    r'(?:static\s+fixture\s+only|artificial\s+static\s+fixture|fixture\s+only|'
    r'do\s+not\s+execute|never\s+(?:import|execute)|not\s+production\s+code|'
    r'synthetic\s+(?:data|sample|example)|inert\s+example|test\s+fixture\s+only)',
    re.I,
)
HEADER_LINES = 12


def _read_header(path: Path) -> str:
    try:
        with path.open('rb') as stream:
            chunk = stream.read(8192)
        return chunk.decode('utf-8', errors='replace')[:4096]
    except OSError:
        return ''


def classify(path: Path, root: Path, *, skip_tests=True, skip_generated=True,
             skip_nonsource=True, trust_declarations=True) -> str | None:
    """Return a reason string when path should be excluded, else None."""
    rel = path.relative_to(root).as_posix()
    parts = [p.lower() for p in rel.split('/')[:-1]]
    name = path.name.lower()

    if skip_tests and any(p in TEST_DIRS for p in parts):
        return 'conventional test/fixture directory'
    if skip_generated and any(p in GENERATED_DIRS for p in parts):
        return 'generated/build directory'
    if skip_nonsource and (name in NON_SOURCE_NAMES or name.endswith(NON_SOURCE_SUFFIXES)):
        return 'non-source artifact'
    if trust_declarations and SELF_DECLARED.search('\n'.join(_read_header(path).splitlines()[:HEADER_LINES])):
        return 'file declares itself a non-executable fixture'
    return None


def is_test_root(root: Path) -> bool:
    """True when the audit target itself is a conventional test/fixture dir.

    In that case the user deliberately pointed at samples, so auto-exclusion
    must not silently empty the report.
    """
    parts = [p.lower() for p in Path(root).resolve().parts]
    return any(p in TEST_DIRS for p in parts[-3:])
