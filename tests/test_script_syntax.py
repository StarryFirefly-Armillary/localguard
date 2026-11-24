"""All scripts must be syntactically valid and key tools must be importable.

Regression: commit 42bba8f shipped rebuild_fp_v2.py with a literal '/n' typo
(`try:/n ...`) that AST parsing would have caught instantly, but 412 tests
passed because none of them parsed script files. This test closes that gap.
"""
import ast
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'


def test_all_scripts_parse():
    files = sorted(SCRIPTS.glob('*.py'))
    assert len(files) > 20, 'unexpected script discovery'
    for path in files:
        try:
            ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        except SyntaxError as exc:
            raise AssertionError(f'{path.name} has a syntax error: {exc}') from exc


def test_key_gold_tools_import():
    """Import (not just parse) the tools used to build the gold batch."""
    sys.path.insert(0, str(SCRIPTS))
    for name in ('rebuild_fp_v2', 'collect_gold_candidates', 'export_review_samples'):
        spec = importlib.util.spec_from_file_location(name, SCRIPTS / f'{name}.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # SyntaxError/ImportError surface here
        assert module is not None
