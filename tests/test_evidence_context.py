"""Evidence construction must strip label comments but KEEP safety guards."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from evidence_context import strip_comments, build_evidence, enclosing_function


VULN = '''def render(comment: str) -> str:
    # VULNERABLE: user input reaches SQL sink
    """docstring that says SINK and hardcoded."""
    query = f"SELECT * FROM t WHERE c = {comment}"  # SINK
    return query
'''


SAFE = '''def render(comment: str) -> str:
    # safe_filename sanitizes the path before use
    """This guard is intentional."""
    name = safe_filename(comment)
    return open(name).read()
'''


def test_strip_comments_removes_labels_keeps_code():
    for source in (VULN, SAFE):
        clean = strip_comments(source, 'python')
        # comment-only labels/docstrings must vanish
        for label in ('VULNERABLE', 'SINK', 'hardcoded', 'intentional',
                      'sanitizes the path', 'docstring that says'):
            assert label not in clean, f'{label} leaked'
        # executable guard/query code stays
        assert 'query = f"SELECT' in clean or 'name = safe_filename(comment)' in clean


def test_safety_guard_code_is_preserved():
    clean = strip_comments(SAFE, 'python')
    # the call itself is executable code, must survive
    assert 'name = safe_filename(comment)' in clean
    assert 'return open(name).read()' in clean


def test_string_literal_hash_is_not_stripped():
    src = 'url = "http://example.com/#frag"  # trailing comment\n'
    clean = strip_comments(src, 'python')
    assert 'http://example.com/#frag' in clean
    assert 'trailing comment' not in clean


def test_full_function_bounded_and_linenumbers():
    ev = build_evidence(SAFE, line=4, language='python', max_chars=500)
    texts = [e['text'] for e in ev]
    assert all('VULNERABLE' not in t and 'safe_filename' in '\n'.join(texts) for t in texts)
    assert sum(len(t) for t in texts) <= 500
    # line numbers preserved from original source
    assert ev[0]['line'] == 1


def test_enclosing_function_returns_full_span():
    assert enclosing_function(SAFE, 4, 'python') == (1, 5)


def test_bounded_shrink_keeps_prologue_guard():
    """Long function: bounded shrink must not cut the leading safety guard."""
    lines = ['def rename(fname):']
    lines.append('    fname = safe_filename(fname)')  # prologue guard
    lines += [f'    x{i} = {i}  # padding' for i in range(60)]
    lines.append('    return os.rename(fname, target)')
    src = '\n'.join(lines)
    ev = build_evidence(src, line=len(lines), language='python', max_chars=600)
    texts = '\n'.join(e['text'] for e in ev)
    assert 'safe_filename(fname)' in texts, 'prologue guard lost during shrink'
    assert sum(len(e['text']) for e in ev) <= 600


def test_generic_cleaner_preserves_inline_hash_slashes_and_interpolation():
    src = '\n'.join([
        '# standalone comment',
        'url = "https://example.com/#anchor"',
        'key = "AAAA//BBBB"',
        'query = request.query_string.empty? ? "" : "?#{request.query_string}"',
        'value = 1  # inline comment',
    ])
    clean = strip_comments(src, 'ruby')
    assert '# standalone comment' not in clean
    assert 'https://example.com/#anchor' in clean
    assert 'AAAA//BBBB' in clean
    assert '#{request.query_string}' in clean
    assert '# inline comment' in clean


def test_document_and_key_files_are_preserved_verbatim():
    src = '# Heading\n[link](../file.md#anchor)\nAAAA//BBBB\n'
    assert strip_comments(src, 'unknown') == src


def test_incomplete_python_window_still_strips_inline_comment():
    src = '    query = cursor.execute(query)  # SINK: SQL execution\n    return query\n'
    clean = strip_comments(src, 'python')
    assert 'SINK' not in clean
    assert 'cursor.execute(query)' in clean


