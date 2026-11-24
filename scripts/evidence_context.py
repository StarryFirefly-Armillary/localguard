"""Build UNBIASED source evidence for triage contexts.

Two contamination sources were confirmed by read-only audit (2026-11-24):
  - negatives: ±3-line slices cut off decisive safety guards (safe_filename,
    hardcoded index list), so the model sees only the scary-looking call;
  - positives: 9/11 slices carried VULNERABLE / SINK / hardcoded comments,
    effectively handing the model the answer.

This module builds a 'full function, code-only, bounded' alternative:
  1. locate the complete enclosing function (Python via AST; other languages
     via brace/indent walking around the finding line);
  2. strip ALL comments and docstrings uniformly from BOTH classes of sample —
     Python via tokenize (never touches '#' inside string literals), other
     languages via a conservative regex for // and /* */ comments;
  3. keep executable safety guards (safe_filename, escape, parameterized
     queries) — they are code, not comments, so stripping comments preserves
     them by construction;
  4. bound size by max_chars; if over, shrink around the finding line while
     staying on AST/function boundaries, never a fixed ±3 lines.

metadata_origin is NOT part of this module's output — it stays audit-only in
evaluate_gold_v0.build_records().
"""
from __future__ import annotations

import ast
import io
import tokenize
from pathlib import Path


def _strip_python_line_comments(source: str) -> str:
    """Fallback for incomplete Python windows: strip inline comments per line."""
    output = []
    for line in source.splitlines():
        indent = line[:len(line) - len(line.lstrip())]
        body = line[len(indent):]
        cut = None
        try:
            for token in tokenize.generate_tokens(io.StringIO(body + '\n').readline):
                if token.type == tokenize.COMMENT:
                    cut = token.start[1]
                    break
        except (tokenize.TokenError, IndentationError, SyntaxError):
            cut = None
        output.append(indent + body[:cut] if cut is not None else line)
    return '\n'.join(output)


def strip_comments_python(source: str) -> str:
    """Remove comments AND docstrings, keep all executable code verbatim.

    tokenize distinguishes COMMENT tokens from '#' inside strings, so safety
    code like `f"<p>{x}</p>" # noqa` loses only the trailing comment.
    """
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError):
        return _strip_python_line_comments(source)
    out_lines = [list(line) for line in source.splitlines()]
    for tok in tokens:
        if tok.type == tokenize.COMMENT:
            line = out_lines[tok.start[0] - 1]
            col = tok.start[1]
            out_lines[tok.start[0] - 1] = line[:col]
    cleaned = '\n'.join(''.join(l) for l in out_lines)
    # Remove docstrings (a STRING token that is the first statement of a
    # module/class/function) by walking the AST for Expr(Constant str).
    try:
        tree = ast.parse(cleaned)
    except SyntaxError:
        return cleaned
    spans = []
    for node in ast.walk(tree):
        body = getattr(node, 'body', None)
        if not body or not isinstance(body, list):
            continue
        first = body[0]
        if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            spans.append((first.lineno, first.end_lineno))
    if spans:
        lines = cleaned.splitlines()
        for lo, hi in spans:
            for i in range(lo - 1, hi):
                if i < len(lines):
                    lines[i] = ''
        cleaned = '\n'.join(lines)
    return cleaned


def _strip_comments_generic(source: str) -> str:
    """Remove only standalone comment lines; never truncate inline content.

    Inline # and // occur in URLs, Base64, Markdown anchors, Ruby interpolation,
    and string literals. Without a language lexer, preserving inline text is
    safer than attempting inline comment removal.
    """
    kept = []
    for line in source.splitlines():
        stripped = line.lstrip()
        if stripped.startswith(('//', '#', '/*', '*', '*/')):
            kept.append('')
        else:
            kept.append(line)
    return '\n'.join(kept)


def strip_comments(source: str, language: str) -> str:
    if language == 'python':
        return strip_comments_python(source)
    if language in {'javascript', 'typescript', 'go', 'ruby', 'java', 'c', 'cpp',
                    'php', 'rust', 'solidity', 'bash', 'powershell'}:
        return _strip_comments_generic(source)
    return source


def strip_window_comments(lines: list[dict], language: str) -> list[dict]:
    """Strip comments from a ±N-line window WITHOUT changing its line range.

    Line count is preserved: a comment-only line becomes blank rather than
    being deleted, so the window's [start, end] line numbers stay identical to
    the plain 'window' mode. That makes window vs window_code_only differ by
    exactly one variable: comments.
    """
    if not lines:
        return lines
    texts = [item['text'] for item in lines]
    cleaned = strip_comments('\n'.join(texts), language).splitlines()
    # pad/truncate to the original count (a trailing comment line may fold)
    cleaned = (cleaned + [''] * len(texts))[:len(texts)]
    return [{'line': item['line'], 'text': text[:100]}
            for item, text in zip(lines, cleaned)]


def enclosing_function(source: str, line: int, language: str) -> tuple[int, int]:
    """Return (start_line, end_line) (1-based, inclusive) of the function.

    Python: AST node span. Other languages: scan backwards from `line` for a
    line containing '(' and '{' (or 'func'/'def'), then forward to matching
    closing brace. Falls back to the whole file when no boundary is found.
    """
    lines = source.splitlines()
    n = len(lines)
    if n == 0:
        return (1, 1)
    line = max(1, min(line, n))
    if language == 'python':
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return (1, n)
        best = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end = getattr(node, 'end_lineno', node.lineno)
                if node.lineno <= line <= end:
                    if best is None or node.lineno > best[0]:
                        best = (node.lineno, end)
        return best if best else (1, n)
    # brace matching for JS/Go/Java/PHP/C-like sources
    depth = 0
    start = None
    for i in range(line - 1, -1, -1):
        depth += lines[i].count('}') - lines[i].count('{')
        if '{' in lines[i] and depth <= 0 and ('(' in lines[i] or i == line - 1):
            start = i + 1
            break
    if start is None:
        start = max(1, line - 20)
    depth, end = 0, n
    for i in range(start - 1, n):
        depth += lines[i].count('{') - lines[i].count('}')
        if depth <= 0 and i >= line - 1 and '{' in '\n'.join(lines[start - 1:i + 1]):
            end = i + 1
            break
    return (start, end)


def build_evidence(source: str, line: int, language: str, max_chars: int = 1200) -> list[dict]:
    """Full enclosing function, comments stripped, bounded around `line`.

    Returns [{'line': N, 'text': ...}, ...] matching the production context
    'source' shape. Keeps original line numbers for provenance.
    """
    src_lines = source.splitlines()
    lo, hi = enclosing_function(source, line, language)
    # strip comments from the function slice, preserving line alignment
    slice_src = '\n'.join(src_lines[lo - 1:hi])
    clean = strip_comments(slice_src, language)
    clean_lines = clean.splitlines()
    out = [(lo + i, text) for i, text in enumerate(clean_lines)]
    # bound by chars. A full function can exceed budget; shrink on statement
    # boundaries while ALWAYS keeping the finding line and the function's
    # prologue (first few statements), where safety guards commonly live
    # (e.g. `fname = safe_filename(...)` at the top of admin_rename_image).
    total = sum(len(t) + 1 for _, t in out)
    if total > max_chars:
        idx = max(0, min(len(out) - 1, line - lo))
        # prologue = leading non-blank executable lines up to a small budget
        prologue_end = 0
        for k, (_, text) in enumerate(out[:12]):
            if text.strip():
                prologue_end = k + 1
        must = set(range(0, min(prologue_end, 6))) | {idx}
        kept_idx = set(must)
        used = sum(len(out[i][1]) + 1 for i in kept_idx)
        used = min(used, max_chars)
        # expand around the finding line, then anywhere else, by budget
        order = []
        i, j = idx - 1, idx + 1
        while i >= 0 or j < len(out):
            if i >= 0:
                order.append(i); i -= 1
            if j < len(out):
                order.append(j); j += 1
        order += [k for k in range(len(out)) if k not in kept_idx and k not in order]
        for k in order:
            if len(out[k][1]) + 1 > max_chars - used:
                continue
            kept_idx.add(k)
            used += len(out[k][1]) + 1
        out = [out[k] for k in sorted(kept_idx)]
    # drop blank-only lines at the edges but keep interior blanks
    while out and not out[0][1].strip():
        out.pop(0)
    while out and not out[-1][1].strip():
        out.pop()
    return [{'line': n, 'text': t} for n, t in out]
