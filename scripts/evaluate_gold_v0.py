"""Paired prompt A/B on the user-confirmed gold v0 evaluation split.

Both conditions call LocalModel.explain_issues(), so schema, batching,
max_tokens, parsing, degradation, model selection, and decoding are shared.
The only difference is the opt-in conservative triage instruction.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from evaluate_triage import mcnemar_exact, wilson_interval
from localguard.config import Config
from localguard.registry import ToolRegistry

GOLD = ROOT / '.workbuddy' / 'gold'
TOOL_CALL = ROOT / '.localguard' / 'curation' / 'tool_call.jsonl'
LANGUAGES = {
    '.py': 'python', '.js': 'javascript', '.ts': 'typescript', '.go': 'go',
    '.rb': 'ruby', '.java': 'java', '.c': 'c', '.cpp': 'cpp', '.php': 'php',
    '.rs': 'rust', '.sol': 'solidity',
}
# HISTORICAL ONLY — DO NOT use to build model inputs.
# This table used to be injected into old-rule_fp_v2 contexts as CWE/category.
# That manufactured a CWE shortcut (e.g. django-sql-injection -> CWE-89) that
# the scanner never produced. build_records() now forwards only metadata that
# is actually present in the normalized finding. Kept solely so the old A/B
# artifact can be interpreted; new runs must not consult it.
RETIRED_RULE_META_FROM_FIRST_AB = {
    'lg.ext.xxe-xml-etree': ('CWE-611', 'other', 'high'),
    'lg.ext.weak-crypto-sha1': ('CWE-327', 'misconfig', 'medium'),
    'lg.ext.weak-crypto-random': ('CWE-330', 'misconfig', 'medium'),
    'lg.ext.python-request-to-path-traversal': ('CWE-22', 'other', 'high'),
    'lg.ext.django-sql-injection-format-string': ('CWE-89', 'injection', 'high'),
}


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def git_output(*args: str, cwd: Path = ROOT) -> str:
    return subprocess.check_output(['git', *args], cwd=cwd, text=True, encoding='utf-8').strip()


def tool_call_index() -> dict[str, dict]:
    index = {}
    for row in load_jsonl(TOOL_CALL):
        for issue in row.get('issues', []):
            index[issue['id']] = row
    return index


def full_source_lines(record: dict, tool_calls: dict[str, dict]) -> tuple[list[str], int]:
    """Return (all file lines, finding line) from the pinned source version."""
    finding = record['finding']
    location = finding.get('locations', [{}])[0]
    path = finding.get('path') or location.get('path', '')
    line = int(finding.get('line') or location.get('line', 1))
    source = record['source']
    if source == 'real_cve_tool_call':
        row = tool_calls[record['id']]
        lines = [item['text'] for item in row['result'].get('lines', [])]
        # tool_call result.lines is already a bounded window near the finding;
        # keep its original numbering by offsetting to the finding line.
        return lines, line
    if source == 'vulnshop_current_scan':
        root = ROOT / 'repos' / 'code-safety' / 'vulnerable-app'
        expected = record['provenance']['code_commit']
        if git_output('rev-parse', 'HEAD', cwd=root) != expected:
            raise ValueError(f'VulnShop checkout moved: expected {expected}')
        lines = (root / path).read_text(encoding='utf-8').splitlines()
    elif source == 'old_rule_fp_v2':
        fix = record['provenance']['fix_commit']
        commit = record['provenance']['code_commit']
        if fix == 'bfc9807':
            lines = git_output('show', f'{commit}:{path}').splitlines()
        elif fix == '852ed77':
            root = ROOT / 'repos' / 'StarryFirefly-s-Blog-personal'
            if git_output('rev-parse', 'HEAD', cwd=root) != commit:
                raise ValueError(f'Blog checkout moved: expected {commit}')
            if git_output('status', '--porcelain', cwd=root):
                raise ValueError('Blog checkout is dirty')
            lines = (root / path).read_text(encoding='utf-8').splitlines()
        else:
            raise ValueError(f'Unsupported old-rule source: {fix}')
    else:
        raise ValueError(f'Unsupported gold source: {source}')
    return lines, line


def source_lines(record: dict, tool_calls: dict[str, dict]) -> list[dict]:
    """Legacy ±3-line context (kept so the first A/B stays reproducible)."""
    lines, line = full_source_lines(record, tool_calls)
    start, end = max(1, line - 3), min(len(lines), line + 3)
    return [{'line': number, 'text': lines[number - 1][:100]} for number in range(start, end + 1)]


VALID_MASKS = {None, 'title', 'metadata', 'both'}


VALID_EVIDENCE = {'window', 'window_code_only', 'full_code_only'}


def build_records(records: list[dict], mask: str | None = None,
                  evidence: str = 'window') -> tuple[list[dict], dict[str, str], dict[str, dict]]:
    """Map gold records to production explain_issues contexts.

    - Missing cwe/category are EMPTY STRINGS (""), matching production
      from_finding()'s finding.get('cwe', '') default. Never 'unknown' — that
      would itself be a label separating negatives from positives.
    - metadata_origin is returned SEPARATELY for audit only; it is NEVER part
      of a model context.
    - masks are SYMMETRIC across all samples: title / metadata / both.
    - evidence='window' (default) keeps the original ±3-line slice verbatim so
      the first A/B stays reproducible.
    - evidence='window_code_only' keeps the SAME ±3-line slice, only stripping
      comments/docstrings. This isolates the de-comment variable: comparing it
      to 'full_code_only' changes ONLY context size, comparing to 'window'
      changes ONLY comments.
    - evidence='full_code_only' extracts the complete enclosing function with
      comments/docstrings stripped uniformly. real_cve_tool_call records have
      no full source (only a 5-line window), so they fall back to that window
      with comments stripped and are marked evidence_basis='window_only' —
      never misrepresented as a full function.
    """
    if mask not in VALID_MASKS:
        raise ValueError(f'mask must be one of {VALID_MASKS}')
    if evidence not in VALID_EVIDENCE:
        raise ValueError(f'evidence must be one of {VALID_EVIDENCE}')
    from evidence_context import build_evidence, strip_comments
    tool_calls = tool_call_index()
    contexts, labels, origins_by_id = [], {}, {}
    for record in records:
        finding = record['finding']
        location = finding.get('locations', [{}])[0]
        path = finding.get('path') or location.get('path', '')
        cwe_raw = finding.get('cwe')
        category_raw = finding.get('category')
        origins = {
            'cwe': 'scanner_normalized' if cwe_raw else 'missing',
            'category': 'scanner_normalized' if category_raw else 'missing',
            'title': 'scanner_normalized' if (finding.get('title') or finding.get('message')) else 'missing',
            'severity': 'scanner_normalized' if finding.get('severity') else 'missing',
            'source': 'scanner_normalized',
        }
        origins_by_id[record['id']] = origins
        # Empty string, never a sentinel the model could read as a class label.
        cwe = str(cwe_raw) if cwe_raw else ''
        category = str(category_raw) if category_raw else ''
        severity_raw = finding.get('severity')
        severity = str(severity_raw).lower() if severity_raw else ''
        severity = {'error': 'high', 'warning': 'medium'}.get(severity, severity)
        title = finding.get('title') or finding.get('message') or ''
        if mask in ('title', 'both'):
            title = ''
        if mask in ('metadata', 'both'):
            cwe, category = '', ''
        language = LANGUAGES.get(Path(path).suffix.lower(), '')
        if evidence in ('window', 'window_code_only'):
            lines = source_lines(record, tool_calls)  # identical ±3-line range
            if evidence == 'window_code_only':
                from evidence_context import strip_window_comments
                lines = strip_window_comments(lines, language)
            evidence_basis = 'window_3_lines' if evidence == 'window' else 'window_3_lines_code_only'
        else:
            all_lines, finding_line = full_source_lines(record, tool_calls)
            if record['source'] == 'real_cve_tool_call':
                # No full source available: strip comments from the window only.
                lines = [{'line': item['line'], 'text': strip_comments(item['text'], language)}
                         for item in all_lines]
                lines = [l for l in lines if l['text'].strip()]
                evidence_basis = 'window_only_no_full_source'
            else:
                lines = build_evidence('\n'.join(all_lines), finding_line, language)
                evidence_basis = 'full_function_code_only'
        contexts.append({
            'id': record['id'],
            'title': str(title)[:300],
            'severity': severity,
            'category': category,
            'cwe': cwe,
            'language': LANGUAGES.get(Path(path).suffix.lower(), 'unknown'),
            'origin_hint': Path(path).parent.as_posix()[:200],
            'source': lines,
            'source_truncated': any(len(item['text']) >= 100 for item in lines),
            # NOTE: metadata_origin AND evidence_basis are audit-only; neither
            # may enter the model payload as they could separate classes.
        })
        origins_by_id[record['id']]['evidence_basis'] = evidence_basis
        labels[record['id']] = record['human_label']
    return contexts, labels, origins_by_id


def metrics(records: list[dict], verdicts: dict, labels: dict[str, str]) -> dict:
    tp = fp = tn = fn = uncertain = exact = triaged = 0
    for record in records:
        verdict = verdicts.get(record['id'], {}).get('verdict')
        if verdict not in {'likely_true', 'likely_false', 'uncertain'}:
            continue
        triaged += 1
        truth = labels[record['id']] == 'likely_true'
        predicted = verdict == 'likely_true'
        tp += truth and predicted
        fn += truth and not predicted
        fp += (not truth) and predicted
        tn += (not truth) and (not predicted)
        uncertain += verdict == 'uncertain'
        exact += verdict == labels[record['id']]
    negatives = fp + tn
    accuracy_lo, accuracy_hi = wilson_interval(exact, triaged)
    fpr_lo, fpr_hi = wilson_interval(fp, negatives)
    return {
        'total_samples': len(records),
        'triaged_count': triaged,
        'coverage': round(triaged / len(records), 4) if records else 0.0,
        'exact_accuracy': round(exact / triaged, 4) if triaged else None,
        'accuracy_wilson95': [round(accuracy_lo, 4), round(accuracy_hi, 4)],
        'binary': {
            'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'precision': round(tp / (tp + fp), 4) if tp + fp else None,
            'recall': round(tp / (tp + fn), 4) if tp + fn else None,
            'false_positive_rate': round(fp / negatives, 4) if negatives else None,
            'fpr_wilson95': [round(fpr_lo, 4), round(fpr_hi, 4)] if negatives else None,
        },
        'uncertain_count': uncertain,
        'uncertain_rate': round(uncertain / triaged, 4) if triaged else None,
        'verdict_distribution': dict(Counter(
            verdicts.get(record['id'], {}).get('verdict', 'missing') for record in records)),
    }


def paired_mcnemar(records: list[dict], before: dict, after: dict) -> dict:
    b = c = paired = excluded = 0
    valid = {'likely_true', 'likely_false', 'uncertain'}
    for record in records:
        first_verdict = before.get(record['id'], {}).get('verdict')
        second_verdict = after.get(record['id'], {}).get('verdict')
        if first_verdict not in valid or second_verdict not in valid:
            excluded += 1
            continue
        paired += 1
        first = first_verdict == 'likely_true'
        second = second_verdict == 'likely_true'
        b += first and not second
        c += (not first) and second
    return {
        'paired_count': paired,
        'excluded_missing_verdict': excluded,
        'comparison_valid': excluded == 0,
        'baseline_positive_conservative_negative': b,
        'baseline_negative_conservative_positive': c,
        'exact_p': round(mcnemar_exact(b, c), 4) if paired else None,
    }


async def run(input_path: Path, out: Path) -> dict:
    gold = load_jsonl(input_path)
    contexts, labels, metadata_origins = build_records(gold)
    config = Config.load(str(ROOT / 'localguard.local.json'))
    registry = ToolRegistry(config)
    try:
        model = registry.get_model()
        baseline = await model.explain_issues(contexts, '8gb', triage=True)
        conservative = await model.explain_issues(contexts, '8gb', triage=True, conservative=True)
    finally:
        await registry.close()
    paired = paired_mcnemar(contexts, baseline, conservative)
    report = {
        'kind': 'gold_v0_prompt_ab',
        'warning': 'EXPLORATORY ONLY — 18 evaluation samples (11 positive / 7 negative). Not a deployment or retraining gate.',
        'comparison_valid': paired['comparison_valid'],
        'input': str(input_path),
        'input_sha256': hashlib.sha256(input_path.read_bytes()).hexdigest(),
        'model_endpoint': config.model_endpoint,
        'model_path': config.model_path,
        'code_commit': git_output('rev-parse', 'HEAD'),
        'conditions': {
            'baseline': {'conservative': False},
            'conservative': {'conservative': True},
        },
        # Audit only — never sent to the model.
        'metadata_origin_audit': metadata_origins,
        'baseline': metrics(contexts, baseline, labels),
        'conservative': metrics(contexts, conservative, labels),
        'paired_mcnemar': paired,
        'per_sample': [
            {
                'id': record['id'],
                'human_label': labels[record['id']],
                'baseline_verdict': baseline.get(record['id'], {}).get('verdict'),
                'baseline_confidence': baseline.get(record['id'], {}).get('confidence'),
                'conservative_verdict': conservative.get(record['id'], {}).get('verdict'),
                'conservative_confidence': conservative.get(record['id'], {}).get('confidence'),
            }
            for record in contexts
        ],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=GOLD / 'gold_v0_eval.jsonl')
    parser.add_argument('--out', type=Path, default=GOLD / 'gold_v0_prompt_ab.json')
    args = parser.parse_args()
    asyncio.run(run(args.input, args.out))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
