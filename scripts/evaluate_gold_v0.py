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
RULE_META = {
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


def source_lines(record: dict, tool_calls: dict[str, dict]) -> list[dict]:
    finding = record['finding']
    location = finding.get('locations', [{}])[0]
    path = finding.get('path') or location.get('path', '')
    line = int(finding.get('line') or location.get('line', 1))
    source = record['source']
    if source == 'real_cve_tool_call':
        row = tool_calls[record['id']]
        return [
            {'line': item['line'], 'text': item['text'][:100]}
            for item in row['result'].get('lines', [])
            if abs(item['line'] - line) <= 3
        ]
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
    start, end = max(1, line - 3), min(len(lines), line + 3)
    return [{'line': number, 'text': lines[number - 1][:100]} for number in range(start, end + 1)]


def build_records(records: list[dict]) -> tuple[list[dict], dict[str, str]]:
    tool_calls = tool_call_index()
    contexts, labels = [], {}
    for record in records:
        finding = record['finding']
        location = finding.get('locations', [{}])[0]
        path = finding.get('path') or location.get('path', '')
        rule = finding.get('rule_id')
        cwe, category, default_severity = RULE_META.get(rule, (finding.get('cwe', ''), finding.get('category', 'other'), 'medium'))
        severity = str(finding.get('severity', default_severity)).lower()
        severity = {'error': 'high', 'warning': 'medium'}.get(severity, severity)
        title = finding.get('title') or finding.get('message') or 'Scanner finding'
        lines = source_lines(record, tool_calls)
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
        })
        labels[record['id']] = record['human_label']
    return contexts, labels


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
    contexts, labels = build_records(gold)
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
