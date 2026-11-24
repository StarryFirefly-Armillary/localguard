"""Finalize the user-confirmed gold v0 review batch.

The input batch contains duplicate semgrep findings and temporary absolute
paths. This script de-duplicates by finding identity, normalizes paths, applies
the labels confirmed by the user, and writes grouped train/eval splits.

Output is local data under .workbuddy/gold/ (gitignored), not a report.
"""
from __future__ import annotations

import argparse
from collections import Counter, OrderedDict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GOLD = ROOT / '.workbuddy' / 'gold'


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def normalize_path(value: str) -> str:
    path = value.replace('\\', '/')
    if 'lg-fp-v2-' in path and '/snapshot/' in path:
        path = path.split('/snapshot/', 1)[1]
    if '/StarryFirefly-s-Blog-personal/' in path:
        path = path.split('/StarryFirefly-s-Blog-personal/', 1)[1]
    return path


def finding_location(record: dict) -> tuple[str, int]:
    finding = record['finding']
    path = finding.get('path') or finding.get('locations', [{}])[0].get('path', '')
    line = finding.get('line') or finding.get('locations', [{}])[0].get('line', 0)
    return normalize_path(path), int(line)


def identity(record: dict) -> tuple:
    finding = record['finding']
    location = finding.get('locations', [{}])[0]
    path, line = finding_location(record)
    return (
        record.get('source'),
        finding.get('rule_id') or finding.get('cwe'),
        path,
        line,
        location.get('snippet_hash', ''),
    )


def confirmed_label(record: dict) -> tuple[str, str]:
    source = record.get('source')
    finding = record['finding']
    path, line = finding_location(record)
    if source == 'real_cve_tool_call':
        cve = record.get('provenance', {}).get('cve', 'CVE')
        return 'likely_true', f'Confirmed real {cve} pre-fix finding with validated evidence.'
    if source == 'vulnshop_current_scan':
        cwe = finding.get('cwe', '')
        reasons = {
            'CWE-89': 'Request-controlled data reaches SQL execution.',
            'CWE-1336': 'Request-controlled template reaches Django Template rendering.',
            'CWE-915': 'Request POST fields are assigned to model attributes without an allowlist.',
            'CWE-798': 'Django SECRET_KEY is hardcoded in source.',
            'CWE-918': 'Request-controlled URL reaches requests.get without validation.',
            'CWE-639': 'Profile lookup by user id has no authorization check.',
            'CWE-78': 'Request-controlled command reaches shell execution.',
            'CWE-22': 'Request-controlled filename reaches filesystem access without containment validation.',
        }
        return 'likely_true', reasons.get(cwe, 'Confirmed vulnerable code in the documented VulnShop function.')
    if source == 'old_rule_fp_v2':
        fix = record.get('provenance', {}).get('fix_commit')
        rule = finding.get('rule_id', '')
        if fix == 'bfc9807':
            if rule == 'lg.ext.xxe-xml-etree':
                return 'likely_false', 'XML parser rejects DOCTYPE and ENTITY before ElementTree parsing.'
            return 'likely_false', 'SHA-1 computes a Git blob object id, not a security-sensitive digest.'
        if fix == '852ed77':
            if rule == 'lg.ext.weak-crypto-random' and path == 'app.py' and line == 247:
                return 'likely_true', 'CAPTCHA answer uses non-cryptographic random; the historical fix retained this as a true positive.'
            if rule == 'lg.ext.weak-crypto-random':
                return 'likely_false', 'Random values only control CAPTCHA image coordinates, colors, and distortion.'
            if rule == 'lg.ext.python-request-to-path-traversal':
                return 'likely_false', 'Filename is sanitized by safe_filename before the path join.'
            if rule == 'lg.ext.django-sql-injection-format-string':
                return 'likely_false', 'SQL identifiers come from a hardcoded migration list, not user input.'
    raise ValueError(f'No confirmed label rule for {source}')


def group_key(record: dict) -> str:
    source = record.get('source')
    finding = record['finding']
    path, _ = finding_location(record)
    if source == 'real_cve_tool_call':
        cve = record.get('provenance', {}).get('cve', '')
        if cve in {'CVE-2020-7598', 'CVE-2021-44906'}:
            return 'real_cve:minimist-setKey'
        return f'real_cve:{cve}'
    if source == 'vulnshop_current_scan':
        function = record.get('provenance', {}).get('enclosing_function') or path
        return f'vulnshop:{function}'
    if source == 'old_rule_fp_v2':
        fix = record.get('provenance', {}).get('fix_commit')
        rule = finding.get('rule_id', '')
        if fix == 'bfc9807':
            return f'localguard:{rule}'
        if rule == 'lg.ext.weak-crypto-random':
            return 'blog:captcha-random'
        if rule == 'lg.ext.python-request-to-path-traversal':
            return 'blog:safe-filename-path'
        return 'blog:migration-hardcoded-sql'
    raise ValueError(f'No group key for {source}')


def dedupe(records: list[dict]) -> tuple[list[dict], int]:
    groups: OrderedDict[tuple, list[dict]] = OrderedDict()
    for record in records:
        groups.setdefault(identity(record), []).append(record)
    unique = []
    duplicates = 0
    for items in groups.values():
        record = items[0]
        record['duplicate_count'] = len(items)
        record['duplicate_source_rows'] = len(items)
        unique.append(record)
        duplicates += len(items) - 1
    return unique, duplicates


def finalize(records: list[dict], confirmed_at: str | None = None) -> tuple[list[dict], dict]:
    unique, duplicates = dedupe(records)
    timestamp = confirmed_at or datetime.now(timezone.utc).isoformat(timespec='seconds')
    output = []
    for record in unique:
        label, reason = confirmed_label(record)
        record['human_label'] = label
        record['human_reason'] = reason
        record['needs_review'] = False
        record['review_status'] = 'confirmed'
        record['confirmed_by'] = 'user'
        record['confirmed_at'] = timestamp
        record['group_key'] = group_key(record)
        finding = record['finding']
        if finding.get('path'):
            finding['path'] = normalize_path(finding['path'])
        if record.get('source') == 'old_rule_fp_v2':
            path, line = finding_location(record)
            fix = record.get('provenance', {}).get('fix_commit', '')
            rule = finding.get('rule_id', '')
            record['id'] = f'{fix}:{rule}:{path}:{line}'
        output.append(record)
    return output, {'raw_records': len(records), 'unique_records': len(output), 'duplicates_removed': duplicates}


def split_records(records: list[dict]) -> tuple[list[dict], list[dict]]:
    train, evaluation = [], []
    for record in records:
        source = record.get('source')
        finding = record['finding']
        path, line = finding_location(record)
        is_captcha_random = (
            source == 'old_rule_fp_v2'
            and finding.get('rule_id') == 'lg.ext.weak-crypto-random'
            and path == 'app.py'
        )
        if source == 'real_cve_tool_call' or is_captcha_random:
            train.append(record)
        else:
            evaluation.append(record)
    train_groups = {r['group_key'] for r in train}
    eval_groups = {r['group_key'] for r in evaluation}
    overlap = train_groups & eval_groups
    if overlap:
        raise ValueError(f'Group leakage between splits: {sorted(overlap)}')
    return train, evaluation


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in records), encoding='utf-8')


def label_counts(records: list[dict]) -> dict:
    return dict(Counter(r['human_label'] for r in records))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=GOLD / 'review_batch_v0.jsonl')
    parser.add_argument('--out-dir', type=Path, default=GOLD)
    args = parser.parse_args()
    records = load_jsonl(args.input)
    finalized, stats = finalize(records)
    train, evaluation = split_records(finalized)
    write_jsonl(args.out_dir / 'gold_v0.jsonl', finalized)
    write_jsonl(args.out_dir / 'gold_v0_train.jsonl', train)
    write_jsonl(args.out_dir / 'gold_v0_eval.jsonl', evaluation)
    manifest = {
        'kind': 'localguard_gold_v0',
        'confirmed_by': 'user',
        'confirmed_at': finalized[0]['confirmed_at'] if finalized else None,
        'source_batch': str(args.input),
        'source_sha256': hashlib.sha256(args.input.read_bytes()).hexdigest(),
        **stats,
        'label_counts': label_counts(finalized),
        'split_counts': {'train': len(train), 'eval': len(evaluation)},
        'split_label_counts': {'train': label_counts(train), 'eval': label_counts(evaluation)},
        'split_policy': 'Grouped by CVE/function/rule family; no group_key appears in both splits.',
        'notes': [
            'human_label values were explicitly confirmed by the user.',
            'Duplicate semgrep findings were collapsed by source/rule-or-cwe/path/line/snippet.',
            'Temporary snapshot paths were normalized to repository-relative paths.',
        ],
    }
    (args.out_dir / 'gold_v0_manifest.json').write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
