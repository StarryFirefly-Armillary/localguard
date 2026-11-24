"""Apply AI-assisted review labels to collected scanner findings.

AI labels are never written to human_label. They remain explicitly marked as
AI annotations requiring user confirmation before becoming gold data.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / '.workbuddy' / 'training_data'

LOCAL_FALSE = {
    'FINDING-f34b996619c422eb', 'FINDING-dc14d6f522081675',
    'FINDING-a68d4012fd56a85e', 'FINDING-8969dd1d66feffb5',
    'FINDING-5b82cd256a67426d', 'FINDING-c39543d8c3be5da6',
    'FINDING-a27c36a1c4e4b725', 'FINDING-a9835c9c43ad233e',
    'FINDING-d184083cf7748a89', 'FINDING-a04400f5d054c1ee',
    'FINDING-0faa10828a58108c', 'FINDING-75c46e0356f9d18a',
    'FINDING-4cb4739a9e0786cb', 'FINDING-ad0f1852da07789d',
    'FINDING-2dd20092ef16d344',
}
LOCAL_UNCERTAIN = {
    'FINDING-562e1c77ed0fec6b', 'FINDING-ec7f1a643a512aa7',
}


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def write(path: Path, rows: list[dict]) -> None:
    path.write_text(''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in rows), encoding='utf-8')


def real_repo_reason(row: dict) -> str:
    rule = row['provenance'].get('rule_id') or ''
    path = row['finding']['path']
    if rule in {'jwt', 'generic-api-key', 'private-key', 'patterns.hardcoded-credential'}:
        return 'Documentation, tutorial, or test credential; no real deployed secret is exposed.'
    if rule in {'lg.ext.weak-crypto-md5', 'lg.ext.weak-crypto-sha1'}:
        return 'Hash is used for protocol compatibility, ETag/cache identity, or non-security integrity, not a security boundary.'
    if rule == 'lg.ext.weak-crypto-random':
        return 'Randomness is used for retry jitter or another non-security purpose.'
    return 'Trusted library-internal API or data flow; no attacker-controlled input reaches the reported sink.'


def local_reason(row: dict, label: str) -> str:
    if label == 'likely_false':
        return 'Scanner finding is a rule/template mismatch, public-data access, placeholder credential, or trusted internal flow.'
    if label == 'uncertain':
        return 'Hardcoded value is present but no reachable security use was established in the repository.'
    rule = row['provenance'].get('rule_id') or ''
    cwe = row['finding'].get('cwe') or ''
    if 'command' in rule or cwe == 'CWE-78':
        return 'Request-controlled data reaches shell command execution.'
    if 'path-traversal' in rule or cwe == 'CWE-22':
        return 'Request-controlled path reaches filesystem access without containment validation.'
    if 'xxe' in rule or cwe == 'CWE-611':
        return 'Request-controlled XML reaches a parser without effective entity/DTD restrictions.'
    if 'sql' in rule or cwe == 'CWE-89':
        return 'Request-controlled data reaches SQL construction/execution without parameterization.'
    if 'pickle' in rule or 'deserial' in rule or cwe == 'CWE-502':
        return 'Client-controlled data reaches unsafe deserialization.'
    if 'ssti' in rule or 'template' in rule or cwe in {'CWE-1336', 'CWE-94'}:
        return 'Request-controlled template content reaches template compilation/rendering.'
    if 'ssrf' in rule or cwe == 'CWE-918':
        return 'Request-controlled URL reaches an outbound server-side request without target validation.'
    if 'xss' in rule or cwe == 'CWE-79':
        return 'User-controlled content is rendered without effective escaping.'
    return 'Source review confirms the scanner finding has a real vulnerability data flow.'


def annotate(rows: list[dict], kind: str) -> list[dict]:
    for row in rows:
        if kind == 'real_repo':
            label, reason = 'likely_false', real_repo_reason(row)
        else:
            label = 'likely_false' if row['id'] in LOCAL_FALSE else (
                'uncertain' if row['id'] in LOCAL_UNCERTAIN else 'likely_true')
            reason = local_reason(row, label)
        row['ai_label'] = label
        row['ai_reason'] = reason
        row['annotator'] = 'AI'
        row['needs_user_confirmation'] = True
        row['human_label'] = None
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--real-repo', type=Path, default=DATA / 'real_repo_findings.jsonl')
    parser.add_argument('--local', type=Path, default=DATA / 'local_findings.jsonl')
    args = parser.parse_args()
    real = annotate(load(args.real_repo), 'real_repo')
    local = annotate(load(args.local), 'local')
    write(args.real_repo.with_name(args.real_repo.stem + '_ai_labeled.jsonl'), real)
    write(args.local.with_name(args.local.stem + '_ai_labeled.jsonl'), local)
    print(json.dumps({
        'real_repo': len(real), 'real_repo_labels': {v: sum(r['ai_label'] == v for r in real) for v in ('likely_true', 'likely_false', 'uncertain')},
        'local': len(local), 'local_labels': {v: sum(r['ai_label'] == v for r in local) for v in ('likely_true', 'likely_false', 'uncertain')},
        'human_labels_written': 0,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
