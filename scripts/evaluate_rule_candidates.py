"""Reusable offline evaluator for Semgrep/Gitleaks rule candidates.

The evaluator materializes labeled source files in a system temporary
directory, runs the scanners there, and writes a redacted, recomputable
report. It never opens a LocalGuard store and never writes source snippets or
secret values into its output.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Callable, Iterable

ROOT = Path(__file__).resolve().parents[1]
RULE_DIR = ROOT / 'localguard' / 'rules'
SMOKE_FIXTURES = ROOT / 'tests' / 'fixtures' / 'rule_eval'

POSITIVE_LABELS = frozenset({'confirmed', 'likely_true', 'true_positive', 'tp'})
NEGATIVE_LABELS = frozenset({'false_positive', 'likely_false', 'benign', 'fp', 'true_negative', 'tn'})
SCANNERS = ('semgrep', 'gitleaks')
FORCED_REPRESENTATIVE_IDS = (
    'ISSUE-0ac8978268f9',
    'ISSUE-1dd606e7aa89',
    'ISSUE-6cd074dc5d2f',
    'ISSUE-da900649d0e9',
    'ISSUE-7349f3ca73f2',
    'ISSUE-df00926eb0a6',
)
GOLD_RULE_IDS = ('generic-api-key', 'lg.ext.ssrf-requests-user-input')
GOLD_COMMAND_ID = 'FINDING-e9a9eccc806a307d'
CONFIRMED_CROSS_FUNCTION_IDS = frozenset({
    'ISSUE-1dd606e7aa89',
    'ISSUE-6cd074dc5d2f',
})
EVALUATION_SCOPES = frozenset({'file_local', 'cross_function_required'})
SUMMARY_COHORTS = ('representative50', 'offline27', 'gold_v1')
_WINDOWS_DRIVE = re.compile(r'^[A-Za-z]:')
_UNSAFE_PART = re.compile(r'[<>:"|?*]')


class EvalInputError(ValueError):
    """Raised when an input is missing, malformed, duplicated or unsafe."""


@dataclass
class Case:
    cohorts: list[str]
    issue_id: str
    rule_id: str
    scanner: str
    path: str
    line: int
    label: str
    label_raw: str
    source_path: Path
    source_sha256: str
    materialized_rel: str = ''
    reference: bool = False
    source_note: str = ''
    aliases: list[str] = field(default_factory=list)
    evaluation_scope: str = 'file_local'

    def as_row(self, status: str, matched: bool) -> dict:
        return {
            'cohorts': list(self.cohorts),
            'issue_id': self.issue_id,
            'aliases': list(self.aliases),
            'reference': self.reference,
            'rule_id': self.rule_id,
            'scanner': self.scanner,
            'path': self.path,
            'line': self.line,
            'label': self.label,
            'label_raw': self.label_raw,
            'source_sha256': self.source_sha256,
            'materialized_path': self.materialized_rel,
            'evaluation_scope': self.evaluation_scope,
            'status': status,
            'matched': matched,
        }


@dataclass
class Variant:
    label: str
    scanner: str
    configs: list[Path]


@dataclass
class RunResult:
    label: str
    scanner: str
    configs: list[dict]
    stdout_sha256: str
    raw_sha256: str
    raw_file: str
    hits: list[dict] = field(default_factory=list)
    unmatched_raw_count: int = 0
    scanner_error_count: int = 0
    returncode: int = 0
    stderr_chars: int = 0


@dataclass
class DedupeResult:
    cases: list[Case]
    forced_references: list[dict]
    input_row_count: int
    duplicate_row_count: int
    duplicate_ids: list[dict]


def deduplicate_cases(summary_cases: list[Case], reference_cases: list[Case]) -> DedupeResult:
    """Merge cases by issue_id or normalized location; keep cohort membership.

    A second row is a duplicate when either its issue_id or its normalized
    scanner/path/line/rule tuple already exists. Labels must agree; differing
    human labels are a hard error rather than a silent merge.
    """
    unique: list[Case] = []
    by_id: dict[str, Case] = {}
    by_location: dict[tuple[str, str, int, str], Case] = {}
    duplicates: list[dict] = []

    def record_duplicate(case: Case, existing: Case, kind: str, key: object) -> None:
        if case.label != existing.label or case.label_raw.strip().lower() != existing.label_raw.strip().lower():
            raise EvalInputError(
                f'Label conflict for {case.issue_id}: {case.label_raw!r} vs {existing.issue_id} {existing.label_raw!r}')
        if case.source_sha256 != existing.source_sha256:
            raise EvalInputError(f'Source hash conflict for {case.issue_id} vs {existing.issue_id}')
        if case.issue_id != existing.issue_id and case.issue_id not in existing.aliases:
            existing.aliases.append(case.issue_id)
            by_id[case.issue_id] = existing
        for cohort in case.cohorts:
            if cohort == 'gold_v1_forced_ref':
                continue  # reference-only membership is reported separately.
            if cohort not in existing.cohorts:
                existing.cohorts.append(cohort)
        merged_cohorts = list(dict.fromkeys([*existing.cohorts, *case.cohorts]))
        duplicates.append({
            'issue_id': case.issue_id,
            'matched_issue_id': existing.issue_id,
            'kind': kind,
            'key': key if isinstance(key, str) else list(key),
            'cohorts': merged_cohorts,
            'aliases': list(existing.aliases),
        })

    for case in summary_cases:
        existing = by_id.get(case.issue_id)
        kind = 'issue_id'
        key: object = case.issue_id
        if existing is None:
            location = location_key(case)
            existing = by_location.get(location)
            kind = 'location'
            key = list(location)
        if existing is None:
            created = Case(**{**case.__dict__, 'cohorts': list(case.cohorts), 'aliases': list(case.aliases)})
            unique.append(created)
            by_id[created.issue_id] = created
            by_location[location_key(created)] = created
            continue
        record_duplicate(case, existing, kind, key)

    references: list[dict] = []
    for case in reference_cases:
        existing = by_id.get(case.issue_id)
        if existing is None:
            raise EvalInputError(f'gold_v1 forced reference has no matching case: {case.issue_id}')
        record_duplicate(case, existing, 'forced_reference', case.issue_id)
        references.append({
            'issue_id': case.issue_id,
            'target_issue_id': existing.issue_id,
            'cohorts': list(case.cohorts),
            'label': existing.label,
            'status': 'reference_verified',
        })

    return DedupeResult(
        cases=unique,
        forced_references=references,
        input_row_count=len(summary_cases) + len(reference_cases),
        duplicate_row_count=len(duplicates),
        duplicate_ids=duplicates,
    )


def portable_path(path: Path, anchor: Path = ROOT) -> str:
    """Render a path relative to an anchor, never as a machine-local absolute path."""
    try:
        return path.resolve().relative_to(anchor.resolve()).as_posix()
    except (OSError, RuntimeError, ValueError):
        return path.name


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.is_file():
        raise EvalInputError(f'Missing input file: {path}')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_config(path: Path) -> str:
    if path.is_file():
        return sha256_file(path)
    if not path.is_dir():
        raise EvalInputError(f'Missing scanner config: {path}')
    digest = hashlib.sha256()
    for child in sorted(path.rglob('*')):
        if child.is_file():
            digest.update(child.relative_to(path).as_posix().encode('utf-8'))
            digest.update(sha256_file(child).encode('ascii'))
    return digest.hexdigest()


def normalize_relative_path(value: object, *, context: str = 'path') -> str:
    """Return a safe POSIX relative path; reject absolute/traversal input."""
    if not isinstance(value, str) or not value.strip():
        raise EvalInputError(f'Missing {context}')
    if '\x00' in value:
        raise EvalInputError(f'NUL byte in {context}')
    candidate = value.strip().replace('\\', '/')
    if candidate.startswith('/') or candidate.startswith('//') or _WINDOWS_DRIVE.match(candidate):
        raise EvalInputError(f'Absolute path is not allowed for {context}: {value}')
    parts: list[str] = []
    for part in candidate.split('/'):
        if part in ('', '.'):
            continue
        if part == '..':
            raise EvalInputError(f'Path traversal is not allowed for {context}: {value}')
        if _UNSAFE_PART.search(part):
            raise EvalInputError(f'Unsafe character in {context}: {value}')
        parts.append(part)
    if not parts:
        raise EvalInputError(f'Empty {context}')
    return '/'.join(parts)


def normalize_rule_id(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        return ''
    rule = value.strip().lower()
    return rule.removeprefix('rules.').removeprefix('localguard.')


def load_scope_map(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    if not path.is_file():
        raise EvalInputError(f'Missing evaluation scope manifest: {path}')
    document = load_json_file(path)
    scopes = document.get('scopes') if isinstance(document, dict) else document
    if not isinstance(scopes, dict) or not scopes:
        raise EvalInputError(f'No scopes in evaluation scope manifest: {path}')
    result: dict[str, str] = {}
    for issue_id, value in scopes.items():
        if not isinstance(issue_id, str) or not issue_id.strip():
            raise EvalInputError(f'Invalid issue_id in scope manifest: {path}')
        scope = str(value or '').strip()
        if scope not in EVALUATION_SCOPES:
            raise EvalInputError(f'Invalid evaluation scope for {issue_id}: {value!r}')
        result[issue_id.strip()] = scope
    return result


def resolve_scope(issue_id: str, explicit: object, scope_map: dict[str, str]) -> str:
    """Resolve a per-case scope; never infer one from rule names."""
    if isinstance(explicit, str) and explicit.strip():
        scope = explicit.strip()
        if scope not in EVALUATION_SCOPES:
            raise EvalInputError(f'Invalid evaluation scope for {issue_id}: {explicit!r}')
        return scope
    if issue_id in scope_map:
        return scope_map[issue_id]
    if issue_id in CONFIRMED_CROSS_FUNCTION_IDS:
        return 'cross_function_required'
    raise EvalInputError(f'Missing evaluation scope for {issue_id}; scope must be explicit')


def location_key(case: Case) -> tuple[str, str, int, str]:
    return (case.scanner, normalize_relative_path(case.path), case.line, normalize_rule_id(case.rule_id))


def normalize_line(value: object, *, context: str = 'line') -> int:
    if isinstance(value, bool):
        raise EvalInputError(f'Invalid {context}: {value!r}')
    try:
        line = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise EvalInputError(f'Invalid {context}: {value!r}') from exc
    if line < 1 or line > 10_000_000:
        raise EvalInputError(f'{context} out of range: {line}')
    return line


def normalize_label(value: object, *, context: str) -> tuple[str, str]:
    raw = value if isinstance(value, str) else ''
    key = raw.strip().lower()
    if key in POSITIVE_LABELS:
        return 'positive', raw
    if key in NEGATIVE_LABELS:
        return 'negative', raw
    raise EvalInputError(f'Unsupported label for {context}: {raw!r}')


def load_json_file(path: Path) -> object:
    if not path.is_file():
        raise EvalInputError(f'Missing input file: {path}')
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, ValueError) as exc:
        raise EvalInputError(f'Cannot parse JSON input {path}: {exc}') from exc


def resolve_source_file(item: dict, base: Path) -> Path:
    candidates: list[Path] = []
    canonical = item.get('canonical_location')
    if isinstance(canonical, str) and canonical.strip():
        candidates.append(Path(canonical))
    target = item.get('target')
    if isinstance(target, str) and target.strip():
        candidates.append(Path(target) / item['path'])
    if not candidates:
        raise EvalInputError(f'No source location for {item.get("issue_id")!r}')
    for candidate in candidates:
        try:
            resolved = candidate if candidate.is_absolute() else (base / candidate)
            resolved = resolved.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved.is_file():
            return resolved
    raise EvalInputError(f'Source file not found for {item.get("issue_id")!r}: {candidates}')


def verify_source_hash(path: Path, expected: object, *, context: str) -> str:
    actual = sha256_file(path)
    if isinstance(expected, str) and expected.strip():
        if expected.strip().lower() != actual:
            raise EvalInputError(f'Source hash mismatch for {context}: expected {expected}, got {actual}')
    return actual


def load_labeled_cohort(path: Path, cohort: str, scope_map: dict[str, str] | None = None) -> list[Case]:
    document = load_json_file(path)
    if isinstance(document, dict):
        items = document.get('findings')
    else:
        items = document
    if not isinstance(items, list) or not items:
        raise EvalInputError(f'No findings in {path}')
    cases: list[Case] = []
    seen: set[str] = set()
    base = path.parent
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise EvalInputError(f'{path}: finding {index} is not an object')
        issue_id = str(item.get('issue_id') or '').strip()
        if not issue_id:
            raise EvalInputError(f'{path}: finding {index} has no issue_id')
        if issue_id in seen:
            raise EvalInputError(f'Duplicate issue_id in {cohort}: {issue_id}')
        seen.add(issue_id)
        scanner = str(item.get('scanner') or '').strip().lower()
        if scanner not in SCANNERS:
            raise EvalInputError(f'{path}: unsupported scanner for {issue_id}: {scanner!r}')
        label, label_raw = normalize_label(item.get('human_decision'), context=issue_id)
        rule_id = str(item.get('rule_id') or '').strip()
        if not rule_id:
            raise EvalInputError(f'{path}: missing rule_id for {issue_id}')
        source = resolve_source_file(item, base)
        cases.append(Case(
            cohorts=[cohort],
            issue_id=issue_id,
            rule_id=rule_id,
            scanner=scanner,
            path=normalize_relative_path(item.get('path'), context=f'{issue_id}.path'),
            line=normalize_line(item.get('line'), context=f'{issue_id}.line'),
            label=label,
            label_raw=label_raw,
            source_path=source,
            source_sha256=verify_source_hash(source, item.get('file_sha256'), context=issue_id),
            evaluation_scope=resolve_scope(issue_id, item.get('scope'), scope_map or {}),
        ))
    return cases


def _recovery_map(report: object, base: Path, *, kind: str) -> dict[str, tuple[Path, str]]:
    if not isinstance(report, dict):
        raise EvalInputError(f'Invalid recovery report: {kind}')
    entries = report.get('entries')
    if not isinstance(entries, list):
        raise EvalInputError(f'No entries in recovery report: {kind}')
    mapping: dict[str, tuple[Path, str]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get('record_id'):
            continue
        status = str(entry.get('status') or '')
        if 'recovered' not in status and 'verified' not in status:
            continue
        recovered = entry.get('recovered_file')
        if not recovered:
            continue
        source = Path(recovered)
        if not source.is_absolute():
            source = base / source
        expected = entry.get('expected_sha256') or entry.get('actual_sha256') or entry.get('pinned_sha256') or ''
        mapping[str(entry['record_id'])] = (source, str(expected))
    return mapping


def load_gold_cases(
    records_path: Path,
    recovery_path: Path,
    representative_cases: list[Case],
    scope_map: dict[str, str] | None = None,
    local_recovery_path: Path | None = None,
) -> tuple[list[Case], list[Case]]:
    if not records_path.is_file():
        raise EvalInputError(f'Missing gold_v1 records: {records_path}')
    if not recovery_path.is_file():
        raise EvalInputError(f'Missing gold_v1 recovery report: {recovery_path}')
    try:
        records = [json.loads(line) for line in records_path.read_text(encoding='utf-8').splitlines() if line.strip()]
    except (OSError, UnicodeError, ValueError) as exc:
        raise EvalInputError(f'Cannot parse gold_v1 records: {exc}') from exc
    by_rule: dict[str, list[dict]] = defaultdict(list)
    command: list[dict] = []
    seen_ids: set[str] = set()
    for record in records:
        record_id = str(record.get('id') or '')
        if not record_id:
            raise EvalInputError('gold_v1 record has no id')
        if record_id in seen_ids:
            raise EvalInputError(f'Duplicate gold_v1 record id: {record_id}')
        seen_ids.add(record_id)
        rule_id = str((record.get('finding') or {}).get('rule_id') or '')
        if rule_id in GOLD_RULE_IDS:
            by_rule[rule_id].append(record)
        if record_id == GOLD_COMMAND_ID:
            command.append(record)
    expected_counts = {'generic-api-key': 12, 'lg.ext.ssrf-requests-user-input': 4}
    for rule_id, expected in expected_counts.items():
        if len(by_rule[rule_id]) != expected:
            raise EvalInputError(f'gold_v1 {rule_id}: expected {expected} records, got {len(by_rule[rule_id])}')
    if len(command) != 1:
        raise EvalInputError(f'gold_v1 command-injection forced regression: expected 1 record, got {len(command)}')

    recovery = _recovery_map(load_json_file(recovery_path), recovery_path.parent, kind='network')
    if local_recovery_path is not None:
        if not local_recovery_path.is_file():
            raise EvalInputError(f'Missing gold_v1 local recovery report: {local_recovery_path}')
        recovery.update(_recovery_map(load_json_file(local_recovery_path),
                                      local_recovery_path.parent, kind='local'))

    cases: list[Case] = []
    all_gold = [record for values in by_rule.values() for record in values] + command
    for record in all_gold:
        record_id = str(record['id'])
        finding = record.get('finding') or {}
        provenance = record.get('provenance') or {}
        rule_id = str(finding.get('rule_id') or '')
        scanner = str(provenance.get('scanner') or '').strip().lower()
        if scanner not in SCANNERS:
            raise EvalInputError(f'gold_v1 {record_id}: unsupported scanner {scanner!r}')
        if record_id in recovery:
            source, expected = recovery[record_id]
            expected = expected or str(provenance.get('pinned_file_sha256') or '')
        else:
            target = provenance.get('target')
            if not target:
                raise EvalInputError(f'gold_v1 {record_id}: no source and no target')
            source = Path(target) / str(finding.get('path') or '')
            expected = str(provenance.get('materialized_source_sha256') or '')
        label, label_raw = normalize_label(record.get('label'), context=record_id)
        cases.append(Case(
            cohorts=['gold_v1'],
            issue_id=record_id,
            rule_id=rule_id,
            scanner=scanner,
            path=normalize_relative_path(finding.get('path'), context=f'{record_id}.path'),
            line=normalize_line(finding.get('line'), context=f'{record_id}.line'),
            label=label,
            label_raw=label_raw,
            source_path=source.resolve(strict=True),
            source_sha256=verify_source_hash(source.resolve(strict=True), expected, context=record_id),
            source_note='recovered_source' if record_id in recovery else 'provenance_target',
            evaluation_scope=resolve_scope(
                record_id, record.get('scope') or finding.get('scope'), scope_map or {}),
        ))

    rep_by_id = {case.issue_id: case for case in representative_cases}
    missing_refs = [issue_id for issue_id in FORCED_REPRESENTATIVE_IDS if issue_id not in rep_by_id]
    if missing_refs:
        raise EvalInputError(f'gold_v1 forced representative regressions missing: {missing_refs}')
    references: list[Case] = []
    for issue_id in FORCED_REPRESENTATIVE_IDS:
        original = rep_by_id[issue_id]
        references.append(Case(
            cohorts=['gold_v1_forced_ref'],
            issue_id=original.issue_id,
            rule_id=original.rule_id,
            scanner=original.scanner,
            path=original.path,
            line=original.line,
            label=original.label,
            label_raw=original.label_raw,
            source_path=original.source_path,
            source_sha256=original.source_sha256,
            reference=True,
            source_note='representative_label_reference',
            evaluation_scope=original.evaluation_scope,
        ))
    if len(cases) + len(references) != 23:
        raise EvalInputError(f'gold_v1 forced regression set must be 23 rows, got {len(cases) + len(references)}')
    return cases, references


def materialize_cases(cases: Iterable[Case], root: Path) -> None:
    for index, case in enumerate(cases):
        cohort = case.cohorts[0] if case.cohorts else 'unknown'
        rel = Path(case.scanner) / cohort / f'{index:04d}' / case.path
        destination = root / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        data = case.source_path.read_bytes()
        if hashlib.sha256(data).hexdigest() != case.source_sha256:
            raise EvalInputError(f'Source changed during materialization: {case.issue_id}')
        destination.write_bytes(data)
        case.materialized_rel = rel.as_posix()


def default_semgrep_configs() -> list[Path]:
    configs = [RULE_DIR / name for name in ('backdoor.json', 'security.json', 'security-extended.json')]
    for config in configs:
        if not config.is_file():
            raise EvalInputError(f'Missing production Semgrep config: {config}')
    return configs


def default_gitleaks_configs() -> list[Path]:
    config = RULE_DIR / 'gitleaks.toml'
    if not config.is_file():
        raise EvalInputError(f'Missing production Gitleaks config: {config}')
    return [config]


def build_variants(scanner: str, candidates: list[str] | None) -> list[Variant]:
    defaults = default_semgrep_configs() if scanner == 'semgrep' else default_gitleaks_configs()
    variants = [Variant(f'{scanner}-baseline', scanner, defaults)]
    for index, value in enumerate(candidates or [], 1):
        path = Path(value).resolve(strict=False)
        if not path.exists():
            raise EvalInputError(f'Missing candidate config for {scanner}: {value}')
        variants.append(Variant(f'{scanner}-candidate-{index}', scanner, [path]))
    return variants


def scanner_environment(scratch: Path) -> dict[str, str]:
    env = {
        'HOME': str(scratch), 'USERPROFILE': str(scratch),
        'XDG_CONFIG_HOME': str(scratch), 'XDG_CACHE_HOME': str(scratch / 'cache'),
        'APPDATA': str(scratch), 'LOCALAPPDATA': str(scratch),
        'TMPDIR': str(scratch), 'TEMP': str(scratch), 'TMP': str(scratch),
        'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'NO_COLOR': '1',
        'PYTHONSAFEPATH': '1', 'PYTHONNOUSERSITE': '1',
        'SEMGREP_SEND_METRICS': 'off', 'SEMGREP_ENABLE_VERSION_CHECK': '0',
        'SEMGREP_SETTINGS_FILE': str(scratch / 'semgrep-settings.yml'),
        'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off',
        'GOVCS': '*:off', 'GOENV': 'off', 'GOWORK': 'off', 'CGO_ENABLED': '0',
        'GOPATH': str(scratch / 'gopath'), 'GOCACHE': str(scratch / 'gocache'),
        'PIP_CONFIG_FILE': os.devnull, 'PIP_NO_INPUT': '1',
        'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_NO_INDEX': '1',
    }
    paths = []
    if os.name == 'nt':
        system = Path(os.environ.get('SystemRoot', 'C:/Windows')).resolve()
        env['SystemRoot'] = env['WINDIR'] = str(system)
        paths.append(str(system / 'System32'))
    else:
        paths.extend(['/usr/bin', '/bin'])
    env['PATH'] = os.pathsep.join(paths)
    return env


def build_command(scanner: str, binary: Path, configs: list[Path], root: Path, scratch: Path) -> list[str]:
    if scanner == 'semgrep':
        command = [str(binary), 'scan']
        for config in configs:
            command += ['--config', str(config.resolve())]
        command += [
            '--json', '--oss-only', '--metrics=off', '--disable-version-check',
            '--disable-nosem', '--no-git-ignore', '--no-rewrite-rule-ids',
            '--jobs=1', '--max-target-bytes', '1048576', str(root),
        ]
        return command
    ignore = scratch / 'empty.gitleaksignore'
    ignore.write_text('', encoding='utf-8')
    return [
        str(binary), 'dir', '--config', str(configs[0].resolve()), '--no-banner',
        '--report-format=json', '--report-path=-', '--exit-code=0',
        '--ignore-gitleaks-allow', '--gitleaks-ignore-path', str(ignore), str(root),
    ]


def run_scanner_command(command: list[str], scratch: Path, timeout: int) -> tuple[bytes, int, int]:
    try:
        completed = subprocess.run(
            command, capture_output=True, timeout=timeout,
            env=scanner_environment(scratch), cwd=str(scratch), check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise EvalInputError(f'Scanner timed out: {command[0]}') from exc
    except OSError as exc:
        raise EvalInputError(f'Cannot execute scanner {command[0]}: {exc}') from exc
    if completed.returncode not in (0, 1):
        raise EvalInputError(f'Scanner exit code {completed.returncode}: {command[0]}')
    return completed.stdout, completed.returncode, len(completed.stderr or b'')


def smoke_runner(scanner: str, root: Path, configs: list[Path], scratch: Path) -> tuple[bytes, int, int]:
    """Deterministic offline scanner seam for tracked minimal fixtures."""
    hits: list[dict] = []
    for path in sorted(root.rglob('*')):
        if not path.is_file():
            continue
        rule = ''
        for index, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            if line.startswith('# rule='):
                rule = line.split('=', 1)[1].strip()
            elif line.startswith('HIT ') and rule:
                relative = path.relative_to(root).as_posix()
                if scanner == 'semgrep':
                    hits.append({'check_id': rule, 'path': relative, 'start': {'line': index}})
                else:
                    hits.append({'RuleID': rule, 'File': relative, 'StartLine': index})
    if scanner == 'semgrep':
        payload = {'results': hits, 'errors': []}
    else:
        payload = hits
    return json.dumps(payload, ensure_ascii=True).encode('utf-8'), 0, 0


def parse_raw_hits(scanner: str, stdout: bytes, *, scan_root: Path | None = None) -> tuple[list[dict], int]:
    try:
        text = stdout.decode('utf-8-sig')
        document = json.loads(text) if text.strip() else (None if scanner == 'gitleaks' else {})
    except (UnicodeError, ValueError) as exc:
        raise EvalInputError(f'Invalid {scanner} JSON output: {exc}') from exc
    if scanner == 'semgrep':
        if not isinstance(document, dict) or not isinstance(document.get('results'), list):
            raise EvalInputError('Unexpected Semgrep JSON schema')
        entries = document['results']
        errors = len(document.get('errors') or [])
    else:
        if document is not None and not isinstance(document, list):
            raise EvalInputError('Unexpected Gitleaks JSON schema')
        entries = document or []
        errors = 0
    root_prefix = scan_root.resolve().as_posix().rstrip('/') + '/' if scan_root is not None else None
    hits: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        raw_path = entry.get('path') if scanner == 'semgrep' else entry.get('File')
        raw_line = (entry.get('start') or {}).get('line') if scanner == 'semgrep' else entry.get('StartLine')
        raw_rule = entry.get('check_id') if scanner == 'semgrep' else entry.get('RuleID')
        if not isinstance(raw_path, str):
            raise EvalInputError(f'Invalid {scanner} path: {raw_path!r}')
        path = raw_path.replace('\\', '/')
        if root_prefix and path.lower().startswith(root_prefix.lower()):
            path = path[len(root_prefix):]
        hits.append({
            'path': normalize_relative_path(path, context=f'{scanner}.path'),
            'line': normalize_line(raw_line, context=f'{scanner}.line'),
            'rule_id': normalize_rule_id(raw_rule),
        })
    hits.sort(key=lambda item: (item['path'], item['line'], item['rule_id']))
    return hits, errors


def canonical_raw_bytes(hits: list[dict]) -> bytes:
    return (json.dumps(hits, ensure_ascii=True, separators=(',', ':'), sort_keys=True) + '\n').encode('utf-8')


def match_status(case: Case, hits: list[dict]) -> tuple[str, bool]:
    rule = normalize_rule_id(case.rule_id)
    matched = any(
        hit['path'] == case.materialized_rel and hit['line'] == case.line and hit['rule_id'] == rule
        for hit in hits
    )
    if case.label == 'positive':
        return ('TP' if matched else 'FN'), matched
    return ('FP' if matched else 'TN'), matched


def _ratio(numerator: int, denominator: int):
    return round(numerator / denominator, 6) if denominator else 'N/A'


def summarize_cases(cases: list[Case], hits: list[dict], *, cohort: str | None = None) -> dict:
    """Summarize one cohort (or all cases for row generation).

    Cross-function cases are reported as N/A and excluded from every TP/FP/FN/TN
    metric: per-file materialization cannot support repository-level analysis.
    """
    selected = cases if cohort is None else [case for case in cases if cohort in case.cohorts]
    supported = [case for case in selected if case.evaluation_scope == 'file_local']
    unsupported = [case for case in selected if case.evaluation_scope != 'file_local']
    rows: list[dict] = []
    statuses: Counter[str] = Counter()
    for case in supported:
        status, matched = match_status(case, hits)
        statuses[status] += 1
        rows.append(case.as_row(status, matched))
    for case in unsupported:
        rows.append(case.as_row('N/A_cross_function', False))
    by_rule: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for row in rows:
        if row['status'] == 'N/A_cross_function':
            continue
        by_rule[(row['scanner'], row['rule_id'])][row['status']] += 1

    def metrics(counts: Counter[str]) -> dict:
        total = sum(counts.values())
        matched = counts['TP'] + counts['FP']
        positives = counts['TP'] + counts['FN']
        negatives = counts['FP'] + counts['TN']
        return {
            'total': total,
            'TP': counts['TP'], 'FP': counts['FP'], 'FN': counts['FN'], 'TN': counts['TN'],
            'matched': matched,
            'coverage': _ratio(matched, total),
            'positive_coverage': _ratio(counts['TP'], positives),
            'false_positive_rate': _ratio(counts['FP'], negatives),
        }

    rule_metrics = [
        {'scanner': scanner, 'rule_id': rule_id, **metrics(counts)}
        for (scanner, rule_id), counts in sorted(by_rule.items())
    ]
    return {
        'overall': metrics(statuses),
        'rules': rule_metrics,
        'rows': rows,
        'case_count': len(selected),
        'supported_case_count': len(supported),
        'unsupported_case_ids': [case.issue_id for case in unsupported],
        'unmatched_issue_ids': [row['issue_id'] for row in rows if row['matched'] is False and row['status'] != 'N/A_cross_function'],
        'false_negative_issue_ids': [row['issue_id'] for row in rows if row['status'] == 'FN'],
        'false_positive_issue_ids': [row['issue_id'] for row in rows if row['status'] == 'FP'],
    }


def discover_binary(scanner: str, explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit).resolve(strict=True)
        if not path.is_file():
            raise EvalInputError(f'Missing {scanner} binary: {path}')
        return path
    config = ROOT / 'localguard.local.json'
    if config.is_file():
        try:
            document = json.loads(config.read_text(encoding='utf-8'))
        except (OSError, UnicodeError, ValueError) as exc:
            raise EvalInputError(f'Cannot parse {config}: {exc}') from exc
        candidate = (document.get('binaries') or {}).get(scanner)
        if candidate:
            path = Path(candidate).resolve(strict=True)
            if path.is_file():
                return path
    found = shutil.which(scanner)
    if found:
        return Path(found).resolve(strict=True)
    raise EvalInputError(f'No {scanner} binary provided and none configured')


def build_report_markdown(report: dict) -> str:
    lines = [
        '# 离线规则候选评估',
        '',
        f"- 生成时间: {report['generated_at']}",
        f"- 输入行数: {report['input_row_count']}；唯一案例: {report['unique_case_count']}；重复行: {report['duplicate_row_count']}",
        f"- 分层: {', '.join(f'{k}={v}' for k, v in sorted(report['cohort_counts'].items()))}",
        '',
        '## 输入',
        '',
    ]
    for name, item in report['inputs'].items():
        lines.append(f"- `{name}`: sha256 `{item['sha256']}`")
    lines += ['', '## 限制', '']
    for note in report['limitations']:
        lines.append(f"- {note}")
    lines += ['', '## 变体结果（分队列，无跨队列合并 FPR）', '']
    for variant in report['variants']:
        lines.append(f"### {variant['label']}")
        lines.append('')
        lines.append(f"- raw_sha256 `{variant['raw_sha256']}`；stdout_sha256 `{variant['stdout_sha256']}`")
        lines.append(f"- raw 未归属: {variant['unmatched_raw_count']}；扫描器错误数: {variant['scanner_error_count']}")
        lines.append('')
        for cohort_name, summary in variant['metrics']['cohorts'].items():
            overall = summary['overall']
            lines.append(f"#### {cohort_name}")
            lines.append('')
            lines.append(
                f"- 唯一案例={summary['case_count']}；可评估={summary['supported_case_count']}；"
                f"N/A 跨函数={len(summary['unsupported_case_ids'])}"
            )
            lines.append(
                f"- TP={overall['TP']} FP={overall['FP']} FN={overall['FN']} TN={overall['TN']} "
                f"coverage={overall['coverage']} positive_coverage={overall['positive_coverage']} "
                f"false_positive_rate={overall['false_positive_rate']}"
            )
            lines.append('| scanner | rule_id | TP | FP | FN | TN | coverage | positive_coverage |')
            lines.append('|---|---|---:|---:|---:|---:|---:|---:|')
            for row in summary['rules']:
                lines.append(
                    f"| {row['scanner']} | `{row['rule_id']}` | {row['TP']} | {row['FP']} | "
                    f"{row['FN']} | {row['TN']} | {row['coverage']} | {row['positive_coverage']} |"
                )
            lines.append('')
    lines += [
        '## 可重算说明',
        '',
        '- 每个变体的 raw 索引保存在独立 JSON 文件，只含规范化 path/line/rule_id。',
        '- `raw_sha256` 是对该索引 bytes 的 SHA256；`stdout_sha256` 仅记录扫描器原始 stdout 哈希，不落盘原文。',
        '- TP/FP/FN/TN 由去重后的用例标签与 raw 索引按 path/line/rule_id 精确匹配，按队列重算。',
        '- `gold_v1_forced_ref` 只校验引用，不进入任何 TP/FP/FN/TN。',
        '- 报告不含源码片段、secret 值或原始扫描器消息。',
        '',
    ]
    return '\n'.join(lines)


def evaluate(
    *,
    representative_path: Path,
    offline_path: Path,
    gold_records_path: Path,
    gold_recovery_path: Path,
    gold_local_recovery_path: Path | None = None,
    scope_map_path: Path | None = None,
    semgrep_candidates: list[str] | None = None,
    gitleaks_candidates: list[str] | None = None,
    semgrep_binary: str | None = None,
    gitleaks_binary: str | None = None,
    output_path: Path,
    raw_dir: Path,
    timeout: int = 300,
    expected_input_rows: int | None = None,
    runner: Callable[[str, Path, list[Path], Path], tuple[bytes, int, int]] | None = None,
) -> dict:
    """Run the full evaluator. ``runner`` is an injectable scanner seam for tests."""
    for path in (representative_path, offline_path, gold_records_path, gold_recovery_path):
        if not path.is_file():
            raise EvalInputError(f'Missing input: {path}')
    scope_map = load_scope_map(scope_map_path)
    summary_rows = load_labeled_cohort(representative_path, 'representative50', scope_map)
    summary_rows += load_labeled_cohort(offline_path, 'offline27', scope_map)
    gold_cases, forced_references = load_gold_cases(
        gold_records_path, gold_recovery_path, summary_rows, scope_map,
        local_recovery_path=gold_local_recovery_path)
    summary_rows += gold_cases
    expected = expected_input_rows if expected_input_rows is not None else len(summary_rows) + len(forced_references)
    if len(summary_rows) + len(forced_references) != expected:
        raise EvalInputError(
            f'Expected {expected} input rows, got {len(summary_rows) + len(forced_references)}')
    for case in summary_rows + forced_references:
        if not case.rule_id:
            raise EvalInputError(f'Empty rule_id for {case.issue_id}')
    dedupe = deduplicate_cases(summary_rows, forced_references)
    cases = dedupe.cases

    variants = build_variants('semgrep', semgrep_candidates) + build_variants('gitleaks', gitleaks_candidates)
    binaries: dict[str, Path] = {}
    if runner is None:
        for scanner in SCANNERS:
            if any(variant.scanner == scanner for variant in variants):
                binaries[scanner] = discover_binary(
                    scanner, semgrep_binary if scanner == 'semgrep' else gitleaks_binary)

    raw_dir.mkdir(parents=True, exist_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    run_results: list[RunResult] = []
    with tempfile.TemporaryDirectory(prefix='localguard-rule-candidate-') as temp:
        work = Path(temp)
        scan_root = work / 'cases'
        materialize_cases(cases, scan_root)
        scratch = work / 'scratch'
        scratch.mkdir()
        for variant in variants:
            if runner is not None:
                stdout, returncode, stderr_chars = runner(variant.scanner, scan_root, variant.configs, scratch)
            else:
                command = build_command(
                    variant.scanner, binaries[variant.scanner], variant.configs, scan_root, scratch)
                stdout, returncode, stderr_chars = run_scanner_command(command, scratch, timeout)
            hits, errors = parse_raw_hits(variant.scanner, stdout, scan_root=scan_root)
            raw_bytes = canonical_raw_bytes(hits)
            raw_file = raw_dir / f'{variant.label}.json'
            raw_file.write_bytes(raw_bytes)
            known = {case.materialized_rel for case in cases if case.scanner == variant.scanner}
            run_results.append(RunResult(
                label=variant.label,
                scanner=variant.scanner,
                configs=[{'path': portable_path(config), 'sha256': sha256_config(config)}
                         for config in variant.configs],
                stdout_sha256=sha256_bytes(stdout),
                raw_sha256=sha256_bytes(raw_bytes),
                raw_file=portable_path(raw_file, output_path.parent),
                hits=hits,
                unmatched_raw_count=sum(1 for hit in hits if hit['path'] not in known),
                scanner_error_count=errors,
                returncode=returncode,
                stderr_chars=stderr_chars,
            ))

    inputs = {
        'representative50': {'path': portable_path(representative_path), 'sha256': sha256_file(representative_path)},
        'offline27': {'path': portable_path(offline_path), 'sha256': sha256_file(offline_path)},
        'gold_v1_records': {'path': portable_path(gold_records_path), 'sha256': sha256_file(gold_records_path)},
        'gold_v1_recovery': {'path': portable_path(gold_recovery_path), 'sha256': sha256_file(gold_recovery_path)},
    }
    if gold_local_recovery_path is not None:
        inputs['gold_v1_local_recovery'] = {
            'path': portable_path(gold_local_recovery_path),
            'sha256': sha256_file(gold_local_recovery_path),
        }
    if scope_map_path is not None:
        inputs['evaluation_scope_manifest'] = {
            'path': portable_path(scope_map_path), 'sha256': sha256_file(scope_map_path)}
    limitations = [
        'Materialization mode is per-file: only cases explicitly scoped file_local are evaluated.',
        'Only the two confirmed cross-function cases are scoped cross_function_required and excluded from TP/FP/FN/TN; all other SSRF cases remain file_local.',
        'Scope is taken from per-case data or the explicit scope manifest; missing or unresolvable scope is a hard error, never inferred from rule names.',
        'Repository-level mode is not implemented; cross-function conclusions remain unsupported for cross_function_required cases.',
        'Metrics are reported per cohort only; no cross-cohort FPR is produced.',
        'gold_v1_forced_ref rows are reference checks only and never enter TP/FP/FN/TN.',
    ]
    report: dict = {
        'kind': 'offline_rule_candidate_eval',
        'generated_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'materialization_mode': 'per_file',
        'input_row_count': dedupe.input_row_count,
        'unique_case_count': len(cases),
        'duplicate_row_count': dedupe.duplicate_row_count,
        'duplicate_ids': dedupe.duplicate_ids,
        'forced_references': dedupe.forced_references,
        'cohort_counts': {
            cohort: sum(1 for case in cases if cohort in case.cohorts) for cohort in SUMMARY_COHORTS
        },
        'inputs': inputs,
        'limitations': limitations,
        'variants': [],
        'notes': [
            'All source files were copied into a system temporary directory; no LocalGuard store was opened.',
            'Raw index files contain only normalized path/line/rule_id; no secret values or source snippets are persisted.',
            'Deduplication merges by issue_id or normalized scanner/path/line/rule; label conflicts are hard errors.',
        ],
    }
    for result in run_results:
        scanner_cases = [case for case in cases if case.scanner == result.scanner]
        all_rows = summarize_cases(scanner_cases, result.hits)
        cohort_metrics = {
            cohort: summarize_cases(scanner_cases, result.hits, cohort=cohort)
            for cohort in SUMMARY_COHORTS
        }
        report['variants'].append({
            'label': result.label,
            'scanner': result.scanner,
            'configs': result.configs,
            'stdout_sha256': result.stdout_sha256,
            'raw_sha256': result.raw_sha256,
            'raw_file': result.raw_file,
            'raw_result_count': len(result.hits),
            'unmatched_raw_count': result.unmatched_raw_count,
            'scanner_error_count': result.scanner_error_count,
            'returncode': result.returncode,
            'stderr_chars': result.stderr_chars,
            'metrics': {
                'cohorts': {
                    cohort: {
                        key: summary[key] for key in (
                            'overall', 'rules', 'case_count', 'supported_case_count',
                            'unsupported_case_ids', 'unmatched_issue_ids',
                            'false_negative_issue_ids', 'false_positive_issue_ids')
                    }
                    for cohort, summary in cohort_metrics.items()
                },
                'unsupported_case_ids': all_rows['unsupported_case_ids'],
            },
            'cases': all_rows['rows'],
        })
    output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    markdown_path = output_path.with_suffix('.md')
    markdown_path.write_text(build_report_markdown(report), encoding='utf-8')
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--smoke', action='store_true',
                        help='Run only tracked minimal fixtures with a deterministic offline scanner seam.')
    parser.add_argument('--representative', type=Path)
    parser.add_argument('--offline', type=Path)
    parser.add_argument('--gold-records', type=Path)
    parser.add_argument('--gold-recovery', type=Path)
    parser.add_argument('--gold-local-recovery', type=Path)
    parser.add_argument('--scope-manifest', type=Path)
    parser.add_argument('--semgrep-config', action='append', default=[],
                        help='Candidate Semgrep config; may repeat. Production baseline is always run.')
    parser.add_argument('--gitleaks-config', action='append', default=[],
                        help='Candidate Gitleaks config; may repeat. Production baseline is always run.')
    parser.add_argument('--semgrep-binary')
    parser.add_argument('--gitleaks-binary')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--raw-dir', type=Path)
    parser.add_argument('--timeout', type=int, default=300)
    args = parser.parse_args(argv)

    explicit_inputs = {
        '--representative': args.representative,
        '--offline': args.offline,
        '--gold-records': args.gold_records,
        '--gold-recovery': args.gold_recovery,
        '--gold-local-recovery': args.gold_local_recovery,
        '--scope-manifest': args.scope_manifest,
        '--semgrep-config': args.semgrep_config or None,
        '--gitleaks-config': args.gitleaks_config or None,
        '--semgrep-binary': args.semgrep_binary,
        '--gitleaks-binary': args.gitleaks_binary,
    }
    if args.smoke:
        supplied = [name for name, value in explicit_inputs.items() if value]
        if supplied:
            parser.error(f'--smoke uses only tracked fixtures; remove: {", ".join(supplied)}')
        out = args.out or (Path(tempfile.mkdtemp(prefix='localguard-rule-eval-smoke-')) / 'report.json')
        raw_dir = args.raw_dir or out.parent / 'raw'
        report = evaluate(
            representative_path=SMOKE_FIXTURES / 'representative_labeled.json',
            offline_path=SMOKE_FIXTURES / 'offline_labeled.json',
            gold_records_path=SMOKE_FIXTURES / 'gold_records.jsonl',
            gold_recovery_path=SMOKE_FIXTURES / 'gold_recovery.json',
            scope_map_path=SMOKE_FIXTURES / 'scope_manifest.json',
            output_path=out.resolve(strict=False),
            raw_dir=raw_dir.resolve(strict=False),
            timeout=args.timeout,
            runner=smoke_runner,
        )
    else:
        missing = [name for name, value in explicit_inputs.items()
                   if name in {'--representative', '--offline', '--gold-records',
                               '--gold-recovery', '--scope-manifest'} and not value]
        if args.out is None:
            missing.append('--out')
        if missing:
            parser.error(f'missing required full-evaluation arguments: {", ".join(missing)}')
        out = args.out
        raw_dir = args.raw_dir or out.parent / 'raw'
        report = evaluate(
            representative_path=args.representative.resolve(strict=False),
            offline_path=args.offline.resolve(strict=False),
            gold_records_path=args.gold_records.resolve(strict=False),
            gold_recovery_path=args.gold_recovery.resolve(strict=False),
            gold_local_recovery_path=(args.gold_local_recovery.resolve(strict=False)
                                      if args.gold_local_recovery else None),
            scope_map_path=args.scope_manifest.resolve(strict=False),
            semgrep_candidates=args.semgrep_config,
            gitleaks_candidates=args.gitleaks_config,
            semgrep_binary=args.semgrep_binary,
            gitleaks_binary=args.gitleaks_binary,
            output_path=out.resolve(strict=False),
            raw_dir=raw_dir.resolve(strict=False),
            timeout=args.timeout,
        )
    print(json.dumps({
        'report': str(out),
        'input_row_count': report['input_row_count'],
        'unique_case_count': report['unique_case_count'],
        'duplicate_row_count': report['duplicate_row_count'],
        'variants': [{
            'label': v['label'],
            'cohorts': {
                cohort: summary['overall'] for cohort, summary in v['metrics']['cohorts'].items()
            },
        } for v in report['variants']],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except EvalInputError as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        raise SystemExit(2)
