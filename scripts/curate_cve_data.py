"""Curate pinned real security fixes without importing or running upstream code.

Run with the existing .localguard/app-env/Scripts/python.exe and -B:
    scripts/curate_cve_data.py fetch   # explicit official API/Git downloads
    scripts/curate_cve_data.py build   # offline extraction and validation
    scripts/curate_cve_data.py verify  # offline revalidation of emitted files

Only .localguard/curation is written. No training, tool-call fabrication,
checkout, scanner, package installation, or application configuration changes.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import re
import subprocess
import sys

# Do not write import caches outside the authorized curation directory.
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / '.localguard' / 'curation'
sys.path.insert(0, str(ROOT))
from localguard.lines import text_lines
from localguard.parser import SourceParser
from localguard.training import MAX_RECORD_BYTES, training_messages, validate_record

ALLOWED_REPOSITORIES = {
    'jpadilla/pyjwt', 'minimistjs/minimist', 'dgrijalva/jwt-go',
    'go-jose/go-jose', 'rack/rack',
}
LANGUAGES = {'python', 'javascript', 'typescript', 'java', 'go', 'rust',
             'c', 'cpp', 'php', 'ruby', 'solidity'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def destination(path):
    path = path.resolve()
    require(path.is_relative_to(OUT.resolve()), 'Write outside curation refused')
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def immutable(path, raw):
    path = destination(path)
    if path.exists():
        require(path.read_bytes() == raw, f'Existing pinned artifact changed: {path}')
    else:
        path.write_bytes(raw)


def write_json(path, value):
    destination(path).write_bytes(json_bytes(value))


def read_json(path):
    return json.loads(path.read_bytes())


def run(args, *, timeout=180, max_bytes=2_000_000):
    environment = os.environ.copy()
    for key in list(environment):
        if key.startswith('GIT_'):
            del environment[key]
    environment.update(GIT_NO_REPLACE_OBJECTS='1', GIT_TERMINAL_PROMPT='0',
                       GIT_CONFIG_NOSYSTEM='1', GIT_NO_LAZY_FETCH='1')
    result = subprocess.run(args, check=True, capture_output=True, timeout=timeout,
                            env=environment)
    require(len(result.stdout) <= max_bytes, 'Command output exceeds curation bound')
    return result.stdout


def git(repo, *args):
    return run(['git', '--no-pager', '-C', str(repo), *args])


def catalog():
    data = read_json(OUT / 'catalog.json')
    seen = set()
    for item in data['candidates']:
        require(item['repository'] in ALLOWED_REPOSITORIES, 'Unapproved repository')
        require(re.fullmatch(r'[a-f0-9]{40}', item['commit']), 'Full commit required')
        require(re.fullmatch(r'CVE-\d{4}-\d{4,}', item['cve']), 'CVE required')
        require(re.fullmatch(r'GHSA-[a-z0-9-]+', item['ghsa']), 'GHSA required')
        require(item['cve'] not in seen, 'Duplicate event')
        seen.add(item['cve'])
        path = Path(item['path'])
        require(not path.is_absolute() and '..' not in path.parts and
                '\\' not in item['path'] and ':' not in item['path'], 'Invalid source path')
    return data


def paths(item):
    return OUT / 'repos' / item['cve'], OUT / 'artifacts' / item['cve']


def cached_api(endpoint, path, *, online):
    """Preserve exact gh stdout plus a source URL and hash receipt; never synthesize links."""
    receipt_path = path.with_suffix('.receipt.json')
    if not path.exists():
        require(online, f'Missing official artifact: {path}')
        raw = run(['gh', 'api', endpoint])
        json.loads(raw)  # Refuse HTML/error bodies masquerading as JSON.
        immutable(path, raw)
        immutable(receipt_path, json_bytes({
            'source_url': 'https://api.github.com/' + endpoint,
            'fetched_at_utc': datetime.now(timezone.utc).isoformat(),
            'method': 'gh api GET', 'sha256': digest(raw), 'bytes': len(raw),
        }))
    raw = path.read_bytes()
    receipt = read_json(receipt_path)
    require(receipt['source_url'] == 'https://api.github.com/' + endpoint,
            'API receipt endpoint mismatch')
    require(receipt['sha256'] == digest(raw), 'API artifact hash mismatch')
    return json.loads(raw)


def api_material(item, *, online=False):
    _, artifacts = paths(item)
    advisory = cached_api('advisories/' + item['ghsa'], artifacts / 'advisory.json', online=online)
    metadata = cached_api('repos/' + item['repository'] + '/commits/' + item['commit'],
                          artifacts / 'commit.json', online=online)
    repository = cached_api('repos/' + item['repository'], artifacts / 'repository.json', online=online)
    require(advisory['cve_id'] == item['cve'] and advisory['ghsa_id'] == item['ghsa'],
            'Advisory event mismatch')
    require(repository['full_name'].lower() == item['repository'].lower(), 'Repository identity mismatch')
    upstream = 'https://github.com/' + item['repository'] + '.git'
    require(repository['clone_url'].lower() == upstream.lower(), 'Official clone URL mismatch')
    require(metadata['sha'] == item['commit'], 'API commit mismatch')
    require(metadata['html_url'].lower() ==
            ('https://github.com/' + item['repository'] + '/commit/' + item['commit']).lower(),
            'API commit repository mismatch')
    # A reference must actually link this exact commit; text coincidence is insufficient.
    require(metadata['html_url'].lower() in {u.lower().split('#')[0].rstrip('/')
            for u in advisory['references']}, 'No direct official advisory-to-fix link')
    require(item['cwe'] in {c['cwe_id'] for c in advisory['cwes']}, 'CWE absent from official advisory')
    require(any(f['filename'] == item['path'] and f['status'] == 'modified'
                for f in metadata['files']), 'Chosen source is not a modified upstream file')
    require(not advisory.get('withdrawn_at'), 'Withdrawn advisory cannot be used')
    return advisory, metadata, repository


def git_material(item, metadata):
    repo, _ = paths(item)
    require(git(repo, 'remote', 'get-url', 'origin').decode().strip() ==
            'https://github.com/' + item['repository'] + '.git', 'Origin mismatch')
    require(git(repo, 'rev-parse', '--is-bare-repository').strip() == b'true', 'Expected bare repository')
    require(git(repo, 'rev-parse', '--is-shallow-repository').strip() == b'true', 'Expected shallow repository')
    require(git(repo, 'rev-parse', item['commit'] + '^{commit}').decode().strip() == item['commit'],
            'Missing pinned fix commit')
    parent = git(repo, 'rev-parse', item['commit'] + '^').decode().strip()
    require(parent == metadata['parents'][0]['sha'], 'Git/API first parent mismatch')
    require(git(repo, 'cat-file', '-t', parent).strip() == b'commit', 'Missing parent object')
    material = {}
    for revision, revision_id in [('before', parent), ('after', item['commit'])]:
        blob_id = git(repo, 'rev-parse', f'{revision_id}:{item["path"]}').decode().strip()
        raw = git(repo, 'cat-file', 'blob', blob_id)
        # Compute the Git blob object identity independently (these repos use SHA-1).
        require(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == blob_id,
                'Git blob content hash mismatch')
        raw.decode('utf-8', errors='strict')
        material[revision] = {'revision': revision_id, 'git_blob': blob_id,
                              'sha256': digest(raw), 'raw': raw}
    return parent, material


def fetch():
    for item in catalog()['candidates']:
        print('Fetching official artifacts:', item['cve'], flush=True)
        _, metadata, _ = api_material(item, online=True)
        repo, _ = paths(item)
        if not repo.exists():
            destination(repo)
            # No checkout, full history, submodules, partial-clone lazy downloads, or hooks.
            run(['git', 'clone', '--bare', '--no-checkout', '--template=', '--depth=2',
                 '--no-tags', '--revision=' + item['commit'],
                 'https://github.com/' + item['repository'] + '.git', str(repo)], timeout=240)
        git_material(item, metadata)
    print('Official source fetch complete; no upstream code executed.', flush=True)


def qualified_name(node, raw):
    names = []
    current = node
    while current is not None:
        if current == node or current.type in {'class_definition', 'class', 'module'}:
            field = current.child_by_field_name('name')
            if field is not None:
                names.append(raw[field.start_byte:field.end_byte].decode('utf-8'))
        current = current.parent
    return '.'.join(reversed(names))


def extract(path, raw, symbol):
    parser = SourceParser()
    summary = parser.summary(Path(path), raw)
    require(not summary['parse_error'], 'Tree-sitter parse error')
    eligible = {(n['start_line'], n['end_line']) for n in summary['nodes']
                if 'function' in n['type'] or 'method' in n['type']}
    _, tree = parser.source(Path(path), raw)
    candidates, stack = [], [tree.root_node]
    while stack:
        node = stack.pop()
        if ('function' in node.type or 'method' in node.type) and node.child_by_field_name('name'):
            name = qualified_name(node, raw)
            if name == symbol or name.endswith('.' + symbol):
                a, b = node.start_point.row + 1, node.end_point.row + 1
                require((a, b) in eligible, f'{symbol} outside bounded validator AST summary')
                candidates.append({'path': path, 'start_line': a, 'end_line': b,
                                   'code': '\n'.join(text_lines(raw.decode('utf-8'))[a - 1:b])})
        stack.extend(reversed(node.children))
    require(len(candidates) == 1, f'Expected one exact function for {symbol}, got {len(candidates)}')
    return candidates[0]


def provenance(item, advisory):
    repo, artifacts = paths(item)
    artifact = artifacts / 'advisory.json'
    raw = artifact.read_bytes()
    reference = advisory['html_url']
    require(all(s.encode('utf-8') in raw for s in (reference, item['cve'], item['commit'])),
            'Raw advisory lacks event, source reference, or full fix commit')
    return {'repository': str(repo.resolve()),
            'upstream_url': 'https://github.com/' + item['repository'] + '.git',
            'commit': item['commit'], 'cve': item['cve'], 'reference': reference,
            'artifact': str(artifact.resolve()), 'sha256': digest(raw)}


def notices(item, repository):
    repo, _ = paths(item)
    entries = git(repo, 'ls-tree', '--name-only', item['commit']).decode().splitlines()
    filenames = [name for name in entries if re.fullmatch(
        r'(?:(?:[A-Z0-9]+-)?LICEN[CS]E|COPYING|NOTICE|AUTHORS|COPYRIGHT)(?:\..+)?', name, re.I)]
    require(filenames, 'Missing upstream source/license notice')
    files = []
    for name in filenames:
        blob = git(repo, 'rev-parse', item['commit'] + ':' + name).decode().strip()
        raw = git(repo, 'cat-file', 'blob', blob)
        files.append({'path': name, 'git_blob': blob, 'sha256': digest(raw),
                      'source_url': f'https://github.com/{item["repository"]}/blob/{item["commit"]}/{name}',
                      'text': raw.decode('utf-8')})
    return {'cve': item['cve'], 'repository': repository['html_url'], 'commit': item['commit'],
            'github_license_metadata': repository.get('license'),
            'authority': 'Pinned license text below is authoritative; GitHub repository metadata is fetched current metadata.',
            'files': files}


def build():
    data = catalog()
    patches, dialogues, source_index, license_notices = [], [], [], []
    for item in data['candidates']:
        advisory, metadata, repository = api_material(item)
        parent, material = git_material(item, metadata)
        before, after = material['before']['raw'], material['after']['raw']
        vulnerable = extract(item['path'], before, item['function'])
        fixed = extract(item['path'], after, item['function'])
        control = extract(item['path'], before, item['unchanged_function'])
        fixed_control = extract(item['path'], after, item['unchanged_function'])
        require(control['code'] == fixed_control['code'], 'Control is not unchanged')
        control.update(fixed_start_line=fixed_control['start_line'], fixed_end_line=fixed_control['end_line'])
        p = provenance(item, advisory)
        patch = {'id': item['cve'] + '-patch', 'source': 'cve_patch', 'provenance': p,
                 'language': item['language'], 'cwe': item['cwe'], 'owasp': item['owasp'],
                 'functions': {'vulnerable': vulnerable, 'fixed': fixed, 'unchanged': control},
                 'curation': {'patch_scope': item['patch_scope'], 'label_rationale': item['label_rationale'],
                              'function': item['function'], 'control_function': item['unchanged_function']}}
        dialogue = {'id': item['cve'] + '-dialogue', 'source': 'security_dialogue',
                    'provenance': p, 'language': item['language'], 'dialogue_language': item['dialogue_language'],
                    'cwe': item['cwe'], 'owasp': item['owasp'],
                    'vulnerable_implementation': vulnerable['code'], 'safe_implementation': fixed['code'],
                    'attack_demo': {'text': item['attack_demo'], 'nonexecuting': True},
                    'remediation': item['remediation'],
                    'curation': {'matched_patch_id': patch['id'], 'label_rationale': item['label_rationale'],
                                 'patch_scope': item['patch_scope'],
                                 'authorship': 'Newly curated explanation grounded in the real advisory and exact Git blobs; not a recorded user interaction or a synthetic test fixture.'}}
        for record in (patch, dialogue):
            validate_record(record)
            require(len(json.dumps(record, ensure_ascii=False).encode('utf-8')) < MAX_RECORD_BYTES,
                    'Record exceeds dataset line limit')
            expected = 3 if record['source'] == 'cve_patch' else 5
            require(len(training_messages(record)) == expected, 'Unexpected training message structure')
        patches.append(patch)
        dialogues.append(dialogue)
        snapshot_entry = {'cve': item['cve'], 'commit': item['commit'], 'parent': parent,
                          'repository': p['repository'], 'path': item['path'],
                          'function': item['function'], 'snapshots': {}}
        for revision, content in material.items():
            target = OUT / 'snapshots' / item['cve'] / revision / item['path']
            immutable(target, content['raw'])
            snapshot_entry['snapshots'][revision] = {
                **{k: v for k, v in content.items() if k != 'raw'},
                'file': str(target.resolve()),
                'upstream_url': f'https://github.com/{item["repository"]}/blob/{content["revision"]}/{item["path"]}',
                'function_span': {k: v for k, v in (vulnerable if revision == 'before' else fixed).items() if k != 'code'},
            }
        source_index.append(snapshot_entry)
        license_notices.append(notices(item, repository))
        print('Validated real pair:', item['cve'], item['language'], flush=True)
    require(len(patches) >= 6 and len({p['language'] for p in patches}) >= 3, 'Requested minimum not met')
    for filename, records in [('cve_patch.jsonl', patches), ('security_dialogue.jsonl', dialogues)]:
        raw = ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in records).encode('utf-8')
        destination(OUT / filename).write_bytes(raw)
    write_json(OUT / 'source_index.json', source_index)
    write_json(OUT / 'source_notices.json', {
        'scope': 'Historical source excerpts, raw official advisory/API artifacts, and newly authored explanatory prose.',
        'advisory_source': 'GitHub global advisories fetched verbatim via official API; no third-party payloads executed.',
        'prose_authorship': 'Curated explanatory prose is not a transcript of real users. No license clearance is inferred for a downstream redistribution.',
        'upstream_notices': license_notices,
    })
    verify()


def verify():
    data = catalog()
    rows = {}
    for filename, source in [('cve_patch.jsonl', 'cve_patch'), ('security_dialogue.jsonl', 'security_dialogue')]:
        records = []
        for raw in (OUT / filename).read_bytes().splitlines():
            require(len(raw) <= MAX_RECORD_BYTES, 'Oversized record')
            record = validate_record(json.loads(raw))
            require(record['source'] == source, 'Mixed dataset source')
            require(len(training_messages(record)) == (3 if source == 'cve_patch' else 5), 'Message conversion failed')
            records.append(record)
        require(len({r['id'] for r in records}) == len(records), 'Duplicate record IDs')
        rows[source] = records
    patch_by_cve = {r['provenance']['cve']: r for r in rows['cve_patch']}
    require(set(patch_by_cve) == {i['cve'] for i in data['candidates']}, 'Catalog/dataset mismatch')
    require(len(rows['security_dialogue']) == len(patch_by_cve), 'Unmatched dialogue count')
    for row in rows['security_dialogue']:
        patch = patch_by_cve[row['provenance']['cve']]
        require(row['vulnerable_implementation'] == patch['functions']['vulnerable']['code'] and
                row['safe_implementation'] == patch['functions']['fixed']['code'], 'Dialogue/patch snippet mismatch')
        require(row['curation']['matched_patch_id'] == patch['id'], 'Incorrect dialogue/patch identity')
    index = read_json(OUT / 'source_index.json')
    for entry in index:
        item = next(i for i in data['candidates'] if i['cve'] == entry['cve'])
        _, metadata, _ = api_material(item)
        parent, material = git_material(item, metadata)
        require(parent == entry['parent'], 'Snapshot parent mismatch')
        for revision, value in entry['snapshots'].items():
            raw = Path(value['file']).read_bytes()
            require(raw == material[revision]['raw'] and digest(raw) == value['sha256'], 'Snapshot/blob mismatch')
    notices_data = read_json(OUT / 'source_notices.json')
    for entry in notices_data['upstream_notices']:
        item = next(i for i in data['candidates'] if i['cve'] == entry['cve'])
        for value in entry['files']:
            raw = git(paths(item)[0], 'cat-file', 'blob', value['git_blob'])
            require(digest(raw) == value['sha256'] and raw.decode('utf-8') == value['text'], 'License text mismatch')
    records = rows['cve_patch'] + rows['security_dialogue']
    files = ['cve_patch.jsonl', 'security_dialogue.jsonl', 'catalog.json',
             'source_index.json', 'source_notices.json']
    categories = sorted({r['owasp'] for r in rows['security_dialogue']})
    languages = sorted({r['language'] for r in rows['cve_patch']})
    report = {
        'validated_at_utc': datetime.now(timezone.utc).isoformat(),
        'counts': {k: len(v) for k, v in rows.items()} | {'tool_call': 0},
        'distinct_cves': len(patch_by_cve), 'official_repositories': len(ALLOWED_REPOSITORIES),
        'code_languages': languages,
        'dialogue_languages': dict(Counter(r['dialogue_language'] for r in rows['security_dialogue'])),
        'owasp_edition': '2021', 'owasp_categories': categories,
        'owasp_counts': dict(Counter(r['owasp'] for r in rows['security_dialogue'])),
        'missing_owasp_categories': sorted({f'A{i:02d}:2021' for i in range(1, 11)} - set(categories)),
        'missing_code_languages': sorted(LANGUAGES - set(languages)),
        'checks': ['All records passed existing validate_record()', 'All records converted using existing training_messages()',
                   'Whole-function spans parsed with tree-sitter and matched to exact Git blobs',
                   'Same-file unchanged controls verified in both first-parent and fix blobs',
                   'Direct full-commit links verified in raw GitHub advisories',
                   'Git origin and first parent corroborated by official GitHub API responses',
                   'Snapshots and source/license notice text rechecked against Git objects'],
        'training_messages': sum(len(training_messages(r)) for r in records),
        'assistant_targets': sum(sum(m['role'] == 'assistant' for m in training_messages(r)) for r in records),
        'fixture_records': 0, 'trained': False, 'upstream_code_executed': False,
        'blocking_full_training': ['No tool_call records: obtain genuine shared-registry reads and location validation logs separately.',
                                   'OWASP/language coverage is incomplete; this is a small seed corpus, not a representative evaluation set.',
                                   'Tokenizer-specific 4096-token checks and held-out evaluation were not performed; no model directory was accessed.'],
        'split_warning': 'Group patch/dialogue counterparts by CVE; group related minimist CVEs by repository when splitting to avoid leakage.',
        'excluded_candidates': data['excluded_candidates'],
        'artifacts': {name: {'sha256': digest((OUT / name).read_bytes()), 'bytes': (OUT / name).stat().st_size} for name in files},
        'runtime': {'python': sys.version.split()[0], 'tree_sitter': version('tree-sitter'),
                    'tree_sitter_language_pack': version('tree-sitter-language-pack')},
        'curator_script_sha256': digest(Path(__file__).read_bytes()),
        'retained_bytes_before_report': sum(p.stat().st_size for p in OUT.rglob('*') if p.is_file()),
    }
    write_json(OUT / 'validation_report.json', report)
    print(json.dumps({k: report[k] for k in ('counts', 'distinct_cves', 'code_languages',
                                          'owasp_categories', 'missing_owasp_categories',
                                          'missing_code_languages')}, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['fetch', 'build', 'verify'])
    args = parser.parse_args()
    {'fetch': fetch, 'build': build, 'verify': verify}[args.action]()


if __name__ == '__main__':
    main()
