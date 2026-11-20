"""Fetch and validate a small additional historical security-dialogue corpus.

Use the existing app-env Python with -B. Commands: fetch (explicit network GETs),
build (offline), verify (offline). Only curation/extended is written. No upstream
code, tests, payloads, package installers, Git checkouts, or training are run.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / '.localguard' / 'curation' / 'extended'
sys.path.insert(0, str(ROOT))
from localguard.lines import source_lines
from localguard.training import MAX_RECORD_BYTES, training_messages, validate_record

HOSTS = {'api.github.com', 'curl.se', 'solr.apache.org', 'tomcat.apache.org',
         'www.jenkins.io', 'blog.rust-lang.org'}
REPOSITORIES = {'vercel/next.js', 'apache/tomcat', 'jenkinsci/audit-trail-plugin',
                'dompdf/dompdf', 'OpenZeppelin/openzeppelin-contracts', 'curl/curl'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def write(path, raw, *, immutable=False):
    path = path.resolve()
    require(path.is_relative_to(OUT.resolve()), 'Write outside extended refused')
    path.parent.mkdir(parents=True, exist_ok=True)
    if immutable and path.exists():
        require(path.read_bytes() == raw, f'Pinned artifact changed: {path}')
    else:
        path.write_bytes(raw)


def read_json(path):
    return json.loads(path.read_bytes())


def catalog():
    data = read_json(OUT / 'catalog.json')
    ids = [item['cve'] for item in data['candidates']]
    require(len(ids) == len(set(ids)), 'Repeated event')
    for item in data['candidates']:
        require(re.fullmatch(r'CVE-\d{4}-\d{4,}', item['cve']), 'Invalid CVE')
        if 'repository' in item:
            require(item['repository'] in REPOSITORIES, 'Unapproved repository')
            require(re.fullmatch(r'[a-f0-9]{40}', item['commit']), 'Full commit required')
            require(not Path(item['path']).is_absolute() and '..' not in Path(item['path']).parts,
                    'Invalid repository path')
    return data


def fetch_artifact(url, path, *, online=False, raw_github=False):
    parts = urlsplit(url)
    require(parts.scheme == 'https' and parts.hostname in HOSTS and not parts.fragment,
            'Non-official or fragmented download URL refused')
    receipt_path = path.with_name(path.name + '.receipt.json')
    if not path.exists():
        require(online, f'Missing cached artifact: {path}')
        if parts.hostname == 'api.github.com':
            args = ['gh', 'api', url]
            if raw_github:
                args += ['-H', 'Accept: application/vnd.github.raw+json']
        else:
            args = ['curl', '--fail', '--silent', '--show-error', '--proto', '=https',
                    '--max-time', '60', '--max-filesize', '2000000', url]
        result = subprocess.run(args, check=True, capture_output=True, timeout=90)
        raw = result.stdout
        require(0 < len(raw) <= 2_000_000, 'Artifact size outside allowed bounds')
        raw.decode('utf-8', errors='strict')
        if not raw_github and (parts.hostname == 'api.github.com' or path.suffix == '.json'):
            json.loads(raw)
        write(path, raw, immutable=True)
        write(receipt_path, encoded({'source_url': url, 'artifact': str(path.resolve()),
              'sha256': sha(raw), 'bytes': len(raw),
              'fetched_at_utc': datetime.now(timezone.utc).isoformat(),
              'method': 'gh api GET' if parts.hostname == 'api.github.com' else 'curl HTTPS GET',
              'representation': 'raw blob' if raw_github else 'unmodified response body'}), immutable=True)
    raw = path.read_bytes()
    receipt = read_json(receipt_path)
    require(receipt['source_url'] == url and receipt['sha256'] == sha(raw)
            and receipt['bytes'] == len(raw), 'Artifact receipt mismatch')
    return raw, receipt


def materials(item, *, online=False):
    folder = OUT / 'artifacts' / item['cve']
    advisory_url = item.get('advisory_url') or 'https://api.github.com/advisories/' + item['ghsa']
    raw, receipt = fetch_artifact(advisory_url, folder / 'advisory.json', online=online)
    advisory = json.loads(raw)
    if 'ghsa' in item:
        require(advisory['cve_id'] == item['cve'] and advisory['ghsa_id'] == item['ghsa']
                and not advisory.get('withdrawn_at'), 'Advisory identity/withdrawal mismatch')
        reference = advisory['html_url']
        if item.get('cwe_origin') == 'advisory':
            require(item['cwe'] in {c['cwe_id'] for c in advisory['cwes']}, 'CWE not in advisory')
    else:
        require(item['cve'] in advisory['aliases'], 'Official advisory CVE mismatch')
        require(item['cwe'] == advisory['database_specific']['CWE']['id'], 'CWE mismatch')
        reference = advisory_url
    require(reference in raw.decode() and item['cve'] in raw.decode(), 'Missing provenance in raw advisory')
    result = {'provenance': {'cve': item['cve'], 'reference': reference,
                            'artifact': str((folder / 'advisory.json').resolve()),
                            'sha256': sha(raw)},
              'artifacts': {'advisory.json': (raw, receipt)}, 'sources': {}, 'notices': []}
    for extra in item.get('supplemental', []):
        result['artifacts'][extra['name']] = fetch_artifact(
            extra['url'], folder / extra['name'], online=online)
    if 'repository' not in item:
        return result
    repo, commit = item['repository'], item['commit']
    api = 'https://api.github.com/repos/' + repo
    raw_commit, commit_receipt = fetch_artifact(api + '/commits/' + commit,
                                               folder / 'commit.json', online=online)
    metadata = json.loads(raw_commit)
    require(metadata['sha'] == commit and metadata['html_url'] ==
            'https://github.com/' + repo + '/commit/' + commit, 'Commit identity mismatch')
    require(any(f['filename'] == item['path'] and f['status'] == 'modified'
                for f in metadata['files']), 'Source not modified by selected commit')
    # Link must be present in a downloaded advisory, not in a curator-created wrapper.
    linked = any(metadata['html_url'] in body.decode() for body, _ in result['artifacts'].values())
    if not linked:
        linked = any(change.get('fixed') == commit
                     for affected in advisory.get('affected', [])
                     for version_range in affected.get('ranges', [])
                     if version_range.get('type') == 'GIT' and version_range.get('repo') == 'https://github.com/' + repo + '.git'
                     for change in version_range.get('events', []))
    require(linked, 'Advisory does not link the selected full fix commit')
    result['artifacts']['commit.json'] = (raw_commit, commit_receipt)
    for side, revision in [('before', metadata['parents'][0]['sha']), ('after', commit)]:
        path = item['path']
        blob, source_receipt = fetch_artifact(api + '/contents/' + path + '?ref=' + revision,
            folder / (side + '.source.txt'), online=online, raw_github=True)
        result['sources'][side] = {'raw': blob, 'receipt': source_receipt,
                                  'revision': revision, 'path': path,
                                  'source_url': 'https://github.com/' + repo + '/blob/' + revision + '/' + path}
    for name in item['license_files']:
        body, notice_receipt = fetch_artifact(api + '/contents/' + name + '?ref=' + commit,
            folder / ('notice-' + name.replace('/', '_') + '.txt'), online=online, raw_github=True)
        result['notices'].append({'path': name, 'source_url': 'https://github.com/' + repo + '/blob/' + commit + '/' + name,
                                  'sha256': sha(body), 'artifact': notice_receipt['artifact'],
                                  'text': body.decode('utf-8')})
    return result


class TextOnly(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def normalized(text):
    return ' '.join(text.split())


def quote_text(material, selection):
    body, receipt = material['artifacts'][selection['artifact']]
    text = body.decode('utf-8')
    if selection.get('field'):
        text = json.loads(text)[selection['field']]
    elif selection['artifact'].endswith('.html'):
        parser = TextOnly()
        parser.feed(text)
        text = ''.join(parser.parts)
    quote = selection['quote']
    require(normalized(quote) in normalized(text), 'Published quotation is absent from official artifact')
    return quote, {'kind': 'published_advisory_quote', 'source_url': receipt['source_url'],
                   'artifact': receipt['artifact'], 'sha256': receipt['sha256'],
                   'field': selection.get('field'), 'quote': quote,
                   'comparison': 'HTML entities decoded, whitespace normalized; no text invented'}


def implementation(item, material, side):
    section = item[side]
    pieces, evidence = [section['context']], []
    for span in section.get('ranges', []):
        src = material['sources'][side]
        lines = source_lines(src['raw'])
        start, end = span
        require(1 <= start <= end <= len(lines), 'Invalid source span')
        code = '\n'.join(lines[start - 1:end])
        pieces.append(code)
        evidence.append({'kind': 'verbatim_source_excerpt', 'source_url': src['source_url'],
                         'path': src['path'], 'revision': src['revision'],
                         'start_line': start, 'end_line': end, 'code': code,
                         'artifact': src['receipt']['artifact'], 'sha256': sha(src['raw'])})
    for selection in section.get('quotes', []):
        text, proof = quote_text(material, selection)
        pieces.append('Published advisory quotation (not application source):\n' + text)
        evidence.append(proof)
    require(evidence, 'Implementation has no source or concrete published evidence')
    pieces.append('Source: ' + evidence[0]['source_url'])
    return '\n\n'.join(pieces), evidence


def record_for(item, material):
    before, before_evidence = implementation(item, material, 'before')
    after, after_evidence = implementation(item, material, 'after')
    record = {'id': 'extended-dialogue-' + item['cve'].lower(), 'source': 'security_dialogue',
              'provenance': material['provenance'], 'language': item['language'],
              'dialogue_language': item['dialogue_language'], 'cwe': item['cwe'], 'owasp': item['owasp'],
              'label_rationale': item['label_rationale'], 'cwe_origin': item['cwe_origin'],
              'vulnerable_implementation': before, 'safe_implementation': after,
              'implementation_evidence': {'vulnerable': before_evidence, 'safe': after_evidence},
              'attack_demo': {'nonexecuting': True, 'text': item['attack_demo']},
              'remediation': item['remediation'], 'scope': item['scope'],
              'curation_note': 'Newly authored educational dialogue grounded in a real published event, not recorded user interactions or a fabricated vulnerability.'}
    validate_record(record)
    require(len(json.dumps(record, ensure_ascii=False).encode('utf-8')) < MAX_RECORD_BYTES, 'Oversized record')
    require(len(training_messages(record)) == 5, 'Unexpected dialogue training conversion')
    return record


def assemble():
    records, notices = [], []
    for item in catalog()['candidates']:
        material = materials(item)
        records.append(record_for(item, material))
        notices.append({'cve': item['cve'], 'repository': item.get('repository'),
                        'commit': item.get('commit'), 'license_note': item['license_note'],
                        'files': material['notices'],
                        'artifacts': [r for _, r in material['artifacts'].values()],
                        'source_snapshots': [s['receipt'] for s in material['sources'].values()]})
    return records, notices


def report(records):
    seed_path = OUT.parent / 'security_dialogue.jsonl'
    seed_raw = seed_path.read_bytes()
    seed = [json.loads(row) for row in seed_raw.splitlines() if row.strip()]
    # Seed remains read-only; the main task owns its artifacts and validation.
    require(not ({r['id'] for r in records} & {r['id'] for r in seed}), 'Duplicate seed id')
    require(not ({r['provenance']['cve'] for r in records} &
                 {r['provenance'].get('cve') for r in seed}), 'Repeated seed CVE')
    combined = seed + records
    categories = {f'A{i:02}:2021' for i in range(1, 11)}
    return {'validated_at_utc': datetime.now(timezone.utc).isoformat(),
            'validator': str((ROOT / 'localguard' / 'training.py').resolve()),
            'validator_sha256': sha((ROOT / 'localguard' / 'training.py').read_bytes()),
            'validation_method': 'Unmodified current validate_record called on every extension record; training_messages checked for five turns; extra offline source/quote/receipt verification.',
            'records': len(records), 'passed': len(records), 'failed': 0,
            'results': [{'id': r['id'], 'cve': r['provenance']['cve'], 'owasp': r['owasp'],
                         'language': r['language'], 'status': 'passed'} for r in records],
            'extension_coverage': dict(sorted(Counter(r['owasp'] for r in records).items())),
            'extension_languages': dict(sorted(Counter(r['language'] for r in records).items())),
            'dialogue_languages': dict(sorted(Counter(r['dialogue_language'] for r in records).items())),
            'read_only_seed': {'path': str(seed_path.resolve()), 'sha256': sha(seed_raw), 'records': len(seed),
                               'status': 'Coverage read only; not revalidated by this script'},
            'combined_dialogue_count': len(combined),
            'combined_coverage': dict(sorted(Counter(r['owasp'] for r in combined).items())),
            'missing_extension_categories': sorted(categories - {r['owasp'] for r in records}),
            'missing_combined_categories': sorted(categories - {r['owasp'] for r in combined}),
            'dataset_sha256': sha((OUT / 'security_dialogue.jsonl').read_bytes()),
            'source_notices_sha256': sha((OUT / 'source_notices.json').read_bytes()),
            'catalog_sha256': sha((OUT / 'catalog.json').read_bytes()),
            'network_artifacts': len(list((OUT / 'artifacts').rglob('*.receipt.json'))),
            'network_artifact_bytes': sum(read_json(p)['bytes'] for p in (OUT / 'artifacts').rglob('*.receipt.json')),
            'limitations': catalog()['limitations'],
            'full_three_source_load_dataset': 'Not invoked: this extension intentionally contains only security_dialogue; main task must combine genuine cve_patch and tool_call sources.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['fetch', 'build', 'verify'])
    args = parser.parse_args()
    if args.command == 'fetch':
        for item in catalog()['candidates']:
            print('Fetching official data:', item['cve'], flush=True)
            materials(item, online=True)
        return
    records, notices = assemble()
    dataset = b''.join((json.dumps(r, ensure_ascii=False) + '\n').encode('utf-8') for r in records)
    if args.command == 'build':
        write(OUT / 'security_dialogue.jsonl', dataset)
        write(OUT / 'source_notices.json', encoded({
            'scope': 'Historical source excerpts, verbatim official advisory artifacts, and newly authored multilingual explanation.',
            'prose_authorship': 'Curator-authored educational dialogue, not a claim of recorded users.',
            'redistribution': 'No blanket license clearance is inferred. Retain pinned source notices; review advisory/web terms before redistribution.',
            'safety': 'All downloaded code and advisory payloads are inert evidence; none was executed. No patch triples or tool traces are emitted.',
            'upstream_notices': notices}))
    else:
        require((OUT / 'security_dialogue.jsonl').read_bytes() == dataset, 'Emitted dataset differs from verified evidence')
        require(read_json(OUT / 'source_notices.json')['upstream_notices'] == notices, 'Source notices mismatch')
    result = report(records)
    write(OUT / 'validation_report.json', encoded(result))
    print(json.dumps({k: result[k] for k in ('records', 'passed', 'combined_dialogue_count',
          'combined_coverage', 'missing_combined_categories', 'network_artifact_bytes')}, indent=2))


if __name__ == '__main__':
    main()
