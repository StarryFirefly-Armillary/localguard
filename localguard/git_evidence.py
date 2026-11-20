from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import re

from .paths import BoundaryError, IGNORED


OID = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})\Z')
REF = re.compile(r'[A-Za-z0-9][A-Za-z0-9_./~^+-]{0,159}\Z')
HUNK = re.compile(rb'@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@(?: .*)?\Z')
ESCAPES = {ord(key): value for key, value in zip('abfnrtv\\"', (7, 8, 12, 10, 13, 9, 11, 92, 34))}


def git_command(binary, metadata, data_dir):
    return [binary, '--no-pager', '--no-replace-objects', '--no-lazy-fetch',
            '-c', 'core.fsmonitor=false', '-c', f'core.hooksPath={data_dir / "no-hooks"}',
            '-c', 'core.quotePath=true', f'--git-dir={metadata}']


def git_path(raw):
    try:
        path = raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise BoundaryError('Git paths must be valid UTF-8 for source evidence') from exc
    if not path or '\0' in path or path.startswith('/') or any(p in ('', '.', '..') for p in path.split('/')):
        raise BoundaryError('Invalid relative Git path')
    return path


def header_path(value, prefix):
    if value.startswith(b'"'):
        decoded = bytearray()
        index = 1
        while index < len(value) and value[index] != 34:
            byte = value[index]
            index += 1
            if byte == 92:
                if index >= len(value):
                    raise ValueError('Incomplete Git quoted path')
                byte = value[index]
                if byte in ESCAPES:
                    byte = ESCAPES[byte]
                    index += 1
                elif 48 <= byte <= 55 and re.fullmatch(rb'[0-7]{3}', value[index:index + 3]):
                    byte = int(value[index:index + 3], 8)
                    index += 3
                    if byte > 255:
                        raise ValueError('Invalid Git octal path escape')
                else:
                    raise ValueError('Invalid Git quoted path escape')
            decoded.append(byte)
        if index >= len(value) or value[index + 1:] not in (b'', b'\t'):
            raise ValueError('Invalid Git quoted path terminator')
        value = bytes(decoded)
    elif value.endswith(b'\t'):
        value = value[:-1]
    if value == b'/dev/null':
        return None
    if not value.startswith(prefix):
        raise ValueError('Unexpected Git diff path prefix')
    return git_path(value[len(prefix):])


def diff_changes(patch):
    changes = []
    path = None
    block = False
    in_hunks = False
    old_header = False
    new_header = False
    for line in patch.split(b'\n'):
        if line.startswith(b'diff --git '):
            path = None
            block = True
            in_hunks = old_header = new_header = False
        elif block and line.startswith(b'@@'):
            match = HUNK.fullmatch(line)
            if not match or not new_header:
                raise ValueError('Invalid Git diff hunk metadata')
            in_hunks = True
            start, count = int(match[1]), int(match[2] or b'1')
            if count:
                if path is None or start < 1:
                    raise ValueError('Invalid Git diff destination range')
                changes.append({'path': path, 'start_line': start, 'end_line': start + count - 1})
        elif block and not in_hunks:
            if line.startswith(b'--- '):
                if old_header:
                    raise ValueError('Duplicate Git diff source header')
                header_path(line[4:], b'a/')
                old_header = True
            elif line.startswith(b'+++ '):
                if not old_header or new_header:
                    raise ValueError('Invalid Git diff destination header')
                path = header_path(line[4:], b'b/')
                new_header = True
    return changes


@dataclass(frozen=True)
class RevisionTree:
    root: Path
    commit: str
    entries: dict[str, str]


def parse_tree(output, root, commit, max_files):
    if not OID.fullmatch(commit):
        raise ValueError('Invalid resolved Git head commit')
    if output and not output.endswith(b'\0'):
        raise ValueError('Incomplete NUL-delimited Git tree metadata')
    entries = {}
    for record in output.split(b'\0')[:-1]:
        metadata, separator, raw_path = record.partition(b'\t')
        fields = metadata.split(b' ')
        if not separator or len(fields) != 3:
            raise ValueError('Invalid Git tree metadata')
        mode, kind, raw_oid = fields
        path = git_path(raw_path)
        try:
            oid = raw_oid.decode('ascii')
        except UnicodeDecodeError as exc:
            raise ValueError('Invalid Git blob ID') from exc
        if not OID.fullmatch(oid) or len(oid) != len(commit):
            raise ValueError('Invalid Git blob ID')
        if mode == b'120000':
            raise BoundaryError(f'Unsupported tracked symlink in requested head: {path!r}')
        if mode == b'160000' or kind == b'commit':
            raise BoundaryError(f'Unsupported tracked submodule in requested head: {path!r}')
        if mode not in (b'100644', b'100755') or kind != b'blob':
            raise BoundaryError(f'Unsupported tracked file mode in requested head: {path!r}')
        if path in entries:
            raise ValueError('Duplicate Git tree path')
        entries[path] = oid
        if len(entries) > max_files:
            raise BoundaryError('Git tree exceeds max_files; select a smaller repository')
    return RevisionTree(root, commit, entries)


async def revision_tree(policy, root, commit, config, run):
    metadata = policy.git_metadata(root)
    if metadata == root:
        raise BoundaryError('Incremental scanning requires a working tree matching the requested head; use git_diff for bare history')
    binary = config.binaries.get('git')
    if not binary:
        raise ValueError('Git is unavailable')
    if not OID.fullmatch(commit):
        raise ValueError('Invalid resolved Git head commit')
    command = git_command(binary, metadata, config.data_dir)
    code, output, _ = await run(command + ['ls-tree', '-r', '-z', '--full-tree', commit, '--'],
                               config.data_dir, 30, config.max_output_bytes)
    if code:
        raise ValueError('Cannot read requested head tree locally; prepare a complete local clone and retry')
    return parse_tree(output, root, commit, config.max_files)


def native_path(root, name):
    parts = PurePosixPath(name).parts
    if any(p.casefold() == '.git' for p in parts) or '\\' in name:
        raise BoundaryError(f'Unsupported tracked path for source evidence: {name!r}')
    if os.name == 'nt' and any(any(ord(c) < 32 or c in '<>:"|?*' for c in p) or p.endswith((' ', '.'))
                               or p.split('.')[0].upper() in {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}
                               for p in parts):
        raise BoundaryError(f'Unsupported tracked path on Windows: {name!r}')
    return root.joinpath(*parts)


def checked_file(policy, root, path):
    for part in (path, *path.parents):
        if part == root:
            break
        if part.is_symlink() or (hasattr(part, 'is_junction') and part.is_junction()):
            raise BoundaryError(f'Unsupported linked tracked path: {path.relative_to(root).as_posix()!r}')
    real = policy.resolve(str(path), directory=False)
    if real != path:
        raise BoundaryError('Tracked source path changed; retry incremental scan')
    return real


def verified_bytes(data, oid):
    algorithm = 'sha1' if len(oid) == 40 else 'sha256'
    for candidate in (data, data.replace(b'\r\n', b'\n')):
        framed = b'blob ' + str(len(candidate)).encode('ascii') + b'\0' + candidate
        if hashlib.new(algorithm, framed).hexdigest() == oid:
            return candidate
    return None


def write_revision_snapshot(root, snapshot, revision, policy, config):
    if revision.root != root:
        raise BoundaryError('Git revision metadata belongs to a different scan root')
    hashes, skipped = {}, []
    total = 0
    destinations = set()
    for name, oid in revision.entries.items():
        path = native_path(root, name)
        if path in destinations:
            raise BoundaryError(f'Tracked paths collide on this filesystem: {name!r}')
        destinations.add(path)
        if any(part in IGNORED for part in PurePosixPath(name).parts[:-1]):
            skipped.append(f'Excluded tracked file in ignored directory: {name!r}')
            continue
        if path.is_relative_to(config.data_dir) and not root.is_relative_to(config.data_dir / 'repositories'):
            skipped.append(f'Excluded tracked LocalGuard data file: {name!r}')
            continue
        try:
            real = checked_file(policy, root, path)
            with real.open('rb') as stream:
                data = stream.read(min(config.max_file_bytes, policy.max_bytes) + 1)
            checked_file(policy, root, path)
        except (BoundaryError, OSError) as exc:
            raise BoundaryError(f'Cannot verify required tracked file {name!r} against requested head {revision.commit}: {exc}') from exc
        if len(data) > min(config.max_file_bytes, policy.max_bytes):
            raise BoundaryError(f'Cannot verify requested head: tracked file {name!r} exceeds max_file_bytes')
        total += len(data)
        if total > config.max_repo_bytes:
            raise BoundaryError('Repository exceeds max_repo_bytes')
        verified = verified_bytes(data, oid)
        if verified is None:
            raise BoundaryError(f'Tracked file {name!r} does not match requested head {revision.commit}; use a matching local working tree or a full nonincremental scan')
        if b'\0' in verified[:8192]:
            skipped.append(f'Excluded binary file: {name}')
            continue
        destination = snapshot / PurePosixPath(name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(verified)
        hashes[name] = hashlib.sha256(data).hexdigest()
    return hashes, skipped
