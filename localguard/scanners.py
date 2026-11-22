"""Deterministic scanners with process containment, not an OS/network sandbox."""
from __future__ import annotations

import asyncio
from bisect import bisect_right
import ctypes
import json
import os
from pathlib import Path, PureWindowsPath
import re
import signal
import subprocess
import tempfile
import time
import tomllib
import xml.etree.ElementTree as ET

from .lines import text_lines

SCANNERS = ('patterns', 'semgrep', 'gitleaks', 'gosec', 'cppcheck', 'pip-audit', 'grype')
RULESETS = ('default', 'security', 'backdoor')
RULE_DIR = Path(__file__).resolve().parent / 'rules'
MAX_OUTPUT_BYTES = 128 * 1024  # Combined stdout/stderr, enforced during reads.
MAX_RESULT_BYTES = 200 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_SCAN_BYTES = 32 * 1024 * 1024
MAX_FILES = 10000
MAX_FINDINGS = 300
MAX_LINE_CHARS = 16384
SOURCE_EXTENSIONS = frozenset('''
.py .pyw .pyi .js .jsx .mjs .cjs .ts .tsx .java .go .rs .c .h .cc .cpp
.cxx .hpp .hh .hxx .php .phtml .rb .rake .sol .cs .fs .fsx .swift .kt
.kts .scala .sc .sh .bash .zsh .ps1 .pl .pm .lua .r .m .mm .ex .exs .erl
.hrl .clj .cljs .groovy .dart .vue .svelte .sql .yaml .yml .toml .json
'''.split())
SKIP_DIRS = frozenset({'.git', '.hg', '.svn', '.venv', 'venv', 'node_modules',
                       '__pycache__', 'target', 'vendor', 'dist', 'build'})
SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')
CATEGORIES = frozenset({'credential_leak', 'injection', 'backdoor',
                        'dependency_cve', 'misconfig', 'other'})
PIN = re.compile(r'^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[A-Za-z0-9_,.-]+\])?==([A-Za-z0-9][A-Za-z0-9.!+_-]*)\s*(?:#.*)?$')


def _result(scanner: str) -> dict:
    return dict(scanner=scanner, status='completed', findings=[], raw=None,
                warnings=[], truncated=False)


def _warn(result: dict, message: str) -> None:
    message = str(message)[:600]
    if message in result['warnings']:
        return
    if len(result['warnings']) < 30:
        result['warnings'].append(message)
    else:
        result['truncated'] = True


def _finish(result: dict) -> dict:
    result['findings'].sort(key=lambda f: (SEVERITIES.index(f['severity']),
                                           -f['confidence'], f['path'], f['line'], f['rule_id']))
    def size():
        return len(json.dumps(result, ensure_ascii=True).encode('utf-8'))
    if size() > MAX_RESULT_BYTES:
        result['truncated'] = True
        before = len(result['findings'])
        while result['findings'] and size() > MAX_RESULT_BYTES:
            result['findings'].pop()
        if len(result['findings']) < before:
            _warn(result, 'Structured result exceeded the output limit; findings were omitted.')
        if size() > MAX_RESULT_BYTES:
            result['raw'] = None
            _warn(result, 'Raw output omitted because its JSON representation exceeded the limit.')
    return result


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _is_link(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction())


def _relative(root: Path, value, *, virtual_root: bool = False) -> str | None:
    """Reject traversal and symlink locations; optionally accept Syft's virtual / root."""
    if not isinstance(value, str) or not value or '\x00' in value:
        return None
    value = value.replace('\\', '/')
    if '..' in value.split('/'):
        return None
    if os.name != 'nt' and PureWindowsPath(value).drive:
        return None
    candidate = Path(value)
    if virtual_root and value.startswith('/') and not value.startswith('//') and not _inside(candidate, root):
        # Syft's virtual root also applies on Windows, where /file is drive-relative.
        candidate = root / value.lstrip('/')
    elif not candidate.is_absolute():
        candidate = root / candidate
    if not _inside(candidate, root):
        return None
    try:
        if any(_is_link(p) for p in (candidate, *candidate.parents) if _inside(p, root)):
            return None
        resolved = candidate.resolve(strict=True)
        if not _inside(resolved, root) or not resolved.is_file():
            return None
        return resolved.relative_to(root).as_posix()
    except (OSError, ValueError, RuntimeError):
        return None


def _read(root: Path, relative: str) -> str:
    path = root / relative
    with path.open('rb') as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError('file exceeds scan size limit')
    if b'\x00' in data:
        raise ValueError('binary file')
    return data.decode('utf-8-sig')


def _files(root: Path, result: dict):
    count = 0
    def walk_error(error):
        _warn(result, f'Cannot enumerate snapshot directory: {error}')
        result['truncated'] = True
    for base, directories, names in os.walk(root, followlinks=False, onerror=walk_error):
        directories[:] = sorted(d for d in directories if d not in SKIP_DIRS and not _is_link(Path(base) / d))
        for name in sorted(names):
            path = Path(base) / name
            if _is_link(path) or not path.is_file():
                continue
            count += 1
            if count > MAX_FILES:
                result['truncated'] = True
                _warn(result, 'Snapshot file-count limit reached.')
                return
            yield path.relative_to(root).as_posix()


def _severity(value, default='medium') -> str:
    value = str(value).lower()
    return value if value in SEVERITIES else {'error': 'high', 'warning': 'medium',
        'style': 'low', 'performance': 'low', 'portability': 'low',
        'information': 'info', 'negligible': 'info'}.get(value, default)


def _confidence(value) -> float:
    if isinstance(value, (float, int)) and not isinstance(value, bool):
        return max(0.0, min(1.0, value)) if value == value else 0.5
    return {'high': 0.9, 'medium': 0.65, 'low': 0.4}.get(str(value).lower(), 0.65)


def _cwe(value) -> str:
    if isinstance(value, list):
        value = value[0] if value else ''
    if isinstance(value, dict):
        value = value.get('id', '')
    match = re.search(r'(?:CWE-)?(\d+)', str(value))
    return 'CWE-' + match[1] if match else ''


def _category(cwe: str) -> str:
    return {'CWE-798': 'credential_leak', 'CWE-259': 'credential_leak',
            'CWE-89': 'injection', 'CWE-78': 'injection', 'CWE-95': 'injection',
            'CWE-79': 'injection', 'CWE-506': 'backdoor', 'CWE-288': 'backdoor',
            'CWE-295': 'misconfig', 'CWE-327': 'misconfig'}.get(cwe, 'other')


def _add(result, root, path, line, title, rule, ref, *, severity='medium',
         category='other', cwe='', confidence=0.65, explanation='', remediation=''):
    if len(result['findings']) >= MAX_FINDINGS:
        result['truncated'] = True
        _warn(result, 'Finding-count limit reached; additional findings omitted.')
        return
    relative = _relative(root, path)
    try:
        if isinstance(line, bool) or not re.fullmatch(r'[0-9]+', str(line)):
            raise ValueError('non-integer line')
        line = int(line)
        if relative is None or not 1 <= line <= len(text_lines(_read(root, relative))):
            raise ValueError('location outside the snapshot file')
    except (OSError, ValueError, UnicodeError):
        _warn(result, f'Omitted unlocated scanner finding {rule}: {path}:{line}.')
        return
    result['findings'].append(dict(path=relative, line=line, title=str(title),
        severity=_severity(severity), category=category if category in CATEGORIES else 'other',
        cwe=_cwe(cwe), confidence=_confidence(confidence), tool=result['scanner'],
        rule_id=str(rule), explanation=str(explanation or title),
        remediation=str(remediation or 'Review the scanner evidence and fix the underlying unsafe behavior.'),
        raw_ref=ref))


async def _patterns(root: Path, ruleset: str, result: dict, timeout: int) -> dict:
    document = json.loads((RULE_DIR / 'patterns.json').read_text(encoding='utf-8'))
    rules = [(r, re.compile(r['regex'])) for r in document['rules'] if ruleset in r['rulesets']]
    raw = {'scanner': 'patterns', 'rules_version': document['version'], 'matches': []}
    result['raw'] = raw
    _warn(result, document['description'])
    _warn(result, 'Patterns exclude generated/vendor directories and non-UTF-8, binary, oversized files; no data-flow analysis is performed.')
    started, total = time.monotonic(), 0
    for path in _files(root, result):
        if Path(path).suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        await asyncio.sleep(0)  # Cancellation and other audit jobs remain responsive.
        if time.monotonic() - started >= timeout:
            result['status'] = 'timeout'
            _warn(result, 'Pattern scan timed out; findings are partial.')
            break
        try:
            text = _read(root, path)
        except (OSError, UnicodeError, ValueError) as error:
            result['truncated'] = True
            _warn(result, f'Skipped {path}: {error}')
            continue
        total += len(text.encode('utf-8'))
        if total > MAX_SCAN_BYTES:
            result['truncated'] = True
            _warn(result, 'Pattern scan byte limit reached.')
            break
        for number, line in enumerate(text_lines(text), 1):
            if number % 256 == 0:
                await asyncio.sleep(0)
                if time.monotonic() - started >= timeout:
                    result['status'] = 'timeout'
                    _warn(result, 'Pattern scan timed out; findings are partial.')
                    return result
            if len(line) > MAX_LINE_CHARS:
                result['truncated'] = True
                _warn(result, f'Skipped oversized line in {path}.')
                continue
            if line.lstrip().startswith(('#', '//', '/*', '*', '--')):
                continue
            for rule, regex in rules:
                match = regex.search(line)
                if not match:
                    continue
                if rule.get('exclude_capture_regex') and re.search(rule['exclude_capture_regex'], match.group('secret')):
                    continue
                if len(raw['matches']) >= MAX_FINDINGS:
                    result['truncated'] = True
                    _warn(result, 'Finding-count limit reached; scan is partial.')
                    return result
                index = len(raw['matches'])
                # Do not echo credential literals; offsets remain scanner-derived evidence.
                raw['matches'].append(dict(path=path, line=number, column=match.start() + 1,
                    end_column=match.end() + 1, rule_id=rule['id']))
                _add(result, root, path, number, rule['title'], rule['id'], f'#/matches/{index}',
                     **{key: rule[key] for key in ('severity', 'category', 'cwe', 'confidence', 'explanation', 'remediation')})
    return result


class _WindowsJob:
    """Contain the suspended child before resuming, preventing descendant escape."""
    def __init__(self, pid: int):
        from ctypes import wintypes as w
        class Basic(ctypes.Structure):
            _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
                        ('flags', w.DWORD), ('min_working', ctypes.c_size_t),
                        ('max_working', ctypes.c_size_t), ('active_limit', w.DWORD),
                        ('affinity', ctypes.c_size_t), ('priority', w.DWORD), ('scheduling', w.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(n, ctypes.c_uint64) for n in ('read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes')]
        class Extended(ctypes.Structure):
            _fields_ = [('basic', Basic), ('io', IO), ('process_memory', ctypes.c_size_t),
                        ('job_memory', ctypes.c_size_t), ('peak_process', ctypes.c_size_t), ('peak_job', ctypes.c_size_t)]
        self.api = ctypes.WinDLL('kernel32', use_last_error=True)
        for name, args, restype in (
            ('CreateJobObjectW', [ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
            ('SetInformationJobObject', [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
            ('OpenProcess', [w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            ('AssignProcessToJobObject', [w.HANDLE, w.HANDLE], w.BOOL),
            ('CloseHandle', [w.HANDLE], w.BOOL)):
            fn = getattr(self.api, name)
            fn.argtypes, fn.restype = args, restype
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        process = None
        try:
            limits = Extended()
            limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                raise ctypes.WinError(ctypes.get_last_error())
            process = self.api.OpenProcess(0x0100 | 0x0001 | 0x0800, False, pid)
            if not process or not self.api.AssignProcessToJobObject(self.handle, process):
                raise ctypes.WinError(ctypes.get_last_error())
            resume = ctypes.WinDLL('ntdll').NtResumeProcess
            resume.argtypes, resume.restype = [w.HANDLE], ctypes.c_long
            if resume(process) != 0:
                raise OSError('Could not resume contained scanner process')
        except BaseException:
            self.close()
            raise
        finally:
            if process:
                self.api.CloseHandle(process)

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


class _OutputLimit(Exception):
    pass


async def _execute(argv: list[str], cwd: Path, env: dict[str, str], timeout: float,
                   max_bytes: int | None = None) -> dict:
    if max_bytes is None:
        max_bytes = MAX_OUTPUT_BYTES
    if type(max_bytes) is not int or max_bytes < 0:
        raise ValueError('max_bytes must be a nonnegative integer')
    kwargs = {'creationflags': 0x00000004 | subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == 'nt' else {'start_new_session': True}
    process = await asyncio.create_subprocess_exec(*argv, cwd=str(cwd), env=env,
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, limit=16384, **kwargs)
    job, tasks, count = None, [], 0
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    status, truncated = 'completed', False
    def kill_tree():
        if job is not None:
            job.close()
        elif os.name != 'nt':
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
    async def drain(name, stream):
        nonlocal count
        while chunk := await stream.read(8192):
            available = max_bytes - count
            streams[name].extend(chunk[:available])
            count += min(len(chunk), available)
            if len(chunk) > available:
                raise _OutputLimit()
    async def cleanup():
        kill_tree()
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        async def discard(stream):
            while await stream.read(8192):
                pass
        try:
            await asyncio.wait_for(asyncio.gather(discard(process.stdout),
                discard(process.stderr), process.wait(), return_exceptions=True), 1)
        except asyncio.TimeoutError:
            pass
        finally:
            # Closing paused pipes lets the subprocess transport finish its waiters.
            transport = getattr(process, '_transport', None)
            if transport is not None:
                transport.close()
        if process.returncode is None:
            try:
                await asyncio.wait_for(process.wait(), 1)
            except asyncio.TimeoutError:
                pass
    try:
        if os.name == 'nt':
            job = _WindowsJob(process.pid)
        tasks = [asyncio.create_task(drain('stdout', process.stdout)),
                 asyncio.create_task(drain('stderr', process.stderr)),
                 asyncio.create_task(process.wait())]
        try:
            await asyncio.wait_for(asyncio.gather(*tasks), timeout)
        except _OutputLimit:
            status, truncated = 'error', True
        except asyncio.TimeoutError:
            status = 'timeout'
    finally:
        cleaning = asyncio.create_task(cleanup())
        cancelled = False
        while not cleaning.done():
            try:
                await asyncio.shield(cleaning)
            except asyncio.CancelledError:
                cancelled = True
        cleaning.result()
        if cancelled:
            raise asyncio.CancelledError
    return dict(status=status, truncated=truncated, returncode=process.returncode,
                **{name: bytes(data) for name, data in streams.items()})


def _environment(binary: Path, scratch: Path, root: Path) -> dict[str, str]:
    # Never inherit PATH, PYTHONPATH, GITLEAKS_CONFIG, GOFLAGS, proxy settings,
    # loader hooks, SEMGREP_* or GRYPE_* config overrides from the parent.
    env = {'HOME': str(scratch), 'USERPROFILE': str(scratch),
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
        # go/packages may try compiling imports. A nonexistent absolute toolexec
        # blocks compiler/linker invocation, even for offline=False. No builds.
        'GOFLAGS': '-mod=readonly -buildvcs=false "-toolexec=' + str(scratch / 'compilation-disabled') + '"',
        'PIP_CONFIG_FILE': os.devnull, 'PIP_NO_INPUT': '1',
        'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_NO_INDEX': '1',
        'GRYPE_DB_AUTO_UPDATE': 'false', 'GRYPE_CHECK_FOR_APP_UPDATE': 'false',
        'GRYPE_DB_UPDATE_CHECK': 'false'}
    paths = [str(binary.parent)]
    if os.name == 'nt':
        system = Path(os.environ.get('SystemRoot', 'C:/Windows')).resolve()
        if _inside(system, root):
            raise ValueError('System directory must not be inside the snapshot')
        env['SystemRoot'] = env['WINDIR'] = str(system)
        paths.append(str(system / 'System32'))
    else:
        paths.extend(p for p in ('/usr/bin', '/bin') if not _inside(Path(p).resolve(), root))
    env['PATH'] = os.pathsep.join(paths)
    # A provisioned Grype DB is data, not repo configuration. Preserve only an
    # explicit absolute cache outside the snapshot, otherwise use OS defaults.
    default_cache = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.cache'))) if os.name == 'nt' else Path(os.environ.get('XDG_CACHE_HOME', str(Path.home() / '.cache')))
    cache = Path(os.environ.get('GRYPE_DB_CACHE_DIR', str(default_cache / 'grype' / 'db')))
    if cache.is_absolute() and not _inside(cache.resolve(), root):
        env['GRYPE_DB_CACHE_DIR'] = str(cache.resolve())
    return env


def _pins(root: Path, result: dict) -> dict[tuple[str, str], list[tuple[str, int]]]:
    pins = {}
    total = 0
    for path in _files(root, result):
        name = Path(path).name.lower()
        if not (name.startswith('requirements') and name.endswith('.txt')):
            continue
        try:
            text = _read(root, path)
        except (OSError, ValueError, UnicodeError) as error:
            _warn(result, f'Skipped requirements manifest {path}: {error}')
            continue
        total += len(text.encode('utf-8'))
        if total > MAX_SCAN_BYTES:
            result['truncated'] = True
            _warn(result, 'Requirements scan byte limit reached.')
            break
        for line, text_line in enumerate(text_lines(text), 1):
            text_line = text_line.strip()
            if not text_line or text_line.startswith('#'):
                continue
            match = PIN.fullmatch(text_line)
            if not match:
                _warn(result, f'Unsupported requirement at {path}:{line}; only literal name==version pins are audited (no includes, URLs, markers, options or resolution).')
                continue
            pins.setdefault((_package(match[1]), match[2]), []).append((path, line))
    return pins


def _package(name: str) -> str:
    return re.sub(r'[-_.]+', '-', name).lower()


def _json_scalars(text: str) -> dict:
    """JSON property-path -> (scalar, actual token line), without string searching."""
    json.loads(text)  # Validate first, including nesting and escapes.
    decoder, values, pos = json.JSONDecoder(), {}, 0
    newlines = [index for index, char in enumerate(text) if char == '\n']
    def ws():
        nonlocal pos
        while pos < len(text) and text[pos].isspace():
            pos += 1
    def value(path):
        nonlocal pos
        ws()
        if text[pos] == '{':
            pos += 1
            ws()
            while text[pos] != '}':
                key, pos = decoder.raw_decode(text, pos)
                ws()
                pos += 1  # colon, already validated
                value(path + (key,))
                ws()
                if text[pos] == ',':
                    pos += 1
                    ws()
                else:
                    break
            pos += 1
        elif text[pos] == '[':
            pos += 1
            ws()
            index = 0
            while text[pos] != ']':
                value(path + (index,))
                index += 1
                ws()
                if text[pos] == ',':
                    pos += 1
                    ws()
                else:
                    break
            pos += 1
        else:
            start = pos
            item, pos = decoder.raw_decode(text, pos)
            values[path] = (item, bisect_right(newlines, start) + 1)
    value(())
    return values


def _manifest_lines(root: Path, path: str, package: str, version: str) -> list[int]:
    """Locate a matched package AND exact version; unsupported formats return []."""
    text = _read(root, path)
    name = Path(path).name.lower()
    lines = text_lines(text)
    found = []
    if name.startswith('requirements') and name.endswith('.txt'):
        for line, content in enumerate(lines, 1):
            match = PIN.fullmatch(content.strip())
            if match and _package(match[1]) == _package(package) and match[2] == version:
                found.append(line)
    elif name in {'package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'composer.lock'}:
        scalars = _json_scalars(text)
        for key, (item, line) in scalars.items():
            if item != version:
                continue
            if name == 'package.json' and len(key) == 2 and key[0] in {'dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'} and key[1] == package:
                found.append(line)
            elif name in {'package-lock.json', 'npm-shrinkwrap.json'} and key[-1:] == ('version',):
                if len(key) == 3 and key[0] == 'packages' and str(key[1]).split('node_modules/')[-1] == package:
                    found.append(line)
                elif len(key) >= 3 and key[-3:-1] == ('dependencies', package) and all(part == 'dependencies' for part in key[:-1:2]):
                    found.append(line)
            elif name == 'composer.lock' and len(key) == 3 and key[0] in {'packages', 'packages-dev'} and isinstance(key[1], int) and key[-1] == 'version' and scalars.get(key[:-1] + ('name',), (None,))[0] == package:
                found.append(line)
    elif name in {'cargo.lock', 'poetry.lock', 'uv.lock'}:
        tomllib.loads(text)
        current_name, current_version, version_line = None, None, None
        in_package = False
        def flush():
            if in_package and current_name == package and current_version == version and version_line:
                found.append(version_line)
        for line, content in enumerate(lines, 1):
            if re.fullmatch(r'\s*\[\[package\]\]\s*(?:#.*)?', content):
                flush()
                in_package = True
                current_name, current_version, version_line = None, None, None
            elif content.lstrip().startswith('['):
                flush()
                in_package = False
                current_name, current_version, version_line = None, None, None
            elif in_package:
                match = re.fullmatch(r'\s*(name|version)\s*=\s*[\"\']([^\"\']+)[\"\']\s*(?:#.*)?', content)
                if match and match[1] == 'name':
                    current_name = match[2]
                elif match:
                    current_version, version_line = match[2], line
        flush()
    elif name == 'go.mod':
        for line, content in enumerate(lines, 1):
            match = re.fullmatch(r'\s*(?:require\s+)?(\S+)\s+(v\S+)\s*(?://.*)?', content)
            if match and match[1] == package and match[2].removeprefix('v') == version.removeprefix('v'):
                found.append(line)
    return sorted(set(found))


def _guard_semgrep_config(root: Path) -> None:
    if any((parent / '.semgrepignore').exists() for parent in (root, *root.parents)):
        raise ValueError('Sanitized snapshot must not inherit .semgrepignore configuration')
    count = 0
    def fail(error):
        raise ValueError(f'Cannot validate sanitized snapshot configuration: {error}')
    for base, directories, names in os.walk(root, followlinks=False, onerror=fail):
        count += len(directories) + len(names)
        if count > MAX_FILES:
            raise ValueError('Snapshot too large to verify absence of Semgrep ignore configuration')
        if '.semgrepignore' in names:
            raise ValueError('Sanitized snapshot must not contain .semgrepignore configuration')
        directories[:] = [name for name in directories if not _is_link(Path(base) / name)]


def _parse(scanner: str, data: bytes):
    text = data.decode('utf-8-sig')
    if scanner == 'cppcheck':
        if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
            raise ValueError('XML DTDs and entities are prohibited')
        root = ET.fromstring(text)
        if root.tag != 'results' or root.find('errors') is None:
            raise ValueError('Expected cppcheck results/errors XML')
        def convert(element):
            return {'tag': element.tag, 'attributes': dict(element.attrib),
                    'text': element.text.strip() if element.text else '',
                    'children': [convert(child) for child in element]}
        return convert(root)
    def reject_constant(value):
        raise ValueError(f'Non-finite JSON number: {value}')
    raw = json.loads(text, parse_constant=reject_constant)
    valid = (raw is None or isinstance(raw, list)) if scanner == 'gitleaks' else isinstance(raw, dict)
    key = {'semgrep': 'results', 'gosec': 'Issues', 'grype': 'matches', 'pip-audit': 'dependencies'}.get(scanner)
    if not valid or (key and (key not in raw or not (
            isinstance(raw[key], list) or (scanner == 'gosec' and raw[key] is None)))):
        raise ValueError('Unexpected scanner JSON schema')
    return raw


def _normalize(scanner: str, root: Path, raw, result: dict, pins: dict) -> None:
    if scanner == 'semgrep':
        if raw.get('errors'):
            result['status'] = 'error'
            _warn(result, 'Semgrep reported scan errors; findings may be partial.')
        for index, item in enumerate(raw['results']):
            extra = item.get('extra', {})
            metadata = extra.get('metadata', {})
            cwe = _cwe(metadata.get('cwe', ''))
            _add(result, root, item.get('path'), item.get('start', {}).get('line'),
                extra.get('message', 'Semgrep finding'), item.get('check_id', ''), f'#/results/{index}',
                severity=extra.get('severity'), category=metadata.get('category', _category(cwe)),
                cwe=cwe, confidence=metadata.get('confidence'), remediation=metadata.get('remediation', ''))
        # Semgrep's raw results carry bulky per-match metadata. The full
        # payload blows the structured-output budget and drops most findings.
        # Keep a compact index aligned with the raw_ref (#/results/{index});
        # evidence text already lives in each finding's explanation fields.
        # Only trim oversized payloads; small ones stay verbatim for evidence.
        if len(json.dumps(raw, ensure_ascii=True).encode('utf-8')) > MAX_RESULT_BYTES // 2:
            raw['results'] = [{
                'check_id': r.get('check_id', ''),
                'path': r.get('path', ''),
                'start': r.get('start', {}),
                'extra': {'message': (r.get('extra') or {}).get('message', ''),
                          'severity': (r.get('extra') or {}).get('severity', '')},
            } for r in raw.get('results', [])]
    elif scanner == 'gitleaks':
        for index, item in enumerate(raw or []):
            _add(result, root, item.get('File'), item.get('StartLine'), item.get('Description', 'Credential detected'),
                item.get('RuleID', ''), f'#/{index}', severity='high', category='credential_leak',
                cwe='CWE-798', confidence=0.9, remediation='Verify and revoke exposed credentials; remove them from source and history.')
    elif scanner == 'gosec':
        if raw.get('Golang errors') or raw.get('Errors'):
            result['status'] = 'error'
            _warn(result, 'gosec could not load all packages. Builds, module downloads and CGO are disabled; findings may be partial.')
        for index, item in enumerate(raw['Issues'] or []):
            cwe = _cwe(item.get('cwe', ''))
            # gosec may report a start-end range; its first endpoint is evidence.
            line = str(item.get('line', '')).split('-')[0]
            _add(result, root, item.get('file'), line, item.get('details', 'Go security finding'),
                item.get('rule_id', ''), f'#/Issues/{index}', severity=item.get('severity'),
                category=_category(cwe), cwe=cwe, confidence=item.get('confidence'))
    elif scanner == 'cppcheck':
        for group_index, group in enumerate(raw['children']):
            if group['tag'] != 'errors':
                continue
            for index, item in enumerate(group['children']):
                attributes = item['attributes']
                locations = [child['attributes'] for child in item['children'] if child['tag'] == 'location']
                if not locations:
                    _warn(result, f'Omitted unlocated cppcheck finding {attributes.get("id", "")}.')
                for location in locations[:1]:
                    cwe = _cwe(attributes.get('cwe', ''))
                    _add(result, root, location.get('file'), location.get('line'), attributes.get('msg', 'C/C++ finding'),
                        attributes.get('id', ''), f'#/children/{group_index}/children/{index}',
                        severity=attributes.get('severity'), cwe=cwe, category=_category(cwe),
                        confidence=0.4 if attributes.get('inconclusive') == 'true' else 0.85,
                        explanation=attributes.get('verbose', ''))
    elif scanner == 'pip-audit':
        for index, dependency in enumerate(raw['dependencies']):
            if dependency.get('skip_reason'):
                _warn(result, f'pip-audit skipped {dependency.get("name", "package")}: {dependency["skip_reason"]}')
            name, version = dependency.get('name', ''), dependency.get('version', '')
            locations = pins.get((_package(name), version), [])
            for vi, vulnerability in enumerate(dependency.get('vulns', [])):
                if not locations:
                    _warn(result, f'Omitted unlocated dependency {name}=={version}: {vulnerability.get("id", "")}.')
                for path, line in locations:
                    _add(result, root, path, line, f'{vulnerability.get("id", "Advisory")} in {name} {version}',
                        vulnerability.get('id', ''), f'#/dependencies/{index}/vulns/{vi}',
                        severity=vulnerability.get('severity', 'info'), category='dependency_cve', confidence=0.95,
                        explanation=vulnerability.get('description', 'pip-audit advisory; severity not provided by the tool.'),
                        remediation='Review advisory and upgrade to a compatible fixed version: ' + ', '.join(vulnerability.get('fix_versions', [])))
    elif scanner == 'grype':
        for index, item in enumerate(raw['matches']):
            artifact, vulnerability = item.get('artifact', {}), item.get('vulnerability', {})
            name, version = artifact.get('name', ''), artifact.get('version', '')
            located = set()
            for location in artifact.get('locations', []):
                relative = _relative(root, location.get('path') or location.get('accessPath') or location.get('realPath'), virtual_root=True)
                if relative is None:
                    continue
                try:
                    for line in _manifest_lines(root, relative, name, version):
                        located.add((relative, line))
                except (ValueError, OSError, UnicodeError, RecursionError):
                    continue
            if not located:
                _warn(result, f'Omitted unlocated dependency {name}=={version}: {vulnerability.get("id", "")}; no exact manifest package/version match.')
            for path, line in sorted(located):
                _add(result, root, path, line, f'{vulnerability.get("id", "Advisory")} in {name} {version}',
                    vulnerability.get('id', ''), f'#/matches/{index}', severity=vulnerability.get('severity', 'info'),
                    category='dependency_cve', confidence=0.95,
                    explanation=vulnerability.get('description') or 'Grype database matched this package version; review applicability.',
                    remediation='Review advisory and upgrade to a compatible fixed version: ' + ', '.join(vulnerability.get('fix', {}).get('versions', [])))
        # Grype advisories carry lengthy descriptions/URLs per match. The full
        # payload is hundreds of KB and would push _finish() to drop every
        # finding. Keep a compact index keyed by the same raw_ref used above;
        # finding explanations already hold the human-readable advisory text.
        raw['matches'] = [{
            'artifact': {'name': (m.get('artifact') or {}).get('name', ''),
                         'version': (m.get('artifact') or {}).get('version', '')},
            'vulnerability': {'id': (m.get('vulnerability') or {}).get('id', ''),
                              'severity': (m.get('vulnerability') or {}).get('severity', '')},
        } for m in raw.get('matches', [])]


async def run_scanner(scanner: str, target: Path, ruleset: str = 'default', *,
                      binaries: dict[str, str] | None = None, timeout: int = 120,
                      offline: bool = True) -> dict:
    """Run a fixed local adapter; missing tools or offline databases stay unavailable."""
    result = _result(scanner)
    if scanner not in SCANNERS or ruleset not in RULESETS:
        result['status'] = 'error'
        _warn(result, 'Unknown scanner or ruleset; only the published enums are accepted.')
        return result
    if type(timeout) is not int or not 1 <= timeout <= 3600 or type(offline) is not bool:
        result['status'] = 'error'
        _warn(result, 'timeout must be an integer between 1 and 3600; offline must be boolean.')
        return result
    try:
        target = Path(target)
        if not target.is_absolute() or _is_link(target):
            raise ValueError('target must be an absolute, non-symlink snapshot directory')
        root = target.resolve(strict=True)
        if not root.is_dir():
            raise ValueError('target must be a snapshot directory')
        if scanner == 'patterns':
            return _finish(await _patterns(root, ruleset, result, timeout))
        if binaries is not None and not isinstance(binaries, dict):
            raise ValueError('binaries must be a registered executable map')
        registered = (binaries or {}).get(scanner)
        if not isinstance(registered, str) or not Path(registered).is_absolute():
            result['status'] = 'unavailable'
            _warn(result, 'Scanner has no registered absolute executable; PATH discovery is disabled.')
            return result
        if _inside(Path(registered), root):
            raise ValueError('Repository executable registrations are prohibited')
        binary = Path(registered).resolve(strict=True)
        if not binary.is_file() or _inside(binary, root):
            raise ValueError('Scanner executable must be a trusted file outside the snapshot')
        if os.name == 'nt' and binary.suffix.lower() != '.exe':
            raise ValueError('Windows scanner registrations must be .exe files, not shell scripts')
        if scanner == 'pip-audit' and offline:
            result['status'] = 'unavailable'
            _warn(result, 'pip-audit has no guaranteed offline advisory service; no process was started. Use a provisioned Grype DB for offline CVE review.')
            return result
        if scanner == 'semgrep':
            _warn(result, 'Semgrep uses bundled offline rules only: selected language-aware security checks plus explicit backdoor indicators; coverage is not exhaustive.')
            # Semgrep discovers ignore files itself. Fail closed if the caller
            # failed to remove them from the sanitized snapshot or its ancestors.
            _guard_semgrep_config(root)
        elif ruleset == 'backdoor':
            _warn(result, f'{scanner} has no backdoor-only preset; its fixed native scope is used.')
        if scanner == 'gosec':
            _warn(result, 'gosec package loading is fail-closed: compiler invocation, CGO, module downloads and toolchain updates are disabled. Missing type data may prevent scanning.')
        if scanner == 'grype':
            _warn(result, 'Grype updates are disabled; an existing local vulnerability DB is required. Only exact, located manifest package/version matches are reported.')
        pins = _pins(root, result) if scanner == 'pip-audit' else {}
        if scanner == 'pip-audit' and not pins:
            result['status'] = 'unavailable'
            _warn(result, 'No supported exact requirements pins; installed-environment and resolver audits are prohibited.')
            return _finish(result)
        with tempfile.TemporaryDirectory(prefix='localguard-scanner-') as directory:
            scratch = Path(directory)
            if _inside(scratch.resolve(), root):
                raise ValueError('Scanner scratch directory must be outside the snapshot')
            env = _environment(binary, scratch, root)
            if scanner == 'semgrep':
                configs = ['--config', str(RULE_DIR / 'backdoor.json')]
                if ruleset != 'backdoor':
                    configs += ['--config', str(RULE_DIR / 'security.json')]
                    # Curated offline rule pack maintained by the product,
                    # never loaded from the repository under audit (supply-chain
                    # risk: a hostile repo could ship rules that suppress or
                    # distort findings).
                    extended = RULE_DIR / 'security-extended.json'
                    if extended.is_file():
                        configs += ['--config', str(extended)]
                args = ['scan', *configs, '--json', '--oss-only',
                    '--metrics=off', '--disable-version-check', '--disable-nosem',
                    '--no-git-ignore', '--no-rewrite-rule-ids', '--jobs=1',
                    '--max-target-bytes', str(MAX_FILE_BYTES), str(root)]
            elif scanner == 'gitleaks':
                ignore = scratch / 'empty.ignore'
                ignore.write_text('', encoding='utf-8')
                args = ['dir', '--config', str(RULE_DIR / 'gitleaks.toml'), '--no-banner',
                    '--report-format=json', '--report-path=-', '--exit-code=0',
                    '--ignore-gitleaks-allow', '--gitleaks-ignore-path', str(ignore), str(root)]
            elif scanner == 'gosec':
                args = ['-fmt=json', '-stdout', '-no-fail', '-nosec=true', './...']
            elif scanner == 'cppcheck':
                args = ['--xml', '--xml-version=2', '--enable=warning,style,performance,portability',
                    '--error-exitcode=0', '--max-configs=1', str(root)]
            elif scanner == 'pip-audit':
                requirements = scratch / 'requirements.txt'
                requirements.write_text(''.join(f'{name}=={version}\n' for name, version in sorted(pins)), encoding='utf-8')
                args = ['--requirement', str(requirements), '--no-deps', '--disable-pip',
                        '--format=json', '--progress-spinner=off']
            else:
                args = ['dir:' + str(root), '--config', str(RULE_DIR / 'grype.yaml'), '--output', 'json']
            # Semgrep and grype emit verbose structured JSON (extra metadata
            # per match). A higher stream cap is safe: both are controlled
            # offline tools, and _finish() still enforces the tighter
            # MAX_RESULT_BYTES / MAX_FINDINGS limits on the normalized result.
            # Grype against a 3 GB advisory DB can produce ~800 KB of matches.
            stream_cap = 1024 * 1024 if scanner == 'grype' else (512 * 1024 if scanner == 'semgrep' else None)
            execution = await _execute([str(binary), *args], root, env, timeout,
                                       max_bytes=stream_cap)
        result['status'], result['truncated'] = execution['status'], result['truncated'] or execution['truncated']
        if execution['status'] != 'completed':
            _warn(result, 'Scanner timed out; its process tree was terminated.' if execution['status'] == 'timeout' else 'Scanner exceeded the combined streaming output limit; its process tree was terminated.')
            return _finish(result)
        diagnostic = execution['stderr'].decode('utf-8', errors='replace')
        if 'Traceback (most recent call last)' in diagnostic:
            diagnostic = next((line for line in reversed(text_lines(diagnostic)) if line.strip()), 'Scanner runtime failed')
        diagnostic = diagnostic[:1500]
        allowed_codes = (0, 1) if scanner in {'semgrep', 'gitleaks', 'gosec', 'pip-audit'} else (0,)
        if execution['returncode'] not in allowed_codes:
            result['status'] = 'error'
            _warn(result, f'Scanner exited with code {execution["returncode"]}. {diagnostic}')
            if scanner == 'grype' and re.search(r'(?i)(database|\bdb\b).*(not found|does not exist|unable|failed|expired|too old)|unable to (load|find).*database', diagnostic):
                result['status'] = 'unavailable'
        payload = execution['stderr'] if scanner == 'cppcheck' else execution['stdout']
        try:
            result['raw'] = _parse(scanner, payload)
            _normalize(scanner, root, result['raw'], result, pins)
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, ET.ParseError, RecursionError) as error:
            if result['status'] == 'completed':
                result['status'] = 'error'
            _warn(result, f'Invalid or unsupported {scanner} output: {error}. {diagnostic if scanner != "cppcheck" else ""}')
        if diagnostic.strip() and scanner != 'cppcheck' and result['status'] == 'completed':
            _warn(result, 'Scanner stderr: ' + diagnostic)
    except (FileNotFoundError, PermissionError) as error:
        result['status'] = 'unavailable'
        _warn(result, f'Target, executable, or bundled resource unavailable: {error}')
    except (OSError, ValueError, TypeError, RuntimeError) as error:
        result['status'] = 'error'
        _warn(result, f'Scanner could not run safely: {error}')
    return _finish(result)
