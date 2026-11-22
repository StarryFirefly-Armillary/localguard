from __future__ import annotations

import fnmatch
import hashlib
import os
from pathlib import Path, PureWindowsPath


class BoundaryError(ValueError):
    pass


IGNORED = {'.git', '.hg', '.svn', '.venv', 'venv', 'node_modules', '__pycache__',
           '.localguard', 'dist', 'build', 'vendor', '.idea', '.vscode'}


class PathPolicy:
    def __init__(self, roots: list[Path], max_bytes: int = 2_000_000):
        self.roots = roots
        self.max_bytes = max_bytes

    def resolve(self, value: str, *, directory: bool | None = None) -> Path:
        if '\x00' in value or '..' in value.replace('\\', '/').split('/'):
            raise BoundaryError('Path traversal is not allowed')
        path = Path(value)
        if not path.is_absolute():
            raise BoundaryError('Use an absolute local path')
        if os.name == 'nt' and (value.startswith(('\\\\', '//')) or ':' in value[2:]):
            raise BoundaryError('Network paths and alternate data streams are not allowed')
        try:
            real = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise BoundaryError('Target path does not exist or cannot be accessed') from exc
        if not any(real.is_relative_to(root) for root in self.roots):
            raise BoundaryError('Target is outside the configured allowed_roots')
        if directory is True and not real.is_dir():
            raise BoundaryError('Expected a directory')
        if directory is False and not real.is_file():
            raise BoundaryError('Expected a regular file')
        return real

    def git_metadata(self, root: Path):
        marker = root / '.git'
        if marker.is_file():
            if marker.stat().st_size > 4096:
                raise BoundaryError('Invalid Git metadata pointer')
            pointer = marker.read_text('utf-8').strip()
            if not pointer.startswith('gitdir: '):
                raise BoundaryError('Invalid Git metadata pointer')
            metadata = (root / pointer[8:]).resolve(strict=True)
        elif marker.is_dir():
            metadata = marker.resolve(strict=True)
        elif (root / 'HEAD').is_file() and (root / 'objects').is_dir() and (root / 'refs').is_dir():
            metadata = root
        else:
            raise BoundaryError('git_diff requires a Git repository root')
        metadata = self.resolve(str(metadata), directory=True)
        directories = [metadata]
        common = metadata / 'commondir'
        if common.exists():
            common = self.resolve(str(common), directory=False)
            if common.stat().st_size > 4096:
                raise BoundaryError('Invalid Git common-directory pointer')
            directories.append(self.resolve(str((metadata / common.read_text('utf-8').strip()).resolve()), directory=True))
        count = 0
        for directory in set(directories):
            config = directory / 'config'
            if config.exists():
                config = self.resolve(str(config), directory=False)
                if config.stat().st_size > 1_000_000:
                    raise BoundaryError('Git configuration exceeds the inspection limit')
                import re
                if re.search(r'(?im)^\s*\[\s*include', config.read_text('utf-8', errors='replace')):
                    raise BoundaryError('Git config includes are not allowed for isolated diff inspection')
            for base, dirs, files in os.walk(directory, followlinks=False):
                for name in dirs + files:
                    path = Path(base) / name
                    count += 1
                    if count > 100_000:
                        raise BoundaryError('Git metadata exceeds the inspection limit')
                    if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
                        raise BoundaryError('Linked Git metadata is not allowed')
                    self.resolve(str(path))
                alternate = Path(base) / 'alternates'
                if alternate.is_file() and alternate.stat().st_size:
                    raise BoundaryError('Git alternate object stores are not allowed')
        return metadata

    def read(self, value: str) -> tuple[Path, bytes, str]:
        real = self.resolve(value, directory=False)
        with real.open('rb') as stream:
            data = stream.read(self.max_bytes + 1)
        if len(data) > self.max_bytes:
            raise BoundaryError('File exceeds max_file_bytes; narrow the scan target')
        if b'\x00' in data[:8192]:
            raise BoundaryError('Binary file cannot be used as source evidence')
        if self.resolve(value) != real:
            raise BoundaryError('Path changed during read; retry view_file')
        return real, data, hashlib.sha256(data).hexdigest()

    def files(self, root: Path, max_files: int = 10_000, respect_gitignore: bool = True,
              exclude: list[str] | None = None):
        count = 0
        # Explicit exclusions always apply; .gitignore patterns are additive.
        patterns = [p.strip().rstrip('/') for p in (exclude or [])
                    if isinstance(p, str) and p.strip()]
        ignore = root / '.gitignore'
        if respect_gitignore and ignore.is_file() and not ignore.is_symlink() and ignore.stat().st_size < 65536:
            patterns += [s.strip() for s in ignore.read_text('utf-8', errors='replace').splitlines()
                         if s.strip() and not s.startswith(('#', '!'))]

        def excluded(rel: str) -> bool:
            for p in patterns:
                pattern = p.rstrip('/')
                # A directory pattern excludes the whole subtree (fixtures/,
                # tests, docs/...), a glob matches paths or leaf names.
                if rel == pattern or rel.startswith(pattern + '/'):
                    return True
                if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel.rsplit('/', 1)[-1], pattern):
                    return True
            return False

        for base, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in IGNORED and not (Path(base) / d).is_symlink()
                             and not excluded((Path(base) / d).relative_to(root).as_posix()))
            for name in sorted(files):
                path = Path(base) / name
                rel = path.relative_to(root).as_posix()
                if path.is_symlink() or excluded(rel):
                    continue
                try:
                    self.resolve(str(path), directory=False)
                except BoundaryError:
                    continue
                count += 1
                if count > max_files:
                    raise BoundaryError('Repository exceeds max_files; select a smaller target')
                yield path


def safe_relative(value: str) -> Path:
    normal = value.replace('\\', '/')
    if Path(normal).is_absolute() or PureWindowsPath(value).is_absolute() or '..' in normal.split('/'):
        raise BoundaryError('Scanner location must be relative to the isolated target')
    return Path(normal)
