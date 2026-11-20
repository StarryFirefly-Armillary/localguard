from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    allowed_roots: list[Path] = field(default_factory=lambda: [Path.cwd().resolve()])
    data_dir: Path = field(default_factory=lambda: Path.home() / '.localguard')
    offline: bool = True
    scanner_timeout: int = 120
    max_output_bytes: int = 200_000
    max_file_bytes: int = 2_000_000
    max_repo_bytes: int = 200_000_000
    max_files: int = 10_000
    max_prompt_files: int = 60
    max_prompt_chars: int = 24_000
    model_tier: str = '8gb'
    keep_model_resident: bool = False
    model_endpoint: str = 'http://127.0.0.1:1234/v1'
    model_name: str = 'qwen3.5-4b'
    model_binary: str = ''
    model_library_dirs: list[str] = field(default_factory=list)
    model_path: str = ''
    model_4gb_path: str = ''
    mmproj_path: str = ''
    model_context: int = 4096
    git_hosts: list[str] = field(default_factory=lambda: ['github.com'])
    binaries: dict[str, str] = field(default_factory=dict)
    grammars: dict[str, str] = field(default_factory=dict)
    port: int = 8765

    def __post_init__(self):
        self.allowed_roots = [Path(p).resolve(strict=True) for p in self.allowed_roots]
        self.data_dir = Path(self.data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        for name in ('semgrep', 'gitleaks', 'gosec', 'cppcheck', 'pip-audit', 'grype', 'git'):
            binary = self.binaries.get(name)
            if not binary:
                for entry in os.get_exec_path():
                    directory = Path(entry)
                    if not directory.is_absolute():
                        continue
                    directory = directory.resolve()
                    if directory == Path.cwd().resolve() or any(directory.is_relative_to(root) for root in self.allowed_roots):
                        continue
                    candidate = directory / (name + '.exe' if os.name == 'nt' else name)
                    if candidate.is_file() and shutil.which(str(candidate)):
                        binary = str(candidate)
                        break
            if binary:
                self.binaries[name] = str(Path(binary).resolve(strict=True))
        if self.max_output_bytes < 4096 or self.max_output_bytes > 200_000:
            raise ValueError('max_output_bytes must be between 4096 and 200000')
        if not 1 <= self.max_prompt_files <= 60:
            raise ValueError('max_prompt_files must be between 1 and 60')
        if self.model_tier not in ('rules', '4gb', '8gb'):
            raise ValueError('Invalid model_tier')

    @classmethod
    def load(cls, path: str | None = None):
        path = path or os.environ.get('LOCALGUARD_CONFIG')
        values = json.loads(Path(path).read_text('utf-8')) if path else {}
        if roots := os.environ.get('LOCALGUARD_ROOTS'):
            values['allowed_roots'] = roots.split(os.pathsep)
        if data := os.environ.get('LOCALGUARD_DATA_DIR'):
            values['data_dir'] = data
        return cls(**values)
