from __future__ import annotations

import os
from pathlib import Path

from .scanners import _execute


def clean_environment():
    allowed = ('SYSTEMROOT','WINDIR','TEMP','TMP','PATHEXT','COMSPEC','LANG','LC_ALL')
    env = {k:v for k,v in os.environ.items() if k.upper() in allowed}
    env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=os.devnull,GIT_TERMINAL_PROMPT='0',
               GIT_OPTIONAL_LOCKS='0',GIT_LFS_SKIP_SMUDGE='1',PYTHONNOUSERSITE='1')
    return env


async def run(command: list[str], cwd: Path, timeout=60, max_bytes=2_000_000):
    result = await _execute(command, cwd, clean_environment(), timeout, max_bytes=max_bytes)
    if result['truncated']:
        raise ValueError('Process output exceeded the safe limit; narrow the target')
    if result['status'] == 'timeout':
        raise TimeoutError('Process timed out')
    return result['returncode'], result['stdout'], result['stderr']
