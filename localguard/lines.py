from __future__ import annotations


def text_lines(text: str) -> list[str]:
    if not text:
        return []
    lines = text.split('\n')
    # Only CR immediately before LF belongs to the line terminator.
    for index in range(len(lines) - 1):
        lines[index] = lines[index].removesuffix('\r')
    if not lines[-1]:
        lines.pop()
    return lines


def source_lines(data: bytes) -> list[str]:
    return text_lines(data.decode('utf-8-sig', errors='replace'))
