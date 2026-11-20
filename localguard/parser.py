from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from .lines import source_lines

GRAMMARS = {'.py':'python','.js':'javascript','.jsx':'javascript','.mjs':'javascript','.cjs':'javascript',
            '.ts':'typescript','.tsx':'tsx','.java':'java','.go':'go','.rs':'rust','.c':'c','.h':'c',
            '.cpp':'cpp','.cc':'cpp','.cxx':'cpp','.hpp':'cpp','.php':'php','.rb':'ruby','.sol':'solidity'}


class SourceParser:
    def __init__(self, grammars=None):
        self.grammars = GRAMMARS | (grammars or {})

    @lru_cache(maxsize=16)
    def parse(self, language: str, data: bytes):
        try:
            from tree_sitter_language_pack import get_parser
        except ImportError as exc:
            raise ValueError('tree-sitter grammars are not installed. Install the packaged offline dependencies.') from exc
        try:
            return get_parser(language).parse(data)
        except (LookupError, ValueError, RuntimeError) as exc:
            raise ValueError(f'Local grammar unavailable: {language}') from exc

    def source(self, path: Path, data: bytes):
        language = self.grammars.get(path.suffix.lower(),'')
        tree = self.parse(language,data) if language else None
        return language, tree

    def summary(self, path: Path, data: bytes, node_type=None):
        language, tree = self.source(path,data)
        if not tree:
            raise ValueError('Unsupported extension; configure an installed grammar in grammars')
        nodes = []
        stack = [tree.root_node]
        visited = 0
        while stack and len(nodes)<1000 and visited<100_000:
            node = stack.pop()
            visited += 1
            if node.is_named and (not node_type or node.type == node_type):
                nodes.append({'type':node.type,'start_line':node.start_point.row+1,'end_line':node.end_point.row+1})
            stack.extend(reversed(node.children))
        return {'path':str(path),'language':language,'nodes':nodes,'parse_error':tree.root_node.has_error,'truncated':bool(stack)}

    def slice(self, path: Path, data: bytes, start: int, end: int):
        text_lines = source_lines(data)
        if start < 1 or start > max(len(text_lines),1) or end < start:
            raise ValueError('Invalid line range; start_line must exist and end_line must be >= start_line')
        end = min(end,len(text_lines),start+399)
        rows = [{'line':i+1,'text':text_lines[i],'tokens':[]} for i in range(start-1,end)]
        language, tree = self.source(path,data)
        if tree:
            byte_lines = data.split(b'\n')
            stack = [tree.root_node]
            visited = 0
            while stack and visited < 100_000:
                node = stack.pop()
                visited += 1
                a,b = node.start_point,node.end_point
                if a.row >= end or b.row < start-1:
                    continue
                if not node.children:
                    for row in range(max(start-1,a.row),min(end-1,b.row)+1):
                        raw = byte_lines[row]
                        left = a.column if row==a.row else 0
                        right = b.column if row==b.row else len(raw)
                        encoding = 'utf-8-sig' if row == 0 else 'utf-8'
                        width = len(text_lines[row])
                        begin = min(width, len(raw[:left].decode(encoding,errors='replace')))
                        finish = min(width, len(raw[:right].decode(encoding,errors='replace')))
                        if finish > begin:
                            rows[row-start+1]['tokens'].append({'start':begin,'end':finish,'type':node.type})
                else:
                    stack.extend(reversed(node.children))
        return {'path':str(path),'start_line':start,'end_line':end,'total_lines':len(text_lines),
                'lines':rows,'language':language,'parse_error':bool(tree and tree.root_node.has_error),'truncated':end<len(text_lines)}
