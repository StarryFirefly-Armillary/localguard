import asyncio
import hashlib
from pathlib import Path
from unittest.mock import Mock

import pytest

from localguard.parser import SourceParser
from localguard.reporting import EvidenceError, Validator, from_finding
from localguard import scanners


SEPARATORS = ('\u2028', '\u2029', '\x85', '\v', '\f', '\r', '\x1c', '\x1d', '\x1e')


@pytest.mark.parametrize('data, expected', [
    (b'', []), (b'\xef\xbb\xbf', []), (b'\n', ['']),
    (b'\r\n', ['']), (b'one\n', ['one']), (b'one\n\n', ['one', '']),
    (b'one\r\ntwo\r', ['one', 'two\r']),
    (b'one\r\r\n', ['one\r']), (b'\xef\xbb\xbfhello\n', ['hello']),
    (b'\xff\n', ['\ufffd']),
    ('a\u2028b\v\fc\rd\U0001f600\nend'.encode(), ['a\u2028b\v\fc\rd\U0001f600', 'end']),
])
def test_shared_line_helper(data, expected):
    from localguard.lines import source_lines, text_lines
    assert source_lines(data) == expected
    assert text_lines(data.decode('utf-8-sig', errors='replace')) == expected


@pytest.mark.parametrize('separator', SEPARATORS)
@pytest.mark.parametrize('newline', ('\n', '\r\n'))
@pytest.mark.parametrize('bom', ('', '\ufeff'))
def test_parser_lf_rows_and_codepoint_tokens(separator, newline, bom):
    comment = '# \U0001f600' + separator + 'auth_bypass = True'
    statement = 'value = "\U0001f600"; pass'
    data = (bom + comment + newline + statement + newline).encode()
    parser = SourceParser()
    view = parser.slice(Path('probe.py'), data, 1, 99)
    assert view['total_lines'] == 2
    assert [(row['line'], row['text']) for row in view['lines']] == [(1, comment), (2, statement)]
    assert not view['parse_error']
    assert view['lines'][0]['tokens'] == [{'start': 0, 'end': len(comment), 'type': 'comment'}]
    for row in view['lines']:
        for token in row['tokens']:
            assert 0 <= token['start'] < token['end'] <= len(row['text'])
    tokens = view['lines'][1]['tokens']
    start = statement.index('pass')
    assert {'start': start, 'end': start + 4, 'type': 'pass'} in tokens
    assert parser.slice(Path('probe.py'), data, 2, 2)['lines'] == view['lines'][1:]
    summary = parser.summary(Path('probe.py'), data, 'pass_statement')
    assert summary['nodes'] == [{'type': 'pass_statement', 'start_line': 2, 'end_line': 2}]


@pytest.mark.parametrize('newline', ('\n', '\r\n'))
@pytest.mark.parametrize('bom', ('', '\ufeff'))
def test_multiline_ast_leaf_clips_crlf_without_shifting_columns(newline, bom):
    lines = ['/* \U0001f600\u2028still comment', 'second\v\f\rpart */', 'const value = "\U0001f600";']
    data = (bom + newline.join(lines) + newline).encode()
    view = SourceParser().slice(Path('probe.js'), data, 1, 99)
    assert [row['text'] for row in view['lines']] == lines
    assert not view['parse_error']
    for row in view['lines'][:2]:
        assert row['tokens'] == [{'start': 0, 'end': len(row['text']), 'type': 'comment'}]
    assert {'start': len(lines[2]) - 1, 'end': len(lines[2]), 'type': ';'} in view['lines'][2]['tokens']


@pytest.mark.parametrize('data, expected', [(b'', []), (b'\xef\xbb\xbf', []), (b'\n', ['']), (b'pass\n', ['pass']), (b'pass\r\n\r\n', ['pass', ''])])
def test_parser_empty_and_trailing_lf(data, expected):
    parser = SourceParser()
    view = parser.slice(Path('probe.py'), data, 1, 99)
    assert view['total_lines'] == len(expected)
    assert [row['text'] for row in view['lines']] == expected
    assert view['end_line'] == len(expected)
    with pytest.raises(ValueError, match='Invalid line range'):
        parser.slice(Path('probe.py'), data, len(expected) + 2, 99)


@pytest.mark.parametrize('separator', SEPARATORS)
def test_patterns_do_not_scan_phantom_comment_lines(tmp_path, separator):
    path = tmp_path / 'comment.py'
    path.write_bytes(('#' + separator + 'auth_bypass = True\npass').encode())
    result = asyncio.run(scanners.run_scanner('patterns', tmp_path))
    assert result['status'] == 'completed'
    assert result['findings'] == []
    assert result['raw']['matches'] == []
    path.write_bytes(('\ufeff#' + separator + 'auth_bypass = True\r\nauth_bypass = True\r\n').encode())
    result = asyncio.run(scanners.run_scanner('patterns', tmp_path))
    assert [(f['line'], f['rule_id']) for f in result['findings']] == [(2, 'patterns.auth-bypass')]
    assert [m['line'] for m in result['raw']['matches']] == [2]


@pytest.mark.parametrize('separator', SEPARATORS)
def test_raw_scanner_locations_reject_phantom_rows(tmp_path, separator):
    (tmp_path / 'source.py').write_bytes(('# note' + separator + 'still comment\npass\n').encode())
    result = scanners._result('semgrep')
    raw = {'results': [{'path': 'source.py', 'start': {'line': line}, 'check_id': str(line)} for line in (2, 3)]}
    scanners._normalize('semgrep', tmp_path, raw, result, {})
    assert [(f['line'], f['rule_id']) for f in result['findings']] == [(2, '2')]
    assert any('unlocated' in warning for warning in result['warnings'])


@pytest.mark.parametrize('separator', SEPARATORS)
def test_requirement_comment_and_dependency_locations(tmp_path, separator):
    (tmp_path / 'requirements.txt').write_bytes(('\ufeff# note' + separator + 'fake==9.0\r\nreal==1.2.3\r\n').encode())
    assert scanners._pins(tmp_path, scanners._result('pip-audit')) == {('real', '1.2.3'): [('requirements.txt', 2)]}
    assert scanners._manifest_lines(tmp_path, 'requirements.txt', 'fake', '9.0') == []
    assert scanners._manifest_lines(tmp_path, 'requirements.txt', 'real', '1.2.3') == [2]


@pytest.mark.parametrize('newline', ('\n', '\r\n'))
def test_json_scalars_and_grype_share_lf_index(tmp_path, newline):
    text = '{"description":"a\u2028b\u2029c\\nfake 1.2.3",' + newline + '"dependencies":{"real":"1.2.3"}}' + newline
    (tmp_path / 'package.json').write_bytes(('\ufeff' + text).encode())
    assert scanners._json_scalars(text)[('dependencies', 'real')] == ('1.2.3', 2)
    assert scanners._manifest_lines(tmp_path, 'package.json', 'fake', '1.2.3') == []
    assert scanners._manifest_lines(tmp_path, 'package.json', 'real', '1.2.3') == [2]
    raw = {'matches': [{'artifact': {'name': 'real', 'version': '1.2.3', 'locations': [{'path': 'package.json'}]}, 'vulnerability': {'id': 'TEST'}}]}
    result = scanners._result('grype')
    scanners._normalize('grype', tmp_path, raw, result, {})
    assert [(f['path'], f['line']) for f in result['findings']] == [('package.json', 2)]
    view = SourceParser().slice(tmp_path / 'package.json', ('\ufeff' + text).encode(), 2, 2)
    assert view['lines'][0]['text'] == '"dependencies":{"real":"1.2.3"}}'


@pytest.mark.parametrize('name, text, package, line', [
    ('Cargo.lock', '# a\u2028b\n[[package]]\nname = "real"\nversion = "1.2.3"\n', 'real', 4),
    ('go.mod', '// a\u2028b\nrequire example.invalid/real v1.2.3\n', 'example.invalid/real', 2),
])
def test_other_manifest_locations(tmp_path, name, text, package, line):
    (tmp_path / name).write_bytes(text.encode())
    assert scanners._manifest_lines(tmp_path, name, package, '1.2.3') == [line]


@pytest.mark.parametrize('separator', SEPARATORS)
def test_validator_hashes_physical_source_line(tmp_path, separator):
    path = tmp_path / 'source.py'
    first = '# note' + separator + 'auth_bypass = True'
    data = ('\ufeff' + first + '\r\npass\r\n').encode()
    digest = hashlib.sha256(data).hexdigest()
    store, policy = Mock(), Mock()
    store.latest.return_value = {'hash': digest, 'start': 1, 'end': 3}
    policy.resolve.return_value = path
    policy.read.return_value = path, data, digest
    validator = Validator(store, policy)
    def issue(line, text):
        return from_finding({'path': path.name, 'line': line, 'title': 'test', 'severity': 'high', 'category': 'other', 'tool': 'patterns'}, text)
    for line, text in ((1, first), (2, 'pass')):
        assert validator.validate(issue(line, text), 'session', tmp_path)['locations'][0]['stale'] is False
    for line, text in ((2, 'auth_bypass = True'), (3, 'pass')):
        with pytest.raises(EvidenceError, match='snippet_hash'):
            validator.validate(issue(line, text), 'session', tmp_path)
