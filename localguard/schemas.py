from copy import deepcopy

SCANNERS = ['patterns', 'semgrep', 'gitleaks', 'gosec', 'cppcheck', 'pip-audit', 'grype']
RULESETS = ['default', 'security', 'backdoor']


def obj(properties, required=(), extra=False):
    return {'type': 'object', 'properties': properties, 'required': list(required), 'additionalProperties': extra}


def string(**kw):
    return {'type': 'string', **kw}


def integer(low=0, high=10_000_000):
    return {'type': 'integer', 'minimum': low, 'maximum': high}


def array(items, maximum=10_000):
    return {'type': 'array', 'items': items, 'maxItems': maximum}


BOOL = {'type': 'boolean'}
PATH = string(minLength=1, maxLength=4096, pattern=r'^(?:[A-Za-z]:[\\/]|/)[^\x00]*$')
TARGET = string(minLength=1, maxLength=4096, pattern=r'^(?:(?:[A-Za-z]:[\\/]|/)[^\x00]*|https://[a-zA-Z0-9.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?)$')
ID = string(pattern='^[a-f0-9]{32}$')
HASH = string(pattern='^[a-f0-9]{64}$')
LOCATION = obj({'path': string(minLength=1), 'line': integer(1), 'snippet_hash': HASH, 'stale': BOOL}, ['path', 'line', 'snippet_hash'])
EVIDENCE = obj({'tool': string(), 'raw_ref': string(), 'range': array(integer(1), 2)}, ['tool'])
ISSUE = obj({
    'id': string(), 'title': string(), 'severity': string(enum=['critical', 'high', 'medium', 'low', 'info']),
    'category': string(enum=['credential_leak', 'injection', 'backdoor', 'dependency_cve', 'misconfig', 'other']),
    'cwe': string(), 'confidence': {'type': 'number', 'minimum': 0, 'maximum': 1},
    'locations': {**array(LOCATION), 'minItems': 1}, 'evidence': {**array(EVIDENCE), 'minItems': 1},
    'explanation': string(), 'remediation': string(), 'needs_human_review': BOOL,
    'review': string(enum=['unreviewed', 'confirmed', 'false_positive']),
    'triage': obj({'verdict': string(enum=['likely_true', 'likely_false', 'uncertain']),
                   'confidence': {'type': 'number', 'minimum': 0, 'maximum': 1},
                   'reason': string(), 'tier': string(), 'overridden': BOOL},
                  ['verdict', 'confidence', 'reason', 'tier']),
    'feedback': obj({'rule_confirmed': integer(), 'rule_false_positive': integer()},
                    ['rule_confirmed', 'rule_false_positive'])
}, ['id', 'title', 'severity', 'category', 'cwe', 'confidence', 'locations', 'evidence', 'explanation', 'remediation', 'needs_human_review'])
STATUS = obj({
    'audit_id': ID, 'status': string(enum=['queued', 'running', 'completed', 'failed', 'cancelled']),
    'queue_position': integer(), 'progress': integer(0, 100), 'completed_modules': array(string()),
    'issues': array(ISSUE), 'warnings': array(string()), 'target': string(), 'root': string(),
    'error': string(), 'truncated': BOOL, 'total_issues': integer(), 'next_offset': integer(),
    'coverage': obj({}, extra=True), 'model_tier': string(),
    'warning_explanations': obj({}, extra=True), 'cache_hits': array(string()),
    'baseline': obj({'baseline_audit_id': string(), 'added': array(string()),
                     'resolved': array(string()), 'persisted': integer()},
                    ['baseline_audit_id', 'added', 'resolved', 'persisted']),
}, ['audit_id', 'status', 'queue_position', 'progress', 'completed_modules', 'issues', 'warnings', 'truncated'])


def tool(description, inputs, outputs, exposed=True):
    return {'description': description, 'inputSchema': inputs, 'outputSchema': outputs, 'exposed': exposed}


TOOLS = {
    'view_file': tool(
        'Read an allowed local UTF-8 source slice with real 1-indexed lines and shared tree-sitter tokens. Use an absolute path, e.g. C:/work/app.py, start_line=40, end_line=55. Returns lines, AST tokens, file hash and actual range; updates this session\'s latest evidence read. Maximum 400 lines and configured file size. No execution; out-of-root or binary files are rejected.',
        obj({'path': PATH, 'start_line': integer(1), 'end_line': integer(1)}, ['path']),
        obj({'path': string(), 'start_line': integer(1), 'end_line': integer(), 'total_lines': integer(), 'hash': HASH,
             'lines': array(obj({'line': integer(1), 'text': string(), 'tokens': array(obj({'start': integer(), 'end': integer(), 'type': string()}, ['start','end','type']))}, ['line','text','tokens']),400),
             'language': string(), 'parse_error': BOOL, 'truncated': BOOL}, ['path','start_line','end_line','total_lines','hash','lines','language','parse_error','truncated'])),
    'list_tree': tool(
        'List an allowlisted absolute directory, e.g. path=C:/work, max_depth=3. Returns sorted entries with relative path, name, type and depth. Skips symlinks, build/dependency folders and simple .gitignore patterns; caps at 3000 entries. Does not read file contents.',
        obj({'path': PATH, 'max_depth': integer(1,12)}, ['path']),
        obj({'entries': array(obj({'path':string(),'name':string(),'type':string(enum=['file','directory']),'depth':integer()}, ['path','name','type','depth']),3000),'truncated':BOOL},['entries','truncated'])),
    'get_ast': tool(
        'Summarize tree-sitter AST nodes with real start/end lines for an absolute source path, e.g. path=C:/work/app.py, node_type=function_definition. Returns language, parse errors and nodes; no inferred line numbers. Grammars are loaded from installed local packages and declarative extension mapping. Unsupported/missing grammars return an actionable error. Caps at 1000 nodes.',
        obj({'path':PATH,'node_type':string(maxLength=100,pattern='^[a-zA-Z0-9_]+$')},['path']),
        obj({'path':string(),'language':string(),'nodes':array(obj({'type':string(),'start_line':integer(1),'end_line':integer(1)},['type','start_line','end_line']),1000),'parse_error':BOOL,'truncated':BOOL},['path','language','nodes','parse_error','truncated'])),
    'run_scanner': tool(
        'Execute exactly one registered deterministic scanner on an allowlisted absolute directory. Example scanner=semgrep,target=C:/work,ruleset=backdoor. Returns scanner status, normalized findings, original raw output, warnings and truncation. Runs against a sanitized snapshot, never builds source or accepts custom configs/flags. Missing binaries or offline CVE data are explicitly unavailable, not a clean result. Patterns is a limited bundled rule scanner, not a substitute for full analyzers.',
        obj({'scanner':string(enum=SCANNERS),'target':PATH,'ruleset':string(enum=RULESETS)},['scanner','target']),
        obj({'scanner':string(enum=SCANNERS),'status':string(enum=['completed','unavailable','error','timeout']),'findings':array(obj({},extra=True)),'raw':{},'warnings':array(string()),'truncated':BOOL,'dropped_count':integer(0)},['scanner','status','findings','warnings','truncated'])),
    'git_diff': tool(
        'Read a bounded zero-context commit-to-commit Git diff without external diff drivers, text converters, filters or hooks. Use an allowed absolute repository root (including bare history) and simple refs, e.g. base=HEAD~1, head=HEAD. Returns diff, decoded UTF-8 paths, destination line ranges and resolved base_commit/head_commit IDs. Deletions have no destination ranges; uncommitted changes are excluded. Both revisions must exist locally; shallow history may require a complete local clone. No automatic fetch; non-UTF-8 paths and unsafe metadata are rejected.',
        obj({'repo':PATH,'base':string(pattern=r'^[A-Za-z0-9][A-Za-z0-9_./~^+-]{0,159}$'),'head':string(pattern=r'^[A-Za-z0-9][A-Za-z0-9_./~^+-]{0,159}$')},['repo']),
        obj({'diff':string(),'changes':array(obj({'path':string(),'start_line':integer(1),'end_line':integer(1)},['path','start_line','end_line'])),
             'base_commit':string(pattern=r'^(?:[a-f0-9]{40}|[a-f0-9]{64})$'),'head_commit':string(pattern=r'^(?:[a-f0-9]{40}|[a-f0-9]{64})$'),
             'truncated':BOOL},['diff','changes','base_commit','head_commit','truncated'])),
    'audit_repository': tool(
        'Queue an asynchronous security audit; immediately returns audit_id/status=queued and an empty issues array. Example target=C:/work,depth=standard,scanners=[patterns,semgrep],include_dependencies=true. Absolute allowlisted paths or allowlisted HTTPS Git URLs only (Git retrieval disabled in offline mode). Poll get_audit_status for validated issues, progress, coverage and queue_position. Form pipeline is deterministic; conversational selection uses local tools only. Unavailable scanners are reported, never hidden. No repository code is executed. auto_exclude defaults true and skips conventional test/fixture/generated directories, self-declared inert fixtures and non-source artifacts across ecosystems (reasons reported in warnings); set false to review everything. exclude_paths additionally skips matching relative directories/files; additive to .gitignore. model_triage defaults true: when a local model tier is active, the model additionally labels each finding likely_true/likely_false/uncertain with a reason for advisory reordering; it never removes findings or changes severity, humans can override, every verdict is logged. resource_estimate optionally supplies scheduling hints, not permission to exceed host limits.',
        obj({'target':TARGET,'depth':string(enum=['quick','standard','deep']),'scanners':{**array(string(enum=SCANNERS),7),'uniqueItems':True,'minItems':1},'include_dependencies':BOOL,'incremental':BOOL,
             'base':string(pattern=r'^[A-Za-z0-9][A-Za-z0-9_./~^+-]{0,159}$'),'head':string(pattern=r'^[A-Za-z0-9][A-Za-z0-9_./~^+-]{0,159}$'),
             'model_tier':string(enum=['rules','4gb','8gb']),
             'exclude_paths':{**array(string(minLength=1,maxLength=300,pattern=r'^[A-Za-z0-9_*?./\\-]+$'),100),'uniqueItems':True},
             'auto_exclude':BOOL,'model_triage':BOOL,
             'resource_estimate':obj({'ram_mb':integer(0,32768),'vram_mb':integer(0,8192)},[])},['target']),deepcopy(STATUS)),
    'get_audit_status': tool(
        'Poll an audit owned by this client session. Example audit_id=32-character lowercase hex returned by audit_repository,wait_seconds=2,offset=0,limit=100. Returns status, queue_position, 0..100 progress, completed modules, coverage warnings and validated issues identical to the UI protocol. wait_seconds is bounded 0..30. Large reports are paginated; truncated=true and next_offset indicate remaining issues. Stale locations are flagged if the source changed since evidence was read.',
        obj({'audit_id':ID,'wait_seconds':integer(0,30),'offset':integer(),'limit':integer(1,200)},['audit_id']),deepcopy(STATUS)),
    'cancel_audit': tool(
        'Request cancellation of a running or queued audit owned by this client session. Example audit_id=32-character lowercase hex. Stops the active scanner subprocess and marks the audit cancelled; a completed/failed audit is returned unchanged. Only the owning session can cancel its own audit. Returns the audit status with status=cancelled.',
        obj({'audit_id': ID}, ['audit_id']), deepcopy(STATUS)),
    'list_audits': tool(
        'List the most recent audits owned by this client session, newest first, for reconnecting after a page reload. Example limit=10. Returns lightweight summaries (audit_id, status, target, progress, issue counts) without full findings; call get_audit_status for a specific audit to retrieve validated issues.',
        obj({'limit': integer(1, 50)}, []),
        obj({'audits': array(obj({'audit_id': ID, 'status': string(), 'target': string(),
                                  'progress': integer(), 'issue_count': integer(), 'created': integer(0, 2000000000)},
                                 ['audit_id', 'status', 'target', 'progress', 'issue_count']), 50)},
            ['audits'])),
    'clone_repository': tool(
        'Explicitly fetch an allowlisted HTTPS Git repository into a private local directory for auditing. Example url=https://github.com/org/repo. This is the ONLY network action; the audit itself stays offline. The bundled UI requires explicit user confirmation in a dialog; MCP tool calls are non-interactive and rely on the host allowlist, no embedded credentials/query/port/path traversal, --depth 2, no submodules, no hooks, no external diff/conv drivers, and isolation under the private state directory. Accepts only HTTPS and a configured git_hosts hostname. Returns a local absolute path to pass to audit_repository; the path is added to this worker allowlist. Cloning is disabled when no Git binary is configured.',
        obj({'url':string(minLength=1,maxLength=1000,pattern=r'^https://[a-zA-Z0-9.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?$')},['url']),
        obj({'path':PATH,'url':string(),'cloned':BOOL},['path','url','cloned'])),
    'analyze_image': tool(
        'Optional local vision assistance for an architecture diagram or terminal screenshot. Example image_path=C:/work/diagram.png,question=Summarize trust boundaries. Returns an untrusted auxiliary description, never security issues or verified code locations. Requires configured local multimodal Qwen model/projector and sufficient memory; rules tier has no image understanding. Allowed local PNG/JPEG/WebP only, maximum 8MB; no uploads to external providers.',
        obj({'image_path':PATH,'question':string(minLength=1,maxLength=2000),'model_tier':string(enum=['rules','4gb','8gb'])},['image_path','question']),
        obj({'description':string(),'auxiliary':BOOL,'truncated':BOOL},['description','auxiliary','truncated'])),
    'rank_and_report': tool(
        'Internal only: validate every proposed location against the latest same-session view_file read, reject unread/out-of-range/stale locations, de-duplicate and sort deterministic findings. No model-authored locations bypass this gate.',
        obj({'issues':array(ISSUE)},['issues']),obj({'issues':array(ISSUE),'truncated':BOOL},['issues','truncated']),False)
}
