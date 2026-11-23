from __future__ import annotations

import base64
from contextlib import asynccontextmanager
import json
from pathlib import Path
import secrets
import uuid
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from jsonschema import Draft202012Validator, ValidationError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import Config
from .model import ModelUnavailable
from .registry import ToolRegistry
from .reporting import export_report
from .schemas import TOOLS


CHAT_INPUT = Draft202012Validator({
    'type': 'object', 'additionalProperties': False, 'required': ['message', 'target'],
    'properties': {
        'message': {'type': 'string', 'minLength': 1, 'maxLength': 8000},
        'target': TOOLS['audit_repository']['inputSchema']['properties']['target'],
        'model_tier': TOOLS['audit_repository']['inputSchema']['properties']['model_tier'],
        'history': {'type': 'array', 'maxItems': 12, 'items': {
            'type': 'object', 'additionalProperties': False, 'required': ['role', 'content'],
            'properties': {'role': {'enum': ['user', 'assistant']},
                           'content': {'type': 'string', 'maxLength': 4000}},
        }},
    },
})
HISTORY_BUDGET = 16000


def create_app(config: Config | None = None):
    registry = ToolRegistry(config or Config.load())
    sessions = {}
    @asynccontextmanager
    async def lifespan(app):
        registry.engine.start()
        yield
        await registry.close()
    app = FastAPI(title='LocalGuard',docs_url=None,redoc_url=None,openapi_url=None,lifespan=lifespan)
    app.state.registry = registry
    app.add_middleware(TrustedHostMiddleware,allowed_hosts=['localhost','127.0.0.1','testserver'])

    @app.middleware('http')
    async def security(request, call_next):
        if request.method=='POST':
            origin = request.headers.get('origin')
            if origin and (urlsplit(origin).hostname not in ('localhost','127.0.0.1','testserver') or urlsplit(origin).netloc!=request.headers.get('host')):
                return JSONResponse({'error':'Cross-origin request rejected'},403)
            sid = request.cookies.get('localguard_session','')
            token = request.headers.get('x-csrf-token','')
            if sid not in sessions or not secrets.compare_digest(token,sessions[sid]):
                return JSONResponse({'error':'Invalid local session or CSRF token; reload the page'},403)
            try:
                size = int(request.headers.get('content-length','0'))
            except ValueError:
                return JSONResponse({'error':'Invalid content length'},400)
            if size>12_000_000:
                return JSONResponse({'error':'Request exceeds the 12MB limit'},413)
            if request.headers.get('content-type','').split(';')[0]!='application/json':
                return JSONResponse({'error':'Use application/json'},415)
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body)>12_000_000:
                    return JSONResponse({'error':'Request exceeds the 12MB limit'},413)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers.update({'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                                 'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Cache-Control':'no-store'})
        return response

    def session(request):
        sid = request.cookies.get('localguard_session','')
        if sid not in sessions:
            raise ValueError('Local session expired; reload the page')
        return sid

    @app.exception_handler(ValueError)
    @app.exception_handler(ModelUnavailable)
    async def invalid(request, exc):
        return JSONResponse({'isError':True,'error':str(exc)[:1500],'data':{}},400)

    @app.get('/api/bootstrap')
    async def bootstrap(request: Request):
        sid = request.cookies.get('localguard_session','')
        if sid not in sessions:
            sid = uuid.uuid4().hex
            sessions[sid] = secrets.token_urlsafe(32)
        response = JSONResponse({'session_id':sid,'csrf_token':sessions[sid],
            'config':{'allowed_roots':[str(r) for r in registry.config.allowed_roots],
                      'scanners':['patterns',*sorted(s for s in registry.config.binaries if s!='git')],
                      'scanner_availability':{s:s=='patterns' or s in registry.config.binaries for s in ('patterns','semgrep','gitleaks','gosec','cppcheck','pip-audit','grype')},
                      'model_tier':registry.config.model_tier,'offline':registry.config.offline},'tools':registry.describe()})
        response.set_cookie('localguard_session',sid,httponly=True,samesite='strict')
        return response

    @app.post('/api/tools/{name}')
    async def tools(name: str, request: Request):
        arguments = await request.json()
        if not isinstance(arguments,dict):
            raise ValueError('Tool arguments must be an object')
        return await registry.call(name,arguments,session(request),'LocalGuard UI')

    @app.post('/api/review')
    async def review(request: Request):
        data = await request.json()
        registry.store.review(data['audit_id'],session(request),data['issue_id'],data['decision'])
        return {'ok':True}

    @app.get('/api/feedback-stats')
    async def feedback_stats(request: Request):
        # Advisory quality metrics from past human reviews. No findings are
        # suppressed by these numbers; they only inform the user.
        return registry.store.triage_accuracy()

    @app.get('/api/audits/{audit_id}/logs')
    async def audit_logs(audit_id: str, request: Request, since: int = 0, limit: int = 100):
        # Ownership check: an audit's logs are visible only to its session.
        registry.store.get(audit_id, session(request))
        return {'logs': registry.store.recent_logs(audit_id, since, min(max(limit, 1), 500))}

    @app.get('/api/audits/{audit_id}/export')
    async def export(audit_id: str, request: Request, format: str='json'):
        sid = session(request)
        result = registry.store.get(audit_id,sid)
        all_issues = []
        offset = 0
        while True:
            page = await registry.call('get_audit_status',{'audit_id':audit_id,'offset':offset,'limit':200},sid,'LocalGuard UI export')
            if page['isError']:
                raise ValueError(page['error'])
            all_issues.extend(page['data']['issues'])
            next_offset = page['data'].get('next_offset')
            if next_offset is None:
                break
            if next_offset<=offset:
                raise ValueError('An issue exceeds the response budget; inspect local evidence logs')
            offset = next_offset
        result.update(issues=all_issues,truncated=False)
        content,media,extension = export_report(result,format)
        return Response(content,media_type=media,headers={'Content-Disposition':f'attachment; filename="localguard-{audit_id}.{extension}"'})

    @app.post('/api/chat')
    async def chat(request: Request):
        data = await request.json()
        try:
            CHAT_INPUT.validate(data)
        except ValidationError as exc:
            field = '.'.join(str(part) for part in exc.absolute_path) or 'body'
            raise ValueError(f'Invalid chat request: {field} failed {exc.validator} validation.') from exc
        message = data['message']
        target = data['target']
        registry.validate_target(target)
        tier = data.get('model_tier',registry.config.model_tier)
        history = data.get('history',[])
        try:
            history_bytes = len(json.dumps({'history': history}, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
        except UnicodeError as exc:
            raise ValueError('Conversation history must contain valid Unicode text.') from exc
        if history_bytes > HISTORY_BUDGET:
            raise ValueError('Conversation history exceeds the 16000-byte local context budget')
        return await registry.get_model().chat(message,target,tier,registry,session(request),history=history)

    @app.post('/api/image')
    async def image(request: Request):
        sid = session(request)
        data = await request.json()
        suffix = Path(data.get('name','')).suffix.lower()
        if suffix not in ('.png','.jpg','.jpeg','.webp'):
            raise ValueError('Use PNG, JPEG or WebP')
        encoded = data.get('data','').split(',')[-1]
        try:
            content = base64.b64decode(encoded,validate=True)
        except (ValueError,TypeError) as exc:
            raise ValueError('Invalid base64 image') from exc
        if not content or len(content)>8_000_000:
            raise ValueError('Image exceeds the 8MB limit or is empty')
        directory = registry.config.data_dir / 'uploads' / sid
        directory.mkdir(parents=True,exist_ok=True)
        path = directory / (uuid.uuid4().hex+suffix)
        path.write_bytes(content)
        registry.uploads.setdefault(sid, set()).add(path.resolve())
        try:
            result = await registry.call('analyze_image', {
                'image_path': str(path), 'question': data.get('question','Explain this diagram'),
                'model_tier': data.get('model_tier','8gb'),
            }, sid, 'LocalGuard UI')
            if result['isError']:
                raise ValueError(result['error'])
            return result['data']
        finally:
            registry.uploads[sid].discard(path.resolve())
            if not registry.uploads[sid]:
                del registry.uploads[sid]
            path.unlink(missing_ok=True)

    static = Path(__file__).parent / 'static'
    @app.get('/')
    async def index():
        return FileResponse(static/'index.html')
    app.mount('/static',StaticFiles(directory=static),name='static')
    return app
