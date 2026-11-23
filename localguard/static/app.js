(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const PAGE_SIZE = 200;
  const MAX_HISTORY = 12;
  const HISTORY_BUDGET = 16000;
  const SCANNERS = ['patterns', 'semgrep', 'gitleaks', 'gosec', 'cppcheck', 'pip-audit', 'grype'];
  const TERMINAL = new Set(['completed', 'complete', 'done', 'finished', 'succeeded', 'success', 'failed', 'error', 'cancelled', 'canceled']);
  const FAILED = new Set(['failed', 'error', 'cancelled', 'canceled']);
  const SEVERITIES = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示', unknown: '未分级' };
  const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
  const CATEGORIES = { credential_leak: '凭据泄漏', injection: '注入风险', backdoor: '可疑后门', dependency_cve: '依赖漏洞', misconfig: '配置风险', other: '其他风险' };
  const DECISIONS = { confirmed: '已确认', false_positive: '误报', unreviewed: '待复核' };
  const state = {
    ready: false, bootstrapped: false, csrf: '', sessionId: '', mode: 'form',
    submitting: false, chatBusy: false, imageBusy: false, exporting: false,
    audit: null, lastArguments: null, pollEpoch: 0, pollTimer: null,
    severity: 'all', selectedIssue: '', issueSignature: '', expandedIssues: new Set(),
    reviews: new Map(), reviewPending: new Set(), reviewErrors: new Map(), environmentWarnings: [],
    treeRoot: '', treeEntries: [], treeEpoch: 0, treeBusy: false, collapsedFolders: new Set(),
    preview: null, previewEpoch: 0, previewBusy: false, fileHashes: new Map(), changedFiles: new Set(),
    history: [], chatEpoch: 0, imageFile: null, imageUrl: '',
  };

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined && text !== null) element.textContent = String(text);
    return element;
  }

  function text(value, fallback = '') {
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    return fallback;
  }

  function readable(value, fallback = '本地服务未返回错误详情') {
    if (typeof value === 'string') return value.slice(0, 2500);
    if (value && typeof value === 'object') {
      const message = value.message || value.error || value.detail || value.reason || value.data?.error || value.data?.message;
      if (typeof message === 'string') return message.slice(0, 2500);
      if (Array.isArray(message)) return message.map((item) => text(item.msg, text(item))).filter(Boolean).join('；').slice(0, 2500) || fallback;
    }
    return fallback;
  }

  function announce(message) { $('announcement').textContent = message; }

  function alertIn(id, message, action, label = '重试') {
    const container = $(id);
    container.replaceChildren();
    container.hidden = !message;
    if (!message) return;
    container.append(node('p', '', message));
    if (action) {
      const button = node('button', 'text-button', label);
      button.type = 'button';
      button.addEventListener('click', () => {
        button.disabled = true;
        Promise.resolve().then(action).catch((error) => announce(readable(error))).finally(() => {
          if (button.isConnected) button.disabled = false;
        });
      });
      container.append(button);
    }
  }

  function setConnection(connected, message) {
    $('connection-status').className = `connection-status ${connected ? 'connected' : 'disconnected'}`;
    $('connection-text').textContent = message || (connected ? '本地服务已连接' : '本地服务未连接');
  }

  class ApiError extends Error {
    constructor(message, status = 0, result = null) { super(message); this.name = 'ApiError'; this.status = status; this.result = result; }
  }

  async function request(path, { method = 'GET', body, timeout = 30000, blob = false } = {}) {
    if (!path.startsWith('/api/') || path.startsWith('//')) throw new ApiError('拒绝非本地 API 请求。');
    if (method === 'POST' && !state.csrf) throw new ApiError('本地会话尚未就绪，请先重新连接。', 403);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const headers = { Accept: blob ? '*/*' : 'application/json' };
      if (method === 'POST') {
        headers['Content-Type'] = 'application/json';
        headers['X-CSRF-Token'] = state.csrf;
      }
      const response = await fetch(path, {
        method, headers, credentials: 'same-origin', cache: 'no-store', mode: 'same-origin', redirect: 'error',
        signal: controller.signal, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      if (response.ok && response.status === 204) { setConnection(true); return {}; }
      if (blob && response.ok && !response.headers.get('content-type')?.includes('text/html')) {
        setConnection(true);
        return { blob: await response.blob(), headers: response.headers };
      }
      let result;
      try { result = await response.json(); } catch { throw new ApiError(`服务返回了无法解析的响应（HTTP ${response.status}）。`, response.status); }
      if (!response.ok || result?.isError === true) {
        if (response.status === 401 || response.status === 403) {
          state.ready = false;
          state.csrf = '';
          setConnection(false, '会话需要重新连接');
          alertIn('connection-alert', '会话已失效或请求被拒绝。请重新连接后手动重试；不会自动重复提交任务。', bootstrap, '重新连接');
          updateControls();
        }
        throw new ApiError(readable(result, `请求失败（HTTP ${response.status}）`), response.status, result);
      }
      setConnection(true);
      return result;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      setConnection(false, '本地连接中断');
      if (error.name === 'AbortError') throw new ApiError('本地服务响应超时。任务可能仍在执行，请先检查状态再重试。');
      throw new ApiError('无法连接本地服务。请检查服务进程与访问地址，然后重试。');
    } finally { clearTimeout(timer); }
  }

  async function tool(name, args, timeout = 30000) {
    const result = await request(`/api/tools/${encodeURIComponent(name)}`, { method: 'POST', body: args, timeout });
    if (!result || !result.data || typeof result.data !== 'object' || Array.isArray(result.data)) {
      throw new ApiError(`工具 ${name} 未返回有效的结构化数据。`);
    }
    return result.data;
  }

  function isActive() {
    return Boolean(state.audit?.audit_id && !TERMINAL.has(String(state.audit.status || '').toLowerCase()));
  }

  function updateControls() {
    const busy = state.submitting || state.chatBusy || state.imageBusy;
    $('start-audit').disabled = !state.ready || busy || isActive();
    $('start-audit-label').textContent = !state.ready ? '等待本地服务连接' : state.submitting ? '正在提交…' : isActive() ? '审查进行中…' : state.audit ? '开始新的审查' : '开始安全审查';
    const stop = $('stop-audit');
    stop.hidden = !isActive();
    stop.disabled = !state.ready || state.stopping;
    stop.textContent = state.stopping ? '停止中…' : '停止审查';
    $('send-chat').disabled = !state.ready || busy || isActive();
    $('send-chat').textContent = state.chatBusy ? '本地助手处理中…' : '发送给本地助手';
    $('chat-busy-note').hidden = !isActive();
    $('clear-chat').disabled = state.chatBusy;
    $('analyze-image').disabled = !state.ready || busy || isActive() || !state.imageFile;
    $('analyze-image').textContent = state.imageBusy ? '图片解读中…' : '解读图片';
    $('image-file').disabled = state.imageBusy;
    $('remove-image').disabled = state.imageBusy;
    $('export-report').disabled = !state.ready || !state.audit?.audit_id || isActive() || state.exporting;
    $('refresh-tree').disabled = !state.ready || !state.treeRoot || state.treeBusy;
    document.querySelectorAll('.review-button').forEach((button) => {
      button.disabled = !state.ready || !button.dataset.issueId || state.reviewPending.has(button.dataset.issueId);
    });
  }

  function configureScanners(configured) {
    const entries = new Map();
    const restricted = Array.isArray(configured) || (configured && typeof configured === 'object');
    if (Array.isArray(configured)) {
      configured.forEach((item) => {
        if (typeof item === 'string') entries.set(item, {});
        else if (item?.name || item?.scanner) entries.set(item.name || item.scanner, item);
      });
    } else if (configured && typeof configured === 'object') {
      Object.entries(configured).forEach(([name, settings]) => entries.set(name, typeof settings === 'object' && settings ? settings : { enabled: settings !== false }));
    }
    state.environmentWarnings = [];
    document.querySelectorAll('.scanner-option').forEach((label) => {
      const name = label.dataset.scanner;
      const settings = entries.get(name) || {};
      const allowed = (!restricted || entries.has(name)) && settings.enabled !== false;
      const input = label.querySelector('input');
      input.dataset.allowed = String(allowed);
      if (!allowed) input.checked = false;
      const status = label.querySelector('.scanner-state');
      status.classList.toggle('unavailable', settings.available === false);
      status.textContent = !allowed ? '未启用' : settings.available === false ? '不可用' : settings.available === true ? '已就绪' : name === 'patterns' ? '内置规则' : '';
      if (allowed && settings.available === false) state.environmentWarnings.push(`${name} 不可用，无法提供该项扫描覆盖。`);
    });
    syncScannerControls();
  }

  function syncScannerControls() {
    let selected = 0;
    document.querySelectorAll('.scanner-option').forEach((label) => {
      const input = label.querySelector('input');
      const dependency = ['pip-audit', 'grype'].includes(input.value);
      input.disabled = input.dataset.allowed === 'false' || (dependency && !$('include-dependencies').checked);
      label.classList.toggle('disabled', input.disabled);
      if (!input.disabled && input.checked) selected += 1;
    });
    $('scanner-count').textContent = `${selected} 项已选`;
  }

  let bootstrapPromise = null;
  function bootstrap() {
    if (!bootstrapPromise) bootstrapPromise = connectSession().finally(() => { bootstrapPromise = null; });
    return bootstrapPromise;
  }

  async function connectSession() {
    stopPolling();
    state.ready = false;
    updateControls();
    setConnection(false, '连接本地服务中');
    alertIn('connection-alert', '正在建立本地会话…');
    try {
      const data = await request('/api/bootstrap');
      if (!data?.session_id || typeof data.csrf_token !== 'string' || !data.csrf_token) throw new ApiError('会话初始化响应不完整，缺少 session_id 或 CSRF 令牌。');
      state.csrf = data.csrf_token;
      state.sessionId = data.session_id;
      state.ready = true;
      const config = data.config || {};
      if (!state.bootstrapped && ['rules', '4gb', '8gb'].includes(config.model_tier)) $('model-tier').value = config.model_tier;
      configureScanners(config.scanners);
      const roots = Array.isArray(config.allowed_roots) ? config.allowed_roots : [];
      $('allowed-roots').replaceChildren(...(roots.length ? roots.map((root) => node('li', '', text(root))) : [node('li', '', '服务未配置可访问的根目录')]));
      $('tool-count').textContent = `${Array.isArray(data.tools) ? data.tools.length : 0} 个注册工具`;
      $('runtime-note').textContent = [...state.environmentWarnings, '扫描器不可用、超时或覆盖受限，不等于扫描通过。配置由服务端管理。'].join(' ');
      state.bootstrapped = true;
      setConnection(true);
      alertIn('connection-alert', '');
      // Advisory: model triage agreement with past human reviews.
      fetch('/api/feedback-stats').then((r) => r.ok ? r.json() : null).then((stats) => {
        const el = $('triage-accuracy');
        if (stats && typeof stats.accuracy === 'number' && stats.decided > 0) {
          el.textContent = `分诊一致率 ${stats.accuracy}% (${stats.decided} 项复核)`;
          el.hidden = false;
        }
      }).catch(() => {});
      renderCoverage();
      if (isActive()) schedulePoll(0);
      // Reconnect to recent/in-flight audits after a reload (best-effort).
      loadRecentAudits({ autoResume: true });
      announce('本地服务已连接，可以开始审查。');
    } catch (error) {
      state.ready = false;
      state.csrf = '';
      setConnection(false);
      alertIn('connection-alert', readable(error), bootstrap, '重新连接');
    } finally { updateControls(); }
  }

  function switchMode(mode) {
    state.mode = mode;
    ['form', 'chat'].forEach((name) => {
      const active = mode === name;
      $(`${name}-tab`).setAttribute('aria-selected', String(active));
      $(`${name}-tab`).tabIndex = active ? 0 : -1;
      $(`${name}-panel`).hidden = !active;
    });
    $('chat-transcript').hidden = mode !== 'chat';
    schedulePills();
  }

  function context() {
    if (!$('target').reportValidity()) return null;
    const target = $('target').value.trim();
    if (!target) { $('target').setCustomValidity('请输入目标仓库或目录路径。'); $('target').reportValidity(); return null; }
    const args = { target, model_tier: $('model-tier').value,
                   auto_exclude: $('auto-exclude').checked,
                   model_triage: $('model-triage').checked };
    const maxExp = Number.parseInt($('max-explanations').value, 10);
    if (Number.isInteger(maxExp) && maxExp >= 0) args.max_explanations = Math.min(500, maxExp);
    const excluded = $('exclude-paths').value.split(',').map((s) => s.trim()).filter(Boolean);
    if (excluded.length) args.exclude_paths = excluded;
    return args;
  }

  function formArguments() {
    const shared = context();
    if (!shared) return null;
    const scanners = [...document.querySelectorAll('input[name="scanners"]:checked')].filter((input) => !input.disabled).map((input) => input.value).filter((name) => SCANNERS.includes(name));
    if (!scanners.length) { alertIn('submit-alert', '请至少选择一个已启用的扫描器。'); return null; }
    const incremental = $('incremental').checked;
    if (incremental && (!$('base').reportValidity() || !$('head').reportValidity())) return null;
    const base = $('base').value.trim();
    const head = $('head').value.trim();
    if (incremental && (!base || !head)) { alertIn('submit-alert', '增量审查需要填写 Base 与 Head 引用。'); return null; }
    return { ...shared, depth: document.querySelector('input[name="depth"]:checked').value, scanners, include_dependencies: $('include-dependencies').checked, incremental, base: incremental ? base : 'HEAD~1', head: incremental ? head : 'HEAD' };
  }

  function confirmClone(url) {
    return new Promise((resolve) => {
      const dialog = $('clone-dialog');
      $('clone-dialog-url').textContent = url;
      dialog.hidden = false;
      const finish = (value) => {
        dialog.hidden = true;
        $('clone-confirm').removeEventListener('click', accept);
        $('clone-cancel').removeEventListener('click', decline);
        resolve(value);
      };
      const accept = () => finish(true);
      const decline = () => finish(false);
      $('clone-confirm').addEventListener('click', accept);
      $('clone-cancel').addEventListener('click', decline);
      $('clone-confirm').focus();
    });
  }

  async function submitAudit(args) {
    if (!args || !state.ready || state.submitting || isActive() || state.chatBusy || state.imageBusy) return;
    state.submitting = true;
    updateControls();
    alertIn('submit-alert', '');
    try {
      let target = args.target;
      if (/^https:\/\//i.test(target)) {
        const ok = await confirmClone(target);
        if (!ok) { announce('已取消克隆，未创建审查任务。'); return; }
        alertIn('submit-alert', '正在克隆远程仓库到本地，请稍候…');
        let cloned;
        try {
          cloned = await tool('clone_repository', { url: target }, 180000);
        } catch (error) {
          throw new ApiError(`克隆失败：${readable(error)} 仓库未更改，可重试或改用本地路径。`);
        }
        target = cloned.path;
        $('target').value = target;
        alertIn('submit-alert', '');
      }
      const data = await tool('audit_repository', { ...args, target });
      if (!data.audit_id) throw new ApiError('服务未返回任务编号；请检查服务状态，重试可能创建新任务。');
      adoptAudit({ ...data, target: data.target || target }, { ...args, target });
      announce('审查任务已提交，正在同步工具执行进度。');
    } catch (error) {
      alertIn('submit-alert', readable(error), () => submitAudit(args), '重新提交');
    } finally { state.submitting = false; updateControls(); }
  }

  function stopPolling() { clearTimeout(state.pollTimer); state.pollTimer = null; state.pollEpoch += 1; }

  async function stopAudit() {
    const auditId = state.audit?.audit_id;
    if (!auditId || !isActive() || !state.ready || state.stopping) return;
    state.stopping = true;
    updateControls();
    try {
      const data = await tool('cancel_audit', { audit_id: auditId }, 20000);
      state.audit = { ...state.audit, ...data, audit_id: auditId };
      alertIn('poll-alert', '');
      renderAudit();
      announce('已请求停止审查。');
    } catch (error) {
      alertIn('poll-alert', `停止请求失败：${readable(error)}`, () => stopAudit(), '重试停止');
    } finally {
      state.stopping = false;
      updateControls();
      if (state.audit?.audit_id) pollAudit(state.pollEpoch);
    }
  }

  function renderRecentAudits(audits) {
    const select = $('resume-select');
    const rows = Array.isArray(audits) ? audits : [];
    select.replaceChildren(...rows.map((item) => {
      const option = document.createElement('option');
      option.value = text(item.audit_id);
      const label = text(item.status, '任务');
      const target = text(item.target, '').split(/[\\/]/).pop() || '目标';
      option.textContent = `${label} · ${target} · ${text(item.audit_id).slice(0, 8)}`;
      return option;
    }));
    $('resume-row').hidden = rows.length === 0;
  }

  async function loadRecentAudits({ autoResume = true } = {}) {
    if (!state.ready) return;
    try {
      const data = await tool('list_audits', { limit: 20 }, 20000);
      const audits = data.audits || [];
      renderRecentAudits(audits);
      // After a page reload the in-memory state.audit is null. Auto-restore
      // the most recent in-flight audit so its progress stays visible.
      if (autoResume && !state.audit && audits.length) {
        const active = audits.find((a) => !TERMINAL.has(String(a.status || '').toLowerCase())) || audits[0];
        if (active?.audit_id) {
          adoptAudit({ audit_id: active.audit_id, status: active.status, target: active.target });
        }
      }
    } catch (error) {
      // Non-fatal: reconnecting to history is best-effort.
      $('resume-row').hidden = true;
    }
  }

  function adoptAudit(data, args = null) {
    stopPolling();
    state.audit = { issues: [], warnings: [], completed_modules: [], status: 'queued', ...data };
    state.lastArguments = args;
    state.selectedIssue = '';
    state.expandedIssues.clear();
    state.reviews.clear();
    state.reviewPending.clear();
    state.reviewErrors.clear();
    state.issueSignature = '';
    state.treeEpoch += 1;
    state.treeRoot = '';
    state.treeEntries = [];
    state.collapsedFolders.clear();
    state.fileHashes.clear();
    state.changedFiles.clear();
    $('file-tree').replaceChildren(node('p', 'tree-placeholder', '等待审查任务返回根目录…'));
    resetPreview();
    alertIn('poll-alert', '');
    alertIn('audit-error', '');
    alertIn('export-alert', '');
    renderAudit();
    // Always obtain an authoritative status snapshot, including the server-resolved root.
    if (isActive()) schedulePoll(0);
    else pollAudit(state.pollEpoch);
  }

  function schedulePoll(delay = 900) {
    clearTimeout(state.pollTimer);
    if (!state.ready || !isActive()) return;
    const epoch = state.pollEpoch;
    state.pollTimer = setTimeout(() => pollAudit(epoch), delay);
  }

  async function pollAudit(epoch) {
    if (epoch !== state.pollEpoch || !state.audit?.audit_id || !state.ready) return;
    const auditId = state.audit.audit_id;
    try {
      const data = await tool('get_audit_status', { audit_id: auditId, wait_seconds: 1 }, 20000);
      if (epoch !== state.pollEpoch || state.audit?.audit_id !== auditId) return;
      if (TERMINAL.has(data.status)) {
        const collected = [...(data.issues || [])];
        let offset = data.next_offset;
        while (data.truncated && Number.isInteger(offset) && offset > 0) {
          const page = await tool('get_audit_status', { audit_id: auditId, offset, limit: 200 }, 20000);
          if (epoch !== state.pollEpoch || state.audit?.audit_id !== auditId) return;
          collected.push(...(page.issues || []));
          if (!page.truncated) { data.truncated = false; break; }
          if (!Number.isInteger(page.next_offset) || page.next_offset <= offset) break;
          offset = page.next_offset;
        }
        data.issues = collected;
      }
      if (data.audit_id && data.audit_id !== auditId) throw new ApiError('服务返回的任务编号不匹配，已停止更新。');
      const previousStatus = state.audit.status;
      state.audit = { ...state.audit, ...data, audit_id: auditId };
      alertIn('poll-alert', '');
      renderAudit();
      if (isActive()) schedulePoll();
      else if (previousStatus !== state.audit.status) announce(FAILED.has(state.audit.status) ? '审查未完成，请查看错误与覆盖说明。' : `审查已结束，返回 ${issues().length} 个问题，请人工复核。`);
    } catch (error) {
      if (epoch !== state.pollEpoch) return;
      alertIn('poll-alert', `进度同步已暂停，后台任务可能仍在执行。${readable(error)}`, () => {
        if (!state.ready) return bootstrap();
        stopPolling();
        return pollAudit(state.pollEpoch);
      }, '重新获取状态');
      updateControls();
    }
  }

  function issues() { return Array.isArray(state.audit?.issues) ? state.audit.issues.filter((issue) => issue && typeof issue === 'object') : []; }
  function severity(issue) { const value = String(issue.severity || '').toLowerCase(); return SEVERITIES[value] ? value : 'unknown'; }
  function reviewOf(issue) {
    const value = state.reviews.get(String(issue.id)) || issue.review_status || issue.review_decision || issue.review?.decision || issue.review || issue.decision;
    return Object.hasOwn(DECISIONS, value) ? value : 'unreviewed';
  }

  function moduleItems() {
    const modules = state.audit?.completed_modules;
    if (Array.isArray(modules)) return modules;
    if (modules && typeof modules === 'object') return Object.entries(modules).map(([name, value]) => ({ name, ...(typeof value === 'object' ? value : { status: value }) }));
    return [];
  }

  function renderAudit() {
    const audit = state.audit;
    if (!audit) return;
    const status = String(audit.status || 'queued').toLowerCase();
    const active = isActive();
    const failed = FAILED.has(status);
    const queued = status === 'queued' || status === 'pending';
    const statusText = queued ? '排队中' : failed ? '未完成' : active ? '执行中' : '已完成';
    $('activity-title').textContent = queued ? '任务已进入本地队列' : failed ? '审查未完整完成' : active ? '正在执行确定性审查' : '审查已完成，等待人工决策';
    $('audit-status').textContent = statusText;
    $('audit-status').className = `badge ${failed ? 'warning' : active ? 'cyan' : 'success'}`;
    $('activity-indicator').className = `activity-indicator ${failed ? 'failed' : active ? 'running' : 'complete'}`;
    $('audit-id').textContent = `ID ${text(audit.audit_id)}`;
    $('audit-id').title = text(audit.audit_id);
    $('audit-target').textContent = text(audit.target, text(audit.root, '等待本地目标解析…'));
    const progress = Number.isFinite(audit.progress) ? Math.max(0, Math.min(100, audit.progress)) : 0;
    $('audit-progress').value = progress;
    $('progress-label').textContent = `${Math.round(progress)}%`;
    $('pipeline-queue').className = queued ? 'active' : 'done';
    $('pipeline-scan').className = !queued && active ? 'active' : !active && !failed ? 'done' : '';
    $('pipeline-report').className = !active && !failed ? 'done' : '';
    $('queue-label').textContent = queued ? Number.isFinite(audit.queue_position) && audit.queue_position > 0 ? `队列第 ${audit.queue_position} 位` : '等待资源调度' : failed ? '已保留返回的初步证据' : active ? '扫描器按本地资源调度' : '结果以实际覆盖范围为限';
    const modules = moduleItems();
    $('completed-modules').hidden = !modules.length;
    $('completed-modules').replaceChildren(...modules.map((item) => node('span', 'module-chip', typeof item === 'string' ? item : [text(item.name, text(item.scanner, text(item.module, '模块'))), text(item.status)].filter(Boolean).join(' · '))));
    $('stat-modules').textContent = String(modules.length);
    if (audit.error) alertIn('audit-error', readable(audit.error, '审查执行失败，请检查本地服务日志。'), !active && state.lastArguments ? () => submitAudit(state.lastArguments) : null, '按原配置重新审查');
    else alertIn('audit-error', '');
    renderStats();
    renderCoverage();
    const signature = JSON.stringify([audit.root, audit.issues, audit.status, audit.truncated]);
    if (signature !== state.issueSignature) {
      state.issueSignature = signature;
      renderIssues();
    }
    if (audit.root && audit.root !== state.treeRoot) {
      state.treeRoot = audit.root;
      loadTree();
    }
    updateControls();
  }

  function renderStats() {
    if (!state.audit) return;
    const list = issues();
    const unreviewed = list.filter((issue) => reviewOf(issue) === 'unreviewed').length;
    $('stat-total').textContent = String(list.length);
    $('stat-high').textContent = String(list.filter((issue) => ['high', 'critical'].includes(severity(issue))).length);
    $('stat-unreviewed').textContent = String(unreviewed);
    const baseline = state.audit?.baseline;
    $('stat-total-note').textContent = baseline
      ? `对比上次：新增 ${baseline.added.length} · 消失 ${baseline.resolved.length}`
      : state.audit.truncated ? '返回结果已截断' : isActive() ? '持续接收初步发现' : '当前范围内的工具发现';
    $('stat-review-note').textContent = `${list.length - unreviewed} 项已人工标记`;
  }

  function renderCoverage() {
    const warnings = [...state.environmentWarnings];
    const returned = state.audit?.warnings;
    if (Array.isArray(returned)) returned.forEach((warning) => {
      if (typeof warning === 'string') warnings.push(warning);
      else if (warning && typeof warning === 'object') warnings.push([text(warning.scanner, text(warning.module)), readable(warning, text(warning.status, '存在未覆盖的检查，请查看本地日志。'))].filter(Boolean).join('：'));
    });
    else if (returned) warnings.push(readable(returned));
    if (state.audit?.truncated) warnings.push('服务端已截断结果。当前列表可能不完整，请结合导出报告与本地日志复核。');
    $('coverage-panel').hidden = !warnings.length;
    const explanations = state.audit?.warning_explanations || {};
    $('coverage-warnings').replaceChildren(...[...new Set(warnings)].map((warning) => {
      const li = node('li', 'coverage-item');
      const zh = explanations[warning];
      if (zh && zh !== warning) {
        li.append(node('span', 'coverage-zh', text(zh)));
        const details = node('details', 'coverage-raw');
        details.append(node('summary', '', '查看原文'), node('span', 'mono', text(warning)));
        li.append(details);
      } else {
        li.append(node('span', '', text(warning)));
      }
      return li;
    }));
  }

  function locationsOf(issue) { return Array.isArray(issue.locations) ? issue.locations.filter((location) => location && typeof location === 'object') : []; }
  function isStale(location) { const path = resolvePath(state.audit?.root, location.path); return Boolean(location.stale || (path && state.changedFiles.has(path))); }

  function renderIssues() {
    const list = $('issues-list');
    const scrollTop = list.scrollTop;
    const focus = document.activeElement;
    const focusKey = focus?.dataset?.focusKey;
    const severityFilter = state.severity;
    const reviewFilter = $('review-filter').value;
    const triageFilter = $('triage-filter').value;
    const search = $('issue-search').value.trim().toLocaleLowerCase();
    const all = issues();
    const filtered = all.filter((issue) => {
      const searchable = [issue.title, issue.id, issue.cwe, issue.category, ...locationsOf(issue).map((location) => location.path)].join(' ').toLocaleLowerCase();
      const verdict = issue.triage?.verdict || 'none';
      return (severityFilter === 'all' || severity(issue) === severityFilter)
        && (reviewFilter === 'all' || reviewOf(issue) === reviewFilter)
        && (triageFilter === 'all' || verdict === triageFilter)
        && (!search || searchable.includes(search));
    });
    $('issue-count').textContent = String(all.length);
    $('results-note').textContent = state.audit ? `显示 ${filtered.length} / ${all.length} 项${isActive() ? ' · 初步结果，仍在更新' : ''}${state.audit.truncated ? ' · 已截断' : ''}` : '按风险等级、置信度与文件排序';
    list.replaceChildren();
    if (!filtered.length) {
      const empty = node('div', 'empty-state');
      let title = '让每个结论都有据可查';
      let description = '从左侧发起审查，问题定位只使用工具返回的真实证据。';
      if (all.length) { title = '没有符合筛选条件的问题'; description = '尝试切换严重程度、复核状态或清空搜索。'; }
      else if (state.audit && isActive()) { title = '正在等待工具返回发现'; description = '任务尚未结束。没有初步问题，不代表扫描通过。'; }
      else if (state.audit && FAILED.has(String(state.audit.status).toLowerCase())) { title = '尚无可展示的发现'; description = '审查未完整完成，请先检查上方错误与覆盖提醒。'; }
      else if (state.audit) { title = '当前范围内未报告问题'; description = '这不代表项目不存在风险。请检查扫描器覆盖、不可用项和截断提示。'; }
      empty.append(node('div', 'code-symbol', all.length ? '∅' : '{ }'), node('h4', '', title), node('p', '', description));
      list.append(empty);
    } else filtered.forEach((issue) => list.append(issueCard(issue)));
    list.scrollTop = scrollTop;
    if (focusKey && list.contains(focus) === false) {
      [...list.querySelectorAll('[data-focus-key]')].find((item) => item.dataset.focusKey === focusKey)?.focus({ preventScroll: true });
    }
  }

  function locationButton(location, issueId, label) {
    const line = Number(location.line);
    const path = resolvePath(state.audit?.root, location.path);
    const button = node('button', 'location-button');
    button.type = 'button';
    button.append(node('span', '', label || `${text(location.path, '未知文件')}:${Number.isInteger(line) && line > 0 ? line : '?'}`));
    button.disabled = !path || !Number.isInteger(line) || line < 1;
    button.title = button.disabled ? '等待有效审查根目录及工具验证的定位' : `读取本地文件并定位到第 ${line} 行`;
    button.dataset.focusKey = `location:${issueId}:${text(location.path)}:${line}:${label || ''}`;
    button.addEventListener('click', async () => {
      state.selectedIssue = issueId;
      // Deep-link must feel instant. Only a still-running audit needs a
      // fresh snapshot; for a completed one state.audit is already current,
      // and awaiting get_audit_status (which re-checks every location's hash)
      // delays the file preview by ~0.8s for no benefit.
      if (isActive() && state.audit?.audit_id) await pollAudit(state.pollEpoch);
      const currentIssue = issues().find((issue) => issue.id === issueId);
      const currentLocation = locationsOf(currentIssue || {}).find((item) => item.path === location.path && item.line === line);
      // Update selection highlight without blocking preview; openFile issues
      // its own single view_file call immediately.
      openFile(path, line, currentLocation || location);
      renderIssues();
    });
    return button;
  }

  function issueCard(issue) {
    const id = text(issue.id);
    const level = severity(issue);
    const decision = reviewOf(issue);
    const card = node('article', `issue-card severity-${level}${state.selectedIssue === id ? ' selected' : ''}${decision === 'false_positive' ? ' false-positive' : ''}`);
    const top = node('div', 'issue-topline');
    top.append(node('span', `badge severity-${level}`, SEVERITIES[level]), node('span', 'issue-category', CATEGORIES[issue.category] || text(issue.category, '未分类')));
    const triage = issue.triage;
    if (triage && triage.verdict) {
      const labels = { likely_true: '模型：可能是真的', likely_false: '模型：可能误报', uncertain: '模型：不确定' };
      const badge = node('span', `badge triage-${triage.verdict}${triage.overridden ? ' triage-overridden' : ''}`,
                         (labels[triage.verdict] || '模型分诊') + (triage.overridden ? ' · 已人工推翻' : ''));
      badge.title = text(triage.reason, '');
      top.append(badge);
    }
    if (issue.ai_explanation === 'skipped_budget') {
      const badge = node('span', 'badge ai-skipped', '未做 AI 解释');
      badge.title = '超过 AI 解释条数上限：此发现保留完整确定性证据与定位，但没有 AI 文字解说。证据与严重度不受影响。';
      top.append(badge);
    }
    const feedback = issue.feedback;
    if (feedback && (feedback.rule_confirmed || feedback.rule_false_positive)) {
      const fb = node('span', 'badge feedback-badge',
                      `历史复核：确认 ${feedback.rule_confirmed} · 误报 ${feedback.rule_false_positive}`);
      fb.title = '基于同一规则的过往人工复核，仅供参考，不自动判定';
      top.append(fb);
    }
    if (typeof issue.confidence === 'number' && Number.isFinite(issue.confidence)) top.append(node('span', 'issue-confidence', `置信度 ${Math.round(Math.max(0, Math.min(1, issue.confidence)) * 100)}%`));
    card.append(top, node('h4', '', text(issue.title, '未命名问题')), node('p', 'issue-id mono', [id, text(issue.cwe)].filter(Boolean).join(' / ')));
    const locations = locationsOf(issue);
    const locationList = node('div', 'issue-locations');
    locations.forEach((location) => locationList.append(locationButton(location, id)));
    if (!locations.length) locationList.append(node('p', 'muted', '服务未返回已验证的文件定位。'));
    card.append(locationList);
    if (issue.stale || locations.some(isStale)) card.append(node('p', 'stale-note', '定位已过期：文件内容可能已变化，请重新审查后确认。'));
    if (issue.explanation) card.append(node('p', 'issue-explanation', text(issue.explanation)));
    else if (issue.ai_explanation === 'skipped_budget') card.append(node('p', 'issue-explanation muted', '未做 AI 文字解释（超出条数上限）。下方证据链与精确定位完整，可据此人工判断。'));
    const details = node('details', 'issue-details');
    details.open = state.expandedIssues.has(id);
    const evidence = Array.isArray(issue.evidence) ? issue.evidence : [];
    details.append(node('summary', '', `证据来源与修复建议 · ${evidence.length} 条证据`));
    details.addEventListener('toggle', () => { if (details.open) state.expandedIssues.add(id); else state.expandedIssues.delete(id); });
    const evidenceList = node('ul', 'evidence-list');
    evidence.forEach((entry) => {
      if (!entry || typeof entry !== 'object') return;
      const item = node('li');
      item.append(node('strong', 'evidence-tool', text(entry.tool, '审查工具')));
      if (entry.raw_ref !== undefined) item.append(node('p', 'evidence-ref mono', typeof entry.raw_ref === 'object' ? JSON.stringify(entry.raw_ref).slice(0, 6000) : text(entry.raw_ref)));
      if (Array.isArray(entry.range)) item.append(node('p', 'evidence-ref', `工具读取范围：${entry.range.map((value) => text(value)).join(' – ')} 行`));
      // Never turn a raw_ref or free-form explanation into a file link.
      const matching = entry.path ? locations.filter((location) => location.path === entry.path) : locations;
      matching.forEach((location) => item.append(locationButton(location, id, `查看对应证据 · ${text(location.path)}:${text(location.line)}`)));
      evidenceList.append(item);
    });
    details.append(evidenceList);
    locations.forEach((location) => {
      if (location.snippet_hash) details.append(node('p', 'evidence-ref mono', `定位快照 · ${text(location.snippet_hash)}`));
    });
    details.append(node('h5', '', '修复建议'), node('p', 'issue-remediation', text(issue.remediation, '暂无修复建议，请结合原始证据人工判断。')));
    card.append(details);
    const review = node('div', 'review-area');
    const reviewStatus = node('div', 'review-status');
    reviewStatus.append(node('span', '', `复核：${DECISIONS[decision]}`), node('span', '', issue.needs_human_review ? '需要人工确认' : '人工复核'));
    review.append(reviewStatus);
    const actions = node('div', 'review-actions');
    [['confirmed', '确认问题'], ['false_positive', '标记误报'], ['unreviewed', '待复核']].forEach(([value, label]) => {
      const button = node('button', 'review-button', label);
      button.type = 'button';
      button.setAttribute('aria-pressed', String(decision === value));
      button.setAttribute('aria-label', `${label}：${text(issue.title, id)}`);
      button.dataset.focusKey = `review:${id}:${value}`;
      button.dataset.issueId = id;
      button.disabled = !state.ready || !id || state.reviewPending.has(id);
      button.addEventListener('click', () => reviewIssue(id, value));
      actions.append(button);
    });
    review.append(actions);
    if (state.reviewPending.has(id)) review.append(node('p', 'review-error', '正在保存复核状态…'));
    if (state.reviewErrors.has(id)) { const error = node('p', 'review-error', state.reviewErrors.get(id)); error.setAttribute('role', 'alert'); review.append(error); }
    card.append(review);
    return card;
  }

  async function reviewIssue(issueId, decision) {
    if (!state.ready || !state.audit?.audit_id || state.reviewPending.has(issueId)) return;
    const auditId = state.audit.audit_id;
    state.reviewPending.add(issueId);
    state.reviewErrors.delete(issueId);
    renderIssues();
    try {
      await request('/api/review', { method: 'POST', body: { audit_id: auditId, issue_id: issueId, decision } });
      if (state.audit?.audit_id !== auditId) return;
      state.reviews.set(issueId, decision);
      announce(`复核状态已保存：${DECISIONS[decision]}。`);
    } catch (error) {
      if (state.audit?.audit_id === auditId) state.reviewErrors.set(issueId, `${readable(error)} 可再次点击复核按钮重试。`);
    } finally {
      if (state.audit?.audit_id === auditId) { state.reviewPending.delete(issueId); renderStats(); renderIssues(); }
    }
  }

  // This is a display-layer boundary only. The service remains responsible for realpath/symlink validation.
  function absolutePath(value) {
    if (typeof value !== 'string' || !value || value.includes('\0')) return null;
    const path = value.replace(/\\/g, '/');
    if (!/^(?:[A-Za-z]:\/|\/)/.test(path)) return null;
    const prefix = /^[A-Za-z]:\//.test(path) ? path.slice(0, 3) : path.startsWith('//') ? '//' : '/';
    const parts = path.slice(prefix.length).split('/').filter((part) => part && part !== '.');
    if (parts.includes('..')) return null;
    return prefix + parts.join('/');
  }

  function resolvePath(root, value) {
    const base = absolutePath(root);
    if (!base || typeof value !== 'string' || !value || value.includes('\0')) return null;
    const relative = value.replace(/\\/g, '/');
    if (relative.split('/').includes('..')) return null;
    const path = absolutePath(relative) || absolutePath(`${base.replace(/\/$/, '')}/${relative}`);
    if (!path) return null;
    const insensitive = /^[A-Za-z]:/.test(base) || base.startsWith('//');
    const a = insensitive ? base.toLowerCase() : base;
    const b = insensitive ? path.toLowerCase() : path;
    return b === a || b.startsWith(`${a.replace(/\/$/, '')}/`) ? path : null;
  }

  function samePath(a, b) {
    if (!a || !b) return false;
    return /^[A-Za-z]:/.test(a) || a.startsWith('//') ? a.toLowerCase() === b.toLowerCase() : a === b;
  }

  function relativePath(path) {
    const root = absolutePath(state.audit?.root);
    return root && resolvePath(root, path) ? path.slice(root.length).replace(/^\//, '') || path : path;
  }

  async function loadTree() {
    const root = state.treeRoot;
    if (!root || !state.ready) return;
    const epoch = ++state.treeEpoch;
    state.treeBusy = true;
    updateControls();
    $('file-tree').replaceChildren(node('p', 'tree-placeholder', '正在读取目录…'));
    try {
      const data = await tool('list_tree', { path: root, max_depth: 4 });
      if (epoch !== state.treeEpoch || root !== state.treeRoot) return;
      state.treeEntries = Array.isArray(data.entries) ? data.entries.filter((entry) => entry && ['file', 'directory'].includes(entry.type)) : [];
      $('tree-note').textContent = data.truncated ? '目录已截断，仅显示部分条目' : '最多展开 4 层目录';
      renderTree();
    } catch (error) {
      if (epoch !== state.treeEpoch) return;
      $('file-tree').replaceChildren(node('p', 'tree-placeholder', readable(error)));
      const retry = node('button', 'text-button', '重新读取目录');
      retry.type = 'button';
      retry.addEventListener('click', () => { if (state.ready) loadTree(); else bootstrap().then(() => loadTree()); });
      $('file-tree').append(retry);
    } finally { if (epoch === state.treeEpoch) { state.treeBusy = false; updateControls(); } }
  }

  function renderTree() {
    const list = node('ul', 'tree-list');
    state.treeEntries.forEach((entry) => {
      const path = resolvePath(state.treeRoot, entry.path);
      if (!path || [...state.collapsedFolders].some((folder) => path.startsWith(`${folder}/`))) return;
      const item = node('li');
      const directory = entry.type === 'directory';
      const collapsed = state.collapsedFolders.has(path);
      const button = node('button', `tree-entry ${directory ? 'directory' : 'file'}${state.preview?.path === path ? ' active' : ''}`);
      button.type = 'button';
      button.style.setProperty('--depth', String(Math.min(10, Math.max(0, Number(entry.depth) || 0))));
      button.title = path;
      button.dataset.path = path;
      const icon = node('span', 'tree-icon', directory ? collapsed ? '▸' : '▾' : '·');
      icon.setAttribute('aria-hidden', 'true');
      button.append(icon, node('span', '', text(entry.name, relativePath(path))));
      if (directory) button.setAttribute('aria-expanded', String(!collapsed));
      button.addEventListener('click', () => {
        if (directory) {
          if (collapsed) state.collapsedFolders.delete(path); else state.collapsedFolders.add(path);
          renderTree();
          [...$('file-tree').querySelectorAll('button')].find((element) => element.dataset.path === path)?.focus({ preventScroll: true });
        } else openFile(path, 1);
      });
      item.append(button);
      list.append(item);
    });
    $('file-tree').replaceChildren(list.children.length ? list : node('p', 'tree-placeholder', '没有可展示的目录条目。'));
  }

  function resetPreview() {
    state.previewEpoch += 1;
    state.previewBusy = false;
    state.preview = null;
    $('file-path').textContent = '尚未选择文件';
    $('file-path').title = '';
    $('file-meta').textContent = '只读';
    $('source-hash').textContent = '文件内容仅从本地工具读取';
    $('preview-pagination').hidden = true;
    $('preview-warning').hidden = true;
    $('code-preview').setAttribute('aria-busy', 'false');
    const empty = node('div', 'empty-state preview-empty');
    empty.append(node('div', 'code-symbol', '{ }'), node('h4', '', '回到代码，验证发现'), node('p', '', '点击工具返回的文件:行号，读取真实片段并精确定位。'));
    $('code-preview').replaceChildren(empty);
    alertIn('preview-alert', '');
  }

  async function openFile(path, targetLine = 1, location = null, pageStart = null) {
    const resolved = resolvePath(state.audit?.root, path);
    if (!resolved || !Number.isInteger(targetLine) || targetLine < 1) {
      alertIn('preview-alert', '文件定位无效，或目标不在当前审查根目录内。');
      return;
    }
    if (!state.ready) { alertIn('preview-alert', '本地会话未就绪，请重新连接后打开文件。', bootstrap, '重新连接'); return; }
    const epoch = ++state.previewEpoch;
    const start = pageStart === null ? Math.max(1, targetLine - 40) : Math.max(1, pageStart);
    state.previewBusy = true;
    $('code-preview').setAttribute('aria-busy', 'true');
    $('file-path').textContent = relativePath(resolved);
    $('file-path').title = resolved;
    $('file-meta').textContent = '读取中';
    $('preview-pagination').hidden = true;
    $('preview-warning').hidden = true;
    $('code-preview').replaceChildren(node('p', 'tree-placeholder', `正在读取第 ${start}–${start + PAGE_SIZE - 1} 行…`));
    alertIn('preview-alert', '');
    try {
      const data = await tool('view_file', { path: resolved, start_line: start, end_line: start + PAGE_SIZE - 1 });
      if (epoch !== state.previewEpoch) return;
      if (!Array.isArray(data.lines) || !Number.isInteger(data.total_lines) || data.total_lines < 0) throw new ApiError('文件预览数据不完整，无法验证真实行号。');
      if (data.path && !samePath(resolvePath(state.audit.root, data.path), resolved)) throw new ApiError('返回文件与请求定位不匹配，已拒绝显示。');
      const previousHash = state.fileHashes.get(resolved);
      if (previousHash && data.hash && previousHash !== data.hash) state.changedFiles.add(resolved);
      if (data.hash) state.fileHashes.set(resolved, data.hash);
      state.preview = { ...data, path: resolved, targetLine, location, requestedStart: start };
      const stale = location?.stale || data.stale || state.changedFiles.has(resolved);
      const warnings = [];
      if (stale) warnings.push('定位已过期或文件自上次读取后已变化。当前显示实时内容，请重新审查以验证证据。');
      if (data.truncated) warnings.push('当前预览已截断，可通过翻页继续读取。');
      $('preview-warning').textContent = warnings.join(' ');
      $('preview-warning').hidden = !warnings.length;
      $('file-meta').textContent = `${data.total_lines} 行 · 只读`;
      $('source-hash').textContent = data.hash ? `HASH ${text(data.hash).slice(0, 16)}` : '服务未返回内容哈希';
      $('source-hash').title = text(data.hash);
      renderCode(data, targetLine, pageStart !== null);
      renderPagination();
      renderTree();
      if (stale) renderIssues();
    } catch (error) {
      if (epoch !== state.previewEpoch) return;
      state.preview = null;
      $('file-meta').textContent = '读取失败';
      $('source-hash').textContent = '未获取到文件内容';
      $('code-preview').replaceChildren(node('p', 'tree-placeholder', '无法加载此文件；没有显示缓存或推测的代码。'));
      alertIn('preview-alert', readable(error), () => openFile(resolved, targetLine, location, pageStart), '重新读取');
    } finally {
      if (epoch === state.previewEpoch) { state.previewBusy = false; $('code-preview').setAttribute('aria-busy', 'false'); renderPagination(); }
    }
  }

  function tokenClass(type) {
    const name = String(type || '').toLowerCase();
    if (/comment/.test(name)) return 'tok-comment';
    if (/string|char|escape/.test(name)) return 'tok-string';
    if (/keyword|boolean/.test(name)) return 'tok-keyword';
    if (/number|integer|float/.test(name)) return 'tok-number';
    if (/function|method/.test(name)) return 'tok-function';
    if (/type|class/.test(name)) return 'tok-type';
    if (/constant/.test(name)) return 'tok-constant';
    if (/property|field/.test(name)) return 'tok-property';
    if (/operator/.test(name)) return 'tok-operator';
    if (/attribute/.test(name)) return 'tok-attribute';
    if (/tag/.test(name)) return 'tok-tag';
    return '';
  }

  function appendTokens(element, line) {
    const source = text(line.text);
    // Offsets are character offsets, not UTF-8 bytes. Code points preserve non-BMP characters.
    const characters = Array.from(source);
    const tokens = (Array.isArray(line.tokens) ? line.tokens : []).filter((token) => token && Number.isInteger(token.start) && Number.isInteger(token.end) && token.start >= 0 && token.end > token.start && token.end <= characters.length).sort((a, b) => a.start - b.start || a.end - b.end);
    let cursor = 0;
    tokens.forEach((token) => {
      if (token.start < cursor) return;
      if (token.start > cursor) element.append(node('span', '', characters.slice(cursor, token.start).join('')));
      element.append(node('span', tokenClass(token.type), characters.slice(token.start, token.end).join('')));
      cursor = token.end;
    });
    if (cursor < characters.length || !characters.length) element.append(node('span', '', characters.slice(cursor).join('')));
  }

  function renderCode(data, targetLine, pagination) {
    const container = node('div', 'code-lines');
    let target = null;
    const seen = new Set();
    data.lines.forEach((line) => {
      if (!line || !Number.isInteger(line.line) || line.line < 1 || line.line > data.total_lines || seen.has(line.line)) return;
      seen.add(line.line);
      const row = node('div', `code-line${line.line === targetLine ? ' highlighted' : ''}`);
      row.tabIndex = -1;
      row.dataset.line = String(line.line);
      row.setAttribute('aria-label', `第 ${line.line} 行${line.line === targetLine ? '，定位行' : ''}`);
      const number = node('span', 'line-number', line.line);
      number.setAttribute('aria-hidden', 'true');
      const code = node('code', 'line-content');
      appendTokens(code, line);
      row.append(number, code);
      container.append(row);
      if (line.line === targetLine) target = row;
    });
    $('code-preview').replaceChildren(container.children.length ? container : node('p', 'tree-placeholder', data.total_lines ? '此范围没有返回代码，请调整行号或重新读取。' : '这是一个空文件。'));
    $('code-preview').scrollTop = 0;
    $('code-preview').scrollLeft = 0;
    if (!pagination && data.total_lines > 0 && !target) alertIn('preview-alert', '目标行未出现在返回片段中，定位可能已经失效。请重新审查或手动选择行号。');
    // The requested slice is rendered before any scroll/focus operation.
    const epoch = state.previewEpoch;
    requestAnimationFrame(() => {
      if (epoch !== state.previewEpoch) return;
      if (target && !pagination) {
        target.focus({ preventScroll: true });
        target.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'auto' });
        announce(`已打开 ${relativePath(state.preview.path)}，定位到第 ${targetLine} 行。`);
      } else if (!pagination) $('code-preview').focus({ preventScroll: true });
    });
  }

  function renderPagination() {
    const preview = state.preview;
    $('preview-pagination').hidden = !preview || !preview.total_lines;
    if (!preview) return;
    const start = Number(preview.start_line) || preview.requestedStart;
    const end = Number(preview.end_line) || Math.min(preview.total_lines, start + PAGE_SIZE - 1);
    $('page-range').textContent = `${start}–${end} / ${preview.total_lines}`;
    $('previous-page').disabled = state.previewBusy || start <= 1;
    $('next-page').disabled = state.previewBusy || end >= preview.total_lines;
    $('jump-line').max = String(preview.total_lines);
    $('jump-line').disabled = state.previewBusy;
    $('jump-form').querySelector('button').disabled = state.previewBusy;
  }

  function boundedHistory(messages) {
    const history = [];
    if (!Array.isArray(messages)) return history;
    const encoder = new TextEncoder();
    for (let index = messages.length - 1; index >= 0 && history.length < MAX_HISTORY; index -= 1) {
      const message = messages[index];
      if (!message || !['user', 'assistant'].includes(message.role) || typeof message.content !== 'string') continue;
      const characters = Array.from(message.content).slice(0, 4000);
      const entry = { role: message.role, content: '' };
      const fits = (length) => {
        entry.content = characters.slice(0, length).join('');
        return encoder.encode(JSON.stringify({ history: [entry, ...history] })).byteLength <= HISTORY_BUDGET;
      };
      if (!fits(0)) break;
      let low = 0;
      let high = characters.length;
      while (low < high) {
        const middle = Math.ceil((low + high) / 2);
        if (fits(middle)) low = middle;
        else high = middle - 1;
      }
      entry.content = characters.slice(0, low).join('');
      history.unshift(entry);
      if (low < characters.length) break;
    }
    return history;
  }

  function addChatMessage(role, content, pending = false) {
    $('chat-empty')?.remove();
    const message = node('div', `chat-message ${role}${pending ? ' pending' : ''}`);
    message.append(node('div', 'chat-author', role === 'user' ? '你' : '本地助手'), node('div', 'chat-body', content));
    $('chat-log').append(message);
    while ($('chat-log').children.length > 24) $('chat-log').firstElementChild.remove();
    $('chat-log').scrollTop = $('chat-log').scrollHeight;
    return message;
  }

  function appendChatTools(reply, toolCalls) {
    if (!Array.isArray(toolCalls) || !toolCalls.length) return;
    const calls = node('div', 'chat-tools');
    toolCalls.slice(0, 30).forEach((call) => {
      const name = typeof call === 'string' ? call : text(call?.name, text(call?.tool, text(call?.function?.name, '本地工具')));
      const result = call?.result?.untrusted_data || call?.result;
      const label = result?.isError === true ? `${name} · 失败：${readable(result)}` : name;
      calls.append(node('span', 'chat-tool mono', label));
    });
    reply.append(calls);
  }

  async function sendChat(payload, retryElement = null) {
    if (!state.ready || state.chatBusy || state.submitting || state.imageBusy || isActive()) return;
    state.chatBusy = true;
    const epoch = state.chatEpoch;
    if (retryElement) retryElement.remove();
    else addChatMessage('user', payload.message);
    const reply = addChatMessage('assistant', '正在调用本地助手与工具…', true);
    updateControls();
    try {
      const result = await request('/api/chat', { method: 'POST', body: payload, timeout: 120000 });
      if (epoch !== state.chatEpoch) return;
      reply.classList.remove('pending');
      const message = text(result.message, '服务没有返回解释文本。请查看工具生成的审查报告。');
      // Plain text only: no Markdown linkification, issue parsing, or model-authored location links.
      reply.querySelector('.chat-body').textContent = message;
      appendChatTools(reply, result.tool_calls);
      state.history = boundedHistory([...state.history, { role: 'user', content: payload.message }, { role: 'assistant', content: message }]);
      if (result.audit_id) {
        adoptAudit({ audit_id: result.audit_id, status: 'queued', target: payload.target });
        const link = node('button', 'text-button chat-audit-link', '查看工具审查任务');
        link.type = 'button';
        link.addEventListener('click', () => $('activity-title').scrollIntoView({ behavior: 'auto', block: 'center' }));
        reply.append(link);
      }
      announce('本地助手已返回解释。文件定位请以下方工具报告为准。');
    } catch (error) {
      if (epoch !== state.chatEpoch) return;
      reply.classList.remove('pending');
      reply.classList.add('error');
      reply.setAttribute('role', 'alert');
      reply.querySelector('.chat-author').textContent = '本地助手 · 请求失败';
      reply.querySelector('.chat-body').textContent = `${readable(error)} 请求可能已触发工具调用，重试前请确认任务状态。`;
      appendChatTools(reply, error.result?.tool_calls);
      if (error.result?.audit_id) {
        adoptAudit({ audit_id: error.result.audit_id, status: 'queued', target: payload.target });
      } else {
        const retry = node('button', 'text-button', '重试这条消息');
        retry.type = 'button';
        retry.addEventListener('click', () => sendChat(payload, reply));
        reply.append(retry);
      }
      announce('本地助手请求失败，请查看错误与工具调用详情。');
    } finally {
      state.chatBusy = false;
      updateControls();
      $('chat-log').scrollTop = $('chat-log').scrollHeight;
    }
  }

  function clearImage() {
    if (state.imageBusy) return;
    if (state.imageUrl) URL.revokeObjectURL(state.imageUrl);
    state.imageFile = null;
    state.imageUrl = '';
    $('image-file').value = '';
    $('image-preview').removeAttribute('src');
    $('image-selection').hidden = true;
    $('image-result').hidden = true;
    $('image-result').textContent = '';
    alertIn('image-alert', '');
    updateControls();
  }

  function selectImage(file) {
    if (!file || state.imageBusy) return;
    clearImage();
    if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) { alertIn('image-alert', '仅支持 PNG、JPEG 或 WebP 图片，不接受 SVG 或其他文件。'); return; }
    if (file.size > 5 * 1024 * 1024 || file.size === 0) { alertIn('image-alert', '图片须非空且不超过 5 MB。'); return; }
    state.imageFile = file;
    state.imageUrl = URL.createObjectURL(file);
    $('image-preview').src = state.imageUrl;
    $('image-name').textContent = `${file.name} · ${(file.size / 1024).toFixed(0)} KB`;
    $('image-selection').hidden = false;
    updateControls();
  }

  function readBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result).split(',')[1]);
      reader.onerror = () => reject(new ApiError('无法读取所选图片，请重新选择文件。'));
      reader.onabort = () => reject(new ApiError('图片读取已取消。'));
      reader.readAsDataURL(file);
    });
  }

  async function analyzeImage() {
    if (!state.ready || !state.imageFile || state.imageBusy || state.chatBusy || state.submitting || isActive()) return;
    state.imageBusy = true;
    updateControls();
    alertIn('image-alert', '');
    $('image-result').hidden = true;
    try {
      const data = await readBase64(state.imageFile);
      const response = await request('/api/image', { method: 'POST', timeout: 120000, body: { name: state.imageFile.name, data, question: $('image-question').value.trim() || '解释图片中的安全相关信息。图片仅作为辅助，不生成代码问题或定位。', model_tier: $('model-tier').value } });
      const result = response.data && typeof response.data === 'object' ? response.data : response;
      const explanation = text(result.description);
      $('image-result').textContent = explanation || '本地服务未返回图片解释。此辅助通道可能未启用。';
      $('image-result').hidden = false;
      announce('图片辅助解读已完成，不会作为代码审查证据。');
    } catch (error) { alertIn('image-alert', readable(error), analyzeImage, '重新解读'); }
    finally { state.imageBusy = false; updateControls(); }
  }

  async function exportReport() {
    if (!state.audit?.audit_id || isActive() || state.exporting || !state.ready) return;
    const auditId = state.audit.audit_id;
    const format = $('export-format').value;
    if (!['json', 'markdown', 'sarif'].includes(format)) return;
    state.exporting = true;
    updateControls();
    alertIn('export-alert', '');
    try {
      const result = await request(`/api/audits/${encodeURIComponent(auditId)}/export?format=${encodeURIComponent(format)}`, { blob: true });
      if (!result.blob) throw new ApiError('导出接口未返回可下载的报告。');
      const url = URL.createObjectURL(result.blob);
      const anchor = node('a');
      anchor.href = url;
      const safeId = String(auditId).replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 80);
      anchor.download = `localguard-${safeId}.${format === 'markdown' ? 'md' : format}`;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      announce('报告已交给浏览器下载。');
    } catch (error) { alertIn('export-alert', readable(error), exportReport, '重新导出'); }
    finally { state.exporting = false; updateControls(); }
  }

  $('form-tab').addEventListener('click', () => switchMode('form'));
  $('chat-tab').addEventListener('click', () => switchMode('chat'));
  document.querySelector('.mode-tabs').addEventListener('keydown', (event) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const mode = event.key === 'Home' ? 'form' : event.key === 'End' ? 'chat' : state.mode === 'form' ? 'chat' : 'form';
    switchMode(mode);
    $(`${mode}-tab`).focus();
  });
  $('target').addEventListener('input', () => $('target').setCustomValidity(''));
  $('include-dependencies').addEventListener('change', syncScannerControls);
  $('scanner-options').addEventListener('change', syncScannerControls);
  $('incremental').addEventListener('change', () => {
    const active = $('incremental').checked;
    $('incremental-fields').hidden = !active;
    $('incremental').setAttribute('aria-expanded', String(active));
    ['base', 'head'].forEach((id) => { $(id).disabled = !active; $(id).required = active; });
  });
  $('audit-form').addEventListener('submit', (event) => {
    event.preventDefault();
    if (state.mode === 'form') submitAudit(formArguments());
  });
  $('severity-filters').addEventListener('click', (event) => {
    const button = event.target.closest('button[data-severity]');
    if (!button) return;
    state.severity = button.dataset.severity;
    $('severity-filters').querySelectorAll('button').forEach((item) => item.setAttribute('aria-pressed', String(item === button)));
    schedulePills();
    renderIssues();
  });
  $('issue-search').addEventListener('input', renderIssues);
  $('review-filter').addEventListener('change', renderIssues);
  $('triage-filter').addEventListener('change', renderIssues);
  $('refresh-tree').addEventListener('click', loadTree);
  $('toggle-tree').addEventListener('click', () => {
    const hidden = !$('file-tree-pane').hidden;
    $('file-tree-pane').hidden = hidden;
    document.querySelector('.source-workspace').classList.toggle('tree-hidden', hidden);
    $('toggle-tree').setAttribute('aria-expanded', String(!hidden));
    $('toggle-tree').textContent = hidden ? '显示目录' : '隐藏目录';
  });
  $('previous-page').addEventListener('click', () => {
    const preview = state.preview;
    if (!preview || state.previewBusy) return;
    openFile(preview.path, preview.targetLine, preview.location, Math.max(1, (Number(preview.start_line) || preview.requestedStart) - PAGE_SIZE));
  });
  $('next-page').addEventListener('click', () => {
    const preview = state.preview;
    if (!preview || state.previewBusy) return;
    const end = Number(preview.end_line) || Math.min(preview.total_lines, preview.requestedStart + PAGE_SIZE - 1);
    openFile(preview.path, preview.targetLine, preview.location, end + 1);
  });
  $('jump-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const line = Number($('jump-line').value);
    if (!state.preview || state.previewBusy || !Number.isInteger(line) || line < 1 || line > state.preview.total_lines) return;
    openFile(state.preview.path, line, state.preview.location);
  });
  $('chat-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const shared = context();
    const message = $('chat-message').value.trim();
    if (!shared || !message || !state.ready || state.chatBusy || state.submitting || state.imageBusy || isActive()) return;
    sendChat({ message, ...shared, history: boundedHistory(state.history) });
    $('chat-message').value = '';
  });
  $('chat-message').addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && (event.ctrlKey || event.metaKey) && !event.isComposing) { event.preventDefault(); $('chat-form').requestSubmit(); }
  });
  $('clear-chat').addEventListener('click', () => {
    if (state.chatBusy) return;
    state.chatEpoch += 1;
    state.history = [];
    const empty = node('div', 'chat-empty', '对话已清空。已生成的审查报告不受影响。');
    empty.id = 'chat-empty';
    $('chat-log').replaceChildren(empty);
    announce('对话上下文已清空。');
  });
  $('image-file').addEventListener('change', (event) => selectImage(event.target.files?.[0]));
  $('image-dropzone').addEventListener('dragover', (event) => { event.preventDefault(); if (!state.imageBusy) $('image-dropzone').classList.add('dragging'); });
  $('image-dropzone').addEventListener('dragleave', (event) => { if (!$('image-dropzone').contains(event.relatedTarget)) $('image-dropzone').classList.remove('dragging'); });
  $('image-dropzone').addEventListener('drop', (event) => {
    event.preventDefault();
    $('image-dropzone').classList.remove('dragging');
    if (event.dataTransfer?.files.length > 1) { alertIn('image-alert', '请每次选择一张图片。'); return; }
    selectImage(event.dataTransfer?.files[0]);
  });
  // Do not let an accidental drop navigate away from the local review workspace.
  ['dragover', 'drop'].forEach((name) => window.addEventListener(name, (event) => {
    if ([...(event.dataTransfer?.types || [])].includes('Files')) event.preventDefault();
  }));
  $('remove-image').addEventListener('click', clearImage);
  $('analyze-image').addEventListener('click', analyzeImage);
  $('export-report').addEventListener('click', exportReport);
  $('stop-audit').addEventListener('click', stopAudit);
  $('resume-load').addEventListener('click', () => {
    const id = $('resume-select').value;
    if (!id) return;
    adoptAudit({ audit_id: id, status: 'queued' });
    if (state.ready) pollAudit(state.pollEpoch);
  });

  // ---- Sliding indicator for grouped buttons --------------------------------
  // The pill is absolutely positioned (out of flow) so moving it never
  // reflows the page. Position is derived from the actually-selected button,
  // so the animation can never drift out of sync with the ARIA state.
  const pillGroups = [
    { root: document.querySelector('.mode-tabs'), attr: 'aria-selected' },
    { root: $('severity-filters'), attr: 'aria-pressed' },
  ].filter((g) => g.root);

  function placePills() {
    for (const { root, attr } of pillGroups) {
      const pill = root.querySelector('.slide-pill');
      if (!pill) continue;
      const active = [...root.children].find((el) => el.tagName === 'BUTTON' && el.getAttribute(attr) === 'true');
      if (!active) { pill.classList.remove('ready'); continue; }
      // offsetLeft/Top are relative to the offsetParent (the group), and work
      // for wrapped rows on narrow screens as well.
      pill.style.width = `${active.offsetWidth}px`;
      pill.style.height = `${active.offsetHeight}px`;
      pill.style.transform = `translate(${active.offsetLeft}px, ${active.offsetTop}px)`;
      pill.classList.add('ready');
    }
  }

  let pillFrame = 0;
  function schedulePills() {
    if (pillFrame) return;                 // coalesce repeated triggers into one frame
    pillFrame = requestAnimationFrame(() => { pillFrame = 0; placePills(); });
  }
  const pillObserver = new ResizeObserver(schedulePills);
  for (const { root } of pillGroups) {
    pillObserver.observe(root);
    root.querySelectorAll('button').forEach((b) => pillObserver.observe(b));
  }
  // Re-measure after fonts settle: Saira changes label widths on first paint.
  if (document.fonts?.ready) document.fonts.ready.then(schedulePills);
  window.addEventListener('resize', schedulePills, { passive: true });
  schedulePills();

  // ---- Menu expand / collapse ----------------------------------------------
  // Native <details> toggles instantly. Animate the body height between 0 and
  // its natural height, then release the inline height so dynamic content can
  // still grow. In-flight animations are cancelled so rapid clicks never
  // leave a stale height or a stuck state.
  const menuAnimations = new WeakMap();
  document.querySelectorAll('#advanced-options').forEach((details) => {
    const body = details.querySelector('.advanced-body');
    const summary = details.querySelector('summary');
    if (!body || !summary) return;
    summary.addEventListener('click', (event) => {
      if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return; // keep native instant toggle
      event.preventDefault();
      const opening = !details.open;
      const existing = menuAnimations.get(body);
      if (existing) existing.cancel();
      details.open = true; // content must be in layout to measure
      const target = body.scrollHeight;
      const from = opening ? 0 : target;
      const to = opening ? target : 0;
      body.style.overflow = 'hidden';
      body.style.height = `${from}px`;
      const animation = body.animate(
        [{ height: `${from}px` }, { height: `${to}px` }],
        { duration: 180, easing: 'cubic-bezier(0.7,0,0.2,1)', fill: 'forwards' },
      );
      menuAnimations.set(body, animation);
      animation.finished.then(() => {
        if (menuAnimations.get(body) !== animation) return; // superseded by a newer click
        menuAnimations.delete(body);
        body.style.height = '';
        body.style.overflow = '';
        details.open = opening;
        schedulePills();
      }).catch(() => {}); // cancelled animation: a newer one owns the state
    });
  });

  window.addEventListener('beforeunload', () => { stopPolling(); if (state.imageUrl) URL.revokeObjectURL(state.imageUrl); });
  bootstrap();
})();
