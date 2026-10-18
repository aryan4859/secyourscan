// Single fetch wrapper for the SecYourScan API.
//
// - credentials: 'include' so the httpOnly `sys_access_token` cookie travels;
// - every non-GET request echoes the JS-readable `sys_csrf` cookie in
//   `X-SYS-CSRF` (double-submit CSRF, see backend/app/deps.py);
// - JSON in / JSON out, FastAPI error bodies turned into readable messages;
// - a 401 anywhere (except the login call itself) drops the session and the
//   app falls back to the Login screen.

const SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);

export class ApiError extends Error {
  constructor(status, message, data) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

let unauthorizedHandler = () => {};
export function onUnauthorized(fn) {
  unauthorizedHandler = fn;
}

export function readCookie(name) {
  const m = document.cookie.split('; ').find((c) => c.startsWith(`${name}=`));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : '';
}

export function qs(params = {}) {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    if (Array.isArray(v)) v.forEach((x) => sp.append(k, x));
    else sp.append(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : '';
}

function formatDetail(detail, fallback) {
  if (!detail) return fallback;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d) => {
        const loc = Array.isArray(d.loc) ? d.loc.filter((x) => x !== 'body').join('.') : '';
        return loc ? `${loc}: ${d.msg}` : d.msg || JSON.stringify(d);
      })
      .join('; ');
  }
  return JSON.stringify(detail);
}

/**
 * request(method, path, { params, json, form, signal, raw })
 *  - json: object sent as application/json
 *  - form: object sent as application/x-www-form-urlencoded
 *  - raw:  return the Response untouched (downloads, SSE)
 */
export async function request(method, path, { params, json, form, signal, raw = false, skipAuthRedirect = false } = {}) {
  const headers = { Accept: raw ? '*/*' : 'application/json' };
  let body;
  if (json !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(json);
  } else if (form !== undefined) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    body = new URLSearchParams(form).toString();
  }
  if (!SAFE.has(method)) {
    const csrf = readCookie('sys_csrf');
    if (csrf) headers['X-SYS-CSRF'] = csrf;
  }

  let res;
  try {
    res = await fetch(path + qs(params), { method, headers, body, signal, credentials: 'include' });
  } catch (e) {
    if (e.name === 'AbortError') throw e;
    throw new ApiError(0, 'Network error: the API is unreachable', null);
  }

  if (res.status === 401 && !skipAuthRedirect) {
    unauthorizedHandler();
  }
  if (!res.ok) {
    let data = null;
    try {
      data = await res.json();
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, formatDetail(data?.detail, `${res.status} ${res.statusText || 'error'}`), data);
  }
  if (raw) return res;
  if (res.status === 204) return null;
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

const get = (path, params, opts) => request('GET', path, { params, ...opts });
const post = (path, json, opts) => request('POST', path, { json, ...opts });
const patch = (path, json, opts) => request('PATCH', path, { json, ...opts });
const put = (path, json, opts) => request('PUT', path, { json, ...opts });
const del = (path, opts) => request('DELETE', path, opts);

// ── Downloads ────────────────────────────────────────────────────────────────

function filenameFrom(res, fallback) {
  const cd = res.headers.get('Content-Disposition') || '';
  const m = /filename="?([^";]+)"?/i.exec(cd);
  return m ? m[1] : fallback;
}

export function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Fetch a file, save it, and return its response headers. */
export async function download(path, params, fallbackName) {
  const res = await request('GET', path, { params, raw: true });
  const blob = await res.blob();
  saveBlob(blob, filenameFrom(res, fallbackName));
  return res.headers;
}

// ── Endpoints ────────────────────────────────────────────────────────────────

export const api = {
  // auth / session
  login: (username, password) =>
    request('POST', '/auth/login', { form: { username, password }, skipAuthRedirect: true }),
  logout: () => request('POST', '/auth/logout', { skipAuthRedirect: true }),
  me: () => get('/users/me', undefined, { skipAuthRedirect: true }),
  updateMe: (body) => put('/users/me', body),

  // users / tenants / keys (admin)
  users: () => get('/users'),
  createUser: (body) => post('/users', body),
  updateUser: (id, body) => patch(`/users/${encodeURIComponent(id)}`, body),
  tenants: () => get('/tenants'),
  createTenant: (body) => post('/tenants', body),
  deleteTenant: (id) => del(`/tenants/${encodeURIComponent(id)}`),
  apiKeys: () => get('/api-keys'),
  createApiKey: (body) => post('/api-keys', body),
  revokeApiKey: (id) => del(`/api-keys/${encodeURIComponent(id)}`),

  // leaks
  leaks: (params, signal) => get('/leaks/', params, { signal }),
  searchLeaks: (params, signal) => get('/leaks/search', params, { signal }),
  stats: () => get('/leaks/stats'),
  insights: (days) => get('/leaks/insights', { days }),
  darkweb: (days) => get('/leaks/darkweb', { days }),
  topology: (params) => get('/leaks/topology', params),
  leak: (id, signal) => get(`/leaks/${encodeURIComponent(id)}`, undefined, { signal }),
  setLeakStatus: (id, status) => patch(`/leaks/${encodeURIComponent(id)}/status`, { status }),
  ackLeak: (id) => post(`/leaks/${encodeURIComponent(id)}/ack`),
  ackAll: (minSeverity = 80) => request('POST', '/leaks/ack-all', { params: { min_severity: minSeverity } }),
  downloadEvidence: (id) => download(`/leaks/${encodeURIComponent(id)}/evidence`, undefined, `evidence-${id}.txt`),
  exportCsv: () => download('/leaks/export/csv', undefined, 'leaks.csv'),
  exportDossier: (minSeverity) => download('/leaks/export/dossier', { min_severity: minSeverity }, 'dossier.pdf'),
  downloadPublicKey: () => download('/leaks/export/public-key', undefined, 'dossier-public-key.pem'),

  // watchlist
  watchlist: () => get('/watchlist'),
  watchExposure: () => get('/watchlist/exposure'),
  watchInsights: (id) => get(`/watchlist/${encodeURIComponent(id)}/insights`),
  addWatch: (body) => post('/watchlist', body),
  updateWatch: (id, body) => patch(`/watchlist/${encodeURIComponent(id)}`, body),
  deleteWatch: (id) => del(`/watchlist/${encodeURIComponent(id)}`),

  // sources & recon
  sources: () => get('/sources'),
  addSource: (body) => post('/sources', body),
  updateSource: (id, body) => patch(`/sources/${encodeURIComponent(id)}`, body),
  deleteSource: (id) => del(`/sources/${encodeURIComponent(id)}`),
  runSource: (id) => post(`/sources/${encodeURIComponent(id)}/run`),
  runs: (params) => get('/sources/runs', params),
  run: (id) => get(`/sources/runs/${encodeURIComponent(id)}`),
  reconDarkweb: (q) => get('/recon/darkweb', { q }),
  reconTelegram: (channel) => get('/recon/telegram', { channel }),
  reconShodan: (ip) => get('/recon/shodan', { ip }),

  // report
  reportDomains: () => get('/report/domains'),
  domainReport: (domain) => get(`/report/domain/${encodeURIComponent(domain)}`),
  domainReportPdf: (domain) => download(`/report/domain/${encodeURIComponent(domain)}/pdf`, undefined, `exposure-${domain}.pdf`),

  // domains
  domains: () => get('/domains'),
  addDomain: (domain) => post('/domains', { domain }),
  verifyDomain: (id) => post(`/domains/${encodeURIComponent(id)}/verify`),
  deleteDomain: (id) => del(`/domains/${encodeURIComponent(id)}`),

  // external risk
  intelStatus: () => get('/intel/status'),
  intelSummary: () => get('/intel/summary'),
  intelScan: (module) => post(`/intel/scan/${encodeURIComponent(module)}`),
  surfaceHosts: () => get('/surface/hosts'),
  surfacePorts: () => get('/surface/ports'),
  surfaceTls: () => get('/surface/tls'),
  surfaceDns: () => get('/surface/dns'),
  surfaceEvents: (limit = 200) => get('/surface/events', { limit }),
  vulns: (status = 'open') => get('/vulns', { status }),
  updateVuln: (id, status) => patch(`/vulns/${encodeURIComponent(id)}`, { status }),
  lookalikes: () => get('/brand/lookalikes'),
  phishing: () => get('/brand/phishing'),
  updatePhishing: (id, status) => patch(`/brand/phishing/${encodeURIComponent(id)}`, { status }),
  updateLookalike: (id, status) => patch(`/brand/lookalikes/${encodeURIComponent(id)}`, { status }),
  ransomwareHits: () => get('/ransomware/hits'),
  updateRansomwareHit: (id, status) => patch(`/ransomware/hits/${encodeURIComponent(id)}`, { status }),
  ransomwareActivity: (days = 7) => get('/ransomware/activity', { days }),

  // yara
  yaraRules: () => get('/yara/rules'),
  createYara: (body) => post('/yara/rules', body),
  deleteYara: (id) => del(`/yara/rules/${encodeURIComponent(id)}`),
  testYara: (content, sample) => post('/yara/test', { content, sample }),

  // notifications
  notifications: (params) => get('/notifications', params),
  ackNotification: (id) => post(`/notifications/${encodeURIComponent(id)}/ack`),

  // ai
  aiHealth: () => get('/ai/health'),
  plans: () => get('/ai/plans'),
  createPlan: (body) => post('/ai/plans', body),
  updatePlan: (id, body) => patch(`/ai/plans/${encodeURIComponent(id)}`, body),
  deletePlan: (id) => del(`/ai/plans/${encodeURIComponent(id)}`),
  addTask: (planId, title) => post(`/ai/plans/${encodeURIComponent(planId)}/tasks`, { title }),
  updateTask: (planId, taskId, status) =>
    patch(`/ai/plans/${encodeURIComponent(planId)}/tasks/${encodeURIComponent(taskId)}`, { status }),

  // system
  health: async () => {
    // 503 still carries the component map; surface it instead of throwing.
    try {
      return await get('/system/health');
    } catch (e) {
      if (e instanceof ApiError && e.status === 503 && e.data?.components) return e.data;
      throw e;
    }
  },
  status: () => get('/system/status'),
  license: () => get('/system/license'),
  audit: (params) => get('/system/audit', params),
  verifyAudit: () => get('/system/audit/verify'),
  exportAudit: () => download('/system/audit/export.csv', undefined, 'audit.csv'),
};

/**
 * POST /ai/chat and read the Server-Sent Events stream with a ReadableStream
 * reader (EventSource cannot POST or send the CSRF header). Calls onEvent for
 * every `data: {json}` line.
 */
export async function streamChat(messages, onEvent, signal) {
  const res = await request('POST', '/ai/chat', { json: { messages }, signal, raw: true });
  if (!res.body) throw new ApiError(0, 'Streaming is not supported by this browser', null);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  const flush = (block) => {
    const data = block
      .split(/\r?\n/)
      .filter((l) => l.startsWith('data:'))
      .map((l) => l.slice(5).replace(/^ /, ''))
      .join('\n');
    if (!data) return;
    try {
      onEvent(JSON.parse(data));
    } catch {
      onEvent({ type: 'error', message: 'Malformed event from server' });
    }
  };
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buffer.search(/\r?\n\r?\n/)) !== -1) {
      const block = buffer.slice(0, idx);
      buffer = buffer.slice(idx).replace(/^\r?\n\r?\n/, '');
      flush(block);
    }
  }
  buffer += decoder.decode();
  if (buffer.trim()) flush(buffer);
}
