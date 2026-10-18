const CF_BASE = "https://api.cloudflare.com/client/v4";
const COOKIE = "nexa_session";
const SESSION_TTL = 7 * 24 * 3600;

const READ_ONLY_PERMISSION_KEYS = [
  "access_audit_log", "account_analytics", "analytics", "domain_page",
  "domain_page_shield", "radar", "request_tracer", "teams_pii", "workers_tail",
];
const SPECIAL_TYPE_PERMISSIONS = { cache: "purge" };
const USER_SCOPED_PERMISSION_KEYS = ["api_tokens", "memberships", "notifications", "user_details"];

const ALL_ACCOUNT_PERMISSION_KEYS = [
  "access", "access_acct", "access_certificate", "access_custom_page",
  "access_device_posture", "access_population", "access_seats",
  "access_service_token", "access_ssh_auditing",
  "account_analytics", "account_api_gateway", "account_api_tokens",
  "account_custom_pages", "account_disable_esc", "account_dns_settings",
  "account_firewall_access_rules", "account_logs", "account_rule_lists",
  "account_rule_policies", "account_rulesets", "account_settings",
  "account_ssl_and_certificates", "account_waf",
  "address_maps", "ai", "aiaudit", "aig", "analytics", "api_gateway",
  "apps", "argotunnel",
  "billing", "bot_management", "bot_management_feedback", "browser_rendering",
  "cache", "cache_settings", "calls", "challenge_widgets",
  "chinanetwork_steering", "cloud_connector", "cloud_email_security",
  "cloudchamber", "cloudforce_one", "config_settings", "constellation",
  "custom_errors", "custom_pages",
  "d1", "ddos_botnet_feed", "ddos_protection", "dns", "dns_firewall",
  "dns_view", "domain_page", "domain_page_shield", "dynamic_redirect",
  "email_routing_address", "email_routing_rule", "email_security_dmarcreports",
  "fbm", "firewall_services", "fraud_detection",
  "healthcheck", "http_applications", "http_ddos_managed_ruleset",
  "images", "integration", "intel", "iot", "ip_prefix",
  "ip_prefix_bgp_on_demand",
  "l4_ddos_managed_ruleset", "load_balancers", "load_balancers_account",
  "load_balancing_monitors_and_pools", "logs",
  "magic_firewall", "magic_transit", "managed_headers", "mass_url_redirects",
  "origin",
  "page", "page_rules", "page_shield", "pcaps_api", "pipelines", "pubsub",
  "query_cache", "queues",
  "radar", "request_tracer", "response_compression",
  "sanitize", "scim_provisioning", "select_configuration", "snippets",
  "ssl_and_certificates", "stream",
  "teams", "teams_cds_compute_account", "teams_connector_cloudflared",
  "teams_connector_warp", "teams_connectors", "teams_dex", "teams_networks",
  "teams_pii", "transform_rules",
  "url_scanner",
  "vectorize",
  "waiting_rooms", "web3_hostnames", "workers_ci", "workers_kv_storage",
  "workers_r2", "workers_r2_bucket_item", "workers_routes", "workers_scripts",
  "workers_subdomain", "workers_tail",
  "zaraz",
  "zone", "zone_access", "zone_disable_esc", "zone_dns_settings",
  "zone_settings", "zone_transform_rules", "zone_versioning", "zone_waf",
];

function permEntry(key) {
  return { key, type: SPECIAL_TYPE_PERMISSIONS[key] || (READ_ONLY_PERMISSION_KEYS.includes(key) ? "read" : "edit") };
}
const ACCOUNT_TOKEN_PERMISSIONS =
  ALL_ACCOUNT_PERMISSION_KEYS.filter(k => !USER_SCOPED_PERMISSION_KEYS.includes(k)).map(permEntry);
const USER_TOKEN_PERMISSIONS =
  [...ALL_ACCOUNT_PERMISSION_KEYS, ...USER_SCOPED_PERMISSION_KEYS].map(permEntry);

const TOKEN_TEMPLATE_NAME = "Nexa-Manager";

function buildTokenCreateUrl(kind, tokenName) {
  const list = kind === "user" ? USER_TOKEN_PERMISSIONS : ACCOUNT_TOKEN_PERMISSIONS;
  const perms = encodeURIComponent(JSON.stringify(list));
  const name = encodeURIComponent(tokenName || TOKEN_TEMPLATE_NAME);
  if (kind === "user") {
    return `https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=${perms}&accountId=*&zoneId=all&name=${name}`;
  }
  return `https://dash.cloudflare.com/?to=/:account/api-tokens&permissionGroupKeys=${perms}&name=${name}`;
}

class ApiError extends Error {
  constructor(message, status = 400, extra = {}) {
    super(typeof message === "object" ? JSON.stringify(message) : message);
    this.status = status;
    this.details = extra.details || null;
    this.step = extra.step || null;
    this.logs = extra.logs || [];
  }
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });
}

function errMsg(res) {
  if (!res) return "پاسخی از Cloudflare دریافت نشد";
  if (typeof res === "string") return res;
  if (res.message) return res.message;
  if (res.error) return typeof res.error === "string" ? res.error : JSON.stringify(res.error);
  if (Array.isArray(res.errors) && res.errors.length > 0) {
    return res.errors
      .map(e => {
        if (!e) return "خطای نامشخص";
        if (typeof e === "string") return e;
        const msg = e.message || e.error || e.code;
        return msg ? (e.code ? `[کد ${e.code}] ${msg}` : msg) : JSON.stringify(e);
      })
      .join(" | ");
  }
  if (Array.isArray(res.messages) && res.messages.length > 0) {
    return res.messages.map(m => typeof m === "string" ? m : m.message || JSON.stringify(m)).join(" | ");
  }
  if (res.statusText) return `HTTP ${res.status}: ${res.statusText}`;
  if (res.status) return `HTTP ${res.status}`;
  try {
    const s = JSON.stringify(res);
    return s !== "{}" ? s : "پاسخ ناموفق از سرور (success: false)";
  } catch {
    return String(res);
  }
}

function assertOk(res, label) {
  if (!res || res.success !== true) throw new ApiError(`${label}: ${errMsg(res)}`, 502, { details: res });
  return res.result;
}

function today() { return new Date().toISOString().slice(0, 10); }

function randomToken(nbytes = 32) {
  const b = crypto.getRandomValues(new Uint8Array(nbytes));
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

const NAME_SYLLABLES = [
  "bj", "bk", "bv", "cb", "cd", "cj", "ck", "cv", "dk", "dv",
  "fj", "fp", "fv", "gb", "gj", "gk", "gv", "gz", "hj", "hk",
  "jb", "jd", "jf", "jk", "jl", "jv", "kb", "kd", "kf", "kj",
  "kl", "kp", "kt", "kv", "kz", "lb", "lj", "lk", "mb", "md",
  "mj", "mk", "mv", "nb", "nj", "nk", "nv", "qb", "qd", "qj",
  "ql", "qv", "rb", "rj", "rk", "rz", "sj", "sk", "sv", "tb",
  "tj", "tk", "vb", "vj", "vk", "xb", "xj", "xk", "zb", "zj",
  "zk", "zv",
];

function randomShortName(syllables = 2) {
  const bytes = crypto.getRandomValues(new Uint8Array(syllables));
  let name = "", last = -1;
  for (const b of bytes) {
    let i = b % NAME_SYLLABLES.length;
    if (i === last) i = (i + 1) % NAME_SYLLABLES.length;
    last = i;
    name += NAME_SYLLABLES[i];
  }
  return name;
}

function randomShortNameForAttempt(attempt) {
  return randomShortName(attempt < 3 ? 2 : 3);
}

function getCookie(req, name) {
  const h = req.headers.get("Cookie") || "";
  for (const part of h.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}

let schemaReady = false;
async function ensureSchema(env) {
  if (!env.DB) throw new ApiError("اتصال D1 پیدا نشد — binding DB را به ورکر اضافه کنید.", 500);
  if (schemaReady) return;
  await env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS profiles (
      name TEXT PRIMARY KEY,
      token TEXT NOT NULL,
      account_id TEXT NOT NULL,
      virex_workers TEXT NOT NULL DEFAULT '[]',
      nexa_workers TEXT NOT NULL DEFAULT '[]',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS scripts (
      key TEXT PRIMARY KEY,
      content TEXT NOT NULL,
      source TEXT NOT NULL DEFAULT 'file',
      source_url TEXT,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      expires_at INTEGER NOT NULL
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS worker_urls (
      profile TEXT NOT NULL,
      worker TEXT NOT NULL,
      url TEXT NOT NULL,
      PRIMARY KEY (profile, worker)
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS health_config (
      profile TEXT NOT NULL,
      worker TEXT NOT NULL,
      path TEXT NOT NULL DEFAULT '/',
      PRIMARY KEY (profile, worker)
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS health_checks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      checked_at TEXT NOT NULL DEFAULT (datetime('now')),
      profile TEXT NOT NULL,
      worker TEXT NOT NULL,
      type TEXT NOT NULL,
      status TEXT NOT NULL,
      http_status INTEGER,
      message TEXT,
      fixed_at TEXT
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS pages_scripts (
      profile TEXT NOT NULL,
      project TEXT NOT NULL,
      script TEXT,
      script_key TEXT,
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (profile, project)
    )`),
  ]);
  for (const ddl of ["ALTER TABLE profiles ADD COLUMN pos INTEGER NOT NULL DEFAULT 0", "ALTER TABLE scripts ADD COLUMN source TEXT NOT NULL DEFAULT 'file'", "ALTER TABLE scripts ADD COLUMN source_url TEXT"]) {
    try { await env.DB.prepare(ddl).run(); } catch {}
  }
  schemaReady = true;
}

async function getSetting(env, key) {
  const row = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind(key).first();
  return row ? row.value : null;
}
async function setSetting(env, key, value) {
  await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(key, String(value)).run();
}
async function delSetting(env, key) {
  await env.DB.prepare("DELETE FROM settings WHERE key = ?").bind(key).run();
}

function adminPassword(env) {
  return typeof env.ADMIN === "string" ? env.ADMIN : "";
}

async function requireSession(req, env) {
  const tok = getCookie(req, COOKIE);
  if (!tok) throw new ApiError("unauthorized", 401);
  const row = await env.DB.prepare("SELECT token FROM sessions WHERE token = ? AND expires_at > ?")
    .bind(tok, Math.floor(Date.now() / 1000)).first();
  if (!row) throw new ApiError("unauthorized", 401);
  return tok;
}

function sessionCookie(tok) {
  return `${COOKIE}=${tok}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL}`;
}
function clearSessionCookie() {
  return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

async function cfFetch(token, path, opts = {}) {
  const { method = "GET", body, formData, raw = false, contentType = "application/json" } = opts;
  const headers = { Authorization: `Bearer ${token}` };
  if (!formData && body !== undefined) headers["Content-Type"] = contentType;
  let res;
  try {
    res = await fetch(`${CF_BASE}${path}`, {
      method,
      headers,
      body: formData ? formData : (
        body !== undefined
          ? (typeof body === "string" && contentType !== "application/json" ? body : JSON.stringify(body))
          : undefined
      ),
    });
  } catch (e) {
    if (raw) return new Response(`{"error":"network: ${e.message}"}`, { status: 502 });
    return { success: false, errors: [{ message: `network: ${e.message}` }] };
  }
  if (raw) return res;
  try { return await res.json(); }
  catch { return { success: false, errors: [{ message: `HTTP ${res.status}` }] }; }
}
const cfGet = (t, p, o) => cfFetch(t, p, { method: "GET", ...o });
const cfPost = (t, p, b, o) => cfFetch(t, p, { method: "POST", body: b, ...o });
const cfPut = (t, p, b, o) => cfFetch(t, p, { method: "PUT", body: b, ...o });
const cfPatch = (t, p, b, o) => cfFetch(t, p, { method: "PATCH", body: b, ...o });
const cfDelete = (t, p, o) => cfFetch(t, p, { method: "DELETE", ...o });

async function fetchAccountEmail(token) {
  try {
    const res = await cfGet(token, "/user");
    if (res && res.success) return (res.result && res.result.email) || null;
  } catch {}
  return null;
}

async function fetchAccountsForToken(token) {
  const res = await cfGet(token, "/accounts");
  if (!res || !res.success) return [];
  return res.result || [];
}

async function fetchAccountName(token, accountId) {
  try {
    const accounts = await fetchAccountsForToken(token);
    const acc = (accounts || []).find(a => a.id === accountId);
    return acc ? (acc.name || null) : null;
  } catch {}
  return null;
}

async function listProfiles(env) {
  const { results } = await env.DB.prepare("SELECT * FROM profiles ORDER BY pos, created_at, name").all();
  return (results || []).map(r => ({
    name: r.name,
    account_id: r.account_id,
    token_masked: r.token ? (r.token.slice(0, 6) + "…" + r.token.slice(-4)) : "",
    nexa_workers: JSON.parse(r.nexa_workers || "[]"),
    created_at: r.created_at,
  }));
}

async function getProfileRow(env, name) {
  const row = await env.DB.prepare("SELECT * FROM profiles WHERE name = ?").bind(name).first();
  if (!row) throw new ApiError(`پروفایل «${name}» پیدا نشد`, 404);
  return { ...row, nexa_workers: JSON.parse(row.nexa_workers || "[]") };
}

async function saveFlags(env, name, nexa) {
  await env.DB.prepare("UPDATE profiles SET nexa_workers = ?, updated_at = datetime('now') WHERE name = ?")
    .bind(JSON.stringify([...nexa]), name).run();
}

async function resolveProfile(env, url) {
  const name = url.searchParams.get("profile");
  if (!name) throw new ApiError("پارامتر profile الزامی است", 400);
  return getProfileRow(env, name);
}

async function fetchWorkers(token, accountId) {
  const res = await cfGet(token, `/accounts/${accountId}/workers/scripts`);
  return res && res.success ? (res.result || []) : [];
}

async function fetchBindings(token, accountId, name) {
  const res = await cfGet(token, `/accounts/${accountId}/workers/scripts/${encodeURIComponent(name)}/bindings`);
  return res && res.success ? (res.result || []) : [];
}

async function fetchCloudflarePaginatedArray(token, path, label) {
  const all = [];
  const perPage = 100;
  for (let page = 1; page <= 100; page++) {
    const query = new URLSearchParams({ page: String(page), per_page: String(perPage) });
    const separator = path.includes("?") ? "&" : "?";
    const res = await cfGet(token, `${path}${separator}${query.toString()}`);
    if (!res || res.success !== true || !Array.isArray(res.result)) {
      throw new ApiError(`${label}: ${errMsg(res)}`, 502);
    }
    all.push(...res.result);
    const info = res.result_info || {};
    const totalPages = Number(info.total_pages || (info.total_count ? Math.ceil(Number(info.total_count) / Number(info.per_page || perPage)) : 0));
    if (totalPages && page >= totalPages) return all;
    if (!totalPages && res.result.length < perPage) return all;
    if (!res.result.length) return all;
  }
  throw new ApiError(`${label}: فهرست بیش از حد صفحه داشت و کامل نشد`, 502);
}

async function fetchAccountZonesStrict(token, accountId) {
  return fetchCloudflarePaginatedArray(token, `/zones?account.id=${encodeURIComponent(accountId)}`, "خواندن Zoneهای اکانت ناموفق بود");
}

async function fetchZoneRoutesStrict(token, zoneId) {
  return fetchCloudflarePaginatedArray(token, `/zones/${encodeURIComponent(zoneId)}/workers/routes`, `خواندن Routeهای Zone «${zoneId}» ناموفق بود`);
}

async function fetchWorkerRoutesStrict(token, accountId, workerName) {
  try {
    const direct = await cfGet(token, `/accounts/${accountId}/workers/scripts/${encodeURIComponent(workerName)}/routes`);
    if (direct?.success === true && Array.isArray(direct.result)) {
      if (!direct.result.length) return { zones: [], routes: [] };
      if (direct.result.every(route => route && route.pattern && route.zone_id)) {
        return { zones: [], routes: direct.result.filter(route => route.script === workerName) };
      }
    }
  } catch {}

  const zones = await fetchAccountZonesStrict(token, accountId);
  const routes = [];
  for (const zone of zones) {
    if (!zone || !zone.id) throw new ApiError("یکی از Zoneهای اکانت شناسه ندارد؛ امکان بکاپ‌گیری کامل از Routeها نیست", 502);
    const zoneRoutes = await fetchZoneRoutesStrict(token, zone.id);
    for (const route of zoneRoutes) {
      if (route && route.script === workerName) routes.push({ ...route, zone_id: zone.id });
    }
  }
  return { zones, routes };
}

async function fetchWorkerDomainsStrict(token, accountId, filters = {}) {
  const all = [];
  const perPage = 100;
  for (let page = 1; page <= 100; page++) {
    const query = new URLSearchParams({ page: String(page), per_page: String(perPage) });
    if (filters.service) query.set("service", filters.service);
    if (filters.hostname) query.set("hostname", filters.hostname);
    const res = await cfGet(token, `/accounts/${accountId}/workers/domains?${query.toString()}`);
    if (!res || res.success !== true || !Array.isArray(res.result)) {
      throw new ApiError(`دریافت دامنه‌های Worker ناموفق بود: ${errMsg(res)}`, 502);
    }
    all.push(...res.result);
    const info = res.result_info || {};
    const totalPages = Number(info.total_pages || (info.total_count ? Math.ceil(Number(info.total_count) / Number(info.per_page || perPage)) : 0));
    if (totalPages && page >= totalPages) return all;
    if (!totalPages && res.result.length < perPage) return all;
    if (!res.result.length) return all;
  }
  throw new ApiError("خواندن فهرست دامنه‌های Worker بیش از حد صفحه داشت و کامل نشد", 502);
}

async function fetchKvNamespaces(token, accountId) {
  const res = await cfGet(token, `/accounts/${accountId}/storage/kv/namespaces`);
  return res && res.success ? (res.result || []) : [];
}

async function fetchD1Databases(token, accountId) {
  const res = await cfGet(token, `/accounts/${accountId}/d1/database`);
  return res && res.success ? (res.result || []) : [];
}

async function workerExists(token, accountId, name) {
  const res = await cfFetch(token, `/accounts/${accountId}/workers/scripts/${encodeURIComponent(name)}`, { raw: true });
  return res.status === 200;
}

async function randomAvailableWorkerName(token, accountId) {
  for (let attempt = 0; attempt < 8; attempt++) {
    const name = randomShortNameForAttempt(attempt);
    const response = await cfFetch(token, `/accounts/${accountId}/workers/scripts/${encodeURIComponent(name)}`, { raw: true });
    if (response.status === 404) return name;
    if (response.status === 200) continue;
    let message = `HTTP ${response.status}`;
    try { message = errMsg(await response.clone().json()); } catch {}
    throw new ApiError(`بررسی یکتایی نام تصادفی Worker ناموفق بود: ${message}`, 502);
  }
  throw new ApiError("پس از چند تلاش نام یکتای تصادفی برای Worker پیدا نشد", 502);
}

function bindingsToMetadata(bindings) {
  return (bindings || []).map(b => {
    const e = { type: b.type, name: b.name || "" };
    if (b.type === "kv_namespace") e.namespace_id = b.namespace_id || "";
    else if (b.type === "d1") e.database_id = b.database_id || "";
    else if (b.type === "plain_text" || b.type === "secret_text") e.text = b.text || "";
    return e;
  });
}

async function getWorkerScript(token, accountId, name) {
  const res = await cfFetch(token, `/accounts/${accountId}/workers/scripts/${encodeURIComponent(name)}/content`, { raw: true });
  const ct = res.headers.get("Content-Type") || "";
  if (ct.includes("multipart/form-data")) {
    const m = ct.match(/boundary="?([^";]+)"?/);
    if (!m) throw new ApiError("پاسخ چندبخشی بود ولی boundary پیدا نشد.", 502);
    const text = await res.text();
    const parts = text.split("--" + m[1]);
    for (let part of parts) {
      part = part.replace(/^\r*\n/, "").replace(/\r*\n--$/, "");
      if (!part) continue;
      let head, body, sep = part.indexOf("\r\n\r\n"), seplen = 4;
      if (sep < 0) { sep = part.indexOf("\n\n"); seplen = 2; }
      if (sep < 0) continue;
      head = part.slice(0, sep);
      body = part.slice(sep + seplen).replace(/\r*\n$/, "");
      if (head.includes('name="worker.js"') || head.includes('filename="worker.js"')) return body;
    }
    throw new ApiError("فایل worker.js داخل پاسخ چندبخشی پیدا نشد.", 502);
  }
  if (res.status !== 200) {
    let msg = `HTTP ${res.status}`;
    try {
      const j = await res.clone().json();
      msg = errMsg(j);
    } catch {}
    throw new ApiError(`دریافت کد فعلی ورکر ناموفق بود: ${msg}`, 502);
  }
  return res.text();
}

function deployWorker(token, accountId, name, code, bindings, extra = {}) {
  const metadata = {
    main_module: "worker.js",
    compatibility_date: today(),
    bindings: bindings || [],
    ...extra,
  };
  const fd = new FormData();
  fd.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }), "metadata.json");
  fd.append("worker.js", new Blob([code], { type: "application/javascript+module" }), "worker.js");
  return cfFetch(token, `/accounts/${accountId}/workers/scripts/${encodeURIComponent(name)}`, { method: "PUT", formData: fd });
}

function isModuleWorker(code) {
  return /(^|[\s;}])export\s+(default\b|\{|const\b|function\b|class\b|async\b)/m.test(String(code || "")) ||
    /(^|[\s;}])import\s+[\w{*"'`]/m.test(String(code || ""));
}

async function uploadWorkerCodeOnly(token, accountId, name, code) {
  const module = isModuleWorker(code);
  const fileName = "worker.js";
  const meta = module ? { main_module: fileName } : { body_part: fileName };
  const fd = new FormData();
  fd.append("metadata", new Blob([JSON.stringify(meta)], { type: "application/json" }), "metadata.json");
  fd.append(fileName, new Blob([code], { type: module ? "application/javascript+module" : "application/javascript" }), fileName);
  let res = await cfFetch(token, `/accounts/${accountId}/workers/scripts/${encodeURIComponent(name)}/content`, { method: "PUT", formData: fd });
  if (res && res.success === true) return { res, method: "content", module };

  const firstErr = errMsg(res);
  let compat = {};
  try {
    const st = await cfGet(token, `/accounts/${accountId}/workers/scripts/${encodeURIComponent(name)}/settings`);
    if (st?.success && st.result) {
      if (st.result.compatibility_date) compat.compatibility_date = st.result.compatibility_date;
      if (Array.isArray(st.result.compatibility_flags) && st.result.compatibility_flags.length) compat.compatibility_flags = st.result.compatibility_flags;
    }
  } catch {}
  const metadata = {
    ...(module ? { main_module: fileName } : { body_part: fileName }),
    compatibility_date: compat.compatibility_date || today(),
    ...(compat.compatibility_flags ? { compatibility_flags: compat.compatibility_flags } : {}),
    bindings: [],
    keep_bindings: ["plain_text", "secret_text", "kv_namespace", "d1", "r2_bucket", "service", "durable_object_namespace",
      "queue", "analytics_engine", "ai", "browser", "vectorize", "hyperdrive", "mtls_certificate", "version_metadata", "assets", "secrets_store_secret", "workflow", "dispatch_namespace", "send_email", "wasm_module", "text_blob", "data_blob", "json", "inherit"],
  };
  const fd2 = new FormData();
  fd2.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }), "metadata.json");
  fd2.append(fileName, new Blob([code], { type: module ? "application/javascript+module" : "application/javascript" }), fileName);
  res = await cfFetch(token, `/accounts/${accountId}/workers/scripts/${encodeURIComponent(name)}`, { method: "PUT", formData: fd2 });
  if (res && res.success === true) return { res, method: "full_keep_bindings", module };
  throw new ApiError(`آپلود کد روی ورکر «${name}» ناموفق بود: ${errMsg(res) || firstErr}`, 502, { details: res });
}

async function rebuildWithBindings(token, accountId, name, newBindings, code = null) {
  if (code === null) code = await getWorkerScript(token, accountId, name);
  return deployWorker(token, accountId, name, code, newBindings);
}

function updateBindingsOnly(token, accountId, name, bindings) {
  const fd = new FormData();
  fd.append("settings", new Blob([JSON.stringify({ bindings })], { type: "application/json" }), "settings.json");
  return cfFetch(token, `/accounts/${accountId}/workers/scripts/${encodeURIComponent(name)}/settings`, { method: "PATCH", formData: fd });
}

async function applyBindings(token, accountId, name, bindings) {
  let res = await updateBindingsOnly(token, accountId, name, bindings);
  if (!res || res.success !== true) {
    res = await rebuildWithBindings(token, accountId, name, bindings);
  }
  assertOk(res, "به‌روزرسانی بایندینگ‌ها");
  return res;
}

async function enableSubdomain(token, accountId, name, enabled = true) {
  return cfPost(token, `/accounts/${accountId}/workers/scripts/${encodeURIComponent(name)}/subdomain`, { enabled });
}

async function getSubdomain(token, accountId) {
  const res = await cfGet(token, `/accounts/${accountId}/workers/subdomain`);
  return res && res.success && res.result ? (res.result.subdomain || null) : null;
}

async function workerUrl(token, accountId, name) {
  const sub = await getSubdomain(token, accountId);
  return `https://${name}.${sub ? sub + "." : ""}workers.dev`;
}

async function createPagesProject(token, accountId, name) {
  return cfPost(token, `/accounts/${accountId}/pages/projects`, {
    name,
    production_branch: "main",
  });
}

async function getOrCreatePagesProject(token, accountId, name) {
  try {
    const res = await cfGet(token, `/accounts/${accountId}/pages/projects/${encodeURIComponent(name)}`);
    if (res && res.success && res.result) {
      return { result: res.result, success: true, skipped: true };
    }
  } catch {}
  const createRes = await createPagesProject(token, accountId, name);
  if (createRes && createRes.success) return createRes;
  if (errMsg(createRes).toLowerCase().includes("already exists")) {
    return { success: true, skipped: true };
  }
  return createRes;
}

async function getOrCreateD1Database(token, accountId, name) {
  try {
    const list = await fetchD1Databases(token, accountId);
    const existing = (list || []).find(d => d.name === name);
    if (existing) {
      return { uuid: existing.uuid || existing.id, name: existing.name, skipped: true, success: true };
    }
  } catch {}
  const res = await cfPost(token, `/accounts/${accountId}/d1/database`, { name });
  if (res && res.success && res.result) {
    return { uuid: res.result.uuid || res.result.id, name: res.result.name, success: true };
  }
  return res;
}

async function createRandomD1Database(token, accountId) {
  for (let attempt = 0; attempt < 8; attempt++) {
    const name = randomShortNameForAttempt(attempt);
    const res = await cfPost(token, `/accounts/${accountId}/d1/database`, { name });
    if (res?.success === true && res.result) {
      const uuid = res.result.uuid || res.result.id;
      if (!uuid) throw new ApiError(`D1 «${name}» ساخته شد اما Cloudflare شناسهٔ آن را برنگرداند`, 502, { details: res });
      if (res.result.name && res.result.name !== name) {
        throw new ApiError(`نام D1 برگشتی با نام تصادفی درخواستی مطابقت ندارد («${res.result.name}» ≠ «${name}»)؛ این دیتابیس متصل نشد`, 502, { details: res });
      }
      return { success: true, name, uuid };
    }
    if (/already exists|already in use|duplicate|conflict/i.test(errMsg(res))) continue;
    throw new ApiError(`ساخت پایگاه دادهٔ تصادفی D1 «${name}» ناموفق بود: ${errMsg(res)}`, 502, { details: res });
  }
  throw new ApiError("پس از چند تلاش پایگاه دادهٔ تصادفی D1 ساخته نشد", 502);
}

async function verifyFreshWorkerD1Binding(token, accountId, workerName, d1Id) {
  const response = await cfGet(token, `/accounts/${accountId}/workers/scripts/${encodeURIComponent(workerName)}/bindings`);
  if (!response || response.success !== true || !Array.isArray(response.result)) {
    throw new ApiError(`تأیید بایندینگ D1 تازه‌ساخته‌شده برای Worker ناموفق بود: ${errMsg(response)}`, 502);
  }
  const d1Bindings = response.result.filter(binding => binding?.type === "d1");
  const exact = d1Bindings.length === 1 && d1Bindings[0].name === "DB" &&
    (d1Bindings[0].database_id || d1Bindings[0].database_uuid) === d1Id;
  if (!exact) {
    throw new ApiError("Worker به D1 تازه‌ساخته‌شده با نام DB وصل نشد؛ عملیات برای جلوگیری از استفاده از دیتابیس دیگری متوقف شد", 502);
  }
}

function verifyFreshPagesD1Bindings(project, d1Id) {
  const configs = project?.deployment_configs || {};
  for (const stage of ["production", "preview"]) {
    const databases = configs[stage]?.d1_databases || {};
    const entries = Object.entries(databases);
    const exact = entries.length === 1 && entries[0][0] === "DB" &&
      (entries[0][1]?.id || entries[0][1]?.database_id || entries[0][1]?.database_uuid) === d1Id;
    if (!exact) {
      throw new ApiError(`تأیید بایندینگ D1 تازه‌ساخته‌شده در Pages (${stage}) ناموفق بود؛ پروژه به D1 دیگری متصل نشد`, 502);
    }
  }
}

async function createRandomPagesProject(token, accountId) {
  for (let attempt = 0; attempt < 8; attempt++) {
    const name = randomShortNameForAttempt(attempt);
    const res = await createPagesProject(token, accountId, name);
    if (res?.success === true && res.result) return { success: true, name: res.result.name || name, result: res.result };
    if (/already exists|already in use|duplicate|conflict/i.test(errMsg(res))) continue;
    throw new ApiError(`ساخت پروژهٔ تصادفی Pages «${name}» ناموفق بود: ${errMsg(res)}`, 502, { details: res });
  }
  throw new ApiError("پس از چند تلاش پروژهٔ تصادفی Pages ساخته نشد", 502);
}

async function deployToPages(token, accountId, projectName, code, options = {}) {
  if (typeof code !== "string" || !code.trim()) {
    return { success: false, errors: [{ message: "کد اسکریپت برای استقرار Pages خالی است" }] };
  }
  let opts = { ...options };
  if (!opts.branch) {
    const projectRes = await cfGet(token, `/accounts/${accountId}/pages/projects/${encodeURIComponent(projectName)}`);
    if (!projectRes || projectRes.success !== true || !projectRes.result) {
      return { success: false, errors: [{ message: `خواندن تنظیمات Pages پیش از دپلوی ناموفق: ${errMsg(projectRes)}` }] };
    }
    const project = projectRes.result;
    const prod = project.deployment_configs?.production || {};
    opts = { compatibility_date: prod.compatibility_date, compatibility_flags: prod.compatibility_flags, ...opts, branch: project.production_branch || "main" };
  }
  const path = `/accounts/${accountId}/pages/projects/${encodeURIComponent(projectName)}/deployments`;
  const buildForm = async (useBundle) => {
    const fd = new FormData();
    fd.set("manifest", "{}");
    fd.set("branch", String(opts.branch || "main"));
    if (opts.message) fd.set("commit_message", String(opts.message).slice(0, 200));
    if (useBundle) {
      fd.set("_worker.bundle", await pagesWorkerBundle(code, opts.compatibility_date, opts.compatibility_flags));
    } else {
      fd.set("_worker.js", new File([code], "_worker.js", { type: "application/javascript+module" }));
    }
    return fd;
  };
  let res = await cfFetch(token, path, { method: "POST", formData: await buildForm(false) });
  if (!res || res.success !== true) {
    const msg = errMsg(res).toLowerCase();
    if (!/network|auth|10000|9109|not found|8000007/.test(msg)) {
      const retry = await cfFetch(token, path, { method: "POST", formData: await buildForm(true) });
      if (retry && retry.success === true) res = retry;
    }
  }
  return res || { success: false, errors: [{ message: "پاسخ استقرار Pages دریافت نشد" }] };
}

function pagesCompatDate() {
  return new Date(Date.now() - 3 * 24 * 3600 * 1000).toISOString().slice(0, 10);
}

function pagesPatchDeploymentConfigs(token, accountId, projectName, stageConfig) {
  return cfPatch(token, `/accounts/${accountId}/pages/projects/${encodeURIComponent(projectName)}`, {
    deployment_configs: { production: stageConfig, preview: stageConfig },
  });
}

function sanitizePagesStageConfig(conf) {
  const allowed = ["d1_databases", "kv_namespaces", "r2_buckets", "env_vars", "durable_object_namespaces",
    "services", "queue_producers", "analytics_engine_datasets", "ai_bindings", "compatibility_date", "compatibility_flags"];
  const out = {};
  for (const k of allowed) {
    if (!conf || conf[k] === undefined) continue;
    if (k === "env_vars" && conf.env_vars && typeof conf.env_vars === "object") {
      const vars = {};
      for (const [name, v] of Object.entries(conf.env_vars)) {
        if (v === null) { vars[name] = null; continue; }
        if (!v || typeof v !== "object") { vars[name] = { type: "plain_text", value: String(v ?? "") }; continue; }
        const masked = v.type === "secret_text" && (v.value == null || v.value === "" || /^\*+$/.test(String(v.value)) || v.value === "[REDACTED]");
        if (masked) continue;
        vars[name] = { type: v.type === "secret_text" ? "secret_text" : "plain_text", value: String(v.value ?? "") };
      }
      out.env_vars = vars;
      continue;
    }
    out[k] = conf[k];
  }
  return out;
}

async function pagesDeploymentLogTail(token, accountId, projectName, deploymentId, lines = 6) {
  try {
    const res = await cfGet(token, `/accounts/${accountId}/pages/projects/${encodeURIComponent(projectName)}/deployments/${encodeURIComponent(deploymentId)}/history/logs`);
    const data = res?.result?.data;
    if (!Array.isArray(data) || !data.length) return "";
    return data.slice(-lines).map(l => String(l?.line || "").trim()).filter(Boolean).join(" | ");
  } catch { return ""; }
}

async function waitPagesDeployment(token, accountId, projectName, deploymentId, maxWaitMs = 120000) {
  if (!deploymentId) throw new ApiError("Cloudflare شناسهٔ دپلوی Pages را برنگرداند", 502);
  const delays = [1500, 2500, 3000, 4000, 5000, 6000, 8000, 10000, 10000, 10000, 12000, 12000, 15000, 15000];
  const started = Date.now();
  let last = null, readErrors = 0;
  for (const d of delays) {
    if (Date.now() - started + d > maxWaitMs) break;
    await new Promise(resolve => setTimeout(resolve, d));
    const res = await cfGet(token, `/accounts/${accountId}/pages/projects/${encodeURIComponent(projectName)}/deployments/${encodeURIComponent(deploymentId)}`);
    if (!res || res.success !== true || !res.result) {
      if (++readErrors >= 3) break;
      continue;
    }
    last = res.result;
    const stage = last.latest_stage || {};
    if (stage.status === "success" && (stage.name === "deploy" || !stage.name)) return { state: "success", result: last };
    if (stage.status === "failure" || stage.status === "canceled") {
      const tail = await pagesDeploymentLogTail(token, accountId, projectName, deploymentId);
      throw new ApiError(
        `دپلوی Pages ${stage.status === "failure" ? "ناموفق شد" : "لغو شد"} (مرحله: ${stage.name || "نامشخص"})${tail ? ` — لاگ Cloudflare: ${tail}` : ""}`,
        502);
    }
  }
  return { state: "pending", result: last };
}

function setPagesConfigs(token, accountId, projectName, configs) {
  return cfPatch(token, `/accounts/${accountId}/pages/projects/${encodeURIComponent(projectName)}`, {
    deployment_configs: {
      production: configs,
      preview: configs,
    },
  });
}

async function pagesProjectExists(token, accountId, name) {
  const res = await cfFetch(token, `/accounts/${accountId}/pages/projects/${encodeURIComponent(name)}`, { raw: true });
  return res.status === 200;
}

const SCRIPT_SOURCE_URL = "https://github.com/irnexa/nexa-panel/raw/refs/heads/main/_worker.js";
const SCRIPT_CACHE_TTL = 5 * 60 * 1000;
let _scriptCache = { code: null, fetchedAt: 0 };

async function fetchScriptUrl(url) {
  url = String(url || "").trim();
  if (!url) throw new ApiError("لینک اسکریپت خالی است", 400);
  let u;
  try { u = new URL(url); } catch { throw new ApiError("لینک اسکریپت معتبر نیست", 400); }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new ApiError("لینک باید با http(s) شروع شود", 400);
  let res;
  try { res = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(15000) }); }
  catch (e) { throw new ApiError(`دانلود اسکریپت از لینک ناموفق: ${e.message}`, 502); }
  if (res.status !== 200) throw new ApiError(`HTTP ${res.status} از سرور مبدأ`, 502);
  const text = await res.text();
  if (!text || text.length < 10) throw new ApiError("محتوای دریافتی از لینک خالی یا خیلی کوتاه است", 502);
  if (text.length > 5 * 1024 * 1024) throw new ApiError("حجم اسکریپت بیشتر از ۵ مگابایت است", 502);
  return text;
}

async function getScript(env, key) {
  const now = Date.now();
  if (_scriptCache.code && now - _scriptCache.fetchedAt < SCRIPT_CACHE_TTL) return _scriptCache.code;
  try {
    const code = await fetchScriptUrl(SCRIPT_SOURCE_URL);
    _scriptCache = { code, fetchedAt: now };
    return code;
  } catch (e) {
    if (_scriptCache.code) return _scriptCache.code;
    throw e;
  }
}

function workerRecoverySourceKey(profileName, workerName) {
  return `worker_recovery_source:${encodeURIComponent(profileName)}:${encodeURIComponent(workerName)}`;
}

async function saveWorkerRecoverySource(env, profileName, workerName, code, scriptKey = null) {
  const value = scriptKey ? { script_key: scriptKey } : { script: code };
  await setSetting(env, workerRecoverySourceKey(profileName, workerName), JSON.stringify(value));
}

async function resolveWorkerRecoverySource(env, profile, workerName, fallbackKey) {
  const raw = await getSetting(env, workerRecoverySourceKey(profile.name, workerName));
  if (raw) {
    try {
      const saved = JSON.parse(raw);
      if (saved.script_key) {
        try { return { code: await getScript(env, saved.script_key), key: saved.script_key }; }
        catch (e) { if (e.status !== 404) throw e; }
      }
      if (typeof saved.script === "string" && saved.script.trim()) return { code: saved.script, key: null };
    } catch (e) { if (e instanceof ApiError && e.status !== 404) throw e; }
  }
  return { code: await getScript(env, fallbackKey), key: fallbackKey };
}

async function pagesWorkerBundle(code, compatDate, compatFlags) {
  const inner = new FormData();
  const metadata = { main_module: "_worker.js" };
  if (compatDate) metadata.compatibility_date = compatDate;
  if (Array.isArray(compatFlags) && compatFlags.length) metadata.compatibility_flags = compatFlags;
  inner.set("metadata", JSON.stringify(metadata));
  inner.set("_worker.js", new File([String(code || "")], "_worker.js", { type: "application/javascript+module" }));
  const innerRes = new Response(inner);
  const innerType = innerRes.headers.get("Content-Type") || "multipart/form-data";
  const bytes = await innerRes.arrayBuffer();
  return new File([bytes], "_worker.bundle", { type: innerType });
}

async function createNexa(env, profile, body) {
  const code = body.script || (body.script_key ? await getScript(env, body.script_key) : await getScript(env, "nexa"));
  const selectedScriptKey = body.script ? null : (body.script_key || "nexa");
  const { token, account_id } = profile;
  const workerName = await randomAvailableWorkerName(token, account_id);
  const d1Res = await createRandomD1Database(token, account_id);
  const d1Name = d1Res.name;
  const d1Id = d1Res.uuid;

  assertOk(
    await deployWorker(token, account_id, workerName, code, [
      { type: "d1", name: "DB", database_id: d1Id },
      { type: "secret_text", name: "CF_API_TOKEN", text: token },
    ]),
    `استقرار ورکر «${workerName}»`
  );
  await verifyFreshWorkerD1Binding(token, account_id, workerName, d1Id);

  const subRes = await enableSubdomain(token, account_id, workerName);
  const url = await workerUrl(token, account_id, workerName);
  try {
    const row = await getProfileRow(env, profile.name);
    await saveFlags(env, profile.name, [...new Set([...row.nexa_workers, workerName])]);
    await env.DB.prepare("INSERT OR REPLACE INTO worker_urls (profile, worker, url) VALUES (?, ?, ?)").bind(profile.name, workerName, url).run();
    await saveWorkerRecoverySource(env, profile.name, workerName, code, selectedScriptKey);
  } catch {}
  return {
    ok: true, worker: workerName, url,
    subdomain_enabled: !!(subRes && subRes.success),
    d1: { name: d1Name, uuid: d1Id, binding: "DB" },
    bindings: ["DB (D1)", "CF_API_TOKEN (secret)"],
    steps: [
      { step: "script", label: "دریافت و آماده‌سازی اسکریپت", ok: true },
      { step: "d1", label: `پایگاه داده D1 تصادفی (${d1Name})`, ok: true, id: d1Id },
      { step: "worker", label: `استقرار ورکر تصادفی (${workerName})`, ok: true },
      { step: "bindings", label: "اتصال D1 و Secret توکن CF_API_TOKEN", ok: true },
      { step: "subdomain", label: "فعال‌سازی ساب‌دامین workers.dev", ok: true, url },
    ],
    logs: [
      `اسکریپت با موفقیت بررسی شد (${code.length} بایت).`,
      `پایگاه دادهٔ تصادفی D1 «${d1Name}» آماده شد (UUID: ${d1Id}).`,
      `ورکر تصادفی «${workerName}» با بایندینگ DB و CF_API_TOKEN مستقر شد.`,
      `ساب‌دامین فعال شد: ${url}`,
    ],
  };
}

async function createNexaPages(env, profile, body) {
  const code = body.script || (body.script_key ? await getScript(env, body.script_key) : await getScript(env, "nexa"));
  const selectedScriptKey = body.script ? null : (body.script_key || "nexa");
  if (typeof code !== "string" || code.trim().length < 10) throw new ApiError("کد اسکریپت انتخاب‌شده خالی یا خیلی کوتاه است", 400);
  const { token, account_id } = profile;
  const logs = [`اسکریپت با موفقیت بررسی شد (${code.length} بایت).`];

  const d1Res = await createRandomD1Database(token, account_id);
  const d1Name = d1Res.name;
  const d1Id = d1Res.uuid;
  logs.push(`پایگاه دادهٔ تصادفی D1 «${d1Name}» ساخته شد (UUID: ${d1Id}).`);

  const stageConfig = {
    compatibility_date: pagesCompatDate(),
    d1_databases: { DB: { id: d1Id } },
    env_vars: { CF_API_TOKEN: { type: "secret_text", value: token } },
  };
  let projectName = null, project = null;
  for (let attempt = 0; attempt < 8 && !projectName; attempt++) {
    const name = randomShortNameForAttempt(attempt);
    const res = await cfPost(token, `/accounts/${account_id}/pages/projects`, {
      name, production_branch: "main",
      deployment_configs: { production: stageConfig, preview: stageConfig },
    });
    if (res?.success === true && res.result) { projectName = res.result.name || name; project = res.result; break; }
    if (/already exists|already in use|duplicate|conflict|8000002/i.test(errMsg(res))) continue;
    throw new ApiError(`ساخت پروژهٔ Pages ناموفق بود: ${errMsg(res)}`, 502, { details: res });
  }
  if (!projectName) throw new ApiError("پس از چند تلاش پروژهٔ تصادفی Pages ساخته نشد", 502);
  logs.push(`پروژهٔ تصادفی Pages «${projectName}» ساخته شد.`);

  let bindingsOk = false;
  try { verifyFreshPagesD1Bindings(project, d1Id); bindingsOk = true; } catch {}
  if (!bindingsOk) {
    assertOk(await pagesPatchDeploymentConfigs(token, account_id, projectName, stageConfig), `تنظیم بایندینگ‌های Pages «${projectName}»`);
    let lastErr = null;
    for (let i = 0; i < 3 && !bindingsOk; i++) {
      await new Promise(resolve => setTimeout(resolve, 1000 + i * 1000));
      try { verifyFreshPagesD1Bindings(await readPagesProjectStrict(token, account_id, projectName), d1Id); bindingsOk = true; }
      catch (e) { lastErr = e; }
    }
    if (!bindingsOk) throw lastErr || new ApiError("اتصال D1 به پروژهٔ Pages تأیید نشد", 502);
  }
  logs.push("بایندینگ D1 با نام DB و متغیر CF_API_TOKEN روی پروژه ثبت و تأیید شد.");

  const dep = assertOk(
    await deployToPages(token, account_id, projectName, code, { branch: "main", message: "nexa deploy" }),
    `استقرار کد روی Pages «${projectName}»`
  );
  if (!dep?.id) throw new ApiError("Cloudflare شناسهٔ دپلوی Pages را برنگرداند", 502);
  const wait = await waitPagesDeployment(token, account_id, projectName, dep.id);
  const pending = wait.state !== "success";
  logs.push(pending
    ? "دپلوی ثبت شد و Cloudflare در حال انتشار آن است (معمولاً کمتر از ۲ دقیقه)."
    : "دپلوی با موفقیت منتشر شد ✓");

  let subdomain = project?.subdomain || null;
  if (!subdomain) {
    try { subdomain = (await readPagesProjectStrict(token, account_id, projectName))?.subdomain || null; } catch {}
  }
  const url = `https://${subdomain || `${projectName}.pages.dev`}`;
  logs.push(`استقرار کامل شد: ${url}`);

  try {
    const row = await getProfileRow(env, profile.name);
    await saveFlags(env, profile.name, [...new Set([...row.nexa_workers, projectName])]);
    await env.DB.prepare("INSERT OR REPLACE INTO worker_urls (profile, worker, url) VALUES (?, ?, ?)").bind(profile.name, projectName, url).run();
    await savePagesScript(env, profile.name, projectName, { script: selectedScriptKey ? null : code, script_key: selectedScriptKey });
  } catch {}
  return {
    ok: true, worker: projectName, url, deploy_type: "pages",
    deployment_id: dep.id, deploying: pending,
    d1: { name: d1Name, uuid: d1Id, binding: "DB" },
    bindings: ["DB (D1)", "CF_API_TOKEN (secret)"],
    note: pending
      ? "Pages ساخته شد؛ انتشار نهایی در Cloudflare چند لحظه دیگر تمام می‌شود — اگر آدرس هنوز باز نشد ۱ دقیقه بعد دوباره امتحان کنید"
      : "Pages — نام پروژه و D1 تصادفی؛ بایندینگ‌ها پیش از دپلوی متصل شدند",
    steps: [
      { step: "script", label: "دریافت و آماده‌سازی اسکریپت", ok: true },
      { step: "d1", label: `پایگاه دادهٔ تصادفی D1 (${d1Name})`, ok: true, id: d1Id },
      { step: "project", label: `ساخت پروژهٔ تصادفی Pages (${projectName}) همراه با بایندینگ‌ها`, ok: true },
      { step: "configs", label: "تأیید اتصال D1 و Secret توکن CF_API_TOKEN", ok: true },
      { step: "deploy", label: pending ? "دپلوی کد (در حال انتشار)" : "دپلوی کد", ok: true, id: dep.id },
      { step: "finalize", label: "دریافت آدرس pages.dev", ok: true, url },
    ],
    logs,
  };
}

async function collectTargets(env) {
  const { results } = await env.DB.prepare("SELECT * FROM profiles ORDER BY pos, created_at, name").all();
  const targets = [];
  for (const p of results || []) {
    const workers = JSON.parse(p.nexa_workers || "[]");
    for (const w of workers) targets.push({ profile: p.name, worker: w });
  }
  return targets;
}

async function bulkUpdate(env, body, type) {
  const code = body.script || (body.script_key ? await getScript(env, body.script_key) : await getScript(env, type));
  const targets = body.targets || [];
  const results = [];
  for (const t of targets) {
    const item = { profile: t.profile, worker: t.worker, kind: t.kind, ok: false, message: "" };
    try {
      const p = await getProfileRow(env, t.profile);
      const isPages = t.kind === "pages" || (t.kind !== "worker" && await pagesProjectExists(p.token, p.account_id, t.worker));
      if (isPages) {
        const res = await redeployPagesProject(env, p, t.worker, code);
        if (!res || !res.redeployed) throw new ApiError(res?.note || "استقرار مجدد Pages ناموفق بود");
        item.ok = true; item.kind = "pages"; item.message = "کد Pages با موفقیت آپدیت شد (بایندینگ‌ها و دامنه‌ها حفظ شدند)";
      } else {
        if (!(await workerExists(p.token, p.account_id, t.worker))) throw new ApiError(`ورکر/پروژه Pages «${t.worker}» در این اکانت پیدا نشد`);
        const bindings = await fetchBindings(p.token, p.account_id, t.worker);
        const res = await rebuildWithBindings(p.token, p.account_id, t.worker, bindingsToMetadata(bindings), code);
        if (!res || res.success !== true) throw new ApiError(errMsg(res));
        try { await saveWorkerRecoverySource(env, p.name, t.worker, code, body.script ? null : (body.script_key || type)); } catch {}
        item.ok = true; item.kind = "worker"; item.message = "کد ورکر با موفقیت آپدیت شد (بایندینگ‌ها حفظ شدند)";
      }
    } catch (e) { item.message = e.message; }
    results.push(item);
  }
  return { ok: true, results };
}

async function rebuildSingleWorker(env, type, profile, workerName, code, options = {}) {
  const item = { profile: profile.name, worker: workerName, kind: "worker", ok: false, message: "", steps: [] };
  const { token, account_id } = profile;
  let stage = "preflight";
  let detachedDomains = [];
  let domainsRestored = false;
  let attachDomainsTo = null;
  try {
    if (typeof code !== "string" || code.trim().length < 10) throw new ApiError("کد جدید خالی یا خیلی کوتاه است؛ ورکر فعلی حذف نشد");
    if (!(await workerExists(token, account_id, workerName))) throw new ApiError(`ورکر «${workerName}» در این اکانت پیدا نشد`, 404);

    stage = "snapshot";
    const [bindingsRes, routeSnapshot, oldDomainRows, subdomainRes] = await Promise.all([
      cfGet(token, `/accounts/${account_id}/workers/scripts/${encodeURIComponent(workerName)}/bindings`),
      fetchWorkerRoutesStrict(token, account_id, workerName),
      fetchWorkerDomainsStrict(token, account_id, { service: workerName }),
      cfGet(token, `/accounts/${account_id}/workers/scripts/${encodeURIComponent(workerName)}/subdomain`),
    ]);
    if (!bindingsRes || bindingsRes.success !== true || !Array.isArray(bindingsRes.result)) {
      throw new ApiError(`خواندن بایندینگ‌های Worker ناموفق بود؛ حذف انجام نشد: ${errMsg(bindingsRes)}`, 502);
    }
    if (!subdomainRes || subdomainRes.success !== true || !subdomainRes.result || typeof subdomainRes.result.enabled !== "boolean") {
      throw new ApiError(`خواندن وضعیت workers.dev ناموفق بود؛ حذف انجام نشد: ${errMsg(subdomainRes)}`, 502);
    }

    const oldBindings = bindingsRes.result;
    const oldRoutes = routeSnapshot.routes;
    const oldSubdomainEnabled = subdomainRes.result.enabled;
    for (const route of oldRoutes) {
      if (!route || typeof route.pattern !== "string" || !route.pattern.trim() || !route.zone_id) {
        throw new ApiError("یکی از Routeهای Worker بدون الگو یا شناسهٔ Zone معتبر برگشت؛ برای جلوگیری از گم‌شدن تنظیمات، حذف انجام نشد", 502);
      }
    }
    const oldCustomDomains = oldDomainRows.filter(domain => {
      const owner = domain && (domain.service || domain.script || domain.worker);
      return owner === workerName;
    });
    for (const domain of oldCustomDomains) {
      if (!(domain.hostname || domain.domain)) {
        throw new ApiError("یکی از دامنه‌های Worker نام میزبان ندارد؛ برای جلوگیری از گم‌شدن آن، حذف انجام نشد", 502);
      }
    }

    const bindings = [];
    const unknownSecrets = [];
    const knownValues = { CF_API_TOKEN: token, CF_ACCOUNT_ID: account_id };
    const readOnlyFields = new Set(["created_on", "modified_on", "modified_by", "updated_at", "last_updated", "deployment_id", "script_version_id"]);
    for (const binding of oldBindings) {
      if (!binding || typeof binding !== "object" || typeof binding.type !== "string" || !binding.type || typeof binding.name !== "string" || !binding.name) {
        throw new ApiError("یکی از بایندینگ‌های Worker ناقص برگشت؛ برای جلوگیری از حذف تنظیمات، عملیات متوقف شد", 502);
      }
      const typeName = binding.type;
      const name = binding.name;

      if (name === "CF_API_TOKEN") {
        bindings.push({ type: "secret_text", name, text: knownValues.CF_API_TOKEN });
        continue;
      }
      if (name === "CF_ACCOUNT_ID") {
        bindings.push({ type: "plain_text", name, text: knownValues[name] });
        continue;
      }

      if (typeName === "d1") {
        const databaseId = binding.database_id || binding.database_uuid;
        if (!databaseId) throw new ApiError(`شناسهٔ دیتابیس D1 بایندینگ «${name}» خوانده نشد؛ حذف انجام نشد`, 502);
        bindings.push({ ...binding, type: typeName, name, database_id: databaseId });
      } else if (typeName === "kv_namespace") {
        const namespaceId = binding.namespace_id;
        if (!namespaceId) throw new ApiError(`شناسهٔ KV بایندینگ «${name}» خوانده نشد؛ حذف انجام نشد`, 502);
        bindings.push({ ...binding, type: typeName, name, namespace_id: namespaceId });
      } else if (typeName === "r2_bucket") {
        if (!binding.bucket_name) throw new ApiError(`نام Bucket بایندینگ «${name}» خوانده نشد؛ حذف انجام نشد`, 502);
        bindings.push({ ...binding, type: typeName, name });
      } else if (typeName === "plain_text" || typeName === "secret_text") {
        const hasText = Object.prototype.hasOwnProperty.call(binding, "text") || Object.prototype.hasOwnProperty.call(binding, "value");
        let value = Object.prototype.hasOwnProperty.call(binding, "text") ? binding.text : binding.value;
        const masked = typeName === "secret_text" && (value == null || value === "" || /^\*+$/.test(String(value)) || /^\[REDACTED\]$/i.test(String(value)));
        if (!hasText || value == null || masked) {
          if (typeName === "secret_text") {
            const supplied = options.secret_values || {};
            let suppliedVal = undefined;
            if (Object.prototype.hasOwnProperty.call(supplied, name)) suppliedVal = supplied[name];
            else if (supplied.production && Object.prototype.hasOwnProperty.call(supplied.production, name)) suppliedVal = supplied.production[name];
            else if (supplied.preview && Object.prototype.hasOwnProperty.call(supplied.preview, name)) suppliedVal = supplied.preview[name];
            if (suppliedVal != null && String(suppliedVal).trim() !== "") {
              bindings.push({ type: typeName, name, text: String(suppliedVal) });
            } else {
              unknownSecrets.push(name);
            }
          } else throw new ApiError(`مقدار متغیر «${name}» خوانده نشد؛ حذف انجام نشد`, 502);
        } else {
          bindings.push({ type: typeName, name, text: String(value) });
        }
      } else {
        const copy = JSON.parse(JSON.stringify(binding));
        for (const field of readOnlyFields) delete copy[field];
        bindings.push(copy);
      }
    }
    if (unknownSecrets.length) {
      const uniq = [...new Set(unknownSecrets)];
      throw new ApiError(`حذف انجام نشد: مقدار Secretهای زیر از Cloudflare قابل بازیابی نیست و روی Worker جدید قابل بازگردانی نخواهد بود: ${uniq.join("، ")}. می‌توانید مقدارشان را دستی وارد کنید تا ریبیلد ادامه یابد.`, 409, { details: { unknown_secrets: uniq, kind: "worker" } });
    }
    if (!bindings.some(binding => binding.name === "CF_API_TOKEN")) {
      bindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: knownValues.CF_API_TOKEN });
    }

    item.steps.push(`بایندینگ‌های قابل‌بازیابی و آمادهٔ اتصال: ${oldBindings.length} مورد${oldBindings.length ? ` (${oldBindings.map(b => b.name).join("، ")})` : ""}`);
    item.steps.push("بایندینگ‌های قبلی حفظ می‌شوند؛ فقط CF_API_TOKEN با توکن پروفایل اکانت فعلی به‌صورت Secret جایگزین می‌شود");
    item.steps.push(oldRoutes.length ? `Routeها پیش از حذف ذخیره شدند: ${oldRoutes.length} مورد` : "Route سفارشی نداشت");
    item.steps.push(oldCustomDomains.length
      ? `دامنه‌های سفارشی پیش از حذف ذخیره شدند: ${oldCustomDomains.map(d => d.hostname || d.domain).join("، ")}`
      : "دامنهٔ سفارشی نداشت");

    const readDomains = hostname => fetchWorkerDomainsStrict(token, account_id, { hostname });
    const domainName = domain => String(domain.hostname || domain.domain || "").toLowerCase();
    const domainOwner = domain => domain.service || domain.script || domain.worker;
    const findDomain = async hostname => {
      for (let attempt = 0; attempt < 4; attempt++) {
        const rows = await readDomains(hostname);
        const found = rows.find(domain => domainName(domain) === String(hostname).toLowerCase());
        if (found) return found;
        if (attempt < 3) await new Promise(resolve => setTimeout(resolve, 400));
      }
      return null;
    };
    attachDomainsTo = async service => {
      for (const oldDomain of detachedDomains) {
        const hostname = oldDomain.hostname || oldDomain.domain;
        const existing = await findDomain(hostname);
        if (existing && domainOwner(existing) === service) continue;
        if (existing && domainOwner(existing) !== service) {
          throw new ApiError(`دامنهٔ «${hostname}» در این فاصله به Worker دیگری («${domainOwner(existing)}») وصل شده؛ اتصال ناخواسته انجام نشد`, 409);
        }
        const payload = { hostname, service };
        if (oldDomain.zone_id) payload.zone_id = oldDomain.zone_id;
        if (oldDomain.zone_name) payload.zone_name = oldDomain.zone_name;
        assertOk(await cfPut(token, `/accounts/${account_id}/workers/domains`, payload), `اتصال دامنهٔ «${hostname}»`);
        const attached = await findDomain(hostname);
        if (!attached || domainOwner(attached) !== service) {
          throw new ApiError(`اتصال دامنهٔ «${hostname}» انجام شد اما در Cloudflare تأیید نشد`, 502);
        }
      }
    };

    stage = "detach_domains";
    for (const domain of oldCustomDomains) {
      const hostname = domain.hostname || domain.domain;
      if (!domain.id) throw new ApiError(`شناسهٔ دامنهٔ «${hostname}» از Cloudflare برنگشت؛ جدا کردن دامنه ممکن نیست و ورکر حذف نشد`, 502);
      const detachRes = await cfDelete(token, `/accounts/${account_id}/workers/domains/${encodeURIComponent(domain.id)}`);
      assertOk(detachRes, `جدا کردن دامنهٔ «${hostname}» از Worker قبلی`);
      detachedDomains.push(domain);
      let still = null;
      for (let attempt = 0; attempt < 5; attempt++) {
        still = (await readDomains(hostname)).find(row => domainName(row) === String(hostname).toLowerCase() && domainOwner(row) === workerName);
        if (!still) break;
        await new Promise(resolve => setTimeout(resolve, 500));
      }
      if (still) throw new ApiError(`دامنهٔ «${hostname}» جدا شد اما هنوز در Cloudflare به Worker قبلی وصل نشان داده می‌شود؛ ورکر حذف نشد`, 502);
    }
    if (detachedDomains.length) item.steps.push(`دامنه‌ها قبل از حذف ورکر جدا شدند: ${detachedDomains.map(d => d.hostname || d.domain).join("، ")}`);

    stage = "delete";
    const deleteRes = await cfDelete(token, `/accounts/${account_id}/workers/scripts/${encodeURIComponent(workerName)}`);
    if (!deleteRes || deleteRes.success !== true) throw new ApiError(`حذف Worker قدیمی ناموفق بود: ${errMsg(deleteRes)}`, 502);
    item.steps.push("Worker قبلی حذف شد؛ منابع D1/KV/R2 حذف نشدند");

    stage = "deploy";
    let deployRes = await deployWorker(token, account_id, workerName, code, bindings);
    if (!deployRes || deployRes.success !== true) {
      item.steps.push(`استقرار اول ناموفق بود (${errMsg(deployRes)})؛ تلاش دوباره...`);
      await new Promise(resolve => setTimeout(resolve, 2000));
      deployRes = await deployWorker(token, account_id, workerName, code, bindings);
    }
    if (!deployRes || deployRes.success !== true) throw new ApiError(`استقرار Worker جدید با همان نام ناموفق بود: ${errMsg(deployRes)}`, 502);
    item.steps.push(`Worker جدید با همان نام «${workerName}» ساخته شد و بایندینگ‌های قبلی (${bindings.map(b => b.name).join("، ") || "—"}) وصل شدند`);

    stage = "restore_domains";
    await attachDomainsTo(workerName);
    for (const oldDomain of detachedDomains) {
      const hostname = oldDomain.hostname || oldDomain.domain;
      const restored = await findDomain(hostname);
      if (!restored || domainOwner(restored) !== workerName) {
        throw new ApiError(`اتصال دامنهٔ «${hostname}» تأیید نشد`, 502);
      }
    }
    domainsRestored = true;
    if (detachedDomains.length) item.steps.push(`همان دامنه‌ها به ورکر جدید وصل و تأیید شدند: ${detachedDomains.map(d => d.hostname || d.domain).join("، ")}`);

    stage = "restore_subdomain";
    const subdomainRestore = await enableSubdomain(token, account_id, workerName, oldSubdomainEnabled);
    assertOk(subdomainRestore, "بازگردانی وضعیت workers.dev");

    stage = "restore_routes";
    const zoneIds = [...new Set(oldRoutes.map(route => route.zone_id))];
    const routesByZone = new Map();
    for (const zoneId of zoneIds) routesByZone.set(zoneId, await fetchZoneRoutesStrict(token, zoneId));
    for (const oldRoute of oldRoutes) {
      let zoneRoutes = routesByZone.get(oldRoute.zone_id) || [];
      const existing = zoneRoutes.find(route => route.pattern === oldRoute.pattern);
      if (existing?.script === workerName) continue;
      if (existing && existing.script && existing.script !== workerName) {
        throw new ApiError(`Route «${oldRoute.pattern}» در Zone دیگری به Worker دیگری متصل است`, 409);
      }
      if (existing && !existing.script) {
        if (!existing.id) throw new ApiError(`Route غیرفعال «${oldRoute.pattern}» شناسه ندارد و قابل بازیابی نیست`, 502);
        assertOk(
          await cfPut(token, `/zones/${encodeURIComponent(oldRoute.zone_id)}/workers/routes/${encodeURIComponent(existing.id)}`, {
            pattern: oldRoute.pattern, script: workerName,
          }),
          `اتصال مجدد Route «${oldRoute.pattern}»`
        );
      } else {
        assertOk(
          await cfPost(token, `/zones/${encodeURIComponent(oldRoute.zone_id)}/workers/routes`, {
            pattern: oldRoute.pattern, script: workerName,
          }),
          `ساخت مجدد Route «${oldRoute.pattern}»`
        );
      }
      routesByZone.set(oldRoute.zone_id, await fetchZoneRoutesStrict(token, oldRoute.zone_id));
    }
    const verifiedRoutesByZone = new Map();
    for (const zoneId of zoneIds) verifiedRoutesByZone.set(zoneId, await fetchZoneRoutesStrict(token, zoneId));
    const missingRoutes = oldRoutes.filter(oldRoute => {
      const matches = (verifiedRoutesByZone.get(oldRoute.zone_id) || []).filter(route => route.pattern === oldRoute.pattern);
      return !matches.some(route => route.script === workerName);
    });
    if (missingRoutes.length) throw new ApiError(`بازیابی این Routeها تأیید نشد: ${missingRoutes.map(route => route.pattern).join("، ")}`, 502);
    if (oldRoutes.length) item.steps.push(`Routeها بازگردانی و تأیید شدند (${oldRoutes.length} مورد)`);

    stage = "verify_subdomain";
    const subdomainVerify = await cfGet(token, `/accounts/${account_id}/workers/scripts/${encodeURIComponent(workerName)}/subdomain`);
    if (!subdomainVerify || subdomainVerify.success !== true || !subdomainVerify.result || subdomainVerify.result.enabled !== oldSubdomainEnabled) {
      throw new ApiError(`تأیید وضعیت workers.dev ناموفق بود: ${errMsg(subdomainVerify)}`, 502);
    }

    const url = await workerUrl(token, account_id, workerName);
    try {
      await env.DB.prepare("INSERT OR REPLACE INTO worker_urls (profile, worker, url) VALUES (?, ?, ?)")
        .bind(profile.name, workerName, url).run();
    } catch {}
    item.ok = true;
    item.message = "ریبیلد Worker کامل شد: همان نام، بایندینگ‌ها، وضعیت workers.dev، Routeها و دامنه‌ها حفظ و تأیید شدند";
  } catch (e) {
    item.failed_stage = stage;
    item.message = `${e.message} (مرحله: ${stage})`;
    if (detachedDomains.length && !domainsRestored && attachDomainsTo) {
      const names = detachedDomains.map(d => d.hostname || d.domain).join("، ");
      try {
        if (await workerExists(token, account_id, workerName)) {
          await attachDomainsTo(workerName);
          item.steps.push(`دامنه‌ها دوباره به «${workerName}» وصل شدند: ${names}`);
          item.message += ` — دامنه‌ها (${names}) دوباره به «${workerName}» وصل شدند`;
        } else {
          item.domains_pending = detachedDomains.map(d => d.hostname || d.domain);
          item.message += ` — توجه: ورکر «${workerName}» الان وجود ندارد و دامنه‌های جداشده (${names}) به جایی وصل نیستند؛ بعد از ساخت ورکر، آن‌ها را از بخش دامنه‌ها دوباره وصل کنید`;
        }
      } catch (re) {
        item.domains_pending = detachedDomains.map(d => d.hostname || d.domain);
        item.message += ` — اتصال دوبارهٔ دامنه‌ها (${names}) ناموفق بود: ${re.message}`;
      }
    }
  }
  return item;
}

function pagesRebuildKeys(accountId, projectName) {
  const suffix = encodeURIComponent(accountId) + ":" + encodeURIComponent(projectName);
  return { snapshot: "pages_rebuild_snapshot:" + suffix, lock: "pages_rebuild_lock:" + suffix };
}

async function readPagesRebuildRecord(env, accountId, projectName) {
  const raw = await getSetting(env, pagesRebuildKeys(accountId, projectName).snapshot);
  if (!raw) return null;
  let record;
  try { record = JSON.parse(raw); } catch { throw new ApiError("بکاپ ریبیلد Pages در D1 نامعتبر است؛ برای جلوگیری از حذف، عملیات متوقف شد"); }
  if (record.account_id !== accountId || record.project !== projectName || !record.snapshot) {
    throw new ApiError("شناسهٔ بکاپ ریبیلد با پروژه و اکانت انتخاب‌شده مطابقت ندارد");
  }
  return record;
}

async function readPagesProjectStrict(token, accountId, projectName) {
  const response = await cfFetch(token, `/accounts/${accountId}/pages/projects/${encodeURIComponent(projectName)}`, { raw: true });
  let data;
  try { data = await response.json(); } catch { throw new ApiError(`دریافت مشخصات Pages ناموفق: HTTP ${response.status}`, 502); }
  if (response.status === 404) return null;
  if (!response.ok || data.success !== true || !data.result) {
    throw new ApiError(`دریافت مشخصات Pages ناموفق: ${errMsg(data)}`, 502);
  }
  return data.result;
}

async function pagesDomainsStrict(token, accountId, projectName) {
  const rows = [];
  const perPage = 100;
  for (let page = 1; page <= 100; page++) {
    const query = new URLSearchParams({ page: String(page), per_page: String(perPage) });
    const res = await cfGet(token, `/accounts/${accountId}/pages/projects/${encodeURIComponent(projectName)}/domains?${query.toString()}`);
    if (!res || res.success !== true || !Array.isArray(res.result)) {
      throw new ApiError(`خواندن دامنه‌های Pages ناموفق: ${errMsg(res)}؛ دامنه‌ها نباید نادیده گرفته شوند`, 502);
    }
    for (const domain of res.result) {
      const name = typeof domain === "string" ? domain : (domain.name || domain.domain);
      if (typeof name !== "string" || !name.trim()) throw new ApiError("نام یکی از دامنه‌های Pages از API خوانده نشد");
      rows.push(typeof domain === "string" ? { name: name.toLowerCase() } : { ...domain, name: name.toLowerCase() });
    }
    const info = res.result_info || {};
    const totalPages = Number(info.total_pages || (info.total_count ? Math.ceil(Number(info.total_count) / Number(info.per_page || perPage)) : 0));
    if (totalPages && page >= totalPages) return rows;
    if (!totalPages && res.result.length < perPage) return rows;
    if (!res.result.length) return rows;
  }
  throw new ApiError("خواندن فهرست دامنه‌های Pages بیش از حد صفحه داشت و کامل نشد", 502);
}

function preparePagesRestoreConfigs(configs, profile, type, supplied = {}) {
  const restored = JSON.parse(JSON.stringify(configs || {}));
  const unreadable = [];
  const known = Object.assign(Object.create(null), { CF_API_TOKEN: profile.token, CF_ACCOUNT_ID: profile.account_id });
  const needed = ["CF_API_TOKEN"];
  for (const stage of ["production", "preview"]) {
    const config = restored[stage] || {};
    const vars = Object.create(null);
    for (const [name, variable] of Object.entries(config.env_vars || {})) {
      if (variable == null) continue;
      if (known[name] !== undefined) {
        vars[name] = { type: name === "CF_API_TOKEN" ? "secret_text" : "plain_text", value: known[name] };
        continue;
      }
      let value = variable.value;
      const masked = variable.type === "secret_text" &&
        (value == null || value === "" || /^\*+$/.test(String(value)) || value === "[REDACTED]");
      if (value == null || masked) {
        const stageValues = supplied[stage];
        if (stageValues && Object.prototype.hasOwnProperty.call(stageValues, name)) value = stageValues[name];
        else if (Object.prototype.hasOwnProperty.call(supplied, name)) value = supplied[name];
        else { unreadable.push(stage + "/" + name); continue; }
      }
      if (value == null || typeof value === "object") { unreadable.push(stage + "/" + name); continue; }
      vars[name] = { type: variable.type === "secret_text" ? "secret_text" : "plain_text", value: String(value) };
    }
    for (const name of needed) vars[name] = { type: "secret_text", value: known[name] };
    config.env_vars = vars;
    restored[stage] = config;
  }
  if (unreadable.length) {
    throw new ApiError(`حذف انجام نشد: مقدار این متغیرها/Secretها از Cloudflare قابل خواندن نیست: ${unreadable.join("، ")}. می‌توانید مقدارشان را دستی وارد کنید تا ریبیلد ادامه یابد.`, 409, { details: { unknown_secrets: unreadable, kind: "pages" } });
  }
  return restored;
}

async function resolvePagesRebuildSource(env, profile, projectName, type, body = {}) {
  if (typeof body.script === "string" && body.script.trim()) return { code: body.script, key: null };
  if (body.script_key) return { code: await getScript(env, body.script_key), key: body.script_key };
  const saved = await env.DB.prepare("SELECT script_key, script FROM pages_scripts WHERE profile = ? AND project = ?")
    .bind(profile.name, projectName).first();
  if (saved?.script_key) return { code: await getScript(env, saved.script_key), key: saved.script_key };
  try { return { code: await getScript(env, type), key: type }; }
  catch (e) {
    if (e.status !== 404 || !saved?.script) throw e;
    return { code: saved.script, key: null };
  }
}

async function waitPagesRebuildDeployment(token, accountId, projectName, deploymentId) {
  const w = await waitPagesDeployment(token, accountId, projectName, deploymentId);
  return { ...(w.result || {}), pending: w.state !== "success" };
}

function pagesBindingSubset(configs) {
  const keys = ["d1_databases", "kv_namespaces", "r2_buckets", "env_vars", "durable_object_namespaces",
    "services", "queue_producers", "analytics_engine_datasets", "ai_bindings", "compatibility_date", "compatibility_flags"];
  const out = {};
  for (const stage of ["production", "preview"]) {
    const src = (configs || {})[stage] || {};
    const dst = {};
    for (const k of keys) {
      const v = src[k];
      if (v === undefined || v === null) continue;
      if (Array.isArray(v) && !v.length) continue;
      if (typeof v === "object" && !Array.isArray(v) && !Object.keys(v).length) continue;
      dst[k] = v;
    }
    out[stage] = dst;
  }
  return out;
}

function pagesConfigContains(actual, expected) {
  if (expected === null || typeof expected !== "object") return actual === expected;
  if (!actual || typeof actual !== "object") return false;
  if (Array.isArray(expected)) return Array.isArray(actual) && expected.length === actual.length && expected.every(value => actual.some(a => JSON.stringify(a) === JSON.stringify(value)));
  if (expected.type === "secret_text") return actual.type === "secret_text";
  return Object.entries(expected).every(([key, value]) => pagesConfigContains(actual[key], value));
}

async function rebuildSinglePages(env, type, profile, projectName, code, options = {}) {
  const item = { profile: profile.name, worker: projectName, kind: "pages", ok: false, redeployed: false, message: "", steps: [] };
  const { token, account_id } = profile;
  const keys = pagesRebuildKeys(account_id, projectName);
  const lock = JSON.stringify({ owner: randomToken(12), expires: Date.now() + 15 * 60 * 1000 });
  let acquired = false, record = null, stage = "preflight";
  const snapshotUrl = `/api/pages/${encodeURIComponent(projectName)}/rebuild-snapshot?profile=${encodeURIComponent(profile.name)}&download=1`;
  const persist = async phase => {
    if (phase) record.phase = phase;
    record.updated_at = new Date().toISOString();
    await setSetting(env, keys.snapshot, JSON.stringify(record));
    item.snapshot_url = snapshotUrl;
  };
  try {
    if (typeof code !== "string" || code.trim().length < 10) throw new ApiError("کد انتخاب‌شده در Scripts خالی یا خیلی کوتاه است؛ هیچ پروژه‌ای حذف نشد");
    await env.DB.prepare("DELETE FROM settings WHERE key = ? AND CAST(json_extract(value, '$.expires') AS INTEGER) <= ?")
      .bind(keys.lock, Date.now()).run();
    const result = await env.DB.prepare("INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)").bind(keys.lock, lock).run();
    if (!result.meta?.changes) throw new ApiError("ریبیلد این پروژه در حال اجراست؛ درخواست هم‌زمان دیگری آغاز نشد", 409);
    acquired = true;

    stage = "snapshot";
    const previous = await readPagesRebuildRecord(env, account_id, projectName);
    let live = await readPagesProjectStrict(token, account_id, projectName);
    if (previous?.delete_requested && !previous.complete) {
      record = previous;
      record.state = "running";
      record.error = null;
      item.steps.push("ادامهٔ ریبیلد ناتمام از بکاپ قبلی؛ نام، بایندینگ‌ها و دامنه‌های اصلی دوباره از پروژهٔ ناقص برداشت نمی‌شوند");
      if (live && record.created_id && live.id && live.id !== record.created_id) {
        throw new ApiError("شناسهٔ پروژهٔ فعلی با پروژهٔ ساخته‌شده در این ریبیلد متفاوت است؛ برای جلوگیری از تغییر پروژهٔ دیگری، ادامه متوقف شد", 409);
      }
      if (!record.deleted) {
        if (!live) record.deleted = true;
        else if (record.create_requested && record.snapshot.id && live.id && live.id !== record.snapshot.id) {
          record.deleted = true; record.created = true; record.created_id = live.id;
        } else if (!record.snapshot.id || !live.id) {
          throw new ApiError("نتیجهٔ حذف قبلی نامشخص است و شناسهٔ پروژه قابل تطبیق نیست؛ برای جلوگیری از حذف اشتباه، عملیات متوقف شد", 409);
        }
      }
      if (record.deleted && live) {
        if (!record.create_requested) throw new ApiError("پروژه‌ای با همین نام پس از حذف ساخته شده ولی از این عملیات نیست؛ ادامهٔ خودکار متوقف شد", 409);
        record.created = true; record.created_id = live.id || record.created_id;
      }
      if (record.deleted && !live) { record.created = false; record.initial_uploaded = false; }
    } else {
      if (!live) throw new ApiError(`پروژه Pages «${projectName}» در این اکانت پیدا نشد؛ پروژه‌ای حذف نشد`, 404);
      if (live.name && live.name !== projectName) throw new ApiError("نام پروژهٔ خوانده‌شده با هدف ریبیلد متفاوت است");
      if (!live.deployment_configs || typeof live.deployment_configs !== "object") throw new ApiError("پیکربندی Pages کامل خوانده نشد؛ پروژه حذف نشد");
      const domainRows = await pagesDomainsStrict(token, account_id, projectName);
      const domains = [...new Set(domainRows.map(d => d.name).filter(d => d !== `${projectName}.pages.dev`))];
      record = {
        version: 1, account_id, project: projectName, profile: profile.name,
        started_at: new Date().toISOString(), state: "running", phase: "snapshot", complete: false,
        snapshot: { id: live.id || null, name: projectName, production_branch: live.production_branch || "main",
          deployment_configs: JSON.parse(JSON.stringify(live.deployment_configs)),
          build_config: live.build_config || null, domains, domain_details: domainRows },
      };
      await persist("snapshot");
      item.steps.push(`نام و تنظیمات production/preview و ${domains.length} دامنه خوانده و پیش از حذف در D1 بکاپ شد`);
    }
    record.restore_configs = preparePagesRestoreConfigs(record.restore_configs || record.snapshot.deployment_configs, profile, type, options.secret_values || {});
    record.script_key = options.script_key || null;
    await persist();
    const snapshot = record.snapshot;
    const projectPath = `/accounts/${account_id}/pages/projects/${encodeURIComponent(projectName)}`;
    const deployOpts = { branch: snapshot.production_branch, compatibility_date: record.restore_configs.production?.compatibility_date,
      compatibility_flags: record.restore_configs.production?.compatibility_flags };

    stage = "delete";
    if (!record.deleted) {
      record.delete_requested = true;
      await persist("delete_requested");
      stage = "detach_domains";
      const oldAttached = new Set((await pagesDomainsStrict(token, account_id, projectName)).map(d => d.name));
      record.detached_domains = record.detached_domains || [];
      for (const domain of snapshot.domains) {
        if (!oldAttached.has(domain)) continue;
        assertOk(await cfDelete(token, projectPath + "/domains/" + encodeURIComponent(domain)), `آزاد کردن اتصال Pages دامنه «${domain}» پیش از حذف پروژه`);
        if (!record.detached_domains.includes(domain)) record.detached_domains.push(domain);
        await persist("domains_detached");
      }
      if (snapshot.domains.length) item.steps.push("اتصال دامنه‌های سفارشی برای امکان حذف پروژه آزاد شد؛ دستور حذف رکورد DNS ارسال نشد و نام دامنه‌ها در بکاپ باقی است");
      stage = "delete";
      assertOk(await cfDelete(token, projectPath), "حذف پروژهٔ قدیمی Pages");
      record.deleted = true;
      await persist("deleted");
      item.steps.push("فقط پروژهٔ Pages قدیمی حذف شد؛ دیتابیس‌های D1، KV و سایر منابع حذف نشدند");
    }

    stage = "create";
    if (!record.created) {
      const runtime = {};
      for (const key of ["compatibility_date", "compatibility_flags", "always_use_latest_compatibility_date"]) {
        if (record.restore_configs.production?.[key] !== undefined) runtime[key] = record.restore_configs.production[key];
      }
      record.create_requested = true;
      await persist("create_requested");
      let created;
      for (let attempt = 0; attempt < 4; attempt++) {
        if (attempt) await new Promise(resolve => setTimeout(resolve, 700 * attempt));
        created = await cfPost(token, `/accounts/${account_id}/pages/projects`, {
          name: snapshot.name, production_branch: snapshot.production_branch,
          deployment_configs: { production: runtime },
        });
        if (created?.success === true) break;
        if (!/already exists|being deleted|in progress|temporar|try again/i.test(errMsg(created))) break;
      }
      assertOk(created, "ساخت Pages جدید با همان نام");
      if (created.result?.name && created.result.name !== projectName) throw new ApiError("نام پروژهٔ ساخته‌شده با نام قبلی متفاوت است");
      record.created = true; record.created_id = created.result?.id || null;
      await persist("created");
      item.steps.push(`پروژهٔ Pages جدید دقیقاً با نام «${snapshot.name}» و شاخهٔ «${snapshot.production_branch}» ساخته شد`);
    }

    stage = "initial_deploy";
    if (!record.initial_uploaded) {
      const initial = assertOk(await deployToPages(token, account_id, projectName, code, { ...deployOpts, message: "full rebuild: initial code" }), "دپلوی اولیهٔ کد Scripts");
      if (!initial?.id) throw new ApiError("شناسهٔ دپلوی اولیه از Cloudflare دریافت نشد", 502);
      record.initial_uploaded = true; record.initial_deployment_id = initial.id;
      await persist("initial_deployed");
      item.steps.push("کد منتخبِ Scripts بار اول روی پروژهٔ جدید دپلوی شد");
    }

    stage = "restore_configs";
    const patch = { production_branch: snapshot.production_branch, deployment_configs: record.restore_configs };
    if (snapshot.build_config) patch.build_config = snapshot.build_config;
    assertOk(await cfPatch(token, projectPath, patch), "برگرداندن بایندینگ‌ها و متغیرهای production/preview");
    await persist("configs_restored");
    item.steps.push("همهٔ بایندینگ‌ها و متغیرهای قابل‌بازیابی production و preview با همان نام و شناسه‌ها برگردانده شدند");

    stage = "restore_domains";
    const attached = new Set((await pagesDomainsStrict(token, account_id, projectName)).map(d => d.name));
    for (const domain of snapshot.domains) {
      if (attached.has(domain)) continue;
      assertOk(await cfPost(token, projectPath + "/domains", { name: domain }), `اتصال دوبارهٔ دامنه «${domain}»`);
      attached.add(domain);
    }
    await persist("domains_restored");
    item.steps.push(snapshot.domains.length ? `دامنه‌ها دوباره متصل شدند: ${snapshot.domains.join("، ")}` : "دامنهٔ سفارشی نداشت؛ آدرس pages.dev با همان نام حفظ شد");

    stage = "final_deploy";
    const final = assertOk(await deployToPages(token, account_id, projectName, code, { ...deployOpts, message: "full rebuild: final code after bindings and domains" }), "دپلوی نهایی بعد از اتصال بایندینگ‌ها و دامنه‌ها");
    record.final_deployment_id = final?.id || null;
    await persist("final_deployed");
    const finalWait = await waitPagesRebuildDeployment(token, account_id, projectName, record.final_deployment_id);
    const rebuildPending = !!finalWait.pending;
    item.steps.push(rebuildPending
      ? "کد Scripts بار دوم دپلوی شد؛ Cloudflare هنوز در حال انتشار آن است (معمولاً تا ۱–۲ دقیقه کامل می‌شود)"
      : "کد Scripts بار دوم، بعد از برگرداندن تنظیمات و دامنه‌ها، دپلوی و موفقیت آن تأیید شد");

    stage = "verify";
    const verified = await readPagesProjectStrict(token, account_id, projectName);
    if (!verified || verified.name !== projectName || verified.production_branch !== snapshot.production_branch ||
        !pagesConfigContains(pagesBindingSubset(verified.deployment_configs), pagesBindingSubset(record.restore_configs))) {
      throw new ApiError("دپلوی انجام شد ولی تطبیق نهایی نام/شاخه/بایندینگ‌ها/متغیرها موفق نبود؛ بکاپ برای ادامهٔ ریبیلد حفظ شده است", 502);
    }
    const finalDomains = await pagesDomainsStrict(token, account_id, projectName);
    const missing = snapshot.domains.filter(d => !finalDomains.some(row => row.name === d));
    if (missing.length) throw new ApiError(`ثبت نهایی این دامنه‌ها تأیید نشد: ${missing.join("، ")}`, 502);
    item.warnings = finalDomains.filter(d => snapshot.domains.includes(d.name) && d.status && d.status !== "active")
      .map(d => `دامنه «${d.name}» ثبت شد؛ وضعیت SSL/DNS فعلاً ${d.status} است`);
    if (rebuildPending) item.warnings.push("دپلوی نهایی ثبت شده و هنوز در حال انتشار است؛ چند لحظه بعد آدرس را باز کنید");
    await env.DB.prepare("INSERT OR REPLACE INTO worker_urls (profile, worker, url) VALUES (?, ?, ?)")
      .bind(profile.name, projectName, `https://${projectName}.pages.dev`).run();
    await savePagesScript(env, profile.name, projectName, { script: options.script_key ? null : code, script_key: options.script_key || null });
    record.complete = true; record.state = "complete"; record.error = null;
    await persist("complete");
    item.ok = true; item.redeployed = true; item.deployment_id = record.final_deployment_id;
    item.message = "ریبیلد کامل Pages انجام شد: حذف پروژه، ساخت با همان نام، دپلوی اولیه، بازگردانی بایندینگ‌ها/متغیرها/دامنه‌ها و دپلوی نهایی";
  } catch (e) {
    item.failed_stage = stage;
    item.message = `${e.message} (مرحله: ${stage})`;
    if (record) {
      record.state = "failed"; record.error = String(e.message || e); record.failed_stage = stage;
      if (record.delete_requested && !record.deleted) {
        try {
          const originalStillThere = await readPagesProjectStrict(token, account_id, projectName);
          if (!originalStillThere) record.deleted = true;
          else if (record.snapshot.id && originalStillThere.id === record.snapshot.id) {
            const remaining = new Set((await pagesDomainsStrict(token, account_id, projectName)).map(d => d.name));
            const recoveredDomains = [], failedDomains = [];
            for (const domain of record.snapshot.domains) {
              if (remaining.has(domain)) continue;
              const restored = await cfPost(token, `/accounts/${account_id}/pages/projects/${encodeURIComponent(projectName)}/domains`, { name: domain });
              (restored?.success === true ? recoveredDomains : failedDomains).push(domain);
            }
            if (recoveredDomains.length) item.steps.push(`پروژهٔ قدیمی حذف نشده بود؛ اتصال این دامنه‌ها برگردانده شد: ${recoveredDomains.join("، ")}`);
            if (failedDomains.length) item.steps.push(`هشدار: بازیابی اتصال این دامنه‌ها روی پروژهٔ قدیمی ناموفق بود؛ بکاپ را نگه دارید: ${failedDomains.join("، ")}`);
          }
        } catch (rollbackError) { item.steps.push(`هشدار: بررسی/بازیابی دامنه‌های پروژهٔ قدیمی ناموفق بود: ${rollbackError.message}`); }
      }
      try { await persist(); } catch { item.steps.push("ثبت آخرین وضعیت شکست در D1 ناموفق بود؛ بکاپ قبلی را نگه دارید"); }
      if (record.delete_requested) item.steps.push("بکاپ قبل از حذف در D1 باقی است؛ اجرای دوبارهٔ ریبیلد ادامهٔ همین عملیات است، نه حذف دوبارهٔ پروژهٔ جدید");
    }
  } finally {
    if (acquired) {
      try { await env.DB.prepare("DELETE FROM settings WHERE key = ? AND value = ?").bind(keys.lock, lock).run(); }
      catch (e) { console.error("Pages rebuild lock cleanup failed:", e); }
    }
  }
  return item;
}

async function repairSinglePagesInPlace(env, type, profile, projectName, code) {
  const item = { profile: profile.name, worker: projectName, kind: "pages", ok: false, message: "", steps: [] };
  try {
    const { token, account_id } = profile;
    if (!(await pagesProjectExists(token, account_id, projectName))) throw new ApiError(`پروژه Pages «${projectName}» در این اکانت پیدا نشد`);

    const projRes = await cfGet(token, `/accounts/${account_id}/pages/projects/${encodeURIComponent(projectName)}`);
    if (!projRes || !projRes.success) throw new ApiError(`دریافت مشخصات پروژه ناموفق: ${errMsg(projRes)}`);
    const configs = (projRes.result && projRes.result.deployment_configs) || {};
    const prod = { ...(configs.production || {}) };
    const prev = { ...(configs.preview || {}) };
    let domainsBefore = [];
    try {
      const dRes = await cfGet(token, `/accounts/${account_id}/pages/projects/${encodeURIComponent(projectName)}/domains`);
      if (dRes && dRes.success && Array.isArray(dRes.result)) domainsBefore = dRes.result.map(d => d.domain || d.name).filter(Boolean);
    } catch {}
    const varCount = Object.keys(prod.env_vars || {}).length;
    item.steps.push(`پیکربندی فعلی خوانده شد (production${varCount ? ` با ${varCount} متغیر` : ""}${domainsBefore.length ? `، دامنه‌ها: ${domainsBefore.join("، ")}` : ""})`);

    const knownValues = { CF_API_TOKEN: token, CF_ACCOUNT_ID: account_id };
    const needVars = ["CF_API_TOKEN"];
    const mergeVars = (vars) => {
      const cur = { ...(vars || {}) };
      let changed = false;
      for (const k of needVars) {
        const v = cur[k];
        const curVal = v && typeof v.value === "string" ? v.value : null;
        const desiredType = k === "CF_API_TOKEN" ? "secret_text" : "plain_text";
        if (curVal !== knownValues[k] || !v || v.type !== desiredType) {
          cur[k] = { type: desiredType, value: knownValues[k] };
          changed = true;
        }
      }
      return { vars: cur, changed };
    };
    const unknownSecrets = [];
    const cleanVars = (vars) => {
      const out = {};
      for (const [k, v] of Object.entries(vars || {})) {
        if (v && v.type === "secret_text" && (v.value === undefined || v.value === null || v.value === "")) {
          if (knownValues[k] !== undefined) {
            out[k] = { type: k === "CF_API_TOKEN" ? "secret_text" : "plain_text", value: knownValues[k] };
          }
          else unknownSecrets.push(k);
        } else {
          out[k] = v && v.type ? { type: v.type, ...(v.value !== undefined ? { value: String(v.value) } : {}) } : v;
        }
      }
      return out;
    };
    const mProd = mergeVars(prod.env_vars);
    const mPrev = mergeVars(prev.env_vars);
    if (mProd.changed || mPrev.changed) {
      const patchRes = await cfPatch(token, `/accounts/${account_id}/pages/projects/${encodeURIComponent(projectName)}`, {
        deployment_configs: {
          production: { ...prod, env_vars: cleanVars(mProd.vars) },
          preview: { ...prev, env_vars: cleanVars(mPrev.vars) },
        },
      });
      if (!patchRes || !patchRes.success) throw new ApiError(`به‌روزرسانی متغیرهای Pages ناموفق: ${errMsg(patchRes)}`);
      item.steps.push("متغیرهای توکن تازه‌سازی شدند (بقیه بایندینگ‌ها و متغیرها دست‌نخورده)");
      if (unknownSecrets.length) {
        item.steps.push(`سکرت‌های ناشناس (مقدارشان از API قابل خواندن نیست، حذف شدند): ${[...new Set(unknownSecrets)].join("، ")}`);
      }
    } else {
      item.steps.push("بایندینگ‌ها و متغیرها به‌روز بودند — تغییری لازم نبود");
    }

    if (!code) throw new ApiError("کدی برای استقرار مجدد پیدا نشد (اسکریپت ذخیره نشده است)");
    const depRes = await deployToPages(token, account_id, projectName, code);
    if (!depRes || !depRes.success) throw new ApiError(`استقرار مجدد روی Pages ناموفق: ${errMsg(depRes)}`);
    item.steps.push("کد تازه روی Pages مستقر شد");
    if (mProd.changed || mPrev.changed) {
      await new Promise(r => setTimeout(r, 1200));
      const second = await deployToPages(token, account_id, projectName, code);
      if (!second || second.success !== true) throw new ApiError(`استقرار دوم Pages ناموفق: ${errMsg(second)}`);
      item.steps.push("استقرار دوم برای اعمال قطعی متغیرها انجام شد");
    }

    let domainsAfter = [];
    try {
      const dRes2 = await cfGet(token, `/accounts/${account_id}/pages/projects/${encodeURIComponent(projectName)}/domains`);
      if (dRes2 && dRes2.success && Array.isArray(dRes2.result)) domainsAfter = dRes2.result.map(d => d.domain || d.name).filter(Boolean);
    } catch {}
    const missing = domainsBefore.filter(d => !domainsAfter.includes(d));
    if (missing.length) item.steps.push(`هشدار: این دامنه‌ها بعد از استقرار دیده نشدند: ${missing.join("، ")}`);
    else item.steps.push(domainsAfter.length ? `دامنه‌ها حفظ شدند (${domainsAfter.length}): ${domainsAfter.join("، ")}` : "دامنه سفارشی نداشت");

    try {
      await env.DB.prepare("INSERT OR REPLACE INTO worker_urls (profile, worker, url) VALUES (?, ?, ?)")
        .bind(profile.name, projectName, `https://${projectName}.pages.dev`).run();
    } catch {}

    item.ok = true;
    item.message = "ریبیلد Pages کامل شد (بایندینگ‌ها، متغیرها و دامنه‌ها حفظ شدند)";
  } catch (e) { item.message = e.message; }
  return item;
}

async function bulkRebuild(env, body, type) {
  const code = body.script || (body.script_key ? await getScript(env, body.script_key) : await getScript(env, type));
  const results = [];
  const seen = new Set();
  for (const t of body.targets || []) {
    let p;
    try { p = await getProfileRow(env, t.profile); }
    catch (e) { results.push({ profile: t.profile, worker: t.worker, kind: t.kind, ok: false, message: e.message, steps: [] }); continue; }
    let isPages = t.kind === "pages";
    try {
      if (t.kind !== "worker" && t.kind !== "pages") {
        const snapshot = await readPagesRebuildRecord(env, p.account_id, t.worker);
        isPages = !!(snapshot?.delete_requested && !snapshot.complete) || await pagesProjectExists(p.token, p.account_id, t.worker);
      }
    } catch (e) {
      results.push({ profile: t.profile, worker: t.worker, kind: t.kind, ok: false, message: e.message, steps: [] });
      continue;
    }
    const kind = isPages ? "pages" : "worker";
    const targetId = JSON.stringify([p.account_id, kind, t.worker]);
    if (seen.has(targetId)) { results.push({ profile: t.profile, worker: t.worker, kind, ok: true, skipped: true, message: "هدف تکراری در همین درخواست دوباره ریبیلد نشد", steps: [] }); continue; }
    seen.add(targetId);
    const item = isPages
      ? await rebuildSinglePages(env, type, p, t.worker, code, { script_key: body.script_key || (body.script ? null : type), secret_values: body.secret_values || {} })
      : await rebuildSingleWorker(env, type, p, t.worker, code, { secret_values: body.secret_values || {} });
    if (!isPages && item.ok) {
      try { await saveWorkerRecoverySource(env, p.name, t.worker, code, body.script ? null : (body.script_key || type)); } catch {}
    }
    item.kind = kind;
    results.push(item);
  }
  return { ok: true, results };
}

async function runHealthCheck(env) {
  await ensureSchema(env);
  const autoRebuild = (await getSetting(env, "auto_rebuild")) !== "0";
  const { results: profiles } = await env.DB.prepare("SELECT * FROM profiles ORDER BY pos, created_at, name").all();
  const cfgRows = (await env.DB.prepare("SELECT * FROM health_config").all()).results || [];
  const cfgMap = {};
  for (const c of cfgRows) cfgMap[`${c.profile}||${c.worker}`] = c.path || "/";
  const out = [];
  const subCache = {};
  for (const p of (profiles || [])) {
    const row = { ...p, nexa_workers: JSON.parse(p.nexa_workers || "[]") };
    for (const w of row.nexa_workers) out.push(await checkOneWorker(env, row, w, "nexa", autoRebuild, subCache, cfgMap[`${row.name}||${w}`]));
  }
  await env.DB.prepare("DELETE FROM health_checks WHERE id NOT IN (SELECT id FROM health_checks ORDER BY id DESC LIMIT 500)").run();
  return out;
}

const DEFAULT_PROBE_PATHS = ["/admin", "/"];

async function checkOneWorker(env, profile, workerName, type, autoRebuild, subCache, pathArg) {
  const custom = (typeof pathArg === "string" && pathArg.trim()) ? pathArg.trim() : null;
  let kind = "worker";
  try {
    const ps = await env.DB.prepare("SELECT project FROM pages_scripts WHERE profile = ? AND project = ?")
      .bind(profile.name, workerName).first();
    if (ps) kind = "pages";
  } catch {}
  if (kind === "worker") {
    try {
      if (!(await workerExists(profile.token, profile.account_id, workerName)) &&
          await pagesProjectExists(profile.token, profile.account_id, workerName)) kind = "pages";
    } catch {}
  }
  const paths = custom ? [(custom.startsWith("/") ? custom : "/" + custom)] : DEFAULT_PROBE_PATHS;
  let httpStatus = null, verdict = "ok", message = custom ? `مسیر بررسی: ${paths[0]}` : "";
  try {
    let base = null;
    if (kind === "pages") {
      base = `https://${encodeURIComponent(workerName)}.pages.dev`;
      try {
        await env.DB.prepare("INSERT OR REPLACE INTO worker_urls (profile, worker, url) VALUES (?, ?, ?)")
          .bind(profile.name, workerName, base).run();
      } catch {}
    } else {
      if (!(profile.account_id in subCache)) {
        const res = await cfGet(profile.token, `/accounts/${profile.account_id}/workers/subdomain`);
        subCache[profile.account_id] = res && res.success && res.result ? (res.result.subdomain || null) : null;
      }
      const sub = subCache[profile.account_id];
      if (sub) {
        base = `https://${encodeURIComponent(workerName)}.${sub}.workers.dev`;
        try {
          await env.DB.prepare("INSERT OR REPLACE INTO worker_urls (profile, worker, url) VALUES (?, ?, ?)")
            .bind(profile.name, workerName, base).run();
        } catch {}
      } else {
        try {
          const row = await env.DB.prepare("SELECT url FROM worker_urls WHERE profile = ? AND worker = ?")
            .bind(profile.name, workerName).first();
          base = row ? row.url : null;
        } catch {}
      }
    }
    if (!base) base = `https://${encodeURIComponent(workerName)}.workers.dev`;
    const baseClean = String(base).replace(/\/+$/, "");
    for (const normPath of paths) {
      const url = `${baseClean}${normPath}`;
      let r;
      try { r = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(15000) }); }
      catch (e) { verdict = "unreachable"; message = String(e.message || e); break; }
      httpStatus = r.status;
      const body = (await r.text()).slice(0, 4096);
      const hasExceptionText = /threw\s+(?:a\s+)?(?:javascript\s+)?exception/i.test(body);
      const hasErr1101 = /error\s*1101/i.test(body);
      const hasBare1101 = /\b1101\b/.test(body);
      if (hasExceptionText || hasErr1101 || (r.status >= 500 && hasBare1101)) {
        verdict = "error_1101";
        if (paths.length > 1) message = `خطا روی ${normPath}`;
        break;
      } else if (r.status >= 500) {
        verdict = "other_error";
        message = `HTTP ${r.status}${paths.length > 1 ? ` (روی ${normPath})` : ""}`;
        break;
      } else if (!message) {
        message = `مسیر ${normPath} سالم است`;
      }
    }
  } catch (e) { verdict = "unreachable"; message = String(e.message || e); }

  let status = verdict, fixedAt = null;
  if (verdict === "error_1101" && autoRebuild) {
    let code = null;
    let sourceKey = null;
    if (kind === "pages") {
      try { const source = await resolvePagesRebuildSource(env, profile, workerName, type); code = source.code; sourceKey = source.key; }
      catch (e) { message = String(e.message || e); }
    } else {
      try {
        const source = await resolveWorkerRecoverySource(env, profile, workerName, type);
        code = source.code;
        sourceKey = source.key;
      } catch (e) { message = String(e.message || e); }
    }
    if (code) {
      const r = kind === "pages"
        ? await rebuildSinglePages(env, type, profile, workerName, code, { script_key: sourceKey || null })
        : await rebuildSingleWorker(env, type, profile, workerName, code);
      if (r.ok) {
        status = "rebuilt_ok";
        fixedAt = new Date().toISOString().slice(0, 19).replace("T", " ");
        message = r.message + (custom ? ` (مسیر: ${paths[0]})` : "");
      } else { status = "rebuild_failed"; message = r.message; }
    } else {
      status = "skipped";
    }
  }
  await env.DB.prepare(
    "INSERT INTO health_checks (profile, worker, type, status, http_status, message, fixed_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).bind(profile.name, workerName, type, status, httpStatus, message || null, fixedAt).run();
  return { profile: profile.name, worker: workerName, type, kind, status, http_status: httpStatus, message: message || null, fixed_at: fixedAt };
}

async function deleteWorkerAndResources(env, profile, name, withResources) {
  const { token, account_id } = profile;
  const bindings = await fetchBindings(token, account_id, name);
  const kvIds = bindings.filter(b => b.type === "kv_namespace" && b.namespace_id).map(b => b.namespace_id);
  const d1Ids = bindings.filter(b => b.type === "d1" && b.database_id).map(b => b.database_id);

  const res = await cfDelete(token, `/accounts/${account_id}/workers/scripts/${encodeURIComponent(name)}`);
  if (!(res && (res.success || res.result !== undefined))) throw new ApiError(`حذف ورکر ناموفق: ${errMsg(res)}`, 502);

  const row = await getProfileRow(env, profile.name);
  await saveFlags(env, profile.name, row.nexa_workers.filter(w => w !== name));
  await env.DB.prepare("DELETE FROM worker_urls WHERE profile = ? AND worker = ?").bind(profile.name, name).run();
  await env.DB.prepare("DELETE FROM pages_scripts WHERE profile = ? AND project = ?").bind(profile.name, name).run();
  await delSetting(env, workerRecoverySourceKey(profile.name, name));

  const deleted = { kv: [], d1: [], kv_failed: [], d1_failed: [] };
  if (withResources) {
    for (const id of kvIds) {
      const r = await cfDelete(token, `/accounts/${account_id}/storage/kv/namespaces/${id}`);
      (r && r.success ? deleted.kv : deleted.kv_failed).push(id);
    }
    for (const id of d1Ids) {
      const r = await cfDelete(token, `/accounts/${account_id}/d1/database/${id}`);
      (r && (r.success || typeof r.result === "object") ? deleted.d1 : deleted.d1_failed).push(id);
    }
  }
  return { ok: true, worker: name, ...deleted };
}

async function deletePagesAndResources(env, profile, name, withResources = true) {
  const { token, account_id } = profile;

  let d1Ids = [];
  let kvIds = [];
  try {
    const projRes = await cfGet(token, `/accounts/${account_id}/pages/projects/${encodeURIComponent(name)}`);
    if (projRes && projRes.success && projRes.result) {
      const configs = projRes.result.deployment_configs || {};
      const d1Set = new Set();
      const kvSet = new Set();
      for (const envKey of ["production", "preview"]) {
        const envConf = configs[envKey];
        if (!envConf) continue;
        if (envConf.d1_databases) {
          for (const k of Object.keys(envConf.d1_databases)) {
            const val = envConf.d1_databases[k];
            const id = typeof val === "string" ? val : (val?.id || val?.database_id);
            if (id) d1Set.add(id);
          }
        }
        if (envConf.kv_namespaces) {
          for (const k of Object.keys(envConf.kv_namespaces)) {
            const val = envConf.kv_namespaces[k];
            const id = typeof val === "string" ? val : (val?.namespace_id || val?.id);
            if (id) kvSet.add(id);
          }
        }
      }
      d1Ids = Array.from(d1Set);
      kvIds = Array.from(kvSet);
    }
  } catch (e) {
    console.error("Failed to inspect pages bindings before deletion:", e);
  }

  const projPath = `/accounts/${account_id}/pages/projects/${encodeURIComponent(name)}`;
  let res = await cfDelete(token, projPath);
  if (!res || (!res.success && typeof res.result !== "object")) {
    try {
      const doms = await cfGet(token, `${projPath}/domains`);
      const list = Array.isArray(doms?.result) ? doms.result : [];
      for (const d of list) {
        const dn = typeof d === "string" ? d : (d.name || d.domain);
        if (dn) await cfDelete(token, `${projPath}/domains/${encodeURIComponent(dn)}`);
      }
      if (list.length) res = await cfDelete(token, projPath);
    } catch {}
  }
  if (!res || (!res.success && typeof res.result !== "object")) {
    throw new ApiError(`حذف پروژه Pages ناموفق: ${errMsg(res)}`, 502, { details: res });
  }

  try {
    const row = await getProfileRow(env, profile.name);
    await saveFlags(env, profile.name, row.nexa_workers.filter(w => w !== name));
    await env.DB.prepare("DELETE FROM worker_urls WHERE profile = ? AND worker = ?").bind(profile.name, name).run();
  } catch {}

  const deleted = { kv: [], d1: [], kv_failed: [], d1_failed: [] };
  if (withResources) {
    for (const id of kvIds) {
      try {
        const r = await cfDelete(token, `/accounts/${account_id}/storage/kv/namespaces/${id}`);
        (r && r.success ? deleted.kv : deleted.kv_failed).push(id);
      } catch {
        deleted.kv_failed.push(id);
      }
    }
    for (const id of d1Ids) {
      try {
        const r = await cfDelete(token, `/accounts/${account_id}/d1/database/${id}`);
        (r && (r.success || typeof r.result === "object") ? deleted.d1 : deleted.d1_failed).push(id);
      } catch {
        deleted.d1_failed.push(id);
      }
    }
  }

  return { ok: true, project: name, ...deleted };
}

async function fetchPagesBindings(token, accountId, name) {
  const projRes = await cfGet(token, `/accounts/${accountId}/pages/projects/${encodeURIComponent(name)}`);
  if (!projRes || !projRes.success || !projRes.result) {
    return { bindings: [], d1_databases: {}, env_vars: {}, kv_namespaces: {} };
  }
  const configs = projRes.result.deployment_configs || {};
  const prod = configs.production || {};
  const prev = configs.preview || {};

  const d1_databases = { ...(prev.d1_databases || {}), ...(prod.d1_databases || {}) };
  const env_vars = { ...(prev.env_vars || {}), ...(prod.env_vars || {}) };
  const kv_namespaces = { ...(prev.kv_namespaces || {}), ...(prod.kv_namespaces || {}) };

  const bindings = [];
  for (const [bindingName, val] of Object.entries(d1_databases)) {
    if (val === null || val === undefined) continue;
    bindings.push({
      name: bindingName,
      type: "d1",
      database_id: typeof val === "string" ? val : (val?.id || val?.database_id),
    });
  }
  for (const [bindingName, val] of Object.entries(kv_namespaces)) {
    if (val === null || val === undefined) continue;
    bindings.push({
      name: bindingName,
      type: "kv_namespace",
      namespace_id: typeof val === "string" ? val : (val?.namespace_id || val?.id),
    });
  }
  for (const [bindingName, val] of Object.entries(env_vars)) {
    if (val === null || val === undefined) continue;
    const isSecret = typeof val === "object" && val?.type === "secret_text";
    bindings.push({
      name: bindingName,
      type: isSecret ? "secret_text" : "plain_text",
      text: typeof val === "string" ? val : (val?.value || ""),
    });
  }

  return {
    bindings,
    d1_databases,
    env_vars,
    kv_namespaces,
    configs
  };
}

async function bindPagesKv(env, profile, name, envName, kvId) {
  const { token, account_id } = profile;
  const projRes = await cfGet(token, `/accounts/${account_id}/pages/projects/${encodeURIComponent(name)}`);
  if (!projRes || !projRes.success) throw new ApiError(`دریافت پروژه ناموفق: ${errMsg(projRes)}`, 502);

  const res = await pagesPatchDeploymentConfigs(token, account_id, name, { kv_namespaces: { [envName]: { namespace_id: kvId } } });
  assertOk(res, `اتصال KV به Pages «${name}»`);

  const redeployResult = await redeployPagesProject(env, profile, name);

  return {
    ok: true,
    redeployed: redeployResult.redeployed,
    message: redeployResult.redeployed
      ? `KV به‌عنوان env.${envName} متصل شد و کدهای پروژه به صورت خودکار مجدداً مستقر (Re-deploy) شدند ✓`
      : `KV به‌عنوان env.${envName} به پروژه Pages متصل شد ✓`
  };
}

async function bindPagesD1(env, profile, name, envName, databaseId, databaseName = null) {
  const { token, account_id } = profile;
  let targetId = databaseId;
  if (!targetId && databaseName) {
    const d1Res = await getOrCreateD1Database(token, account_id, databaseName.trim());
    targetId = d1Res.uuid || d1Res.id || (d1Res.result && (d1Res.result.uuid || d1Res.result.id));
  }
  if (!targetId) throw new ApiError("شناسه یا نام پایگاه داده D1 الزامی است", 400);

  const projRes = await cfGet(token, `/accounts/${account_id}/pages/projects/${encodeURIComponent(name)}`);
  if (!projRes || !projRes.success) throw new ApiError(`دریافت پروژه ناموفق: ${errMsg(projRes)}`, 502);

  const res = await pagesPatchDeploymentConfigs(token, account_id, name, { d1_databases: { [envName]: { id: targetId } } });
  assertOk(res, `اتصال D1 به Pages «${name}»`);

  const redeployResult = await redeployPagesProject(env, profile, name);

  return {
    ok: true,
    redeployed: redeployResult.redeployed,
    redeploy_method: redeployResult.method,
    message: redeployResult.redeployed
      ? `D1 به‌عنوان env.${envName} متصل شد و کدهای پروژه به صورت خودکار مجدداً مستقر (Re-deploy) شدند ✓`
      : `D1 به‌عنوان env.${envName} به پروژه Pages متصل شد ✓`
  };
}

async function unbindPages(env, profile, name, envName) {
  const { token, account_id } = profile;
  const projRes = await cfGet(token, `/accounts/${account_id}/pages/projects/${encodeURIComponent(name)}`);
  if (!projRes || !projRes.success) throw new ApiError(`دریافت پروژه ناموفق: ${errMsg(projRes)}`, 502);

  const configs = projRes.result?.deployment_configs || {};
  const stagePatch = (conf) => {
    const out = {};
    for (const field of ["d1_databases", "kv_namespaces", "env_vars", "r2_buckets", "services", "durable_object_namespaces"]) {
      if (conf && conf[field] && Object.prototype.hasOwnProperty.call(conf[field], envName)) out[field] = { [envName]: null };
    }
    return out;
  };
  const prodPatch = stagePatch(configs.production);
  const prevPatch = stagePatch(configs.preview);
  if (!Object.keys(prodPatch).length && !Object.keys(prevPatch).length) {
    throw new ApiError(`بایندینگ یا متغیری با نام «${envName}» روی این پروژه وجود ندارد`, 404);
  }
  const res = await cfPatch(token, `/accounts/${account_id}/pages/projects/${encodeURIComponent(name)}`, {
    deployment_configs: { production: prodPatch, preview: prevPatch },
  });
  assertOk(res, `حذف بایندینگ از Pages «${name}»`);

  const redeployResult = await redeployPagesProject(env, profile, name);

  return {
    ok: true,
    redeployed: redeployResult.redeployed,
    message: redeployResult.redeployed
      ? `بایندینگ «${envName}» حذف شد و کدهای پروژه مجدداً مستقر (Re-deploy) شدند ✓`
      : `بایندینگ «${envName}» از پروژه Pages حذف شد ✓`
  };
}

async function savePagesScript(env, profileName, projectName, { script, script_key }) {
  if (!env.DB) return;
  try {
    await env.DB.prepare(`
      INSERT OR REPLACE INTO pages_scripts (profile, project, script, script_key, updated_at)
      VALUES (?, ?, ?, ?, datetime('now'))
    `).bind(profileName, projectName, script || null, script_key || null).run();
  } catch (e) {
    console.error("Failed to save pages script:", e);
  }
}

async function getPagesScript(env, profileName, projectName) {
  if (!env.DB) return null;
  try {
    const row = await env.DB.prepare("SELECT * FROM pages_scripts WHERE profile = ? AND project = ?")
      .bind(profileName, projectName).first();
    if (row) {
      if (row.script_key) return await getScript(env, row.script_key);
      if (row.script) return row.script;
    }
  } catch {}
  return null;
}

async function redeployPagesProject(env, profile, projectName, explicitCode = null) {
  const { token, account_id } = profile;
  let code = explicitCode, sourceError = null;
  if (!code) {
    const type = "nexa";
    try { code = (await resolvePagesRebuildSource(env, profile, projectName, type)).code; }
    catch (e) {
      sourceError = e;
      if (e.status !== 404) return { ok: false, redeployed: false, note: `دریافت کد از منبع سراسری ناموفق: ${e.message}` };
    }
  }
  if (code) {
    const res = await deployToPages(token, account_id, projectName, code);
    if (res?.success === true) return { ok: true, redeployed: true, method: "direct_upload", deployment_id: res.result?.id || null };
    return { ok: false, redeployed: false, note: `استقرار کد موجود روی Pages ناموفق: ${errMsg(res)}` };
  }
  const deps = await cfGet(token, `/accounts/${account_id}/pages/projects/${encodeURIComponent(projectName)}/deployments`);
  if (deps?.success !== true) return { ok: false, redeployed: false, note: `دریافت دپلوی‌های قبلی Pages ناموفق: ${errMsg(deps)}` };
  const latest = deps.result?.[0]?.id;
  if (latest) {
    const retry = await cfPost(token, `/accounts/${account_id}/pages/projects/${encodeURIComponent(projectName)}/deployments/${encodeURIComponent(latest)}/retry`);
    if (retry?.success === true) return { ok: true, redeployed: true, method: "deployment_retry" };
    return { ok: false, redeployed: false, note: `تکرار دپلوی قبلی Pages ناموفق: ${errMsg(retry)}` };
  }
  return { ok: false, redeployed: false, note: sourceError?.message || "کدی در Scripts یا دپلوی قبلی برای این پروژه وجود ندارد" };
}

async function setPagesEnvVar(env, profile, name, { key, value, type = "plain_text" }) {
  const { token, account_id } = profile;
  const k = String(key || "").trim();
  if (!k) throw new ApiError("نام متغیر محیطی الزامی است", 400);

  const projRes = await cfGet(token, `/accounts/${account_id}/pages/projects/${encodeURIComponent(name)}`);
  if (!projRes || !projRes.success) throw new ApiError(`دریافت مشخصات پروژه ناموفق: ${errMsg(projRes)}`, 502);

  const varObj = {
    type: type === "secret_text" ? "secret_text" : "plain_text",
    value: String(value ?? "")
  };
  const res = await pagesPatchDeploymentConfigs(token, account_id, name, { env_vars: { [k]: varObj } });
  assertOk(res, `ذخیره متغیر محیطی «${k}» در Pages`);

  const redeployResult = await redeployPagesProject(env, profile, name);

  return {
    ok: true,
    key: k,
    type: varObj.type,
    redeployed: redeployResult.redeployed,
    redeploy_method: redeployResult.method,
    message: redeployResult.redeployed
      ? `متغیر محیطی «${k}» با موفقیت ذخیره شد و کدهای پروژه به صورت خودکار مجدداً مستقر (Re-deploy) شدند ✓`
      : `متغیر محیطی «${k}» در پروژه Pages ذخیره شد ✓`
  };
}

async function deletePagesEnvVar(env, profile, name, key) {
  const { token, account_id } = profile;
  const k = String(key || "").trim();
  if (!k) throw new ApiError("نام متغیر محیطی الزامی است", 400);

  const projRes = await cfGet(token, `/accounts/${account_id}/pages/projects/${encodeURIComponent(name)}`);
  if (!projRes || !projRes.success) throw new ApiError(`دریافت مشخصات پروژه ناموفق: ${errMsg(projRes)}`, 502);

  const res = await pagesPatchDeploymentConfigs(token, account_id, name, { env_vars: { [k]: null } });
  assertOk(res, `حذف متغیر محیطی «${k}» از Pages`);

  const redeployResult = await redeployPagesProject(env, profile, name);

  return {
    ok: true,
    key: k,
    redeployed: redeployResult.redeployed,
    redeploy_method: redeployResult.method,
    message: redeployResult.redeployed
      ? `متغیر «${k}» حذف شد و کدهای پروژه به صورت خودکار مجدداً مستقر (Re-deploy) شدند ✓`
      : `متغیر «${k}» از پروژه Pages حذف شد ✓`
  };
}

async function changePagesD1(env, profile, projectName, { new_database_id, new_database_name, env_name = "DB", delete_old = false }) {
  const { token, account_id } = profile;

  const projRes = await cfGet(token, `/accounts/${account_id}/pages/projects/${encodeURIComponent(projectName)}`);
  if (!projRes || !projRes.success) throw new ApiError(`دریافت مشخصات پروژه Pages ناموفق: ${errMsg(projRes)}`, 502);

  const configs = projRes.result?.deployment_configs || {};
  const prod = configs.production || {};
  const prev = configs.preview || {};

  let oldId = null;
  const oldVal = prod.d1_databases?.[env_name] || prev.d1_databases?.[env_name];
  if (oldVal) {
    oldId = typeof oldVal === "string" ? oldVal : (oldVal?.id || oldVal?.database_id);
  }

  let targetId = new_database_id;
  if (!targetId && new_database_name) {
    const d1Res = await getOrCreateD1Database(token, account_id, new_database_name.trim());
    targetId = d1Res.uuid || d1Res.id || (d1Res.result && (d1Res.result.uuid || d1Res.result.id));
  }
  if (!targetId) throw new ApiError("شناسه یا نام پایگاه داده D1 جدید الزامی است", 400);

  const patchRes = await pagesPatchDeploymentConfigs(token, account_id, projectName, { d1_databases: { [env_name]: { id: targetId } } });
  assertOk(patchRes, `تغییر بایندینگ D1 در Pages «${projectName}»`);

  let oldDeleted = false;
  if (delete_old && oldId && oldId !== targetId) {
    try {
      const delRes = await cfDelete(token, `/accounts/${account_id}/d1/database/${oldId}`);
      oldDeleted = !!(delRes && (delRes.success === true || (delRes.result && typeof delRes.result === "object")));
    } catch (e) {
      console.error("Failed to delete old D1:", e);
    }
  }

  const redeployResult = await redeployPagesProject(env, profile, projectName);

  return {
    ok: true,
    project: projectName,
    old_database_id: oldId,
    new_database_id: targetId,
    old_deleted: oldDeleted,
    redeployed: redeployResult.redeployed,
    redeploy_method: redeployResult.method,
    message: `دیتابیس D1 با موفقیت به «${String(targetId)}» تغییر یافت${oldDeleted ? " (دیتابیس قبلی حذف شد)" : ""}${redeployResult.redeployed ? " و کدهای پروژه به صورت خودکار مجدداً مستقر (Re-deploy) شدند ✓" : ` — Re-deploy خودکار انجام نشد: ${redeployResult.note || "نامشخص"}`}`
  };
}

async function renameWorker(env, profile, oldName, newName) {
  if (!newName || newName === oldName) throw new ApiError("نام جدید نامعتبر است");
  const { token, account_id } = profile;

  const code = await getWorkerScript(token, account_id, oldName);
  const bindings = bindingsToMetadata(await fetchBindings(token, account_id, oldName));

  assertOk(await rebuildWithBindings(token, account_id, newName, bindings, code), `استقرار «${newName}»`);

  const row = await getProfileRow(env, profile.name);
  await saveFlags(env, profile.name, row.nexa_workers.map(w => w === oldName ? newName : w));
  try {
    await saveWorkerRecoverySource(env, profile.name, newName, code, null);
    await delSetting(env, workerRecoverySourceKey(profile.name, oldName));
  } catch {}
  try {
    const migratedUrl = await workerUrl(token, account_id, newName);
    await env.DB.prepare("UPDATE worker_urls SET worker = ?, url = ? WHERE profile = ? AND worker = ?")
      .bind(newName, migratedUrl, profile.name, oldName).run();
  } catch {}

  await enableSubdomain(token, account_id, newName);
  const delRes = await cfDelete(token, `/accounts/${account_id}/workers/scripts/${encodeURIComponent(oldName)}`);
  return {
    ok: true,
    new_name: newName,
    old_deleted: !!(delRes && (delRes.success || delRes.result !== undefined)),
    url: await workerUrl(token, account_id, newName),
  };
}

const routes = [];
function route(method, pattern, handler, opts = {}) {
  const names = [];
  const rx = new RegExp("^" + pattern.replace(/:[a-zA-Z_]+/g, m => { names.push(m.slice(1)); return "([^/]+)"; }) + "$");
  routes.push({ method, rx, names, handler, public: !!opts.public });
}

route("GET", "/api/status", async (m, req, env) => {
  let d1 = true, d1Error = null;
  try { await ensureSchema(env); } catch (e) { d1 = false; d1Error = e.message || String(e); }
  const admin_set = adminPassword(env).length > 0;
  let authed = false;
  if (d1) {
    try { await requireSession(req, env); authed = true; } catch {}
  }
  return json({ d1, d1Error, admin_set, setup: admin_set, authed });
}, { public: true });

route("POST", "/api/login", async (m, req, env) => {
  await ensureSchema(env);
  const lockUntil = parseInt((await getSetting(env, "lock_until")) || "0", 10);
  if (lockUntil > Date.now()) throw new ApiError(`تلاش زیاد. تا ${Math.ceil((lockUntil - Date.now()) / 60000)} دقیقه دیگر صبر کنید.`, 429);
  const body = await req.json();
  const pw = String(body.password || "");
  const realPw = adminPassword(env);
  if (!realPw || pw !== realPw) {
    const fails = parseInt((await getSetting(env, "login_fails")) || "0", 10) + 1;
    await setSetting(env, "login_fails", String(fails));
    if (fails >= 5) {
      await setSetting(env, "lock_until", String(Date.now() + 10 * 60 * 1000));
      await setSetting(env, "login_fails", "0");
    }
    throw new ApiError("رمز عبور اشتباه است", 401);
  }
  await delSetting(env, "login_fails");
  await delSetting(env, "lock_until");
  const tok = randomToken(32);
  await env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(Math.floor(Date.now() / 1000)).run();
  await env.DB.prepare("INSERT INTO sessions (token, expires_at) VALUES (?, ?)")
    .bind(tok, Math.floor(Date.now() / 1000) + SESSION_TTL).run();
  return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(tok) });
}, { public: true });

route("POST", "/api/logout", async (m, req, env) => {
  const tok = getCookie(req, COOKIE);
  if (tok) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(tok).run();
  return json({ ok: true }, 200, { "Set-Cookie": clearSessionCookie() });
});

route("POST", "/api/admin-password", async (m, req, env) => {
  const body = await req.json();
  const realPw = adminPassword(env);
  if (!realPw) throw new ApiError("متغیر محیطی ADMIN تنظیم نشده است", 400);
  if (String(body.current || "") !== realPw) throw new ApiError("رمز فعلی اشتباه است", 401);
  const next = String(body.next || "");
  if (next.length < 6) throw new ApiError("رمز جدید باید حداقل ۶ کاراکتر باشد", 400);

  let selfName = typeof env.WORKER_NAME === "string" && env.WORKER_NAME ? env.WORKER_NAME : null;
  if (!selfName) {
    const host = new URL(req.url).hostname;
    const mm = host.match(/^([a-z0-9-]+)\.[a-z0-9-]+\.workers\.dev$/i);
    if (mm) selfName = mm[1].toLowerCase();
  }
  if (!selfName) throw new ApiError("نام این ورکر قابل تشخیص نبود — از آدرس workers.dev وارد شوید، متغیر WORKER_NAME را تنظیم کنید، یا ADMIN را مستقیم از داشبورد تغییر دهید.", 400);

  const { results } = await env.DB.prepare("SELECT * FROM profiles ORDER BY pos, created_at, name").all();
  const errs = [];
  for (const p of (results || [])) {
    try {
      if (!(await workerExists(p.token, p.account_id, selfName))) continue;
      const defs = bindingsToMetadata(await fetchBindings(p.token, p.account_id, selfName))
        .filter(b => b.name !== "ADMIN");
      defs.push({ type: "plain_text", name: "ADMIN", text: next });
      await applyBindings(p.token, p.account_id, selfName, defs);
      return json({
        ok: true, worker: selfName, account: p.name,
        message: `متغیر ADMIN روی ورکر «${selfName}» به‌صورت Text به‌روزرسانی شد؛ چند لحظه تا اعمال کامل زمان می‌برد.`,
      });
    } catch (e) { errs.push(`${p.name}: ${e.message}`); }
  }
  throw new ApiError(`ورکر «${selfName}» در اکانت‌های ذخیره‌شده پیدا نشد${errs.length ? " — " + errs.join(" | ") : ""}. متغیر ADMIN را از داشبورد Cloudflare دستی تغییر دهید.`, 404);
});

route("GET", "/api/profiles", async (m, req, env) => {
  return json({ profiles: await listProfiles(env) });
});

route("POST", "/api/profiles", async (m, req, env) => {
  const body = await req.json();
  const name = String(body.name || "").trim();
  const token = String(body.token || "").trim();
  let accountId = String(body.account_id || "").trim();
  if (!name) throw new ApiError("نام پروفایل نمی‌تواند خالی باشد", 400);
  if (!token) throw new ApiError("توکن نمی‌تواند خالی باشد", 400);

  const exists = await env.DB.prepare("SELECT name, pos FROM profiles WHERE name = ?").bind(name).first();
  if (exists && !body.overwrite) throw new ApiError(`پروفایل «${name}» از قبل وجود دارد`, 409);

  const accounts = await fetchAccountsForToken(token);
  if (!accounts.length) throw new ApiError("توکن معتبر نیست یا به هیچ اکانتی دسترسی ندارد", 401);
  if (!accountId) {
    if (accounts.length === 1) accountId = accounts[0].id;
    else return json({ need_account: true, accounts: accounts.map(a => ({ id: a.id, name: a.name })) });
  }

  let pos = exists ? exists.pos : (((await env.DB.prepare("SELECT COALESCE(MAX(pos), -1) AS m FROM profiles").first()) || {}).m + 1);
  await env.DB.prepare(`INSERT OR REPLACE INTO profiles (name, token, account_id, nexa_workers, pos) VALUES (?, ?, ?, '[]', ?)`).bind(name, token, accountId, pos).run();
  const acc = accounts.find(a => a.id === accountId);
  return json({ ok: true, profile: { name, account_id: accountId, account_name: acc ? acc.name : null } });
});

route("POST", "/api/profiles/bulk", async (m, req, env) => {
  const body = await req.json();
  const entries = Array.isArray(body.entries) ? body.entries : [];
  if (!entries.length) throw new ApiError("لیست خالی است", 400);
  if (entries.length > 50) throw new ApiError("حداکثر ۵۰ اکانت در هر بار", 400);
  const existRows = (await env.DB.prepare("SELECT name, pos FROM profiles").all()).results || [];
  const posOf = new Map(existRows.map(r => [r.name, r.pos]));
  let nextPos = existRows.length ? Math.max(...existRows.map(r => r.pos)) + 1 : 0;
  const results = [];
  for (const e of entries) {
    const name = String(e.name || "").trim();
    const token = String(e.token || "").trim();
    const item = { name, ok: false, message: "" };
    try {
      if (!name) throw new ApiError("نام خالی است");
      if (!token) throw new ApiError("توکن خالی است");
      let accountId = String(e.account_id || "").trim();
      const accounts = await fetchAccountsForToken(token);
      if (!accounts.length) throw new ApiError("توکن معتبر نیست یا به هیچ اکانتی دسترسی ندارد");
      if (!accountId) {
        if (accounts.length === 1) accountId = accounts[0].id;
        else {
          item.message = `توکن به ${accounts.length} اکانت دسترسی دارد (${accounts.map(a => a.name).join("، ")}) — account_id را در انتهای خط اضافه کنید`;
          results.push(item);
          continue;
        }
      }
      const pos = posOf.has(name) ? posOf.get(name) : nextPos++;
      await env.DB.prepare("INSERT OR REPLACE INTO profiles (name, token, account_id, nexa_workers, pos) VALUES (?, ?, ?, '[]', ?)")
        .bind(name, token, accountId, pos).run();
      const acc = accounts.find(a => a.id === accountId);
      item.ok = true;
      item.account_id = accountId;
      item.message = `ذخیره شد — ${acc ? acc.name : accountId}`;
    } catch (err) { item.message = err.message; }
    results.push(item);
  }
  return json({ ok: true, results });
});

route("POST", "/api/profiles/reorder", async (m, req, env) => {
  const body = await req.json().catch(() => ({}));
  const order = Array.isArray(body.order) ? body.order.map(String).filter(Boolean) : [];
  if (!order.length) throw new ApiError("ترتیب معتبر نیست", 400);
  const stmts = order.map((n, i) => env.DB.prepare("UPDATE profiles SET pos = ? WHERE name = ?").bind(i, n));
  for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
  return json({ ok: true });
});

route("DELETE", "/api/profiles/:name", async (m, req, env) => {
  const name = decodeURIComponent(m.name);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM profiles WHERE name = ?").bind(name),
    env.DB.prepare("DELETE FROM worker_urls WHERE profile = ?").bind(name),
    env.DB.prepare("DELETE FROM health_config WHERE profile = ?").bind(name),
    env.DB.prepare("DELETE FROM pages_scripts WHERE profile = ?").bind(name),
  ]);
  return json({ ok: true });
});

route("PUT", "/api/profiles/:name", async (m, req, env) => {
  const oldName = decodeURIComponent(m.name);
  const body = await req.json();
  const cur = await getProfileRow(env, oldName);
  const newName = String(body.new_name || "").trim() || oldName;
  let token = String(body.token || "").trim();
  let accountId = String(body.account_id || "").trim();

  if (newName !== oldName) {
    const dup = await env.DB.prepare("SELECT name FROM profiles WHERE name = ?").bind(newName).first();
    if (dup) throw new ApiError(`پروفایل «${newName}» از قبل وجود دارد`, 409);
  }

  if (token) {
    const accounts = await fetchAccountsForToken(token);
    if (!accounts.length) throw new ApiError("توکن معتبر نیست یا به هیچ اکانتی دسترسی ندارد", 401);
    if (!accountId) {
      if (accounts.length === 1) accountId = accounts[0].id;
      else throw new ApiError(`توکن به ${accounts.length} اکانت دسترسی دارد (${accounts.map(a => a.name).join("، ")}) — Account ID را مشخص کنید`, 400);
    }
  } else {
    token = cur.token;
    if (!accountId) accountId = cur.account_id;
  }

  await env.DB.prepare("UPDATE profiles SET name = ?, token = ?, account_id = ?, updated_at = datetime('now') WHERE name = ?")
    .bind(newName, token, accountId, oldName).run();

  if (newName !== oldName) {
    await env.DB.batch([
      env.DB.prepare("UPDATE worker_urls SET profile = ? WHERE profile = ?").bind(newName, oldName),
      env.DB.prepare("UPDATE health_config SET profile = ? WHERE profile = ?").bind(newName, oldName),
      env.DB.prepare("UPDATE pages_scripts SET profile = ? WHERE profile = ?").bind(newName, oldName),
    ]);
  }
  return json({ ok: true, profile: { name: newName, account_id: accountId } });
});

route("GET", "/api/token-link", async (m, req, env) => {
  const url = new URL(req.url);
  return json({ url: buildTokenCreateUrl(url.searchParams.get("kind") || "account", url.searchParams.get("name") || undefined) });
});

route("GET", "/api/me", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const [email, account_name] = await Promise.all([
    fetchAccountEmail(p.token),
    fetchAccountName(p.token, p.account_id),
  ]);
  return json({ email, account_name, account_id: p.account_id, name: p.name });
});

const FREE_DAILY_REQUESTS = 100000;

async function cfGraphQL(token, query) {
  const res = await cfFetch(token, "/graphql", { method: "POST", body: { query } });
  if (!res) throw new ApiError("پاسخی از GraphQL کلادفلر دریافت نشد", 502);
  if (Array.isArray(res.errors) && res.errors.length && !res.data) {
    const msg = res.errors.map(e => e?.message || JSON.stringify(e)).join(" | ");
    throw new ApiError(msg, 502);
  }
  if (res.success === false && !res.data) throw new ApiError(errMsg(res), 502);
  return res;
}

function usageGqlMsg(e) {
  const m = String(e?.message || e || "");
  if (/not authorized|unauthorized|permission|access|10000|authentication/i.test(m)) {
    return "توکن این اکانت دسترسی Account Analytics: Read ندارد";
  }
  return m;
}

async function fetchAccountUsage(token, accountId) {
  const now = new Date();
  const dayStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const yStart = new Date(dayStart.getTime() - 86400000);
  const resetAt = new Date(dayStart.getTime() + 86400000);
  const acc = JSON.stringify(String(accountId));
  const t0 = JSON.stringify(dayStart.toISOString()), t1 = JSON.stringify(now.toISOString()), y0 = JSON.stringify(yStart.toISOString());
  const wBlock = `
      wToday: workersInvocationsAdaptive(limit: 10000, filter: { datetime_geq: ${t0}, datetime_leq: ${t1} }) {
        sum { requests errors subrequests }
        dimensions { scriptName }
      }
      wYest: workersInvocationsAdaptive(limit: 10000, filter: { datetime_geq: ${y0}, datetime_lt: ${t0} }) {
        sum { requests errors }
      }`;
  const pBlock = `
      pToday: pagesFunctionsInvocationsAdaptiveGroups(limit: 10000, filter: { datetime_geq: ${t0}, datetime_leq: ${t1} }) {
        sum { requests errors }
        dimensions { scriptName }
      }
      pYest: pagesFunctionsInvocationsAdaptiveGroups(limit: 10000, filter: { datetime_geq: ${y0}, datetime_lt: ${t0} }) {
        sum { requests errors }
      }`;
  const build = (blocks) => `{ viewer { accounts(filter: { accountTag: ${acc} }) { ${blocks} } } }`;

  let data, pagesAvailable = true, pagesError = null;
  try {
    data = await cfGraphQL(token, build(wBlock + pBlock));
    if (Array.isArray(data.errors) && data.errors.length) { pagesAvailable = false; pagesError = data.errors.map(e => e?.message).join(" | "); }
  } catch (e) {
    pagesAvailable = false; pagesError = e.message;
    try { data = await cfGraphQL(token, build(wBlock)); }
    catch (e2) { throw new ApiError(usageGqlMsg(e2), 502); }
  }
  const a = data?.data?.viewer?.accounts?.[0] || {};
  const sumRows = (rows, key) => (rows || []).reduce((n, r) => n + (Number(r?.sum?.[key]) || 0), 0);
  const groupBy = (rows) => {
    const map = new Map();
    for (const r of rows || []) {
      const name = r?.dimensions?.scriptName || "(نامشخص)";
      const cur = map.get(name) || { name, requests: 0, errors: 0, subrequests: 0 };
      cur.requests += Number(r?.sum?.requests) || 0;
      cur.errors += Number(r?.sum?.errors) || 0;
      cur.subrequests += Number(r?.sum?.subrequests) || 0;
      map.set(name, cur);
    }
    return [...map.values()].sort((x, y) => y.requests - x.requests);
  };
  const workers = {
    requests: sumRows(a.wToday, "requests"), errors: sumRows(a.wToday, "errors"), subrequests: sumRows(a.wToday, "subrequests"),
    yesterday: sumRows(a.wYest, "requests"), scripts: groupBy(a.wToday),
  };
  const pages = {
    available: pagesAvailable && Array.isArray(a.pToday),
    requests: sumRows(a.pToday, "requests"), errors: sumRows(a.pToday, "errors"),
    yesterday: sumRows(a.pYest, "requests"), projects: groupBy(a.pToday),
    error: pagesAvailable ? null : pagesError,
  };
  const total = workers.requests + pages.requests;
  return {
    account_id: accountId,
    date: dayStart.toISOString().slice(0, 10),
    reset_at: resetAt.toISOString(),
    limit: FREE_DAILY_REQUESTS,
    total,
    yesterday_total: workers.yesterday + pages.yesterday,
    percent: Math.round((total / FREE_DAILY_REQUESTS) * 1000) / 10,
    workers, pages,
  };
}

route("GET", "/api/usage", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const usage = await fetchAccountUsage(p.token, p.account_id);
  return json({ ok: true, profile: p.name, ...usage });
});

route("GET", "/api/workers", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const workers = await fetchWorkers(p.token, p.account_id);
  return json({
    workers: workers.map(w => ({
      name: w.id || w.name || "?",
      modified_on: (w.modified_on || "").slice(0, 10),
    })),
    nexa_workers: p.nexa_workers,
  });
});

route("GET", "/api/workers/:name/code", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  return json({ code: await getWorkerScript(p.token, p.account_id, name) });
});

route("PUT", "/api/workers/:name/code", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  const body = await req.json();
  const code = typeof body.code === "string" ? body.code : "";
  if (!code.trim()) throw new ApiError("کد خالی است", 400);
  if (code.length > 10 * 1024 * 1024) throw new ApiError("حجم کد بیشتر از ۱۰ مگابایت است", 400);
  if (!(await workerExists(p.token, p.account_id, name))) throw new ApiError(`ورکر «${name}» در این اکانت پیدا نشد`, 404);
  const up = await uploadWorkerCodeOnly(p.token, p.account_id, name, code);
  try { await saveWorkerRecoverySource(env, p.name, name, code, null); } catch {}
  let liveUrl = null;
  try { liveUrl = await workerUrl(p.token, p.account_id, name); } catch {}
  return json({
    ok: true, method: up.method, format: up.module ? "module" : "service-worker", url: liveUrl,
    size: code.length,
    message: "کد روی ورکر دپلوی شد ✓ (بایندینگ‌ها، Secretها، دامنه‌ها و تنظیمات دست نخوردند)",
  });
});

route("GET", "/api/workers/:name/bindings", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  return json({ bindings: await fetchBindings(p.token, p.account_id, decodeURIComponent(m.name)) });
});

route("POST", "/api/workers/:name/bind-kv", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  const body = await req.json();
  const envName = body.env_name || "KV";
  const defs = bindingsToMetadata(await fetchBindings(p.token, p.account_id, name))
    .filter(b => b.name !== envName);
  defs.push({ type: "kv_namespace", name: envName, namespace_id: body.kv_id });
  await applyBindings(p.token, p.account_id, name, defs);
  return json({ ok: true, message: `KV به‌عنوان env.${envName} متصل شد` });
});

route("POST", "/api/workers/:name/bind-d1", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  const body = await req.json();
  const envName = body.env_name || "DB";
  const defs = bindingsToMetadata(await fetchBindings(p.token, p.account_id, name))
    .filter(b => b.name !== envName);
  defs.push({ type: "d1", name: envName, database_id: body.database_id });
  await applyBindings(p.token, p.account_id, name, defs);
  return json({ ok: true, message: `D1 به‌عنوان env.${envName} متصل شد` });
});

route("POST", "/api/workers/:name/unbind", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  const body = await req.json();
  const bindings = await fetchBindings(p.token, p.account_id, name);
  const remaining = bindings.filter(b => b.name !== body.env_name);
  await applyBindings(p.token, p.account_id, name, bindingsToMetadata(remaining));
  return json({ ok: true, message: `بایندینگ env.${body.env_name} حذف شد` });
});

route("POST", "/api/workers/:name/rename", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const body = await req.json();
  return json(await renameWorker(env, p, decodeURIComponent(m.name), String(body.new_name || "").trim()));
});

route("GET", "/api/workers/:name/url", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  const subRes = await cfGet(p.token, `/accounts/${p.account_id}/workers/scripts/${encodeURIComponent(name)}/subdomain`);
  return json({
    url: await workerUrl(p.token, p.account_id, name),
    enabled: !!(subRes && subRes.success && subRes.result && subRes.result.enabled),
  });
});

route("POST", "/api/workers/:name/subdomain", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const body = await req.json();
  const res = await enableSubdomain(p.token, p.account_id, decodeURIComponent(m.name), body.enabled !== false);
  if (!res || !res.success) throw new ApiError(`فعال‌سازی workers.dev ناموفق: ${errMsg(res)}`, 502);
  return json({ ok: true, url: await workerUrl(p.token, p.account_id, decodeURIComponent(m.name)) });
});

route("POST", "/api/workers/:name/flags", async (m, req, env, url) => {
  const nameQ = url.searchParams.get("profile");
  if (!nameQ) throw new ApiError("پارامتر profile الزامی است", 400);
  const workerName = decodeURIComponent(m.name);
  const body = await req.json();
  const row = await getProfileRow(env, nameQ);
  let nexa = row.nexa_workers;
  if (typeof body.nexa === "boolean") {
    nexa = body.nexa ? [...new Set([...nexa, workerName])] : nexa.filter(w => w !== workerName);
  }
  await saveFlags(env, nameQ, nexa);

  const flagged = nexa.includes(workerName);
  let storedUrl = null;
  if (flagged) {
    try {
      storedUrl = await workerUrl(row.token, row.account_id, workerName);
      if (storedUrl) {
        await env.DB.prepare("INSERT OR REPLACE INTO worker_urls (profile, worker, url) VALUES (?, ?, ?)")
          .bind(nameQ, workerName, storedUrl).run();
      }
    } catch {}
  } else {
    await env.DB.prepare("DELETE FROM worker_urls WHERE profile = ? AND worker = ?").bind(nameQ, workerName).run();
  }
  return json({ ok: true, nexa_workers: nexa, url: storedUrl });
});

route("DELETE", "/api/workers/:name", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  return json(await deleteWorkerAndResources(env, p, decodeURIComponent(m.name), url.searchParams.get("resources") === "1"));
});

route("GET", "/api/tagged-workers", async (m, req, env) => {
  const { results } = await env.DB.prepare("SELECT * FROM profiles ORDER BY pos, created_at, name").all();
  const items = [];
  let missing = 0, unchecked = 0;
  for (const row of (results || [])) {
    let nexa = [];
    try { nexa = JSON.parse(row.nexa_workers || "[]"); } catch {}
    const names = [...new Set(nexa)];
    if (!names.length) continue;

    let existsSet = null, pagesSet = null, error = null;
    try {
      const [wRes, pRes] = await Promise.all([
        cfGet(row.token, `/accounts/${row.account_id}/workers/scripts`).catch(() => null),
        cfGet(row.token, `/accounts/${row.account_id}/pages/projects`).catch(() => null),
      ]);
      if ((!wRes || wRes.success !== true) && (!pRes || pRes.success !== true)) {
        error = `دریافت لیست ورکرها و صفحات ناموفق: ${errMsg(wRes || pRes)}`;
      } else {
        existsSet = new Set((wRes?.result || []).map(w => w.id || w.name || "?"));
        pagesSet = new Set((pRes?.result || []).map(p => p.name || "?"));
      }
    } catch (e) { error = e.message || String(e); }

    for (const worker of names) {
      const isWorker = existsSet ? existsSet.has(worker) : false;
      let isPages = pagesSet ? pagesSet.has(worker) : false;
      if (!isWorker && !isPages) {
        try { isPages = await pagesProjectExists(row.token, row.account_id, worker); } catch {}
      }
      const exists = (existsSet || pagesSet) ? (isWorker || isPages) : null;
      const item = {
        profile: row.name,
        account_id: row.account_id,
        worker,
        kind: isPages ? "pages" : (isWorker ? "worker" : "unknown"),
        nexa: nexa.includes(worker),
        exists,
        error,
        missing: exists === false,
      };
      if (exists === false) missing++;
      if (exists === null) unchecked++;
      items.push(item);
    }
  }
  items.sort((a, b) =>
    (Number(b.missing) - Number(a.missing)) ||
    a.profile.localeCompare(b.profile) ||
    a.worker.localeCompare(b.worker));
  return json({
    items,
    summary: { total: items.length, missing, unchecked, profiles: (results || []).length },
  });
});

route("POST", "/api/tagged-workers/set", async (m, req, env) => {
  const body = await req.json();
  const profileName = String(body.profile || "").trim();
  const workerName = String(body.worker || "").trim();
  const tag = body.tag === "nexa" ? "nexa" : null;
  if (!profileName || !workerName) throw new ApiError("profile و worker الزامی است", 400);
  const row = await getProfileRow(env, profileName);

  const nexa = tag === "nexa"
    ? [...new Set([...row.nexa_workers, workerName])]
    : row.nexa_workers.filter(w => w !== workerName);
  await saveFlags(env, profileName, nexa);

  if (tag) {
    let storedUrl = null;
    try {
      if (await workerExists(row.token, row.account_id, workerName)) {
        storedUrl = await workerUrl(row.token, row.account_id, workerName);
      } else if (await pagesProjectExists(row.token, row.account_id, workerName)) {
        storedUrl = `https://${workerName}.pages.dev`;
      }
    } catch {}
    if (storedUrl) {
      await env.DB.prepare("INSERT OR REPLACE INTO worker_urls (profile, worker, url) VALUES (?, ?, ?)")
        .bind(profileName, workerName, storedUrl).run();
    } else {
      await env.DB.prepare("DELETE FROM worker_urls WHERE profile = ? AND worker = ?")
        .bind(profileName, workerName).run();
    }
  } else {
    await env.DB.prepare("DELETE FROM worker_urls WHERE profile = ? AND worker = ?")
      .bind(profileName, workerName).run();
  }
  return json({ ok: true, profile: profileName, worker: workerName, tag, nexa_workers: nexa });
});

route("POST", "/api/tagged-workers/prune", async (m, req, env) => {
  const { results } = await env.DB.prepare("SELECT * FROM profiles ORDER BY pos, created_at, name").all();
  const removed = [];
  for (const row of (results || [])) {
    let nexa = [];
    try { nexa = JSON.parse(row.nexa_workers || "[]"); } catch {}
    const names = [...new Set(nexa)];
    if (!names.length) continue;

    let existsSet;
    try {
      const [wRes, pRes] = await Promise.all([
        cfGet(row.token, `/accounts/${row.account_id}/workers/scripts`).catch(() => null),
        cfGet(row.token, `/accounts/${row.account_id}/pages/projects`).catch(() => null),
      ]);
      if ((!wRes || wRes.success !== true) && (!pRes || pRes.success !== true)) {
        removed.push({ profile: row.name, error: `بررسی اکانت ناموفق: ${errMsg(wRes || pRes)}` });
        continue;
      }
      const wSet = new Set((wRes?.result || []).map(w => w.id || w.name || "?"));
      const pSet = new Set((pRes?.result || []).map(p => p.name || "?"));
      existsSet = new Set([...wSet, ...pSet]);
    } catch (e) {
      removed.push({ profile: row.name, error: `بررسی اکانت ناموفق: ${e.message || e}` });
      continue;
    }

    const dropped = names.filter(w => !existsSet.has(w));
    if (!dropped.length) continue;
    await saveFlags(env, row.name, nexa.filter(w => existsSet.has(w)));
    if (dropped.length === 1) {
      await env.DB.prepare("DELETE FROM worker_urls WHERE profile = ? AND worker = ?").bind(row.name, dropped[0]).run();
    } else {
      await env.DB.prepare(`DELETE FROM worker_urls WHERE profile = ? AND worker IN (${dropped.map(() => "?").join(",")})`)
        .bind(row.name, ...dropped).run();
    }
    for (const w of dropped) removed.push({ profile: row.name, worker: w });
  }
  return json({ ok: true, removed, count: removed.filter(r => r.worker).length });
});

route("GET", "/api/kv", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  return json({ namespaces: await fetchKvNamespaces(p.token, p.account_id) });
});

route("PUT", "/api/kv/:id", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const body = await req.json();
  const res = await cfPut(p.token, `/accounts/${p.account_id}/storage/kv/namespaces/${m.id}`, { title: body.title });
  if (!res || !res.success) throw new ApiError(`تغییر نام ناموفق: ${errMsg(res)}`, 502);
  return json({ ok: true });
});

route("DELETE", "/api/kv/:id", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const res = await cfDelete(p.token, `/accounts/${p.account_id}/storage/kv/namespaces/${m.id}`);
  if (!res || !res.success) throw new ApiError(`حذف ناموفق: ${errMsg(res)}`, 502);
  return json({ ok: true });
});

route("GET", "/api/kv/:id/keys", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const cursor = url.searchParams.get("cursor");
  let path = `/accounts/${p.account_id}/storage/kv/namespaces/${m.id}/keys?limit=20`;
  if (cursor) path += `&cursor=${encodeURIComponent(cursor)}`;
  const res = await cfGet(p.token, path);
  if (!res || !res.success) throw new ApiError(`دریافت کلیدها ناموفق: ${errMsg(res)}`, 502);
  return json({
    keys: res.result || [],
    cursor: (res.result_info && res.result_info.cursor) || null,
  });
});

route("GET", "/api/kv/:id/values/:key", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const key = decodeURIComponent(m.key);
  const res = await cfFetch(p.token,
    `/accounts/${p.account_id}/storage/kv/namespaces/${m.id}/values/${encodeURIComponent(key)}`, { raw: true });
  if (res.status === 404) throw new ApiError(`کلید «${key}» پیدا نشد`, 404);
  if (res.status !== 200) throw new ApiError(`HTTP ${res.status}`, 502);
  return new Response(await res.text(), { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8" } });
});

route("PUT", "/api/kv/:id/values/:key", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const body = await req.json();
  const key = decodeURIComponent(m.key);
  let path = `/accounts/${p.account_id}/storage/kv/namespaces/${m.id}/values/${encodeURIComponent(key)}`;
  if (body.expiration_ttl) path += `?expiration_ttl=${parseInt(body.expiration_ttl, 10)}`;
  const res = await cfFetch(p.token, path, { method: "PUT", body: String(body.value ?? ""), contentType: "text/plain" });
  if (!res || !res.success) throw new ApiError(`نوشتن کلید ناموفق: ${errMsg(res)}`, 502);
  return json({ ok: true });
});

route("DELETE", "/api/kv/:id/values/:key", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const res = await cfDelete(p.token, `/accounts/${p.account_id}/storage/kv/namespaces/${m.id}/values/${encodeURIComponent(decodeURIComponent(m.key))}`);
  if (!res || !res.success) throw new ApiError(`حذف کلید ناموفق: ${errMsg(res)}`, 502);
  return json({ ok: true });
});

route("GET", "/api/d1", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  return json({ databases: await fetchD1Databases(p.token, p.account_id) });
});

route("POST", "/api/d1", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const body = await req.json();
  const res = await cfPost(p.token, `/accounts/${p.account_id}/d1/database`, { name: body.name });
  assertOk(res, `ساخت D1 «${body.name}»`);
  return json({ ok: true, uuid: res.uuid || (res.result && res.result.uuid) || "" });
});

route("GET", "/api/d1/:uuid/info", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const res = await cfGet(p.token, `/accounts/${p.account_id}/d1/database/${m.uuid}`);
  if (!res || !res.success) throw new ApiError(`دریافت اطلاعات ناموفق: ${errMsg(res)}`, 502);
  return json({ info: res.result });
});

route("GET", "/api/d1/:uuid/tables", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const res = await cfPost(p.token, `/accounts/${p.account_id}/d1/database/${m.uuid}/query`,
    { sql: "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;" });
  if (!res || !res.success) throw new ApiError(`کوئری ناموفق: ${errMsg(res)}`, 502);
  const rows = [];
  for (const r of res.result || []) rows.push(...(r.results || []));
  return json({ tables: rows.map(r => r.name) });
});

route("POST", "/api/d1/:uuid/query", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const body = await req.json();
  if (!body.sql || !String(body.sql).trim()) throw new ApiError("SQL خالی است", 400);
  const res = await cfPost(p.token, `/accounts/${p.account_id}/d1/database/${m.uuid}/query`, { sql: body.sql });
  if (!res || !res.success) throw new ApiError(`کوئری ناموفق: ${errMsg(res)}`, 502);
  const out = [];
  for (const r of res.result || []) {
    out.push({ results: r.results || [], meta: r.meta || {} });
  }
  return json({ ok: true, result: out });
});

route("DELETE", "/api/d1/:uuid", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const res = await cfDelete(p.token, `/accounts/${p.account_id}/d1/database/${m.uuid}`);
  if (!(res && (res.success || typeof res.result === "object"))) throw new ApiError(`حذف ناموفق: ${errMsg(res)}`, 502);
  return json({ ok: true });
});

route("POST", "/api/create/nexa", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const body = await req.json();
  if (body.deploy_type === "pages") return json(await createNexaPages(env, p, body));
  return json(await createNexa(env, p, body));
});

route("GET", "/api/pages", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const res = await cfGet(p.token, `/accounts/${p.account_id}/pages/projects`);
  if (!res || !res.success) throw new ApiError(`دریافت پروژه‌های Pages ناموفق: ${errMsg(res)}`, 502, { details: res });
  const row = await getProfileRow(env, p.name);
  return json({
    projects: res.result || [],
    nexa_workers: row.nexa_workers,
  });
});

route("POST", "/api/pages", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const body = await req.json();
  const name = String(body.name || "").trim();
  if (!name) throw new ApiError("نام پروژه الزامی است", 400);
  const branch = String(body.production_branch || "main").trim();
  const res = await cfPost(p.token, `/accounts/${p.account_id}/pages/projects`, { name, production_branch: branch });
  assertOk(res, `ساخت پروژه Pages «${name}»`);
  return json({ ok: true, project: res.result });
});

route("GET", "/api/pages/get-or-create", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = String(url.searchParams.get("name") || "").trim();
  if (!name) throw new ApiError("نام پروژه الزامی است", 400);
  const res = await getOrCreatePagesProject(p.token, p.account_id, name);
  return json({ ok: true, project: res.result || res });
});

route("GET", "/api/pages/:name", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const res = await cfGet(p.token, `/accounts/${p.account_id}/pages/projects/${encodeURIComponent(m.name)}`);
  if (!res || !res.success) throw new ApiError(`دریافت پروژه ناموفق: ${errMsg(res)}`, 502, { details: res });
  return json({ project: res.result });
});

route("DELETE", "/api/pages/:name", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const withResources = url.searchParams.get("resources") !== "0";
  const result = await deletePagesAndResources(env, p, decodeURIComponent(m.name), withResources);
  return json(result);
});

route("GET", "/api/pages/:name/url", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  const res = await cfGet(p.token, `/accounts/${p.account_id}/pages/projects/${encodeURIComponent(name)}`);
  if (!res || !res.success || !res.result) throw new ApiError(`دریافت آدرس پروژه ناموفق: ${errMsg(res)}`, 502);
  const subdomain = res.result.subdomain || `${name}.pages.dev`;
  return json({ url: `https://${subdomain}`, subdomain, project: res.result });
});

route("GET", "/api/pages/:name/bindings", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const data = await fetchPagesBindings(p.token, p.account_id, decodeURIComponent(m.name));
  return json(data);
});

route("POST", "/api/pages/:name/bind-kv", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  const body = await req.json();
  const envName = (body.env_name || "KV").trim();
  const kvId = body.kv_id;
  if (!kvId) throw new ApiError("شناسه KV Namespace الزامی است", 400);
  const result = await bindPagesKv(env, p, name, envName, kvId);
  return json(result);
});

route("POST", "/api/pages/:name/bind-d1", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  const body = await req.json();
  const envName = (body.env_name || "DB").trim();
  const databaseId = body.database_id;
  const databaseName = body.database_name;
  if (!databaseId && !databaseName) throw new ApiError("شناسه یا نام دیتابیس D1 الزامی است", 400);
  const result = await bindPagesD1(env, p, name, envName, databaseId, databaseName);
  return json(result);
});

route("POST", "/api/pages/:name/env-vars", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  const body = await req.json();
  const result = await setPagesEnvVar(env, p, name, body);
  return json(result);
});

route("DELETE", "/api/pages/:name/env-vars/:key", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  const key = decodeURIComponent(m.key);
  const result = await deletePagesEnvVar(env, p, name, key);
  return json(result);
});

route("POST", "/api/pages/:name/change-d1", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const body = await req.json();
  const result = await changePagesD1(env, p, decodeURIComponent(m.name), body);
  return json(result);
});

route("POST", "/api/pages/:name/redeploy", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const result = await redeployPagesProject(env, p, decodeURIComponent(m.name));
  return json(result);
});

route("POST", "/api/pages/:name/rebuild", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  const body = await req.json().catch(() => ({}));
  const type = "nexa";
  const source = await resolvePagesRebuildSource(env, p, name, type, body);
  return json(await rebuildSinglePages(env, type, p, name, source.code, { script_key: source.key, secret_values: body.secret_values || {} }));
});

route("POST", "/api/workers/:name/rebuild", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  const body = await req.json().catch(() => ({}));
  const type = "nexa";
  let code = null;
  let sourceKey = null;
  if (typeof body.script === "string" && body.script.trim()) {
    code = body.script;
  } else if (body.script_key) {
    code = await getScript(env, body.script_key);
    sourceKey = body.script_key;
  } else {
    try {
      const src = await resolveWorkerRecoverySource(env, p, name, type);
      code = src.code;
      sourceKey = src.key;
    } catch {
      code = await getScript(env, type);
      sourceKey = type;
    }
  }
  const result = await rebuildSingleWorker(env, type, p, name, code, { secret_values: body.secret_values || {}, script_key: sourceKey });
  return json(result);
});

route("GET", "/api/pages/:name/rebuild-snapshot", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  const record = await readPagesRebuildRecord(env, p.account_id, name);
  if (!record) throw new ApiError("بکاپ ریبیلد Pages برای این پروژه موجود نیست", 404);
  const headers = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" };
  if (url.searchParams.get("download") === "1") headers["Content-Disposition"] = `attachment; filename="pages-rebuild-${encodeURIComponent(name)}.json"`;
  return new Response(JSON.stringify(record, null, 2), { headers });
});

route("POST", "/api/pages/:name/unbind", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  const body = await req.json();
  const envName = String(body.env_name || "").trim();
  if (!envName) throw new ApiError("نام بایندینگ الزامی است", 400);
  const result = await unbindPages(env, p, name, envName);
  return json(result);
});

route("POST", "/api/pages/:name/flags", async (m, req, env, url) => {
  const nameQ = url.searchParams.get("profile");
  if (!nameQ) throw new ApiError("پارامتر profile الزامی است", 400);
  const projName = decodeURIComponent(m.name);
  const body = await req.json();
  const row = await getProfileRow(env, nameQ);
  let nexa = row.nexa_workers;
  if (typeof body.nexa === "boolean") {
    nexa = body.nexa ? [...new Set([...nexa, projName])] : nexa.filter(w => w !== projName);
  }
  await saveFlags(env, nameQ, nexa);
  return json({ ok: true, nexa_workers: nexa });
});

route("GET", "/api/pages/:name/deployments", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const res = await cfGet(p.token, `/accounts/${p.account_id}/pages/projects/${encodeURIComponent(m.name)}/deployments`);
  if (!res || !res.success) throw new ApiError(`دریافت دپلویمنت‌ها ناموفق: ${errMsg(res)}`, 502, { details: res });
  return json({ deployments: res.result || [] });
});

route("POST", "/api/pages/:name/deployments/:id/retry", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const res = await cfPost(p.token, `/accounts/${p.account_id}/pages/projects/${encodeURIComponent(m.name)}/deployments/${encodeURIComponent(m.id)}/retry`);
  if (!res || !res.success) throw new ApiError(`استقرار مجدد ناموفق: ${errMsg(res)}`, 502, { details: res });
  return json({ ok: true, deployment: res.result });
});

route("DELETE", "/api/pages/:name/deployments/:id", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const res = await cfDelete(p.token, `/accounts/${p.account_id}/pages/projects/${encodeURIComponent(m.name)}/deployments/${encodeURIComponent(m.id)}`);
  if (!res || (!res.success && typeof res.result !== "object")) throw new ApiError(`حذف دپلویمنت ناموفق: ${errMsg(res)}`, 502, { details: res });
  return json({ ok: true });
});

route("POST", "/api/pages/:name/deploy", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  const body = await req.json();
  const code = (typeof body.script === "string" && body.script.trim()) ? body.script : (body.script_key ? await getScript(env, body.script_key) : null);
  if (!code) throw new ApiError("کد یا کلید اسکریپت الزامی است", 400);
  if (code.length > 10 * 1024 * 1024) throw new ApiError("حجم کد بیشتر از ۱۰ مگابایت است", 400);
  const project = await readPagesProjectStrict(p.token, p.account_id, name);
  if (!project) throw new ApiError(`پروژهٔ Pages «${name}» در این اکانت پیدا نشد`, 404);
  const prod = project.deployment_configs?.production || {};
  const res = assertOk(await deployToPages(p.token, p.account_id, name, code, {
    branch: project.production_branch || "main", message: "manual deploy from panel",
    compatibility_date: prod.compatibility_date, compatibility_flags: prod.compatibility_flags,
  }), `استقرار کد روی Pages «${name}»`);
  await savePagesScript(env, p.name, name, { script: body.script_key ? null : code, script_key: body.script_key || null });
  let state = "pending";
  if (body.wait !== false && res?.id) state = (await waitPagesDeployment(p.token, p.account_id, name, res.id)).state;
  const siteUrl = `https://${project.subdomain || `${name}.pages.dev`}`;
  return json({
    ok: true, result: res, deployment_id: res?.id || null, state, url: siteUrl, size: code.length,
    message: state === "success"
      ? "کد روی Pages دپلوی و منتشر شد ✓ (بایندینگ‌ها، متغیرها و دامنه‌ها دست نخوردند)"
      : "کد دپلوی شد و Cloudflare در حال انتشار آن است (معمولاً کمتر از ۲ دقیقه)",
  });
});

route("GET", "/api/pages/:name/code", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  const code = await getPagesScript(env, p.name, name);
  if (!code) throw new ApiError("کدی برای این پروژه در پنل ذخیره نشده است (کد Pages از Cloudflare قابل دانلود نیست)", 404);
  return json({ code });
});

route("GET", "/api/pages/:name/domains", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const res = await cfGet(p.token, `/accounts/${p.account_id}/pages/projects/${encodeURIComponent(m.name)}/domains`);
  if (!res || !res.success) throw new ApiError(`دریافت دامنه‌ها ناموفق: ${errMsg(res)}`, 502, { details: res });
  return json({ domains: res.result || [] });
});

route("POST", "/api/pages/:name/domains", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const body = await req.json();
  const domain = String(body.domain || "").trim();
  if (!domain) throw new ApiError("نام دامنه الزامی است", 400);
  const res = await cfPost(p.token, `/accounts/${p.account_id}/pages/projects/${encodeURIComponent(m.name)}/domains`, { name: domain });
  assertOk(res, `افزودن دامنه «${domain}»`);
  return json({ ok: true, domain: res.result });
});

route("DELETE", "/api/pages/:name/domains/:domain", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const res = await cfDelete(p.token, `/accounts/${p.account_id}/pages/projects/${encodeURIComponent(m.name)}/domains/${encodeURIComponent(m.domain)}`);
  if (!res || (!res.success && typeof res.result !== "object")) throw new ApiError(`حذف دامنه ناموفق: ${errMsg(res)}`, 502, { details: res });
  return json({ ok: true });
});

route("POST", "/api/pages/:name/configs", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const body = await req.json();
  const res = await pagesPatchDeploymentConfigs(p.token, p.account_id, m.name, sanitizePagesStageConfig(body.configs || {}));
  assertOk(res, `تنظیم بایندینگ‌ها و متغیرهای Pages «${m.name}»`);

  const redeployResult = await redeployPagesProject(env, p, m.name);

  return json({
    ok: true,
    redeployed: redeployResult.redeployed,
    message: redeployResult.redeployed
      ? `تنظیمات ذخیره شد و پروژه به صورت خودکار مجدداً مستقر (Re-deploy) شد ✓`
      : `تنظیمات پروژه با موفقیت ذخیره شد ✓`
  });
});

route("GET", "/api/worker-domains", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const [zonesRes, domainsRes] = await Promise.all([
    cfGet(p.token, `/zones?account.id=${encodeURIComponent(p.account_id)}&per_page=100`),
    cfGet(p.token, `/accounts/${p.account_id}/workers/domains`),
  ]);
  const zones = (zonesRes && zonesRes.success ? zonesRes.result : []) || [];
  const domains = (domainsRes && domainsRes.success ? domainsRes.result : []) || [];
  return json({
    zones: zones.map(z => ({ id: z.id, name: z.name, status: z.status })),
    domains,
  });
});

route("GET", "/api/workers/:name/domains", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const res = await cfGet(p.token, `/accounts/${p.account_id}/workers/domains`);
  if (!res || !res.success) throw new ApiError(`دریافت دامنه‌های Worker ناموفق: ${errMsg(res)}`, 502);
  const name = decodeURIComponent(m.name);
  return json({ domains: (res.result || []).filter(d => d.service === name || d.script === name || d.worker === name) });
});

route("POST", "/api/workers/:name/domains", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const body = await req.json();
  const hostname = String(body.hostname || body.domain || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/+$/, "");
  if (!hostname || hostname.includes("/")) throw new ApiError("دامنه یا ساب‌دامنه معتبر وارد کنید", 400);
  const name = decodeURIComponent(m.name);
  const res = await cfPost(p.token, `/accounts/${p.account_id}/workers/domains`, {
    hostname,
    service: name,
    environment: String(body.environment || "production"),
  });
  assertOk(res, `اتصال دامنه «${hostname}» به Worker «${name}»`);
  return json({ ok: true, domain: res.result || { hostname, service: name } });
});

route("DELETE", "/api/workers/:name/domains/:domain", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const name = decodeURIComponent(m.name);
  const domain = decodeURIComponent(m.domain);
  const res = await cfDelete(p.token, `/accounts/${p.account_id}/workers/domains/${encodeURIComponent(domain)}`);
  if (!res || (!res.success && res.result === undefined)) throw new ApiError(`حذف اتصال دامنه ناموفق: ${errMsg(res)}`, 502);
  return json({ ok: true });
});

route("POST", "/api/workers", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const body = await req.json();
  const name = String(body.name || "").trim();
  if (!name) throw new ApiError("نام ورکر الزامی است", 400);
  const code = body.script || (body.script_key ? await getScript(env, body.script_key) : 'export default { async fetch(req) { return new Response("Hello from Cloudflare Worker!"); } };');
  const bindings = body.bindings || [];
  assertOk(await deployWorker(p.token, p.account_id, name, code, bindings), `ساخت و استقرار ورکر «${name}»`);
  if (body.subdomain) await enableSubdomain(p.token, p.account_id, name);
  return json({ ok: true, name });
});

route("GET", "/api/workers/:name/routes", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const res = await cfGet(p.token, `/accounts/${p.account_id}/workers/scripts/${encodeURIComponent(m.name)}/routes`);
  return json({ routes: (res && res.success && res.result) ? res.result : [] });
});

route("POST", "/api/workers/:name/routes", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const body = await req.json();
  const pattern = String(body.pattern || "").trim();
  const zone_id = String(body.zone_id || "").trim();
  if (!pattern) throw new ApiError("الگوی route (مثلا example.com/*) الزامی است", 400);
  const payload = { pattern, script: m.name };
  if (zone_id) payload.zone_id = zone_id;
  const res = await cfPost(p.token, `/accounts/${p.account_id}/workers/scripts/${encodeURIComponent(m.name)}/routes`, payload);
  assertOk(res, `افزودن Route «${pattern}»`);
  return json({ ok: true, route: res.result });
});

route("DELETE", "/api/workers/:name/routes/:id", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const res = await cfDelete(p.token, `/accounts/${p.account_id}/workers/scripts/${encodeURIComponent(m.name)}/routes/${encodeURIComponent(m.id)}`);
  if (!res || !res.success) throw new ApiError(`حذف Route ناموفق: ${errMsg(res)}`, 502, { details: res });
  return json({ ok: true });
});

route("GET", "/api/workers/:name/deployments", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const res = await cfGet(p.token, `/accounts/${p.account_id}/workers/scripts/${encodeURIComponent(m.name)}/deployments`);
  return json({ deployments: (res && res.success && (res.result?.deployments || res.result)) || [] });
});

route("POST", "/api/kv", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const body = await req.json();
  const title = String(body.title || "").trim();
  if (!title) throw new ApiError("عنوان Namespace الزامی است", 400);
  const res = await cfPost(p.token, `/accounts/${p.account_id}/storage/kv/namespaces`, { title });
  assertOk(res, `ساخت KV «${title}»`);
  return json({ ok: true, namespace: res.result });
});

route("POST", "/api/d1/get-or-create", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const body = await req.json();
  const name = String(body.name || "").trim();
  if (!name) throw new ApiError("نام دیتابیس الزامی است", 400);
  const res = await getOrCreateD1Database(p.token, p.account_id, name);
  return json({ ok: true, uuid: res.uuid || res.id, name: res.name || name, skipped: !!res.skipped });
});

route("POST", "/api/d1/:uuid/export", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const schemaRes = await cfPost(p.token, `/accounts/${p.account_id}/d1/database/${m.uuid}/query`, {
    sql: "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE '_cf_%' ORDER BY name;"
  });
  const tables = (schemaRes && schemaRes.success && schemaRes.result && schemaRes.result[0] && schemaRes.result[0].results) || [];
  let dump = "-- Cloudflare D1 Database Export (" + m.uuid + ")\\n-- Created at: " + new Date().toISOString() + "\\n\\nPRAGMA foreign_keys = OFF;\\n\\n";
  for (const tbl of tables) {
    if (!tbl.sql) continue;
    dump += tbl.sql + ";\\n\\n";
    try {
      const rowsRes = await cfPost(p.token, `/accounts/${p.account_id}/d1/database/${m.uuid}/query`, {
        sql: `SELECT * FROM "${tbl.name.replace(/"/g, '""')}" LIMIT 500;`
      });
      const rows = (rowsRes && rowsRes.success && rowsRes.result && rowsRes.result[0] && rowsRes.result[0].results) || [];
      for (const row of rows) {
        const cols = Object.keys(row);
        if (!cols.length) continue;
        const colNames = cols.map(c => `"${c.replace(/"/g, '""')}"`).join(", ");
        const colVals = cols.map(c => {
          const v = row[c];
          if (v === null || v === undefined) return "NULL";
          if (typeof v === "number") return v;
          return "'" + String(v).replace(/'/g, "''") + "'";
        }).join(", ");
        dump += `INSERT INTO "${tbl.name.replace(/"/g, '""')}" (${colNames}) VALUES (${colVals});\\n`;
      }
      if (rows.length) dump += "\\n";
    } catch {}
  }
  dump += "PRAGMA foreign_keys = ON;\\n";
  return json({ ok: true, sql: dump });
});

route("GET", "/api/d1/:uuid/tables/:name/schema", async (m, req, env, url) => {
  const p = await resolveProfile(env, url);
  const res = await cfPost(p.token, `/accounts/${p.account_id}/d1/database/${m.uuid}/query`, {
    sql: `PRAGMA table_info("${m.name.replace(/"/g, '""')}");`
  });
  const cols = (res && res.success && res.result && res.result[0] && res.result[0].results) || [];
  return json({ columns: cols });
});

route("GET", "/api/bulk/targets", async (m, req, env, url) => {
  const type = "nexa";
  const tagged = await collectTargets(env);
  const rows = (await env.DB.prepare("SELECT * FROM profiles ORDER BY pos, created_at, name").all()).results || [];
  const byName = new Map(rows.map(p => [p.name, p]));
  const urls = (await env.DB.prepare("SELECT * FROM worker_urls").all()).results || [];
  const urlMap = new Map(urls.map(u => [JSON.stringify([u.profile, u.worker]), u.url]));
  const savedPages = (await env.DB.prepare("SELECT profile, project FROM pages_scripts").all()).results || [];
  const knownPages = new Set(savedPages.map(p => JSON.stringify([p.profile, p.project])));
  const targets = [];
  const seen = new Set();
  const subCache = new Map();
  for (const t of tagged) {
    const key = JSON.stringify([t.profile, t.worker]);
    if (seen.has(key)) continue;
    seen.add(key);
    const p = byName.get(t.profile);
    if (!p) { targets.push({ ...t, kind: "worker", exists: false, url: null }); continue; }
    const [workerFound, pagesFound] = await Promise.all([
      workerExists(p.token, p.account_id, t.worker),
      pagesProjectExists(p.token, p.account_id, t.worker)
    ]);
    let recoverable = false;
    if (!pagesFound) {
      const record = await readPagesRebuildRecord(env, p.account_id, t.worker);
      recoverable = !!(record?.delete_requested && !record.complete);
    }
    if (workerFound) {
      if (!subCache.has(p.account_id)) subCache.set(p.account_id, await getSubdomain(p.token, p.account_id));
      const sub = subCache.get(p.account_id);
      const cached = urlMap.get(key);
      const workerUrl = sub ? `https://${t.worker}.${sub}.workers.dev` : (cached && !/\.pages\.dev(?:\/|$)/i.test(cached) ? cached : null);
      targets.push({ ...t, kind: "worker", exists: true, url: workerUrl });
    }
    if (pagesFound || recoverable || knownPages.has(key)) {
      targets.push({ ...t, kind: "pages", exists: pagesFound, ...(recoverable ? { recoverable: true } : {}), url: `https://${t.worker}.pages.dev` });
    } else if (!workerFound) {
      targets.push({ ...t, kind: "worker", exists: false, url: urlMap.get(key) || null });
    }
  }
  return json({ targets });
});

route("POST", "/api/bulk/update", async (m, req, env) => {
  const body = await req.json();
  return json(await bulkUpdate(env, body, "nexa"));
});

route("POST", "/api/bulk/rebuild", async (m, req, env) => {
  const body = await req.json();
  return json(await bulkRebuild(env, body, "nexa"));
});

async function runHostHealthCron(env) { return runHealthCheck(env); }

const PANEL_BACKUP_TABLES = {
  worker_urls: ['profile', 'worker', 'url'],
  pages_scripts: ['profile', 'project', 'script', 'script_key', 'updated_at'],
  health_config: ['profile', 'worker', 'path'],
  health_checks: ['id', 'checked_at', 'profile', 'worker', 'type', 'status', 'http_status', 'message', 'fixed_at']
};

route("GET", "/api/backup", async (m, req, env, url) => {
  const profiles = (await env.DB.prepare("SELECT * FROM profiles ORDER BY pos, name").all()).results || [];
  const scripts = (await env.DB.prepare("SELECT * FROM scripts ORDER BY key").all()).results || [];
  const settings = Object.create(null);
  for (const r of (await env.DB.prepare("SELECT * FROM settings").all()).results || []) {
    if (!["login_fails", "lock_until"].includes(r.key) && !r.key.startsWith('pages_rebuild_lock:')) settings[r.key] = r.value;
  }
  const tables = Object.create(null);
  for (const name of Object.keys(PANEL_BACKUP_TABLES)) tables[name] = (await env.DB.prepare(`SELECT * FROM ${name}`).all()).results || [];
  const backup = { app: "Nexa-Manager", version: 2, created_at: new Date().toISOString(), profiles, scripts, settings, tables };
  const headers = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" };
  if (url.searchParams.get("download") === "1") headers["Content-Disposition"] = 'attachment; filename="Nexa-Manager-backup-' + new Date().toISOString().replace(/[:T]/g, '-').slice(0,16) + '.json"';
  return new Response(JSON.stringify(backup, null, 2), { headers });
});

route("POST", "/api/backup/restore", async (m, req, env) => {
  const body = await req.json();
  const data = body && body.backup ? body.backup : body;
  if (!data || !['Nexa-Manager', 'cf-wizard'].includes(data.app) || !Array.isArray(data.profiles)) throw new ApiError('فایل بکاپ کل پنل معتبر نیست.', 400);
  if (data.version != null && ![1,2].includes(data.version)) throw new ApiError('نسخهٔ بکاپ پنل پشتیبانی نمی‌شود.', 400);
  const stmts = [env.DB.prepare('DELETE FROM profiles')];
  let pCount = 0, sCount = 0, setCount = 0;
  const flags = value => {
    let array = value;
    if (typeof array === 'string') { try { array = JSON.parse(array); } catch { throw new ApiError('برچسب‌های حساب در بکاپ نامعتبرند.', 400); } }
    if (array == null) array = [];
    if (!Array.isArray(array) || array.some(x => typeof x !== 'string')) throw new ApiError('برچسب‌های حساب در بکاپ نامعتبرند.', 400);
    return JSON.stringify(array);
  };
  data.profiles.forEach((p, idx) => {
    if (!p || typeof p !== 'object' || !p.name || !p.token || !p.account_id) throw new ApiError('مشخصات حساب در بکاپ نامعتبر است.', 400);
    stmts.push(env.DB.prepare('INSERT OR REPLACE INTO profiles (name,token,account_id,nexa_workers,created_at,updated_at,pos) VALUES (?,?,?,?,?,?,?)')
      .bind(String(p.name),String(p.token),String(p.account_id),flags(p.nexa_workers),p.created_at || new Date().toISOString(),p.updated_at || p.created_at || new Date().toISOString(),typeof p.pos === 'number' ? p.pos : idx));
    pCount++;
  });
  if (data.scripts !== undefined) {
    if (!Array.isArray(data.scripts)) throw new ApiError('فهرست اسکریپت‌های بکاپ نامعتبر است.', 400);
    stmts.push(env.DB.prepare('DELETE FROM scripts'));
    for (const s of data.scripts) {
      if (!s || !/^[a-zA-Z0-9._-]{1,64}$/.test(String(s.key || ''))) throw new ApiError('نام اسکریپت بکاپ نامعتبر است.', 400);
      const source = s.source === 'url' ? 'url' : 'file';
      if (typeof s.content !== 'string') throw new ApiError('محتوای اسکریپت بکاپ نامعتبر است.', 400);
      if (source === 'url') {
        let link; try { link = new URL(s.source_url); } catch { throw new ApiError('لینک اسکریپت بکاپ نامعتبر است.', 400); }
        if (!['http:','https:'].includes(link.protocol)) throw new ApiError('پروتکل اسکریپت بکاپ نامعتبر است.', 400);
      }
      stmts.push(env.DB.prepare('INSERT OR REPLACE INTO scripts (key,content,source,source_url,updated_at) VALUES (?,?,?,?,?)')
        .bind(s.key,s.content,source,s.source_url || null,s.updated_at || new Date().toISOString()));
      sCount++;
    }
  }
  if (data.settings !== undefined) {
    if (!data.settings || typeof data.settings !== 'object' || Array.isArray(data.settings)) throw new ApiError('تنظیمات بکاپ نامعتبر است.', 400);
    for (const [key, value] of Object.entries(data.settings)) {
      if (!key || ['login_fails','lock_until'].includes(key) || key.startsWith('pages_rebuild_lock:')) continue;
      if (typeof value !== 'string') throw new ApiError('مقادیر تنظیمات بکاپ باید متن باشند.', 400);
      stmts.push(env.DB.prepare('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)').bind(key,value)); setCount++;
    }
  }
  const counts = Object.create(null);
  if (data.tables !== undefined) {
    if (!data.tables || typeof data.tables !== 'object' || Array.isArray(data.tables)) throw new ApiError('جدول‌های بکاپ نامعتبرند.', 400);
    for (const [name, columns] of Object.entries(PANEL_BACKUP_TABLES)) {
      if (!Object.hasOwn(data.tables,name)) continue;
      const rows = data.tables[name];
      if (!Array.isArray(rows)) throw new ApiError(`جدول «${name}» باید آرایه باشد.`, 400);
      stmts.push(env.DB.prepare(`DELETE FROM ${name}`));
      for (const row of rows) {
        if (!row || typeof row !== 'object' || Array.isArray(row)) throw new ApiError(`ردیف جدول «${name}» نامعتبر است.`, 400);
        const values = columns.map(c => row[c] === undefined ? null : row[c]);
        if (values.some(v => v !== null && typeof v !== 'string' && typeof v !== 'number')) throw new ApiError(`مقدار جدول «${name}» نامعتبر است.`, 400);
        stmts.push(env.DB.prepare(`INSERT INTO ${name} (${columns.join(',')}) VALUES (${columns.map(() => '?').join(',')})`).bind(...values));
      }
      counts[name] = rows.length;
    }
  }
  await env.DB.batch(stmts);
  return json({ ok: true, profiles:pCount, scripts:sCount, settings:setCount, tables:counts });
});

route("POST", "/api/reset", async (m, req, env) => {
  const body = await req.json();
  const stmts = [];
  if (body.profiles) stmts.push(env.DB.prepare("DELETE FROM profiles"));
  if (body.scripts) stmts.push(env.DB.prepare("DELETE FROM scripts"));
  if (body.history) stmts.push(env.DB.prepare("DELETE FROM health_checks"));
  if (body.auth) {
    stmts.push(env.DB.prepare("DELETE FROM sessions"));
  }
  if (!stmts.length) throw new ApiError("چیزی برای بازنشانی انتخاب نشده است", 400);
  await env.DB.batch(stmts);
  const headers = body.auth ? { "Set-Cookie": clearSessionCookie() } : {};
  return json({ ok: true, reset: Object.keys(body).filter(k => body[k]) }, 200, headers);
});

route("GET", "/api/health/summary", async (m, req, env) => {
  const last = await env.DB.prepare("SELECT MAX(checked_at) AS last FROM health_checks").first();
  const counts = await env.DB.prepare("SELECT status, COUNT(*) AS n FROM health_checks GROUP BY status").all();
  const nexa = await collectTargets(env);
  return json({
    auto_rebuild: (await getSetting(env, "auto_rebuild")) !== "0",
    last_check: last ? last.last : null,
    counts: counts.results || [],
    targets: { nexa: nexa.length },
  });
});

route("GET", "/api/health/history", async (m, req, env) => {
  const { results } = await env.DB.prepare("SELECT * FROM health_checks ORDER BY id DESC LIMIT 100").all();
  return json({ history: results || [] });
});

route("POST", "/api/health/run", async (m, req, env) => {
  return json({ ok: true, results: await runHealthCheck(env) });
});

route("GET", "/api/health/config", async (m, req, env) => {
  const { results } = await env.DB.prepare("SELECT * FROM health_config").all();
  return json({ configs: results || [] });
});

route("POST", "/api/health/config", async (m, req, env) => {
  const body = await req.json();
  const profile = String(body.profile || "").trim();
  const worker = String(body.worker || "").trim();
  let path = String(body.path || "/").trim() || "/";
  if (!profile || !worker) throw new ApiError("profile و worker الزامی است", 400);
  if (!path.startsWith("/")) path = "/" + path;
  if (path.length > 200) throw new ApiError("مسیر طولانی است", 400);
  await env.DB.prepare("INSERT OR REPLACE INTO health_config (profile, worker, path) VALUES (?, ?, ?)")
    .bind(profile, worker, path).run();
  return json({ ok: true, path });
});

route("POST", "/api/health/toggle", async (m, req, env) => {
  const body = await req.json();
  await setSetting(env, "auto_rebuild", body.enabled === false ? "0" : "1");
  return json({ ok: true, auto_rebuild: body.enabled !== false });
});

const FONT_VAZIRMATN = "data:font/woff2;base64,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";

const UI_CSS = `
@font-face {
  font-family: "Vazirmatn";
  src: url(${FONT_VAZIRMATN}) format("woff2-variations");
  font-weight: 100 900;
  font-style: normal;
  font-display: block;
}

:root {
  color-scheme: light;
  --bg: #F8FCF9;
  --surface: #FFFFFF;
  --surface-2: #F4F8F5;
  --surface-3: #EFF3EA;
  --border: #E0EBE1;
  --border-strong: #C9DACE;
  --text: #0A140B;
  --muted: #5A6B5F;
  --faint: #98AB9C;
  --primary: #0A8A1E;
  --primary-hover: #087118;
  --primary-soft: #ECF8EF;
  --primary-text: #FFFFFF;
  --ok: #0A8A1E;
  --ok-soft: #ECF8EF;
  --warn: #B7924A;
  --warn-soft: #F7F1E2;
  --danger: #C93030;
  --danger-soft: #FDEEEE;
  --violet: #22C22F;
  --violet-soft: #ECF8EF;
  --shadow-sm: 0 1px 2px rgba(10, 42, 18, 0.05);
  --shadow-md: 0 8px 24px rgba(10, 42, 18, 0.10);
  --radius: 14px;
  --radius-sm: 10px;
  --field-h: 40px;
  --side-w: 252px;
  --top-h: 60px;
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --bg: #071209;
  --surface: #0C120E;
  --surface-2: #111A14;
  --surface-3: #17211A;
  --border: #1E2B22;
  --border-strong: #2C3D31;
  --text: #EAF5EC;
  --muted: #98AB9C;
  --faint: #718075;
  --primary: #38E331;
  --primary-hover: #6EF75A;
  --primary-soft: rgba(56, 227, 49, 0.14);
  --primary-text: #05140A;
  --ok: #22C22F;
  --ok-soft: rgba(34, 194, 47, 0.14);
  --warn: #E8C77A;
  --warn-soft: rgba(232, 199, 122, 0.13);
  --danger: #F27474;
  --danger-soft: rgba(242, 116, 116, 0.13);
  --violet: #80D99A;
  --violet-soft: rgba(128, 217, 154, 0.14);
  --shadow-sm: none;
  --shadow-md: 0 10px 30px rgba(0, 0, 0, 0.45);
}

* { box-sizing: border-box; }
html, body {
  margin: 0;
  padding: 0;
  background: var(--bg);
  color: var(--text);
  font-family: "Vazirmatn", Tahoma, system-ui, sans-serif;
  font-size: 14px;
  line-height: 1.7;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}
h1, h2, h3, h4 { margin: 0; font-weight: 700; line-height: 1.4; }
h3 { font-size: 15px; }
p { margin: 0 0 8px; }
a { color: var(--primary); text-decoration: none; }
code, pre, .mono, input[type="url"], .ltr {
  font-family: ui-monospace, Consolas, "Courier New", monospace;
  direction: ltr;
  unicode-bidi: isolate;
}
code {
  font-size: 12px;
  background: var(--surface-3);
  padding: 1px 6px;
  border-radius: 6px;
  color: var(--text);
}
hr.divider {
  border: 0;
  border-top: 1px solid var(--border);
  margin: 18px 0;
}
.hidden { display: none !important; }

.ico { display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0; line-height: 0; }
.ico svg { display: block; }
.spin {
  width: 14px; height: 14px; border-radius: 50%;
  border: 2px solid currentColor; border-right-color: transparent;
  display: inline-block; animation: spin 0.8s linear infinite;
  will-change: transform;
}
@keyframes spin { to { transform: rotate(360deg); } }

.row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.spread { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.small { font-size: 12.5px; }
.xs { font-size: 11.5px; }
.dim { color: var(--muted); }
.bold { font-weight: 700; }
.u { text-decoration: underline; text-underline-offset: 3px; }
.empty { color: var(--muted); text-align: center; padding: 32px 16px; font-size: 13px; line-height: 1.9; }
.empty .btn-row { justify-content: center; margin-top: 16px; }
.copy-ico {
  display: inline-flex; align-items: center; cursor: pointer;
  color: var(--faint); padding: 2px; border-radius: 6px;
  transition: color 0.15s, background 0.15s;
}
.copy-ico:hover { color: var(--primary); background: var(--primary-soft); }

.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 8px;
  height: var(--field-h); padding: 0 18px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-strong);
  background: var(--surface);
  color: var(--text);
  font: inherit; font-size: 13.5px; font-weight: 600;
  cursor: pointer; white-space: nowrap; user-select: none;
  transition: background-color 0.15s, border-color 0.15s, color 0.15s, opacity 0.15s;
}
.btn:hover { background: var(--surface-2); border-color: var(--faint); }
.btn:focus-visible { outline: 2px solid var(--primary); outline-offset: 2px; }
.btn:disabled { opacity: 0.55; cursor: not-allowed; }
.btn.sm { height: 34px; padding: 0 14px; font-size: 12.5px; border-radius: 9px; }
.btn.xs { height: 28px; padding: 0 10px; font-size: 12px; border-radius: 8px; }
.btn.primary { background: var(--primary); border-color: var(--primary); color: var(--primary-text); }
.btn.primary:hover { background: var(--primary-hover); border-color: var(--primary-hover); }
.btn.danger { color: var(--danger); border-color: var(--danger-soft); background: var(--danger-soft); }
.btn.danger:hover { border-color: var(--danger); background: var(--danger-soft); }
.btn.ok { color: var(--ok); border-color: var(--ok-soft); background: var(--ok-soft); }
.btn.ok:hover { border-color: var(--ok); }
.btn.ghost { background: transparent; border-color: transparent; color: var(--muted); }
.btn.ghost:hover { background: var(--surface-3); color: var(--text); border-color: transparent; }
.btn-row { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
.btn-row.center { justify-content: center; }
.back-link {
  display: inline-flex; align-items: center; gap: 6px;
  color: var(--primary); font-size: 13px; cursor: pointer; margin-bottom: 12px;
}
.back-link:hover { text-decoration: underline; }

input[type="number"], input[type="file"], input[type="email"], input[type="search"],
input[type="text"], input[type="password"], input[type="url"], input:not([type]),
select, textarea {
  font: inherit; font-size: 13.5px; color: var(--text);
  background: var(--surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  height: var(--field-h);
  padding: 0 12px;
  width: 100%;
  margin-top: 8px;
  outline: none;
  transition: border-color 0.15s, box-shadow 0.15s;
}
textarea {
  height: auto; min-height: 120px; padding: 10px 12px; line-height: 1.6;
  resize: vertical;
}
select {
  appearance: none; -webkit-appearance: none; cursor: pointer;
  padding-inline-end: 34px;
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2398AB9C' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'><polyline points='6 9 12 15 18 9'/></svg>");
  background-repeat: no-repeat;
  background-position: left 12px center;
}
input[type="file"] { padding: 6px 8px; cursor: pointer; }
input[type="file"]::file-selector-button {
  font: inherit; font-size: 12.5px; font-weight: 600;
  margin-inline-end: 10px; padding: 6px 12px;
  border: 1px solid var(--border-strong); border-radius: 8px;
  background: var(--surface-2); color: var(--text); cursor: pointer;
}
input:focus, select:focus, textarea:focus {
  border-color: var(--primary);
  box-shadow: 0 0 0 3px var(--primary-soft);
}
input:disabled, select:disabled, textarea:disabled { opacity: 0.6; cursor: not-allowed; }
input[type="number"] { direction: ltr; }
.fld { display: flex; flex-direction: column; min-width: 0; }
.lbl { font-size: 12.5px; font-weight: 600; color: var(--muted); margin-bottom: 2px; }

:where(.fld, .chk, .btn-row, .auth-hint, .result-box, .tbl-wrap, .err-line, .ok-line, .out, .log, .grid, .small, .dim, p, textarea, .qd-target)
  + :where(.fld, .chk, .btn-row, .auth-hint, .result-box, .tbl-wrap, .err-line, .ok-line, .out, .log, .grid, textarea) {
  margin-top: 16px;
}
:where(.fld) + :where(.auth-hint, .small) { margin-top: 10px; }
:where(.row, .spread, .btn-row, .grid, .qd, .log, .tabs, .modal, #view > div) > :where(*) { margin-top: 0; }
.chk { min-height: 24px; }
.chk {
  display: inline-flex; align-items: center; gap: 8px;
  font-size: 13.5px; cursor: pointer; user-select: none;
}
.chk input { width: 16px; height: 16px; margin: 0; accent-color: var(--primary); cursor: pointer; }

.switch { position: relative; display: inline-flex; align-items: center; cursor: pointer; }
.switch input { position: absolute; opacity: 0; width: 0; height: 0; margin: 0; }
.switch .track {
  position: relative; width: 40px; height: 22px; border-radius: 999px;
  background: var(--border-strong); transition: background-color 0.18s;
}
.switch .track::after {
  content: ""; position: absolute; top: 3px; inset-inline-start: 3px;
  width: 16px; height: 16px; border-radius: 50%;
  background: #fff; box-shadow: var(--shadow-sm);
  transition: transform 0.18s ease;
}
.switch input:checked + .track { background: var(--primary); }
.switch input:checked + .track::after { transform: translateX(-18px); }
.switch input:focus-visible + .track { box-shadow: 0 0 0 3px var(--primary-soft); }

.grid { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }
.grid.c2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.grid.c3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.grid.c4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }

.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px 22px;
  box-shadow: var(--shadow-sm);
  min-width: 0;
}
.card > * + * { margin-top: 16px; }
.card > .card-head + * { margin-top: 12px; }
label { font-weight: 600; }
.card h3 {
  font-size: 15px; font-weight: 700;
  margin: 0 0 14px;
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
}
.card h3 .ico { color: var(--primary); }

.stat {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px 18px;
  box-shadow: var(--shadow-sm);
}
.stat .num { font-size: 24px; font-weight: 800; line-height: 1.2; letter-spacing: -0.2px; }
.stat .lbl { margin-top: 4px; }

.badge {
  display: inline-flex; align-items: center; gap: 5px;
  height: 22px; padding: 0 9px;
  border-radius: 999px;
  font-size: 12px; font-weight: 600; white-space: nowrap;
  background: var(--surface-3); color: var(--muted);
}
.badge.c { background: var(--primary-soft); color: var(--primary); }
.badge.v { background: var(--violet-soft); color: var(--violet); }
.badge.ok { background: var(--ok-soft); color: var(--ok); }
.badge.n { background: var(--surface-3); color: var(--text); }
.badge.y, .badge.warn { background: var(--warn-soft); color: var(--warn); }
.badge.r, .badge.bad { background: var(--danger-soft); color: var(--danger); }
.badge.off { background: var(--surface-3); color: var(--faint); }

.c { color: var(--primary); }
.v { color: var(--violet); }
.y { color: var(--warn); }
.r { color: var(--danger); }
.n { color: var(--text); }
.ok { color: var(--ok); }
.bad { color: var(--danger); }
.warn { color: var(--warn); }
.off { color: var(--faint); }

.dot {
  display: inline-block; width: 7px; height: 7px; border-radius: 50%;
  background: currentColor; flex-shrink: 0;
}
.d1-pill {
  display: inline-flex; align-items: center; gap: 6px;
  height: 24px; padding: 0 10px; border-radius: 999px;
  font-size: 12px; font-weight: 600;
  background: var(--surface-3); color: var(--muted);
}
.d1-pill.ok { background: var(--ok-soft); color: var(--ok); }
.d1-pill.bad { background: var(--danger-soft); color: var(--danger); }
.d1-pill.small { height: 20px; font-size: 11px; padding: 0 8px; }

.tbl-wrap {
  overflow: auto;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--surface);
}
table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 13px; }
th, td { padding: 11px 14px; text-align: right; vertical-align: middle; }
th {
  background: var(--surface-2);
  color: var(--muted); font-size: 12px; font-weight: 600;
  white-space: nowrap;
  border-bottom: 1px solid var(--border);
}
tbody tr td { border-bottom: 1px solid var(--border); }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover td { background: var(--surface-2); }

.tabs {
  display: inline-flex; flex-wrap: wrap; gap: 4px;
  background: var(--surface-3);
  padding: 4px; border-radius: 12px;
  margin-bottom: 16px;
  max-width: 100%;
}
.tab {
  height: 32px; padding: 0 14px;
  border: 0; border-radius: 9px;
  background: transparent; color: var(--muted);
  font: inherit; font-size: 13px; font-weight: 600;
  cursor: pointer;
  transition: background-color 0.15s, color 0.15s;
}
.tab:hover { color: var(--text); }
.tab.active { background: var(--surface); color: var(--text); box-shadow: var(--shadow-sm); }

.kv-item {
  display: flex; justify-content: space-between; align-items: center; gap: 12px;
  padding: 9px 0; border-bottom: 1px solid var(--border); font-size: 13px;
}
.kv-item:last-child { border-bottom: 0; }
.result-box {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 14px 16px;
}
.result-box .row { gap: 10px; }
.result-box > div:first-child { font-weight: 700; margin-bottom: 4px; }
.out, pre.out {
  margin: 10px 0 0;
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 12px 14px;
  font-size: 12px; line-height: 1.7;
  max-height: 360px; overflow: auto;
  white-space: pre-wrap; word-break: break-word;
  color: var(--text);
}
.log {
  margin-top: 10px; max-height: 260px; overflow: auto;
  font-size: 12.5px; color: var(--muted);
  display: flex; flex-direction: column; gap: 4px;
}
.step {
  display: flex; align-items: center; gap: 8px;
  padding: 6px 10px; border-radius: 8px;
  background: var(--surface-2); color: var(--muted); font-size: 13px;
}
.ok-line, .err-line {
  display: flex; align-items: flex-start; gap: 8px;
  padding: 6px 10px; border-radius: 8px; font-size: 13px;
}
.ok-line { color: var(--ok); background: var(--ok-soft); }
.err-line { color: var(--danger); background: var(--danger-soft); }
.err-line .ico { margin-top: 3px; }

.err-box {
  display: flex; align-items: flex-start; gap: 12px;
  background: var(--danger-soft);
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  padding: 14px 16px;
  margin: 4px 0;
}
.err-box .ico { color: var(--danger); margin-top: 2px; }
.err-box h3 { color: var(--danger); font-size: 14px; margin: 0 0 4px; }
.err-box p { color: var(--text); margin: 0; font-size: 13px; }
.err-box .raw {
  margin-top: 6px; font-size: 11.5px; color: var(--muted);
  font-family: ui-monospace, Consolas, monospace; direction: ltr; text-align: left;
  word-break: break-word;
}
.raw { color: var(--muted); font-size: 11.5px; }

.auth-hint { color: var(--muted); font-size: 12.5px; line-height: 1.9; }

#toasts {
  position: fixed; bottom: 20px; inset-inline-start: 20px;
  display: flex; flex-direction: column; gap: 8px;
  z-index: 60; pointer-events: none; max-width: min(380px, calc(100vw - 40px));
}
.toast {
  display: flex; align-items: center; gap: 10px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-inline-start: 3px solid var(--primary);
  border-radius: var(--radius-sm);
  box-shadow: var(--shadow-md);
  padding: 11px 14px;
  font-size: 13px;
  animation: toast-in 0.2s ease-out;
}
.toast.ok { border-inline-start-color: var(--ok); }
.toast.err { border-inline-start-color: var(--danger); }
.toast.warn { border-inline-start-color: var(--warn); }
.toast.info { border-inline-start-color: var(--primary); }
.toast > span:last-child { line-height: 1.6; }
@keyframes toast-in {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}

#modal-root { position: fixed; inset: 0; z-index: 50; display: none; align-items: center; justify-content: center; padding: 20px; }
#modal-root.open { display: flex; }
.modal-back {
  position: absolute; inset: 0;
  background: rgba(15, 20, 32, 0.45);
  animation: fade-in 0.15s ease-out;
}
.modal {
  position: relative; z-index: 1;
  width: min(520px, 100%);
  max-height: calc(100vh - 40px);
  max-height: calc(100dvh - 40px);
  display: flex; flex-direction: column; gap: 18px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 16px;
  box-shadow: var(--shadow-md);
  padding: 22px 24px;
  animation: pop-in 0.18s ease-out;
}
.modal.wide { width: min(760px, 100%); }
.modal.xl { width: min(1000px, 100%); }
.modal > .spread {
  margin: 0; padding-bottom: 16px;
  border-bottom: 1px solid var(--border);
}
.modal > .spread h3 { margin: 0; font-size: 16px; display: flex; align-items: center; gap: 10px; }
.modal > .spread h3 .ico { color: var(--primary); }
.modal-body { overflow: auto; min-height: 0; padding: 4px; margin: -4px; }
.modal-body > div:not(.qd, .row, .spread, .grid, .btn-row) > * + * { margin-top: 16px; }
.modal-body > div > .auth-hint:last-child { margin-top: 12px; }
.modal-body p { margin: 0; line-height: 1.9; }
.modal > .btn-row {
  justify-content: flex-start; gap: 10px;
  padding-top: 18px; border-top: 1px solid var(--border);
}
.modal > .btn-row .btn { min-width: 96px; }
@keyframes fade-in { from { opacity: 0; } to { opacity: 1; } }
@keyframes pop-in {
  from { opacity: 0; transform: translateY(6px) scale(0.99); }
  to { opacity: 1; transform: none; }
}

#auth {
  min-height: 100vh;
  display: flex; align-items: center; justify-content: center;
  padding: 24px;
}
.auth-wrap { width: 100%; max-width: 420px; }
.auth-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 18px;
  box-shadow: var(--shadow-md);
  padding: 32px 30px 28px;
}
.auth-logo {
  display: flex; align-items: center; gap: 10px;
  font-size: 18px; font-weight: 800;
}
.auth-logo .ico { color: var(--primary); }
.auth-sub { color: var(--muted); font-size: 13px; margin: 6px 0 24px; }
.auth-card form { display: flex; flex-direction: column; gap: 16px; }
.auth-card .btn.primary { width: 100%; height: 42px; font-size: 14px; }

#main { display: flex; min-height: 100vh; }
#side {
  width: var(--side-w); flex-shrink: 0;
  position: sticky; top: 0; height: 100vh;
  display: flex; flex-direction: column;
  background: var(--surface);
  border-inline-end: 1px solid var(--border);
  padding: 16px 12px;
  z-index: 30;
  transition: transform 0.2s ease;
}
.brand {
  display: flex; align-items: center; gap: 10px;
  height: 44px; padding: 0 10px; margin-bottom: 12px;
  font-size: 15px; font-weight: 800;
}
.brand .ico { color: var(--primary); }

.brand-logo {
  width: 34px; height: 34px; object-fit: contain;
  border-radius: 8px; flex: none;
  box-shadow: 0 4px 18px rgba(56, 227, 49, 0.22);
}
.auth-logo .brand-logo {
  width: 46px; height: 46px; border-radius: 11px;
  box-shadow: 0 7px 24px rgba(56, 227, 49, 0.20);
}
#nav { display: flex; flex-direction: column; gap: 2px; overflow-y: auto; flex: 1; min-height: 0; }
.nav-item {
  display: flex; align-items: center; gap: 12px;
  height: 40px; padding: 0 12px;
  border-radius: var(--radius-sm);
  color: var(--muted);
  font-size: 13.5px; font-weight: 600;
  cursor: pointer;
  transition: background-color 0.15s, color 0.15s;
}
.nav-item .ico { color: var(--faint); transition: color 0.15s; }
.nav-item:hover { background: var(--surface-3); color: var(--text); }
.nav-item:hover .ico { color: var(--text); }
.nav-item.active { background: var(--primary-soft); color: var(--primary); font-weight: 700; }
.nav-item.active .ico { color: var(--primary); }
.side-foot { border-top: 1px solid var(--border); padding-top: 12px; margin-top: 10px; }
.side-foot .btn { width: 100%; justify-content: flex-start; }
.side-foot .btn:hover { color: var(--danger); }

#content { flex: 1; min-width: 0; display: flex; flex-direction: column; }
#topbar {
  position: sticky; top: 0; z-index: 20;
  height: var(--top-h);
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  padding: 0 24px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
}
#crumb { font-size: 16px; font-weight: 800; min-width: 0; overflow-wrap: anywhere; line-height: 1.4; }
#profile-wrap { display: flex; align-items: center; gap: 10px; }
#profile-wrap label { font-size: 12.5px; color: var(--muted); font-weight: 600; white-space: nowrap; }
#profile-select { width: 200px; height: 36px; margin-top: 0; font-size: 13px; }
.btn.btn-theme-top { width: 36px; padding: 0; flex: none; }
#btn-menu { display: none; padding: 0; width: 36px; }
#view { padding: 24px; flex: 1; min-width: 0; }
#view > div {
  max-width: 1240px; margin: 0 auto;
  display: flex; flex-direction: column; gap: 16px;
}
#view > div > * { margin: 0; }
#side-backdrop { display: none; }

.theme-fab {
  position: fixed; top: 14px; inset-inline-end: 14px; z-index: 40;
  width: 38px; height: 38px; padding: 0 !important;
  background: var(--surface); border-color: var(--border-strong);
  color: var(--text);
}

@media (max-width: 1100px) {
  .grid.c4 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 900px) {
  #side {
    position: fixed; top: 0; bottom: 0; inset-inline-start: 0;
    width: min(var(--side-w), 86vw);
    height: 100vh; height: 100dvh;
    transform: translateX(100%);
    box-shadow: var(--shadow-md);
    padding-bottom: max(16px, env(safe-area-inset-bottom));
    -webkit-overflow-scrolling: touch;
  }
  body.side-open #side { transform: translateX(0); }
  body.side-open { overflow: hidden; }
  body.side-open #side-backdrop {
    display: block; position: fixed; inset: 0; z-index: 25;
    background: rgba(15, 20, 32, 0.4);
  }
  #nav { overscroll-behavior: contain; }
  #btn-menu { display: inline-flex; }
  #topbar { padding: 0 14px; }
  #view { padding: 16px; }
  .grid.c2, .grid.c3, .grid.c4 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  #profile-select { width: 150px; }
}
@media (max-width: 560px) {
  .grid.c2, .grid.c3, .grid.c4 { grid-template-columns: 1fr; }
  #profile-wrap label { display: none; }
  #profile-select { width: min(130px, 38vw); }
  #crumb { font-size: 14.5px; }
  .card { padding: 16px; }
  .auth-card { padding: 26px 22px 22px; }
  .stat .num { font-size: 20px; }
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
}

.rq-card { padding:18px 20px !important; }
.rq-top { display:flex; align-items:center; justify-content:space-between; gap:12px; font-size:13.5px; }
.rq-label { color:var(--muted); }
.rq-val { direction:ltr; font-weight:600; color:var(--text); font-variant-numeric:tabular-nums; white-space:nowrap; }
.rq-val span { color:var(--muted); font-weight:500; }
.rq-bar { margin-top:10px; height:10px; border-radius:99px; background:var(--surface-3); overflow:hidden; direction:rtl; display:flex; }
.rq-bar > i { display:block; flex:none; height:100%; border-radius:99px; background:var(--primary); transition:width .5s ease; }
.rq-bar.bad > i { background:var(--danger); }
.rq-msg { margin-top:8px; font-size:12px; color:var(--muted); }
.rq-skel { display:inline-block; width:120px; height:14px; border-radius:6px; background:var(--surface-3); vertical-align:middle; }

select.sel-open { border-color: var(--primary); box-shadow: 0 0 0 3px var(--primary-soft);
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2338E331' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'><polyline points='18 15 12 9 6 15'/></svg>"); }
.dd-panel {
  position: fixed; z-index: 10000; direction: rtl;
  background: var(--surface); color: var(--text);
  border: 1px solid var(--border-strong); border-radius: 12px;
  box-shadow: 0 14px 36px rgba(16, 24, 40, 0.18), 0 2px 6px rgba(16, 24, 40, 0.06);
  padding: 6px; display: flex; flex-direction: column; gap: 4px;
  animation: dd-in .14s ease-out; font-size: 13.5px;
}
:root[data-theme="dark"] .dd-panel { box-shadow: 0 16px 40px rgba(0, 0, 0, 0.55); }
.dd-panel.up { animation-name: dd-in-up; }
@keyframes dd-in { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: none; } }
@keyframes dd-in-up { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: none; } }
.dd-search { position: relative; }
.dd-search input { margin: 0 !important; height: 34px !important; font-size: 13px !important; padding-inline-start: 32px !important; background: var(--surface-2) !important; }
.dd-search .ico { position: absolute; top: 50%; right: 10px; transform: translateY(-50%); color: var(--faint); pointer-events: none; }
.dd-list { overflow-y: auto; overscroll-behavior: contain; display: flex; flex-direction: column; gap: 2px; padding: 1px; }
.dd-list::-webkit-scrollbar { width: 8px; }
.dd-list::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 8px; border: 2px solid var(--surface); }
.dd-opt {
  display: flex; align-items: center; gap: 10px;
  min-height: 36px; padding: 7px 10px; border-radius: 8px;
  cursor: pointer; user-select: none; color: var(--text);
  transition: background .1s, color .1s;
}
.dd-opt .dd-txt { flex: 1; min-width: 0; unicode-bidi: plaintext; text-align: right; white-space: normal; overflow-wrap: anywhere; line-height: 1.5; }
.dd-opt .dd-chk { width: 16px; height: 16px; flex: none; color: var(--primary); opacity: 0; display: inline-flex; }
.dd-opt.act { background: var(--surface-3); }
.dd-opt.sel { background: var(--primary-soft); color: var(--primary); font-weight: 600; }
.dd-opt.sel .dd-chk { opacity: 1; }
.dd-opt.sel.act { background: var(--primary-soft); box-shadow: inset 0 0 0 1px var(--primary); }
.dd-opt.dis { opacity: .45; cursor: not-allowed; }
.dd-group { padding: 8px 10px 4px; font-size: 11.5px; font-weight: 700; color: var(--faint); }
.dd-empty { padding: 14px 10px; text-align: center; color: var(--muted); font-size: 12.5px; }

.qd { display:flex; flex-direction:column; gap:12px; }
.qd-target { display:flex; align-items:center; gap:10px; padding:10px 12px; border:1px solid var(--border); border-radius:var(--radius-sm); background:var(--surface-2); font-size:13px; }
.qd-target .nm { direction:ltr; font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight:600; }
.qd-target .grow { flex:1; }
.qd-drop {
  display:flex; align-items:center; gap:14px; padding:16px 18px;
  border:1.5px dashed var(--border-strong); border-radius:var(--radius);
  background:var(--surface); cursor:pointer; transition:border-color .15s, background .15s;
}
.qd-drop:hover { border-color:var(--primary); }
.qd-drop.over { border-color:var(--primary); background:var(--primary-soft); }
.qd-drop .qd-ic { width:42px; height:42px; flex:none; border-radius:12px; display:grid; place-items:center; background:var(--primary-soft); color:var(--primary); }
.qd-drop .t1 { font-weight:700; font-size:13.5px; }
.qd-drop .t2 { color:var(--muted); font-size:12px; margin-top:2px; }
.qd-drop .grow { flex:1; min-width:0; }
.qd-file { display:inline-flex; align-items:center; gap:6px; max-width:100%; padding:3px 10px; border-radius:999px; background:var(--ok-soft); color:var(--ok); font-size:12px; font-weight:600; direction:ltr; }
.qd-or { display:flex; align-items:center; gap:10px; color:var(--faint); font-size:12px; }
.qd-or::before, .qd-or::after { content:""; flex:1; height:1px; background:var(--border); }
.qd textarea.qd-code {
  margin:0; min-height:300px; max-height:55vh; direction:ltr; text-align:left; white-space:pre; tab-size:2;
  font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12.5px; line-height:1.6;
  background:var(--surface-2);
}
.qd-meta { display:flex; flex-wrap:wrap; align-items:center; gap:8px; font-size:12px; color:var(--muted); min-height:24px; }
.qd-chip { display:inline-flex; align-items:center; gap:5px; height:22px; padding:0 9px; border-radius:999px; background:var(--surface-3); color:var(--muted); font-weight:600; font-size:11.5px; }
.qd-chip.ok { background:var(--ok-soft); color:var(--ok); }
.qd-chip.warn { background:var(--warn-soft); color:var(--warn); }
.qd-chip.c { background:var(--primary-soft); color:var(--primary); }
.qd-steps { display:flex; flex-direction:column; gap:6px; padding:12px 14px; border:1px solid var(--border); border-radius:var(--radius-sm); background:var(--surface-2); font-size:13px; }
.qd-step { display:flex; align-items:center; gap:8px; color:var(--muted); }
.qd-step.done { color:var(--ok); }
.qd-step.run { color:var(--text); font-weight:600; }
.qd-step.fail { color:var(--danger); font-weight:600; }
.qd-step .spin { width:14px; height:14px; }
.qd-result { display:flex; align-items:center; gap:10px; flex-wrap:wrap; padding:12px 14px; border-radius:var(--radius-sm); background:var(--ok-soft); color:var(--ok); font-weight:600; font-size:13px; }
.qd-result a { direction:ltr; color:inherit; text-decoration:underline; word-break:break-all; }
.qd-kbd { font-size:11px; color:var(--faint); }

td.mono, td .mono, .kv-item .mono, .result-box .u, .result-box .mono { overflow-wrap: anywhere; word-break: break-word; }
td { overflow-wrap: anywhere; }
.dd-opt { height: auto !important; min-height: 34px; padding-top: 6px; padding-bottom: 6px; }

.bk-group { border: 1px solid var(--border); border-radius: var(--radius-sm); overflow: hidden; margin-top: 12px; }
.bk-head { display: flex; align-items: center; gap: 8px; padding: 9px 12px; background: var(--surface-2); border-bottom: 1px solid var(--border); font-weight: 700; font-size: 13.5px; }
.bk-head .btn { margin-inline-start: auto; }
.bk-list { display: flex; flex-direction: column; }
.chk.bk-row { display: flex; width: 100%; align-items: center; gap: 10px; padding: 9px 12px; border-bottom: 1px solid var(--border); flex-wrap: wrap; }
.chk.bk-row:last-child { border-bottom: 0; }
.chk.bk-row:hover { background: var(--surface-2); }
.bk-row .bk-name { font-family: ui-monospace, Consolas, "Courier New", monospace; direction: ltr; font-size: 13px; font-weight: 600; overflow-wrap: anywhere; }
.bk-row .bk-acc { color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
.bk-row .bk-st { margin-inline-start: auto; }
`;

function clientApp() {
  "use strict";

  const S = { view: "dashboard", profile: null, profiles: [], me: null, d1: null };

  const $ = (s) => document.querySelector(s);

  function el(tag, attrs, ...children) {
    const n = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") n.className = v;
      else if (k === "html") n.innerHTML = v;
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else if (v !== null && v !== undefined) n.setAttribute(k, v);
    }
    for (const c of children.flat(9)) {
      if (c === null || c === undefined) continue;
      n.append(c.nodeType ? c : document.createTextNode(String(c)));
    }
    return n;
  }

  const ICONS = {
    bolt: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    home: '<path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>',
    user: '<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    server: '<rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
    box: '<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>',
    database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5"/><path d="M3 12a9 3 0 0 0 18 0"/>',
    rocket: '<path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"/><path d="m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"/><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"/><path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"/>',
    refresh: '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
    file: '<path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/>',
    lock: '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
    plus: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
    trash: '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
    pencil: '<path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/>',
    link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    globe: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    scissors: '<circle cx="6" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><line x1="20" y1="4" x2="8.12" y2="15.88"/><line x1="14.47" y1="14.48" x2="20" y2="20"/><line x1="8.12" y1="8.12" x2="12" y2="12"/>',
    search: '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    clock: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    copy: '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
    download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
    upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>',
    play: '<polygon points="6 3 20 12 6 21 6 3"/>',
    info: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
    alert: '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    terminal: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
    table: '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/><path d="M3 15h18"/><path d="M12 3v18"/>',
    key: '<path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
    x: '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    hammer: '<path d="m15 12-8.373 8.373a1 1 0 1 1-3-3L12 9"/><path d="m18 15 4-4"/><path d="m21.5 11.5-1.914-1.914A2 2 0 0 1 19 8.172V7l-2.26-2.26a6 6 0 0 0-4.202-1.756L9 2.96l.92.82A6.18 6.18 0 0 1 12 8.4V10l2 2h1.172a2 2 0 0 1 1.414.586L18.5 14.5"/>',
    building: '<rect x="4" y="2" width="16" height="20" rx="2"/><path d="M9 22v-4h6v4"/><path d="M8 6h.01"/><path d="M16 6h.01"/><path d="M12 6h.01"/><path d="M8 10h.01"/><path d="M16 10h.01"/><path d="M12 10h.01"/><path d="M8 14h.01"/><path d="M16 14h.01"/><path d="M12 14h.01"/>',
    eye: '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
    check: '<polyline points="20 6 9 17 4 12"/>',
    save: '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    flame: '<path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"/>',
    zap: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    sparkles: '<path d="m12 3-1.9 5.8a2 2 0 0 1-1.3 1.3L3 12l5.8 1.9a2 2 0 0 1 1.3 1.3L12 21l1.9-5.8a2 2 0 0 1 1.3-1.3L21 12l-5.8-1.9a2 2 0 0 1-1.3-1.3Z"/>',
    pulse: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    tag: '<path d="M12.586 2.586A2 2 0 0 0 11.172 2H4a2 2 0 0 0-2 2v7.172a2 2 0 0 0 .586 1.414l8.704 8.704a2.426 2.426 0 0 0 3.42 0l6.58-6.58a2.426 2.426 0 0 0 0-3.42z"/><circle cx="7.5" cy="7.5" r=".5" fill="currentColor"/>',
    layers: '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
    up: '<polyline points="18 15 12 9 6 15"/>',
    down: '<polyline points="6 9 12 15 18 9"/>',
    crosshair: '<circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/>',
    menu: '<line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32 1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/>',
    moon: '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
  };

  function icon(name, size = 16) {
    return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ICONS.info}</svg>`;
  }

  function ic(name, size = 16) {
    return el("span", { class: "ico", html: icon(name, size) });
  }

  function applyTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    try { localStorage.setItem("nexa_theme", t); } catch {}
    const btn = document.getElementById("btn-theme");
    if (btn) btn.innerHTML = icon(t === "light" ? "moon" : "sun", 16);
  }
  (function initTheme() {
    let t = null;
    try { t = localStorage.getItem("nexa_theme"); } catch {}
    if (t !== "light" && t !== "dark") {
      t = (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) ? "light" : "dark";
    }
    applyTheme(t);
    const btn = document.getElementById("btn-theme");
    if (btn) btn.addEventListener("click", () => {
      applyTheme(document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light");
    });
  })();

  const HTTP_FA = {
    0: "اتصال به سرور برقرار نشد. اینترنت یا آدرس ورکر را بررسی کنید.",
    400: "درخواست نامعتبر است. ورودی‌ها را بررسی کنید.",
    401: "نشست شما منقضی شده یا رمز پنل اشتباه است. دوباره وارد شوید.",
    403: "دسترسی مجاز نیست. توکن Cloudflare این اکانت دسترسی لازم را ندارد.",
    404: "مورد موردنظر پیدا نشد؛ ممکن است قبلاً حذف شده باشد.",
    409: "تداخل: این نام یا منبع از قبل وجود دارد.",
    429: "تعداد درخواست‌ها زیاد است. چند ثانیه صبر کنید و دوباره تلاش کنید.",
    500: "خطای داخلی ورکر. جزئیات فنی را ببینید.",
    502: "سرور مقصد پاسخ معتبر نداد.",
    503: "سرویس موقتاً در دسترس نیست. کمی بعد تلاش کنید.",
    504: "زمان انتظار تمام شد (timeout). دوباره تلاش کنید.",
  };
  function explainError(status, raw) {
    const m = String(raw || "").trim();
    const low = m.toLowerCase();
    let hint = "";
    if (!m) return { hint: HTTP_FA[status] || (status >= 500 ? HTTP_FA[500] : "خطای ناشناخته."), raw: "" };
    if (status === 0 && /failed to fetch|networkerror|load failed|network request failed/.test(low)) hint = HTTP_FA[0];
    else if (status === 401 && low === "unauthorized") hint = "نشست شما منقضی شده؛ دوباره وارد شوید.";
    else if (/\b(10000|9109)\b|authentication error|invalid api token/.test(low)) hint = "توکن Cloudflare نامعتبر است یا دسترسی کافی ندارد. توکن را در بخش «اکانت‌ها» بررسی کنید.";
    else if (/\b971\b|rate limit|too many requests/.test(low)) hint = "تعداد درخواست‌ها به Cloudflare زیاد شده؛ یک دقیقه صبر کنید و دوباره امتحان کنید.";
    return { hint: hint || m, raw: m };
  }
  function apiErr(status, raw, details = null, fullBody = null) {
    const { hint } = explainError(status, raw);
    const err = new Error(raw && raw !== hint ? `${hint} — جزئیات: ${raw}` : hint);
    err.status = status; err.hint = hint; err.raw = raw || "";
    err.details = details || (fullBody && fullBody.details) || null;
    err.body = fullBody || null;
    if (fullBody && fullBody.details && fullBody.details.unknown_secrets) err.unknown_secrets = fullBody.details.unknown_secrets;
    else if (details && details.unknown_secrets) err.unknown_secrets = details.unknown_secrets;
    return err;
  }
  function errInfo(e) {
    if (e && e.hint) return { hint: e.hint, raw: e.raw || "" };
    return explainError(0, e && e.message ? e.message : e);
  }
  function errorBox(title, e, retry) {
    const info = errInfo(e);
    return el("div", { class: "err-box" }, ic("alert", 22),
      el("div", { style: "flex:1;min-width:0" },
        el("h3", null, title),
        el("p", null, info.hint),
        info.raw && info.raw !== info.hint ? el("div", { class: "raw" }, info.raw) : null,
        retry ? el("div", { class: "btn-row" }, el("button", { class: "btn sm", onclick: retry }, ic("refresh", 14), " تلاش مجدد")) : null));
  }

  function errLine(e) {
    const i = errInfo(e);
    return el("div", { class: "err-line" }, ic("alert", 15),
      el("div", { style: "min-width:0" }, el("div", { style: "font-weight:600" }, i.hint),
        i.raw && i.raw !== i.hint ? el("div", { class: "raw" }, i.raw) : null));
  }

  async function api(path, opts = {}) {
    const o = { headers: {}, ...opts };
    if (o.body && typeof o.body !== "string") {
      o.body = JSON.stringify(o.body);
      o.headers["Content-Type"] = "application/json";
    }
    let res;
    try { res = await fetch(path, o); }
    catch (e) { throw apiErr(0, e && e.message ? e.message : ""); }
    const ct = res.headers.get("Content-Type") || "";
    let data;
    try { data = ct.includes("json") ? await res.json() : await res.text(); }
    catch { data = ""; }
    if (!res.ok) {
      const raw = data && typeof data === "object" && data.error ? (typeof data.error === "string" ? data.error : JSON.stringify(data.error)) : (typeof data === "string" ? data.slice(0, 300) : "");
      const details = data && typeof data === "object" ? data.details : null;
      throw apiErr(res.status, raw, details, data);
    }
    return data;
  }

  function toast(msg, type = "info", ms = 3800) {
    const cls = type === "ok" ? "ok" : type === "err" ? "err" : type === "warn" ? "warn" : "info";
    const icn = type === "ok" ? "check" : type === "err" ? "alert" : type === "warn" ? "alert" : "info";
    const t = el("div", { class: `toast ${cls}` }, ic(icn, 16), el("span", { style: "flex:1" }, msg));
    $("#toasts").append(t);
    setTimeout(() => t.remove(), ms);
  }

  function modal(title, bodyNode, actions = [], size = "") {
    const root = $("#modal-root");
    root.innerHTML = "";
    const box = el("div", { class: `modal ${size}` });
    const close = el("button", { class: "btn ghost sm", onclick: closeModal }, ic("x", 14), " بستن");
    const head = el("div", { class: "spread" }, el("h3", null, title), close);
    const footer = actions.length ? el("div", { class: "btn-row", style: "justify-content:flex-start" }, ...actions) : null;
    box.append(head, el("div", { class: "modal-body" }, bodyNode));
    if (footer) box.append(footer);
    const back = el("div", { class: "modal-back", onclick: closeModal });
    root.append(back, box);
    root.classList.add("open");
    return box;
  }
  function closeModal() { const r = $("#modal-root"); r.classList.remove("open"); r.innerHTML = ""; }

  function confirmBox(msg, onYes, danger = true) {
    modal("تأیید", el("div", null, el("p", null, msg)), [
      el("button", { class: danger ? "btn danger" : "btn primary", onclick: () => { closeModal(); onYes(); } }, "بله، ادامه بده"),
      el("button", { class: "btn ghost", onclick: closeModal }, "انصراف"),
    ]);
  }

  function copyText(txt) {
    navigator.clipboard.writeText(txt).then(
      () => toast("کپی شد ✓", "ok", 1500),
      () => toast("کپی ناموفق بود", "err")
    );
  }

  function spinner(label) { return el("span", { class: "row small dim" }, el("span", { class: "spin" }), ` ${label} `); }

  function fmtBytes(n) {
    if (n == null) return "-";
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
    return (n / 1048576).toFixed(2) + " MB";
  }

  function ensureProfile() {
    if (S.profile) return true;
    toast("اول یک اکانت انتخاب یا اضافه کنید", "warn");
    go("accounts");
    return false;
  }

  async function boot() {
    let st;
    try { st = await api("/api/status"); }
    catch (e) { $("#auth").classList.remove("hidden"); renderConnError(e.message); return; }
    if (st.authed) { await showMain(); return; }
    $("#auth").classList.remove("hidden");
    renderAuthScreen(st);
  }

  function d1Pill(ok, small) {
    return el("span", { class: "d1-pill " + (ok ? "ok" : "bad") + (small ? " small" : "") },
      el("span", { class: "dot" }),
      ok ? "دیتابیس D1 متصل است" : "دیتابیس D1 متصل نیست");
  }

  function renderConnError(msg) {
    const b = $("#auth-body");
    b.innerHTML = "";
    b.append(
      d1Pill(false),
      el("div", { class: "empty" }, ic("alert", 22), el("div", { style: "margin:4px 0" }, "خطا در ارتباط با ورکر"),
        el("div", { class: "small dim" }, msg || "")),
      el("div", { class: "btn-row", style: "justify-content:center" },
        el("button", { class: "btn sm", onclick: () => location.reload() }, ic("refresh", 14), " تلاش مجدد")));
  }

  async function renderAuthScreen(st) {
    const b = $("#auth-body");
    b.innerHTML = "";

    if (!st.d1) {
      b.append(
        d1Pill(false),
        el("div", { style: "font-weight:700;margin:6px 0 10px" }, "دیتابیس D1 به این ورکر متصل نیست"),
        el("div", { class: "auth-hint", style: "text-align:right;line-height:2.2" },
          "این پنل برای ذخیره‌سازی توکن‌ها و تنظیمات به D1 نیاز دارد. برای وصل کردن:",
          el("br"), "۱. در داشبورد Cloudflare بخش ", el("b", null, "Storage & Databases → D1"), " یک دیتابیس بسازید.",
          el("br"), "۲. در تنظیمات ورکر ", el("b", null, "Settings → Bindings → Add"), " یک binding از نوع ", el("b", null, "D1 database"), " اضافه کنید.",
          el("br"), "۳. ", el("b", null, "Variable name"), " باید دقیقاً ", el("code", { style: "color:var(--green);direction:ltr" }, "DB"), " باشد.",
          el("br"), "۴. ذخیره کنید و این صفحه را دوباره باز کنید."),
        st.d1Error ? el("div", { class: "dim small", style: "margin-top:10px" }, st.d1Error) : null,
        el("div", { class: "btn-row", style: "justify-content:center;margin-top:14px" },
          el("button", { class: "btn sm", onclick: () => location.reload() }, ic("refresh", 14), " بررسی مجدد")));
      return;
    }

    if (!st.admin_set) {
      b.append(
        el("span", { class: "d1-pill bad" }, el("span", { class: "dot" }), "متغیر محیطی ADMIN تنظیم نشده"),
        el("div", { style: "font-weight:700;margin:6px 0 10px" }, "رمز عبور پنل تعیین نشده است"),
        el("div", { class: "auth-hint", style: "text-align:right;line-height:2.2" },
          "رمز این پنل به‌صورت متغیر محیطی (Text) روی همین ورکر ذخیره می‌شود — نه در دیتابیس. برای تنظیم:",
          el("br"), "۱. در داشبورد Cloudflare وارد تنظیمات همین ورکر شوید: ", el("b", null, "Settings → Variables and Secrets"),
          el("br"), "۲. دکمه ", el("b", null, "Add"), " را بزنید؛ نوع را ", el("b", null, "Text"), " بگذارید (نه Secret).",
          el("br"), "۳. نام متغیر: ", el("code", { style: "color:var(--green);direction:ltr" }, "ADMIN"),
          el("br"), "۴. مقدار: رمز دلخواه شما (حداقل ۶ کاراکتر).",
          el("br"), "۵. ذخیره و ", el("b", null, "Deploy"), " کنید، سپس این صفحه را دوباره باز کنید."),
        el("div", { class: "btn-row", style: "justify-content:center;margin-top:14px" },
          el("button", { class: "btn sm", onclick: () => location.reload() }, ic("refresh", 14), " بررسی مجدد")));
      return;
    }

    b.append(
      el("span", { class: "d1-pill ok" }, el("span", { class: "dot" }), "D1 متصل"),
      el("span", { class: "d1-pill ok" }, el("span", { class: "dot" }), "متغیر ADMIN فعال"));

    const pw = el("input", { type: "password", placeholder: "رمز عبور (متغیر ADMIN)", autocomplete: "current-password" });
    const btn = el("button", { class: "btn primary", style: "width:100%;margin-top:6px" }, ic("lock", 14), " ورود");

    b.append(el("form", {
      onsubmit: async (e) => {
        e.preventDefault();
        btn.disabled = true; btn.textContent = "...";
        try {
          await api("/api/login", { method: "POST", body: { password: pw.value } });
          await showMain();
        } catch (ex) {
          toast(ex.message, "err", 5000);
          btn.disabled = false;
          btn.replaceChildren(ic("lock", 14), " ورود");
        }
      },
    }, el("label", { class: "fld", style: "text-align:right" }, "رمز عبور پنل", pw), btn));
    pw.focus();
  }

  async function showMain() {
    $("#auth").classList.add("hidden");
    $("#main").classList.remove("hidden");
    const tb = $("#btn-theme"), pw = $("#profile-wrap");
    if (tb && pw) { tb.classList.remove("theme-fab"); tb.classList.add("btn-theme-top"); pw.prepend(tb); }
    buildNav();
    const doLogout = async () => { try { await api("/api/logout", { method: "POST" }); } catch {} location.reload(); };
    $("#btn-logout").onclick = doLogout;
    const logoutTop = $("#btn-logout-top");
    if (logoutTop) logoutTop.onclick = doLogout;
    const menuBtn = $("#btn-menu");
    if (menuBtn) menuBtn.onclick = () => document.body.classList.toggle("side-open");
    const backdrop = $("#side-backdrop");
    if (backdrop) backdrop.onclick = () => document.body.classList.remove("side-open");
    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape" && document.body.classList.contains("side-open") && !$("#modal-root").classList.contains("open")) {
        document.body.classList.remove("side-open");
      }
    });
    try {
      const d = await api("/api/profiles");
      S.profiles = d.profiles || [];
      const saved = localStorage.getItem("nexa_profile");
      if (S.profiles.length && S.profiles.some(p => p.name === saved)) S.profile = saved;
      else if (S.profiles.length) S.profile = S.profiles[0].name;
    } catch {}
    renderProfileSelect();
    const requested = location.hash.replace(/^#\/?/, "");
    go(NAV.some(n => n[0] === requested) ? requested : (S.profile ? "dashboard" : "accounts"));
  }

  function renderProfileSelect() {
    const sel = $("#profile-select");
    sel.innerHTML = "";
    if (!S.profiles.length) {
      sel.append(el("option", null, "— هیچ اکانتی نیست —"));
      sel.disabled = true;
      return;
    }
    sel.disabled = false;
    for (const p of S.profiles) sel.append(el("option", { value: p.name }, p.name));
    if (S.profile) sel.value = S.profile;
    sel.onchange = () => { S.profile = sel.value; localStorage.setItem("nexa_profile", S.profile); S.me = null; go(S.view === "accounts" ? "accounts" : "dashboard"); };
  }

  async function refreshProfiles() {
    const d = await api("/api/profiles");
    S.profiles = d.profiles || [];
    if (S.profiles.length && !S.profiles.some(p => p.name === S.profile)) S.profile = S.profiles[0].name;
    if (!S.profiles.length) S.profile = null;
    renderProfileSelect();
  }

  const NAV = [
    ["dashboard", "home", "داشبورد"],
    ["accounts", "user", "اکانت‌ها"],
    ["workers", "server", "ورکرها"],
    ["pages", "layers", "پروژه‌های Pages"],
    ["tagged", "tag", "ورکرهای برچسب‌دار"],
    ["kv", "box", "مخزن‌های KV"],
    ["d1", "database", "دیتابیس‌های D1"],
    ["creators", "rocket", "ساخت پنل"],
    ["bulk", "refresh", "عملیات گروهی"],
    ["health", "pulse", "پایش سلامت"],
    ["settings", "lock", "تنظیمات"],
  ];
  function buildNav() {
    const nav = $("#nav");
    nav.innerHTML = "";
    for (const [key, ico, label] of NAV) {
      const b = el("a", { class: "nav-item" + (S.view === key ? " active" : ""), "data-v": key, href: "#/" + key, onclick: (e) => { e.preventDefault(); go(key); } }, ic(ico), label);
      nav.append(b);
    }
  }
  function go(view) {
    document.body.classList.remove("side-open");
    S.view = view;
    location.hash = "#/" + view;
    buildNav();
    $("#crumb").textContent = (NAV.find(n => n[0] === view) || ["", "", view])[2];
    const root = $("#view");
    root.innerHTML = "";
    const v = document.createElement("div");
    root.append(v);
    const views = {
      dashboard: viewDashboard, accounts: viewAccounts, workers: viewWorkers, pages: viewPages, tagged: viewTagged, kv: viewKv,
      d1: viewD1, creators: viewCreators, bulk: viewBulk, health: viewHealth, settings: viewSettings,
    };
    const fn = views[view] || viewDashboard;
    Promise.resolve().then(() => fn(v)).catch((e) => {
      console.error(e);
      v.innerHTML = "";
      v.append(errorBox("این بخش بارگذاری نشد", e, () => go(view)));
    });
  }

  window.addEventListener("hashchange", () => {
    const h = location.hash.replace(/^#\/?/, "") || "dashboard";
    if (h !== S.view && NAV.some(n => n[0] === h)) go(h);
  });
  (function initHash() {
    const h = location.hash.replace(/^#\/?/, "");
    if (h && NAV.some(n => n[0] === h)) S.view = h;
  })();

  async function viewDashboard(v) {
    if (!ensureProfile()) return;
    v.append(spinner("در حال بارگذاری اطلاعات اکانت..."));
    try {
      if (!S.me) S.me = await api(`/api/me?profile=${encodeURIComponent(S.profile)}`);
      const [w, pg, kv, d1] = await Promise.all([
        api(`/api/workers?profile=${encodeURIComponent(S.profile)}`),
        api(`/api/pages?profile=${encodeURIComponent(S.profile)}`).catch(() => ({ projects: [] })),
        api(`/api/kv?profile=${encodeURIComponent(S.profile)}`),
        api(`/api/d1?profile=${encodeURIComponent(S.profile)}`),
      ]);
      v.innerHTML = "";
      v.append(el("div", { class: "card" },
        el("h3", null, ic("user"), " اکانت فعال"),
        el("div", { style: "display:flex;flex-direction:column;gap:12px;margin-top:4px" },
          el("div", { class: "row", style: "gap:10px" },
            el("span", { class: "dim small", style: "min-width:130px" }, "پروفایل:"),
            el("span", { class: "badge c" }, S.profile)),
          el("div", { class: "row", style: "gap:10px" },
            el("span", { class: "dim small", style: "min-width:130px" }, "نام اکانت کلادفلر:"),
            el("span", { style: "font-weight:700" }, S.me.account_name || "-")),
          el("div", { class: "row", style: "gap:10px" },
            el("span", { class: "dim small", style: "min-width:130px" }, "شناسه اکانت:"),
            el("span", { class: "mono", style: "font-size:12.5px" }, S.me.account_id)))));
      v.append(usageCard());
      v.append(el("div", { class: "grid c4" },
        el("div", { class: "stat" }, el("div", { class: "num" }, String(w.workers.length)), el("div", { class: "lbl" }, "ورکرها")),
        el("div", { class: "stat" }, el("div", { class: "num" }, String((pg.projects || []).length)), el("div", { class: "lbl" }, "پروژه‌های Pages")),
        el("div", { class: "stat" }, el("div", { class: "num" }, String(kv.namespaces.length)), el("div", { class: "lbl" }, "مخزن‌های KV")),
        el("div", { class: "stat" }, el("div", { class: "num" }, String(d1.databases.length)), el("div", { class: "lbl" }, "دیتابیس‌های D1"))));
      v.append(el("div", { class: "card" },
        el("h3", null, ic("bolt"), " دسترسی سریع"),
        el("div", { class: "btn-row" },
          el("button", { class: "btn primary", onclick: () => go("creators") }, ic("rocket", 14), " ساخت پنل Nexa"),
          el("button", { class: "btn", onclick: () => go("workers") }, ic("server", 14), " مدیریت ورکرها"),
          el("button", { class: "btn", onclick: () => go("tagged") }, ic("tag", 14), " ورکرهای برچسب‌دار"),
          el("button", { class: "btn", onclick: () => go("bulk") }, ic("refresh", 14), " آپدیت/ریبیلد گروهی"))));
    } catch (e) { v.innerHTML = ""; v.append(el("div", { class: "card" }, el("div", { class: "empty" }, errLine(e)))); }
  }

  function usageCard() {
    const LIMIT = 100000;
    const fmt = (n) => Number(n || 0).toLocaleString("en-US");
    const val = el("span", { class: "rq-val" }, el("span", { class: "rq-skel" }));
    const fill = el("i", { style: "width:0%" });
    const bar = el("div", { class: "rq-bar" }, fill);
    const msg = el("div", { class: "rq-msg" });
    msg.style.display = "none";
    const card = el("div", { class: "card rq-card" },
      el("div", { class: "rq-top" }, el("span", { class: "rq-label" }, "ریکوئست‌های امروز"), val),
      bar, msg);
    api(`/api/usage?profile=${encodeURIComponent(S.profile)}`).then(u => {
      const total = Number(u.total) || 0, limit = Number(u.limit) || LIMIT;
      const pct = Math.min(100, (total / limit) * 100);
      val.replaceChildren(fmt(total), el("span", null, ` / ${fmt(limit)}`));
      fill.style.width = `${total > 0 ? Math.max(pct, 1.5) : 0}%`;
      bar.classList.toggle("bad", pct >= 90);
    }).catch(e => {
      val.replaceChildren(el("span", null, "—"));
      msg.textContent = (e && e.raw) || (e && e.message) || "دریافت آمار ناموفق بود";
      msg.style.display = "";
    });
    return card;
  }

  async function viewAccounts(v) {
    v.append(spinner("در حال دریافت اکانت‌ها..."));
    await refreshProfiles().catch(() => {});
    v.innerHTML = "";
    const card = el("div", { class: "card" },
      el("div", { class: "spread" },
        el("h3", null, ic("user"), " اکانت‌های ذخیره‌شده (توکن‌ها داخل D1)"),
        el("div", { class: "row" },
          el("button", { class: "btn primary sm", onclick: addProfileModal }, ic("plus", 14), " افزودن اکانت"),
          el("button", { class: "btn sm", onclick: addBulkProfilesModal }, ic("layers", 14), " افزودن گروهی"))));
    if (!S.profiles.length) {
      card.append(el("div", { class: "empty" }, "هیچ اکانی ذخیره نشده. یکی اضافه کنید."));
      v.append(card);
      return;
    }
    const rows = S.profiles.map((p, idx) => el("tr", { onclick: () => { S.profile = p.name; localStorage.setItem("nexa_profile", p.name); renderProfileSelect(); go("dashboard"); } },
      el("td", null, p.name === S.profile ? el("span", { class: "badge c" }, p.name) : p.name),
      el("td", { class: "mono" }, p.account_id),
      el("td", { class: "mono" }, p.token_masked),
      el("td", null, String(p.nexa_workers.length)),
      el("td", null, el("div", { class: "row", style: "gap:8px;flex-wrap:nowrap" },
        p.name === S.profile ? el("span", { class: "badge v" }, "فعال") : el("span", { class: "dim small" }, "انتخاب کن"),
        el("button", { class: "btn xs", title: "انتقال به بالا", disabled: idx === 0 ? "disabled" : null, style: idx === 0 ? "opacity:.35;cursor:default" : "", onclick: (e) => { e.stopPropagation(); moveProfile(p.name, -1); } }, ic("up", 14)),
        el("button", { class: "btn xs", title: "انتقال به پایین", disabled: idx === S.profiles.length - 1 ? "disabled" : null, style: idx === S.profiles.length - 1 ? "opacity:.35;cursor:default" : "", onclick: (e) => { e.stopPropagation(); moveProfile(p.name, 1); } }, ic("down", 14)),
        el("button", { class: "btn xs", onclick: (e) => { e.stopPropagation(); editProfileModal(p.name); } }, ic("pencil", 12), " ویرایش"))),
    ));
    card.append(el("div", { class: "tbl-wrap" }, el("table", null,
      el("thead", null, el("tr", null,
        el("th", null, "نام پروفایل"), el("th", null, "Account ID"), el("th", null, "توکن"), el("th", null, "پنل Nexa"), el("th", null, "عملیات"))),
      el("tbody", null, rows))));
    const actions = el("div", { class: "btn-row" },
      el("button", { class: "btn warn sm", onclick: deleteProfileModal }, ic("trash", 14), " حذف پروفایل"),
      el("button", { class: "btn sm", onclick: tokenLinkModal }, ic("link", 14), " لینک ساخت توکن (با دسترسی‌های آماده)"));
    card.append(actions);
    v.append(card);
  }

  async function moveProfile(name, dir) {
    const i = S.profiles.findIndex(p => p.name === name);
    const j = i + dir;
    if (i < 0 || j < 0 || j >= S.profiles.length) return;
    const arr = S.profiles.slice();
    [arr[i], arr[j]] = [arr[j], arr[i]];
    try {
      await api("/api/profiles/reorder", { method: "POST", body: { order: arr.map(p => p.name) } });
      S.profiles = arr;
      renderProfileSelect();
      go("accounts");
    } catch (e) { toast(e.message, "err"); }
  }

  function tokenLinkModal() {
    const kind = el("select", null, el("option", { value: "account" }, "توکن اکانتی (Account-owned)"), el("option", { value: "user" }, "توکن شخصی (My Profile)"));
    const name = el("input", { value: "Nexa-Manager" });
    const linkBox = el("div", { class: "small dim", style: "margin-top:10px" }, "برای گرفتن لینک، دکمه ساخت را بزنید.");
    const mk = el("button", {
      class: "btn primary sm", onclick: async () => {
        try {
          const d = await api(`/api/token-link?kind=${kind.value}&name=${encodeURIComponent(name.value)}`);
          linkBox.innerHTML = "";
          linkBox.append(
            el("a", { href: d.url, target: "_blank", rel: "noopener" }, "باز کردن صفحه ساخت توکن در Cloudflare ↗"),
            el("div", { style: "margin-top:8px" }, el("button", { class: "btn sm", onclick: () => copyText(d.url) }, ic("copy", 14), " کپی لینک")),
            el("div", { class: "auth-hint" }, "این لینک «تمام دسترسی‌های» کلادفلر (حساب + زون + کاربر) را از پیش انتخاب می‌کند تا هیچ‌جا به خطای کمبود دسترسی نخورید. روی صفحه Cloudflare فقط: Continue to summary → Create Token را بزنید و توکن را کپی کنید (فقط یک بار نشان داده می‌شود)."),
          );
        } catch (e) { toast(e.message, "err"); }
      }
    }, "ساخت لینک");
    modal([ic("link", 18), " لینک ساخت توکن Cloudflare"], el("div", null,
      el("label", { class: "fld" }, "نوع توکن", kind),
      el("label", { class: "fld" }, "نام توکن", name),
      el("div", { class: "btn-row" }, mk),
      linkBox));
  }

  function addProfileModal() {
    const name = el("input", { placeholder: "مثلاً: My Company" });
    const token = el("input", { placeholder: "CF API Token", direction: "ltr" });
    const body = el("div", null,
      el("label", { class: "fld" }, "نام پروفایل", name),
      el("label", { class: "fld" }, "توکن API کلادفلر", token),
      el("div", { class: "btn-row" },
        el("button", { class: "btn sm ghost", onclick: tokenLinkModal }, ic("link", 14), " کمک: لینک ساخت توکن")),
      el("div", { class: "auth-hint" }, "اکانت به‌صورت خودکار از روی توکن تشخیص داده می‌شود."));
    const submit = async () => {
      try {
        const d = await api("/api/profiles", { method: "POST", body: { name: name.value.trim(), token: token.value.trim(), overwrite: true } });
        if (d.need_account) {
          closeModal();
          pickAccountModal(d.accounts, name.value.trim(), token.value.trim());
          return;
        }
        closeModal();
        toast(`پروفایل «${d.profile.name}» ذخیره شد ✓`, "ok");
        S.profile = d.profile.name;
        await refreshProfiles();
        go("dashboard");
      } catch (e) { toast(e.message, "err", 5000); }
    };
    modal([ic("plus", 18), " افزودن اکانت"], body, [el("button", { class: "btn primary", onclick: submit }, "ذخیره")]);
  }

  function addBulkProfilesModal() {
    const ta = el("textarea", { class: "code", style: "width:100%;min-height:190px;direction:ltr;text-align:left",
      placeholder: "Name1 | cf_token_xxx...\nName2 | cf_token_yyy...\nName3 | cf_token_zzz... | 4f3b...account_id" });
    const out = el("div", { style: "margin-top:10px" });
    const parse = () => ta.value.split("\n").map(l => l.trim()).filter(Boolean).map(l => {
      const parts = l.split(/[|\t,]/).map(s => s.trim()).filter(Boolean);
      return { name: parts[0] || "", token: parts[1] || "", account_id: parts[2] || "" };
    });
    modal([ic("layers", 18), " افزودن گروهی اکانت‌ها"], el("div", null,
      el("div", { class: "auth-hint", style: "text-align:right;line-height:2" },
        "هر خط یک اکانت: ", el("b", null, "نام | توکن | account_id"),
        el("br"), "جداکننده می‌تواند ", el("code", null, "|"), " یا Tab یا کاما باشد. بخش account_id اختیاری است (فقط وقتی لازم می‌شود که توکن به چند اکانت دسترسی داشته باشد).",
        el("br"), "هر توکن اعتبارسنجی می‌شود و اکانتش به‌صورت خودکار تشخیص داده می‌شود — مثل افزودن تکی."),
      el("label", { class: "fld", style: "margin-top:10px" }, "لیست اکانت‌ها", ta),
      el("div", { class: "btn-row" },
        el("button", {
          class: "btn primary sm", onclick: async (e) => {
            const entries = parse();
            if (!entries.length) return toast("چیزی وارد نشده است", "warn");
            e.target.disabled = true; e.target.textContent = "...";
            try {
              const r = await api("/api/profiles/bulk", { method: "POST", body: { entries } });
              out.innerHTML = "";
              let okN = 0;
              for (const it of r.results) {
                okN += it.ok ? 1 : 0;
                out.append(el("div", {
                  style: `font-size:12px;padding:4px 0;border-bottom:1px solid var(--line-soft);color:${it.ok ? "var(--green)" : "var(--red)"}`,
                }, `${it.ok ? "✓" : "✗"} ${it.name || "(بی‌نام)"} — ${it.message}`));
              }
              toast(`${okN} از ${r.results.length} اکانت ذخیره شد`, okN === r.results.length ? "ok" : "warn", 6000);
              if (okN) await refreshProfiles();
            } catch (ex) { toast(ex.message, "err", 6000); }
            e.target.disabled = false; e.target.replaceChildren(ic("check", 13), " افزودن همه");
          }
        }, ic("check", 13), " افزودن همه")),
      out), [], "wide");
  }

  function pickAccountModal(accounts, name, token) {
    const sel = el("select", null, accounts.map(a => el("option", { value: a.id }, `${a.name} — ${a.id}`)));
    const body = el("div", null,
      el("p", { class: "dim small" }, "این توکن به چند اکانت دسترسی دارد. یکی را انتخاب کنید:"),
      el("label", { class: "fld" }, "اکانت", sel));
    modal([ic("building", 18), " انتخاب اکانت"], body, [
      el("button", {
        class: "btn primary", onclick: async () => {
          try {
            const d = await api("/api/profiles", { method: "POST", body: { name, token, account_id: sel.value, overwrite: true } });
            closeModal();
            S.profile = d.profile.name;
            await refreshProfiles();
            go("dashboard");
            toast(`پروفایل «${name}» ذخیره شد ✓`, "ok");
          } catch (e) { toast(e.message, "err"); }
        }
      }, "ذخیره"),
    ]);
  }

  function deleteProfileModal() {
    if (!S.profiles.length) return toast("پروفایلی برای حذف نیست", "warn");
    const sel = el("select", null, S.profiles.map(p => el("option", { value: p.name }, p.name)));
    modal([ic("trash", 18), " حذف پروفایل"], el("div", null,
      el("p", { class: "dim small" }, "فقط پروفایل از D1 حذف می‌شود (منابع کلادفلر دست نمی‌خورند)."),
      el("label", { class: "fld" }, "پروفایل", sel)), [
      el("button", {
        class: "btn danger", onclick: async () => {
          try {
            await api(`/api/profiles/${encodeURIComponent(sel.value)}`, { method: "DELETE" });
            closeModal();
            await refreshProfiles();
            go("accounts");
            toast("پروفایل حذف شد", "ok");
          } catch (e) { toast(e.message, "err"); }
        }
      }, "حذف کن"),
    ]);
  }

  function editProfileModal(pname) {
    const p = S.profiles.find(x => x.name === pname);
    if (!p) return toast("پروفایل پیدا نشد", "err");
    const nameInp = el("input", { value: p.name });
    const tokenInp = el("input", { placeholder: "خالی = بدون تغییر", direction: "ltr" });
    const accInp = el("input", { value: p.account_id || "", direction: "ltr" });
    const body = el("div", null,
      el("label", { class: "fld" }, "نام پروفایل", nameInp),
      el("label", { class: "fld" }, `توکن جدید (فعلی: ${p.token_masked}) — خالی بگذارید تا عوض نشود`, tokenInp),
      el("label", { class: "fld" }, "Account ID", accInp),
      el("div", { class: "auth-hint" }, "اگر توکن را عوض کنید و Account ID را خالی بگذارید، اکانت به‌صورت خودکار تشخیص داده می‌شود (وقتی توکن فقط به یک اکانت دسترسی داشته باشد). تغییر نام، برچسب‌ها و تاریخچه سلامت را هم منتقل می‌کند."));
    const submit = async () => {
      try {
        const d = await api(`/api/profiles/${encodeURIComponent(pname)}`, { method: "PUT", body: { new_name: nameInp.value.trim(), token: tokenInp.value.trim(), account_id: accInp.value.trim() } });
        closeModal();
        toast(`پروفایل «${d.profile.name}» به‌روزرسانی شد ✓`, "ok");
        if (S.profile === pname) { S.profile = d.profile.name; try { localStorage.setItem("nexa_profile", S.profile); } catch {} S.me = null; }
        await refreshProfiles();
        go("accounts");
      } catch (e) { toast(e.message, "err", 5000); }
    };
    modal([ic("pencil", 18), ` ویرایش اکانت «${pname}»`], body, [el("button", { class: "btn primary", onclick: submit }, "ذخیره تغییرات")]);
  }

  async function viewWorkers(v) {
    if (!ensureProfile()) return;
    v.append(spinner("در حال دریافت ورکرها..."));
    try {
      const d = await api(`/api/workers?profile=${encodeURIComponent(S.profile)}`);
      v.innerHTML = "";
      const card = el("div", { class: "card" }, el("h3", null, ic("server"), ` ورکرهای اکانت «${S.profile}»`));
      if (!d.workers.length) { card.append(el("div", { class: "empty" }, "ورکری در این اکانت نیست.")); v.append(card); return; }
      const rows = d.workers.map(w => {
        const isN = d.nexa_workers.includes(w.name);
        return el("tr", { onclick: () => workerDetail(w.name) },
          el("td", null, w.name),
          el("td", null, isN ? el("span", { class: "badge n" }, "nexa") : el("span", { class: "badge off" }, "—")),
          el("td", { class: "mono" }, w.modified_on || "-"));
      });
      card.append(el("div", { class: "tbl-wrap" }, el("table", null,
        el("thead", null, el("tr", null, el("th", null, "نام ورکر"), el("th", null, "پرچم‌ها"), el("th", null, "آخرین تغییر"))),
        el("tbody", null, rows))));
      card.append(el("div", { class: "auth-hint" }, "برای مدیریت روی ورکر کلیک کنید."));
      v.append(card);
    } catch (e) { v.innerHTML = ""; v.append(el("div", { class: "card" }, el("div", { class: "empty" }, errLine(e)))); }
  }

  async function workerDetail(name) {
    const v = $("#view");
    v.innerHTML = "";
    v.append(el("span", { class: "back-link", onclick: () => go("workers") }, "→ بازگشت به لیست ورکرها"));
    const head = el("div", { class: "card" }, spinner("در حال دریافت..."));
    v.append(head);
    let flags = { nexa_workers: [] };
    try { const d = await api(`/api/workers?profile=${encodeURIComponent(S.profile)}`); flags = d; } catch {}
    const isN = flags.nexa_workers.includes(name);
    head.innerHTML = "";
    head.append(
      el("h3", { style: "direction:ltr" }, name),
      el("div", { class: "row", style: "margin:8px 0" },
        isN ? el("span", { class: "badge n" }, "پنل Nexa") : el("span", { class: "badge off" }, "Nexa: ندارد")),
      el("div", { class: "btn-row" },
        el("button", { class: "btn primary sm", onclick: () => quickDeployModal("worker", name) }, ic("upload", 14), " آپلود / پیست کد و دپلوی"),
        el("button", { class: "btn sm", onclick: () => workerCodeModal(name) }, ic("file", 14), " نمایش / ویرایش کد"),
        el("button", { class: "btn sm", onclick: () => workerUrlModal(name) }, ic("globe", 14), " آدرس ورکر"),
        el("button", { class: "btn danger sm", onclick: () => workerRebuildModal(name, "nexa") }, ic("hammer", 14), " ریبیلد کامل Worker"),
        el("button", { class: "btn sm", onclick: () => workerRenameModal(name) }, ic("pencil", 14), " تغییر نام"),
        el("button", { class: "btn sm", onclick: () => workerBindKvModal(name) }, ic("box", 14), " اتصال KV"),
        el("button", { class: "btn sm", onclick: () => workerBindD1Modal(name) }, ic("database", 14), " اتصال D1"),
        el("button", { class: "btn sm", onclick: () => workerUnbindModal(name) }, ic("scissors", 14), " حذف بایندینگ"),
        el("button", { class: "btn sm", onclick: () => workerBindingsModal(name) }, ic("search", 14), " لیست بایندینگ‌ها"),
        el("button", { class: "btn sm", onclick: () => workerDomainsModal(name) }, ic("globe", 14), " دامنه‌های حساب"),
        el("button", { class: "btn danger sm", onclick: () => workerDeleteModal(name) }, ic("trash", 14), " حذف ورکر"),
        el("button", { class: `btn sm ${isN ? "ok" : "warn"}`, onclick: () => toggleFlag(name, "nexa", !isN) }, isN ? [ic("check", 14), " Nexa فعال — خاموش کن"] : "علامت‌گذاری Nexa")));
    v.append(head);
  }

  async function toggleFlag(name, kind, val) {
    try {
      await api(`/api/workers/${encodeURIComponent(name)}/flags?profile=${encodeURIComponent(S.profile)}`, { method: "POST", body: { [kind]: val } });
      toast(val ? `«${name}» به‌عنوان پنل ${kind} علامت خورد ✓` : `علامت ${kind} «${name}» برداشته شد`, "ok");
      workerDetail(name);
    } catch (e) { toast(e.message, "err"); }
  }

  async function viewPages(v) {
    if (!ensureProfile()) return;
    v.append(spinner("در حال دریافت پروژه‌های Cloudflare Pages..."));
    try {
      const d = await api(`/api/pages?profile=${encodeURIComponent(S.profile)}`);
      v.innerHTML = "";

      const headRow = el("div", { class: "spread", style: "margin-bottom:14px;flex-wrap:wrap;gap:8px" },
        el("h3", null, ic("layers"), ` پروژه‌های Cloudflare Pages (اکانت «${S.profile}»)`),
        el("div", { class: "btn-row" },
          el("button", { class: "btn primary sm", onclick: () => pagesCreateModal() }, ic("plus", 14), " پروژه Pages جدید"),
          el("button", { class: "btn sm", onclick: () => pagesDeployModal() }, ic("upload", 14), " استقرار سریع کد"),
          el("button", { class: "btn sm", onclick: () => go("pages") }, ic("refresh", 14), " تازه‌سازی"))
      );

      const filterInput = el("input", { placeholder: "جستجوی پروژه Pages یا دامنه...", style: "margin-bottom:12px;width:100%" });
      const card = el("div", { class: "card" }, headRow, filterInput);
      const projects = d.projects || [];
      const nexaList = d.nexa_workers || [];

      if (!projects.length) {
        card.append(el("div", { class: "empty" }, "هیچ پروژه Pagesای در این اکانت پیدا نشد.",
          el("div", { class: "small dim", style: "margin-top:6px" }, "می‌توانید از دکمه «پروژه Pages جدید» در بالا یا از بخش «ساخت پنل / ورکر» یک پروژه بسازید.")));
        v.append(card);
        return;
      }

      const tbody = el("tbody");
      function renderRows(list) {
        tbody.innerHTML = "";
        if (!list.length) {
          tbody.append(el("tr", null, el("td", { colspan: "5", style: "text-align:center" }, "موردی یافت نشد")));
          return;
        }
        for (const p of list) {
                  const isN = nexaList.includes(p.name);
          const subdomain = p.subdomain || `${p.name}.pages.dev`;
          const url = `https://${subdomain}`;
          const prodBranch = p.production_branch || "main";
          const latestDep = p.latest_deployment;
          const depStatus = latestDep ? latestDep.status : "—";
          const statusBadge = depStatus === "SUCCESS"
            ? el("span", { class: "badge ok" }, "موفق")
            : depStatus === "FAILURE"
              ? el("span", { class: "badge danger" }, "ناموفق")
              : depStatus === "ACTIVE"
                ? el("span", { class: "badge ok" }, "فعال")
                : el("span", { class: "badge off" }, depStatus || "بدون دپلویمنت");

          const tr = el("tr", { onclick: () => pagesDetail(p.name), style: "cursor:pointer" },
            el("td", { class: "bold mono", style: "font-size:13px" }, p.name),
            el("td", null,
              isN ? el("span", { class: "badge n" }, "nexa") : el("span", { class: "badge off" }, "—")),
            el("td", null, el("a", { href: url, target: "_blank", rel: "noopener", class: "mono small", style: "color:var(--cyan);display:inline-flex;align-items:center;gap:4px", onclick: (e) => e.stopPropagation() }, subdomain, ic("link", 11))),
            el("td", null, el("span", { class: "badge off" }, prodBranch), " ", statusBadge),
            el("td", { class: "small mono" }, (p.created_on || "").slice(0, 10) || "—")
          );
          tbody.append(tr);
        }
      }

      renderRows(projects);

      filterInput.addEventListener("input", () => {
        const q = filterInput.value.toLowerCase().trim();
        renderRows(projects.filter(p => p.name.toLowerCase().includes(q) || (p.subdomain || "").toLowerCase().includes(q)));
      });

      const tblWrap = el("div", { class: "tbl-wrap" }, el("table", null,
        el("thead", null, el("tr", null,
          el("th", null, "نام پروژه Pages"),
          el("th", null, "پرچم‌ها"),
          el("th", null, "آدرس ساب‌دامین"),
          el("th", null, "شاخه اصلی / وضعیت"),
          el("th", null, "تاریخ ساخت"))),
        tbody
      ));

      card.append(tblWrap);
      card.append(el("div", { class: "auth-hint" }, "برای مدیریت کامل پروژه، اتصال‌های KV و D1، مدیریت دامنه‌ها، استقرار کد و تنظیمات روی سطر پروژه کلیک کنید."));
      v.append(card);
    } catch (e) {
      v.innerHTML = "";
      v.append(el("div", { class: "card" }, el("div", { class: "empty" }, errLine(e))));
    }
  }

  async function pagesDetail(name) {
    const v = $("#view");
    v.innerHTML = "";
    v.append(el("span", { class: "back-link", onclick: () => go("pages") }, "→ بازگشت به لیست پروژه‌های Pages"));
    const head = el("div", { class: "card" }, spinner("در حال دریافت مشخصات پروژه Pages..."));
    v.append(head);

    let proj = null;
    let flags = { nexa_workers: [] };
    let bindsData = { bindings: [], d1_databases: {}, env_vars: {}, kv_namespaces: {} };
    try {
      const [pRes, fRes, bRes] = await Promise.all([
        api(`/api/pages/${encodeURIComponent(name)}?profile=${encodeURIComponent(S.profile)}`),
        api(`/api/pages?profile=${encodeURIComponent(S.profile)}`).catch(() => ({ nexa_workers: [] })),
        api(`/api/pages/${encodeURIComponent(name)}/bindings?profile=${encodeURIComponent(S.profile)}`).catch(() => ({ bindings: [], d1_databases: {}, env_vars: {}, kv_namespaces: {} }))
      ]);
      proj = pRes.project || {};
      flags = fRes;
      bindsData = bRes || {};
    } catch (e) {
      head.innerHTML = "";
      head.append(el("div", { class: "empty" }, errLine(e)));
      return;
    }

      const isN = (flags.nexa_workers || []).includes(name);
    const subdomain = proj.subdomain || `${name}.pages.dev`;
    const url = `https://${subdomain}`;
    const prodBranch = proj.production_branch || "main";
    const domainsCount = (proj.domains || []).length;

    head.innerHTML = "";
    head.append(
      el("h3", { style: "direction:ltr;display:flex;align-items:center;gap:8px" }, ic("layers", 20), name),
      el("div", { class: "row", style: "margin:10px 0;flex-wrap:wrap;gap:8px" },
        isN ? el("span", { class: "badge n" }, "پنل Nexa") : el("span", { class: "badge off" }, "Nexa: ندارد"),
        el("a", { href: url, target: "_blank", rel: "noopener", class: "badge ok", style: "text-decoration:none;display:inline-flex;align-items:center;gap:4px" }, ic("globe", 12), ` ${subdomain} ↗`),
        el("span", { class: "badge off" }, `شاخه: ${prodBranch}`),
        el("span", { class: "badge off" }, `دامنه‌ها: ${domainsCount}`)
      ),
      el("div", { class: "btn-row" },
        el("button", { class: "btn primary sm", onclick: () => pagesChangeD1Modal(name) }, ic("database", 14), " تغییر دیتابیس D1"),
        el("button", { class: "btn primary sm", onclick: () => quickDeployModal("pages", name) }, ic("upload", 14), " آپلود / پیست کد و دپلوی"),
        el("button", { class: "btn sm", onclick: () => pagesRedeployDirect(name) }, ic("refresh", 14), " استقرار مجدد (Re-deploy)"),
        el("button", { class: "btn danger sm", onclick: () => pagesRebuildModal(name, "nexa") }, ic("hammer", 14), " ریبیلد کامل Pages"),
        el("button", { class: "btn sm", onclick: () => pagesUrlModal(name) }, ic("globe", 14), " آدرس پروژه"),
        el("button", { class: "btn sm", onclick: () => pagesDomainsModal(name) }, ic("globe", 14), ` دامنه‌ها (${domainsCount})`),
        el("button", { class: "btn sm", onclick: () => pagesDeploymentsModal(name) }, ic("clock", 14), " استقرارها / تاریخچه"),
        el("button", { class: "btn sm", onclick: () => pagesBindKvModal(name) }, ic("box", 14), " اتصال KV"),
        el("button", { class: "btn sm", onclick: () => pagesBindD1Modal(name) }, ic("database", 14), " اتصال D1"),
        el("button", { class: "btn sm", onclick: () => pagesAddEnvVarModal(name) }, ic("settings", 14), " افزودن متغیر"),
        el("button", { class: "btn sm", onclick: () => pagesConfigsModal(name) }, ic("settings", 14), " مدیریت کل تنظیمات"),
        el("button", { class: "btn danger sm", onclick: () => pagesDeleteModal(name) }, ic("trash", 14), " حذف پروژه Pages"),
        el("button", { class: `btn sm ${isN ? "ok" : "warn"}`, onclick: () => togglePagesFlag(name, "nexa", !isN) }, isN ? [ic("check", 14), " Nexa فعال — خاموش کن"] : "علامت‌گذاری Nexa")
      )
    );

    const configs = (proj.deployment_configs && proj.deployment_configs.production) || {};
    const d1Obj = (bindsData.d1_databases && Object.keys(bindsData.d1_databases).length) ? bindsData.d1_databases : (configs.d1_databases || {});
    const envObj = (bindsData.env_vars && Object.keys(bindsData.env_vars).length) ? bindsData.env_vars : (configs.env_vars || {});
    const kvObj = (bindsData.kv_namespaces && Object.keys(bindsData.kv_namespaces).length) ? bindsData.kv_namespaces : (configs.kv_namespaces || {});

    const d1Card = el("div", { class: "card", style: "margin-top:14px" });
    const d1Header = el("div", { class: "spread", style: "margin-bottom:10px;flex-wrap:wrap;gap:8px" },
      el("div", null,
        el("h4", { style: "display:flex;align-items:center;gap:8px;margin:0" }, ic("database", 17), " پایگاه‌داده‌های D1"),
        el("div", { class: "small dim", style: "margin-top:4px" }, "دیتابیس‌های متصل به عنوان env.DB. پس از هر تغییر، کدهای پروژه به صورت خودکار مجدداً مستقر (Re-deploy) می‌شوند.")
      ),
      el("div", { class: "btn-row" },
        el("button", { class: "btn primary sm", onclick: () => pagesChangeD1Modal(name) }, ic("refresh", 13), " تغییر / تعویض D1"),
        el("button", { class: "btn sm", onclick: () => pagesBindD1Modal(name) }, ic("plus", 13), " اتصال D1 جدید")
      )
    );
    d1Card.append(d1Header);

    const d1Keys = Object.keys(d1Obj).filter(k => d1Obj[k] !== null && d1Obj[k] !== undefined);
    if (!d1Keys.length) {
      d1Card.append(
        el("div", { class: "empty", style: "padding:18px 12px" },
          "هیچ پایگاه‌داده D1ای به این پروژه متصل نیست.",
          el("div", { style: "margin-top:10px" },
            el("button", { class: "btn primary sm", onclick: () => pagesBindD1Modal(name) }, ic("plus", 13), " اتصال دیتابیس D1")
          )
        )
      );
    } else {
      const d1Rows = d1Keys.map(k => {
        const val = d1Obj[k];
        const dbId = typeof val === "string" ? val : (val?.id || val?.database_id || "—");
        return el("tr", null,
          el("td", { class: "bold mono", style: "color:var(--cyan)" }, `env.${k}`),
          el("td", { class: "mono small" }, dbId),
          el("td", null, el("span", { class: "badge ok" }, "متصل (Active)")),
          el("td", null,
            el("div", { class: "btn-row", style: "justify-content:flex-end" },
              el("button", { class: "btn primary sm", title: "تغییر یا تعویض دیتابیس D1", onclick: () => pagesChangeD1Modal(name, k) }, ic("refresh", 13), " تعویض دیتابیس"),
              el("button", { class: "btn danger sm", title: "حذف بایندینگ", onclick: () => pagesUnbindBinding(name, k, "D1") }, ic("trash", 13), " حذف بایندینگ")
            )
          )
        );
      });
      d1Card.append(
        el("div", { class: "tbl-wrap" }, el("table", null,
          el("thead", null, el("tr", null,
            el("th", null, "نام در کد (Binding)"),
            el("th", null, "شناسه پایگاه داده (UUID)"),
            el("th", null, "وضعیت"),
            el("th", { style: "text-align:left" }, "عملیات")
          )),
          el("tbody", null, d1Rows)
        ))
      );
    }
    v.append(d1Card);

    const envCard = el("div", { class: "card", style: "margin-top:14px" });
    const envHeader = el("div", { class: "spread", style: "margin-bottom:10px;flex-wrap:wrap;gap:8px" },
      el("div", null,
        el("h4", { style: "display:flex;align-items:center;gap:8px;margin:0" }, ic("settings", 17), " متغیرهای محیطی (Environment Variables)"),
        el("div", { class: "small dim", style: "margin-top:4px" }, "متغیرهای متنی و مقادیر محرمانه (Secret / Plain Text). پس از هر تغییر، پروژه خودکار Re-deploy می‌شود.")
      ),
      el("div", { class: "btn-row" },
        el("button", { class: "btn primary sm", onclick: () => pagesAddEnvVarModal(name) }, ic("plus", 13), " افزودن متغیر جدید")
      )
    );
    envCard.append(envHeader);

    const envKeys = Object.keys(envObj).filter(k => envObj[k] !== null && envObj[k] !== undefined);
    if (!envKeys.length) {
      envCard.append(
        el("div", { class: "empty", style: "padding:18px 12px" },
          "هیچ متغیر محیطی برای این پروژه تعریف نشده است.",
          el("div", { style: "margin-top:10px" },
            el("button", { class: "btn primary sm", onclick: () => pagesAddEnvVarModal(name) }, ic("plus", 13), " افزودن اولین متغیر")
          )
        )
      );
    } else {
      const envRows = envKeys.map(k => {
        const val = envObj[k];
        const isSecret = typeof val === "object" && val?.type === "secret_text";
        const varType = isSecret ? "secret_text" : "plain_text";
        const rawVal = typeof val === "string" ? val : (val?.value || "");

        let valCell;
        if (isSecret) {
          valCell = el("td", { class: "mono small dim" }, "••••••••");
        } else {
          valCell = el("td", { class: "mono small", style: "word-break:break-all;max-width:260px" }, rawVal);
        }

        return el("tr", null,
          el("td", { class: "bold mono" }, k),
          el("td", null, el("span", { class: isSecret ? "badge warn" : "badge off" }, isSecret ? "محرمانه (Secret)" : "متن عادی (Plain)")),
          valCell,
          el("td", null,
            el("div", { class: "btn-row", style: "justify-content:flex-end" },
              el("button", { class: "btn sm", title: "ویرایش متغیر", onclick: () => pagesEditEnvVarModal(name, k, rawVal, varType) }, ic("pencil", 13), " ویرایش"),
              el("button", { class: "btn danger sm", title: "حذف متغیر", onclick: () => pagesDeleteEnvVar(name, k) }, ic("trash", 13), " حذف")
            )
          )
        );
      });
      envCard.append(
        el("div", { class: "tbl-wrap" }, el("table", null,
          el("thead", null, el("tr", null,
            el("th", null, "نام متغیر (Key)"),
            el("th", null, "نوع (Type)"),
            el("th", null, "مقدار (Value)"),
            el("th", { style: "text-align:left" }, "عملیات")
          )),
          el("tbody", null, envRows)
        ))
      );
    }
    v.append(envCard);

    const kvKeys = Object.keys(kvObj).filter(k => kvObj[k] !== null && kvObj[k] !== undefined);
    if (kvKeys.length) {
      const kvCard = el("div", { class: "card", style: "margin-top:14px" });
      const kvHeader = el("div", { class: "spread", style: "margin-bottom:10px;flex-wrap:wrap;gap:8px" },
        el("div", null,
          el("h4", { style: "display:flex;align-items:center;gap:8px;margin:0" }, ic("box", 17), " مخزن‌های KV"),
          el("div", { class: "small dim", style: "margin-top:4px" }, "فضاهای ذخیره‌سازی کلید-مقدار متصل به پروژه.")
        ),
        el("div", { class: "btn-row" },
          el("button", { class: "btn sm", onclick: () => pagesBindKvModal(name) }, ic("plus", 13), " اتصال KV جدید")
        )
      );
      kvCard.append(kvHeader);
      const kvRows = kvKeys.map(k => {
        const val = kvObj[k];
        const kvId = typeof val === "string" ? val : (val?.namespace_id || val?.id || "—");
        return el("tr", null,
          el("td", { class: "bold mono", style: "color:var(--cyan)" }, `env.${k}`),
          el("td", { class: "mono small" }, kvId),
          el("td", null, el("span", { class: "badge v" }, "مخزن KV")),
          el("td", null,
            el("div", { class: "btn-row", style: "justify-content:flex-end" },
              el("button", { class: "btn danger sm", onclick: () => pagesUnbindBinding(name, k, "KV") }, ic("trash", 13), " حذف بایندینگ")
            )
          )
        );
      });
      kvCard.append(
        el("div", { class: "tbl-wrap" }, el("table", null,
          el("thead", null, el("tr", null,
            el("th", null, "نام در کد (Binding)"),
            el("th", null, "شناسه KV (ID)"),
            el("th", null, "نوع"),
            el("th", { style: "text-align:left" }, "عملیات")
          )),
          el("tbody", null, kvRows)
        ))
      );
      v.append(kvCard);
    }

    const guideCard = el("div", { class: "card", style: "margin-top:14px;background:rgba(56,227,49,0.05);border-color:rgba(56,227,49,0.25)" },
      el("div", { style: "display:flex;align-items:center;gap:8px;font-weight:bold;margin-bottom:6px;color:var(--text)" },
        ic("zap", 16), " استقرار خودکار و بی‌درنگ تغییرات :"
      ),
      el("div", { class: "small dim", style: "line-height:1.7" },
        "در پلتفرم Cloudflare Pages، اعمال هرگونه تغییر بر روی پایگاه‌داده‌های D1، متغیرهای محیطی یا KV نیازمند استقرار مجدد کدهای پروژه است. ",
        "سیستم این فرایند را کاملاً خودکار نموده است: با هر ثبت، ویرایش، تعویض دیتابیس یا حذف، کدهای پروژه بلافاصله روی Cloudflare Pages مجدداً مستقر (Re-deploy) می‌شوند."
      )
    );
    v.append(guideCard);
  }
  async function togglePagesFlag(name, kind, val) {
    try {
      await api(`/api/pages/${encodeURIComponent(name)}/flags?profile=${encodeURIComponent(S.profile)}`, {
        method: "POST",
        body: { [kind]: val }
      });
      toast(val ? `پروژه Pages «${name}» به‌عنوان پنل ${kind} علامت خورد ✓` : `علامت ${kind} پروژه «${name}» برداشته شد`, "ok");
      pagesDetail(name);
    } catch (e) {
      toast(e.message, "err");
    }
  }

  function pagesCreateModal() {
    const nameInp = el("input", { placeholder: "نام پروژه (مانند my-pages-app)", direction: "ltr" });
    const branchInp = el("input", { placeholder: "main", value: "main", direction: "ltr" });

    modal([ic("plus", 18), " ساخت پروژه Pages جدید"], el("div", null,
      el("label", { class: "fld" }, "نام پروژه Pages", nameInp),
      el("label", { class: "fld" }, "شاخه Production (پیش‌فرض: main)", branchInp),
      el("div", { class: "auth-hint" }, "پروژه در حالت Direct Upload ساخته می‌شود و می‌توانید فایل _worker.js را مستقیم روی آن مستقر کنید.")
    ), [
      el("button", {
        class: "btn primary sm", onclick: async (e) => {
          const name = nameInp.value.trim();
          if (!name) { toast("نام پروژه الزامی است", "warn"); return; }
          e.target.disabled = true;
          try {
            await api(`/api/pages?profile=${encodeURIComponent(S.profile)}`, {
              method: "POST",
              body: { name, production_branch: branchInp.value.trim() || "main" }
            });
            toast(`پروژه «${name}» ساخته شد ✓`, "ok");
            closeModal();
            go("pages");
          } catch (ex) { toast(ex.message, "err"); }
          e.target.disabled = false;
        }
      }, "ساخت پروژه")
    ]);
  }

  async function pagesRedeployDirect(name) {
    confirmBox(`آیا مایلید کدهای پروژه Pages «${name}» را جهت اعمال قطعی تمام بایندینگ‌ها و متغیرها مجدداً مستقر (Re-deploy) کنید؟`, async () => {
      try {
        toast("در حال استقرار مجدد (Re-deploy) کدهای پروژه روی شبکه Cloudflare...", "info", 8000);
        const r = await api(`/api/pages/${encodeURIComponent(name)}/redeploy?profile=${encodeURIComponent(S.profile)}`, { method: "POST", body: {} });
        if (r.redeployed) {
          toast(`کدهای پروژه «${name}» با موفقیت مجدداً مستقر شدند ✓`, "ok", 6000);
        } else {
          toast(r.note || r.message || "استقرار مجدد انجام نشد", r.ok === false ? "err" : "warn", 7000);
        }
        pagesDetail(name);
      } catch (e) {
        toast(e.message, "err", 6000);
      }
    });
  }

  function parseSecretList(list) {
    const map = new Map();
    for (const item of list || []) {
      const s = String(item || "").trim();
      if (!s) continue;
      const slash = s.indexOf("/");
      let stage = null, name = s;
      if (slash > 0 && (s.startsWith("production/") || s.startsWith("preview/"))) {
        stage = s.slice(0, slash);
        name = s.slice(slash+1);
      }
      if (!map.has(name)) map.set(name, { name, stages: new Set(), raw: [] });
      const entry = map.get(name);
      if (stage) entry.stages.add(stage);
      entry.raw.push(s);
    }
    return [...map.values()];
  }

  function promptSecretsModal(unknownList, kind, onSubmit) {
    const parsed = parseSecretList(unknownList);
    if (!parsed.length) { onSubmit({}); return; }
    const inputs = {};
    const rows = parsed.map(p => {
      const inp = el("input", { type: "password", placeholder: `مقدار ${p.name}`, direction: "ltr", autocomplete: "off" });
      const show = el("button", { class: "btn ghost xs", type: "button", style: "margin-right:6px" }, "👁");
      show.onclick = () => { inp.type = inp.type === "password" ? "text" : "password"; };
      inputs[p.name] = inp;
      const stageBadge = p.stages.size ? el("span", { class: "badge off", style: "margin-right:6px" }, [...p.stages].join(", ")) : null;
      return el("label", { class: "fld" },
        el("div", { style: "display:flex;align-items:center;gap:6px;flex-wrap:wrap" },
          el("span", { class: "mono", style: "font-weight:700" }, p.name),
          stageBadge,
          p.raw.length > 1 ? el("span", { class: "dim small" }, `(${p.raw.join(", ")})`) : null
        ),
        el("div", { style: "display:flex;align-items:center;gap:4px;margin-top:4px" }, inp, show)
      );
    });
    const hint = el("div", { class: "auth-hint", style: "line-height:2" },
      ic("key", 14), ` برخی متغیرهای محرمانه (Secret) از Cloudflare قابل خواندن نیستند. اگر می‌خواهی آن‌ها را برای ${kind === "pages" ? "پروژه Pages" : "ورکر"} جدید حفظ کنی، مقدارشان را دستی وارد کن. `,
      el("br"),
      "اگر خالی بگذاری، ریبیلد بدون آن Secretها ادامه می‌یابد و ممکن است ورکر جدید خطا بدهد."
    );
    const skipBtn = el("button", { class: "btn ghost sm", onclick: () => { closeModal(); onSubmit(null); } }, "انصراف");
    const submitBtn = el("button", { class: "btn primary sm", onclick: () => {
      const vals = {};
      for (const [k, inp] of Object.entries(inputs)) {
        const v = inp.value.trim();
        if (v) vals[k] = v;
      }
      if (!Object.keys(vals).length) {
        toast("هیچ مقداری وارد نکردی — اگر مطمئنی می‌خواهی بدون Secretها ادامه بدهی، دوباره تلاش کن و تأیید کن", "warn", 4000);
        confirmBox(`هیچ Secret جدیدی وارد نکردی. آیا می‌خواهی ریبیلد را بدون این Secretها (${parsed.map(p=>p.name).join("، ")}) ادامه بدهی؟ این ممکن است باعث خطا در ورکر جدید شود.`, () => { closeModal(); onSubmit({}); }, true);
        return;
      }
      closeModal();
      onSubmit(vals);
    } }, ic("save", 14), " ذخیره و ادامه ریبیلد");
    modal([ic("key", 18), ` ورود دستی Secretها — ${parsed.length} مورد`], el("div", null, hint, ...rows, el("div", { class: "btn-row", style: "margin-top:12px" }, submitBtn, skipBtn)), [], "wide");
  }

  async function pagesRebuildModal(name, type = "nexa") {
    const output = el("div", { class: "log", style: "display:none" });
    let pendingSecrets = {};
    const runRebuild = async (button) => {
      button.disabled = true;
      output.style.display = "block";
      output.replaceChildren(spinner("در حال ریبیلد کامل Pages؛ لطفاً منتظر بمانید..."));
      try {
        const body = { type };
        if (Object.keys(pendingSecrets).length) body.secret_values = pendingSecrets;
        const result = await api(`/api/pages/${encodeURIComponent(name)}/rebuild?profile=${encodeURIComponent(S.profile)}`, {
          method: "POST", body,
        });
        output.replaceChildren(el("div", { class: result.ok ? "ok-line" : "err-line" }, result.message));
        for (const step of result.steps || []) output.append(el("div", { class: "step" }, "· " + step));
        for (const warning of result.warnings || []) output.append(el("div", { class: "small dim" }, warning));
        if (result.snapshot_url) output.append(el("a", { class: "btn sm", href: result.snapshot_url, download: "" }, ic("download", 13), " دانلود بکاپ قبل از حذف"));
        toast(result.ok ? "ریبیلد کامل Pages تمام شد" : result.message, result.ok ? "ok" : "err", 7000);
        if (result.ok) await pagesDetail(name);
      } catch (error) {
        const list = error.details?.unknown_secrets || error.unknown_secrets || error.body?.details?.unknown_secrets;
        if (error.status === 409 && list && list.length) {
          output.replaceChildren(el("div", { class: "err-line" }, error.message));
          output.append(el("div", { class: "small dim", style: "margin-top:8px" }, `Secretهای غیرقابل‌خواندن: ${list.join("، ")}`));
          const askBtn = el("button", { class: "btn primary sm", onclick: () => {
            promptSecretsModal(list, "pages", (vals) => {
              if (vals === null) { output.append(el("div", { class: "small dim" }, "لغو شد.")); return; }
              for (const [k,v] of Object.entries(vals)) pendingSecrets[k] = v;
              if (!pendingSecrets.production) pendingSecrets.production = {};
              if (!pendingSecrets.preview) pendingSecrets.preview = {};
              for (const [k,v] of Object.entries(vals)) {
                pendingSecrets.production[k] = v;
                pendingSecrets.preview[k] = v;
              }
              output.append(el("div", { class: "ok-line" }, `مقادیر ${Object.keys(vals).length} Secret دریافت شد — دوباره تلاش می‌کنیم...`));
              runRebuild(button);
            });
          } }, ic("key", 14), " وارد کردن دستی Secretها و ادامه ریبیلد");
          output.append(el("div", { class: "btn-row", style: "margin-top:8px" }, askBtn));
        } else {
          output.replaceChildren(el("div", { class: "err-line" }, error.message));
        }
      }
      finally { button.disabled = false; }
    };
    const runButton = el("button", { class: "btn danger", onclick: async e => { await runRebuild(e.currentTarget); } }, ic("hammer", 14), " شروع ریبیلد کامل (حذف + ساخت مجدد)");
    modal([ic("hammer", 18), ` ریبیلد کامل Pages — ${name}`], el("div", null,
      el("p", { class: "badge r", style: "white-space:normal;line-height:2" },
        "این عملیات پروژهٔ Pages و تاریخچهٔ استقرار آن را حذف می‌کند؛ سپس با همان نام می‌سازد، کد را دپلوی می‌کند، بایندینگ‌ها/متغیرها/دامنه‌ها را برمی‌گرداند و دوباره کد را دپلوی می‌کند. D1، KV و R2 حذف نمی‌شوند؛ فایل‌های استاتیک و اتصال Git قبلی در این مسیر بازسازی نمی‌شوند."),
      el("p", { class: "small dim" }, "کد به‌صورت خودکار از منبع سراسری (nexa-panel) گرفته می‌شود، نه از پیج مسدودشده. اگر Secret قابل‌خواندن نباشد، عملیات پیش از حذف متوقف می‌شود. بکاپ و وضعیت مرحله‌ها در D1 ذخیره می‌شوند."),
      runButton, output), [], "wide");
  }

  async function workerRebuildModal(name, type = "nexa") {
    const output = el("div", { class: "log", style: "display:none" });
    let pendingSecrets = {};
    const runRebuild = async (button) => {
      button.disabled = true;
      output.style.display = "block";
      output.replaceChildren(spinner("در حال ریبیلد کامل Worker؛ لطفاً منتظر بمانید..."));
      try {
        const body = { type };
        if (Object.keys(pendingSecrets).length) body.secret_values = pendingSecrets;
        const result = await api(`/api/workers/${encodeURIComponent(name)}/rebuild?profile=${encodeURIComponent(S.profile)}`, {
          method: "POST", body,
        });
        output.replaceChildren(el("div", { class: result.ok ? "ok-line" : "err-line" }, result.message || "ریبیلد انجام شد"));
        for (const step of result.steps || []) output.append(el("div", { class: "step" }, "· " + step));
        for (const warning of result.warnings || []) output.append(el("div", { class: "small dim" }, warning));
        toast(result.ok ? "ریبیلد کامل Worker تمام شد" : result.message, result.ok ? "ok" : "err", 7000);
        if (result.ok) await workerDetail(name);
      } catch (error) {
        const list = error.details?.unknown_secrets || error.unknown_secrets || error.body?.details?.unknown_secrets;
        if (error.status === 409 && list && list.length) {
          output.replaceChildren(el("div", { class: "err-line" }, error.message));
          output.append(el("div", { class: "small dim", style: "margin-top:8px" }, `Secretهای غیرقابل‌خواندن: ${list.join("، ")}`));
          const askBtn = el("button", { class: "btn primary sm", onclick: () => {
            promptSecretsModal(list, "worker", (vals) => {
              if (vals === null) { output.append(el("div", { class: "small dim" }, "لغو شد.")); return; }
              for (const [k,v] of Object.entries(vals)) pendingSecrets[k] = v;
              output.append(el("div", { class: "ok-line" }, `مقادیر ${Object.keys(vals).length} Secret دریافت شد — دوباره تلاش می‌کنیم...`));
              runRebuild(button);
            });
          } }, ic("key", 14), " وارد کردن دستی Secretها و ادامه ریبیلد");
          output.append(el("div", { class: "btn-row", style: "margin-top:8px" }, askBtn));
        } else {
          output.replaceChildren(el("div", { class: "err-line" }, error.message));
        }
      } finally { button.disabled = false; }
    };
    const runButton = el("button", { class: "btn danger", onclick: async e => { await runRebuild(e.currentTarget); } }, ic("hammer", 14), " شروع ریبیلد کامل (حذف + ساخت مجدد)");
    modal([ic("hammer", 18), ` ریبیلد کامل Worker — ${name}`], el("div", null,
      el("p", { class: "badge r", style: "white-space:normal;line-height:2" },
        "این عملیات ورکر و بایندینگ‌هایش را حذف و با همان نام دوباره می‌سازد. D1، KV و R2 حذف نمی‌شوند. اگر Secret غیرقابل‌خواندن باشد، عملیات پیش از حذف متوقف می‌شود و می‌توانید مقدارش را دستی وارد کنید."),
      runButton, output), [], "wide");
  }

  async function pagesChangeD1Modal(name, specificEnvName = 'DB') {
    const box = el("div", null, spinner("در حال دریافت مشخصات دیتابیس‌ها و پروژه..."));
    modal([ic("database", 18), ` تغییر دیتابیس D1 پروژه Pages «${name}»`], box, [], "wide");

    try {
      const [pRes, d1Res] = await Promise.all([
        api(`/api/pages/${encodeURIComponent(name)}?profile=${encodeURIComponent(S.profile)}`),
        api(`/api/d1?profile=${encodeURIComponent(S.profile)}`),
      ]);

      const proj = pRes.project || {};
      const configs = (proj.deployment_configs && proj.deployment_configs.production) || {};
      const d1Binds = configs.d1_databases || {};
      const currentBindingKey = specificEnvName || Object.keys(d1Binds)[0] || "DB";
      const currentD1Val = d1Binds[currentBindingKey];
      const currentD1Id = typeof currentD1Val === "string" ? currentD1Val : (currentD1Val?.id || currentD1Val?.database_id || "");

      const databases = d1Res.databases || [];
      const currentDbObj = databases.find(d => d.uuid === currentD1Id || d.id === currentD1Id);
      const currentTitle = currentDbObj ? `${currentDbObj.name} (${currentD1Id})` : (currentD1Id ? currentD1Id : "هیچ دیتابیسی متصل نیست");

      box.innerHTML = "";

      const currentCard = el("div", { class: "result-box", style: "margin-bottom:14px;padding:12px;background:rgba(232,199,122,0.08);border-color:rgba(232,199,122,0.30)" },
        el("div", { style: "font-weight:bold;margin-bottom:4px;display:flex;align-items:center;gap:6px" }, ic("info", 15), " وضعیت فعلی بایندینگ دیتابیس:"),
        el("div", { class: "mono small" }, `نام متغیر در کد: env.${currentBindingKey} → دیتابیس متصل: ${currentTitle}`)
      );

      const modeSel = el("select", null,
        el("option", { value: "existing" }, "انتخاب از میان دیتابیس‌های موجود D1"),
        el("option", { value: "create" }, "ساخت خودکار یک دیتابیس D1 جدید و اتصال آن")
      );

      const dbSelect = el("select");
      databases.forEach(db => {
        const isCur = db.uuid === currentD1Id;
        const opt = el("option", { value: db.uuid }, `${db.name} — ${db.uuid}${isCur ? " (فعلی)" : ""}`);
        if (isCur) opt.selected = true;
        dbSelect.append(opt);
      });

      const newDbInp = el("input", { placeholder: `${name}-new-db`, direction: "ltr" });
      const bindingNameInp = el("input", { value: currentBindingKey, direction: "ltr" });
      const delOldChk = el("input", { type: "checkbox" });

      const existingRow = el("div", { class: "fld" }, "انتخاب دیتابیس جدید", dbSelect);
      const createRow = el("div", { class: "fld", style: "display:none" }, "نام دیتابیس D1 جدید", newDbInp);

      modeSel.onchange = () => {
        existingRow.style.display = modeSel.value === "existing" ? "" : "none";
        createRow.style.display = modeSel.value === "create" ? "" : "none";
      };

      const delOldLabel = el("label", { class: "chk", style: "margin:10px 0;color:var(--text);font-weight:bold" },
        delOldChk,
        " حذف فیزیکی دیتابیس قبلی از کلادفلر پس از جایگزینی (اختیاری)"
      );

      const notice = el("div", { class: "auth-hint", style: "line-height:1.7;margin-top:10px" },
        ic("zap", 13), " توجه: پس از تغییر دیتابیس، کدهای پروژه به صورت کاملاً خودکار مجدداً مستقر (Re-deploy) خواهند شد تا اتصال جدید بلافاصله در محیط زنده فعال شود."
      );

      const submitBtn = el("button", {
        class: "btn primary", onclick: async (e) => {
          const isCreate = modeSel.value === "create";
          let targetId = dbSelect.value;
          let targetName = newDbInp.value.trim();
          if (isCreate && !targetName) {
            toast("نام دیتابیس جدید الزامی است", "warn");
            return;
          }
          if (!isCreate && !targetId) {
            toast("دیتابیسی انتخاب نشده است", "warn");
            return;
          }

          e.target.disabled = true;
          toast("در حال تغییر دیتابیس و استقرار مجدد کدهای پروژه (Re-deploy)...", "info", 10000);

          try {
            const body = {
              env_name: bindingNameInp.value.trim() || "DB",
              delete_old: delOldChk.checked,
            };
            if (isCreate) {
              body.new_database_name = targetName;
            } else {
              body.new_database_id = targetId;
            }

            const r = await api(`/api/pages/${encodeURIComponent(name)}/change-d1?profile=${encodeURIComponent(S.profile)}`, {
              method: "POST",
              body
            });

            toast(r.message || "دیتابیس D1 با موفقیت تغییر یافت و پروژه مجدداً مستقر شد ✓", "ok", 8000);
            closeModal();
            pagesDetail(name);
          } catch (err) {
            toast(err.message, "err", 8000);
          }
          e.target.disabled = false;
        }
      }, ic("refresh", 14), " تغییر دیتابیس و استقرار خودکار");

      box.append(
        currentCard,
        el("div", { class: "grid c2" },
          el("label", { class: "fld" }, "روش انتخاب دیتابیس جدید", modeSel),
          el("label", { class: "fld" }, "نام متغیر در کد (Binding Name)", bindingNameInp)
        ),
        existingRow,
        createRow,
        currentD1Id ? delOldLabel : null,
        notice,
        el("div", { class: "btn-row", style: "margin-top:14px" }, submitBtn)
      );
    } catch (e) {
      box.innerHTML = "";
      box.append(el("div", { class: "empty" }, errLine(e)));
    }
  }

  async function pagesDeployModal(defaultName = "") {
    const nameInp = el("input", { placeholder: "نام پروژه Pages", value: defaultName, direction: "ltr" });
    const scriptSource = el("select", null,
      el("option", { value: "global" }, "اسکریپت سراسری (nexa-panel)"),
      el("option", { value: "manual" }, "کد دستی"));

    const ta = el("textarea", { class: "code", style: "width:100%;min-height:160px;display:none", placeholder: "export default {\n  async fetch(req, env) {\n    return new Response('Hello from Pages Function!');\n  }\n};" });

    scriptSource.onchange = () => {
      ta.style.display = scriptSource.value === "manual" ? "" : "none";
    };

    const statusBox = el("div", { class: "small dim", style: "margin-top:8px" });

    modal([ic("upload", 18), " استقرار کد روی Pages"], el("div", null,
      el("label", { class: "fld" }, "نام پروژه Pages", nameInp),
      el("label", { class: "fld" }, "منبع کد", scriptSource),
      el("div", { class: "fld" }, ta),
      el("div", { class: "auth-hint", style: "margin-top:8px" }, "توجه: استقرار کد سبب اعمال و کامپایل تمام بایندینگ‌های جدید (D1 و KV) روی پروژه Pages خواهد شد."),
      statusBox
    ), [
      el("button", {
        class: "btn primary sm", onclick: async (e) => {
          const name = nameInp.value.trim();
          if (!name) { toast("نام پروژه الزامی است", "warn"); return; }
          e.target.disabled = true;
          statusBox.textContent = "در حال ایجاد دپلویمنت و آپلود کدهای منبع به Cloudflare Pages...";
          try {
            const body = { name };
            if (scriptSource.value === "global") {
              body.script_key = "nexa";
            } else {
              body.script = ta.value;
            }
            await api(`/api/pages/${encodeURIComponent(name)}/deploy?profile=${encodeURIComponent(S.profile)}`, {
              method: "POST",
              body
            });
            toast(`استقرار کد روی Pages «${name}» با موفقیت انجام شد ✓`, "ok");
            closeModal();
            pagesDetail(name);
          } catch (ex) {
            toast(ex.message, "err");
            statusBox.replaceChildren(errLine(ex));
          }
          e.target.disabled = false;
        }
      }, "استقرار کد")
    ], "wide");
  }

  async function pagesUrlModal(name) {
    const box = el("div", null, spinner("در حال دریافت آدرس..."));
    modal([ic("globe", 18), " آدرس پروژه Pages"], box);
    try {
      const d = await api(`/api/pages/${encodeURIComponent(name)}/url?profile=${encodeURIComponent(S.profile)}`);
      box.innerHTML = "";
      box.append(
        el("div", { class: "row", style: "margin-bottom:12px;gap:8px;align-items:center" },
          el("a", { href: d.url, target: "_blank", rel: "noopener", style: "direction:ltr;font-weight:bold;font-size:14px;color:var(--cyan)" }, d.url),
          el("span", { class: "copy-ico", onclick: () => copyText(d.url) }, ic("copy", 14))
        ),
        el("div", { class: "small dim" }, `ساب‌دامین رسمی کلادفلر: `, el("span", { class: "mono" }, d.subdomain)),
        el("div", { class: "btn-row", style: "margin-top:14px" },
          el("a", { href: d.url, target: "_blank", rel: "noopener", class: "btn primary sm" }, ic("link", 13), " باز کردن در تب جدید"),
          el("button", { class: "btn sm", onclick: () => copyText(d.url) }, ic("copy", 13), " کپی آدرس")
        )
      );
    } catch (e) {
      box.innerHTML = "";
      box.append(el("div", { class: "empty" }, errLine(e)));
    }
  }

  async function pagesBindKvModal(name) {
    const box = el("div", null, spinner("در حال بارگذاری لیست KVها..."));
    modal([ic("box", 18), ` اتصال مخزن KV به Pages «${name}»`], box);
    try {
      const d = await api(`/api/kv?profile=${encodeURIComponent(S.profile)}`);
      if (!d.namespaces || !d.namespaces.length) {
        box.innerHTML = "";
        box.append(el("div", { class: "empty" }, "هیچ مخزن KVای یافت نشد. اول در منوی KV یک مخزن KV بسازید."));
        return;
      }
      const sel = el("select", null, d.namespaces.map(k => el("option", { value: k.id }, `${k.title} — ${k.id}`)));
      const envName = el("input", { value: "KV", direction: "ltr" });
      box.innerHTML = "";
      box.append(
        el("label", { class: "fld" }, "انتخاب مخزن KV", sel),
        el("label", { class: "fld" }, "نام متغیر در کد (Binding Name)", envName),
        el("div", { class: "auth-hint", style: "margin-top:6px" }, "توجه مهم: پس از اتصال بایندینگ، باید فایل پروژه یک‌بار دیگر مستقر (Deploy) شود تا بایندینگ در نسخه زنده فعال گردد.")
      );
      box.append(el("div", { class: "btn-row", style: "margin-top:12px" }, el("button", {
        class: "btn primary sm", onclick: async (e) => {
          const vName = envName.value.trim() || "KV";
          e.target.disabled = true;
          try {
            const r = await api(`/api/pages/${encodeURIComponent(name)}/bind-kv?profile=${encodeURIComponent(S.profile)}`, {
              method: "POST",
              body: { kv_id: sel.value, env_name: vName }
            });
            toast(r.message || "KV با موفقیت به Pages متصل شد ✓", "ok");
            closeModal();
            pagesDetail(name);
          } catch (err) {
            toast(err.message, "err");
          }
          e.target.disabled = false;
        }
      }, "اتصال KV")));
    } catch (e) {
      box.innerHTML = "";
      box.append(el("div", { class: "empty" }, errLine(e)));
    }
  }

  async function pagesBindD1Modal(name, defaultEnv = "DB") {
    const box = el("div", null, spinner("در حال بارگذاری لیست دیتابیس‌های D1..."));
    modal([ic("database", 18), ` اتصال پایگاه داده D1 به Pages «${name}»`], box);
    try {
      const d = await api(`/api/d1?profile=${encodeURIComponent(S.profile)}`);
      const databases = d.databases || [];

      const modeSel = el("select", null,
        el("option", { value: "existing" }, "انتخاب از بین دیتابیس‌های موجود D1"),
        el("option", { value: "create" }, "ساخت دیتابیس D1 جدید و اتصال آن")
      );

      const sel = el("select");
      if (databases.length) {
        databases.forEach(k => {
          sel.append(el("option", { value: k.uuid }, `${k.name} — ${k.uuid}`));
        });
      } else {
        sel.append(el("option", { value: "" }, "دیتابیسی در اکانت یافت نشد"));
      }

      const newDbInp = el("input", { placeholder: `${name}-db`, direction: "ltr" });
      const envNameInp = el("input", { value: defaultEnv || "DB", direction: "ltr" });

      const existingRow = el("label", { class: "fld" }, "انتخاب پایگاه داده D1", sel);
      const createRow = el("label", { class: "fld", style: "display:none" }, "نام دیتابیس D1 جدید", newDbInp);

      modeSel.onchange = () => {
        existingRow.style.display = modeSel.value === "existing" ? "" : "none";
        createRow.style.display = modeSel.value === "create" ? "" : "none";
      };

      const notice = el("div", { class: "auth-hint", style: "margin-top:10px;line-height:1.6" },
        ic("zap", 13), " "
      );

      box.innerHTML = "";
      box.append(
        el("label", { class: "fld" }, "نوع عملیات", modeSel),
        existingRow,
        createRow,
        el("label", { class: "fld" }, "نام متغیر در کد (Binding Name)", envNameInp),
        notice,
        el("div", { class: "btn-row", style: "margin-top:14px" },
          el("button", {
            class: "btn primary sm", onclick: async (e) => {
              const vName = envNameInp.value.trim() || "DB";
              const isCreate = modeSel.value === "create";
              const targetId = sel.value;
              const targetName = newDbInp.value.trim();

              if (isCreate && !targetName) {
                toast("نام دیتابیس جدید الزامی است", "warn");
                return;
              }
              if (!isCreate && !targetId) {
                toast("دیتابیسی انتخاب نشده است", "warn");
                return;
              }

              e.target.disabled = true;
              toast("در حال اتصال دیتابیس D1 و استقرار خودکار کدهای پروژه...", "info", 8000);
              try {
                const body = { env_name: vName };
                if (isCreate) body.database_name = targetName;
                else body.database_id = targetId;

                const r = await api(`/api/pages/${encodeURIComponent(name)}/bind-d1?profile=${encodeURIComponent(S.profile)}`, {
                  method: "POST",
                  body
                });
                toast(r.message || "D1 با موفقیت به Pages متصل شد و پروژه Re-deploy گردید ✓", "ok", 8000);
                closeModal();
                pagesDetail(name);
              } catch (err) {
                toast(err.message, "err", 8000);
                e.target.disabled = false;
              }
            }
          }, ic("plus", 14), " اتصال و استقرار خودکار")
        )
      );
    } catch (e) {
      box.innerHTML = "";
      box.append(el("div", { class: "empty" }, errLine(e)));
    }
  }

  async function pagesAddEnvVarModal(name) {
    const keyInp = el("input", { placeholder: "مانند API_TOKEN یا BASE_URL", direction: "ltr" });
    const typeSel = el("select", null,
      el("option", { value: "plain_text" }, "متن عادی (plain_text)"),
      el("option", { value: "secret_text" }, "کلید محرمانه (secret_text)")
    );
    const valInp = el("textarea", { class: "code", style: "width:100%;min-height:90px", placeholder: "مقدار متغیر...", direction: "ltr" });
    const notice = el("div", { class: "auth-hint", style: "margin-top:10px" },
      ic("zap", 13), " "
    );

    const box = el("div", null,
      el("label", { class: "fld" }, "نام متغیر محیطی (Key)", keyInp),
      el("label", { class: "fld" }, "نوع متغیر", typeSel),
      el("label", { class: "fld" }, "مقدار متغیر (Value)", valInp),
      notice,
      el("div", { class: "btn-row", style: "margin-top:14px" },
        el("button", {
          class: "btn primary sm", onclick: async (e) => {
            const k = keyInp.value.trim();
            const v = valInp.value;
            const t = typeSel.value;
            if (!k) { toast("نام متغیر الزامی است", "warn"); return; }
            e.target.disabled = true;
            toast("در حال ثبت متغیر و استقرار خودکار کدهای پروژه...", "info", 8000);
            try {
              const r = await api(`/api/pages/${encodeURIComponent(name)}/env-vars?profile=${encodeURIComponent(S.profile)}`, {
                method: "POST",
                body: { key: k, value: v, type: t }
              });
              toast(r.message || `متغیر «${k}» افزوده شد و پروژه Re-deploy شد ✓`, "ok", 8000);
              closeModal();
              pagesDetail(name);
            } catch (err) {
              toast(err.message, "err", 8000);
              e.target.disabled = false;
            }
          }
        }, ic("plus", 14), " افزودن و استقرار خودکار (Save & Re-deploy)")
      )
    );
    modal([ic("settings", 18), ` افزودن متغیر محیطی به Pages «${name}»`], box);
  }

  async function pagesEditEnvVarModal(name, key, currentValue, currentType = "plain_text") {
    const typeSel = el("select", null,
      el("option", { value: "plain_text" }, "متن عادی (plain_text)"),
      el("option", { value: "secret_text" }, "کلید محرمانه (secret_text)")
    );
    typeSel.value = currentType || "plain_text";

    const valInp = el("textarea", { class: "code", style: "width:100%;min-height:90px", direction: "ltr" });
    if (currentType !== "secret_text") {
      valInp.value = currentValue || "";
    } else {
      valInp.placeholder = "برای حفظ مقدار قبلی خالی بگذارید یا مقدار جدید را وارد کنید";
    }

    const notice = el("div", { class: "auth-hint", style: "margin-top:10px" },
      ic("zap", 13), " "
    );

    const box = el("div", null,
      el("div", { class: "result-box", style: "margin-bottom:12px;padding:8px 12px;font-family:monospace;color:var(--cyan)" }, `متغیر: ${key}`),
      el("label", { class: "fld" }, "نوع متغیر", typeSel),
      el("label", { class: "fld" }, "مقدار جدید (Value)", valInp),
      notice,
      el("div", { class: "btn-row", style: "margin-top:14px" },
        el("button", {
          class: "btn primary sm", onclick: async (e) => {
            const v = valInp.value;
            const t = typeSel.value;
            if (t === "secret_text" && !v) {
              toast("برای متغیر محرمانه باید مقدار را وارد کنید", "warn");
              return;
            }
            e.target.disabled = true;
            toast("در حال ذخیره متغیر و استقرار خودکار کدهای پروژه...", "info", 8000);
            try {
              const r = await api(`/api/pages/${encodeURIComponent(name)}/env-vars?profile=${encodeURIComponent(S.profile)}`, {
                method: "POST",
                body: { key, value: v, type: t }
              });
              toast(r.message || `متغیر «${key}» ویرایش شد و پروژه Re-deploy شد ✓`, "ok", 8000);
              closeModal();
              pagesDetail(name);
            } catch (err) {
              toast(err.message, "err", 8000);
              e.target.disabled = false;
            }
          }
        }, ic("check", 14), " ذخیره تغییرات و استقرار خودکار")
      )
    );
    modal([ic("pencil", 18), ` ویرایش متغیر محیطی «${key}»`], box);
  }

  function pagesDeleteEnvVar(name, key) {
    confirmBox(`آیا از حذف متغیر محیطی «${key}» از پروژه «${name}» اطمینان دارید؟\nپس از حذف، کدهای پروژه به صورت خودکار مجدداً مستقر (Re-deploy) خواهند شد.`, async () => {
      toast(`در حال حذف متغیر «${key}» و استقرار مجدد پروژه...`, "info", 8000);
      try {
        const r = await api(`/api/pages/${encodeURIComponent(name)}/env-vars/${encodeURIComponent(key)}?profile=${encodeURIComponent(S.profile)}`, {
          method: "DELETE"
        });
        toast(r.message || `متغیر «${key}» حذف شد و پروژه Re-deploy شد ✓`, "ok", 8000);
        pagesDetail(name);
      } catch (err) {
        toast(err.message, "err", 8000);
      }
    });
  }

  function pagesUnbindBinding(name, envName, typeLabel) {
    confirmBox(`آیا از قطع اتصال و حذف بایندینگ «${envName}» (${typeLabel}) از پروژه «${name}» اطمینان دارید؟\nپس از حذف بایندینگ، کدهای پروژه مجدداً مستقر (Re-deploy) خواهند شد.`, async () => {
      toast(`در حال حذف بایندینگ «${envName}» و استقرار مجدد پروژه...`, "info", 8000);
      try {
        const r = await api(`/api/pages/${encodeURIComponent(name)}/unbind?profile=${encodeURIComponent(S.profile)}`, {
          method: "POST",
          body: { env_name: envName }
        });
        toast(r.message || `بایندینگ «${envName}» حذف و پروژه Re-deploy شد ✓`, "ok", 8000);
        pagesDetail(name);
      } catch (err) {
        toast(err.message, "err", 8000);
      }
    });
  }
  async function pagesUnbindModal(name) {
    const box = el("div", null, spinner("در حال بارگذاری بایندینگ‌ها..."));
    modal([ic("scissors", 18), ` حذف بایندینگ از Pages «${name}»`], box);
    try {
      const d = await api(`/api/pages/${encodeURIComponent(name)}/bindings?profile=${encodeURIComponent(S.profile)}`);
      if (!d.bindings || !d.bindings.length) {
        box.innerHTML = "";
        box.append(el("div", { class: "empty" }, "این پروژه هیچ بایندینگی ندارد."));
        return;
      }
      const sel = el("select", null, d.bindings.map(b => el("option", { value: b.name }, `env.${b.name} (${b.type})`)));
      box.innerHTML = "";
      box.append(
        el("label", { class: "fld" }, "انتخاب بایندینگ جهت حذف", sel),
        el("div", { class: "small dim", style: "margin-top:6px" }, "حذف بایندینگ دسترسی کد پروژه به این منبع را قطع می‌کند اما خود منبع اصلی پاک نمی‌شود.")
      );
      box.append(el("div", { class: "btn-row", style: "margin-top:12px" }, el("button", {
        class: "btn danger sm", onclick: async (e) => {
          e.target.disabled = true;
          try {
            const r = await api(`/api/pages/${encodeURIComponent(name)}/unbind?profile=${encodeURIComponent(S.profile)}`, {
              method: "POST",
              body: { env_name: sel.value }
            });
            toast(r.message || "بایندینگ با موفقیت حذف شد ✓", "ok");
            closeModal();
            pagesDetail(name);
          } catch (err) {
            toast(err.message, "err");
          }
          e.target.disabled = false;
        }
      }, "حذف بایندینگ")));
    } catch (e) {
      box.innerHTML = "";
      box.append(el("div", { class: "empty" }, errLine(e)));
    }
  }

  async function pagesBindingsModal(name) {
    const box = el("div", null, spinner("در حال بارگذاری بایندینگ‌ها..."));
    modal([ic("search", 18), ` لیست بایندینگ‌های Pages «${name}»`], box, [], "wide");
    try {
      const d = await api(`/api/pages/${encodeURIComponent(name)}/bindings?profile=${encodeURIComponent(S.profile)}`);
      box.innerHTML = "";
      if (!d.bindings || !d.bindings.length) {
        box.append(el("div", { class: "empty" }, "این پروژه Pages هیچ بایندینگی (KV یا D1 یا متغیر) ندارد."));
        return;
      }
      const rows = d.bindings.map(b => el("tr", null,
        el("td", { class: "bold mono" }, `env.${b.name || "?"}`),
        el("td", null, el("span", { class: b.type === "d1" ? "badge ok" : (b.type === "kv_namespace" ? "badge v" : "badge off") }, b.type)),
        el("td", { class: "mono small" }, String(b.database_id || b.namespace_id || b.text || "—"))
      ));
      box.append(
        el("div", { class: "tbl-wrap" }, el("table", null,
          el("thead", null, el("tr", null, el("th", null, "نام در کد"), el("th", null, "نوع منبع"), el("th", null, "شناسه / مقدار"))),
          el("tbody", null, rows)
        )),
        el("div", { class: "auth-hint", style: "margin-top:10px" }, "برای اعمال تغییرات بایندینگ‌ها بر روی نسخه فعال، از دکمه «استقرار کد» در صفحه پروژه استفاده نمایید.")
      );
    } catch (e) {
      box.innerHTML = "";
      box.append(el("div", { class: "empty" }, errLine(e)));
    }
  }

  async function pagesDomainsModal(name) {
    const box = el("div", null, spinner("در حال دریافت دامنه‌ها..."));
    modal([ic("globe", 18), ` دامنه‌های Pages «${name}»`], box, [], "wide");

    const load = async () => {
      try {
        const d = await api(`/api/pages/${encodeURIComponent(name)}/domains?profile=${encodeURIComponent(S.profile)}`);
        box.innerHTML = "";
        const domains = d.domains || [];

        const addInput = el("input", { placeholder: "نام دامنه (مانند sub.example.com)", direction: "ltr", style: "flex:1" });
        const addRow = el("div", { class: "row", style: "gap:8px;margin-bottom:14px" },
          addInput,
          el("button", {
            class: "btn primary sm", onclick: async (e) => {
              const dom = addInput.value.trim();
              if (!dom) return;
              e.target.disabled = true;
              try {
                await api(`/api/pages/${encodeURIComponent(name)}/domains?profile=${encodeURIComponent(S.profile)}`, {
                  method: "POST", body: { domain: dom }
                });
                toast(`دامنه «${dom}» اضافه شد ✓`, "ok");
                load();
              } catch (ex) { toast(ex.message, "err"); }
              e.target.disabled = false;
            }
          }, ic("plus", 14), " افزودن دامنه")
        );

        box.append(addRow);

        if (!domains.length) {
          box.append(el("div", { class: "empty" }, "دامنه اختصاصی ثبت نشده است."));
          return;
        }

        const rows = domains.map(dom => {
          const domName = dom.name || dom;
          const status = dom.status || "—";
          const stBadge = status === "active"
            ? el("span", { class: "badge ok" }, "فعال")
            : status === "pending"
              ? el("span", { class: "badge warn" }, "در انتظار DNS")
              : el("span", { class: "badge off" }, status);

          return el("tr", null,
            el("td", { class: "bold mono" }, domName),
            el("td", null, stBadge),
            el("td", null, el("button", {
              class: "btn danger xs", onclick: () => confirmBox(`دامنه «${domName}» حذف شود؟`, async () => {
                try {
                  await api(`/api/pages/${encodeURIComponent(name)}/domains/${encodeURIComponent(domName)}?profile=${encodeURIComponent(S.profile)}`, { method: "DELETE" });
                  toast(`دامنه «${domName}» حذف شد ✓`, "ok");
                  load();
                } catch (ex) { toast(ex.message, "err"); }
              })
            }, ic("trash", 12), " حذف"))
          );
        });

        box.append(el("div", { class: "tbl-wrap" }, el("table", null,
          el("thead", null, el("tr", null, el("th", null, "نام دامنه"), el("th", null, "وضعیت"), el("th", null, "عملیات"))),
          el("tbody", null, rows))));
      } catch (e) {
        box.innerHTML = "";
        box.append(el("div", { class: "empty" }, errLine(e)));
      }
    };

    load();
  }

  async function pagesDeploymentsModal(name) {
    const box = el("div", null, spinner("در حال دریافت تاریخچه دپلویمنت‌ها..."));
    modal([ic("clock", 18), ` تاریخچه استقرارهای Pages «${name}»`], box, [], "wide");

    const load = async () => {
      try {
        const d = await api(`/api/pages/${encodeURIComponent(name)}/deployments?profile=${encodeURIComponent(S.profile)}`);
        box.innerHTML = "";
        const deps = d.deployments || [];

        if (!deps.length) {
          box.append(el("div", { class: "empty" }, "هنوز هیچ دپلویمنتی برای این پروژه ثبت نشده است."));
          return;
        }

        const rows = deps.map(dep => {
          const id = dep.id;
          const shortId = id || dep.short_id || "—";
          const url = dep.url;
          const envName = dep.environment || "production";
          const status = dep.latest_stage?.status || dep.status || "—";
          const stBadge = status === "SUCCESS"
            ? el("span", { class: "badge ok" }, "موفق")
            : status === "FAILURE"
              ? el("span", { class: "badge danger" }, "ناموفق")
              : status === "ACTIVE"
                ? el("span", { class: "badge ok" }, "فعال")
                : el("span", { class: "badge off" }, status);

          const created = (dep.created_on || "").slice(0, 19).replace("T", " ");

          return el("tr", null,
            el("td", { class: "mono small" }, shortId),
            el("td", null, el("span", { class: "badge off" }, envName)),
            el("td", null, stBadge),
            el("td", { class: "small mono" }, created),
            el("td", null,
              el("div", { class: "btn-row" },
                url ? el("a", { href: url, target: "_blank", rel: "noopener", class: "btn xs", title: "مشاهده پیش‌نمایش" }, ic("link", 12)) : null,
                el("button", {
                  class: "btn primary xs", title: "استقرار مجدد این نسخه (Re-deploy جهت اعمال بایندینگ‌ها)", onclick: async (e) => {
                    e.target.disabled = true;
                    try {
                      await api(`/api/pages/${encodeURIComponent(name)}/deployments/${encodeURIComponent(id)}/retry?profile=${encodeURIComponent(S.profile)}`, { method: "POST" });
                      toast("استقرار مجدد (Re-deploy) در شبکه آغاز شد ✓", "ok");
                      load();
                    } catch (ex) { toast(ex.message, "err"); }
                    e.target.disabled = false;
                  }
                }, ic("refresh", 12), " Re-deploy"),
                el("button", {
                  class: "btn danger xs", title: "حذف این دپلویمنت", onclick: () => confirmBox("این دپلویمنت حذف شود؟", async () => {
                    try {
                      await api(`/api/pages/${encodeURIComponent(name)}/deployments/${encodeURIComponent(id)}?profile=${encodeURIComponent(S.profile)}`, { method: "DELETE" });
                      toast("دپلویمنت حذف شد ✓", "ok");
                      load();
                    } catch (ex) { toast(ex.message, "err"); }
                  })
                }, ic("trash", 12))
              )
            )
          );
        });

        box.append(
          el("div", { class: "spread", style: "margin-bottom:10px" },
            el("span", { class: "small dim" }, `تعداد کل استقرارها: ${deps.length}`),
            el("button", { class: "btn primary sm", onclick: () => pagesDeployModal(name) }, ic("upload", 13), " استقرار فایل جدید")
          ),
          el("div", { class: "tbl-wrap" }, el("table", null,
            el("thead", null, el("tr", null,
              el("th", null, "شناسه"),
              el("th", null, "محیط"),
              el("th", null, "وضعیت"),
              el("th", null, "تاریخ استقرار"),
              el("th", null, "عملیات"))),
            el("tbody", null, rows)))
        );
      } catch (e) {
        box.innerHTML = "";
        box.append(el("div", { class: "empty" }, errLine(e)));
      }
    };

    load();
  }

  async function pagesConfigsModal(name) {
    const box = el("div", null, spinner("در حال دریافت تنظیمات پروژه..."));
    modal([ic("settings", 18), ` متغیرها و بایندینگ‌های Pages «${name}»`], box, [], "wide");

    try {
      const d = await api(`/api/pages/${encodeURIComponent(name)}?profile=${encodeURIComponent(S.profile)}`);
      box.innerHTML = "";
      const p = d.project || {};
      const configs = (p.deployment_configs && p.deployment_configs.production) || {};
      const envVars = configs.env_vars || {};
      const d1Binds = configs.d1_databases || {};
      const kvBinds = configs.kv_namespaces || {};

      const varRows = Object.keys(envVars).map(k => el("tr", null,
        el("td", { class: "bold mono" }, k),
        el("td", null, el("span", { class: "badge off" }, envVars[k].type || "plain_text")),
        el("td", { class: "mono small" }, envVars[k].type === "secret_text" ? "••••••••" : String(envVars[k].value || ""))
      ));

      const d1Rows = Object.keys(d1Binds).map(k => el("tr", null,
        el("td", { class: "bold mono" }, k),
        el("td", null, el("span", { class: "badge v" }, "دیتابیس D1")),
        el("td", { class: "mono small" }, d1Binds[k].id || "")
      ));

      const kvRows = Object.keys(kvBinds).map(k => el("tr", null,
        el("td", { class: "bold mono" }, k),
        el("td", null, el("span", { class: "badge ok" }, "مخزن KV")),
        el("td", { class: "mono small" }, kvBinds[k].namespace_id || "")
      ));

      const varTable = el("div", { class: "tbl-wrap", style: "margin-bottom:14px" }, el("table", null,
        el("thead", null, el("tr", null, el("th", null, "نام متغیر / بایندینگ"), el("th", null, "نوع"), el("th", null, "مقدار / شناسه"))),
        el("tbody", null, [...varRows, ...d1Rows, ...kvRows])));

      const newKey = el("input", { placeholder: "نام متغیر (مانند MY_VAR)", direction: "ltr" });
      const newVal = el("input", { placeholder: "مقدار متغیر", direction: "ltr" });
      const addRow = el("div", { class: "grid c2", style: "margin-top:10px" },
        el("label", { class: "fld" }, "نام متغیر جدید", newKey),
        el("label", { class: "fld" }, "مقدار متغیر", newVal));

      const saveBtn = el("button", {
        class: "btn primary sm", onclick: async (e) => {
          const k = newKey.value.trim();
          const val = newVal.value;
          if (!k) { toast("نام متغیر الزامی است", "warn"); return; }
          e.target.disabled = true;
          try {
            await api(`/api/pages/${encodeURIComponent(name)}/configs?profile=${encodeURIComponent(S.profile)}`, {
              method: "POST",
              body: { configs: { env_vars: { [k]: { type: "plain_text", value: val } } } }
            });
            toast(`متغیر «${k}» ذخیره شد ✓ برای اعمال در محیط زنده کد را Re-deploy کنید.`, "ok");
            pagesConfigsModal(name);
          } catch (ex) { toast(ex.message, "err"); }
          e.target.disabled = false;
        }
      }, "افزودن متغیر");

      box.append(
        el("h4", { style: "margin-bottom:8px" }, "متغیرها و بایندینگ‌های فعال (محیط Production):"),
        (varRows.length || d1Rows.length || kvRows.length) ? varTable : el("div", { class: "empty", style: "margin-bottom:12px" }, "متغیر یا بایندینگی تنظیم نشده است."),
        addRow,
        el("div", { class: "btn-row", style: "margin-top:8px" }, saveBtn),
        el("div", { class: "auth-hint", style: "margin-top:14px" }, "")
      );
    } catch (e) {
      box.innerHTML = "";
      box.append(el("div", { class: "empty" }, errLine(e)));
    }
  }

  function pagesDeleteModal(name) {
    const delRes = el("input", { type: "checkbox", checked: true });
    modal([ic("trash", 18), ` حذف پروژه Pages «${name}»`], el("div", null,
      el("p", { style: "font-size:14px;margin-bottom:8px" }, `آیا مطمئنید می‌خواهید پروژه Pages «${name}» را حذف کنید؟`),
      el("label", { class: "chk", style: "margin-top:10px;font-weight:bold;color:var(--text)" },
        delRes,
        " منابع متصل (دیتابیس D1 و مخزن‌های KV بایندشده) هم حذف شوند"
      ),
      el("div", { class: "small dim", style: "margin-top:6px;line-height:1.6" },
        "با فعال بودن این گزینه، تمام پایگاه‌های داده D1 و مخزن‌های KV متصل به این پروژه به صورت خودکار شناسایی و از حساب Cloudflare حذف خواهند شد."
      )
    ), [
      el("button", {
        class: "btn danger", onclick: () => confirmBox(`آیا از حذف کامل پروژه Pages «${name}»${delRes.checked ? " به همراه تمام بایندینگ‌های متصل" : ""} اطمینان کامل دارید؟`, async () => {
          try {
            toast("در حال حذف پروژه Pages و منابع متصل...", "info", 8000);
            const d = await api(`/api/pages/${encodeURIComponent(name)}?profile=${encodeURIComponent(S.profile)}&resources=${delRes.checked ? 1 : 0}`, { method: "DELETE" });
            let extra = "";
            if (d.d1 && d.d1.length) extra += ` (+${d.d1.length} دیتابیس D1)`;
            if (d.kv && d.kv.length) extra += ` (+${d.kv.length} مخزن KV)`;
            toast(`پروژه Pages «${name}» با موفقیت حذف شد ✓${extra}`, "ok");
            closeModal();
            go("pages");
          } catch (e) {
            toast(e.message, "err");
          }
        })
      }, "حذف کامل پروژه")
    ]);
  }

  let taggedFilter = { q: "", missingOnly: false };

  async function viewTagged(v) {
    v.append(spinner("در حال دریافت ورکرهای برچسب‌دار (همه اکانت‌ها)..."));
    let d;
    try { d = await api("/api/tagged-workers"); }
    catch (e) {
      v.innerHTML = "";
      v.append(el("div", { class: "card" }, el("div", { class: "empty" }, errLine(e))));
      return;
    }
    v.innerHTML = "";
    const items = d.items || [];
    const missing = items.filter(i => i.missing).length;
    const unchecked = items.filter(i => i.exists === null).length;

    const card = el("div", { class: "card" },
      el("h3", null, ic("tag"), " ورکرهای برچسب‌دار (همه اکانت‌ها)"),
      el("div", { class: "row", style: "margin:8px 0;flex-wrap:wrap" },
        el("span", { class: "badge c" }, `${items.length} ورکر برچسب‌دار`),
        " ",
        el("span", { class: "badge v" }, `${items.length - missing - unchecked} موجود`),
        missing ? [" ", el("span", { class: "badge r" }, `${missing} ناموجود (حذف‌شده)`)] : null,
        unchecked ? [" ", el("span", { class: "badge y" }, `${unchecked} بررسی‌نشده`)] : null));

    const q = el("input", { type: "search", placeholder: "جستجو: نام ورکر یا اکانت...", style: "max-width:250px;margin:0" });
    q.value = taggedFilter.q;
    const onlyMissing = el("input", { type: "checkbox" });
    onlyMissing.checked = taggedFilter.missingOnly;
    const refreshBtn = el("button", { class: "btn sm", onclick: () => go("tagged") }, ic("refresh", 13), " به‌روزرسانی");
    const pruneBtn = missing
      ? el("button", { class: "btn danger sm", onclick: pruneTagged }, ic("trash", 13), ` پاک‌سازی ${missing} مورد ناموجود`)
      : null;

    const tbody = el("tbody");
    function renderRows() {
      tbody.innerHTML = "";
      const qv = taggedFilter.q.trim().toLowerCase();
      const rows = items.filter(i =>
        (!qv || i.worker.toLowerCase().includes(qv) || i.profile.toLowerCase().includes(qv)) &&
        (!taggedFilter.missingOnly || i.missing));
      if (!rows.length) {
        tbody.append(el("tr", null, el("td", { colspan: "5" },
          el("div", { class: "empty" }, items.length ? "موردی مطابق فیلتر نیست." : "هیچ ورکری برچسب (nexa) ندارد."))));
        return;
      }
      for (const it of rows) tbody.append(taggedRow(it));
    }
    q.oninput = () => { taggedFilter.q = q.value; renderRows(); };
    onlyMissing.onchange = () => { taggedFilter.missingOnly = onlyMissing.checked; renderRows(); };

    card.append(el("div", { class: "row", style: "margin:10px 0;gap:14px;align-items:center;flex-wrap:wrap" },
      q,
      el("label", { class: "chk", style: "margin:0" }, onlyMissing, el("span", { class: "small" }, "فقط ناموجودها")),
      refreshBtn, pruneBtn));
    card.append(el("div", { class: "tbl-wrap" }, el("table", null,
      el("thead", null, el("tr", null,
        el("th", null, "اکانت"), el("th", null, "نام ورکر"), el("th", null, "برچسب"), el("th", null, "وضعیت"), el("th", null, "عملیات"))),
      tbody)));
    card.append(el("div", { class: "auth-hint" },
      "برچسب‌ها همان علامت‌های nexa هستند که عملیات گروهی و پایش خودکار از آن‌ها استفاده می‌کنند. ",
      "از همین‌جا می‌توانی برچسب هر ورکر را عوض کنی (nexa) یا کاملاً برداری. ",
      "مواردی که «این ورکر وجود ندارد» می‌گیرند یعنی ورکر از کلادفلر حذف شده و فقط رکورد برچسبش مانده — با دکمه قرمز پاکش کن."));
    renderRows();
    v.append(card);
  }

  function taggedRow(it) {
    const acts = el("div", { class: "btn-row", style: "margin:0;flex-wrap:nowrap" });
    acts.append(it.missing
      ? el("button", { class: "btn danger xs", onclick: () => setTagged(it, null) }, ic("trash", 12), " حذف برچسب")
      : el("button", { class: "btn ghost xs", onclick: () => setTagged(it, null) }, ic("x", 12), " برداشتن برچسب"));
    return el("tr", { style: it.missing ? "background:rgba(255,64,64,.07)" : (it.exists === null ? "background:rgba(255,200,60,.05)" : "") },
      el("td", null, it.profile),
      el("td", { class: "mono", style: "direction:ltr;text-align:right" },
        it.worker,
        it.kind === "pages" ? el("span", { class: "badge off", style: "margin-right:6px;font-size:10px" }, "Pages") : null
      ),
      el("td", null, it.nexa ? el("span", { class: "badge n" }, "nexa") : null),
      el("td", null, it.exists === null
        ? el("span", { class: "badge y", title: it.error || "" }, "بررسی ناموفق")
        : it.exists
          ? el("span", { class: "badge c" }, "موجود ✓")
          : el("span", { class: "badge r" }, "⚠ پروژه / ورکر وجود ندارد")),
      el("td", null, acts));
  }

  async function setTagged(it, tag) {
    const run = async () => {
      try {
        await api("/api/tagged-workers/set", { method: "POST", body: { profile: it.profile, worker: it.worker, tag } });
        toast(tag
          ? `برچسب «${it.worker}» به ${tag} تغییر کرد ✓`
          : `برچسب «${it.worker}» از اکانت «${it.profile}» برداشته شد ✓`, "ok");
        go("tagged");
      } catch (e) { toast(e.message, "err"); }
    };
    if (it.missing && !tag) {
      confirmBox(`ورکر «${it.worker}» در اکانت «${it.profile}» وجود ندارد — فقط برچسبش (رکورد D1) حذف می‌شود. ادامه؟`, run);
    } else run();
  }

  function pruneTagged() {
    confirmBox("برچسب همه ورکرهای ناموجود (حذف‌شده از کلادفلر) در همه اکانت‌ها برداشته شود؟", async () => {
      try {
        const r = await api("/api/tagged-workers/prune", { method: "POST", body: {} });
        toast(r.count ? `${r.count} برچسب ناموجود پاک شد ✓` : "چیزی برای پاک‌سازی نبود", r.count ? "ok" : "info");
        go("tagged");
      } catch (e) { toast(e.message, "err"); }
    });
  }

  async function workerCodeModal(name) {
    const box = el("div", null, spinner("در حال دریافت کد..."));
    modal([ic("file", 18), ` کد ورکر: ${name}`], box, [], "xl");
    try {
      const d = await api(`/api/workers/${encodeURIComponent(name)}/code?profile=${encodeURIComponent(S.profile)}`);
      box.innerHTML = "";
      const ta = el("textarea", { class: "code", style: "width:100%;min-height:400px" });
      ta.value = d.code;
      const save = el("button", {
        class: "btn primary sm", onclick: () => confirmBox("کد جدید با حفظ بایندینگ‌ها دیپلوی شود؟", async () => {
          try {
            toast("در حال دیپلوی...", "info", 8000);
            const r = await api(`/api/workers/${encodeURIComponent(name)}/code?profile=${encodeURIComponent(S.profile)}`, { method: "PUT", body: { code: ta.value } });
            toast(r.message || "کد آپدیت شد ✓", "ok");
          } catch (e) { toast(e.message, "err", 6000); }
        })
      }, ic("save", 14), " دیپلوی کد جدید");
      box.append(
        el("div", { class: "spread" },
          el("span", { class: "dim small" }, `${d.code.length.toLocaleString("en")} کاراکتر — برای ویرایش مستقیم تغییرش بده`),
          el("div", { class: "row" },
            el("button", { class: "btn sm", onclick: () => copyText(ta.value) }, ic("copy", 14), " کپی"),
            el("button", { class: "btn sm", onclick: () => { const a = el("a", { href: URL.createObjectURL(new Blob([ta.value], { type: "text/javascript" })), download: `${name}.js` }); a.click(); } }, ic("download", 14), " دانلود"),
            save)),
        ta);
    } catch (e) { box.innerHTML = ""; box.append(el("div", { class: "empty" }, errLine(e))); }
  }

  function quickDeployModal(kind, name) {
    const isPages = kind === "pages";
    const P = encodeURIComponent(S.profile);
    const N = encodeURIComponent(name);
    let fileName = "";

    const ta = el("textarea", {
      class: "qd-code", spellcheck: "false", autocomplete: "off",
      placeholder: isPages
        ? "// کد _worker.js را اینجا پیست کنید (فرمت ES Module)\nexport default {\n  async fetch(request, env) {\n    return new Response(\"Hello from Pages\");\n  }\n};"
        : "// کد ورکر را اینجا پیست کنید\nexport default {\n  async fetch(request, env, ctx) {\n    return new Response(\"Hello from Worker\");\n  }\n};",
    });
    const meta = el("div", { class: "qd-meta" });
    const fileTag = el("span", null);
    const fileInp = el("input", { type: "file", accept: ".js,.mjs,.cjs,.ts,.txt,text/javascript,application/javascript", style: "display:none" });

    const drop = el("div", { class: "qd-drop", onclick: () => fileInp.click() },
      el("div", { class: "qd-ic" }, ic("upload", 20)),
      el("div", { class: "grow" },
        el("div", { class: "t1" }, "فایل کد را اینجا رها کنید یا برای انتخاب کلیک کنید"),
        el("div", { class: "t2" }, "فایل‌های ‎.js / .mjs / .txt — حداکثر ۱۰ مگابایت"),
        fileTag),
      el("button", { class: "btn sm", onclick: (ev) => { ev.stopPropagation(); fileInp.click(); } }, ic("file", 14), " انتخاب فایل"));

    function readFile(f) {
      if (!f) return;
      if (f.size > 10 * 1024 * 1024) return toast("حجم فایل بیشتر از ۱۰ مگابایت است", "warn");
      const r = new FileReader();
      r.onload = () => {
        ta.value = String(r.result || "");
        fileName = f.name;
        fileTag.replaceChildren(el("div", { style: "margin-top:8px" }, el("span", { class: "qd-file" }, ic("check", 12), `${f.name} — ${fmtBytes(f.size)}`)));
        refreshMeta();
        toast(`فایل «${f.name}» بارگذاری شد — حالا «دپلوی» را بزنید`, "ok");
      };
      r.onerror = () => toast("خواندن فایل ناموفق بود", "err");
      r.readAsText(f);
    }
    fileInp.addEventListener("change", () => { readFile(fileInp.files && fileInp.files[0]); fileInp.value = ""; });
    ["dragenter", "dragover"].forEach(t => drop.addEventListener(t, (ev) => { ev.preventDefault(); drop.classList.add("over"); }));
    ["dragleave", "dragend"].forEach(t => drop.addEventListener(t, () => drop.classList.remove("over")));
    drop.addEventListener("drop", (ev) => { ev.preventDefault(); drop.classList.remove("over"); readFile(ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0]); });
    ta.addEventListener("dragover", (ev) => { if (ev.dataTransfer && [...(ev.dataTransfer.types || [])].includes("Files")) ev.preventDefault(); });
    ta.addEventListener("drop", (ev) => { const f = ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0]; if (f) { ev.preventDefault(); readFile(f); } });
    ta.addEventListener("input", () => { if (fileName) { fileName = ""; fileTag.replaceChildren(); } refreshMeta(); });
    ta.addEventListener("keydown", (ev) => {
      if (ev.key === "Tab" && !ev.shiftKey) { ev.preventDefault(); const st = ta.selectionStart, en = ta.selectionEnd; ta.value = ta.value.slice(0, st) + "  " + ta.value.slice(en); ta.selectionStart = ta.selectionEnd = st + 2; refreshMeta(); }
      if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter") { ev.preventDefault(); deploy(); }
    });

    function detect(code) {
      const isModule = /(^|[\s;}])export\s+(default\b|\{|const\b|function\b|class\b|async\b)/m.test(code) || /(^|[\s;}])import\s+[\w{*"'`]/m.test(code);
      const isSW = /addEventListener\s*\(\s*["'`]fetch["'`]/.test(code);
      return { isModule, isSW };
    }
    function refreshMeta() {
      const code = ta.value;
      if (!code.trim()) { meta.replaceChildren(el("span", { class: "qd-kbd" }, "کد را پیست کنید یا فایل انتخاب کنید · Ctrl+Enter برای دپلوی")); return; }
      const lines = code.split("\n").length;
      const d = detect(code);
      const chips = [
        el("span", { class: "qd-chip" }, `${lines.toLocaleString("en-US")} خط`),
        el("span", { class: "qd-chip" }, fmtBytes(new Blob([code]).size)),
      ];
      if (d.isModule) chips.push(el("span", { class: "qd-chip ok" }, ic("check", 11), " ES Module"));
      else if (d.isSW) chips.push(el("span", { class: isPages ? "qd-chip warn" : "qd-chip c" }, isPages ? "Service Worker — Pages فقط ES Module قبول می‌کند" : "Service Worker"));
      else chips.push(el("span", { class: "qd-chip warn" }, "export default یا addEventListener پیدا نشد"));
      meta.replaceChildren(...chips, el("span", { class: "qd-kbd", style: "margin-inline-start:auto" }, "Ctrl+Enter = دپلوی"));
    }

    const loadCurrent = el("button", {
      class: "btn ghost sm", onclick: async () => {
        if (ta.value.trim() && !confirm("کد داخل ادیتور با کد فعلی جایگزین شود؟")) return;
        loadCurrent.disabled = true;
        try {
          const d = await api(isPages ? `/api/pages/${N}/code?profile=${P}` : `/api/workers/${N}/code?profile=${P}`);
          ta.value = d.code || ""; fileName = ""; fileTag.replaceChildren(); refreshMeta();
          toast("کد فعلی بارگذاری شد", "ok");
        } catch (e) { toast(e.message, "err", 6000); }
        loadCurrent.disabled = false;
      }
    }, ic("download", 14), " بارگذاری کد فعلی");
    const clearBtn = el("button", { class: "btn ghost sm", onclick: () => { ta.value = ""; fileName = ""; fileTag.replaceChildren(); refreshMeta(); ta.focus(); } }, ic("x", 14), " پاک کردن");

    const progress = el("div", null);
    const deployBtn = el("button", { class: "btn primary", onclick: () => deploy() }, ic("rocket", 14), " دپلوی همین الان");

    function step(label, state) {
      const icon = state === "run" ? el("span", { class: "spin" }) : state === "done" ? ic("check", 14) : state === "fail" ? ic("alert", 14) : ic("clock", 14);
      return el("div", { class: `qd-step ${state}` }, icon, el("span", null, label));
    }

    let busy = false;
    async function deploy() {
      if (busy) return;
      const code = ta.value;
      if (!code.trim()) { toast("اول کد را پیست کنید یا یک فایل انتخاب کنید", "warn"); ta.focus(); return; }
      const d = detect(code);
      if (isPages && !d.isModule && d.isSW) { toast("Pages فقط کد ES Module (export default) را اجرا می‌کند", "err", 6000); return; }
      busy = true; deployBtn.disabled = true; ta.readOnly = true;
      const steps = el("div", { class: "qd-steps" });
      const s1 = step(`آپلود کد${fileName ? ` (${fileName})` : ""} روی ${isPages ? "Pages" : "Worker"} «${name}»`, "run");
      const s2 = isPages ? step("انتشار دپلوی در Cloudflare", "wait") : null;
      steps.append(s1); if (s2) steps.append(s2);
      progress.replaceChildren(steps);
      let t2 = null;
      if (s2) t2 = setTimeout(() => { s1.replaceWith(step(s1.textContent, "done")); s2.replaceWith(step("در انتظار انتشار در Cloudflare (معمولاً ۱۰ تا ۶۰ ثانیه)...", "run")); }, 2500);
      try {
        const r = isPages
          ? await api(`/api/pages/${N}/deploy?profile=${P}`, { method: "POST", body: { script: code } })
          : await api(`/api/workers/${N}/code?profile=${P}`, { method: "PUT", body: { code } });
        if (t2) clearTimeout(t2);
        const done = [step(`کد آپلود شد (${fmtBytes(new Blob([code]).size)})`, "done")];
        if (isPages) done.push(step(r.state === "success" ? "دپلوی منتشر شد" : "دپلوی ثبت شد؛ انتشار تا چند لحظهٔ دیگر کامل می‌شود", r.state === "success" ? "done" : "run"));
        steps.replaceChildren(...done);
        progress.append(el("div", { class: "qd-result", style: "margin-top:10px" }, ic("check", 16),
          el("span", null, r.message || "دپلوی انجام شد ✓"),
          r.url ? el("a", { href: r.url, target: "_blank", rel: "noopener" }, r.url) : null));
        toast(r.message || "دپلوی انجام شد ✓", "ok", 6000);
      } catch (e) {
        if (t2) clearTimeout(t2);
        steps.replaceChildren(step("دپلوی ناموفق بود", "fail"));
        progress.append(el("div", { style: "margin-top:10px" }, errLine(e)));
        toast(e.message, "err", 8000);
      } finally { busy = false; deployBtn.disabled = false; ta.readOnly = false; }
    }

    const body = el("div", { class: "qd" },
      el("div", { class: "qd-target" },
        ic(isPages ? "layers" : "server", 16),
        el("span", { class: "grow" }, isPages ? "مقصد: پروژهٔ Pages " : "مقصد: ورکر ", el("span", { class: "nm" }, name)),
        el("span", { class: "qd-chip ok" }, "بایندینگ‌ها و تنظیمات حفظ می‌شوند")),
      drop, fileInp,
      el("div", { class: "qd-or" }, "یا کد را مستقیم پیست کنید"),
      el("div", { class: "spread" }, el("span", { class: "small dim" }, isPages ? "کد ⁦_worker.js⁩" : "کد ورکر"), el("div", { class: "row" }, loadCurrent, clearBtn)),
      ta, meta, progress);
    refreshMeta();
    modal([ic("upload", 18), ` آپلود / پیست کد و دپلوی — ${name}`], body, [deployBtn], "xl");
    setTimeout(() => ta.focus(), 50);
  }

  async function workerUrlModal(name) {
    const box = el("div", null, spinner("..."));
    modal([ic("globe", 18), " آدرس ورکر"], box);
    try {
      const d = await api(`/api/workers/${encodeURIComponent(name)}/url?profile=${encodeURIComponent(S.profile)}`);
      box.innerHTML = "";
      box.append(
        el("div", { class: "row", style: "margin-bottom:10px" },
          el("a", { href: d.url, target: "_blank", rel: "noopener", style: "direction:ltr" }, d.url),
          el("span", { class: "copy-ico", onclick: () => copyText(d.url) }, ic("copy", 13))),
        el("div", null, "وضعیت workers.dev: ", d.enabled ? el("span", { class: "badge v" }, "✓ فعال") : el("span", { class: "badge r" }, "✗ غیرفعال")),
        !d.enabled ? el("div", { class: "btn-row" }, el("button", {
          class: "btn ok sm", onclick: async () => {
            try {
              await api(`/api/workers/${encodeURIComponent(name)}/subdomain?profile=${encodeURIComponent(S.profile)}`, { method: "POST", body: { enabled: true } });
              toast("workers.dev فعال شد ✓", "ok"); closeModal();
            } catch (e) { toast(e.message, "err"); }
          }
        }, "فعال‌سازی workers.dev")) : null);
    } catch (e) { box.innerHTML = ""; box.append(el("div", { class: "empty" }, errLine(e))); }
  }

  function workerRenameModal(name) {
    const inp = el("input", { placeholder: "نام جدید", direction: "ltr" });
    modal([ic("pencil", 18), " تغییر نام ورکر"], el("div", null,
      el("div", { class: "badge r" }, "هشدار: ورکر جدیدی با نام جدید ساخته شده و ورکر قدیمی حذف می‌شود."),
      el("label", { class: "fld", style: "margin-top:10px" }, "نام جدید", inp)), [
      el("button", {
        class: "btn primary", onclick: async () => {
          try {
            closeModal();
            toast("در حال تغییر نام...", "info", 10000);
            const d = await api(`/api/workers/${encodeURIComponent(name)}/rename?profile=${encodeURIComponent(S.profile)}`, { method: "POST", body: { new_name: inp.value.trim() } });
            toast(`«${name}» ← «${d.new_name}» ✓`, "ok");
            workerDetail(d.new_name);
          } catch (e) { toast(e.message, "err", 6000); }
        }
      }, "تغییر نام"),
    ]);
  }

  async function workerBindKvModal(name) {
    const box = el("div", null, spinner("..."));
    modal([ic("box", 18), " اتصال مخزن KV"], box);
    try {
      const d = await api(`/api/kv?profile=${encodeURIComponent(S.profile)}`);
      if (!d.namespaces.length) { box.innerHTML = ""; box.append(el("div", { class: "empty" }, "KVای وجود ندارد.")); return; }
      const sel = el("select", null, d.namespaces.map(k => el("option", { value: k.id }, `${k.title} — ${k.id}`)));
      const envName = el("input", { value: "KV", direction: "ltr" });
      box.innerHTML = "";
      box.append(el("label", { class: "fld" }, "مخزن KV", sel), el("label", { class: "fld" }, "نام در env", envName));
      box.append(el("div", { class: "btn-row" }, el("button", {
        class: "btn primary sm", onclick: async () => {
          try {
            const r = await api(`/api/workers/${encodeURIComponent(name)}/bind-kv?profile=${encodeURIComponent(S.profile)}`, { method: "POST", body: { kv_id: sel.value, env_name: envName.value.trim() } });
            toast(r.message, "ok"); closeModal();
          } catch (e) { toast(e.message, "err"); }
        }
      }, "اتصال")));
    } catch (e) { box.innerHTML = ""; box.append(el("div", { class: "empty" }, errLine(e))); }
  }

  async function workerBindD1Modal(name) {
    const box = el("div", null, spinner("..."));
    modal([ic("database", 18), " اتصال دیتابیس D1"], box);
    try {
      const d = await api(`/api/d1?profile=${encodeURIComponent(S.profile)}`);
      if (!d.databases.length) { box.innerHTML = ""; box.append(el("div", { class: "empty" }, "دیتابیسی وجود ندارد.")); return; }
      const sel = el("select", null, d.databases.map(k => el("option", { value: k.uuid }, `${k.name} — ${k.uuid}`)));
      const envName = el("input", { value: "DB", direction: "ltr" });
      box.innerHTML = "";
      box.append(el("label", { class: "fld" }, "دیتابیس", sel), el("label", { class: "fld" }, "نام در env", envName));
      box.append(el("div", { class: "btn-row" }, el("button", {
        class: "btn primary sm", onclick: async () => {
          try {
            const r = await api(`/api/workers/${encodeURIComponent(name)}/bind-d1?profile=${encodeURIComponent(S.profile)}`, { method: "POST", body: { database_id: sel.value, env_name: envName.value.trim() } });
            toast(r.message, "ok"); closeModal();
          } catch (e) { toast(e.message, "err"); }
        }
      }, "اتصال")));
    } catch (e) { box.innerHTML = ""; box.append(el("div", { class: "empty" }, errLine(e))); }
  }

  async function workerUnbindModal(name) {
    const box = el("div", null, spinner("..."));
    modal([ic("scissors", 18), " حذف بایندینگ"], box);
    try {
      const d = await api(`/api/workers/${encodeURIComponent(name)}/bindings?profile=${encodeURIComponent(S.profile)}`);
      if (!d.bindings.length) { box.innerHTML = ""; box.append(el("div", { class: "empty" }, "بایندینگی ندارد.")); return; }
      const sel = el("select", null, d.bindings.map(b => el("option", { value: b.name }, `env.${b.name} (${b.type})`)));
      box.innerHTML = "";
      box.append(el("label", { class: "fld" }, "بایندینگ", sel));
      box.append(el("div", { class: "btn-row" }, el("button", {
        class: "btn danger sm", onclick: async () => {
          try {
            const r = await api(`/api/workers/${encodeURIComponent(name)}/unbind?profile=${encodeURIComponent(S.profile)}`, { method: "POST", body: { env_name: sel.value } });
            toast(r.message, "ok"); closeModal();
          } catch (e) { toast(e.message, "err"); }
        }
      }, "حذف")));
    } catch (e) { box.innerHTML = ""; box.append(el("div", { class: "empty" }, errLine(e))); }
  }

  async function workerBindingsModal(name) {
    const box = el("div", null, spinner("..."));
    modal([ic("search", 18), ` بایندینگ‌های ${name}`], box);
    try {
      const d = await api(`/api/workers/${encodeURIComponent(name)}/bindings?profile=${encodeURIComponent(S.profile)}`);
      box.innerHTML = "";
      if (!d.bindings.length) { box.append(el("div", { class: "empty" }, "بایندینگی ندارد.")); return; }
      const rows = d.bindings.map(b => el("tr", null,
        el("td", null, b.name || "?"),
        el("td", null, b.type),
        el("td", { class: "mono" }, String(b.namespace_id || b.database_id || b.bucket_name || (b.type === "secret_text" ? "(secret)" : b.text) || "—"))));
      const table = el("table", null,
        el("thead", null, el("tr", null, el("th", null, "env"), el("th", null, "نوع"), el("th", null, "مقدار/شناسه"))),
        el("tbody", null, rows));
      box.append(el("div", { class: "tbl-wrap" }, table));
    } catch (e) { box.innerHTML = ""; box.append(el("div", { class: "empty" }, errLine(e))); }
  }

  async function workerDomainsModal(name) {
    const box = el("div", null, spinner("در حال دریافت دامنه‌های اکانت..."));
    modal([ic("globe", 18), ` اتصال دامنه به Worker «${name}»`], box, [], "wide");
    try {
      const d = await api(`/api/worker-domains?profile=${encodeURIComponent(S.profile)}`);
      const host = el("input", { direction: "ltr", placeholder: "example.com یا api.example.com" });
      const zones = d.zones || [];
      const existing = (d.domains || []).filter(x => x.service === name || x.script === name || x.worker === name);
      const zoneHint = zones.length
        ? el("div", { class: "auth-hint", style: "direction:ltr;text-align:left" }, "دامنه‌های این حساب: ", zones.map(z => z.name).join("  •  "))
        : el("div", { class: "auth-hint" }, "دامنه‌ای از این حساب پیدا نشد؛ ابتدا دامنه را به Cloudflare اضافه کنید.");
      const list = el("div", { class: "tbl-wrap", style: "margin-top:12px" });
      const render = () => {
        list.innerHTML = "";
        if (!existing.length) { list.append(el("div", { class: "empty" }, "هنوز دامنه‌ای به این Worker متصل نیست.")); return; }
        list.append(el("div", { class: "small dim", style: "margin-bottom:6px" }, "دامنه‌های متصل به این Worker:"));
        for (const x of existing) {
          const h = x.hostname || x.domain || "—";
          list.append(el("div", { class: "spread", style: "padding:7px 0;border-bottom:1px solid var(--line-soft)" },
            el("span", { class: "mono", direction: "ltr" }, h),
            el("button", { class: "btn danger xs", onclick: async () => {
              try { await api(`/api/workers/${encodeURIComponent(name)}/domains/${encodeURIComponent(h)}?profile=${encodeURIComponent(S.profile)}`, { method: "DELETE" });
                const i = existing.indexOf(x); if (i >= 0) existing.splice(i, 1); render(); toast("اتصال دامنه حذف شد", "ok");
              } catch (e) { toast(e.message, "err"); }
            } }, ic("trash", 12), " قطع اتصال")));
        }
      };
      box.innerHTML = "";
      box.append(zoneHint,
        el("label", { class: "fld", style: "margin-top:10px" }, "دامنه یا ساب‌دامنه", host),
        el("div", { class: "auth-hint" }, "برای دامنه اصلی بنویسید example.com؛ برای ساب‌دامنه بنویسید api.example.com."),
        el("div", { class: "btn-row" }, el("button", { class: "btn primary sm", onclick: async () => {
          const hostname = host.value.trim(); if (!hostname) return toast("دامنه را وارد کنید", "warn");
          try {
            const r = await api(`/api/workers/${encodeURIComponent(name)}/domains?profile=${encodeURIComponent(S.profile)}`, { method: "POST", body: { hostname } });
            existing.push(r.domain || { hostname }); host.value = ""; render(); toast("دامنه با موفقیت به Worker متصل شد ✓", "ok");
          } catch (e) { toast(e.message, "err", 6000); }
        } }, ic("link", 13), " اتصال دامنه")), list);
      render();
    } catch (e) { box.innerHTML = ""; box.append(el("div", { class: "empty" }, errLine(e))); }
  }

  function workerDeleteModal(name) {
    const delRes = el("input", { type: "checkbox" });
    modal([ic("trash", 18), " حذف ورکر"], el("div", null,
      el("p", null, `ورکر «${name}» حذف شود؟`),
      el("label", { class: "chk", style: "margin-top:8px" }, delRes, "منابع متصل (KV / D1 بایندشده) هم حذف شوند")), [
      el("button", {
        class: "btn danger", onclick: () => confirmBox("مطمئنی؟ این عمل قابل بازگشت نیست!", async () => {
          try {
            toast("در حال حذف...", "info", 8000);
            const d = await api(`/api/workers/${encodeURIComponent(name)}?profile=${encodeURIComponent(S.profile)}&resources=${delRes.checked ? 1 : 0}`, { method: "DELETE" });
            toast(`ورکر «${name}» حذف شد ✓${d.kv && d.kv.length ? ` (+${d.kv.length} KV)` : ""}${d.d1 && d.d1.length ? ` (+${d.d1.length} D1)` : ""}`, "ok", 6000);
            closeModal(); go("workers");
          } catch (e) { toast(e.message, "err", 6000); }
        })
      }, "حذف"),
    ]);
  }

  async function viewKv(v) {
    if (!ensureProfile()) return;
    v.append(spinner("در حال دریافت KVها..."));
    try {
      const d = await api(`/api/kv?profile=${encodeURIComponent(S.profile)}`);
      v.innerHTML = "";
      const card = el("div", { class: "card" }, el("h3", null, ic("box"), " مخزن‌های KV"));
      if (!d.namespaces.length) { card.append(el("div", { class: "empty" }, "مخزنی وجود ندارد.")); v.append(card); return; }
      const kvRows = d.namespaces.map(k => el("tr", { onclick: () => kvDetail(k) },
        el("td", null, k.title || "?"), el("td", { class: "mono" }, k.id)));
      const kvTable = el("table", null,
        el("thead", null, el("tr", null, el("th", null, "عنوان"), el("th", null, "ID"))),
        el("tbody", null, kvRows));
      card.append(el("div", { class: "tbl-wrap" }, kvTable));
      v.append(card);
    } catch (e) { v.innerHTML = ""; v.append(el("div", { class: "card" }, el("div", { class: "empty" }, errLine(e)))); }
  }

  async function kvDetail(kv) {
    const v = $("#view");
    v.innerHTML = "";
    v.append(el("span", { class: "back-link", onclick: () => go("kv") }, "→ بازگشت به لیست KV"));
    const card = el("div", { class: "card" },
      el("h3", null, ic("box"), ` ${kv.title}`),
      el("div", { class: "mono small" }, kv.id),
      el("div", { class: "btn-row" },
        el("button", { class: "btn sm", onclick: () => kvRenameModal(kv) }, ic("pencil", 14), " تغییر نام"),
        el("button", { class: "btn ok sm", onclick: () => kvSetValueModal(kv) }, ic("plus", 14), " افزودن / ویرایش کلید"),
        el("button", { class: "btn danger sm", onclick: () => confirmBox(`کل مخزن KV «${kv.title}» و همه‌ی داده‌هایش حذف شود؟`, async () => {
          try {
            await api(`/api/kv/${kv.id}?profile=${encodeURIComponent(S.profile)}`, { method: "DELETE" });
            toast("مخزن KV حذف شد", "ok"); go("kv");
          } catch (e) { toast(e.message, "err"); }
        }) }, ic("trash", 14), " حذف مخزن KV")));
    const list = el("div", { class: "card" }, el("h3", null, ic("key"), " کلیدها"), spinner("..."));
    v.append(card, list);
    let cursor = null;
    const load = async () => {
      try {
        const d = await api(`/api/kv/${kv.id}/keys?profile=${encodeURIComponent(S.profile)}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
        list.innerHTML = "";
        list.append(el("h3", null, ic("key"), " کلیدها"));
        if (!d.keys.length) { list.append(el("div", { class: "empty" }, d.cursor ? "کلید بیشتری نیست." : "کلیدی وجود ندارد.")); return; }
        for (const k of d.keys) {
          list.append(el("div", { class: "kv-item" },
            el("span", { class: "mono", style: "flex:1;min-width:0;overflow-wrap:anywhere" }, k.name),
            k.expiration ? el("span", { class: "badge y" }, `انقضا: ${k.expiration}`) : null,
            el("button", { class: "btn xs", title: "مشاهده", onclick: () => kvGetValueModal(kv, k.name) }, ic("eye", 13)),
            el("button", { class: "btn xs", onclick: () => copyText(k.name) }, ic("copy", 13)),
            el("button", {
              class: "btn danger xs", onclick: () => confirmBox(`کلید «${k.name}» حذف شود؟`, async () => {
                try {
                  await api(`/api/kv/${kv.id}/values/${encodeURIComponent(k.name)}?profile=${encodeURIComponent(S.profile)}`, { method: "DELETE" });
                  toast("کلید حذف شد", "ok"); load();
                } catch (e) { toast(e.message, "err"); }
              })
            }, ic("trash", 13))));
        }
        if (d.cursor) list.append(el("div", { class: "btn-row" }, el("button", { class: "btn sm", onclick: () => { cursor = d.cursor; load(); } }, "صفحه بعد ←")));
      } catch (e) { list.innerHTML = ""; list.append(el("h3", null, ic("key"), " کلیدها"), el("div", { class: "empty" }, errLine(e))); }
    };
    load();
  }

  function kvRenameModal(kv) {
    const inp = el("input", { value: kv.title });
    modal([ic("pencil", 18), " تغییر نام مخزن KV"], el("label", { class: "fld" }, "عنوان جدید", inp), [
      el("button", {
        class: "btn primary sm", onclick: async () => {
          try {
            await api(`/api/kv/${kv.id}?profile=${encodeURIComponent(S.profile)}`, { method: "PUT", body: { title: inp.value.trim() } });
            toast("نام تغییر کرد ✓", "ok"); closeModal(); go("kv");
          } catch (e) { toast(e.message, "err"); }
        }
      }, "ذخیره"),
    ]);
  }

  async function kvGetValueModal(kv, key) {
    const box = el("div", null, spinner("..."));
    modal([ic("key", 18), ` مقدار «${key}»`], box, [], "wide");
    try {
      const txt = await api(`/api/kv/${kv.id}/values/${encodeURIComponent(key)}?profile=${encodeURIComponent(S.profile)}`);
      box.innerHTML = "";
      let pretty = txt;
      try { pretty = JSON.stringify(JSON.parse(txt), null, 2); } catch {}
      box.append(
        el("div", { class: "spread", style: "margin-bottom:8px" },
          el("span", { class: "mono small" }, key),
          el("button", { class: "btn sm", onclick: () => copyText(txt) }, ic("copy", 14), " کپی")),
        el("pre", { class: "out" }, pretty));
    } catch (e) { box.innerHTML = ""; box.append(el("div", { class: "empty" }, errLine(e))); }
  }

  function kvSetValueModal(kv) {
    const key = el("input", { placeholder: "نام کلید", direction: "ltr" });
    const val = el("textarea", { class: "sm", placeholder: "مقدار (چندخطی اشکال ندارد)", style: "width:100%" });
    const ttl = el("input", { placeholder: "خالی = بدون انقضا", direction: "ltr" });
    modal([ic("plus", 18), " افزودن / ویرایش کلید"], el("div", null,
      el("label", { class: "fld" }, "کلید", key),
      el("label", { class: "fld" }, "مقدار", val),
      el("label", { class: "fld" }, "انقضا (ثانیه)", ttl)), [
      el("button", {
        class: "btn primary sm", onclick: async () => {
          try {
            await api(`/api/kv/${kv.id}/values/${encodeURIComponent(key.value.trim())}?profile=${encodeURIComponent(S.profile)}`, {
              method: "PUT", body: { value: val.value, expiration_ttl: ttl.value ? parseInt(ttl.value, 10) : null },
            });
            toast("کلید ذخیره شد ✓", "ok"); closeModal(); kvDetail(kv);
          } catch (e) { toast(e.message, "err"); }
        }
      }, "ذخیره"),
    ]);
  }

  async function viewD1(v) {
    if (!ensureProfile()) return;
    v.append(spinner("در حال دریافت دیتابیس‌ها..."));
    try {
      const d = await api(`/api/d1?profile=${encodeURIComponent(S.profile)}`);
      v.innerHTML = "";
      const card = el("div", { class: "card" },
        el("div", { class: "spread" }, el("h3", null, ic("database"), " دیتابیس‌های D1"),
          el("button", { class: "btn primary sm", onclick: () => d1CreateModal() }, ic("plus", 14), " ساخت D1 جدید")));
      if (!d.databases.length) { card.append(el("div", { class: "empty" }, "دیتابیسی وجود ندارد.")); v.append(card); return; }
      const d1Rows = d.databases.map(db => el("tr", { onclick: () => d1Detail(db) },
        el("td", null, db.name || "?"),
        el("td", { class: "mono" }, (db.uuid || "?")),
        el("td", { class: "mono" }, (db.created_at || "").slice(0, 10))));
      const d1Table = el("table", null,
        el("thead", null, el("tr", null, el("th", null, "نام"), el("th", null, "UUID"), el("th", null, "ساخته‌شده"))),
        el("tbody", null, d1Rows));
      card.append(el("div", { class: "tbl-wrap" }, d1Table));
      card.append(el("div", { class: "auth-hint" }, "توجه: D1 از API تغییر نام (rename) واقعی پشتیبانی نمی‌کند؛ گزینه «تغییر نام» در جزئیات، یک دیتابیس خالی جدید می‌سازد."));
      v.append(card);
    } catch (e) { v.innerHTML = ""; v.append(el("div", { class: "card" }, el("div", { class: "empty" }, errLine(e)))); }
  }

  function d1CreateModal() {
    const inp = el("input", { placeholder: "نام دیتابیس", direction: "ltr" });
    modal([ic("plus", 18), " ساخت D1 جدید"], el("label", { class: "fld" }, "نام", inp), [
      el("button", {
        class: "btn primary sm", onclick: async () => {
          try {
            await api(`/api/d1?profile=${encodeURIComponent(S.profile)}`, { method: "POST", body: { name: inp.value.trim() } });
            toast("دیتابیس ساخته شد ✓", "ok"); closeModal(); go("d1");
          } catch (e) { toast(e.message, "err"); }
        }
      }, "ساخت"),
    ]);
  }

  async function d1Detail(db) {
    const v = $("#view");
    v.innerHTML = "";
    v.append(el("span", { class: "back-link", onclick: () => go("d1") }, "→ بازگشت به لیست D1"));
    const head = el("div", { class: "card" },
      el("h3", null, ic("database"), ` ${db.name}`),
      el("div", { class: "mono small" }, db.uuid),
      el("div", { class: "btn-row" },
        el("button", { class: "btn sm", onclick: () => d1InfoModal(db) }, ic("info", 14), " اطلاعات"),
        el("button", { class: "btn sm", onclick: () => d1TablesModal(db) }, ic("table", 14), " جدول‌ها"),
        el("button", { class: "btn primary sm", onclick: () => d1QueryModal(db) }, ic("terminal", 14), " کنسول SQL"),
        el("button", { class: "btn warn sm", onclick: () => d1CreateModal() }, ic("pencil", 14), " «تغییر نام» (ساخت جدید)"),
        el("button", { class: "btn danger sm", onclick: () => confirmBox(`دیتابیس «${db.name}» و همه داده‌هایش برای همیشه حذف شود؟`, async () => {
          try {
            await api(`/api/d1/${db.uuid}?profile=${encodeURIComponent(S.profile)}`, { method: "DELETE" });
            toast("دیتابیس حذف شد", "ok"); go("d1");
          } catch (e) { toast(e.message, "err"); }
        }) }, ic("trash", 14), " حذف دیتابیس")));
    v.append(head);
  }

  async function d1InfoModal(db) {
    const box = el("div", null, spinner("..."));
    modal([ic("info", 18), " اطلاعات دیتابیس"], box);
    try {
      const d = await api(`/api/d1/${db.uuid}/info?profile=${encodeURIComponent(S.profile)}`);
      box.innerHTML = "";
      const rows = ["name", "uuid", "version", "num_tables", "file_size", "created_at"]
        .filter(k => d.info[k] !== undefined && d.info[k] !== null)
        .map(k => el("tr", null, el("td", null, k), el("td", { class: "mono" }, k === "file_size" ? fmtBytes(Number(d.info[k])) : String(d.info[k]))));
      box.append(el("div", { class: "tbl-wrap" }, el("table", null, el("tbody", null, rows))));
    } catch (e) { box.innerHTML = ""; box.append(el("div", { class: "empty" }, errLine(e))); }
  }

  async function d1TablesModal(db) {
    const box = el("div", null, spinner("..."));
    modal([ic("table", 18), " جدول‌ها"], box);
    try {
      const d = await api(`/api/d1/${db.uuid}/tables?profile=${encodeURIComponent(S.profile)}`);
      box.innerHTML = "";
      if (!d.tables.length) { box.append(el("div", { class: "empty" }, "جدولی نیست (دیتابیس خالی).")); return; }
      for (const t of d.tables) {
        box.append(el("div", { class: "kv-item" },
          el("span", { class: "mono", style: "flex:1" }, t),
          el("button", { class: "btn xs", title: "مشاهده داده‌ها", onclick: () => d1ViewTableModal(db, t) }, ic("eye", 13))));
      }
    } catch (e) { box.innerHTML = ""; box.append(el("div", { class: "empty" }, errLine(e))); }
  }

  function d1QueryModal(db) {
    const ta = el("textarea", { class: "code", style: "width:100%;min-height:140px", placeholder: "SELECT * FROM sqlite_master LIMIT 10;" });
    ta.value = "SELECT name FROM sqlite_master WHERE type='table';";
    const out = el("pre", { class: "out", style: "display:none" });
    modal([ic("terminal", 18), ` کنسول SQL — ${db.name}`], el("div", null, ta, el("div", { class: "btn-row" },
      el("button", {
        class: "btn primary sm", onclick: async () => {
          try {
            const d = await api(`/api/d1/${db.uuid}/query?profile=${encodeURIComponent(S.profile)}`, { method: "POST", body: { sql: ta.value } });
            out.style.display = "block";
            out.textContent = JSON.stringify(d.result, null, 2).slice(0, 20000);
          } catch (e) { toast(e.message, "err", 6000); }
        }
      }, ic("play", 13), " اجرا"), el("span", { class: "dim small" }, "هر عبارت SQL؛ خروجی JSON")), out), [], "wide");
  }

  async function d1ViewTableModal(db, table) {
    const box = el("div", null, spinner("..."));
    modal([ic("table", 18), ` داده‌های جدول «${table}»`], box, [], "wide");
    try {
      const d = await api(`/api/d1/${db.uuid}/query?profile=${encodeURIComponent(S.profile)}`, {
        method: "POST", body: { sql: `SELECT * FROM "${table.replace(/"/g, '""')}" LIMIT 50;` },
      });
      const rows = [];
      for (const r of d.result || []) rows.push(...(r.results || []));
      box.innerHTML = "";
      if (!rows.length) { box.append(el("div", { class: "empty" }, "جدول خالی است.")); return; }
      const cols = Object.keys(rows[0]);
      const thead = el("thead", null, el("tr", null, cols.map(c => el("th", { style: "text-align:left" }, c))));
      const tbody = el("tbody", null, rows.map(r => el("tr", null, cols.map(c => el("td", { style: "text-align:left" }, String(r[c] ?? ""))))));
      box.append(el("div", { class: "tbl-wrap" }, el("table", { style: "direction:ltr" }, thead, tbody)));
      box.append(el("div", { class: "dim small", style: "margin-top:8px" }, `${rows.length} ردیف (حداکثر ۵۰)`));
    } catch (e) { box.innerHTML = ""; box.append(el("div", { class: "empty" }, errLine(e))); }
  }

  const CREATOR_TABS = [["nexa", "پنل Nexa", "zap"]];
  let creatorTab = "nexa";

  async function viewCreators(v) {
    if (!ensureProfile()) return;
    const tabs = el("div", { class: "tabs" }, CREATOR_TABS.map(([k, l, ii]) =>
      el("button", { class: "tab" + (creatorTab === k ? " active" : ""), onclick: () => { creatorTab = k; go("creators"); } }, ic(ii, 14), l)));
    v.append(tabs);
    const form = el("div", { class: "card" });
    v.append(form);
    const out = el("div");
    v.append(out);
    const P = () => encodeURIComponent(S.profile);
    const fld = (label, input) => el("label", { class: "fld" }, label, input);
    const inp = (val, ph) => { const i = el("input", { direction: "ltr", placeholder: ph || "" }); if (val) i.value = val; return i; };

      form.append(el("h3", null, ic("zap"), " سازنده پنل Nexa"),
        el("div", { class: "auth-hint" }, "کد Nexa به‌صورت خودکار از منبع سراسری (nexa-panel) دریافت می‌شود؛ D1 + CF_API_TOKEN."));
      const cron = inp("30 20 * * *");
      const deployType = el("select", null,
        el("option", { value: "worker" }, "Worker (ورکر)"),
        el("option", { value: "pages" }, "Pages (پیجز)"));
      const cronRow = fld("عبارت Cron", cron);
      cronRow.style.display = "none";
      deployType.onchange = () => {
        if (deployType.value === "pages") {
          cronRow.style.opacity = "0.4";
          cronRow.style.pointerEvents = "none";
          cron.title = "Pages از Cron پشتیبانی نمی‌کند";
        } else {
          cronRow.style.opacity = "1";
          cronRow.style.pointerEvents = "";
          cron.title = "";
        }
      };
      form.append(el("div", { class: "auth-hint" }, "نام Worker یا Pages و نام D1 به‌صورت تصادفی ساخته می‌شوند."));
      form.append(el("div", { class: "grid c2" }, fld("محل استقرار", deployType), el("div", { class: "dim small", style: "align-self:end;padding-bottom:4px" }, "Worker: ورکر کلاسیک با Cron — Pages: بدون Cron")));
      form.append(cronRow);
      form.append(el("div", { class: "btn-row" },
        el("button", {
          class: "btn primary", onclick: async (e) => {
            e.target.disabled = true;
            try {
              const isPages = deployType.value === "pages";
              const d = await api(`/api/create/${creatorTab}?profile=${P()}`, { method: "POST", body: { cron: isPages ? undefined : cron.value, deploy_type: deployType.value } });
              showResult(out, `پنل Nexa ${isPages ? "(Pages)" : "(Worker)"} مستقر شد!`, d);
            } catch (ex) { toast(ex.message, "err", 7000); }
            e.target.disabled = false;
          }
        }, ic("rocket", 14), " شروع ساخت")));
  }

  function showResult(out, title, d) {
    out.innerHTML = "";
    const box = el("div", { class: "result-box" });
    box.append(el("div", { style: "font-weight:700;margin-bottom:8px;color:var(--green);display:flex;align-items:center;gap:6px" }, ic("check", 16), ` ${title}`));
    const lines = [];
    if (d.url) lines.push(["آدرس ورکر", d.url, true]);
    if (d.panel_url) lines.push(["آدرس پنل (صفحه ورود)", d.panel_url, true]);
    if (d.kv && d.kv.name) lines.push(["KV", `${d.kv.name} (${d.kv.binding || "kv"}) → ${d.kv.id}`]);
    if (d.d1 && d.d1.name) lines.push(["D1", `${d.d1.name} (${d.d1.binding || "DB"}) → ${d.d1.uuid}`]);
    if (d.cron) lines.push(["Cron", `${d.cron} ${d.cron_set === false ? "(تنظیم نشد!)" : "✓"}`]);
    if (d.deploy_type) lines.push(["نوع استقرار", d.deploy_type === "pages" ? "Cloudflare Pages" : "Cloudflare Worker"]);
    if (d.note) lines.push(["توجه", d.note]);
    if (d.bindings) lines.push(["بایندینگ‌ها", d.bindings.join(" ، ")]);
    if (d.secrets) for (const [k, v] of Object.entries(d.secrets)) if (v) lines.push([k, String(v), k !== "UUID" && k !== "SUB_PATH" ? true : true]);
    for (const [k, val, cp] of lines) {
      box.append(el("div", { class: "row small", style: "margin:3px 0" },
        el("span", { class: "dim", style: "min-width:130px" }, k),
        cp ? el("span", { class: "u" }, String(val)) : el("span", { class: "mono" }, String(val)),
        el("span", { class: "copy-ico", onclick: () => copyText(String(val)) }, ic("copy", 13))));
    }
    if (d.url) box.append(el("div", { class: "btn-row" }, el("a", { class: "btn ok sm", href: d.url, target: "_blank", rel: "noopener" }, "باز کردن ورکر ↗")));
    out.append(box);
    box.scrollIntoView({ behavior: "smooth" });
  }

  let bulkType = "nexa";
  async function viewBulk(v) {
    const tabs = el("div", { class: "tabs" },
      el("button", { class: "tab" + (bulkType === "nexa" ? " active" : ""), onclick: () => { bulkType = "nexa"; go("bulk"); } }, ic("zap", 14), " پنل Nexas"));
    v.append(tabs);
    const card = el("div", { class: "card" }, spinner("در حال دریافت تارگت‌ها..."));
    const log = el("div", { class: "log", style: "display:none" });
    v.append(card, log);
    try {
      const d = await api(`/api/bulk/targets?type=${bulkType}`);
      card.innerHTML = "";
      card.append(el("h3", null, ic("refresh"), ` عملیات گروهی Nexa (همه اکانت‌ها)`));
      if (!d.targets.length) {
        card.append(el("div", { class: "empty" }, `هیچ ورکر یا پروژهٔ Pages به‌عنوان پنل ${bulkType} علامت نخورده است.`,
          el("div", { class: "small dim", style: "margin-top:6px" }, "از بخش Workers یا Pages، هدف موردنظر را برچسب‌گذاری کنید.")));
        return;
      }
      const targetRow = t => {
        const cb = el("input", { type: "checkbox", checked: "checked", "data-p": t.profile, "data-w": t.worker, "data-kind": t.kind || "worker" });
        return el("label", { class: "chk bk-row" },
          cb,
          el("span", { class: "bk-name" }, t.worker),
          el("span", { class: "bk-acc" }, `@ ${t.profile}`),
          el("span", { class: "bk-st" },
            t.recoverable ? el("span", { class: "badge y" }, "نیاز به تکمیل ریبیلد") : (t.exists ? el("span", { class: "badge v" }, "موجود") : el("span", { class: "badge r" }, "پیدا نشد"))));
      };
      const bkGroup = (kind, title, icon) => {
        const items = d.targets.filter(t => (t.kind || "worker") === kind);
        if (!items.length) return null;
        const head = el("div", { class: "bk-head" }, ic(icon, 15), ` ${title}`, el("span", { class: "badge n" }, String(items.length)),
          el("button", {
            class: "btn ghost xs", type: "button", onclick: () => {
              const boxes = grp.querySelectorAll("input[type=checkbox]");
              const all = [...boxes].every(b => b.checked);
              boxes.forEach(b => { b.checked = !all; });
            }
          }, "انتخاب/لغو این گروه"));
        const grp = el("div", { class: "bk-group" }, head, el("div", { class: "bk-list" }, items.map(targetRow)));
        return grp;
      };
      const checks = [bkGroup("worker", "ورکرها", "server"), bkGroup("pages", "پروژه‌های Pages", "layers")].filter(Boolean);
      card.append(el("hr", { class: "divider" }));
      card.append(el("div", { class: "spread" },
        el("span", { class: "dim small" }, `${d.targets.length} هدف برچسب‌دار: ${d.targets.filter(t => (t.kind || "worker") === "worker").length} ورکر و ${d.targets.filter(t => t.kind === "pages").length} پروژهٔ Pages`),
        el("button", {
          class: "btn ghost sm", onclick: () => {
            const boxes = card.querySelectorAll("input[type=checkbox]");
            const all = [...boxes].every(b => b.checked);
            boxes.forEach(b => { b.checked = !all; });
          }
        }, "انتخاب/لغو همه")));
      card.append(...checks);
      const run = async (endpoint, btn) => {
        const targets = [...card.querySelectorAll("input[type=checkbox]:checked")]
          .map(b => ({ profile: b.dataset.p, worker: b.dataset.w, kind: b.dataset.kind }));
        if (!targets.length) return toast("چیزی انتخاب نشده", "warn");
        const actions = [...card.querySelectorAll(".btn-row .btn.ok, .btn-row .btn.danger")];
        const disabledBefore = actions.map(button => button.disabled);
        actions.forEach(button => button.disabled = true);
        log.style.display = "block";
        log.replaceChildren();
        const progress = el("div", { class: "dim" });
        log.append(progress);
        let ok = 0, fail = 0;
        const pendingSecretsByTarget = {};
        const getTargetKey = (t) => `${t.profile}||${t.worker}||${t.kind}`;
        try {
          for (let index = 0; index < targets.length; index++) {
            const target = targets[index];
            progress.textContent = `در حال ${endpoint === "rebuild" ? "ریبیلد" : "آپدیت"} ${index + 1} از ${targets.length}: [${target.kind === "pages" ? "Pages" : "Worker"}] ${target.worker} @ ${target.profile}`;
            let results;
            let attempt = 0;
            while (true) {
              attempt++;
              try {
                const tKey = getTargetKey(target);
                const extraSecrets = pendingSecretsByTarget[tKey] || {};
                const body = { type: bulkType, targets: [target] };
                if (Object.keys(extraSecrets).length) {
                  body.secret_values = extraSecrets;
                  body.secret_values.production = { ...extraSecrets };
                  body.secret_values.preview = { ...extraSecrets };
                  for (const [k,v] of Object.entries(extraSecrets)) body.secret_values[k]=v;
                }
                const response = await api(`/api/bulk/${endpoint}`, { method: "POST", body });
                results = response.results || [];
                if (!results.length) throw new Error("پاسخ عملیات شامل نتیجهٔ این هدف نبود");
                break;
              } catch (error) {
                const list = error.details?.unknown_secrets || error.unknown_secrets || error.body?.details?.unknown_secrets;
                if (endpoint === "rebuild" && error.status === 409 && list && list.length && attempt === 1) {
                  log.append(el("div", { class: "err-line" }, `✗ [${target.profile}] ${target.worker} — Secretهای غیرقابل‌خواندن: ${list.join("، ")}`));
                  const secretsForThisTarget = await new Promise(resolve => {
                    const parsed = parseSecretList(list);
                    const inputs = {};
                    const rows = parsed.map(p => {
                      const inp = el("input", { type: "password", placeholder: `مقدار ${p.name} برای ${target.worker}`, direction: "ltr" });
                      inputs[p.name]=inp;
                      return el("label", { class: "fld" }, el("span", { class: "mono", style: "font-weight:700" }, `${p.name} (${target.worker} @ ${target.profile})`), inp);
                    });
                    const submitBtn = el("button", { class: "btn primary sm", onclick: () => {
                      const vals={};
                      for (const [k,inp] of Object.entries(inputs)) { const v=inp.value.trim(); if(v) vals[k]=v; }
                      closeModal();
                      resolve(vals);
                    } }, " ذخیره و ادامه");
                    const skipBtn = el("button", { class: "btn ghost sm", onclick: () => { closeModal(); resolve(null); } }, " رد کردن این هدف");
                    modal([ic("key", 18), ` Secret برای ${target.worker} @ ${target.profile}`], el("div", null,
                      el("div", { class: "auth-hint" }, `برای ${target.kind === "pages" ? "پروژه Pages" : "ورکر"} «${target.worker}» در اکانت «${target.profile}» این Secretها قابل بازیابی نیستند: ${list.join("، ")}. مقدارشان را وارد کن تا ریبیلد ادامه یابد.`),
                      ...rows,
                      el("div", { class: "btn-row", style: "margin-top:10px" }, submitBtn, skipBtn)
                    ), [], "wide");
                  });
                  if (secretsForThisTarget && Object.keys(secretsForThisTarget).length) {
                    const tKey = getTargetKey(target);
                    pendingSecretsByTarget[tKey] = { ...(pendingSecretsByTarget[tKey]||{}), ...secretsForThisTarget };
                    log.append(el("div", { class: "ok-line" }, `✓ Secretها برای ${target.worker} دریافت شد — دوباره تلاش می‌کنیم...`));
                    continue;
                  } else {
                    results = [{ ...target, ok: false, message: error.message + " (رد شد توسط کاربر)", steps: [] }];
                    break;
                  }
                } else {
                  results = [{ ...target, ok: false, message: error.message, steps: [], details: error.details }];
                  break;
                }
              }
            }
            for (const result of results) {
              result.ok ? ok++ : fail++;
              log.append(el("div", { class: result.ok ? "ok-line" : "err-line" }, `${result.ok ? "✓" : "✗"} [${result.profile}] ${result.worker} [${(result.kind || target.kind) === "pages" ? "Pages" : "Worker"}] — ${result.message}`));
              for (const step of result.steps || []) log.append(el("div", { class: "step" }, "· " + step));
              for (const warning of result.warnings || []) log.append(el("div", { class: "small dim" }, warning));
              if (result.snapshot_url) log.append(el("a", { class: "btn sm", href: result.snapshot_url, download: "" }, ic("download", 13), " بکاپ قبل از حذف Pages"));
            }
          }
          progress.remove();
          log.append(el("div", { style: "margin-top:8px;font-weight:700" }, `نتیجه: ✓ ${ok} موفق — ✗ ${fail} ناموفق`));
        } finally {
          actions.forEach((button, index) => button.disabled = disabledBefore[index]);
        }
      };
      card.append(el("div", { class: "btn-row" },
        el("button", { class: "btn ok", onclick: (e) => run("update", e.currentTarget) }, ic("upload", 14), " آپدیت کد (بایندینگ‌ها حفظ می‌شوند)"),
        el("button", {
          class: "btn danger", onclick: (e) => {
            const button = e.currentTarget;
            confirmBox("ریبیلد کامل = حذف پروژهٔ Pages/ورکر و تاریخچهٔ دپلوی آن و ساخت مجدد با همان نام. برای Pages: بکاپ نام/بایندینگ‌ها/متغیرها/دامنه‌ها، حذف پروژه، ساخت، دپلوی اول، بازگردانی تنظیمات و دامنه‌ها، دپلوی دوم. منابع D1/KV/R2 حذف نمی‌شوند. ادامه؟", () => run("rebuild", button));
          }
        }, ic("hammer", 14), " ریبیلد کامل (حذف + استقرار مجدد)")));
      card.append(el("div", { class: "auth-hint" }, "ریبیلد کامل Pages حتی اگر پیج مسدود باشد، کد را از منبع سراسری (nexa-panel) می‌گیرد: بکاپ → حذف فقط پروژه → ساخت با همان نام → دپلوی اولیه → اتصال بایندینگ‌ها، متغیرها و دامنه‌ها → دپلوی نهایی. منابع D1/KV/R2 حذف نمی‌شوند و Secret غیرقابل‌خواندن پیش از حذف بررسی می‌شود."));
    } catch (e) { card.innerHTML = ""; card.append(el("div", { class: "empty" }, errLine(e))); }
  }

  function faTime(iso) {
    if (!iso) return "-";
    const d = new Date(String(iso).includes("T") ? iso : iso + "Z");
    if (isNaN(d)) return String(iso);
    return d.toLocaleString("fa-IR");
  }
  function timeAgo(iso) {
    if (!iso) return "-";
    const d = new Date(String(iso).includes("T") ? iso : iso + "Z");
    if (isNaN(d)) return String(iso);
    const s = Math.floor((Date.now() - d.getTime()) / 1000);
    if (s < 0) return faTime(iso);
    if (s < 60) return "همین حالا";
    if (s < 3600) return Math.floor(s / 60) + " دقیقه پیش";
    if (s < 86400) return Math.floor(s / 3600) + " ساعت پیش";
    return Math.floor(s / 86400) + " روز پیش";
  }
  const HEALTH_STATUS = {
    ok: { label: "سالم", cls: "v" },
    error_1101: { label: "خطای 1101", cls: "r" },
    rebuilt_ok: { label: "ریبیلد خودکار شد", cls: "c" },
    rebuild_failed: { label: "ریبیلد ناموفق", cls: "r" },
    unreachable: { label: "در دسترس نیست", cls: "y" },
    other_error: { label: "خطای دیگر", cls: "y" },
    skipped: { label: "رد شد", cls: "off" },
  };

  async function viewHealth(v) {
    const sum = el("div", { class: "card" }, spinner("در حال دریافت وضعیت پایش..."));
    v.append(sum);
    const load = async () => {
      try {
        const [s, h, tn, cfg] = await Promise.all([
          api("/api/health/summary"),
          api("/api/health/history"),
          api("/api/bulk/targets?type=nexa"),
          api("/api/health/config"),
        ]);
        sum.innerHTML = "";
        sum.append(el("h3", null, ic("pulse"), " پایش خودکار پنل‌ها"));
        const counts = {};
        for (const c of s.counts || []) counts[c.status] = c.n;
        const lastErr = (h.history || []).find(r => r.status === "error_1101" || r.status === "rebuild_failed");
        const lastFix = (h.history || []).find(r => r.fixed_at);

        const cb = el("input", { type: "checkbox" });
        cb.checked = s.auto_rebuild;
        cb.onchange = async () => {
          try {
            await api("/api/health/toggle", { method: "POST", body: { enabled: cb.checked } });
            toast(cb.checked ? "ریبیلد خودکار فعال شد" : "ریبیلد خودکار خاموش شد (فقط ثبت در تاریخچه)", "ok");
          } catch (e) { toast(e.message, "err"); cb.checked = !cb.checked; }
        };
        const runBtn = el("button", {
          class: "btn primary sm", onclick: async (e) => {
            e.target.disabled = true;
            const old = e.target.textContent; e.target.textContent = "در حال بررسی...";
            try {
              const r = await api("/api/health/run", { method: "POST" });
              const bad = r.results.filter(x => x.status !== "ok" && x.status !== "rebuilt_ok").length;
              const fixed = r.results.filter(x => x.status === "rebuilt_ok").length;
              toast(`بررسی تمام شد — ${r.results.length} پنل، ${fixed} ریبیلد، ${bad} مشکل`, fixed || bad ? (bad ? "warn" : "ok") : "ok", 6000);
              load();
            } catch (ex) { toast(ex.message, "err", 6000); }
            e.target.disabled = false; e.target.textContent = old;
          }
        }, ic("play", 13), " بررسی فوری همه پنل‌ها");

        sum.append(el("div", { class: "grid c3", style: "margin:12px 0" },
          el("div", { class: "stat" },
            el("div", { class: "lbl" }, "آخرین بررسی"),
            el("div", { class: "num", style: "font-size:17px" }, timeAgo(s.last_check)),
            el("div", { class: "dim small" }, faTime(s.last_check))),
          el("div", { class: "stat" },
            el("div", { class: "lbl" }, "پنل‌های تحت نظر"),
            el("div", { class: "num", style: "font-size:17px" }, String(s.targets?.nexa || 0)),
            el("div", { class: "dim small" }, `${s.targets?.nexa || 0} پنل`)),
          el("div", { class: "stat" },
            el("div", { class: "lbl" }, "وضعیت"),
            el("div", { style: "margin:6px 0" },
              el("label", { class: "switch" }, cb, el("span", { class: "track" })),
              el("div", { class: "small dim", style: "margin-top:6px" }, s.auto_rebuild ? "ریبیلد خودکار: روشن" : "ریبیلد خودکار: خاموش")),
            el("div", { class: "dim small" }, runBtn))));

        if (lastFix || lastErr) {
          sum.append(el("div", { class: "small", style: "line-height:2.1" },
            lastErr ? el("div", null,
              el("span", { class: "badge r" }, "آخرین خطا"),
              ` «${lastErr.worker}» @ ${lastErr.profile} — ${faTime(lastErr.checked_at)}`) : null,
            lastFix ? el("div", null,
              el("span", { class: "badge c" }, "آخرین رفع"),
              ` «${lastFix.worker}» — ریبیلد در ${faTime(lastFix.fixed_at)}`) : null));
        }
        sum.append(el("div", { class: "auth-hint" },
          "زمان‌بندی خودکار: طبق کرون‌ترگر ورکر (مثلاً هر ۱۵ دقیقه). اگر پنلی خطای 1101 بدهد، همان‌جا با کد nexa ریبیلد می‌شود: همان نام، همه بایندینگ‌ها و کرون قبلی برمی‌گردند و متغیرها plain_text ساخته می‌شوند."));

        const cfgMap = {};
        for (const c of (cfg.configs || [])) cfgMap[c.profile + "||" + c.worker] = c.path;
        const lastBy = {};
        for (const r of (h.history || [])) {
          const k = r.profile + "||" + r.worker;
          if (!(k in lastBy)) lastBy[k] = r;
        }
        const allTargets = [
          ...(tn.targets || []).map(t => ({ ...t, type: "nexa" })),
        ];
        const tCard = el("div", { class: "card", id: "health-targets" },
          el("h3", null, ic("crosshair"), " پنل‌های تحت نظر و مسیر بررسی"));
        if (!allTargets.length) {
          tCard.append(el("div", { class: "empty" }, "هیچ ورکری علامت‌گذاری نشده است (nexa)."));
        } else {
          for (const t of allTargets) {
            const path = cfgMap[t.profile + "||" + t.worker] || "/";
            const last = lastBy[t.profile + "||" + t.worker];
            const st = last ? (HEALTH_STATUS[last.status] || { label: last.status, cls: "off" }) : null;
            tCard.append(el("div", { class: "kv-item" },
              el("div", { style: "flex:1;min-width:0" },
                el("div", { class: "mono", style: "overflow-wrap:anywhere" }, t.worker),
                t.url
                  ? el("a", { href: t.url, target: "_blank", rel: "noopener", class: "mono dim",
                      style: "font-size:11px;direction:ltr;display:inline-block;max-width:100%;overflow-wrap:anywhere;vertical-align:middle" },
                    t.url.replace(/^https?:\/\//, ""))
                  : el("span", { class: "dim small" }, "(آدرس هنوز ثبت نشده)"),
                el("span", { class: "dim small", style: "display:block" }, `@ ${t.profile}`)),
              el("span", { class: "badge " + "v" }, t.type),
              path === "/"
                ? el("span", { class: "dim small" }, "پیش‌فرض: /admin + /")
                : el("span", { class: "mono small", style: "color:var(--cyan)" }, path),
              st ? el("span", { class: "badge " + st.cls }, st.label) : el("span", { class: "badge off" }, "بدون بررسی"),
              el("button", {
                class: "btn xs", title: "تنظیم مسیر بررسی", onclick: () => {
                  const inp = el("input", { value: path, direction: "ltr", placeholder: "مثلاً /panel یا /UUID-پنل" });
                  modal([ic("crosshair", 18), ` مسیر بررسی «${t.worker}»`], el("div", null,
                    el("div", { class: "auth-hint", style: "text-align:right;line-height:2" },
                      "مسیر اختصاصی بررسی این پنل.", el("br"), "پیش‌فرض (خالی بگذاری): اول ", el("code", null, "/admin"), " و بعد ", el("code", null, "/"), " بررسی می‌شود."),
                    el("label", { class: "fld", style: "margin-top:10px" }, "مسیر", inp),
                    el("div", { class: "btn-row" },
                      el("button", {
                        class: "btn primary sm", onclick: async () => {
                          try {
                            await api("/api/health/config", { method: "POST", body: { profile: t.profile, worker: t.worker, path: inp.value || "/" } });
                            closeModal();
                            toast("مسیر بررسی ذخیره شد ✓", "ok");
                            load();
                          } catch (e) { toast(e.message, "err"); }
                        }
                      }, ic("save", 13), " ذخیره"))));
                }
              }, ic("pencil", 12))));
          }
        }
        tCard.append(el("div", { class: "auth-hint" },
          "به‌صورت پیش‌فرض هر پنل اول روی ", el("code", null, "/admin"), " (مسیر اصلی پنل‌های nexa) و سپس ", el("code", null, "/"), " بررسی می‌شود. اگر پنلی مسیر متفاوتی دارد، با دکمه‌ی مداد همان مسیر را ثبت کن."));

        const card2 = el("div", { class: "card" }, el("h3", null, ic("clock"), " تاریخچه بررسی‌ها"));
        const rows = (h.history || []).map(r => {
          const st = HEALTH_STATUS[r.status] || { label: r.status, cls: "off" };
          return el("tr", null,
            el("td", { class: "small" }, faTime(r.checked_at), el("div", { class: "dim" }, timeAgo(r.checked_at))),
            el("td", null, el("span", { class: "badge " + "v" }, r.type)),
            el("td", { class: "mono small" }, r.worker, el("div", { class: "dim" }, r.profile)),
            el("td", null, el("span", { class: "badge " + st.cls }, st.label), " ",
              r.http_status ? el("span", { class: "dim small" }, `HTTP ${r.http_status}`) : null),
            el("td", { class: "small" }, r.status === "rebuilt_ok" && r.fixed_at ? `درست شد: ${faTime(r.fixed_at)}` : (r.message || "—")));
        });
        card2.append(rows.length
          ? el("div", { class: "tbl-wrap" }, el("table", null,
              el("thead", null, el("tr", null, el("th", null, "زمان بررسی"), el("th", null, "نوع"), el("th", null, "ورکر"), el("th", null, "وضعیت"), el("th", null, "توضیح / زمان رفع"))),
              el("tbody", null, rows)))
          : el("div", { class: "empty" }, "هنوز بررسی‌ای ثبت نشده. دکمه «بررسی فوری» را بزن یا منتظر Cron بمان."));
        const oldT2 = v.querySelector("#health-targets");
        if (oldT2) oldT2.remove();
        v.append(tCard);
        const oldCard = v.querySelector("#health-history");
        if (oldCard) oldCard.remove();
        card2.id = "health-history";
        v.append(card2);
      } catch (e) {
        sum.innerHTML = "";
        sum.append(el("h3", null, ic("pulse"), " پایش خودکار پنل‌ها"),
          el("div", { class: "empty" }, errLine(e)));
      }
    };
    load();
  }

  async function backupModal() {
    const box = el("div", null, spinner("در حال ساخت بکاپ..."));
    modal([ic("save", 18), " بکاپ کامل"], box, [], "wide");
    try {
      const d = await api("/api/backup");
      const txt = JSON.stringify(d, null, 2);
      box.innerHTML = "";
      box.append(
        el("div", { class: "spread", style: "margin-bottom:10px" },
          el("span", { class: "small dim" }, `${d.profiles.length} پروفایل — ${Object.keys(d.settings).length} تنظیم`),
          el("div", { class: "row" },
            el("button", { class: "btn sm", onclick: () => copyText(txt) }, ic("copy", 13), " کپی JSON"),
            el("a", { class: "btn ok sm", href: "/api/backup?download=1", download: "" }, ic("download", 13), " دانلود فایل"))),
        el("pre", { class: "out", style: "max-height:360px" }, txt.length > 8000 ? txt.slice(0, 8000) + "\n… (ادامه در فایل دانلودی)" : txt));
    } catch (e) {
      box.innerHTML = "";
      box.append(el("div", { class: "empty" }, errLine(e)));
    }
  }

  function restoreModal() {
    const ta = el("textarea", { class: "code", style: "width:100%;min-height:170px", placeholder: "محتوای فایل بکاپ (JSON) را اینجا بچسبانید..." });
    const file = el("input", { type: "file", accept: ".json,application/json" });
    file.addEventListener("change", () => {
      const f = file.files && file.files[0];
      if (!f) return;
      const r = new FileReader();
      r.onload = () => { ta.value = r.result; toast("فایل خوانده شد — دکمه بازیابی را بزن", "ok"); };
      r.readAsText(f);
    });
    modal([ic("upload", 18), " بازیابی بکاپ"], el("div", null,
      el("div", { class: "badge y" }, "بکاپ شامل حساب‌ها و تنظیمات است."),
      el("label", { class: "fld", style: "margin-top:12px" }, "یا فایل بکاپ را انتخاب کنید", file),
      el("label", { class: "fld" }, "محتوای بکاپ", ta),
      el("div", { class: "btn-row" },
        el("button", {
          class: "btn primary sm", onclick: async () => {
            try {
              let data = JSON.parse(ta.value);
              if (data.backup) data = data.backup;
              const r = await api("/api/backup/restore", { method: "POST", body: { backup: data } });
              closeModal();
              toast(`بازیابی شد ✓ ${r.profiles} پروفایل، ${r.settings} تنظیم`, "ok", 6000);
              await refreshProfiles();
              go("accounts");
            } catch (e) { toast(e.message, "err", 6000); }
          }
        }, ic("check", 13), " بازیابی کن"))));
  }

  function resetModal() {
    const items = [
      ["profiles", "پروفایل‌ها و توکن‌های ذخیره‌شده", true],
      ["history", "تاریخچه‌ی پایش سلامت", true],
      ["auth", "نشست‌های ورود (خروج اجباری از همه دستگاه‌ها)", false],
    ].map(([k, label, def]) => {
      const cb = el("input", { type: "checkbox" });
      if (def) cb.checked = true;
      return { k, cb, node: el("label", { class: "chk", style: "padding:6px 0;border-bottom:1px solid var(--line-soft)" }, cb, el("span", { class: "small" }, label)) };
    });
    modal([ic("alert", 18), " بازنشانی تنظیمات"], el("div", null,
      el("p", { class: "small dim" }, "موارد انتخاب‌شده به‌طور کامل از دیتابیس D1 حذف می‌شوند. این عمل قابل بازگشت نیست — اگر لازم است اول بکاپ بگیرید."),
      el("div", { style: "margin:8px 0" }, items.map(i => i.node)),
      el("div", { class: "btn-row", style: "margin-top:12px" },
        el("button", { class: "btn sm", onclick: () => { items.forEach(i => { i.cb.checked = true; }); } }, "انتخاب همه"),
        el("button", { class: "btn sm ghost", onclick: () => { items.forEach(i => { i.cb.checked = false; }); } }, "پاک کردن انتخاب‌ها"))), [
      el("button", {
        class: "btn danger", onclick: () => {
          const body = {};
          items.forEach(i => { if (i.cb.checked) body[i.k] = true; });
          if (!Object.keys(body).length) return toast("چیزی انتخاب نشده", "warn");
          confirmBox("مطمئنی؟ داده‌های انتخاب‌شده برای همیشه حذف می‌شوند!", async () => {
            try {
              await api("/api/reset", { method: "POST", body });
              closeModal();
              if (body.auth) { toast("همه‌چیز بازنشانی شد — صفحه راه‌اندازی", "ok"); setTimeout(() => location.reload(), 900); }
              else { toast("بازنشانی انجام شد ✓", "ok"); await refreshProfiles(); go("dashboard"); }
            } catch (e) { toast(e.message, "err"); }
          });
        }
      }, ic("trash", 14), " حذف موارد انتخاب‌شده"),
    ]);
  }

  function viewSettings(v) {
    const cur = el("input", { type: "password" });
    const next = el("input", { type: "password" });
    v.append(el("div", { class: "card" },
      el("h3", null, ic("lock"), " تغییر رمز عبور (متغیر محیطی ADMIN)"),
      el("div", { class: "small dim", style: "line-height:2" },
        "رمز پنل در دیتابیس ذخیره نمی‌شود — متغیر محیطی ", el("code", { style: "color:var(--green);direction:ltr" }, "ADMIN"),
        " (از نوع Text) روی همین ورکر است. با این فرم همان متغیر از طریق API کلادفلر به‌روزرسانی می‌شود",
        " (اکانتی که این ورکر در آن است باید در پروفایل‌ها ذخیره شده باشد)."),
      el("label", { class: "fld" }, "رمز فعلی", cur),
      el("label", { class: "fld" }, "رمز جدید (حداقل ۶ کاراکتر)", next),
      el("div", { class: "btn-row" }, el("button", {
        class: "btn primary sm", onclick: async () => {
          try {
            const r = await api("/api/admin-password", { method: "POST", body: { current: cur.value, next: next.value } });
            toast(r.message || "متغیر ADMIN به‌روزرسانی شد ✓", "ok", 7000);
            cur.value = next.value = "";
          } catch (e) { toast(e.message, "err", 7000); }
        }
      }, ic("save", 14), " تغییر رمز"))));
    v.append(el("div", { class: "card" },
      el("h3", null, ic("save"), " بکاپ و بازیابی"),
      el("div", { class: "small dim", style: "line-height:2" },
        "بکاپ شامل پروفایل‌ها (به‌همراه توکن‌های API) و تنظیمات است.",
        el("br"), "فایل بکاپ را جای امن نگه دارید — داخل آن توکن‌ها به‌صورت خام هستند."),
      el("div", { class: "btn-row" },
        el("button", { class: "btn primary sm", onclick: backupModal }, ic("save", 14), " ساخت بکاپ"),
        el("a", { class: "btn ok sm", href: "/api/backup?download=1", download: "", title: "دانلود فایل بکاپ JSON" }, ic("download", 14), " دانلود بکاپ"),
        el("button", { class: "btn sm", onclick: restoreModal }, ic("upload", 14), " بازیابی بکاپ"))));
    v.append(el("div", { class: "card" },
      el("h3", null, ic("alert"), " بازنشانی تنظیمات"),
      el("div", { class: "small dim" }, "موارد انتخاب‌شده برای همیشه از D1 حذف می‌شوند — قبل از ادامه حتماً بکاپ بگیرید."),
      el("div", { class: "btn-row" },
        el("button", { class: "btn danger sm", onclick: resetModal }, ic("trash", 14), " بازنشانی..."))));
  }

  (function customSelects() {
    let cur = null;
    const CHECK = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
    const usable = (sel) => sel && sel.tagName === "SELECT" && !sel.multiple && !(sel.size > 1) && !sel.disabled && !sel.hasAttribute("data-native");

    function close(focusBack) {
      if (!cur) return;
      const { sel, panel } = cur;
      panel.remove(); sel.classList.remove("sel-open");
      cur = null;
      if (focusBack) try { sel.focus({ preventScroll: true }); } catch {}
    }

    function pick(item) {
      if (!cur || !item || item.disabled) return;
      const sel = cur.sel;
      const changed = sel.value !== item.value || sel.selectedIndex !== item.index;
      sel.selectedIndex = item.index;
      close(true);
      if (changed) {
        sel.dispatchEvent(new Event("input", { bubbles: true }));
        sel.dispatchEvent(new Event("change", { bubbles: true }));
      }
    }

    function setAct(i, scroll) {
      if (!cur) return;
      const vis = cur.items.filter(it => !it.hidden && !it.disabled);
      if (!vis.length) { cur.act = -1; return; }
      cur.items.forEach(it => it.node.classList.remove("act"));
      const it = cur.items[i];
      if (!it || it.hidden || it.disabled) return;
      cur.act = i; it.node.classList.add("act");
      if (scroll) it.node.scrollIntoView({ block: "nearest" });
    }

    function move(dir) {
      if (!cur) return;
      const vis = cur.items.map((it, i) => ({ it, i })).filter(x => !x.it.hidden && !x.it.disabled);
      if (!vis.length) return;
      let k = vis.findIndex(x => x.i === cur.act);
      k = k < 0 ? (dir > 0 ? 0 : vis.length - 1) : Math.min(vis.length - 1, Math.max(0, k + dir));
      setAct(vis[k].i, true);
    }

    function place() {
      if (!cur) return;
      const { sel, panel, list } = cur;
      const r = sel.getBoundingClientRect();
      const vw = window.innerWidth, vh = window.innerHeight, gap = 6;
      const width = Math.min(Math.max(r.width, 200), vw - 16);
      const below = vh - r.bottom - gap - 8, above = r.top - gap - 8;
      const up = below < 220 && above > below;
      const room = Math.max(120, Math.min(340, up ? above : below));
      panel.style.width = width + "px";
      let left = r.right - width;
      left = Math.max(8, Math.min(left, vw - width - 8));
      panel.style.left = left + "px";
      const searchH = cur.search ? 42 : 0;
      list.style.maxHeight = (room - searchH - 14) + "px";
      panel.classList.toggle("up", up);
      if (up) { panel.style.top = ""; panel.style.bottom = (vh - r.top + gap) + "px"; }
      else { panel.style.bottom = ""; panel.style.top = (r.bottom + gap) + "px"; }
    }

    function open(sel) {
      if (cur && cur.sel === sel) { close(true); return; }
      close(false);
      const panel = document.createElement("div");
      panel.className = "dd-panel"; panel.setAttribute("role", "listbox");
      const list = document.createElement("div"); list.className = "dd-list";
      const items = [];
      let lastGroup = null;
      Array.from(sel.options).forEach((o, index) => {
        const grp = o.parentElement && o.parentElement.tagName === "OPTGROUP" ? o.parentElement : null;
        if (grp && grp !== lastGroup) {
          const g = document.createElement("div"); g.className = "dd-group"; g.textContent = grp.label; list.append(g);
        }
        lastGroup = grp;
        if (o.hidden) return;
        const node = document.createElement("div");
        node.className = "dd-opt" + (index === sel.selectedIndex ? " sel" : "") + (o.disabled ? " dis" : "");
        node.setAttribute("role", "option");
        const txt = document.createElement("span"); txt.className = "dd-txt"; txt.textContent = o.textContent; txt.title = o.textContent;
        const chk = document.createElement("span"); chk.className = "dd-chk"; chk.innerHTML = CHECK;
        node.append(txt, chk);
        const item = { node, index, value: o.value, text: (o.textContent || "").toLowerCase(), disabled: o.disabled, hidden: false };
        node.addEventListener("mousedown", ev => ev.preventDefault());
        node.addEventListener("click", () => pick(item));
        node.addEventListener("mousemove", () => { if (cur && cur.act !== items.indexOf(item)) setAct(items.indexOf(item), false); });
        items.push(item); list.append(node);
      });
      let search = null;
      if (items.length > 8) {
        const wrap = document.createElement("div"); wrap.className = "dd-search";
        search = document.createElement("input"); search.type = "search"; search.placeholder = "جستجو...";
        wrap.innerHTML = '<svg class="ico" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.6" y2="16.6"/></svg>';
        wrap.prepend(search);
        panel.append(wrap);
        const empty = document.createElement("div"); empty.className = "dd-empty"; empty.textContent = "موردی پیدا نشد"; empty.style.display = "none";
        search.addEventListener("input", () => {
          const q = search.value.trim().toLowerCase();
          let shown = 0;
          items.forEach(it => { it.hidden = !!q && !it.text.includes(q); it.node.style.display = it.hidden ? "none" : ""; if (!it.hidden) shown++; });
          list.querySelectorAll(".dd-group").forEach(g => { g.style.display = q ? "none" : ""; });
          empty.style.display = shown ? "none" : "";
          const first = items.findIndex(it => !it.hidden && !it.disabled);
          if (first >= 0) setAct(first, true);
        });
        search.addEventListener("keydown", onKey);
        list.after(empty);
        panel.append(list, empty);
      } else {
        panel.append(list);
      }
      if (!items.length) { const em = document.createElement("div"); em.className = "dd-empty"; em.textContent = "گزینه‌ای وجود ندارد"; list.append(em); }
      document.body.append(panel);
      sel.classList.add("sel-open");
      cur = { sel, panel, list, items, act: -1, search };
      place();
      const selIdx = items.findIndex(it => it.index === sel.selectedIndex);
      setAct(selIdx >= 0 ? selIdx : items.findIndex(it => !it.disabled), true);
      if (search) setTimeout(() => search.focus({ preventScroll: true }), 0);
    }

    function onKey(ev) {
      if (!cur) return;
      if (ev.key === "ArrowDown") { ev.preventDefault(); move(1); }
      else if (ev.key === "ArrowUp") { ev.preventDefault(); move(-1); }
      else if (ev.key === "Home") { ev.preventDefault(); setAct(cur.items.findIndex(it => !it.hidden && !it.disabled), true); }
      else if (ev.key === "End") { ev.preventDefault(); const v = cur.items.map((it, i) => (!it.hidden && !it.disabled) ? i : -1).filter(i => i >= 0); if (v.length) setAct(v[v.length - 1], true); }
      else if (ev.key === "Enter" || (ev.key === " " && ev.target.tagName === "SELECT")) { ev.preventDefault(); if (cur.act >= 0) pick(cur.items[cur.act]); }
      else if (ev.key === "Escape") { ev.preventDefault(); ev.stopPropagation(); close(true); }
      else if (ev.key === "Tab") { close(false); }
    }

    document.addEventListener("mousedown", (ev) => {
      const sel = ev.target && ev.target.closest ? ev.target.closest("select") : null;
      if (usable(sel)) {
        if (ev.button !== 0) return;
        ev.preventDefault();
        try { sel.focus({ preventScroll: true }); } catch {}
        open(sel);
        return;
      }
      if (cur && !cur.panel.contains(ev.target)) close(false);
    }, true);

    document.addEventListener("keydown", (ev) => {
      const t = ev.target;
      if (cur && (t === cur.sel || cur.panel.contains(t))) { if (t !== cur.search) onKey(ev); return; }
      if (usable(t) && (ev.key === " " || ev.key === "Enter" || (ev.altKey && ev.key === "ArrowDown") || ev.key === "F4")) {
        ev.preventDefault(); open(t);
      }
    }, true);

    window.addEventListener("resize", () => close(false));
    document.addEventListener("scroll", (ev) => { if (cur && !cur.panel.contains(ev.target)) place(); }, true);
    setInterval(() => { if (cur && !document.body.contains(cur.sel)) close(false); }, 400);
  })();

  boot();
}

const UI_JS = `var __name = (fn) => fn;\n(${clientApp})();`;

const LOGO_DATA_URI = "data:image/webp;base64,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";
const FAVICON_DATA_URI = "data:image/png;base64,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";
const LOGO_IMG = '<img class="brand-logo" src="' + LOGO_DATA_URI + '" alt="NEXA">';
const LOGOUT_SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>';
const MENU_SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>';
const SUN_SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32 1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>';
const TERMINAL_SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>';
const BODY_HTML = `
<button id="btn-theme" class="btn ghost sm theme-fab" title="حالت روشن / تاریک">${SUN_SVG}</button>
<div id="auth" class="hidden">
  <div class="auth-wrap">
    <div class="auth-card">
      <div class="auth-logo">${LOGO_IMG}<span>Nexa-Manager</span></div>
      <div class="auth-sub">پنل مدیریت Cloudflare — نسخه ورکر</div>
      <div id="auth-body"></div>
    </div>
  </div>
</div>
<div id="main" class="hidden">
  <aside id="side">
    <div class="brand">${LOGO_IMG}<span>Nexa-Manager</span></div>
    <nav id="nav"></nav>
    <div class="side-foot">
      <button id="btn-logout" class="btn ghost sm">${LOGOUT_SVG} خروج</button>
    </div>
  </aside>
  <div id="content">
    <header id="topbar">
      <div class="row" style="gap:8px;min-width:0">
        <button id="btn-menu" class="btn ghost sm" title="منو">${MENU_SVG}</button>
        <div id="crumb">داشبورد</div>
      </div>
      <div id="profile-wrap"><label>اکانت:</label><select id="profile-select"></select><button id="btn-logout-top" class="btn ghost sm" title="خروج">${LOGOUT_SVG}</button></div>
    </header>
    <main id="view"></main>
  </div>
</div>
<div id="side-backdrop"></div>
<div id="toasts"></div>
<div id="modal-root"></div>
`;

function pageHTML() {
  return `<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<meta name="theme-color" content="#09110D">
<link rel="icon" type="image/png" sizes="48x48" href="${FAVICON_DATA_URI}">
<title>Nexa-Manager — مدیریت Cloudflare</title>
<style>${UI_CSS}</style>
</head>
<body>
${BODY_HTML}
<script>${UI_JS}</script>
</body>
</html>`;
}

export default {
  async scheduled(event, env, ctx) {
    const run = (async () => { await ensureSchema(env); await runHostHealthCron(env); })();
    if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(run);
    else await run;
  },
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/" || url.pathname === "/index.html" || url.pathname === "/ui") {
      return new Response(pageHTML(), { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
    }

    if (url.pathname === "/favicon.ico") {
      return new Response(null, { status: 204 });
    }

    if (url.pathname.startsWith("/api/")) {
      try {
        for (const r of routes) {
          if (r.method !== request.method) continue;
          const m = url.pathname.match(r.rx);
          if (!m) continue;
          if (!r.public) await requireSession(request, env);
          const params = {};
          r.names.forEach((n, i) => { params[n] = m[i + 1]; });
          return await r.handler(params, request, env, url, ctx);
        }
        return json({ error: "not found" }, 404);
      } catch (e) {
        if (e instanceof ApiError) {
          const body = { error: e.message };
          if (e.details) body.details = e.details;
          if (e.step) body.step = e.step;
          if (e.logs) body.logs = e.logs;
          return json(body, e.status);
        }
        return json({ error: e.message || "internal error" }, 500);
      }
    }

    return new Response("Not found", { status: 404 });
  },
};
