// --- Cloudflare raw TCP socket loader (lazy singleton) ---
let tcpConnectFn = null;
let tcpConnectLoadingPromise = null;
async function loadTcpConnect() {
  if (tcpConnectFn) return tcpConnectFn;
  if (!tcpConnectLoadingPromise) {
    tcpConnectLoadingPromise = import('cloudflare:sockets').then(function (mod) {
      tcpConnectFn = mod.connect;
      return tcpConnectFn;
    });
  }
  return tcpConnectLoadingPromise;
}

// --- Runtime state stores ---
const trafficByteCache = new Map();
const activeConnCountByUser = new Map();
const lastActiveWriteAt = new Map();
const lastDbWriteAt = new Map();
const dbWriteLock = new Map();
const dnsAnswerCache = new Map();
let pendingRequestCount = 0;
let lastRequestFlushAt = 0;
const userRequestPending = new Map();
const userRequestLastFlush = new Map();

// --- Tunables ---
const dnsAnswerCache_TTL = 5 * 60 * 1000;
const DOH_RESOLVER_URL = "https://cloudflare-dns.com/dns-query";
const UPSTREAM_BUNDLE_TARGET_BYTES = 32 * 1024;
const UPSTREAM_QUEUE_MAX_BYTES = 16 * 1024 * 1024;
const UPSTREAM_QUEUE_MAX_ITEMS = 4096;
const DOWNSTREAM_CHUNK_BYTES = 32 * 1024;
const DOWNSTREAM_CHUNK_TAIL_MIN = 512;
const DOWNSTREAM_FLUSH_DELAY_MS = 1;
const TCP_DIAL_CONCURRENCY = 3;
const RACE_DIAL_ENABLED = true;

// --- Fallback CDN proxy pool (used when no admin-configured proxy exists) ---
const FALLBACK_PROXY_HOSTS = [
  'proxyip.cmliussss.net'
];

// --- Remote resource endpoints (replace with your own hosted JSON) ---
const PUBLIC_PROXY_LIST_SOURCES = {
  proxyip: 'https://raw.githubusercontent.com/farzadqavidel/nexa-panel/refs/heads/main/resources/proxy-ip.json',
  socks5: 'https://raw.githubusercontent.com/farzadqavidel/nexa-panel/refs/heads/main/resources/socks5.json'
};
const REMOTE_PROXY_LIST_CACHE_TTL_MS = 30 * 60 * 1000;
let remoteProxyListCache = { key: '', data: null, fetchedAt: 0 };

let cachedProxyResolveKey = null;
let cachedProxyResolveList = null;
let cachedProxyResolveIndex = 0;

const SYSTEM_USER_LABEL = 'Telegram : @irnexa';
const FREE_SERVICE_NOTICE = '❌ این سرویس کاملاً رایگان است ❌ ';

const REMOTE_MANIFEST_DATA_URL = "https://raw.githubusercontent.com/farzadqavidel/nexa-panel/refs/heads/main/resources/data.json";
const REMOTE_MANIFEST_ANNOUNCE_URL = "https://raw.githubusercontent.com/farzadqavidel/nexa-panel/refs/heads/main/resources/notice.json";
const REMOTE_UPDATE_SCRIPT_URL = "https://raw.githubusercontent.com/farzadqavidel/nexa-panel/refs/heads/main/nexa.js";
const REMOTE_CLEAN_IPS_URL = "https://raw.githubusercontent.com/farzadqavidel/nexa-panel/refs/heads/main/resources/clean-ip.json";

const PANEL_VERSION = "2.4.1";
const CLEAN_IPS_CACHE_TTL_MS_MS = 60 * 60 * 1000;
const MANIFEST_CACHE_TTL_MS = 5 * 60 * 1000;
const MANIFEST_FETCH_TIMEOUT_MS = 8000;
const API_FETCH_TIMEOUT_MS = 6000;
function withTimeout(promise, ms, fallback) {
  return Promise.race([
    promise,
    new Promise(function(resolve) {
      setTimeout(function() { resolve(fallback); }, ms);
    })
  ]);
}
async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(function() { controller.abort(); }, timeoutMs || API_FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, Object.assign({}, options || {}, { signal: controller.signal }));
  } finally {
    clearTimeout(timer);
  }
}
const CLEAN_IP_OPERATOR_KEYS = {
  'آیپی های ایران پشت کلود': 'IR_CLOUD',
  'دامنه های ایران پشت کلود': 'IR_DOMAINS',
  'همراه اول': 'MCI',
  'ایرانسل': 'IRANCELL',
  'آپتل/رایتل/سامانتل': 'Rightel',
  'شاتل/پیشگامان': 'Shatel',
  'آسیاتک/مخابرات': 'ADSL'
};
let cleanIpsCache = { data: null, fetchedAt: 0 };
let blockedDomainsCache = { enabled: false, domains: [], fetchedAt: 0 };
let systemUserCache = { user: null, fetchedAt: 0 };
const SYSTEM_USER_CACHE_TTL_MS = 60000;
let workerConfigCache = { data: null, fetchedAt: 0 };
const WORKER_CONFIG_CACHE_TTL_MS = 30000;
let contentPolicyCache = { data: null, fetchedAt: 0 };
const CONTENT_POLICY_CACHE_TTL_MS = 30000;
const BLOCKED_DOMAINS_CACHE_TTL = 30000;
const ADULT_BLOCKLIST_URL = 'https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt';
const ADULT_BLOCKLIST_CACHE_TTL = 6 * 60 * 60 * 1000;
let adultBlocklistCache = { domains: [], fetchedAt: 0 };

function isCleanListIpv4(value) {
  const parts = String(value || '').split('.');
  return parts.length === 4 && parts.every(p => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}
function isCleanDomain(value) {
  if (!value || value.length > 253 || !value.includes('.')) return false;
  if (!/^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(value)) return false;
  return value.split('.').every(part =>
    part.length > 0 && part.length <= 63 &&
    /^[a-zA-Z0-9-]+$/.test(part) &&
    !part.startsWith('-') && !part.endsWith('-')
  );
}
function parseCleanIpsList(raw) {
  const result = {};
  let currentOp = null;
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed === '----------') continue;
    if (trimmed.startsWith('#')) {
      currentOp = trimmed.replace(/^#\s*/, '').trim();
      if (currentOp && !result[currentOp]) result[currentOp] = [];
      continue;
    }
    if (!currentOp) continue;
    if (isCleanListIpv4(trimmed) || isCleanDomain(trimmed)) result[currentOp].push(trimmed);
  }
  for (const op of Object.keys(result)) {
    result[op] = [...new Set(result[op])];
  }
  return result;
}
function normalizeCleanIpsByOperator(parsed) {
  const result = {};
  for (const [label, ips] of Object.entries(parsed)) {
    const key = CLEAN_IP_OPERATOR_KEYS[label] || label;
    if (!result[key]) result[key] = [];
    result[key].push(...ips);
    result[key] = [...new Set(result[key])];
  }
  return result;
}
function isCloudflareIPv4(ip) {
  const p = String(ip).split('.').map(Number);
  if (p.length !== 4 || p.some(x => !(Number.isInteger(x) && x >= 0 && x <= 255))) return false;
  const n = ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
  const cidrs = [['173.245.48.0', 20], ['103.21.244.0', 22], ['103.22.200.0', 22], ['103.31.4.0', 22], ['141.101.64.0', 18], ['108.162.192.0', 18], ['190.93.240.0', 20], ['188.114.96.0', 20], ['197.234.240.0', 22], ['198.41.128.0', 17], ['162.158.0.0', 15], ['104.16.0.0', 13], ['104.24.0.0', 14], ['172.64.0.0', 13], ['131.0.72.0', 22]];
  for (const [base, bits] of cidrs) {
    const bp = base.split('.').map(Number);
    const bn = ((bp[0] << 24) >>> 0) + (bp[1] << 16) + (bp[2] << 8) + bp[3];
    const mask = (~((1 << (32 - bits)) - 1)) >>> 0;
    if (((n & mask) >>> 0) === ((bn & mask) >>> 0)) return true;
  }
  return false;
}
const CLEAN_IP_AUTO_ASSIGN_COUNT = 16;
const PER_USER_CLEAN_IP_CAP = 40;
const IR_CARRIER_TO_POOL_KEY = {
  mtn: 'IRANCELL',
  mci: 'MCI',
  rightel: 'Rightel',
  shatel: 'Shatel',
  ir: 'IR_CLOUD',
  all: null
};
function detectIranCarrier(request) {
  const cf = (request && request.cf) || {};
  const org = String(cf.asOrganization || '').toLowerCase();
  const asn = Number(cf.asn || 0);
  if (String(cf.country || '').toUpperCase() !== 'IR') return 'all';
  if (asn === 44244 || org.includes('irancell') || org.includes('mtn')) return 'mtn';
  if (asn === 197207 || org.includes('mobile communication company of iran') || org.includes('mcci') || org.includes('hamrah')) return 'mci';
  if (asn === 57218 || org.includes('rightel')) return 'rightel';
  if (asn === 31549 || org.includes('shatel')) return 'shatel';
  return 'ir';
}
function normalizeCleanIpEntry(line) {
  const trimmed = String(line || '').trim();
  if (!trimmed) return '';
  const hashIdx = trimmed.indexOf('#');
  const addr = (hashIdx >= 0 ? trimmed.slice(0, hashIdx) : trimmed).trim();
  if (!addr) return '';
  const hostPart = addr.split(':')[0].replace(/^\[|\]$/g, '').trim();
  if (isCleanListIpv4(hostPart) || isCleanDomain(hostPart)) return addr;
  return '';
}
function normalizeCleanIpList(raw, maxCount) {
  const seen = new Set();
  const out = [];
  const lines = Array.isArray(raw) ? raw : String(raw || '').split(/[\r\n,;]+/);
  for (const line of lines) {
    const entry = normalizeCleanIpEntry(line);
    if (!entry || seen.has(entry)) continue;
    seen.add(entry);
    out.push(entry);
    if (maxCount && out.length >= maxCount) break;
  }
  return out;
}
function normalizeCleanIpsField(raw) {
  if (raw == null || String(raw).trim() === '') return null;
  const list = normalizeCleanIpList(raw);
  return list.length ? list.join('\n') : null;
}
function normalizeCleanIpsFieldForUpdate(raw) {
  if (raw == null || String(raw).trim() === '') return '';
  const list = normalizeCleanIpList(raw);
  return list.length ? list.join('\n') : '';
}
function shouldAutoAssignCleanIps(user) {
  if (!user || isSystemUser(user)) return false;
  return user.ips == null;
}
const SCANNER_POOL_KEY = 'scanner_pool_ips';
const CLEAN_IP_SOURCE_KEY = 'clean_ip_source_mode';
const SCANNER_POOL_MAX = 50;
const ScannerPoolService = {
  parseList(raw) {
    const seen = new Set();
    const out = [];
    for (const line of String(raw || '').split(/[\r\n,;]+/)) {
      const entry = normalizeCleanIpEntry(line);
      if (!entry) continue;
      const ip = entry.split(':')[0].trim();
      if (!isCleanListIpv4(ip) || !isCloudflareIPv4(ip) || seen.has(entry)) continue;
      seen.add(entry);
      out.push(entry);
    }
    return out;
  },
  async getSourceMode(env) {
    try {
      const row = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind(CLEAN_IP_SOURCE_KEY).first();
      const mode = String(row?.value || 'pool').trim().toLowerCase();
      return mode === 'smart' ? 'smart' : 'pool';
    } catch (e) {
      return 'pool';
    }
  },
  async setSourceMode(env, mode) {
    const val = String(mode || '').trim().toLowerCase() === 'pool' ? 'pool' : 'smart';
    await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(CLEAN_IP_SOURCE_KEY, val).run();
    return val;
  },
  async get(env) {
    const row = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind(SCANNER_POOL_KEY).first();
    return this.parseList(row?.value);
  },
  async save(env, ips, merge = true) {
    const incoming = this.parseList(Array.isArray(ips) ? ips.join('\n') : ips);
    if (merge && !incoming.length) {
      try { return await this.get(env); } catch (e) { return []; }
    }
    let merged = incoming.slice(0, SCANNER_POOL_MAX);
    if (merge) {
      let current = [];
      try { current = await this.get(env); } catch (e) {}
      const seen = new Set();
      const out = [];
      for (const ip of [...incoming, ...current]) {
        if (seen.has(ip)) continue;
        seen.add(ip);
        out.push(ip);
        if (out.length >= SCANNER_POOL_MAX) break;
      }
      merged = out;
    }
    if (merged.length) {
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(SCANNER_POOL_KEY, merged.join('\n')).run();
    } else {
      await env.DB.prepare("DELETE FROM settings WHERE key = ?").bind(SCANNER_POOL_KEY).run();
    }
    return merged;
  }
};
const CleanIpsService = {
  resolveUrl(env) {
    return String(env?.CLEAN_IPS_URL || REMOTE_CLEAN_IPS_URL || '').trim();
  },
  async fetch(env, forceRefresh = false) {
    const sourceUrl = this.resolveUrl(env);
    if (!sourceUrl) return {};
    const now = Date.now();
    if (!forceRefresh && cleanIpsCache.data && (now - cleanIpsCache.fetchedAt) < CLEAN_IPS_CACHE_TTL_MS) {
      return cleanIpsCache.data;
    }
    try {
      const res = await fetch(sourceUrl, {
        headers: { Accept: 'text/plain, application/json, */*' }
      });
      if (!res.ok) throw new Error('Failed to fetch clean IPs');
      const contentType = res.headers.get('content-type') || '';
      let data;
      if (contentType.includes('application/json')) {
        const json = await res.json();
        data = (json && typeof json === 'object' && !Array.isArray(json)) ? json : {};
      } else {
        data = normalizeCleanIpsByOperator(parseCleanIpsList(await res.text()));
      }
      cleanIpsCache = { data, fetchedAt: now };
      return data;
    } catch (e) {
      if (cleanIpsCache.data) return cleanIpsCache.data;
      return {};
    }
  }
};
const SmartCleanIpsService = {
  async resolveOperatorList(env, carrier) {
    const data = await CleanIpsService.fetch(env);
    const tryOrder = [...new Set([carrier, 'ir', 'all'])];
    for (const c of tryOrder) {
      const key = IR_CARRIER_TO_POOL_KEY[c];
      let list = [];
      if (key && Array.isArray(data[key]) && data[key].length) {
        list = data[key];
      } else if (c === 'all' || c === 'ir') {
        list = Object.values(data).flat();
      }
      list = normalizeCleanIpList(list);
      if (list.length) return list;
    }
    return [];
  },
  async fetchForRequest(request, env, count) {
    const carrier = detectIranCarrier(request);
    const list = await this.resolveOperatorList(env, carrier);
    if (!list.length) return [];
    const shuffled = list.slice().sort(() => 0.5 - Math.random());
    return shuffled.slice(0, count || CLEAN_IP_AUTO_ASSIGN_COUNT);
  },
  async fetchScannerCandidates(request, env, count) {
    const entries = await this.fetchForRequest(request, env, count || 32);
    const out = [];
    const seen = new Set();
    for (const entry of entries) {
      const ip = entry.split(':')[0].trim();
      if (!isCleanListIpv4(ip) || seen.has(ip)) continue;
      seen.add(ip);
      out.push(ip);
    }
    return out;
  },
  shuffleForUserSeed(username, list, cap) {
    if (!username || list.length <= cap) return list.slice(0, cap);
    let seed = 2166136261;
    for (let i = 0; i < username.length; i++) {
      seed ^= username.charCodeAt(i);
      seed = (seed * 16777619) >>> 0;
    }
    const rand = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
    const byIp = new Map();
    for (const entry of list) {
      const ip = entry.split(':')[0].trim();
      if (ip && !byIp.has(ip)) byIp.set(ip, entry);
    }
    const pool = [...byIp.values()];
    for (let i = pool.length - 1; i > 0; i--) {
      const j = Math.floor(rand() * (i + 1));
      const tmp = pool[i];
      pool[i] = pool[j];
      pool[j] = tmp;
    }
    return pool.slice(0, cap);
  },
  async assignToUserOnFirstVisit(env, user, request) {
    if (!shouldAutoAssignCleanIps(user)) return user;

    const carrier = detectIranCarrier(request);
    let list = [];
    try {
      list = await this.resolveOperatorList(env, carrier);
    } catch (e) {}
    if (list.length) {
      try {
    
        await ScannerPoolService.save(env, list.join('\n'), true);
      } catch (e) {}
    }

    try {
      await env.DB.prepare("UPDATE users SET ips = '' WHERE username = ? AND ips IS NULL").bind(user.username).run();
    } catch (e) {}
    return Object.assign({}, user, { ips: user.ips ?? '' });
  }
};
let managDataCache = { data: null, announcement: '', fetchedAt: 0 };
function parseRemoteBool(value) {
  const v = String(value ?? '').trim().toLowerCase();
  return v === 'true' || v === '1' || v === 'yes';
}
const UpdateService = {
  resolveDataUrl(env) {
    return String(env?.MANAG_DATA_URL || REMOTE_MANIFEST_DATA_URL || '').trim();
  },
  resolveAnnouncesUrl(env) {
    return String(env?.MANAG_ANNOUNCES_URL || REMOTE_MANIFEST_ANNOUNCE_URL || '').trim();
  },
  resolveScriptUrl(env) {
    return String(env?.MANAG_SCRIPT_URL || REMOTE_UPDATE_SCRIPT_URL || '').trim();
  },
  versionsMatch(a, b) {
    return String(a || '').trim() === String(b || '').trim();
  },
  async fetchWithTimeout(url, options, timeoutMs) {
    return fetchWithTimeout(url, options, timeoutMs || MANIFEST_FETCH_TIMEOUT_MS);
  },
  async fetchRemoteData(env) {
    const dataUrl = this.resolveDataUrl(env);
    if (!dataUrl) return null;
    const res = await this.fetchWithTimeout(dataUrl, {
      headers: { Accept: 'application/json, text/plain, */*' }
    });
    if (!res.ok) throw new Error('خطا در دریافت data');
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) return await res.json();
    try {
      return JSON.parse(await res.text());
    } catch (e) {
      throw new Error('پاسخ data نامعتبر است');
    }
  },
  async fetchAnnouncement(env) {
    const announcesUrl = this.resolveAnnouncesUrl(env);
    if (!announcesUrl) return '';
    const res = await this.fetchWithTimeout(announcesUrl, {
      headers: { Accept: 'text/plain, */*' }
    });
    if (!res.ok) return '';
    return String(await res.text() || '').trim();
  },
  async fetchScript(env) {
    const scriptUrl = this.resolveScriptUrl(env);
    if (!scriptUrl) throw new Error('آدرس سورس اسکریپت تنظیم نشده است');
    const res = await this.fetchWithTimeout(scriptUrl, {
      headers: { Accept: 'text/plain, application/javascript, */*' }
    }, 30000);
    if (!res.ok) throw new Error('خطا در دریافت سورس اسکریپت');
    const code = await res.text();
    if (!code || code.length < 100 || !code.includes('export default')) {
      throw new Error('اسکریپت نامعتبر (وجود ندارد !)');
    }
    return code;
  },
  async getStatus(env) {
    const now = Date.now();
    if (managDataCache.data && (now - managDataCache.fetchedAt) < MANIFEST_CACHE_TTL_MS) {
      return {
        version: managDataCache.data.version || '',
        updaterequired: !!managDataCache.data.updaterequired,
        announcement: managDataCache.announcement || ''
      };
    }
    const [remote, announcement] = await Promise.all([
      this.fetchRemoteData(env).catch(function() { return null; }),
      this.fetchAnnouncement(env).catch(function() { return ''; })
    ]);
    const version = String(remote?.version || '').trim();
    const updaterequired = parseRemoteBool(remote?.updaterequired);
    managDataCache = {
      data: { version, updaterequired },
      announcement,
      fetchedAt: now
    };
    return { version, updaterequired, announcement };
  }
};
const WORKER_CONFIG_KEY = 'worker_config';
const WORKER_CONFIG_DEFAULTS = {
  protocolType: 'vless',
  transportProtocol: 'ws',
  gRPCmode: 'gun',
  skipCertVerify: false,
  tlsFragment: '',
  randomPath: false,
  fingerprint: 'chrome',
  transportPath: '/in_config_foroshi_nist',
  echEnabled: false,
  echSni: 'cloudflare-ech.com',
  echDns: 'https://dns.alidns.com/dns-query',
  centralApi: '',
  subName: 'Nexa Panel',
  subUpdateHours: 3,
  subConverterApi: 'https://SUBAPI.dler.net',
  subConfigUrl: 'https://raw.githubusercontent.com/cmliu/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini',
  subEmoji: false,
  statusPagePath: 'servicestat',
  subPagePath: 'sub',
  logsPagePath: 'logs',
  adminPagePath: 'admin',
  ssEncryption: 'aes-128-gcm',
  infoRemarkTemplate: '[مصرف شده: {used}] [{total} : کل ] [مانده : {dayremind}]',
  nodeRemarkTemplate: '{username}'
};
const NETWORK_SETTINGS_KEY = 'network_settings';
const NETWORK_SETTINGS_DEFAULTS = {
  enableDomesticBypass: true,
  blockQUIC: false,
  enableAdBlock: true,
  enableMalwareBlock: true,
  enablePhishingBlock: true,
  bypassSanctions: false,
  bypassChina: false,
  bypassRussia: false,
  enableDoH: true,
  enableAntiSanctionDNS: false,
  antiSanctionDNSProvider: 'shekan'
};
const RESISTANCE_PROFILE_IRAN_HIGH = {
  enableDomesticBypass: true,
  blockQUIC: true,
  enableAdBlock: true,
  enableMalwareBlock: true,
  enablePhishingBlock: true,
  bypassSanctions: true,
  bypassChina: false,
  bypassRussia: false,
  enableDoH: true,
  enableAntiSanctionDNS: true,
  antiSanctionDNSProvider: 'shekan'
};
const NetworkSettingsService = {
  getDefaults() {
    return Object.assign({}, NETWORK_SETTINGS_DEFAULTS);
  },
  getProfiles() {
    return {
      iran_high: { label: 'ایران / سانسور بال', settings: RESISTANCE_PROFILE_IRAN_HIGH }
    };
  },
  normalize(data) {
    const d = this.getDefaults();
    const src = data && typeof data === 'object' ? data : {};
    const pickBool = (key) => (typeof src[key] === 'boolean' ? src[key] : d[key]);
    const provider = ['cloudflare', 'google', 'quad9', 'adguard', 'alidns', 'shekan', 'custom'].includes(String(src.antiSanctionDNSProvider || ''))
      ? String(src.antiSanctionDNSProvider)
      : d.antiSanctionDNSProvider;
    return {
      enableDomesticBypass: pickBool('enableDomesticBypass'),
      blockQUIC: pickBool('blockQUIC'),
      enableAdBlock: pickBool('enableAdBlock'),
      enableMalwareBlock: pickBool('enableMalwareBlock'),
      enablePhishingBlock: pickBool('enablePhishingBlock'),
      bypassSanctions: pickBool('bypassSanctions'),
      bypassChina: pickBool('bypassChina'),
      bypassRussia: pickBool('bypassRussia'),
      enableDoH: pickBool('enableDoH'),
      enableAntiSanctionDNS: pickBool('enableAntiSanctionDNS'),
      antiSanctionDNSProvider: provider
    };
  },
  async loadSettings(env) {
    try {
      const row = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind(NETWORK_SETTINGS_KEY).first();
      if (row && row.value) return this.normalize(JSON.parse(row.value));
    } catch (e) {}
    return this.getDefaults();
  },
  async saveSettings(env, data) {
    const normalized = this.normalize(data);
    await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(NETWORK_SETTINGS_KEY, JSON.stringify(normalized)).run();
    return normalized;
  },
  getAntiSanctionDnsUrl(provider) {
    const map = {
      cloudflare: 'https://cloudflare-dns.com/dns-query',
      google: 'https://dns.google/dns-query',
      quad9: 'https://dns.quad9.net/dns-query',
      adguard: 'https://dns.adguard-dns.com/dns-query',
      alidns: 'https://dns.alidns.com/dns-query',
      shekan: 'https://shecan.ir/dns-query'
    };
    return map[String(provider || '').toLowerCase()] || map.shekan;
  },
  applyClashHotpatch(yaml, ns) {
    if (!yaml || !ns) return yaml;
    let out = String(yaml);
    if (ns.blockQUIC && !out.includes('DST-PORT,443,REJECT,udp')) {
      const quicRule = '  - "DST-PORT,443,REJECT,udp"';
      if (/^\s*-\s*MATCH,/m.test(out)) out = out.replace(/^(\s*-\s*MATCH,)/m, quicRule + '\n$1');
      else if (/^rules:\s*$/m.test(out)) out = out.replace(/^rules:\s*$/m, 'rules:\n' + quicRule);
    }
    if (ns.enableDomesticBypass && !out.includes('# IRANIAN DIRECT RULES')) {
      out = out.replace(/^(\s*)rules:\s*$/m, '$&' + '\n# IRANIAN DIRECT RULES\n$1  - DOMAIN-SUFFIX,ir,DIRECT\n$1  - GEOIP,ir,DIRECT');
    }
    if (ns.bypassSanctions && !out.includes('# SANCTION BYPASS RULES')) {
      out = out.replace(/^(\s*)rules:\s*$/m, '$&' + '\n# SANCTION BYPASS RULES\n$1  - GEOSITE,category-sanctioned,DIRECT\n$1  - DOMAIN-SUFFIX,intel.com,DIRECT\n$1  - DOMAIN-SUFFIX,oracle.com,DIRECT\n$1  - DOMAIN-SUFFIX,docker.com,DIRECT\n$1  - DOMAIN-SUFFIX,android.com,DIRECT');
    }
    if (ns.enableAdBlock && !out.includes('# AD BLOCK RULES')) {
      out = out.replace(/^(\s*)rules:\s*$/m, '$&' + '\n# AD BLOCK RULES\n$1  - GEOSITE,category-ads-all,REJECT');
    }
    if (ns.enableMalwareBlock && !out.includes('# MALWARE BLOCK RULES')) {
      out = out.replace(/^(\s*)rules:\s*$/m, '$&' + '\n# MALWARE BLOCK RULES\n$1  - GEOSITE,category-malware,REJECT\n$1  - GEOSITE,malware,REJECT');
    }
    if (ns.enablePhishingBlock && !out.includes('# PHISHING BLOCK RULES')) {
      out = out.replace(/^(\s*)rules:\s*$/m, '$&' + '\n# PHISHING BLOCK RULES\n$1  - GEOSITE,category-phishing,REJECT\n$1  - GEOSITE,phishing,REJECT');
    }
    if (ns.enableDoH || ns.enableAntiSanctionDNS) {
      const dohUrl = ns.enableAntiSanctionDNS
        ? this.getAntiSanctionDnsUrl(ns.antiSanctionDNSProvider)
        : 'https://cloudflare-dns.com/dns-query';
      const dnsTag = '# NEXA DNS POLICY';
      if (!out.includes(dnsTag)) {
        const dnsBlock = `dns:\n  enable: true\n  ${dnsTag}\n  nameserver:\n    - ${dohUrl}\n    - https://dns.alidns.com/dns-query\n  fallback:\n    - 8.8.8.8\n    - 1.1.1.1\n`;
        if (!/^dns:\s*(?:\n|$)/m.test(out)) out = dnsBlock + out;
      }
    }
    return out;
  },
  applySingboxHotpatch(jsonText, ns) {
    if (!jsonText || !ns) return jsonText;
    try {
      const config = JSON.parse(jsonText);
      if (!config.route || !Array.isArray(config.route.rules)) config.route = { rules: [] };
      if (!Array.isArray(config.route.rules)) config.route.rules = [];
      const ensureReject = () => {
        if (!config.outbounds) config.outbounds = [];
        if (!config.outbounds.some(o => o && (o.tag === 'REJECT' || o.type === 'block'))) {
          config.outbounds.push({ type: 'block', tag: 'REJECT' });
        }
      };
      const ensureRuleSet = (type, code) => {
        if (!config.route.rule_set) config.route.rule_set = [];
        const tag = `${type}-${code}`;
        if (!config.route.rule_set.some(s => s && s.tag === tag)) {
          config.route.rule_set.push({
            type: 'remote',
            tag,
            format: 'binary',
            url: `https://raw.githubusercontent.com/SagerNet/sing-${type}/rule-set/${tag}.srs`
          });
        }
        return tag;
      };
      if (ns.blockQUIC && !config.route.rules.some(r => r.outbound === 'block' && r.network === 'udp' && Array.isArray(r.port) && r.port.includes(443))) {
        config.route.rules.unshift({ outbound: 'block', network: 'udp', port: [443] });
      }
      if (ns.enableDomesticBypass && !config.route.rules.some(r => r.outbound === 'direct' && Array.isArray(r.domain_suffix) && r.domain_suffix.includes('.ir'))) {
        config.route.rules.unshift({ outbound: 'direct', domain_suffix: ['.ir'] });
      }
      if (ns.bypassSanctions && !config.route.rules.some(r => r.outbound === 'direct' && JSON.stringify(r).includes('sanction'))) {
        config.route.rules.unshift({ outbound: 'direct', rule_set: [ensureRuleSet('geosite', 'category-sanctioned-ir')] });
      }
      if (ns.enableAdBlock && !config.route.rules.some(r => r.outbound === 'block' && JSON.stringify(r).includes('ads'))) {
        ensureReject();
        config.route.rules.unshift({ outbound: 'block', rule_set: [ensureRuleSet('geosite', 'category-ads-all')] });
      }
      if (ns.enableMalwareBlock && !config.route.rules.some(r => r.outbound === 'block' && JSON.stringify(r).includes('malware'))) {
        ensureReject();
        config.route.rules.unshift({ outbound: 'block', rule_set: [ensureRuleSet('geosite', 'category-malware')] });
      }
      if (ns.enablePhishingBlock && !config.route.rules.some(r => r.outbound === 'block' && JSON.stringify(r).includes('phishing'))) {
        ensureReject();
        config.route.rules.unshift({ outbound: 'block', rule_set: [ensureRuleSet('geosite', 'category-phishing')] });
      }
      if (ns.enableDoH || ns.enableAntiSanctionDNS) {
        const dohUrl = ns.enableAntiSanctionDNS
          ? this.getAntiSanctionDnsUrl(ns.antiSanctionDNSProvider)
          : 'https://cloudflare-dns.com/dns-query';
        config.dns = config.dns && typeof config.dns === 'object' ? config.dns : {};
        const servers = Array.isArray(config.dns.servers) ? config.dns.servers : [];
        if (!servers.some(s => s && String(s.server || s.address || '').includes('dns'))) {
          servers.unshift({ tag: 'nexa-doh', address: dohUrl, detour: 'direct' });
          config.dns.servers = servers;
        }
      }
      return JSON.stringify(config, null, 2);
    } catch (e) {
      return jsonText;
    }
  }
};
const WorkerConfigService = {
  getDefaults() {
    return Object.assign({}, WORKER_CONFIG_DEFAULTS);
  },
  cleanPathSegment(value) {
    return String(value || '').trim().toLowerCase().replace(/^\/+|\/+$/g, '').replace(/[^a-z0-9_-]/g, '').slice(0, 40);
  },
  normalize(data) {
    const d = this.getDefaults();
    const src = data && typeof data === 'object' ? data : {};
    const pickStr = (key, maxLen) => {
      const val = src[key];
      if (val === undefined || val === null || val === '') return d[key];
      return String(val).trim().slice(0, maxLen || 300);
    };
    const pickBool = (key) => (typeof src[key] === 'boolean' ? src[key] : d[key]);
    const pickNum = (key, min, max) => {
      const n = Number(src[key]);
      if (!Number.isFinite(n)) return d[key];
      return Math.min(max, Math.max(min, n));
    };
    const protocolType = ['vless', 'trojan', 'ss', 'mixed'].includes(String(src.protocolType || '').toLowerCase())
      ? String(src.protocolType).toLowerCase()
      : d.protocolType;
    const transportProtocol = ['ws', 'grpc', 'xhttp'].includes(String(src.transportProtocol || '').toLowerCase())
      ? String(src.transportProtocol).toLowerCase()
      : d.transportProtocol;
    const tlsFragment = ['', 'Shadowrocket', 'Happ'].includes(String(src.tlsFragment ?? d.tlsFragment))
      ? String(src.tlsFragment ?? d.tlsFragment)
      : d.tlsFragment;
    const statusPagePath = this.cleanPathSegment(src.statusPagePath) || d.statusPagePath;
    const subPagePath = this.cleanPathSegment(src.subPagePath) || d.subPagePath;
    const logsPagePath = this.cleanPathSegment(src.logsPagePath) || d.logsPagePath;
    const adminPagePath = this.cleanPathSegment(src.adminPagePath) || d.adminPagePath;
    let transportPath = pickStr('transportPath', 120);
    if (!transportPath.startsWith('/')) transportPath = '/' + transportPath;
    return {
      protocolType,
      transportProtocol,
      gRPCmode: src.gRPCmode === 'multi' ? 'multi' : 'gun',
      skipCertVerify: pickBool('skipCertVerify'),
      tlsFragment,
      randomPath: pickBool('randomPath'),
      fingerprint: pickStr('fingerprint', 32) || d.fingerprint,
      transportPath,
      echEnabled: pickBool('echEnabled'),
      echSni: pickStr('echSni', 120) || d.echSni,
      echDns: pickStr('echDns', 300) || d.echDns,
      centralApi: pickStr('centralApi', 300),
      subName: pickStr('subName', 80) || d.subName,
      subUpdateHours: pickNum('subUpdateHours', 1, 168),
      subConverterApi: pickStr('subConverterApi', 300) || d.subConverterApi,
      subConfigUrl: pickStr('subConfigUrl', 500) || d.subConfigUrl,
      subEmoji: pickBool('subEmoji'),
      statusPagePath,
      subPagePath,
      logsPagePath,
      adminPagePath,
      ssEncryption: pickStr('ssEncryption', 32) || d.ssEncryption,
      infoRemarkTemplate: pickStr('infoRemarkTemplate', 300) || d.infoRemarkTemplate,
      nodeRemarkTemplate: pickStr('nodeRemarkTemplate', 120) || d.nodeRemarkTemplate
    };
  },
  async loadSettings(env) {
    const now = Date.now();
    if (workerConfigCache.data && (now - workerConfigCache.fetchedAt) < WORKER_CONFIG_CACHE_TTL_MS) {
      return workerConfigCache.data;
    }
    let result = this.getDefaults();
    try {
      const row = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind(WORKER_CONFIG_KEY).first();
      if (row && row.value) {
        result = this.normalize(JSON.parse(row.value));
      }
    } catch (e) {}
    workerConfigCache = { data: result, fetchedAt: now };
    return result;
  },
  async saveSettings(env, data) {
    const normalized = this.normalize(data);
    await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(WORKER_CONFIG_KEY, JSON.stringify(normalized)).run();
    workerConfigCache = { data: normalized, fetchedAt: Date.now() };
    return normalized;
  },
  async getStatusPath(env) {
    const cfg = await this.loadSettings(env);
    return cfg.statusPagePath || WORKER_CONFIG_DEFAULTS.statusPagePath;
  },
  async getSubPath(env) {
    const cfg = await this.loadSettings(env);
    return cfg.subPagePath || WORKER_CONFIG_DEFAULTS.subPagePath;
  },
  async getAdminPath(env) {
    const cfg = await this.loadSettings(env);
    return cfg.adminPagePath || WORKER_CONFIG_DEFAULTS.adminPagePath;
  },
  async getTransportPath(env) {
    const cfg = await this.loadSettings(env);
    return cfg.transportPath || WORKER_CONFIG_DEFAULTS.transportPath;
  },
  getTransportConfig(cfg) {
    const transport = cfg.transportProtocol || 'ws';
    const isGrpc = transport === 'grpc';
    return {
      typeParam: this.getTransportTypeParam(cfg),
      pathField: isGrpc ? 'serviceName' : 'path',
      hostField: isGrpc ? 'authority' : 'host'
    };
  },
  resolveFingerprint(fp) {
    const val = String(fp || 'chrome').trim().toLowerCase();
    if (val && val !== 'random' && val !== 'randomized') return val;
    return 'chrome';
  },
  resolveTransportPathValue(cfg) {
    let path = cfg.transportPath || WORKER_CONFIG_DEFAULTS.transportPath;
    if (cfg.randomPath) {
      const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      let suffix = '';
      for (let i = 0; i < 8; i++) suffix += chars[Math.floor(Math.random() * chars.length)];
      path = path.replace(/\/?$/, '/') + suffix;
    }
    if (cfg.transportProtocol === 'grpc') return (path.split('?')[0] || '/');
    return path;
  },
  getTransportTypeParam(cfg) {
    const transport = cfg.transportProtocol || 'ws';
    if (transport === 'grpc') {
      return cfg.gRPCmode === 'multi' ? 'grpc&mode=multi' : 'grpc&mode=gun';
    }
    if (transport === 'xhttp') return 'xhttp&mode=stream-one';
    return 'ws';
  },
  getTlsFragmentParam(cfg) {
    if (cfg.tlsFragment === 'Shadowrocket') return '&fragment=' + encodeURIComponent('1,40-60,30-50,tlshello');
    if (cfg.tlsFragment === 'Happ') return '&fragment=' + encodeURIComponent('3,1,tlshello');
    return '';
  },
  getEchParam(cfg) {
    if (!cfg.echEnabled) return '';
    const dns = cfg.echDns || WORKER_CONFIG_DEFAULTS.echDns;
    const sni = cfg.echSni || '';
    return '&ech=' + encodeURIComponent((sni ? sni + '+' : '') + dns);
  },
  buildLinkQuery(cfg, host, portStr, fp) {
    const tc = this.getTransportConfig(cfg);
    const pathEnc = encodeURIComponent(this.resolveTransportPathValue(cfg));
    const resolvedFp = this.resolveFingerprint(fp);
    const isTlsPort = ['443', '2053', '2083', '2087', '2096', '8443'].includes(String(portStr));
    const tlsVal = isTlsPort ? 'tls' : 'none';
    const transportType = tc.typeParam + this.getEchParam(cfg);
    const insecure = cfg.skipCertVerify ? '&insecure=1&allowInsecure=1' : '&insecure=0&allowInsecure=0';
    const fragment = tlsVal === 'tls' ? this.getTlsFragmentParam(cfg) : '';
    return '?' + tc.pathField + '=' + pathEnc + '&security=' + tlsVal + '&encryption=none' + insecure + '&' + tc.hostField + '=' + host + '&fp=' + resolvedFp + '&type=' + transportType + '&sni=' + host + fragment;
  },
  buildNodeLink(cfg, user, ip, portStr, fp, remark, protoOverride, linkHost, proxyIpOverride) {
    const host = linkHost || ip;
    const protocol = protoOverride || cfg.protocolType || 'vless';
    const resolvedFp = this.resolveFingerprint(fp);
    let pathVal = this.resolveTransportPathValue(cfg);
    if (proxyIpOverride) {
      pathVal += (pathVal.includes('?') ? '&' : '?') + 'proxyip=' + encodeURIComponent(proxyIpOverride);
    }
    const tc = this.getTransportConfig(cfg);
    const ech = this.getEchParam(cfg);
    const tlsPorts = ['443', '2053', '2083', '2087', '2096', '8443'];
    const noTlsPorts = ['80', '2052', '2082', '2086', '2095', '8080'];
    const isTlsPort = tlsPorts.includes(String(portStr));
    if (protocol === 'ss') {
      const enc = cfg.ssEncryption || WORKER_CONFIG_DEFAULTS.ssEncryption;
      const ssPath = pathVal.replace(/([=,])/g, '\\$1');
      const plugin = 'ray-plugin;mode=websocket;host=' + host + ';path=' + ssPath + (isTlsPort ? ';tls' : '');
      return 'ss://' + btoa(enc + ':' + user.uuid) + '@' + ip + ':' + portStr + '?plugin=v2' + encodeURIComponent(plugin) + ech + (isTlsPort ? this.getTlsFragmentParam(cfg) : '') + '#' + encodeURIComponent(remark);
    }
    const tlsVal = isTlsPort ? 'tls' : 'none';
    const fragment = tlsVal === 'tls' ? this.getTlsFragmentParam(cfg) : '';
    const insecure = cfg.skipCertVerify ? '&insecure=1&allowInsecure=1' : '';
    if (!isTlsPort) {
      const mapped = noTlsPorts[tlsPorts.indexOf(Number(portStr))];
      const p = mapped != null ? String(mapped) : portStr;
      return protocol + '://' + user.uuid + '@' + ip + ':' + p + '?security=none&type=' + tc.typeParam + '&' + tc.hostField + '=' + host + '&' + tc.pathField + '=' + encodeURIComponent(pathVal) + '&encryption=none#' + encodeURIComponent(remark);
    }
    return protocol + '://' + user.uuid + '@' + ip + ':' + portStr + '?security=tls&type=' + tc.typeParam + ech + '&' + tc.hostField + '=' + host + '&fp=' + resolvedFp + '&sni=' + host + '&' + tc.pathField + '=' + encodeURIComponent(pathVal) + fragment + '&encryption=none' + insecure + '#' + encodeURIComponent(remark);
  }
};
function pathStartsWithSegment(pathname, segment) {
  const seg = String(segment || '').replace(/^\/+|\/+$/g, '');
  if (!seg) return false;
  return pathname === '/' + seg || pathname.startsWith('/' + seg + '/');
}
function extractSegmentKey(pathname, segment) {
  const seg = String(segment || '').replace(/^\/+|\/+$/g, '');
  const prefix = '/' + seg + '/';
  if (!pathname.startsWith(prefix)) return '';
  return decodeURIComponent(pathname.slice(prefix.length).split('/')[0] || '');
}
function buildRemarkVariables(user, now = Date.now(), extra = {}) {
  const usedStr = fmtRemarkVolume(user?.used_gb || 0);
  const totalStr = user?.limit_gb != null ? fmtRemarkVolume(user.limit_gb) : '∞';
  let dayremind = '∞';
  if (user?.expiry_days) {
    if (user.created_at) {
      const created = new Date(user.created_at);
      const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
      const diffDays = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
      dayremind = (diffDays > 0 ? diffDays : 0) + ' روز';
    } else {
      dayremind = user.expiry_days + ' روز';
    }
  }
  return {
    username: user?.username || '',
    dayremind,
    used: usedStr,
    total: totalStr,
    expiry: user?.expiry_days != null ? String(user.expiry_days) : '∞',
    port: extra.port != null ? String(extra.port) : '',
    proxyip: extra.proxyip != null ? String(extra.proxyip) : '',
    flag: extra.flag != null ? String(extra.flag) : ''
  };
}
function applyRemarkTemplate(template, user, now = Date.now(), extra = {}) {
  const tpl = String(template || '');
  if (!tpl) return '';
  const vars = buildRemarkVariables(user, now, extra);
  let result = tpl;
  for (const [key, val] of Object.entries(vars)) {
    result = result.split('{' + key + '}').join(val);
  }
  if (result.includes('dayremind')) result = result.replace(/dayremind/g, vars.dayremind);
  return result;
}
const StatusUrlService = {
  async assignStatusSlug(db, username) {
    const name = String(username || '').trim();
    if (!name) return '';
    await db.prepare("UPDATE users SET status_slug = ? WHERE username = ?").bind(name, name).run();
    return name;
  },
  async resolveUser(db, pathKey) {
    const key = decodeURIComponent(String(pathKey || '').trim());
    if (!key) return null;
    let user = await db.prepare("SELECT * FROM users WHERE username = ?").bind(key).first();
    if (!user) user = await db.prepare("SELECT * FROM users WHERE status_slug = ?").bind(key).first();
    if (!user) user = await db.prepare("SELECT * FROM users WHERE uuid = ?").bind(key).first();
    return user;
  },
  getPublicPath(user) {
    return user?.username || '';
  },
  async getPublicUrl(origin, user, env) {
    const slug = this.getPublicPath(user);
    const statusPath = env ? await WorkerConfigService.getStatusPath(env) : WORKER_CONFIG_DEFAULTS.statusPagePath;
    return origin + '/' + statusPath + '/' + encodeURIComponent(slug);
  }
};
const CdnProxyService = {
  parseList(value) {
    if (!value) return [];
    if (Array.isArray(value)) return value.map(v => String(v).trim()).filter(Boolean);
    let normalized = String(value).replace(/[\t"';\r\n]+/g, ',').replace(/,+/g, ',');
    if (normalized.charAt(0) === ',') normalized = normalized.slice(1);
    if (normalized.charAt(normalized.length - 1) === ',') normalized = normalized.slice(0, normalized.length - 1);
    return normalized.split(',').map(v => v.trim()).filter(Boolean);
  },
  parseHostPortString(str) {
    let address = str, port = 443;
    if (str.includes(']:')) {
      const parts = str.split(']:');
      address = parts[0] + ']';
      port = parseInt(parts[1], 10) || port;
    } else if ((str.match(/:/g) || []).length === 1 && !str.startsWith('[')) {
      const colonIndex = str.lastIndexOf(':');
      address = str.slice(0, colonIndex);
      port = parseInt(str.slice(colonIndex + 1), 10) || port;
    }
    return [address, port];
  },
  parseTxtProxyRecords(txtData) {
    return txtData.flatMap(data => {
      let item = data;
      if (item.startsWith('"') && item.endsWith('"')) item = item.slice(1, -1);
      return item.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
    }).map(prefix => this.parseHostPortString(prefix));
  },
  extractPathValue(value) {
    if (!value.includes('://')) {
      const slashIndex = value.indexOf('/');
      return slashIndex > 0 ? value.slice(0, slashIndex) : value;
    }
    const parts = value.split('://');
    if (parts.length !== 2) return value;
    const slashIndex = parts[1].indexOf('/');
    return slashIndex > 0 ? `${parts[0]}://${parts[1].slice(0, slashIndex)}` : value;
  },
  parseProxyFromUrl(url) {
    if (!url) return null;
    const searchParams = url.searchParams;
    const pathname = decodeURIComponent(url.pathname);
    const pathLower = pathname.toLowerCase();
    const queryProxy = searchParams.get('proxyip');
    if (queryProxy !== null) return this.extractPathValue(queryProxy);
    const match = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower);
    if (match) return this.extractPathValue(match[2]);
    return null;
  },
  isAutoProxy(value) {
    const v = String(value || '').trim().toLowerCase();
    return !v || v === 'auto';
  },
  stripProxyCountryTag(raw) {
    const m = String(raw || '').match(/^(.*?)#([A-Za-z]{2})\s*$/);
    return m ? m[1].trim() : String(raw || '').trim();
  },
  parseProxyEntryMeta(raw) {
    const str = String(raw || '').trim();
    const m = str.match(/^(.*?)#([A-Za-z]{2})\s*$/);
    return m ? { address: m[1].trim(), cc: m[2].toUpperCase() } : { address: str, cc: '' };
  },
  getEffectiveProxyList(settings) {
    const list = settings?.proxy_ips?.length
      ? settings.proxy_ips.slice()
      : (settings?.proxy_ip ? [settings.proxy_ip] : []);
    return list
      .map(v => this.stripProxyCountryTag(v))
      .filter(v => v && !this.isAutoProxy(v));
  },
  getEffectiveProxyListWithMeta(settings) {
    const list = settings?.proxy_ips?.length
      ? settings.proxy_ips.slice()
      : (settings?.proxy_ip ? [settings.proxy_ip] : []);
    return list
      .map(v => this.parseProxyEntryMeta(v))
      .filter(entry => entry.address && !this.isAutoProxy(entry.address));
  },
  async loadSettings(env) {
    const defaults = {
      mode: 'proxyip',
      proxy_ips: [],
      proxy_ip: 'auto',
      chain_proxy: '',
      socks5_rotate_every: '',
      socks5_rotate_count: 3
    };
    try {
      const { results } = await env.DB.prepare(
        "SELECT key, value FROM settings WHERE key IN ('proxy_ips','proxy_ip','cdn_proxy_mode','chain_proxy','socks5_rotate_every','socks5_rotate_count')"
      ).all();
      for (const row of (results || [])) {
        if (row.key === 'proxy_ips') defaults.proxy_ips = this.parseList(row.value);
        else if (row.key === 'proxy_ip') defaults.proxy_ip = row.value || 'auto';
        else if (row.key === 'cdn_proxy_mode') defaults.mode = row.value || 'proxyip';
        else if (row.key === 'chain_proxy') defaults.chain_proxy = row.value || '';
        else if (row.key === 'socks5_rotate_every') defaults.socks5_rotate_every = row.value || '';
        else if (row.key === 'socks5_rotate_count') defaults.socks5_rotate_count = Math.max(1, parseInt(row.value, 10) || 3);
      }
    } catch (e) {}
    if (!defaults.proxy_ip && !defaults.proxy_ips.length) defaults.proxy_ip = 'auto';
    if (!defaults.proxy_ips.length && defaults.proxy_ip && !this.isAutoProxy(defaults.proxy_ip)) {
      defaults.proxy_ips = [defaults.proxy_ip];
    }
    defaults.envProxyIPs = env.PROXYIP || env.PROXY_IP ? this.parseList(env.PROXYIP || env.PROXY_IP) : [];
    defaults.defaultProxyIPs = FALLBACK_PROXY_HOSTS.slice();
    return defaults;
  },
  async saveSettings(env, data) {
    const mode = ['proxyip', 'socks5', 'http', 'https', 'turn', 'sstp'].includes(String(data.mode || '').toLowerCase())
      ? String(data.mode).toLowerCase()
      : 'proxyip';
    await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('cdn_proxy_mode', ?)").bind(mode).run();
    if (mode === 'proxyip') {
      const proxyIp = String(data.proxy_ip ?? 'auto').trim() || 'auto';
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_ip', ?)").bind(proxyIp).run();
      if (this.isAutoProxy(proxyIp)) {
        await env.DB.prepare("DELETE FROM settings WHERE key = 'proxy_ips'").run();
      } else {
        const list = this.parseList(proxyIp);
        await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_ips', ?)").bind(list.join('\n')).run();
      }
      await env.DB.prepare("DELETE FROM settings WHERE key = 'chain_proxy'").run();
      await env.DB.prepare("DELETE FROM settings WHERE key = 'socks5_rotate_every'").run();
      await env.DB.prepare("DELETE FROM settings WHERE key = 'socks5_rotate_count'").run();
    } else {
      const chain = String(data.chain_proxy || '').trim();
      if (chain) {
        await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('chain_proxy', ?)").bind(chain).run();
      } else {
        await env.DB.prepare("DELETE FROM settings WHERE key = 'chain_proxy'").run();
      }
      const rotateEvery = String(data.socks5_rotate_every || '').trim();
      if (rotateEvery) {
        await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('socks5_rotate_every', ?)").bind(rotateEvery).run();
      } else {
        await env.DB.prepare("DELETE FROM settings WHERE key = 'socks5_rotate_every'").run();
      }
      const rotateCount = Math.max(1, Math.floor(Number(data.socks5_rotate_count) || 3));
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('socks5_rotate_count', ?)").bind(String(rotateCount)).run();
      await env.DB.prepare("DELETE FROM settings WHERE key = 'proxy_ip'").run();
      await env.DB.prepare("DELETE FROM settings WHERE key = 'proxy_ips'").run();
    }
    return this.loadSettings(env);
  },
  buildUserSettings(panelSettings, user) {
    const userProxyIps = this.parseList(user?.proxy_ip);
    if (!userProxyIps.length) return panelSettings;
    return {
      ...panelSettings,
      proxy_ips: userProxyIps,
      proxy_ip: userProxyIps[0]
    };
  },
  hasManualProxyConfigured(panelSettings, user) {
    const userProxyIps = this.parseList(user?.proxy_ip).filter(v => !this.isAutoProxy(v));
    if (userProxyIps.length) return true;
    const effective = this.getEffectiveProxyList(panelSettings);
    if (effective.length) return true;
    if (panelSettings?.envProxyIPs?.length) return true;
    return false;
  },
  getActiveProxyIp(settings, request) {
    const urlOverride = request ? this.parseProxyFromUrl(new URL(request.url)) : null;
    if (urlOverride) {
      return { proxyIp: urlOverride, mode: settings.mode || 'proxyip', enableFallback: false };
    }
    const effective = this.getEffectiveProxyList(settings);
    const customList = effective.length
      ? effective
      : (settings.envProxyIPs.length ? settings.envProxyIPs : null);
    if (customList?.length) {
      return {
        proxyIp: customList[Math.floor(Math.random() * customList.length)],
        mode: settings.mode || 'proxyip',
        enableFallback: false
      };
    }
    const colo = (request?.cf && request.cf.colo) || 'auto';
    const seed = [...colo].reduce((a, c) => a + c.charCodeAt(0), 0);
    return {
      proxyIp: FALLBACK_PROXY_HOSTS[seed % FALLBACK_PROXY_HOSTS.length],
      mode: 'proxyip',
      enableFallback: true
    };
  },
  async resolveProxyAddresses(proxyIP, targetDomain = 'dash.cloudflare.com', uuid = '00000000-0000-4000-8000-000000000000') {
    proxyIP = String(proxyIP || '').toLowerCase();
    if (!proxyIP) return [];
    if (!cachedProxyResolveKey || !cachedProxyResolveList || cachedProxyResolveKey !== proxyIP) {
      const proxyIpList = this.parseList(proxyIP);
      let allEntries = [];
      const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
      const ipv6Regex = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;
      for (const singleProxyIP of proxyIpList) {
        let [address, port] = this.parseHostPortString(singleProxyIP);
        if (singleProxyIP.includes('.tp')) {
          const tpMatch = singleProxyIP.match(/\.tp(\d+)/);
          if (tpMatch) port = parseInt(tpMatch[1], 10);
        }
        if (ipv4Regex.test(address) || ipv6Regex.test(address)) {
          allEntries.push([address, port]);
          continue;
        }
        const [txtRecords, aRecords] = await Promise.all([
          dohQuery(address, 'TXT'),
          dohQuery(address, 'A')
        ]);
        const txtData = txtRecords.filter(r => r.type === 16).map(r => r.data);
        const txtAddresses = this.parseTxtProxyRecords(txtData);
        if (txtAddresses.length > 0) {
          allEntries.push(...txtAddresses);
          continue;
        }
        const ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
        if (ipv4List.length > 0) {
          allEntries.push(...ipv4List.map(ip => [ip, port]));
          continue;
        }
        const aaaaRecords = await dohQuery(address, 'AAAA');
        const ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
        if (ipv6List.length > 0) {
          allEntries.push(...ipv6List.map(ip => [ip, port]));
        } else {
          allEntries.push([address, port]);
        }
      }
      const sorted = allEntries.sort((a, b) => a[0].localeCompare(b[0]));
      const rootDomain = targetDomain.includes('.') ? targetDomain.split('.').slice(-2).join('.') : targetDomain;
      let randomSeed = [...(rootDomain + uuid)].reduce((a, c) => a + c.charCodeAt(0), 0);
      const shuffled = [...sorted].sort(() => (randomSeed = (randomSeed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
      cachedProxyResolveList = shuffled.slice(0, 8);
      cachedProxyResolveKey = proxyIP;
    }
    return cachedProxyResolveList || [];
  },
  async geoLookupSingle(ip) {
    const res = await fetchWithTimeout(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=query,city,country,countryCode,isp,status,timezone,regionName,as,mobile,proxy,hosting,lat,lon`,
      {},
      4000
    );
    if (!res.ok) throw new Error(`ip-api request failed: ${res.status}`);
    const data = await res.json();
    if (data.status === "success") {
      return {
        ip: data.query,
        city: data.city,
        country: data.country,
        countryCode: data.countryCode,
        isp: data.isp,
        region: data.regionName,
        timezone: data.timezone,
        asn: data.as,
        mobile: data.mobile,
        proxy: data.proxy,
        hosting: data.hosting,
        lat: data.lat,
        lon: data.lon
      };
    }
    throw new Error(data.message || "Geo lookup failed");
  },
  async fetchPublicProxyList(mode) {
    const normalizedMode = String(mode || 'proxyip').toLowerCase();
    const sourceUrl = REMOTE_PROXY_LIST_SOURCES[normalizedMode];
    if (!sourceUrl) throw new Error('unsupported mode');
    const now = Date.now();
    const canCache = normalizedMode !== 'proxyip';
    if (canCache && remoteProxyListCache.key === normalizedMode && remoteProxyListCache.data && (now - remoteProxyListCache.fetchedAt) < REMOTE_PROXY_LIST_CACHE_TTL_MS) {
      return remoteProxyListCache.data;
    }
    const res = await fetchWithTimeout(sourceUrl, {
      headers: { 'User-Agent': 'NexaProxy' },
      cf: { cacheTtl: 1800, cacheEverything: true }
    }, normalizedMode === 'proxyip' ? 90000 : 15000);
    if (!res.ok) throw new Error(`fetch failed: ${res.status}`);
    const data = await res.json();
    if (canCache) remoteProxyListCache = { key: normalizedMode, data, fetchedAt: now };
    return data;
  }
};

export default {
  async fetch(request, env, ctx) {
    trackRequest(env, ctx);
    await DbService.ensureSchema(env.DB);
    await ensureSystemUser(env.DB);
    if (ctx) ctx.waitUntil(BackupService.maybeRunScheduledBackup(env).catch(() => {}));
    const url = new URL(request.url);
    const userReqTask = (async () => {
      const username = await resolveRequestUsername(url, env);
      if (username) trackUserRequest(username, env, ctx);
    })();
    if (ctx) ctx.waitUntil(userReqTask);
    const workerCfg = await WorkerConfigService.loadSettings(env);
    const transportPath = workerCfg.transportPath || WORKER_CONFIG_DEFAULTS.transportPath;
    if (Router.isWebSocketUpgrade(request) && url.pathname === transportPath) {
      return await Router.handleWebSocket(request, env, ctx);
    }
    const subPath = workerCfg.subPagePath || WORKER_CONFIG_DEFAULTS.subPagePath;
    if (pathStartsWithSegment(url.pathname, subPath)) {
      return await Router.handleSubscription(url, env, request, ctx, subPath);
    }
    if (url.pathname.startsWith('/api/') || url.pathname === '/locations') {
      return await Router.handleApi(request, url, env, ctx);
    }
    if (url.pathname === '/my-ip/geo') {
      return await Router.handleMyIpGeo(request);
    }
    const logsPath = workerCfg.logsPagePath || WORKER_CONFIG_DEFAULTS.logsPagePath;
    if (pathStartsWithSegment(url.pathname, logsPath)) {
      return await Router.handleUserLogsPage(request, url, env, logsPath);
    }
    if (url.pathname === '/' + logsPath) {
      return await Router.handleLogsPage(request, env);
    }
    if (url.pathname === '/setup') {
      return await Router.handleSetupPage(request, env);
    }
    const adminPath = workerCfg.adminPagePath || WORKER_CONFIG_DEFAULTS.adminPagePath;
    const panelIsDisabled = await PanelDisableService.isPanelDisabled(env);
    const forceUnlock = url.searchParams.get('unlock') === '1';
    if (panelIsDisabled && !forceUnlock && (url.pathname === '/login' || url.pathname === '/' + adminPath)) {
      return await Router.handleStatusHome(env);
    }
    if (url.pathname === '/login') {
      return Response.redirect(new URL('/' + adminPath, url.origin).href, 302);
    }
    if (url.pathname === '/' + adminPath) {
      return await Router.handlePanel(request, env);
    }
    const statusPath = workerCfg.statusPagePath || WORKER_CONFIG_DEFAULTS.statusPagePath;
    if (pathStartsWithSegment(url.pathname, statusPath)) {
      return await Router.handleUserStatus(url, env, statusPath, request);
    }
    if (url.pathname === '/guide') {
      return new Response(HTML_TEMPLATES.guide, {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    const setupReady = await SetupService.isReady(env);
    if (!setupReady) {
      return Response.redirect(new URL('/setup', url.origin).href, 302);
    }
    return await Router.handleStatusHome(env);
  },
  async scheduled(event, env, ctx) {
    await DbService.ensureSchema(env.DB);
    await ensureSystemUser(env.DB);
    ctx.waitUntil(BackupService.runScheduledBackup(env, 'cron').catch(() => {}));
  }
};
const Router = {
  isWebSocketUpgrade(request) {
    const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase();
    return upgradeHeader === 'websocket';
  },
  isSubscriptionPath(pathname, subPath) {
    return pathStartsWithSegment(pathname, subPath || WORKER_CONFIG_DEFAULTS.subPagePath);
  },
  async handleWebSocket(request, env, ctx) {
    try {
      const proxySettings = await CdnProxyService.loadSettings(env);
      return handleVLESS(env, proxySettings, ctx, request);
    } catch (e) {
      return new Response("Internal Server Error", { status: 500 });
    }
  },
  async handleMyIpGeo(request) {
    let ip = request.headers.get('CF-Connecting-IP')
      || request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim()
      || '';
    if (request.method === 'POST') {
      const body = (await request.text()).trim();
      if (body) ip = body;
    }
    if (!ip) {
      return new Response(JSON.stringify({ success: false, message: 'IP یافت نشد' }), {
        status: 400,
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }
    try {
      const geo = await CdnProxyService.geoLookupSingle(ip);
      return new Response(JSON.stringify({ success: true, body: geo }), {
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    } catch (e) {
      return new Response(JSON.stringify({ success: false, message: e.message }), {
        status: 500,
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }
  },
  async handleStatusHome(env) {
    const startedAt = await PanelUptimeService.getStartedAt(env);
    const html = buildNexaStatusPage(startedAt);
    return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
  },
  async handleSubscription(url, env, request, ctx, subPath) {
    const seg = subPath || WORKER_CONFIG_DEFAULTS.subPagePath;
    const subUser = extractSegmentKey(url.pathname, seg);
    const host = url.hostname;
    try {
      let user = await env.DB.prepare("SELECT * FROM users WHERE username = ? OR uuid = ?").bind(subUser, subUser).first();
      if (!user || user.connection_type !== atob('dmxlc3M=')) {
        return new Response("Not Found", { status: 404 });
      }
      user = await SmartCleanIpsService.assignToUserOnFirstVisit(env, user, request);
      if (isUserRequestLimitExceeded(user, user.username)) {
        return new Response("Request limit exceeded", { status: 429 });
      }
      const clientIp = request ? getClientIp(request) : '';
      if (clientIp) {
        const logTask = async () => {
          try {
            await ConnectionLogService.addLog(env, user.username, clientIp, {
              eventType: 'دریافت کانفیگ',
              extra: 'مسیر: /' + seg + '/' + user.username
            });
          } catch (e) {}
        };
        if (ctx) ctx.waitUntil(logTask());
        else logTask();
      }
      return await SubscriptionService.generateText(user, host, env, request, url);
    } catch (err) {
      return new Response("Error building config: " + err.message, { status: 500 });
    }
  },
  async handleSetupPage(request, env) {
    const pageUrl = new URL(request.url);
    const cfTokenMode = pageUrl.searchParams.get('cf_token') === '1';
    const status = await SetupService.getStatus(env, request);
    return new Response(buildSetupHtml(status, { cfTokenMode }), {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  },
  async handleLogsPage(request, env) {
    const setupReady = await SetupService.isReady(env);
    if (!setupReady) {
      return Response.redirect(new URL('/setup', new URL(request.url).origin).href, 302);
    }
    const authorized = await DbService.verifyApiAuth(request, env);
    if (!authorized) {
      return new Response(HTML_TEMPLATES.login, {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    const adminPath = await WorkerConfigService.getAdminPath(env);
    return Response.redirect(new URL('/' + adminPath + '#logs', new URL(request.url).origin).href, 302);
  },
  async handleUserLogsPage(request, url, env, logsPath) {
    const setupReady = await SetupService.isReady(env);
    if (!setupReady) {
      return Response.redirect(new URL('/setup', new URL(request.url).origin).href, 302);
    }
    const authorized = await DbService.verifyApiAuth(request, env);
    if (!authorized) {
      return new Response(HTML_TEMPLATES.login, {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    const seg = logsPath || WORKER_CONFIG_DEFAULTS.logsPagePath;
    const username = extractSegmentKey(url.pathname, seg);
    if (!username) {
      return new Response("Username is required", { status: 400 });
    }
    try {
      const user = await env.DB.prepare("SELECT username FROM users WHERE username = ? OR uuid = ?").bind(username, username).first();
      if (!user) {
        return new Response(HTML_TEMPLATES.userNotFound, {
          status: 404,
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });
      }
      const html = HTML_TEMPLATES.serviceLogs.replace(
        "/* {{USERNAME_PLACEHOLDER}} */",
        `window.serviceLogUsername = ${JSON.stringify(user.username)}; window.serviceLogsPagePath = ${JSON.stringify(seg)};`
      );
      return new Response(html, {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    } catch (err) {
      return new Response("Error: " + err.message, { status: 500 });
    }
  },
  async handlePanel(request, env) {
    const setupReady = await SetupService.isReady(env);
    if (!setupReady) {
      return Response.redirect(new URL('/setup', new URL(request.url).origin).href, 302);
    }
    const authorized = await DbService.verifyApiAuth(request, env);
    if (!authorized) {
      return new Response(HTML_TEMPLATES.login, {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    return new Response(HTML_TEMPLATES.panel, {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  },
  async handleUserStatus(url, env, statusPath, request) {
    const seg = statusPath || WORKER_CONFIG_DEFAULTS.statusPagePath;
    const pathKey = extractSegmentKey(url.pathname, seg);
    if (!pathKey) {
      return new Response("Username is required", { status: 400 });
    }
    try {
      const user = await StatusUrlService.resolveUser(env.DB, pathKey);
      if (!user) {
        return new Response(HTML_TEMPLATES.userNotFound, {
          status: 404,
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });
      }
      await syncExpiredUsersStatus(env);
      let activeUser = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(user.username).first() || user;
      activeUser = await SmartCleanIpsService.assignToUserOnFirstVisit(env, activeUser, request);
      const panelSettings = await CdnProxyService.loadSettings(env);
      const hasManualProxy = CdnProxyService.hasManualProxyConfigured(panelSettings, activeUser);
      let remoteStatus = { announcement: '' };
      try {
        remoteStatus = await UpdateService.getStatus(env);
      } catch (e) {}
      const allServicesOff = await PanelKillService.isAllServicesOff(env);
      const reqLimitExceeded = isUserRequestLimitExceeded(activeUser, activeUser.username);
      const userJson = JSON.stringify({
        username: activeUser.username,
        uuid: activeUser.uuid,
        limit_gb: activeUser.limit_gb,
        expiry_days: activeUser.expiry_days,
        used_gb: activeUser.used_gb,
        is_active: activeUser.is_active,
        created_at: activeUser.created_at,
        tls: activeUser.tls,
        port: activeUser.port,
        ips: activeUser.ips,
        fingerprint: activeUser.fingerprint || 'random',
        proxy_ip: activeUser.proxy_ip || '',
        max_requests: activeUser.max_requests,
        max_requests_daily: activeUser.max_requests_daily,
        used_requests_total: getUserReqUsageTotal(activeUser, activeUser.username),
        used_requests_today: getUserReqUsageToday(activeUser, activeUser.username),
        request_limit_exceeded: reqLimitExceeded,
        has_manual_proxy: hasManualProxy,
        all_services_off: allServicesOff,
        announcement: remoteStatus.announcement || ''
      });
      const workerConfig = await WorkerConfigService.loadSettings(env);
      const html = HTML_TEMPLATES.status.replace(
        "/* {{USER_DATA_PLACEHOLDER}} */",
        `window.statusUser = ${userJson}; window.statusWorkerConfig = ${JSON.stringify(workerConfig)};`
      );
      return new Response(html, {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    } catch (err) {
      return new Response("Error: " + err.message, { status: 500 });
    }
  },
  async handleApi(request, url, env, ctx) {
    const hasPassword = await DbService.getPanelPassword(env);
    const setupReady = await SetupService.isReady(env);
    if (url.pathname === '/api/setup-status' && request.method === 'GET') {
      if (setupReady) {
        return new Response(JSON.stringify({ error: "راه‌اندازی کامل شده است" }), {
          status: 403, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      const status = await SetupService.getStatus(env, request);
      return new Response(JSON.stringify(status), {
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }
    if (url.pathname === '/api/setup' && request.method === 'POST') {
      if (hasPassword) {
        return new Response(JSON.stringify({ error: "راه‌اندازی قبلاً انجام شده است" }), {
          status: 403, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      if (!env.DB) {
        return new Response(JSON.stringify({ error: "D1 متصل نیست" }), {
          status: 400, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      try {
        await DbService.ensureSchema(env.DB);
        await env.DB.prepare("SELECT 1 AS ok").first();
      } catch (e) {
        return new Response(JSON.stringify({ error: "D1 متصل نیست" }), {
          status: 400, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      let body;
      try {
        body = await request.json();
      } catch (e) {
        return new Response(JSON.stringify({ error: "درخواست نامعتبر است" }), {
          status: 400, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      const password = body.password ? String(body.password) : '';
      const confirmPassword = body.confirmPassword ? String(body.confirmPassword) : password;
      if (!password || password.length < 4) {
        return new Response(JSON.stringify({ error: "رمز عبور باید حداقل ۴ کاراکتر باشد" }), {
          status: 400, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      if (password !== confirmPassword) {
        return new Response(JSON.stringify({ error: "رمز عبور و تکرار آن یکسان نیستند" }), {
          status: 400, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      const cfToken = await DbService.getCfToken(env);
      if (!cfToken) {
        return new Response(JSON.stringify({ error: "برای تنظیم رمز عبور، متغیر CF_TOKEN باید در ورکر تنظیم شده باشد." }), {
          status: 400, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      try {
        await SetupService.setAdminVariable(env, request, password);
        try {
          await env.DB.prepare("DELETE FROM settings WHERE key = 'ADMIN'").run();
        } catch (e) {}
        setPasswordOverride(password);
        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message || "خطا در ایجاد متغیر ADMIN" }), {
          status: 500, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }
    if (url.pathname === '/api/login' && request.method === 'POST') {
      if (!setupReady) {
        return new Response(JSON.stringify({ error: "راه‌اندازی کامل نشده است. ابتدا D1 و متغیرهای ADMIN و CF_TOKEN را تنظیم کنید." }), {
          status: 403, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      const { password } = await request.json();
      const hashedInput = await DbService.sha256(password);
      const storedHash = await DbService.getPanelPassword(env);
      const clientIp = getClientIp(request);
      if (storedHash === hashedInput) {
        await LogService.addLog(env, 'ورود ادمین', 'ورود موفق به پنل مدیریت', clientIp);
        return new Response(JSON.stringify({ success: true }), {
          headers: { 
            "Content-Type": "application/json; charset=utf-8",
            "Set-Cookie": "panel_session=" + hashedInput + "; Path=/; HttpOnly; Secure; SameSite=Lax"
          }
        });
      }
      await LogService.addLog(env, 'ورود ناموفق', 'تلاش ناموفق برای ورود به پنل', clientIp);
      return new Response(JSON.stringify({ error: "رمز عبور اشتباه است" }), { 
        status: 401, headers: { "Content-Type": "application/json; charset=utf-8" } 
      });
    }
    if (url.pathname === '/api/logout' && request.method === 'POST') {
      await LogService.addLog(env, 'خروج ادمین', 'خروج از پنل مدیریت', getClientIp(request));
      return new Response(JSON.stringify({ success: true }), {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Set-Cookie": "panel_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax"
        }
      });
    }
    if (url.pathname === '/api/change-password' && request.method === 'POST') {
      const changeAuth = await DbService.verifyApiAuth(request, env);
      if (!changeAuth) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      let body;
      try {
        body = await request.json();
      } catch (e) {
        return new Response(JSON.stringify({ error: "درخواست نامعتبر است" }), {
          status: 400, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      const currentPassword = body.currentPassword ? String(body.currentPassword) : '';
      const newPassword = body.newPassword ? String(body.newPassword) : '';
      const confirmPassword = body.confirmPassword ? String(body.confirmPassword) : '';
      if (!currentPassword) {
        return new Response(JSON.stringify({ error: "رمز عبور فعلی را وارد کنید" }), {
          status: 400, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      if (!newPassword || newPassword.length < 4) {
        return new Response(JSON.stringify({ error: "رمز عبور جدید باید حداقل ۴ کاراکتر باشد" }), {
          status: 400, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      if (newPassword !== confirmPassword) {
        return new Response(JSON.stringify({ error: "رمز عبور جدید و تکرار آن یکسان نیستند" }), {
          status: 400, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      const storedHash = await DbService.getPanelPassword(env);
      const currentHash = await DbService.sha256(currentPassword);
      if (currentHash !== storedHash) {
        return new Response(JSON.stringify({ error: "رمز عبور فعلی اشتباه است" }), {
          status: 401, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      const cfToken = await DbService.getCfToken(env);
      if (!cfToken) {
        return new Response(JSON.stringify({ error: "برای تغییر رمز عبور، متغیر CF_TOKEN باید در ورکر تنظیم شده باشد." }), {
          status: 400, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      try {
        await SetupService.setAdminVariable(env, request, newPassword);
        try {
          await env.DB.prepare("DELETE FROM settings WHERE key = 'ADMIN'").run();
        } catch (e) {}
        setPasswordOverride(newPassword);
        const newHash = await DbService.sha256(newPassword);
        await LogService.addLog(env, 'تغییر رمز عبور', 'رمز عبور پنل مدیریت تغییر کرد', getClientIp(request));
        return new Response(JSON.stringify({ success: true }), {
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Set-Cookie": "panel_session=" + newHash + "; Path=/; HttpOnly; Secure; SameSite=Lax"
          }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message || "خطا در تغییر رمز عبور" }), {
          status: 500, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }
    const authorized = await DbService.verifyApiAuth(request, env);
    if (!authorized) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), { 
        status: 401, headers: { "Content-Type": "application/json; charset=utf-8" } 
      });
    }
    if (url.pathname === '/api/dashboard' && request.method === 'GET') {
      const clientIp = getClientIp(request);
      const systemUser = await ensureSystemUser(env.DB);
      const [geo, cfReqs, subState, topRequestUsers] = await Promise.all([
        withTimeout(
          clientIp ? CdnProxyService.geoLookupSingle(clientIp).catch(function() { return null; }) : Promise.resolve(null),
          4500,
          null
        ),
        withTimeout(getWorkerRequestStats(env), 5500, { today: 0, total: 0, pending: pendingRequestCount }),
        withTimeout(resolveSubscriptionState(systemUser, env, { skipRemote: true }), 3000, { inactive: false, firstRemark: buildFirstRemark(), secondRemark: buildSecondRemark(systemUser) }),
        withTimeout(getTopRequestUsers(env, 3), 3000, [])
      ]);
      const requestUrl = new URL(request.url);
      const origin = requestUrl.origin;
      const host = requestUrl.hostname;
      const workerCfg = await WorkerConfigService.loadSettings(env);
      const subPath = workerCfg.subPagePath || WORKER_CONFIG_DEFAULTS.subPagePath;
      const nodeConfigs = await buildNodeTlsConfigLinks(systemUser, host, subState.inactive, env);
      return new Response(JSON.stringify({
        visitor: {
          ip: clientIp || '',
          city: geo?.city || '',
          country: geo?.country || '',
          countryCode: geo?.countryCode || '',
          region: geo?.region || '',
          isp: geo?.isp || '',
          lat: geo?.lat ?? null,
          lon: geo?.lon ?? null
        },
        requests: cfReqs,
        topRequestUsers,
        systemUser: {
          username: systemUser.username,
          subLink: origin + '/' + subPath + '/' + encodeURIComponent(systemUser.username),
          nodeConfigs
        }
      }), {
        headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
      });
    }
    if (url.pathname.startsWith('/api/connection-logs/')) {
      const logUsername = decodeURIComponent(url.pathname.slice('/api/connection-logs/'.length));
      if (!logUsername) {
        return new Response(JSON.stringify({ error: "نام کاربری اجباری است" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
      }
      const logUser = await env.DB.prepare("SELECT username FROM users WHERE username = ? OR uuid = ?").bind(logUsername, logUsername).first();
      if (!logUser) {
        return new Response(JSON.stringify({ error: "کاربر یافت نشد" }), { status: 404, headers: { "Content-Type": "application/json; charset=utf-8" } });
      }
      if (request.method === 'GET') {
        const logs = await ConnectionLogService.getLogs(env, logUser.username);
        return new Response(JSON.stringify({ logs, username: logUser.username }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      if (request.method === 'DELETE') {
        await ConnectionLogService.clearLogs(env, logUser.username);
        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }
    if (url.pathname === '/api/clean-ips' && request.method === 'GET') {
      const forceRefresh = url.searchParams.get('refresh') === '1';
      const data = await CleanIpsService.fetch(env, forceRefresh);
      return new Response(JSON.stringify(data), {
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }
    if (url.pathname === '/api/scanner-candidates' && request.method === 'GET') {
      try {
        const sourceMode = await ScannerPoolService.getSourceMode(env);
        let ips = [];
        if (sourceMode === 'pool') {
          const poolIps = await ScannerPoolService.get(env);
          ips = poolIps.map(entry => entry.split(':')[0].trim()).filter(ip => isCleanListIpv4(ip));
        } else {
          ips = await SmartCleanIpsService.fetchScannerCandidates(request, env, 32);
          if (!ips.length) {
            const poolIps = await ScannerPoolService.get(env);
            ips = poolIps.map(entry => entry.split(':')[0].trim()).filter(ip => isCleanListIpv4(ip));
          }
        }
        return new Response(JSON.stringify({ ips }), {
          headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ ips: [], error: String(e.message || e) }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }
    if (url.pathname === '/api/whoami' && request.method === 'GET') {
      const cf = request.cf || {};
      return new Response(JSON.stringify({
        asn: cf.asn || 0,
        isp: cf.asOrganization || '',
        country: cf.country || '',
        city: cf.city || '',
        carrier: detectIranCarrier(request),
        ip: getClientIp(request) || ''
      }), {
        headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
      });
    }
    if (url.pathname === '/api/scanner-pool') {
      if (request.method === 'GET') {
        const ips = await ScannerPoolService.get(env);
        const sourceMode = await ScannerPoolService.getSourceMode(env);
        return new Response(JSON.stringify({
          ips,
          count: ips.length,
          source_mode: sourceMode,
          clean_ips_url: CleanIpsService.resolveUrl(env)
        }), {
          headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
        });
      }
      if (request.method === 'POST') {
        let body = {};
        try { body = await request.json(); } catch (e) {}
        let sourceMode = null;
        if (body.source_mode != null) {
          sourceMode = await ScannerPoolService.setSourceMode(env, body.source_mode);
        }
        let merged = null;
        if (body.ips != null || body.text != null) {
          merged = await ScannerPoolService.save(env, body.ips || body.text || '', body.merge !== false);
          await LogService.addLog(env, 'مخزن اسکنر IP', merged.length + ' آی‌پی در مخزن اسکنر پنل ذخیره شد', getClientIp(request));
        } else if (sourceMode) {
          merged = await ScannerPoolService.get(env);
        }
        if (merged == null) merged = await ScannerPoolService.get(env);
        if (sourceMode == null) sourceMode = await ScannerPoolService.getSourceMode(env);
        return new Response(JSON.stringify({
          success: true,
          ips: merged,
          count: merged.length,
          source_mode: sourceMode,
          clean_ips_url: CleanIpsService.resolveUrl(env)
        }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }
    if (url.pathname === '/api/panel-update-status' && request.method === 'GET') {
      try {
        const remote = await UpdateService.getStatus(env);
        const updateAvailable = !!(remote.version && !UpdateService.versionsMatch(remote.version, PANEL_VERSION));
        const allServicesOff = await PanelKillService.isAllServicesOff(env);
        return new Response(JSON.stringify({
          panelVersion: PANEL_VERSION,
          remoteVersion: remote.version || '',
          updateAvailable,
          updaterequired: !!remote.updaterequired,
          all_services_off: allServicesOff,
          announcement: remote.announcement || ''
        }), {
          headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
        });
      } catch (err) {
        return new Response(JSON.stringify({
          panelVersion: PANEL_VERSION,
          updateAvailable: false,
          updaterequired: false,
          all_services_off: false,
          announcement: '',
          error: err.message || 'خطا در بررسی به‌روزرسانی'
        }), {
          headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
        });
      }
    }
    if (url.pathname === '/api/update-panel' && request.method === 'POST') {
      try {
        const newCode = await UpdateService.fetchScript(env);
        const deployed = await deployPanelScript(env, request, newCode);
        managDataCache = { data: null, announcement: '', fetchedAt: 0 };
        await LogService.addLog(env, 'به‌روزرسانی پنل', 'نسخه جدید نصب شد (' + (deployed.scriptName || '') + ')', getClientIp(request));
        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      } catch (err) {
        const msg = err.message || 'خطا در به‌روزرسانی پنل';
        const cfTokenInvalid = isCfTokenAuthError(msg);
        return new Response(JSON.stringify({
          error: cfTokenInvalid ? 'توکن CF_TOKEN معتبر نیست. لطفاً توکن جدید وارد کنید.' : msg,
          cf_token_invalid: cfTokenInvalid
        }), {
          status: 500, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }

    if (url.pathname === '/api/cf-credentials') {
      if (request.method === 'GET') {
        const cfToken = await DbService.getCfToken(env);
        const cfAccountId = await DbService.getCfAccountIdResolved(env, request);
        const tokenFromEnv = DbService.isCfTokenBound(env);
        return new Response(JSON.stringify({
          cf_token_set: !!(cfToken || tokenFromEnv),
          cf_token_from_env: tokenFromEnv,
          cf_account_id: cfAccountId || '',
          cf_account_id_auto: !!(cfAccountId && !(await DbService.getCfAccountId(env)))
        }), { headers: { "Content-Type": "application/json; charset=utf-8" } });
      }
      if (request.method === 'POST') {
        const body = await request.json();
        const cfToken = String(body.cf_token || '').trim();
        let cfAccountId = String(body.cf_account_id || '').trim();
        if (!cfToken) {
          return new Response(JSON.stringify({ error: 'توکن API کلودفلر را وارد کنید' }), {
            status: 400, headers: { "Content-Type": "application/json; charset=utf-8" }
          });
        }
        if (!cfAccountId) {
          try {
            const scriptName = getWorkerScriptName(env, request);
            cfAccountId = await resolveCfAccountId(cfToken, scriptName);
          } catch (e) {
            return new Response(JSON.stringify({ error: e.message || 'Account ID کلودفلر یافت نشد' }), {
              status: 400, headers: { "Content-Type": "application/json; charset=utf-8" }
            });
          }
        }
        try {
          await SetupService.setCfCredentials(env, request, cfToken, cfAccountId);
          await LogService.addLog(env, 'تغییر تنظیمات CF', 'CF_TOKEN و CF_AC_ID به‌روزرسانی شد', getClientIp(request));
          return new Response(JSON.stringify({ success: true }), {
            headers: { "Content-Type": "application/json; charset=utf-8" }
          });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message || 'خطا در ذخیره تنظیمات Cloudflare' }), {
            status: 500, headers: { "Content-Type": "application/json; charset=utf-8" }
          });
        }
      }
    }
    if (url.pathname === '/locations') {
      try {
        const response = await fetch('https://speed.cloudflare.com/locations', {
          headers: { 'Referer': 'https://speed.cloudflare.com/' }
        });
        const data = await response.json();
        return new Response(JSON.stringify(data), {
          headers: { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }
    if (url.pathname === '/api/proxy-public-list') {
      const mode = ['proxyip', 'socks5', 'http', 'https'].includes(String(url.searchParams.get('mode') || '').toLowerCase())
        ? String(url.searchParams.get('mode')).toLowerCase()
        : 'proxyip';
      try {
        const data = await CdnProxyService.fetchPublicProxyList(mode);
        return new Response(JSON.stringify({ success: true, mode, data }), {
          headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "public, max-age=1800" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ success: false, error: e.message || 'fetch failed' }), {
          status: 500,
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }
    if (url.pathname === '/api/proxy-ip') {
      if (request.method === 'POST') {
        const body = await request.json();
        const oldSettings = await CdnProxyService.loadSettings(env);
        const saved = await CdnProxyService.saveSettings(env, body);
        const changes = getProxySettingsChanges(oldSettings, body);
        const logDetails = formatProxySettingsLogDetails(changes);
        await LogService.addLog(env, 'تغییر تنظیمات پروکسی CDN', logDetails, getClientIp(request));
        return new Response(JSON.stringify({
          success: true,
          changes,
          message: logDetails,
          settings: {
            mode: saved.mode,
            proxy_ip: saved.proxy_ip || 'auto',
            proxy_ips: saved.proxy_ips,
            chain_proxy: saved.chain_proxy || '',
            socks5_rotate_every: saved.socks5_rotate_every || '',
            socks5_rotate_count: saved.socks5_rotate_count || 3,
            default_proxy_ips: saved.defaultProxyIPs || FALLBACK_PROXY_HOSTS
          }
        }), { headers: { "Content-Type": "application/json" } });
      }
      if (request.method === 'GET') {
        const settings = await CdnProxyService.loadSettings(env);
        return new Response(JSON.stringify({
          mode: settings.mode || 'proxyip',
          proxy_ip: settings.proxy_ip || 'auto',
          proxy_ips: settings.proxy_ips,
          chain_proxy: settings.chain_proxy || '',
          socks5_rotate_every: settings.socks5_rotate_every || '',
          socks5_rotate_count: settings.socks5_rotate_count || 3,
          default_proxy_ips: settings.defaultProxyIPs || FALLBACK_PROXY_HOSTS
        }), { headers: { "Content-Type": "application/json" } });
      }
    }
    if (url.pathname === '/api/proxy-check') {
      const mode = ['proxyip', 'socks5', 'http', 'https', 'turn', 'sstp'].find(t => url.searchParams.has(t)) || 'proxyip';
      const value = url.searchParams.get(mode) || '';
      if (!String(value).trim()) {
        return new Response(JSON.stringify({ success: false, error: 'پارامتر پروکسی موجود نیست' }), {
          status: 400, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      if (mode === 'proxyip') {
        if (CdnProxyService.isAutoProxy(value)) {
          return new Response(JSON.stringify({
            success: true,
            message: 'حالت auto — از پول پیش‌فرض CDN استفاده می‌شود'
          }), { headers: { "Content-Type": "application/json; charset=utf-8" } });
        }
        try {
          const resolved = await CdnProxyService.resolveProxyAddresses(value);
          return new Response(JSON.stringify({
            success: resolved.length > 0,
            ip: resolved[0]?.[0] || null,
            count: resolved.length,
            message: resolved.length ? `${resolved.length} آدرس یافت شد` : 'آدرسی یافت نشد'
          }), { headers: { "Content-Type": "application/json; charset=utf-8" } });
        } catch (e) {
          return new Response(JSON.stringify({ success: false, error: e.message }), {
            status: 500, headers: { "Content-Type": "application/json; charset=utf-8" }
          });
        }
      }
      return new Response(JSON.stringify({
        success: false,
        error: 'بررسی ' + mode.toUpperCase() + ' هنوز در Nexa پشتیبانی نمی‌شود — فقط ذخیره می‌شود'
      }), { status: 501, headers: { "Content-Type": "application/json; charset=utf-8" } });
    }
    if (url.pathname === '/api/network-settings') {
      if (request.method === 'GET') {
        const settings = await NetworkSettingsService.loadSettings(env);
        return new Response(JSON.stringify({ settings, defaults: NetworkSettingsService.getDefaults(), profiles: NetworkSettingsService.getProfiles() }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      if (request.method === 'POST') {
        const body = await request.json();
        const saved = await NetworkSettingsService.saveSettings(env, body);
        await LogService.addLog(env, 'تغییر سیاست مقاومت', 'تنظیمات شبکه و پروفایل مقاومت به‌روزرسانی شد', getClientIp(request));
        return new Response(JSON.stringify({ success: true, settings: saved }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }
    if (url.pathname === '/api/worker-config') {
      if (request.method === 'GET') {
        const settings = await WorkerConfigService.loadSettings(env);
        return new Response(JSON.stringify({ settings, defaults: WorkerConfigService.getDefaults(), lockedFirstRemark: FREE_SERVICE_NOTICE }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      if (request.method === 'POST') {
        const body = await request.json();
        const newAdminPath = WorkerConfigService.cleanPathSegment(body.adminPagePath) || WORKER_CONFIG_DEFAULTS.adminPagePath;
        const newStatusPath = WorkerConfigService.cleanPathSegment(body.statusPagePath) || WORKER_CONFIG_DEFAULTS.statusPagePath;
        const newSubPath = WorkerConfigService.cleanPathSegment(body.subPagePath) || WORKER_CONFIG_DEFAULTS.subPagePath;
        const newLogsPath = WorkerConfigService.cleanPathSegment(body.logsPagePath) || WORKER_CONFIG_DEFAULTS.logsPagePath;
        const reservedPaths = ['api', 'setup', 'login', 'guide', 'locations', 'my-ip'];
        const allPaths = [newAdminPath, newStatusPath, newSubPath, newLogsPath];
        const hasDuplicate = new Set(allPaths).size !== allPaths.length;
        const hasReserved = allPaths.some(p => reservedPaths.includes(p));
        if (hasDuplicate || hasReserved) {
          return new Response(JSON.stringify({ error: "آدرس پنل مدیریت، صفحه وضعیت، ساب و لاگ‌ها باید با هم و با مسیرهای رزرو شده (api, setup, login, guide) متفاوت باشند" }), {
            status: 400, headers: { "Content-Type": "application/json; charset=utf-8" }
          });
        }
        const saved = await WorkerConfigService.saveSettings(env, body);
        await LogService.addLog(env, 'تغییر تنظیمات ورکر', 'پروتکل، اشتراک و نام کانفیگ‌ها به‌روزرسانی شد', getClientIp(request));
        return new Response(JSON.stringify({ success: true, settings: saved }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }
    if (url.pathname === '/api/blocked-domains') {
      if (request.method === 'POST') {
        const body = await request.json();
        await DomainBlockService.saveSettings(env, body);
        const settings = await DomainBlockService.getSettings(env);
        const logDetails = (settings.enabled ? 'فعال — ' : 'غیرفعال — ') + settings.domains.length + ' دامنه';
        await LogService.addLog(env, 'تغییر مسدودسازی دامنه', logDetails, getClientIp(request));
        return new Response(JSON.stringify({ success: true, enabled: settings.enabled, domains: settings.domains }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      if (request.method === 'GET') {
        const settings = await DomainBlockService.getSettings(env);
        return new Response(JSON.stringify({ enabled: settings.enabled, domains: settings.domains }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }
    if (url.pathname === '/api/content-policy') {
      if (request.method === 'GET') {
        const settings = await ContentPolicyService.getSettings(env);
        return new Response(JSON.stringify(settings), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      if (request.method === 'POST') {
        const body = await request.json();
        await ContentPolicyService.saveSettings(env, body);
        const details = body.adultBlockEnabled ? 'مسدودسازی بزرگسال: فعال' : 'مسدودسازی بزرگسال: غیرفعال';
        await LogService.addLog(env, 'تغییر فیلترهای محتوایی', details, getClientIp(request));
        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }
    if (url.pathname === '/api/logs' && request.method === 'GET') {
      const logs = await LogService.getLogs(env);
      return new Response(JSON.stringify({ logs }), {
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }
    if (url.pathname === '/api/logs' && request.method === 'DELETE') {
      await LogService.clearLogs(env, getClientIp(request));
      return new Response(JSON.stringify({ success: true }), {
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }
    if (url.pathname === '/api/telegram-notify' && request.method === 'GET') {
      const settings = await TelegramNotifyService.getSettings(env);
      return new Response(JSON.stringify(settings), {
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }
    if (url.pathname === '/api/all-services-off' && request.method === 'GET') {
      const enabled = await PanelKillService.isAllServicesOff(env);
      return new Response(JSON.stringify({ enabled }), {
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }
    if (url.pathname === '/api/all-services-off' && request.method === 'POST') {
      const body = await request.json();
      const enabled = !!body.enabled;
      await PanelKillService.setAllServicesOff(env, enabled);
      if (!body.quiet) {
        await LogService.addLog(env, 'قطع تمامی سرویس‌ها', enabled ? 'فعال شد — تمام سرویس‌ها قطع شدند' : 'غیرفعال شد — سرویس‌ها مجدداً فعال شدند', getClientIp(request));
      }
      return new Response(JSON.stringify({ success: true, enabled }), {
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }
    if (url.pathname === '/api/panel-disabled' && request.method === 'GET') {
      const enabled = await PanelDisableService.isPanelDisabled(env);
      return new Response(JSON.stringify({ enabled }), { headers: { "Content-Type": "application/json; charset=utf-8" } });
    }
    if (url.pathname === '/api/panel-disabled' && request.method === 'POST') {
      const body = await request.json();
      const enabled = !!body.enabled;
      await PanelDisableService.setPanelDisabled(env, enabled);
      await LogService.addLog(env, 'خاموش/روشن کردن پنل', enabled ? 'پنل مدیریت غیرفعال شد' : 'پنل مدیریت مجدداً فعال شد', getClientIp(request));
      return new Response(JSON.stringify({ success: true, enabled }), { headers: { "Content-Type": "application/json; charset=utf-8" } });
    }
    if (url.pathname === '/api/panel-restart' && request.method === 'POST') {
      const startedAt = await PanelUptimeService.reset(env);
      trafficByteCache.clear(); activeConnCountByUser.clear(); lastActiveWriteAt.clear();
      lastDbWriteAt.clear(); dbWriteLock.clear(); dnsAnswerCache.clear();
      await LogService.addLog(env, 'ری‌استارت پنل', 'شمارشگر آپتایم و کش‌های موقت پاک‌سازی شد', getClientIp(request));
      return new Response(JSON.stringify({ success: true, started_at: startedAt }), { headers: { "Content-Type": "application/json; charset=utf-8" } });
    }
    if (url.pathname === '/api/telegram-notify' && request.method === 'POST') {
      const body = await request.json();
      await TelegramNotifyService.saveSettings(env, body);
      if (!body.quiet) {
        await LogService.addLog(env, 'تنظیم اعلان تلگرام', body.enabled ? 'فعال شد' : 'غیرفعال شد', getClientIp(request));
      }
      return new Response(JSON.stringify({ success: true }), {
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }
    if (url.pathname === '/api/backup' && request.method === 'GET') {
      const backup = await BackupService.build(env);
      const filename = 'nexa-backup-' + new Date().toISOString().slice(0, 10) + '.json';
      const meta = backup.meta || {};
      await LogService.addLog(env, 'بکاپ پنل', 'دریافت بکاپ (' + (meta.users_count || 0) + ' کاربر، ' + (meta.settings_count || 0) + ' تنظیم)', getClientIp(request));
      return new Response(JSON.stringify(backup, null, 2), {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Content-Disposition": 'attachment; filename="' + filename + '"'
        }
      });
    }
    if (url.pathname === '/api/backup-settings' && request.method === 'GET') {
      const settings = await BackupService.getAutoSettings(env);
      return new Response(JSON.stringify(settings), {
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }
    if (url.pathname === '/api/backup-settings' && request.method === 'POST') {
      const body = await request.json();
      await BackupService.saveAutoSettings(env, body);
      if (!body.quiet) {
        await LogService.addLog(env, 'تنظیم بکاپ خودکار', body.auto_enabled ? 'فعال شد — ارسال روزانه ساعت ۰۰:۰۰' : 'غیرفعال شد', getClientIp(request));
      }
      return new Response(JSON.stringify({ success: true }), {
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }
    if (url.pathname === '/api/backup/send-telegram' && request.method === 'POST') {
      try {
        const tg = await TelegramNotifyService.getSettings(env);
        const backup = await BackupService.build(env);
        const json = JSON.stringify(backup, null, 2);
        const filename = 'nexa-backup-' + BackupService.getTehranDateKey() + '.json';
        await BackupService.sendToTelegram(tg, filename, json);
        await LogService.addLog(env, 'بکاپ تلگرام', 'ارسال دستی بکاپ به تلگرام (' + (backup.meta?.users_count || 0) + ' کاربر)', getClientIp(request));
        return new Response(JSON.stringify({ success: true, users_count: backup.meta?.users_count || 0 }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message || 'خطا در ارسال بکاپ به تلگرام' }), {
          status: 400, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }
    if (url.pathname === '/api/restore' && request.method === 'POST') {
      let body;
      try {
        body = await request.json();
      } catch (e) {
        return new Response(JSON.stringify({ error: "فرمت فایل بکاپ نامعتبر است" }), {
          status: 400, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      try {
        const result = await BackupService.restore(env, body);
        await LogService.addLog(env, 'بازیابی بکاپ', 'بازیابی بکاپ (' + result.users_count + ' کاربر)', getClientIp(request));
        return new Response(JSON.stringify({ success: true, users_count: result.users_count }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      } catch (err) {
        const status = err.message && err.message.includes('فرمت بکاپ') ? 400 : 500;
        return new Response(JSON.stringify({ error: err.message || "خطا در بازیابی بکاپ" }), {
          status, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }
    if (url.pathname === '/api/reset-panel' && request.method === 'POST') {
      try {
        try { await flushExpiredTraffic(env); } catch (e) {}
        await env.DB.prepare("DELETE FROM users").run();
        systemUserCache = { user: null, fetchedAt: 0 };
        await ensureSystemUser(env.DB);
        await env.DB.prepare("DELETE FROM settings WHERE key != 'ADMIN'").run();
        await env.DB.prepare("DELETE FROM panel_logs").run();
        await env.DB.prepare("DELETE FROM connection_logs").run();
        trafficByteCache.clear();
        activeConnCountByUser.clear();
        lastActiveWriteAt.clear();
        lastDbWriteAt.clear();
        dbWriteLock.clear();
        await LogService.addLog(env, 'بازنشانی پنل', 'بازنشانی تمام تنظیمات پنل', getClientIp(request));
        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message || "خطا در بازنشانی پنل" }), {
          status: 500, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }
    if (url.pathname === '/api/users/bulk' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) {
        return new Response(JSON.stringify({ error: "فرمت درخواست نامعتبر است" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
      }
      const usernames = [...new Set((body.usernames || []).map(u => String(u).trim()).filter(Boolean))];
      if (!usernames.length) {
        return new Response(JSON.stringify({ error: "هیچ کاربری انتخاب نشده است" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
      }
      if (!body.action) {
        return new Response(JSON.stringify({ error: "نوع عملیات مشخص نشده است" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
      }
      if (body.action === 'update') {
        const apply = body.apply || {};
        if (!Object.values(apply).some(Boolean)) {
          return new Response(JSON.stringify({ error: "حداقل یک فیلد برای ویرایش انتخاب کنید" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
        }
        if (apply.port && !(body.updates?.port || '').trim()) {
          return new Response(JSON.stringify({ error: "حداقل یک پورت انتخاب کنید" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
        }
      }
      const actionLabels = {
        delete: 'حذف گروهی',
        activate: 'فعال‌سازی گروهی',
        deactivate: 'قطع گروهی',
        reset_volume: 'ریست حجم گروهی',
        reset_time: 'ریست زمان گروهی',
        reset_requests: 'ریست ریکوئست کل گروهی',
        enable_save: 'ذخیره گروهی',
        update: 'ویرایش گروهی'
      };
      try {
        const { processed, errors } = await applyBulkUserAction(env, usernames, body);
        await LogService.addLog(env, actionLabels[body.action] || 'عملیات گروهی', usernames.length + ' انتخاب | ' + processed + ' موفق' + (errors.length ? ' | ' + errors.length + ' خطا' : ''), getClientIp(request));
        return new Response(JSON.stringify({ success: true, processed, failed: errors.length, errors }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message || "خطا در عملیات گروهی" }), {
          status: 500, headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }
    if (url.pathname.startsWith('/api/users')) {
      const pathParts = url.pathname.split('/');
      const isUserAction = pathParts.length > 3; 
      if (isUserAction) {
        const username = decodeURIComponent(pathParts.pop());
        if (request.method === 'PUT') {
          const body = await request.json();
          if (body.toggle_only !== undefined) {
            const oldUser = await env.DB.prepare("SELECT is_active, is_system, username FROM users WHERE username = ?").bind(username).first();
            await env.DB.prepare(
              "UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE username = ?"
            ).bind(username).run();
            const newState = oldUser?.is_active ? 'غیرفعال' : 'فعال';
            await LogService.addLog(env, 'تغییر وضعیت کاربر', 'کاربر: ' + username + ' | وضعیت: ' + newState, getClientIp(request));
            return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
          }
          if (body.save_only !== undefined) {
            const oldUser = await env.DB.prepare("SELECT is_saved, is_system, username FROM users WHERE username = ?").bind(username).first();
            if (isSystemUser(oldUser)) {
              return new Response(JSON.stringify({ error: "سرویس اصلی همیشه ذخیره است" }), { status: 403, headers: { "Content-Type": "application/json" } });
            }
            await env.DB.prepare(
              "UPDATE users SET is_saved = CASE WHEN is_saved = 1 THEN 0 ELSE 1 END WHERE username = ?"
            ).bind(username).run();
            const newState = oldUser?.is_saved ? 'حذف از ذخیره' : 'ذخیره';
            await LogService.addLog(env, 'تغییر ذخیره کاربر', 'کاربر: ' + username + ' | ' + newState, getClientIp(request));
            return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
          }
          if (body.reset_time || body.reset_volume) {
            const targetUser = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
            if (isSystemUser(targetUser)) {
              return new Response(JSON.stringify({ error: "ریست حجم یا زمان سرویس اصلی مجاز نیست" }), { status: 403, headers: { "Content-Type": "application/json" } });
            }
            const parts = [];
            const logParts = [];
            if (body.reset_volume) {
              parts.push('used_gb = 0', 'expired_at = NULL');
              logParts.push('ریست حجم');
            }
            if (body.reset_time) {
              parts.push("created_at = datetime('now')", 'expired_at = NULL');
              logParts.push('ریست زمان');
            }
            parts.push('is_active = 1');
            await env.DB.prepare(
              'UPDATE users SET ' + parts.join(', ') + ' WHERE username = ?'
            ).bind(username).run();
            await LogService.addLog(env, 'ریست سرویس کاربر', 'کاربر: ' + username + ' | ' + logParts.join(' + '), getClientIp(request));
            return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
          }
          const oldUser = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
          if (isSystemUser(oldUser)) {
            const { ips, tls, port, proxy_ip, fingerprint } = body;
            if (!port || !String(port).trim()) {
              return new Response(JSON.stringify({ error: "حداقل یک پورت انتخاب کنید" }), { status: 400, headers: { "Content-Type": "application/json" } });
            }
            await env.DB.prepare(
              "UPDATE users SET limit_gb = NULL, expiry_days = NULL, max_requests = NULL, max_requests_daily = NULL, ips = ?, tls = ?, port = ?, proxy_ip = ?, fingerprint = ?, is_saved = 1, expired_at = NULL WHERE username = ?"
            ).bind(
              normalizeCleanIpsFieldForUpdate(ips),
              tls,
              port,
              proxy_ip ? String(proxy_ip).trim() || null : null,
              fingerprint || 'chrome',
              username
            ).run();
            await LogService.addLog(env, 'ویرایش سرویس اصلی', buildUserEditLogDetails(oldUser, { ips, tls, port, proxy_ip, fingerprint }), getClientIp(request));
            return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
          }
          let targetUsername = username;
          const requestedName = body.username ? String(body.username).trim() : '';
          if (requestedName && requestedName !== username) {
            const renameResult = await renameUserService(env.DB, username, requestedName);
            if (!renameResult.ok) {
              return new Response(JSON.stringify({ error: renameResult.error }), {
                status: 409, headers: { "Content-Type": "application/json; charset=utf-8" }
              });
            }
            targetUsername = renameResult.username;
          }
          const { limit_gb, expiry_days, ips, tls, port, fingerprint, max_requests: maxReqBody, max_requests_daily, max_connections, proxy_ip } = body;
          const max_requests = maxReqBody ?? max_connections;
          await env.DB.prepare(
            "UPDATE users SET limit_gb = ?, expiry_days = ?, ips = ?, tls = ?, port = ?, fingerprint = ?, max_requests = ?, max_requests_daily = ?, proxy_ip = ?, expired_at = NULL WHERE username = ?"
          ).bind(
            limit_gb ? parseFloat(limit_gb) : null, 
            expiry_days ? parseInt(expiry_days) : null, 
            normalizeCleanIpsFieldForUpdate(ips), 
            tls, 
            port, 
            fingerprint || 'chrome',
            max_requests ? parseInt(max_requests) : null,
            max_requests_daily ? parseInt(max_requests_daily) : null,
            proxy_ip ? String(proxy_ip).trim() || null : null,
            targetUsername
          ).run();
          const logDetails = buildUserEditLogDetails(oldUser, body);
          await LogService.addLog(env, 'ویرایش کاربر', logDetails, getClientIp(request));
          return new Response(JSON.stringify({ success: true, username: targetUsername }), { headers: { "Content-Type": "application/json" } });
        }
        if (request.method === 'DELETE') {
          const targetUser = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
          if (isSystemUser(targetUser)) {
            return new Response(JSON.stringify({ error: "این کاربر سیستمی است و قابل حذف نیست" }), { status: 403, headers: { "Content-Type": "application/json" } });
          }
          await env.DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
          await LogService.addLog(env, 'حذف کاربر', 'کاربر: ' + username, getClientIp(request));
          return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
        }
      } else {
        if (request.method === 'GET') {
          try {
            await flushExpiredTraffic(env);
            await syncExpiredUsersStatus(env);
            await purgeExpiredUsers(env);
          } catch (e) {}
          const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY id DESC").all();
          const now = Date.now();
          const enrichedUsers = (results || []).map(user => ({
            ...user,
            is_online: (user.last_active && (now - user.last_active) < 65000) ? 1 : 0,
            used_requests_total: getUserReqUsageTotal(user, user.username),
            used_requests_today: getUserReqUsageToday(user, user.username)
          }));
          let cfReqs = await getWorkerRequestStats(env);
          return new Response(JSON.stringify({ 
              users: enrichedUsers, 
              serverTime: now,
              cfRequestsToday: cfReqs.today,
              cfRequestsTotal: cfReqs.total
          }), {
            headers: { 
              "Content-Type": "application/json", 
              "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0" 
            }
          });
        }
        if (request.method === 'POST') {
          const { username, limit_gb, expiry_days, ips, tls, port, fingerprint, max_requests: maxReqBody, max_requests_daily, max_connections, proxy_ip } = await request.json();
          const max_requests = maxReqBody ?? max_connections;
          if (!username) {
            return new Response(JSON.stringify({ error: "نام کاربری اجباری است" }), { status: 400, headers: { "Content-Type": "application/json" } });
          }
          const existingUser = await env.DB.prepare("SELECT username FROM users WHERE username = ?").bind(username).first();
          if (existingUser) {
            return new Response(JSON.stringify({ error: "همچین کاربری با این نام وجود داره" }), { status: 409, headers: { "Content-Type": "application/json" } });
          }
          const uuid = crypto.randomUUID();
          try {
            await env.DB.prepare(
              "INSERT INTO users (username, uuid, limit_gb, expiry_days, ips, connection_type, tls, port, fingerprint, max_requests, max_requests_daily, proxy_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            ).bind(
              username, 
              uuid,
              limit_gb ? parseFloat(limit_gb) : null, 
              expiry_days ? parseInt(expiry_days) : null, 
              normalizeCleanIpsField(ips), 
              atob('dmxlc3M='), 
              tls, 
              port,
              fingerprint || 'chrome',
              max_requests ? parseInt(max_requests) : null,
              max_requests_daily ? parseInt(max_requests_daily) : null,
              proxy_ip ? String(proxy_ip).trim() || null : null
            ).run();
            await StatusUrlService.assignStatusSlug(env.DB, username);
            await LogService.addLog(env, 'ساخت کاربر', buildUserCreateLogDetails(username, { limit_gb, expiry_days, tls, port, max_requests, max_requests_daily, proxy_ip }), getClientIp(request));
            return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
          } catch (err) {
            const isDuplicateUsername = /UNIQUE constraint failed:\s*users\.username/i.test(String(err?.message || ''));
            return new Response(JSON.stringify({ error: friendlyDbError(err) }), {
              status: isDuplicateUsername ? 409 : 500,
              headers: { "Content-Type": "application/json" }
            });
          }
        }
      }
    }
    return new Response(JSON.stringify({ error: "Not Found" }), { status: 404, headers: { "Content-Type": "application/json" } });
  }
};
function getClientIp(request) {
  return request.headers.get('CF-Connecting-IP')
    || request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim()
    || '';
}
function friendlyDbError(err) {
  const msg = String(err?.message || '');
  if (/UNIQUE constraint failed:\s*users\.username/i.test(msg)) {
    return 'همچین کاربری با این نام وجود داره';
  }
  return msg || 'خطا در عملیات';
}
async function renameUserService(db, oldUsername, newUsername) {
  const oldName = String(oldUsername || '').trim();
  const newName = String(newUsername || '').trim();
  if (!oldName || !newName || oldName === newName) {
    return { ok: true, username: oldName };
  }
  const existing = await db.prepare("SELECT username FROM users WHERE username = ?").bind(newName).first();
  if (existing) {
    return { ok: false, error: 'همچین کاربری با این نام وجود داره' };
  }
  await db.prepare("UPDATE users SET username = ?, status_slug = ? WHERE username = ?").bind(newName, newName, oldName).run();
  await db.prepare("UPDATE connection_logs SET username = ? WHERE username = ?").bind(newName, oldName).run();
  return { ok: true, username: newName };
}
function formatLogValue(value, suffix = '') {
  if (value == null || value === '') return 'نامحدود';
  return String(value) + suffix;
}
function buildUserEditLogDetails(oldUser, body) {
  if (!oldUser) return 'کاربر: ' + (body.username || 'نامشخص');
  const parts = ['کاربر: ' + oldUser.username];
  const newName = body.username ? String(body.username).trim() : '';
  if (newName && newName !== oldUser.username) {
    parts.push('نام: ' + oldUser.username + ' → ' + newName);
  }
  const newLimit = body.limit_gb ? parseFloat(body.limit_gb) : null;
  const oldLimit = oldUser.limit_gb != null ? parseFloat(oldUser.limit_gb) : null;
  if (newLimit !== oldLimit) {
    parts.push('حجم: ' + formatLogValue(oldLimit, ' GB') + ' → ' + formatLogValue(newLimit, ' GB'));
  }
  const newExpiry = body.expiry_days ? parseInt(body.expiry_days) : null;
  const oldExpiry = oldUser.expiry_days != null ? parseInt(oldUser.expiry_days) : null;
  if (newExpiry !== oldExpiry) {
    parts.push('انقضا: ' + formatLogValue(oldExpiry, ' روز') + ' → ' + formatLogValue(newExpiry, ' روز'));
  }
  const newTls = body.tls || null;
  const oldTls = oldUser.tls || null;
  if (newTls !== oldTls) parts.push('TLS: ' + (oldTls || '-') + ' → ' + (newTls || '-'));
  const newPort = body.port || null;
  const oldPort = oldUser.port || null;
  if (newPort !== oldPort) parts.push('پورت: ' + (oldPort || '-') + ' → ' + (newPort || '-'));
  const newFp = body.fingerprint || 'random';
  const oldFp = oldUser.fingerprint || 'random';
  if (newFp !== oldFp) parts.push('Fingerprint: ' + oldFp + ' → ' + newFp);
  const newMax = body.max_requests ? parseInt(body.max_requests) : null;
  const oldMax = oldUser.max_requests != null ? parseInt(oldUser.max_requests) : null;
  if (newMax !== oldMax) {
    parts.push('ریکوئست کل: ' + formatLogValue(oldMax) + ' → ' + formatLogValue(newMax));
  }
  const newMaxDaily = body.max_requests_daily ? parseInt(body.max_requests_daily) : null;
  const oldMaxDaily = oldUser.max_requests_daily != null ? parseInt(oldUser.max_requests_daily) : null;
  if (newMaxDaily !== oldMaxDaily) {
    parts.push('ریکوئست روزانه: ' + formatLogValue(oldMaxDaily) + ' → ' + formatLogValue(newMaxDaily));
  }
  const newProxy = body.proxy_ip ? String(body.proxy_ip).trim() || null : null;
  const oldProxy = oldUser.proxy_ip ? String(oldUser.proxy_ip).trim() || null : null;
  if (newProxy !== oldProxy) parts.push('Proxy IP: ' + (oldProxy || '-') + ' → ' + (newProxy || '-'));
  const newIps = body.ips || null;
  const oldIps = oldUser.ips || null;
  if (newIps !== oldIps) parts.push('IPها تغییر کرد');
  if (parts.length === 1) parts.push('بدون تغییر مشخص');
  return parts.join(' | ');
}
const TLS_PORT_LIST = ['443', '2053', '2083', '2087', '2096', '8443'];
async function applyBulkUserAction(env, usernames, body) {
  const action = body.action;
  const updates = body.updates || {};
  const apply = body.apply || {};
  let processed = 0;
  const errors = [];
  for (const username of usernames) {
    try {
      const targetUser = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
      if (isSystemUser(targetUser)) {
        errors.push({ username, error: 'عملیات روی سرویس اصلی مجاز نیست' });
        continue;
      }
      if (action === 'delete') {
        await env.DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
      } else if (action === 'activate') {
        await env.DB.prepare("UPDATE users SET is_active = 1 WHERE username = ?").bind(username).run();
      } else if (action === 'deactivate') {
        await env.DB.prepare("UPDATE users SET is_active = 0 WHERE username = ?").bind(username).run();
      } else if (action === 'reset_volume') {
        await env.DB.prepare("UPDATE users SET used_gb = 0, expired_at = NULL, is_active = 1 WHERE username = ?").bind(username).run();
      } else if (action === 'reset_time') {
        await env.DB.prepare("UPDATE users SET created_at = datetime('now'), expired_at = NULL, is_active = 1 WHERE username = ?").bind(username).run();
      } else if (action === 'reset_requests') {
        userRequestPending.set(username, 0);
        await env.DB.prepare("UPDATE users SET used_requests = 0, is_active = 1 WHERE username = ?").bind(username).run();
      } else if (action === 'enable_save') {
        await env.DB.prepare("UPDATE users SET is_saved = 1 WHERE username = ?").bind(username).run();
      } else if (action === 'update') {
        const sets = [];
        const binds = [];
        if (apply.limit_gb) {
          sets.push('limit_gb = ?');
          binds.push(updates.limit_gb !== '' && updates.limit_gb != null ? parseFloat(updates.limit_gb) : null);
        }
        if (apply.expiry_days) {
          sets.push('expiry_days = ?');
          binds.push(updates.expiry_days !== '' && updates.expiry_days != null ? parseInt(updates.expiry_days) : null);
        }
        if (apply.max_requests) {
          sets.push('max_requests = ?');
          binds.push(updates.max_requests !== '' && updates.max_requests != null ? parseInt(updates.max_requests) : null);
        }
        if (apply.max_requests_daily) {
          sets.push('max_requests_daily = ?');
          binds.push(updates.max_requests_daily !== '' && updates.max_requests_daily != null ? parseInt(updates.max_requests_daily) : null);
        }
        if (apply.ips) {
          sets.push('ips = ?');
          binds.push(normalizeCleanIpsFieldForUpdate(updates.ips));
        }
        if (apply.proxy_ip) {
          sets.push('proxy_ip = ?');
          binds.push(updates.proxy_ip ? String(updates.proxy_ip).trim() || null : null);
        }
        if (apply.port) {
          const portStr = updates.port || '443';
          const ports = String(portStr).split(',').map(p => p.trim()).filter(Boolean);
          sets.push('port = ?', 'tls = ?');
          binds.push(portStr, ports.some(p => TLS_PORT_LIST.includes(p)) ? 'on' : 'off');
        }
        if (apply.fingerprint) {
          sets.push('fingerprint = ?');
          binds.push(updates.fingerprint || 'chrome');
        }
        if (sets.length) {
          sets.push('expired_at = NULL');
          binds.push(username);
          await env.DB.prepare('UPDATE users SET ' + sets.join(', ') + ' WHERE username = ?').bind(...binds).run();
        }
      } else {
        throw new Error('عملیات نامعتبر');
      }
      processed++;
    } catch (e) {
      errors.push({ username, error: e.message });
    }
  }
  return { processed, errors };
}
function buildUserCreateLogDetails(username, fields) {
  const parts = ['کاربر: ' + username];
  if (fields.limit_gb) parts.push('حجم: ' + fields.limit_gb + ' GB');
  if (fields.expiry_days) parts.push('انقضا: ' + fields.expiry_days + ' روز');
  if (fields.tls) parts.push('TLS: ' + fields.tls);
  if (fields.port) parts.push('پورت: ' + fields.port);
  if (fields.max_requests) parts.push('ریکوئست کل: ' + fields.max_requests);
  if (fields.max_requests_daily) parts.push('ریکوئست روزانه: ' + fields.max_requests_daily);
  if (fields.proxy_ip) parts.push('Proxy IP: ' + String(fields.proxy_ip).trim());
  return parts.join(' | ');
}
function formatLimitGb(value) {
  return value != null && value !== '' ? parseFloat(value) + ' GB' : 'نامحدود';
}
function formatUserEditLogDetails(oldUser, body) {
  const parts = ['کاربر: ' + oldUser.username];
  const newLimit = body.limit_gb ? parseFloat(body.limit_gb) : null;
  const oldLimit = oldUser.limit_gb != null ? parseFloat(oldUser.limit_gb) : null;
  if (newLimit !== oldLimit) {
    parts.push('حجم: ' + formatLimitGb(oldLimit) + ' ← ' + formatLimitGb(newLimit));
  }
  const newExpiry = body.expiry_days ? parseInt(body.expiry_days) : null;
  const oldExpiry = oldUser.expiry_days != null ? parseInt(oldUser.expiry_days) : null;
  if (newExpiry !== oldExpiry) {
    const fmt = v => v != null ? v + ' روز' : 'نامحدود';
    parts.push('انقضا: ' + fmt(oldExpiry) + ' ← ' + fmt(newExpiry));
  }
  const newIps = body.ips || null;
  const oldIps = oldUser.ips || null;
  if (newIps !== oldIps) parts.push('IPها تغییر کرد');
  if (body.tls !== oldUser.tls) parts.push('TLS: ' + (oldUser.tls || '-') + ' ← ' + (body.tls || '-'));
  if (body.port !== oldUser.port) parts.push('پورت: ' + (oldUser.port || '-') + ' ← ' + (body.port || '-'));
  if ((body.fingerprint || 'random') !== (oldUser.fingerprint || 'random')) {
    parts.push('Fingerprint: ' + (oldUser.fingerprint || 'random') + ' ← ' + (body.fingerprint || 'random'));
  }
  const newMax = body.max_requests ? parseInt(body.max_requests) : null;
  const oldMax = oldUser.max_requests != null ? parseInt(oldUser.max_requests) : null;
  if (newMax !== oldMax) {
    const fmt = v => v != null ? String(v) : 'نامحدود';
    parts.push('ریکوئست کل: ' + fmt(oldMax) + ' ← ' + fmt(newMax));
  }
  const newMaxDaily = body.max_requests_daily ? parseInt(body.max_requests_daily) : null;
  const oldMaxDaily = oldUser.max_requests_daily != null ? parseInt(oldUser.max_requests_daily) : null;
  if (newMaxDaily !== oldMaxDaily) {
    const fmt = v => v != null ? String(v) : 'نامحدود';
    parts.push('ریکوئست روزانه: ' + fmt(oldMaxDaily) + ' ← ' + fmt(newMaxDaily));
  }
  const newProxy = body.proxy_ip ? String(body.proxy_ip).trim() || null : null;
  const oldProxy = oldUser.proxy_ip || null;
  if (newProxy !== oldProxy) parts.push('Proxy IP تغییر کرد');
  return parts.join(' | ');
}
function normalizeProxyListForCompare(value) {
  if (Array.isArray(value)) return value.map(s => String(s).trim()).filter(Boolean).join('\n');
  if (value == null || value === '') return '';
  return CdnProxyService.parseList(String(value)).join('\n');
}
function getProxySettingsChanges(oldSettings, body) {
  const changes = [];
  if (body.mode !== undefined && String(body.mode || 'proxyip') !== String(oldSettings.mode || 'proxyip')) {
    changes.push('mode');
  }
  if (body.proxy_ip !== undefined) {
    const oldIp = String(oldSettings.proxy_ip || 'auto').trim();
    const newIp = String(body.proxy_ip || 'auto').trim();
    if (oldIp !== newIp) changes.push('proxy_ip');
  }
  if (body.proxy_ips !== undefined) {
    const oldIps = normalizeProxyListForCompare(oldSettings.proxy_ips || oldSettings.proxy_ip || '');
    const newIps = normalizeProxyListForCompare(body.proxy_ips);
    if (oldIps !== newIps) changes.push('proxy_ips');
  }
  if (body.chain_proxy !== undefined && String(body.chain_proxy || '') !== String(oldSettings.chain_proxy || '')) {
    changes.push('chain_proxy');
  }
  return changes;
}
function formatProxySettingsLogDetails(changes) {
  const labels = {
    mode: 'حالت پروکسی CDN',
    proxy_ip: 'آدرس PROXYIP',
    proxy_ips: 'آدرس‌های Proxy IP (CDN)',
    chain_proxy: 'پروکسی زنجیره‌ای'
  };
  if (!changes.length) return 'تنظیمات پروکسی CDN ذخیره شد | بدون تغییر';
  return 'تنظیمات پروکسی CDN ذخیره شد | ' + changes.map(k => labels[k] || k).join('، ') + ' تغییر کرد';
}
function formatNewUserLogDetails(username, body) {
  const parts = ['کاربر: ' + username];
  if (body.limit_gb) parts.push('حجم: ' + body.limit_gb + ' GB');
  if (body.expiry_days) parts.push('انقضا: ' + body.expiry_days + ' روز');
  if (body.port) parts.push('پورت: ' + body.port);
  if (body.tls) parts.push('TLS: ' + body.tls);
  if (body.max_requests) parts.push('ریکوئست کل: ' + body.max_requests);
  if (body.max_requests_daily) parts.push('ریکوئست روزانه: ' + body.max_requests_daily);
  return parts.join(' | ');
}
let allServicesOffCache = { value: false, fetchedAt: 0 };
const ALL_SERVICES_OFF_CACHE_TTL = 30000;
const PANEL_STARTED_AT_KEY = 'panel_started_at';
const PanelUptimeService = {
  async getStartedAt(env) {
    try {
      const row = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind(PANEL_STARTED_AT_KEY).first();
      if (row?.value) return parseInt(row.value, 10) || Date.now();
      const now = Date.now();
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(PANEL_STARTED_AT_KEY, String(now)).run();
      return now;
    } catch (e) {
      return Date.now();
    }
  },
  async reset(env) {
    const now = Date.now();
    await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(PANEL_STARTED_AT_KEY, String(now)).run();
    return now;
  }
};
let panelDisabledCache = { value: false, fetchedAt: 0 };
const PANEL_DISABLED_CACHE_TTL = 30000;
const PanelDisableService = {
  async isPanelDisabled(env) {
    const now = Date.now();
    if (now - panelDisabledCache.fetchedAt < PANEL_DISABLED_CACHE_TTL) return panelDisabledCache.value;
    try {
      const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'panel_disabled'").first();
      panelDisabledCache = { value: row?.value === '1', fetchedAt: now };
      return panelDisabledCache.value;
    } catch (e) {
      return panelDisabledCache.value;
    }
  },
  async setPanelDisabled(env, enabled) {
    await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_disabled', ?)").bind(enabled ? '1' : '0').run();
    panelDisabledCache = { value: enabled, fetchedAt: Date.now() };
  }
};
const PanelKillService = {
  async isAllServicesOff(env) {
    const now = Date.now();
    if (now - allServicesOffCache.fetchedAt < ALL_SERVICES_OFF_CACHE_TTL) {
      return allServicesOffCache.value;
    }
    try {
      const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'all_services_off'").first();
      allServicesOffCache = { value: row?.value === '1' || row?.value === 'true', fetchedAt: now };
      return allServicesOffCache.value;
    } catch (e) {
      return allServicesOffCache.value;
    }
  },
  async setAllServicesOff(env, enabled) {
    await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('all_services_off', ?)").bind(enabled ? '1' : '0').run();
    allServicesOffCache = { value: enabled, fetchedAt: Date.now() };
  }
};
const DomainBlockService = {
  normalizeDomain(value) {
    let d = String(value || '').trim().toLowerCase();
    d = d.replace(/^https?:\/\//, '');
    d = d.replace(/\/.*$/, '');
    d = d.replace(/:\d+$/, '');
    d = d.replace(/^www\./, '');
    d = d.replace(/^\*\./, '');
    return d;
  },
  parseList(value) {
    return CdnProxyService.parseList(value).map(v => this.normalizeDomain(v)).filter(Boolean);
  },
  isBlocked(target, blocklist) {
    if (!target || !blocklist?.length) return false;
    if (isIPv4(target)) return false;
    const host = this.normalizeDomain(target);
    if (!host || !host.includes('.')) return false;
    for (const entry of blocklist) {
      const blocked = this.normalizeDomain(entry);
      if (!blocked) continue;
      if (host === blocked || host.endsWith('.' + blocked)) return true;
    }
    return false;
  },
  invalidateCache() {
    blockedDomainsCache = { enabled: false, domains: [], fetchedAt: 0 };
  },
  async getSettings(env) {
    const now = Date.now();
    if (blockedDomainsCache.fetchedAt && (now - blockedDomainsCache.fetchedAt) < BLOCKED_DOMAINS_CACHE_TTL) {
      return blockedDomainsCache;
    }
    const settings = { enabled: false, domains: [], fetchedAt: now };
    try {
      const { results } = await env.DB.prepare(
        "SELECT key, value FROM settings WHERE key IN ('blocked_domains', 'blocked_domains_enabled')"
      ).all();
      for (const row of (results || [])) {
        if (row.key === 'blocked_domains_enabled') {
          settings.enabled = row.value === '1' || row.value === 'true';
        } else if (row.key === 'blocked_domains') {
          settings.domains = this.parseList(row.value);
        }
      }
    } catch (e) {}
    blockedDomainsCache = settings;
    return settings;
  },
  async saveSettings(env, data) {
    if (data.enabled !== undefined) {
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('blocked_domains_enabled', ?)")
        .bind(data.enabled ? '1' : '0').run();
    }
    if (data.domains !== undefined) {
      const list = this.parseList(data.domains);
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('blocked_domains', ?)")
        .bind(list.join('\n')).run();
    }
    this.invalidateCache();
  }
};
function isIranDomain(hostname) {
  const host = DomainBlockService.normalizeDomain(hostname);
  return !!host && (host === 'ir' || host.endsWith('.ir'));
}
const ContentPolicyService = {
  async getSettings(env) {
    const now = Date.now();
    if (contentPolicyCache.data && (now - contentPolicyCache.fetchedAt) < CONTENT_POLICY_CACHE_TTL_MS) {
      return contentPolicyCache.data;
    }
    const result = { adultBlockEnabled: false };
    try {
      const { results } = await env.DB.prepare(
        "SELECT key, value FROM settings WHERE key IN ('adult_block_enabled')"
      ).all();
      for (const row of (results || [])) {
        if (row.key === 'adult_block_enabled') result.adultBlockEnabled = row.value === '1';
      }
    } catch (e) {}
    contentPolicyCache = { data: result, fetchedAt: now };
    return result;
  },
  async saveSettings(env, data) {
    await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind('adult_block_enabled', data.adultBlockEnabled ? '1' : '0').run();
    contentPolicyCache = { data: { adultBlockEnabled: !!data.adultBlockEnabled }, fetchedAt: Date.now() };
  },
  async getAdultBlocklist() {
    const now = Date.now();
    if (adultBlocklistCache.domains.length && (now - adultBlocklistCache.fetchedAt) < ADULT_BLOCKLIST_CACHE_TTL) {
      return adultBlocklistCache.domains;
    }
    try {
      const res = await fetch(ADULT_BLOCKLIST_URL);
      if (!res.ok) throw new Error('fetch failed');
      const text = await res.text();
      const domains = text.split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'))
        .map(l => l.replace(/^0\.0\.0\.0\s+/, '').replace(/^127\.0\.0\.1\s+/, '').trim())
        .filter(Boolean);
      adultBlocklistCache = { domains, fetchedAt: now };
      return domains;
    } catch (e) {
      return adultBlocklistCache.domains;
    }
  },
  async checkBlocked(env, hostname) {
    if (!hostname || isIPv4(hostname)) return { blocked: false };
    const settings = await this.getSettings(env);
    if (settings.adultBlockEnabled) {
      const list = await this.getAdultBlocklist();
      if (DomainBlockService.isBlocked(hostname, list)) {
        return { blocked: true, reason: 'محتوای بزرگسال' };
      }
    }
    return { blocked: false };
  }
};
const BACKUP_EXCLUDED_SETTINGS = ['panel_password', 'ADMIN'];
const BACKUP_VERSION = 2;
const BackupService = {
  getTehranDateKey(date) {
    return new Intl.DateTimeFormat('en-CA', {
      timeZone: 'Asia/Tehran',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit'
    }).format(date || new Date());
  },
  getTehranHour(date) {
    return parseInt(new Intl.DateTimeFormat('en-US', {
      timeZone: 'Asia/Tehran',
      hour: 'numeric',
      hour12: false
    }).format(date || new Date()), 10);
  },
  async build(env, options = {}) {
    if (!options.skipMaintenance) {
      try {
        await flushExpiredTraffic(env);
        await purgeExpiredUsers(env);
      } catch (e) {}
    }
    const { results: users } = await env.DB.prepare("SELECT * FROM users ORDER BY id ASC").all();
    const { results: settingsRows } = await env.DB.prepare("SELECT key, value FROM settings").all();
    const settings = {};
    (settingsRows || []).forEach(row => {
      if (!BACKUP_EXCLUDED_SETTINGS.includes(row.key)) settings[row.key] = row.value;
    });
    let panel_logs = [];
    let connection_logs = [];
    try {
      const { results: pl } = await env.DB.prepare("SELECT * FROM panel_logs ORDER BY id ASC").all();
      panel_logs = pl || [];
    } catch (e) {}
    try {
      const { results: cl } = await env.DB.prepare("SELECT * FROM connection_logs ORDER BY id ASC").all();
      connection_logs = cl || [];
    } catch (e) {}
    return {
      version: BACKUP_VERSION,
      exported_at: new Date().toISOString(),
      users: users || [],
      settings,
      panel_logs,
      connection_logs,
      meta: {
        users_count: (users || []).length,
        settings_count: Object.keys(settings).length,
        panel_logs_count: panel_logs.length,
        connection_logs_count: connection_logs.length
      }
    };
  },
  async restore(env, body) {
    if (!body || !Array.isArray(body.users)) {
      throw new Error('فرمت بکاپ نامعتبر است — لیست کاربران یافت نشد');
    }
    try { await flushExpiredTraffic(env); } catch (e) {}
    await env.DB.prepare("DELETE FROM users").run();
    for (const user of body.users) {
      await env.DB.prepare(
        "INSERT INTO users (username, uuid, limit_gb, expiry_days, ips, connection_type, tls, port, used_gb, is_active, last_active, created_at, fingerprint, max_requests, max_requests_daily, used_requests, used_requests_today, req_last_date, proxy_ip, is_saved, expired_at, status_slug, is_system) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      ).bind(
        user.username,
        user.uuid,
        user.limit_gb != null ? parseFloat(user.limit_gb) : null,
        user.expiry_days != null ? parseInt(user.expiry_days) : null,
        user.ips || null,
        user.connection_type || atob('dmxlc3M='),
        user.tls || null,
        user.port || null,
        user.used_gb != null ? parseFloat(user.used_gb) : 0,
        user.is_active != null ? parseInt(user.is_active) : 1,
        user.last_active || null,
        user.created_at || null,
        user.fingerprint || 'random',
        user.max_requests != null ? parseInt(user.max_requests) : (user.max_connections != null ? parseInt(user.max_connections) : null),
        user.max_requests_daily != null ? parseInt(user.max_requests_daily) : null,
        user.used_requests != null ? parseInt(user.used_requests) : 0,
        user.used_requests_today != null ? parseInt(user.used_requests_today) : 0,
        user.req_last_date || null,
        user.proxy_ip || null,
        user.is_saved != null ? parseInt(user.is_saved) : 0,
        user.expired_at || null,
        user.status_slug || user.username || null,
        user.is_system != null ? parseInt(user.is_system) : 0
      ).run();
    }
    await ensureSystemUser(env.DB);
    if (body.settings && typeof body.settings === 'object') {
      await env.DB.prepare("DELETE FROM settings").run();
      for (const [key, value] of Object.entries(body.settings)) {
        if (BACKUP_EXCLUDED_SETTINGS.includes(key) || value == null) continue;
        await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(key, String(value)).run();
      }
    }
    if (Array.isArray(body.panel_logs) && body.panel_logs.length) {
      try {
        await env.DB.prepare("DELETE FROM panel_logs").run();
        for (const log of body.panel_logs) {
          await env.DB.prepare(
            "INSERT INTO panel_logs (action, details, ip, created_at) VALUES (?, ?, ?, ?)"
          ).bind(log.action || '', log.details || '', log.ip || '', log.created_at || new Date().toISOString()).run();
        }
      } catch (e) {}
    }
    if (Array.isArray(body.connection_logs) && body.connection_logs.length) {
      try {
        await env.DB.prepare("DELETE FROM connection_logs").run();
        for (const log of body.connection_logs) {
          await env.DB.prepare(
            "INSERT INTO connection_logs (username, ip, event_type, details, created_at) VALUES (?, ?, ?, ?, ?)"
          ).bind(
            log.username || '',
            log.ip || '',
            log.event_type || 'اتصال',
            log.details || '',
            log.created_at || new Date().toISOString()
          ).run();
        }
      } catch (e) {}
    }
    return { users_count: body.users.length };
  },
  async getAutoSettings(env) {
    const settings = {
      auto_enabled: false,
      last_run_at: '',
      last_run_date: '',
      last_status: '',
      telegram_ready: false
    };
    try {
      const { results } = await env.DB.prepare(
        "SELECT key, value FROM settings WHERE key IN ('backup_auto_enabled', 'backup_last_run_at', 'backup_last_run_date', 'backup_last_status')"
      ).all();
      for (const row of results || []) {
        if (row.key === 'backup_auto_enabled') settings.auto_enabled = row.value === '1' || row.value === 'true';
        if (row.key === 'backup_last_run_at') settings.last_run_at = row.value || '';
        if (row.key === 'backup_last_run_date') settings.last_run_date = row.value || '';
        if (row.key === 'backup_last_status') settings.last_status = row.value || '';
      }
    } catch (e) {}
    const tg = await TelegramNotifyService.getSettings(env);
    settings.telegram_ready = !!(tg.bot_token && TelegramNotifyService.parseChatIds(tg.chat_ids).length);
    return settings;
  },
  async saveAutoSettings(env, data) {
    const enabled = data.auto_enabled ? '1' : '0';
    await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('backup_auto_enabled', ?)").bind(enabled).run();
  },
  async sendToTelegram(tgSettings, filename, jsonContent) {
    const chatIds = TelegramNotifyService.parseChatIds(tgSettings.chat_ids);
    if (!tgSettings.bot_token || !chatIds.length) {
      throw new Error('تنظیمات تلگرام کامل نیست — توکن ربات و شناسه چت را در بخش لاگ فعالیت وارد کنید');
    }
    const caption = '📦 بکاپ پنل Nexa\n🕐 ' + new Date().toISOString();
    await Promise.all(chatIds.map(async chatId => {
      const form = new FormData();
      form.append('chat_id', chatId);
      form.append('document', new Blob([jsonContent], { type: 'application/json' }), filename);
      form.append('caption', caption);
      const res = await fetch('https://api.telegram.org/bot' + tgSettings.bot_token + '/sendDocument', {
        method: 'POST',
        body: form
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.description || 'خطا در ارسال به تلگرام');
      }
    }));
  },
  async runScheduledBackup(env, source) {
    const autoSettings = await this.getAutoSettings(env);
    if (!autoSettings.auto_enabled) return { skipped: true, reason: 'disabled' };
    const tg = await TelegramNotifyService.getSettings(env);
    if (!tg.bot_token || !TelegramNotifyService.parseChatIds(tg.chat_ids).length) {
      return { skipped: true, reason: 'no_telegram' };
    }
    const today = this.getTehranDateKey();
    if (autoSettings.last_run_date === today) return { skipped: true, reason: 'already_ran' };
    try {
      const backup = await this.build(env);
      const json = JSON.stringify(backup, null, 2);
      const filename = 'nexa-backup-' + today + '.json';
      await this.sendToTelegram(tg, filename, json);
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('backup_last_run_date', ?)").bind(today).run();
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('backup_last_run_at', ?)").bind(new Date().toISOString()).run();
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('backup_last_status', ?)").bind('success').run();
      const details = 'ارسال بکاپ روزانه به تلگرام (' + backup.meta.users_count + ' کاربر، ' + backup.meta.settings_count + ' تنظیم)';
      await LogService.addLog(env, 'بکاپ خودکار', details + (source ? ' [' + source + ']' : ''), '');
      return { success: true, users_count: backup.meta.users_count };
    } catch (err) {
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('backup_last_status', ?)").bind(String(err.message || 'error')).run();
      return { success: false, error: err.message };
    }
  },
  async maybeRunScheduledBackup(env) {
    const autoSettings = await this.getAutoSettings(env);
    if (!autoSettings.auto_enabled) return;
    if (this.getTehranHour() !== 0) return;
    return this.runScheduledBackup(env, 'auto');
  }
};
const TelegramNotifyService = {
  async getSettings(env) {
    const settings = { enabled: false, bot_token: '', chat_ids: '' };
    try {
      const { results } = await env.DB.prepare(
        "SELECT key, value FROM settings WHERE key IN ('tg_notify_enabled', 'tg_bot_token', 'tg_chat_ids')"
      ).all();
      for (const row of results || []) {
        if (row.key === 'tg_notify_enabled') settings.enabled = row.value === '1' || row.value === 'true';
        if (row.key === 'tg_bot_token') settings.bot_token = row.value || '';
        if (row.key === 'tg_chat_ids') settings.chat_ids = row.value || '';
      }
    } catch (e) {}
    return settings;
  },
  async saveSettings(env, data) {
    const enabled = data.enabled ? '1' : '0';
    const token = String(data.bot_token || '').trim();
    const chatIds = String(data.chat_ids || '').trim();
    await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('tg_notify_enabled', ?)").bind(enabled).run();
    await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('tg_bot_token', ?)").bind(token).run();
    await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('tg_chat_ids', ?)").bind(chatIds).run();
  },
  parseChatIds(raw) {
    return String(raw || '').split(/[\n,،]+/).map(s => s.trim()).filter(Boolean);
  },
  escapeHtml(text) {
    return String(text || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  },
  async sendIfEnabled(env, action, details, ip) {
    try {
      const settings = await this.getSettings(env);
      if (!settings.enabled || !settings.bot_token) return;
      const chatIds = this.parseChatIds(settings.chat_ids);
      if (!chatIds.length) return;
      const lines = ['📋 Nexa Panel Log', '🔹 ' + action];
      if (details) lines.push('📝 ' + details);
      if (ip) lines.push('🌐 IP: ' + ip);
      lines.push('🕐 ' + new Date().toISOString());
      const body = lines.map(l => this.escapeHtml(l)).join('\n');
      const text = body + '\n\n<a href="https://t.me/irnexa">بزرگ ترین پنل رایگان ایران</a>';
      await Promise.all(chatIds.map(chatId =>
        fetch('https://api.telegram.org/bot' + settings.bot_token + '/sendMessage', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML', disable_web_page_preview: true })
        }).catch(() => {})
      ));
    } catch (e) {}
  }
};
const LogService = {
  async addLog(env, action, details = '', ip = '') {
    try {
      await env.DB.prepare(
        "INSERT INTO panel_logs (action, details, ip, created_at) VALUES (?, ?, ?, ?)"
      ).bind(action, details, ip || '', new Date().toISOString()).run();
      await TelegramNotifyService.sendIfEnabled(env, action, details, ip);
    } catch (e) {}
  },
  async getLogs(env, limit = 300) {
    try {
      const { results } = await env.DB.prepare(
        "SELECT * FROM panel_logs ORDER BY id DESC LIMIT ?"
      ).bind(limit).all();
      return results || [];
    } catch (e) {
      return [];
    }
  },
  async clearLogs(env, ip = '') {
    try {
      await env.DB.prepare("DELETE FROM panel_logs").run();
      await this.addLog(env, 'پاک کردن لاگ‌ها', 'همه لاگ‌های فعالیت حذف شدند', ip);
    } catch (e) {}
  }
};
const ConnectionLogService = {
  PING_MAX_BYTES: 8192,
  PING_MAX_MS: 30000,
  formatBytes(bytes) {
    if (!bytes || bytes <= 0) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  },
  formatDuration(durationMs) {
    if (!durationMs || durationMs < 1000) return 'کمتر از ۱ ث';
    const sec = Math.round(durationMs / 1000);
    if (sec < 60) return sec + ' ث';
    const min = Math.floor(sec / 60);
    const rem = sec % 60;
    return rem ? min + ' د ' + rem + ' ث' : min + ' د';
  },
  buildDetails(opts = {}) {
    const parts = [];
    if (opts.prevIp) parts.push('IP قبلی: ' + opts.prevIp);
    if (opts.durationMs !== undefined && opts.durationMs !== null) {
      parts.push('مدت: ' + ConnectionLogService.formatDuration(opts.durationMs));
    }
    if (opts.bytes !== undefined && opts.bytes !== null) {
      parts.push('حجم: ' + ConnectionLogService.formatBytes(opts.bytes));
    }
    if (opts.extra) parts.push(opts.extra);
    return parts.join(' | ');
  },
  classifySession(bytes, durationMs) {
    if (bytes < ConnectionLogService.PING_MAX_BYTES && durationMs < ConnectionLogService.PING_MAX_MS) {
      return 'پینگ';
    }
    return 'اتصال';
  },
  applyIpChange(eventType, prevIp, currentIp) {
    if (!prevIp || prevIp === currentIp) return { eventType, prevIp: null };
    if (eventType === 'پینگ') return { eventType: 'پینگ (IP جدید)', prevIp };
    if (eventType === 'اتصال') return { eventType: 'اتصال (IP جدید)', prevIp };
    return { eventType: 'IP جدید', prevIp };
  },
  async getLastIp(env, username) {
    try {
      const last = await env.DB.prepare(
        "SELECT ip FROM connection_logs WHERE username = ? ORDER BY id DESC LIMIT 1"
      ).bind(username).first();
      return last?.ip || null;
    } catch (e) {
      return null;
    }
  },
  async addLog(env, username, ip, opts = {}) {
    if (!username || !ip) return;
    const bytes = opts.bytes || 0;
    const durationMs = opts.durationMs || 0;
    let eventType = opts.eventType || ConnectionLogService.classifySession(bytes, durationMs);
    let prevIp = null;
    const skipIpCheck = eventType === 'دریافت کانفیگ';
    if (!skipIpCheck) {
      prevIp = await ConnectionLogService.getLastIp(env, username);
      const changed = ConnectionLogService.applyIpChange(eventType, prevIp, ip);
      eventType = changed.eventType;
      prevIp = changed.prevIp;
    } else {
      prevIp = await ConnectionLogService.getLastIp(env, username);
      if (prevIp && prevIp !== ip) {
        eventType = 'دریافت کانفیگ (IP جدید)';
      }
    }
    const details = ConnectionLogService.buildDetails({
      prevIp: prevIp || null,
      bytes: skipIpCheck ? null : bytes,
      durationMs: skipIpCheck ? null : durationMs,
      extra: opts.extra || ''
    });
    try {
      await env.DB.prepare(
        "INSERT INTO connection_logs (username, ip, event_type, details, created_at) VALUES (?, ?, ?, ?, ?)"
      ).bind(username, ip, eventType, details, new Date().toISOString()).run();
    } catch (e) {}
  },
  async getLogs(env, username, limit = 5000) {
    try {
      const { results } = await env.DB.prepare(
        "SELECT * FROM connection_logs WHERE username = ? ORDER BY id DESC LIMIT ?"
      ).bind(username, limit).all();
      return results || [];
    } catch (e) {
      return [];
    }
  },
  async clearLogs(env, username) {
    try {
      await env.DB.prepare("DELETE FROM connection_logs WHERE username = ?").bind(username).run();
    } catch (e) {}
  }
};
let schemaEnsured = false;
let cachedAdminSecret = null;
let cachedPanelPassword = null;
let pendingPasswordOverride = null;
function clearPasswordCache() {
  cachedAdminSecret = null;
  cachedPanelPassword = null;
  pendingPasswordOverride = null;
}
function setPasswordOverride(plainPassword) {
  pendingPasswordOverride = plainPassword ? String(plainPassword) : null;
  cachedAdminSecret = null;
  cachedPanelPassword = null;
}
const DbService = {
  async ensureSchema(db) {
    if (schemaEnsured) return;
    try {
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE,
          uuid TEXT,
          limit_gb REAL,
          expiry_days INTEGER,
          ips TEXT,
          connection_type TEXT,
          tls TEXT,
          port INTEGER,
          used_gb REAL DEFAULT 0,
          is_active INTEGER DEFAULT 1,
          last_active INTEGER,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
    } catch (e) {}
    try { await db.prepare("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1").run(); } catch (e) {}
    try { await db.prepare("ALTER TABLE users ADD COLUMN last_active INTEGER").run(); } catch (e) {}
    try { await db.prepare("ALTER TABLE users ADD COLUMN fingerprint TEXT DEFAULT 'random'").run(); } catch (e) {}
    try { await db.prepare("ALTER TABLE users ADD COLUMN max_connections INTEGER").run(); } catch (e) {}
    try { await db.prepare("ALTER TABLE users ADD COLUMN max_requests INTEGER").run(); } catch (e) {}
    try { await db.prepare("ALTER TABLE users ADD COLUMN used_requests INTEGER DEFAULT 0").run(); } catch (e) {}
    try { await db.prepare("ALTER TABLE users ADD COLUMN req_last_date TEXT").run(); } catch (e) {}
    try { await db.prepare("ALTER TABLE users ADD COLUMN max_requests_daily INTEGER").run(); } catch (e) {}
    try { await db.prepare("ALTER TABLE users ADD COLUMN used_requests_today INTEGER DEFAULT 0").run(); } catch (e) {}
    try { await db.prepare("UPDATE users SET max_requests = max_connections WHERE max_requests IS NULL AND max_connections IS NOT NULL").run(); } catch (e) {}
    try {
      const today = new Date().toISOString().split('T')[0];
      await db.prepare("UPDATE users SET used_requests_today = used_requests, used_requests = used_requests WHERE req_last_date = ? AND used_requests_today IS NULL").bind(today).run();
      await db.prepare("UPDATE users SET used_requests_today = 0 WHERE req_last_date IS NOT NULL AND req_last_date != ? AND (used_requests_today IS NULL OR used_requests_today = 0)").bind(today).run();
    } catch (e) {}
    try { await db.prepare("ALTER TABLE users ADD COLUMN proxy_ip TEXT").run(); } catch (e) {}
    try { await db.prepare("ALTER TABLE users ADD COLUMN is_saved INTEGER DEFAULT 0").run(); } catch (e) {}
    try { await db.prepare("ALTER TABLE users ADD COLUMN expired_at INTEGER").run(); } catch (e) {}
    try { await db.prepare("ALTER TABLE users ADD COLUMN status_slug TEXT").run(); } catch (e) {}
    try { await db.prepare("UPDATE users SET status_slug = username WHERE status_slug IS NULL OR status_slug != username").run(); } catch (e) {}
    try { await db.prepare("ALTER TABLE users ADD COLUMN is_system INTEGER DEFAULT 0").run(); } catch (e) {}
    try { await db.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)").run(); } catch (e) {}
    try {
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS panel_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          action TEXT NOT NULL,
          details TEXT,
          ip TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
    } catch (e) {}
    try {
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS connection_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL,
          ip TEXT,
          event_type TEXT DEFAULT 'اتصال',
          details TEXT DEFAULT '',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
    } catch (e) {}
    try { await db.prepare("ALTER TABLE connection_logs ADD COLUMN event_type TEXT DEFAULT 'اتصال'").run(); } catch (e) {}
    try { await db.prepare("ALTER TABLE connection_logs ADD COLUMN details TEXT DEFAULT ''").run(); } catch (e) {}
    schemaEnsured = true;
  },
  readCfTokenFromEnv(env) {
    for (const key of ['CF_TOKEN', 'CF_API_TOKEN', 'CLOUDFLARE_API_TOKEN']) {
      try {
        const val = env[key];
        if (val != null && String(val).trim()) return String(val).trim();
      } catch (e) {}
    }
    return '';
  },
  isCfTokenBound(env) {
    return !!this.readCfTokenFromEnv(env);
  },
  async getCfToken(env) {
    const fromEnv = this.readCfTokenFromEnv(env);
    if (fromEnv) return fromEnv;
    if (!env.DB) return '';
    const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'CF_TOKEN'").first();
    return row?.value ? String(row.value).trim() : '';
  },
  async getCfAccountId(env) {
    const fromEnv = env.CF_AC_ID ? String(env.CF_AC_ID).trim() : '';
    if (fromEnv) return fromEnv;
    if (!env.DB) return '';
    const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'CF_AC_ID'").first();
    return row?.value ? String(row.value).trim() : '';
  },
  async cacheCfAccountId(env, accountId) {
    const id = String(accountId || '').trim();
    if (!id || !env.DB) return;
    await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('CF_AC_ID', ?)").bind(id).run();
  },
  async getCfAccountIdResolved(env, request) {
    const stored = await this.getCfAccountId(env);
    if (stored) return stored;
    const token = await this.getCfToken(env);
    if (!token) return '';
    const scriptName = request ? getWorkerScriptName(env, request) : '';
    try {
      const accountId = await resolveCfAccountId(token, scriptName);
      if (accountId) await this.cacheCfAccountId(env, accountId);
      return accountId;
    } catch (e) {
      return '';
    }
  },
  async getPanelPassword(env) {
    if (pendingPasswordOverride) {
      const envAdmin = env.ADMIN ? String(env.ADMIN).trim() : '';
      if (envAdmin && envAdmin === pendingPasswordOverride) {
        pendingPasswordOverride = null;
      } else {
        return await this.sha256(pendingPasswordOverride);
      }
    }
    const adminSecret = env.ADMIN ? String(env.ADMIN).trim() : '';
    if (adminSecret) {
      if (cachedAdminSecret === adminSecret && cachedPanelPassword !== null) {
        return cachedPanelPassword;
      }
      cachedAdminSecret = adminSecret;
      cachedPanelPassword = await this.sha256(adminSecret);
      return cachedPanelPassword;
    }
    if (!env.DB) return null;
    const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'ADMIN'").first();
    if (!row?.value) return null;
    const storedHash = String(row.value).trim();
    const cacheKey = '__d1__' + storedHash;
    if (cachedAdminSecret === cacheKey && cachedPanelPassword !== null) {
      return cachedPanelPassword;
    }
    cachedAdminSecret = cacheKey;
    cachedPanelPassword = storedHash;
    return storedHash;
  },
  async verifyApiAuth(request, env) {
    const storedPasswordHash = await this.getPanelPassword(env);
    if (!storedPasswordHash) return true;
    const cookies = request.headers.get('Cookie') || '';
    const sessionCookie = cookies.split(';').find(c => c.trim().startsWith('panel_session='));
    if (!sessionCookie) return false;
    const sessionToken = sessionCookie.split('=')[1].trim();
    return sessionToken === storedPasswordHash;
  },
  async sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
};
function isSystemUser(user) {
  if (!user) return false;
  return user.is_system === 1 || user.username === SYSTEM_USER_LABEL;
}
async function ensureSystemUser(db) {
  const now = Date.now();
  if (systemUserCache.user && (now - systemUserCache.fetchedAt) < SYSTEM_USER_CACHE_TTL_MS) {
    return systemUserCache.user;
  }
  let user = await db.prepare("SELECT * FROM users WHERE is_system = 1 OR username = ? LIMIT 1").bind(SYSTEM_USER_LABEL).first();
  if (user) {
    if (user.is_system !== 1 || user.is_saved !== 1 || user.limit_gb != null || user.expiry_days != null || user.max_requests != null || user.max_requests_daily != null) {
      await db.prepare("UPDATE users SET is_system = 1, is_saved = 1, limit_gb = NULL, expiry_days = NULL, max_requests = NULL, max_requests_daily = NULL WHERE username = ?").bind(user.username).run();
      user = await db.prepare("SELECT * FROM users WHERE username = ?").bind(user.username).first();
    }
    systemUserCache = { user, fetchedAt: now };
    return user;
  }
  const uuid = crypto.randomUUID();
  await db.prepare(
    "INSERT INTO users (username, uuid, limit_gb, expiry_days, ips, connection_type, tls, port, fingerprint, max_requests, proxy_ip, is_active, is_saved, is_system) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, 1)"
  ).bind(
    SYSTEM_USER_LABEL, uuid, null, null, null, atob('dmxlc3M='), 'on', 443, 'chrome', null, null
  ).run();
  await StatusUrlService.assignStatusSlug(db, SYSTEM_USER_LABEL);
  user = await db.prepare("SELECT * FROM users WHERE username = ?").bind(SYSTEM_USER_LABEL).first();
  systemUserCache = { user, fetchedAt: now };
  return user;
}
async function getWorkerRequestStats(env) {
  let cfReqs = { today: 0, total: 0, pending: pendingRequestCount };
  try {
    const liveCf = await getCfUsage(env);
    const todayStr = new Date().toISOString().split('T')[0];
    const dateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_last_date'").first();
    const totalRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_total'").first();
    let dbTotal = totalRow ? parseInt(totalRow.value) || 0 : 0;
    let dbToday = 0;
    if (dateRow && dateRow.value === todayStr) {
      const todayRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_today'").first();
      dbToday = todayRow ? parseInt(todayRow.value) || 0 : 0;
    }
    if (liveCf.today > dbToday) {
      dbToday = liveCf.today;
      await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(dbToday), String(dbToday)).run();
      await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_last_date', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(todayStr, todayStr).run();
    }
    if (liveCf.total > dbTotal) {
      dbTotal = liveCf.total;
      await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_total', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(dbTotal), String(dbTotal)).run();
    }
    cfReqs.today = dbToday + pendingRequestCount;
    cfReqs.total = dbTotal + pendingRequestCount;
  } catch (e) {}
  return cfReqs;
}
function getWorkerScriptName(env, request) {
  if (env.WORKER_NAME) return String(env.WORKER_NAME).trim();
  if (request) return new URL(request.url).hostname.split('.')[0];
  return '';
}
function buildDeployBindings(existingBindings, cfToken, cfAccountId, env) {
  const names = new Set();
  const bindings = [];
  for (const b of existingBindings || []) {
    if (!b?.name || names.has(b.name)) continue;
    names.add(b.name);
    if (b.type === 'd1') {
      bindings.push({ type: 'd1', name: b.name, id: b.database_id || b.id });
    } else if (b.type === 'kv_namespace') {
      bindings.push({ type: 'kv_namespace', name: b.name, namespace_id: b.namespace_id });
    } else if (b.type === 'plain_text') {
      if (b.text != null) {
        bindings.push({ type: 'plain_text', name: b.name, text: b.text });
      } else if (b.name === 'ADMIN' && env?.ADMIN) {
        bindings.push({ type: 'plain_text', name: 'ADMIN', text: String(env.ADMIN) });
      } else {
        bindings.push({ type: 'inherit', name: b.name });
      }
    } else if (b.name === 'CF_TOKEN') {
      bindings.push({ type: 'secret_text', name: 'CF_TOKEN', text: cfToken });
    } else if (b.name === 'CF_AC_ID') {
      bindings.push({ type: 'secret_text', name: 'CF_AC_ID', text: cfAccountId });
    } else {
      bindings.push({ type: 'inherit', name: b.name });
    }
  }
  if (env?.ADMIN && !names.has('ADMIN')) {
    bindings.push({ type: 'plain_text', name: 'ADMIN', text: String(env.ADMIN) });
  }
  return bindings;
}
function isCfTokenAuthError(message) {
  const msg = String(message || '').trim().toLowerCase();
  if (!msg) return false;
  return msg.includes('authentication error')
    || msg.includes('unauthorized')
    || msg.includes('invalid api token')
    || msg.includes('invalid access token')
    || msg.includes('invalid credentials')
    || msg.includes('عدم دسترسی به bindings ورکر')
    || msg.includes('توکن یا اکانت آیدی کلودفلر تنظیم نشده');
}
async function deployPanelScript(env, request, sourceCode) {
  const cfToken = await DbService.getCfToken(env);
  const cfAccountId = await DbService.getCfAccountIdResolved(env, request);
  if (!cfToken || !cfAccountId) {
    throw new Error('توکن یا اکانت آیدی کلودفلر تنظیم نشده است.');
  }
  if (!sourceCode || sourceCode.length < 100) {
    throw new Error('سورس دریافتی نامعتبر است');
  }
  const scriptName = getWorkerScriptName(env, request);
  if (!scriptName) throw new Error('نام ورکر یافت نشد');
  const baseUrl = `https://api.cloudflare.com/client/v4/accounts/${cfAccountId}/workers/scripts/${encodeURIComponent(scriptName)}`;
  const authHeaders = { Authorization: 'Bearer ' + cfToken };
  const bindingsRes = await fetch(`${baseUrl}/bindings`, { headers: authHeaders });
  const bindingsData = await parseCfApiJson(bindingsRes, 'عدم دسترسی به bindings ورکر');
  if (!bindingsData.success) {
    throw new Error(bindingsData.errors?.[0]?.message || 'عدم دسترسی به تنظیمات ورکر');
  }
  const mainModule = 'nexa.js';
  const metadata = {
    main_module: mainModule,
    compatibility_date: '2024-02-08',
    bindings: buildDeployBindings(bindingsData.result || [], cfToken, cfAccountId, env)
  };
  const formData = new FormData();
  formData.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
  formData.append(mainModule, new Blob([sourceCode], { type: 'application/javascript+module' }), mainModule);
  const deployRes = await fetch(baseUrl, {
    method: 'PUT',
    headers: authHeaders,
    body: formData
  });
  const deployData = await parseCfApiJson(deployRes, 'خطا در اعمال آپدیت در کلودفلر');
  if (!deployData.success) {
    throw new Error(deployData.errors?.[0]?.message || 'خطا در اعمال آپدیت در کلودفلر');
  }
  return { scriptName };
}
async function parseCfApiJson(response, fallbackError) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch (e) {
    if (text.trimStart().startsWith('<!')) {
      throw new Error(fallbackError + ' (پاسخ نامعتبر از Cloudflare)');
    }
    throw new Error(fallbackError);
  }
}
async function resolveCfAccountId(cfToken, scriptName) {
  const token = String(cfToken || '').trim();
  if (!token) throw new Error('توکن API کلودفلر یافت نشد');
  const res = await fetchWithTimeout('https://api.cloudflare.com/client/v4/accounts', {
    headers: { Authorization: 'Bearer ' + token }
  }, 8000);
  const data = await parseCfApiJson(res, 'خطا در دریافت لیست اکانت‌های کلودفلر');
  if (!data.success || !Array.isArray(data.result) || !data.result.length) {
    throw new Error(data.errors?.[0]?.message || 'اکانت کلودفلر یافت نشد');
  }
  if (scriptName) {
    for (const acc of data.result) {
      try {
        const wrRes = await fetchWithTimeout(
          `https://api.cloudflare.com/client/v4/accounts/${acc.id}/workers/scripts/${encodeURIComponent(scriptName)}`,
          { headers: { Authorization: 'Bearer ' + token } },
          5000
        );
        if (wrRes.ok) {
          const wrData = await wrRes.json();
          if (wrData.success) return acc.id;
        }
      } catch (e) {}
    }
  }
  return data.result[0].id;
}
const SetupService = {
  async setAdminVariable(env, request, password) {
    const cfToken = await DbService.getCfToken(env);
    const cfAccountId = await DbService.getCfAccountIdResolved(env, request);
    if (!cfToken || !cfAccountId) {
      throw new Error('CF_TOKEN باید تنظیم شده باشد');
    }
    const scriptName = getWorkerScriptName(env, request);
    if (!scriptName) throw new Error('نام ورکر یافت نشد');
    const baseUrl = `https://api.cloudflare.com/client/v4/accounts/${cfAccountId}/workers/scripts/${encodeURIComponent(scriptName)}`;
    const authHeaders = { Authorization: 'Bearer ' + cfToken };

    try {
      await fetch(`${baseUrl}/secrets`, {
        method: 'DELETE',
        headers: { ...authHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'ADMIN' })
      });
    } catch (e) {}

    const bindingsRes = await fetch(`${baseUrl}/bindings`, { headers: authHeaders });
    const bindingsData = await parseCfApiJson(bindingsRes, 'عدم دسترسی به bindings ورکر');
    if (!bindingsData.success) {
      throw new Error(bindingsData.errors?.[0]?.message || 'عدم دسترسی به تنظیمات ورکر');
    }

    const newBindings = (bindingsData.result || [])
      .filter(b => b.name !== 'ADMIN')
      .map(b => ({ type: 'inherit', name: b.name }));
    newBindings.push({ type: 'plain_text', name: 'ADMIN', text: password });

    const formData = new FormData();
    formData.append('settings', new Blob([JSON.stringify({ bindings: newBindings })], { type: 'application/json' }));

    const patchRes = await fetch(`${baseUrl}/settings`, {
      method: 'PATCH',
      headers: authHeaders,
      body: formData
    });
    const patchData = await parseCfApiJson(patchRes, 'خطا در به‌روزرسانی متغیر ADMIN');
    if (!patchData.success) {
      const msg = patchData.errors?.[0]?.message || patchData.errors?.[0]?.code || 'خطا در به‌روزرسانی متغیر ADMIN';
      throw new Error(msg);
    }
    return true;
  },
  async setCfCredentials(env, request, newToken, newAccountId) {
    const currentToken = await DbService.getCfToken(env);
    newToken = String(newToken || '').trim();
    newAccountId = String(newAccountId || '').trim();
    if (!newToken) throw new Error('توکن API کلودفلر را وارد کنید');
    const scriptName = getWorkerScriptName(env, request);
    if (!scriptName) throw new Error('نام ورکر یافت نشد');
    if (!newAccountId) {
      newAccountId = await resolveCfAccountId(newToken, scriptName);
    }
    let currentAccountId = await DbService.getCfAccountId(env);
    if (!currentAccountId && currentToken) {
      try {
        currentAccountId = await resolveCfAccountId(currentToken, scriptName);
      } catch (e) {}
    }
    if (!currentAccountId) currentAccountId = newAccountId;
    const authToken = currentToken || newToken;
    const baseUrl = `https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${encodeURIComponent(scriptName)}`;
    const authHeaders = { Authorization: 'Bearer ' + authToken };

    const bindingsRes = await fetch(`${baseUrl}/bindings`, { headers: authHeaders });
    const bindingsData = await parseCfApiJson(bindingsRes, 'عدم دسترسی به bindings ورکر');
    if (!bindingsData.success) {
      throw new Error(bindingsData.errors?.[0]?.message || 'عدم دسترسی به تنظیمات ورکر');
    }

    const existing = bindingsData.result || [];
    const newBindings = existing.map(b => {
      if (b.name === 'CF_TOKEN') return { type: 'secret_text', name: 'CF_TOKEN', text: newToken };
      if (b.name === 'CF_AC_ID') return { type: 'secret_text', name: 'CF_AC_ID', text: newAccountId };
      return { type: 'inherit', name: b.name };
    });
    if (!existing.some(b => b.name === 'CF_TOKEN')) {
      newBindings.push({ type: 'secret_text', name: 'CF_TOKEN', text: newToken });
    }
    if (!existing.some(b => b.name === 'CF_AC_ID')) {
      newBindings.push({ type: 'secret_text', name: 'CF_AC_ID', text: newAccountId });
    }

    const formData = new FormData();
    formData.append('settings', new Blob([JSON.stringify({ bindings: newBindings })], { type: 'application/json' }));
    const patchRes = await fetch(`${baseUrl}/settings`, {
      method: 'PATCH',
      headers: authHeaders,
      body: formData
    });
    const patchData = await parseCfApiJson(patchRes, 'خطا در به‌روزرسانی CF_TOKEN و CF_AC_ID');
    if (!patchData.success) {
      throw new Error(patchData.errors?.[0]?.message || 'خطا در به‌روزرسانی CF_TOKEN و CF_AC_ID');
    }

    if (env.DB) {
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('CF_TOKEN', ?)").bind(newToken).run();
      await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('CF_AC_ID', ?)").bind(newAccountId).run();
    }
    return true;
  },
  async getStatus(env, request) {
    let d1Connected = false;
    let d1BindingName = 'DB';
    let d1DatabaseName = null;
    let d1DatabaseId = null;
    let d1Error = null;
    if (!env.DB) {
      d1Error = 'اتصال D1 (binding: DB) یافت نشد';
    } else {
      try {
        await DbService.ensureSchema(env.DB);
        await env.DB.prepare("SELECT 1 AS ok").first();
        d1Connected = true;
      } catch (e) {
        d1Error = e.message || 'خطا در اتصال به D1';
      }
    }
    const cfToken = await DbService.getCfToken(env);
    let cfAccountId = await DbService.getCfAccountId(env);
    let cfApiToken = !!cfToken || DbService.isCfTokenBound(env);
    const tokenForApi = cfToken || DbService.readCfTokenFromEnv(env);
    let cfAccountIdAuto = false;
    if (!cfAccountId && tokenForApi && request) {
      cfAccountId = await DbService.getCfAccountIdResolved(env, request);
      cfAccountIdAuto = !!cfAccountId;
    }
    const cfAccountIdSet = !!cfAccountId;
    if (cfAccountIdSet && tokenForApi && request) {
      try {
        const scriptName = getWorkerScriptName(env, request);
        const bindingsRes = await fetch(
          `https://api.cloudflare.com/client/v4/accounts/${cfAccountId}/workers/scripts/${scriptName}/bindings`,
          { headers: { Authorization: 'Bearer ' + tokenForApi } }
        );
        const bindingsData = await bindingsRes.json();
        if (bindingsData.success && Array.isArray(bindingsData.result)) {
          const cfTokenBinding = bindingsData.result.find(b => b.name === 'CF_TOKEN');
          if (cfTokenBinding) cfApiToken = true;
          const d1Binding = bindingsData.result.find(b => b.type === 'd1');
          if (d1Binding) {
            d1BindingName = d1Binding.name || 'DB';
            d1DatabaseId = d1Binding.database_id || d1Binding.id || null;
            if (d1DatabaseId) {
              const dbRes = await fetch(
                `https://api.cloudflare.com/client/v4/accounts/${cfAccountId}/d1/database/${d1DatabaseId}`,
                { headers: { Authorization: 'Bearer ' + tokenForApi } }
              );
              const dbData = await dbRes.json();
              if (dbData.success && dbData.result?.name) {
                d1DatabaseName = dbData.result.name;
              }
            }
          }
        }
      } catch (e) {}
    }
    const adminSecret = !!(env.ADMIN && String(env.ADMIN).trim());
    let adminLegacyD1 = false;
    if (!adminSecret && env.DB) {
      try {
        const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'ADMIN'").first();
        adminLegacyD1 = !!(row?.value && String(row.value).trim());
      } catch (e) {}
    }
    const setupReady = d1Connected && adminSecret && cfApiToken;
    return {
      d1_connected: d1Connected,
      d1_binding_name: d1BindingName,
      d1_database_name: d1DatabaseName,
      d1_database_id: d1DatabaseId,
      d1_error: d1Error,
      cf_api_token: cfApiToken,
      cf_account_id: cfAccountIdSet,
      cf_account_id_auto: cfAccountIdAuto,
      cf_account_id_value: cfAccountId || '',
      admin_secret: adminSecret,
      admin_from_env: adminSecret,
      admin_legacy_d1: adminLegacyD1,
      setup_ready: setupReady
    };
  },
  async isReady(env) {
    if (!env.DB) return false;
    try {
      await DbService.ensureSchema(env.DB);
      await env.DB.prepare("SELECT 1 AS ok").first();
    } catch (e) {
      return false;
    }
    const hasAdmin = !!(await DbService.getPanelPassword(env));
    if (!hasAdmin) return false;
    const cfToken = await DbService.getCfToken(env);
    return !!(cfToken || DbService.isCfTokenBound(env));
  }
};
const EXPIRED_PURGE_DELAY_MS = 24 * 60 * 60 * 1000;
function isUserExpired(user, now = Date.now()) {
  if (!user) return false;
  if (isVolumeExpired(user)) return true;
  return isTimeExpired(user, now);
}
function isVolumeExpired(user) {
  return user.limit_gb != null && user.used_gb >= user.limit_gb;
}
function isTimeExpired(user, now = Date.now()) {
  if (!user.expiry_days || !user.created_at) return false;
  const created = new Date(user.created_at);
  const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
  return now > expiryDate.getTime();
}
function getInactiveReason(user, now = Date.now()) {
  if (isUserRequestLimitExceeded(user, user.username)) return 'اتمام ریکوئست';
  const volExp = isVolumeExpired(user);
  const timeExp = isTimeExpired(user, now);
  if (volExp && timeExp) return 'پایان زمان و حجم سرویس';
  if (volExp) return 'پایان حجم سرویس';
  if (timeExp) return 'پایان زمان سرویس';
  if (user.is_active === 0) return 'قطع شدن دستی توسط ادمین';
  return 'غیرفعال';
}
function isUserInactive(user, now = Date.now()) {
  return user.is_active === 0 || isUserExpired(user, now) || isUserRequestLimitExceeded(user, user.username);
}
function fmtRemarkVolume(gb) {
  if (gb == null || gb === undefined) return '∞';
  if (gb < 1) return (gb * 1024).toFixed(0) + ' MB';
  const n = gb % 1 === 0 ? gb.toFixed(0) : gb.toFixed(2);
  return n + ' GB';
}
function buildServiceInfoRemark(user, now = Date.now()) {
  const usedStr = fmtRemarkVolume(user.used_gb || 0);
  const totalStr = user.limit_gb != null ? fmtRemarkVolume(user.limit_gb) : '∞';
  let daysPart = '∞';
  if (user.expiry_days) {
    if (user.created_at) {
      const created = new Date(user.created_at);
      const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
      const diffDays = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
      daysPart = (diffDays > 0 ? diffDays : 0) + ' روز';
    } else {
      daysPart = user.expiry_days + ' روز';
    }
  }
  return '[مصرف شده: ' + usedStr +']' + '['+ totalStr +' : کل ' +']'+ '[مانده :' + daysPart+']';
}
function buildFirstRemark() {
  return FREE_SERVICE_NOTICE;
}
function buildSecondRemark(user, now = Date.now(), workerConfig = null) {
  if (isUserInactive(user, now)) {
    return 'غیر فعال : ' + getInactiveReason(user, now);
  }
  const template = workerConfig?.infoRemarkTemplate || WORKER_CONFIG_DEFAULTS.infoRemarkTemplate;
  return applyRemarkTemplate(template, user, now);
}
async function resolveSubscriptionState(user, env, opts) {
  const firstRemark = buildFirstRemark();
  const workerConfig = env ? await WorkerConfigService.loadSettings(env) : null;
  if (isUserRequestLimitExceeded(user, user.username)) {
    return { inactive: true, firstRemark, secondRemark: 'غیر فعال : اتمام ریکوئست', workerConfig };
  }
  if (isUserInactive(user)) {
    return { inactive: true, firstRemark, secondRemark: buildSecondRemark(user, Date.now(), workerConfig), workerConfig };
  }
  if (env) {
    if (await PanelKillService.isAllServicesOff(env)) {
      return { inactive: true, firstRemark, secondRemark: 'غیر فعال : قطع تمامی سرویس‌ها', workerConfig };
    }
    }
  return { inactive: false, firstRemark, secondRemark: buildSecondRemark(user, Date.now(), workerConfig), workerConfig };
}
async function syncExpiredUsersStatus(env) {
  try {
    const { results } = await env.DB.prepare("SELECT * FROM users WHERE is_active = 1").all();
    const now = Date.now();
    for (const user of (results || [])) {
      if (!isUserExpired(user, now)) continue;
      await env.DB.prepare(
        "UPDATE users SET is_active = 0 WHERE username = ? AND is_active = 1"
      ).bind(user.username).run();
      if (isVolumeExpired(user) && !user.expired_at) {
        await env.DB.prepare(
          "UPDATE users SET expired_at = ? WHERE username = ? AND expired_at IS NULL"
        ).bind(now, user.username).run();
      }
    }
  } catch (e) {}
}
function getUserExpiredAtMs(user, now = Date.now()) {
  if (!isUserExpired(user, now)) return null;
  const timeExpiryMs = (user.expiry_days && user.created_at)
    ? new Date(user.created_at).getTime() + (user.expiry_days * 24 * 60 * 60 * 1000)
    : null;
  const timeExpired = timeExpiryMs != null && now > timeExpiryMs;
  const volumeExpired = user.limit_gb != null && user.used_gb >= user.limit_gb;
  if (timeExpired && volumeExpired) {
    return Math.max(timeExpiryMs, user.expired_at || 0);
  }
  if (timeExpired) return timeExpiryMs;
  return user.expired_at || now;
}
async function maybeMarkVolumeExpired(env, username) {
  try {
    const user = await env.DB.prepare(
      "SELECT limit_gb, used_gb, expired_at, is_active FROM users WHERE username = ?"
    ).bind(username).first();
    if (user && isVolumeExpired(user)) {
      const now = Date.now();
      if (!user.expired_at) {
        await env.DB.prepare(
          "UPDATE users SET expired_at = ?, is_active = 0 WHERE username = ? AND expired_at IS NULL"
        ).bind(now, username).run();
      } else if (user.is_active === 1) {
        await env.DB.prepare(
          "UPDATE users SET is_active = 0 WHERE username = ? AND is_active = 1"
        ).bind(username).run();
      }
    }
  } catch (e) {}
}
async function purgeExpiredUsers(env) {
  try {
    const { results } = await env.DB.prepare("SELECT * FROM users").all();
    const now = Date.now();
    for (const user of (results || [])) {
      if (user.is_saved === 1 || isSystemUser(user)) continue;
      if (!isUserExpired(user, now)) continue;
      const volumeExpired = user.limit_gb != null && user.used_gb >= user.limit_gb;
      if (volumeExpired && !user.expired_at) {
        await env.DB.prepare(
          "UPDATE users SET expired_at = ? WHERE username = ? AND expired_at IS NULL"
        ).bind(now, user.username).run();
        user.expired_at = now;
      }
      const expiredAt = getUserExpiredAtMs(user, now);
      if (expiredAt != null && now - expiredAt >= EXPIRED_PURGE_DELAY_MS) {
        await env.DB.prepare("DELETE FROM users WHERE username = ?").bind(user.username).run();
      }
    }
  } catch (e) {}
}
function formatVolumeLabel(gb) {
  if (gb == null || gb === undefined) return 'نامحدود';
  if (gb < 1) return (gb * 1024).toFixed(0) + ' MB';
  const n = gb % 1 === 0 ? gb.toFixed(0) : gb.toFixed(2);
  return n + ' GB';
}
function resolveConfigIps(host, userIpsRaw) {
  const userCleanIps = normalizeCleanIpList(userIpsRaw || '', PER_USER_CLEAN_IP_CAP);
  if (!userCleanIps.length) return [host];
  const ips = [host];
  for (const ip of userCleanIps) {
    if (!ips.some(existing => existing.toLowerCase() === ip.toLowerCase())) {
      ips.push(ip);
    }
  }
  return ips;
}
async function buildNodeTlsConfigLinks(user, host, inactive, env = null) {
  if (inactive || !user) return [];
  const fp = user.fingerprint || WorkerConfigService.getDefaults().fingerprint;
  const remark = user.username;
  const workerConfig = env ? await WorkerConfigService.loadSettings(env) : WorkerConfigService.getDefaults();
  const proto = workerConfig.protocolType === 'mixed' ? 'vless' : (workerConfig.protocolType || 'vless');
  return TLS_PORT_LIST.map(portStr => ({
    port: portStr,
    address: host,
    link: WorkerConfigService.buildNodeLink(workerConfig, user, host, portStr, fp, remark, proto, host)
  }));
}
function detectSubscriptionType(url, ua, isSubConverterRequest) {
  if (isSubConverterRequest) return 'mixed';
  if (url && url.searchParams.has('target')) return url.searchParams.get('target');
  if (url && (url.searchParams.has('clash') || ua.includes('clash') || ua.includes('meta') || ua.includes('mihomo'))) return 'clash';
  if (url && (url.searchParams.has('sb') || url.searchParams.has('singbox') || ua.includes('singbox') || ua.includes('sing-box'))) return 'singbox';
  if (url && (url.searchParams.has('surge') || ua.includes('surge'))) return 'surge&ver=4';
  if (url && (url.searchParams.has('quanx') || ua.includes('quantumult'))) return 'quanx';
  if (url && (url.searchParams.has('loon') || ua.includes('loon'))) return 'loon';
  return 'mixed';
}
function isSubConverterRequest(request, url, ua) {
  if (!request && !url) return false;
  ua = ua || (request ? String(request.headers.get('User-Agent') || '').toLowerCase() : '');
  return !!(url && (url.searchParams.has('b64') || url.searchParams.has('base64')))
    || !!(request && (request.headers.get('subconverter-request') || request.headers.get('subconverter-version')))
    || ua.includes('subconverter')
    || ua.includes('cf-workers-sub');
}
const SubscriptionService = {
  async buildMixedLinks(user, host, env, workerConfig) {
    const proxySettingsBase = await CdnProxyService.loadSettings(env);
    const proxySettingsForRemark = CdnProxyService.buildUserSettings(proxySettingsBase, user);
    const proxyEntries = CdnProxyService.getEffectiveProxyListWithMeta(proxySettingsForRemark);
    const ips = resolveConfigIps(host, user.ips);
    const ports = String(user.port || '443').split(',').map(p => p.trim()).filter(p => p.length > 0);
    const fp = user.fingerprint || workerConfig.fingerprint || WorkerConfigService.getDefaults().fingerprint;
    const links = [];
    const { inactive, firstRemark, secondRemark } = await resolveSubscriptionState(user, env);
    const tc = WorkerConfigService.getTransportConfig(workerConfig);
    const pathEnc = encodeURIComponent(WorkerConfigService.resolveTransportPathValue(workerConfig));
    const buildFakeLink = (remark) => {
      const proto = workerConfig.protocolType === 'mixed' ? 'vless' : (workerConfig.protocolType || 'vless');
      return proto + '://' + user.uuid + '@127.0.0.1:17?encryption=none&security=none&type=' + WorkerConfigService.getTransportTypeParam(workerConfig) + '&' + tc.hostField + '=' + host + '&' + tc.pathField + '=' + pathEnc + '#' + encodeURIComponent(remark);
    };
    links.push(buildFakeLink(firstRemark));
    links.push(buildFakeLink(secondRemark));
    if (!inactive) {
      let nodeIndex = 0;
      const proxyList = proxyEntries.length ? proxyEntries : [null];
      ips.forEach((ip) => {
        ports.forEach((portStr) => {
          proxyList.forEach((proxyEntry) => {
            const flag = proxyEntry ? flagEmojiFromCountryCode(proxyEntry.cc) : '';
            const proxyipForRemark = proxyEntry ? proxyEntry.address : (proxyEntries[0]?.address || 'auto');
            const remark = applyRemarkTemplate(workerConfig.nodeRemarkTemplate, user, Date.now(), { port: portStr, proxyip: proxyipForRemark, flag });
            let proto = workerConfig.protocolType || 'vless';
            if (proto === 'mixed') {
              proto = ['vless', 'trojan', 'ss'][nodeIndex % 3];
            }
            links.push(WorkerConfigService.buildNodeLink(workerConfig, user, ip, portStr, fp, remark, proto, host, proxyEntry ? proxyEntry.address : null));
            nodeIndex++;
          });
        });
      });
    }
    const noise = [
      "# System Update Feed: OK",
      "# Sync Code: " + Math.random().toString(36).slice(2, 10),
      "# Version: 2.10.1",
      "# Description: Secure Node Configurations",
      ""
    ].join('\n');
    return noise + links.join('\n');
  },
  buildResponseHeaders(workerConfig, subType) {
    const headers = {
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-store"
    };
    if (subType === 'clash') headers["Content-Type"] = "application/x-yaml; charset=utf-8";
    else if (subType === 'singbox') headers["Content-Type"] = "application/json; charset=utf-8";
    else headers["Content-Type"] = "text/plain; charset=utf-8";
    if (workerConfig.subName) {
      try {
        headers["Profile-Title"] = "base64:" + btoa(unescape(encodeURIComponent(workerConfig.subName)));
      } catch (e) {}
    }
    if (workerConfig.subUpdateHours) {
      headers["Profile-Update-Interval"] = String(workerConfig.subUpdateHours);
    }
    return headers;
  },
  async generateText(user, host, env = null, request = null, url = null) {
    const workerConfig = env ? await WorkerConfigService.loadSettings(env) : WorkerConfigService.getDefaults();
    const networkSettings = env ? await NetworkSettingsService.loadSettings(env) : NetworkSettingsService.getDefaults();
    const ua = (request ? String(request.headers.get('User-Agent') || '') : '').toLowerCase();
    const converterReq = isSubConverterRequest(request, url, ua);
    const subType = detectSubscriptionType(url, ua, converterReq);
    const mixedContent = await this.buildMixedLinks(user, host, env, workerConfig);
    const headers = this.buildResponseHeaders(workerConfig, subType);
    if (subType === 'mixed') {
      const shouldB64 = converterReq || !ua.includes('mozilla') || (url && (url.searchParams.has('b64') || url.searchParams.has('base64')));
      const body = shouldB64 ? btoa(unescape(encodeURIComponent(mixedContent))) : mixedContent;
      return new Response(body, { headers });
    }
    const subPath = workerConfig.subPagePath || WORKER_CONFIG_DEFAULTS.subPagePath;
    const origin = url ? (url.protocol + '//' + url.host) : ('https://' + host);
    const mixedUrl = origin + '/' + subPath + '/' + encodeURIComponent(user.username) + '?target=mixed&b64';
    const converterApi = (workerConfig.subConverterApi || WORKER_CONFIG_DEFAULTS.subConverterApi).replace(/\/$/, '');
    const configUrl = workerConfig.subConfigUrl || WORKER_CONFIG_DEFAULTS.subConfigUrl;
    const emoji = workerConfig.subEmoji ? 'true' : 'false';
    const scv = workerConfig.skipCertVerify ? 'true' : 'false';
    const convertUrl = converterApi + '/sub?target=' + encodeURIComponent(subType)
      + '&url=' + encodeURIComponent(mixedUrl)
      + '&config=' + encodeURIComponent(configUrl)
      + '&emoji=' + emoji
      + '&scv=' + scv;
    let subContent;
    try {
      const res = await fetchWithTimeout(convertUrl, {
        headers: { 'User-Agent': 'Subconverter for ' + subType + ' (Nexa Panel)' }
      }, 12000);
      if (!res.ok) throw new Error(res.statusText || String(res.status));
      subContent = await res.text();
    } catch (e) {
      return new Response('Subscription converter error: ' + e.message, { status: 403, headers: { "Content-Type": "text/plain; charset=utf-8" } });
    }
    if (subType === 'singbox') {
      subContent = NetworkSettingsService.applySingboxHotpatch(subContent, networkSettings);
    } else if (subType === 'clash') {
      subContent = NetworkSettingsService.applyClashHotpatch(subContent, networkSettings);
    }
    return new Response(subContent, { headers });
  }
};
async function flushExpiredTraffic(env) {
  const now = Date.now();
  for (const [uname, cachedBytes] of trafficByteCache.entries()) {
    if (cachedBytes <= 0) continue;
    if (dbWriteLock.get(uname)) continue;
    const lastActive = lastActiveWriteAt.get(uname) || 0;
    const activeCount = activeConnCountByUser.get(uname) || 0;
    if (activeCount <= 0 || (now - lastActive > 65000)) {
      dbWriteLock.set(uname, true);
      trafficByteCache.set(uname, 0);
      const deltaGb = cachedBytes / (1024 * 1024 * 1024);
      try {
        await env.DB.prepare("UPDATE users SET used_gb = used_gb + ? WHERE username = ?").bind(deltaGb, uname).run();
        await maybeMarkVolumeExpired(env, uname);
      } catch (e) {
      } finally {
        dbWriteLock.set(uname, false);
      }
    }
  }
}
async function handleVLESS(env, storedData = null, ctx = null, request = null) {
  const connectClientIp = request ? getClientIp(request) : '';
  const socketPair = new WebSocketPair();
  const [clientSock, serverSock] = Object.values(socketPair);
  serverSock.accept();
  serverSock.binaryType = 'arraybuffer';
  let username = null;
  let tickCount = 0;
  let validUUID = null;
  let connBytes = 0;
  let connStart = Date.now();
  function addBytes(bytes) {
    if (bytes <= 0 || !username) return;
    connBytes += bytes;
    let current = trafficByteCache.get(username) || 0;
    trafficByteCache.set(username, current + bytes);
    lastActiveWriteAt.set(username, Date.now());
    if (dbWriteLock.get(username)) return;
    let lastDbWrite = lastDbWriteAt.get(username) || 0;
    let now = Date.now();
    let thresholdBytes = 10 * 1024 * 1024;
    if (current >= thresholdBytes || (current > 0 && now - lastDbWrite > 60000)) {
        dbWriteLock.set(username, true);
        let toCommit = trafficByteCache.get(username) || 0;
        if (toCommit <= 0) {
            dbWriteLock.set(username, false);
            return;
        }
        trafficByteCache.set(username, 0);
        lastDbWriteAt.set(username, now);
        let deltaGb = toCommit / (1024 * 1024 * 1024);
        let writeTask = async () => {
            try {
                await env.DB.prepare("UPDATE users SET used_gb = used_gb + ? WHERE username = ?").bind(deltaGb, username).run();
                await maybeMarkVolumeExpired(env, username);
            } catch (e) {
            } finally {
                dbWriteLock.set(username, false);
            }
        };
        if (ctx) ctx.waitUntil(writeTask());
        else writeTask();
    }
  }
  let isOfflineSet = false;
  const setOffline = () => {
    if (isOfflineSet) return;
    isOfflineSet = true;
    const uname = username;
    const uuid = validUUID;
    const clientIp = connectClientIp;
    const sessionBytes = connBytes;
    const sessionDuration = Date.now() - connStart;
    if (!uname) return;
    let activeCount = activeConnCountByUser.get(uname) || 1;
    activeCount = activeCount - 1;
    if (activeCount <= 0) {
      activeConnCountByUser.delete(uname);
      let cachedBytes = trafficByteCache.get(uname) || 0;
      if (cachedBytes > 0 && !dbWriteLock.get(uname)) {
        dbWriteLock.set(uname, true);
        trafficByteCache.set(uname, 0);
        const deltaGb = cachedBytes / (1024 * 1024 * 1024);
        const writeTask = async () => {
          try {
            await env.DB.prepare("UPDATE users SET used_gb = used_gb + ? WHERE username = ?").bind(deltaGb, uname).run();
            await maybeMarkVolumeExpired(env, uname);
          } catch (e) {
          } finally {
            dbWriteLock.set(uname, false);
          }
        };
        if (ctx) {
          ctx.waitUntil(writeTask());
        } else {
          writeTask();
        }
      }
    } else {
      activeConnCountByUser.set(uname, activeCount);
    }
    if (uuid && clientIp) {
      const logConnTask = async () => {
        try {
          await ConnectionLogService.addLog(env, uname, clientIp, {
            bytes: sessionBytes,
            durationMs: sessionDuration
          });
        } catch (e) {}
      };
      if (ctx) ctx.waitUntil(logConnTask());
      else logConnTask();
    }
  };
  const heartbeat = setInterval(async () => {
    if (serverSock.readyState === WebSocket.OPEN) {
      try {
        serverSock.send(new Uint8Array(0));
        if (!validUUID) return;
        tickCount++;
        if (tickCount >= 4) {
          tickCount = 0;
          const user = await env.DB.prepare("SELECT is_active, limit_gb, used_gb, expiry_days, created_at FROM users WHERE uuid = ?").bind(validUUID).first();
          let isExpired = false;
          if (!user || user.is_active === 0) {
            isExpired = true;
          } else {
            try {
              if (await PanelKillService.isAllServicesOff(env)) isExpired = true;
            } catch (e) {}
          }
          if (!isExpired) {
            if (user.limit_gb && user.used_gb >= user.limit_gb) {
              isExpired = true;
            }
            if (user.expiry_days && user.created_at) {
              const created = new Date(user.created_at);
              const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
              if (new Date() > expiryDate) {
                isExpired = true;
              }
            }
          }
          if (isExpired) {
            await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(validUUID).run();
            clearInterval(heartbeat);
            closeSocketQuietly(serverSock);
            return;
          }
          const now = Date.now();
          const lastRecorded = lastActiveWriteAt.get(username) || 0;
          if (now - lastRecorded > 60000) {
            lastActiveWriteAt.set(username, now);
            await env.DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(now, username).run();
          }
        }
      } catch (e) {}
    } else {
      clearInterval(heartbeat);
    }
  }, 15000);
  let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
  let reqUUID = null;
  let isHeaderParsed = false;
  let isDnsQuery = false;
  let chunkBuffer = new Uint8Array(0);
  let proxySettings = storedData || { proxy_ips: [], defaultProxyIPs: FALLBACK_PROXY_HOSTS.slice() };
  let activeProxyIp = '';
  let activeProxyMode = 'proxyip';
  let proxyEnableFallback = true;
  let wsChain = Promise.resolve();
  let wsStopped = false, wsFailed = false, wsFinished = false;
  let wsQueueBytes = 0, wsQueueItems = 0;
  let currentSocketWriter = null, activeRemoteWriter = null;
  const releaseRemoteWriter = () => {
    if (activeRemoteWriter) {
      try { activeRemoteWriter.releaseLock(); } catch (e) {}
      activeRemoteWriter = null;
    }
    currentSocketWriter = null;
  };
  const getRemoteWriter = () => {
    const s = remoteConnWrapper.socket;
    if (!s) return null;
    if (s !== currentSocketWriter) {
      releaseRemoteWriter();
      currentSocketWriter = s;
      activeRemoteWriter = s.writable.getWriter();
    }
    return activeRemoteWriter;
  };
  const upstreamQueue = createUpstreamQueue({
    getWriter: getRemoteWriter,
    releaseWriter: releaseRemoteWriter,
    retryConnect: async () => {
      if (typeof remoteConnWrapper.retryConnect === 'function') {
        await remoteConnWrapper.retryConnect();
      }
    },
    closeConnection: () => {
      try { remoteConnWrapper.socket?.close(); } catch (e) {}
      closeSocketQuietly(serverSock);
    },
    name: 'VlessWSQueue'
  });
  const writeToRemote = async (chunk, allowRetry = true) => {
    return upstreamQueue.writeAndAwait(chunk, allowRetry);
  };
  const processWsMessage = async (chunk) => {
    const bytes = chunk.byteLength || 0;
    await addBytes(bytes);
    if (isDnsQuery) {
      await forwardVlessUDP(chunk, serverSock, null, addBytes);
      return;
    }
    if (await writeToRemote(chunk)) return;
    if (!isHeaderParsed) {
      chunkBuffer = concatBytes(chunkBuffer, chunk);
      if (chunkBuffer.byteLength < 24) return;
      reqUUID = extractUUIDFromVless(chunkBuffer);
      if (!reqUUID) {
        serverSock.close();
        return;
      }
      let user = null;
      try {
        user = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(reqUUID).first();
      } catch (e) {}
      if (!user || user.is_active === 0) {
        serverSock.close();
        return;
      }
      try {
        if (await PanelKillService.isAllServicesOff(env)) {
          serverSock.close();
          return;
        }
      } catch (e) {}
      proxySettings = CdnProxyService.buildUserSettings(proxySettings, user);
      const proxyState = CdnProxyService.getActiveProxyIp(proxySettings, request);
      activeProxyIp = proxyState.proxyIp;
      activeProxyMode = proxyState.mode || 'proxyip';
      proxyEnableFallback = proxyState.enableFallback;
      if (user.limit_gb && user.used_gb >= user.limit_gb) {
        serverSock.close();
        return;
      }
      if (user.expiry_days && user.created_at) {
        const created = new Date(user.created_at);
        const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
        if (new Date() > expiryDate) {
          try {
            await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(reqUUID).run();
          } catch (e) {}
          serverSock.close();
          return;
        }
      }
      validUUID = reqUUID;
      username = user.username;
      isHeaderParsed = true;
      if (isUserRequestLimitExceeded(user, username)) {
        serverSock.close();
        return;
      }
      trackUserRequest(username, env, ctx);
      let activeCount = activeConnCountByUser.get(username) || 0;
      activeConnCountByUser.set(username, activeCount + 1);
      if (activeCount === 0) {
        const setOnlineTask = async () => {
          try {
            const now = Date.now();
            lastActiveWriteAt.set(username, now);
            await env.DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(now, username).run();
          } catch (e) {}
        };
        if (ctx) ctx.waitUntil(setOnlineTask());
        else setOnlineTask();
      }
      try {
        let offset = 17;
        const optLen = chunkBuffer[offset++];
        offset += optLen;
        const cmd = chunkBuffer[offset++];
        const port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
        const addrType = chunkBuffer[offset++];
        let addr = '';
        if (addrType === 1) {
          addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
        } else if (addrType === 2) {
          const domainLen = chunkBuffer[offset++];
          addr = new TextDecoder().decode(chunkBuffer.slice(offset, offset + domainLen));
          offset += domainLen;
        } else if (addrType === 3) {
          offset += 16;
          addr = "ipv6-unsupported";
        }
        if (addr && addr !== 'ipv6-unsupported') {
          const blockSettings = await DomainBlockService.getSettings(env);
          const manualBlocked = blockSettings.enabled && DomainBlockService.isBlocked(addr, blockSettings.domains);
          const policyResult = manualBlocked ? { blocked: false } : await ContentPolicyService.checkBlocked(env, addr);
          if (manualBlocked || policyResult.blocked) {
            const logTask = ConnectionLogService.addLog(env, username, connectClientIp, {
              eventType: 'مسدود شده',
              extra: 'دامنه: ' + addr + (policyResult.blocked ? ' (' + policyResult.reason + ')' : '')
            });
            if (ctx) ctx.waitUntil(logTask);
            else logTask.catch(() => {});
            serverSock.close();
            return;
          }
        }
        const rawData = chunkBuffer.slice(offset);
        const respHeader = new Uint8Array([chunkBuffer[0], 0]);
        if (cmd === 2) {
          if (port === 53) {
            isDnsQuery = true;
            await forwardVlessUDP(rawData, serverSock, respHeader, addBytes);
          } else {
            serverSock.close();
          }
          return;
        }
        const connectTCP = async (dataPayload = null, useFallback = true) => {
          if (remoteConnWrapper.connectingPromise) {
            await remoteConnWrapper.connectingPromise;
            return;
          }
          const establishConnection = async (targetAddr, targetPort, payload, allowProxyRetry) => {
            let s = null;
            try {
              s = await connectDirect(targetAddr, targetPort, payload);
            } catch (err) {
              if (useFallback && allowProxyRetry && activeProxyIp) {
                try {
                  s = await connectViaActiveProxy(activeProxyIp, activeProxyMode, targetAddr, port, validUUID || reqUUID, proxyEnableFallback, payload);
                } catch (proxyErr) {
                  throw err;
                }
              } else {
                throw err;
              }
            }
            remoteConnWrapper.socket = s;
            s.closed.catch(() => {}).finally(() => closeSocketQuietly(serverSock));
            const retryWithProxy = (useFallback && allowProxyRetry && activeProxyIp) ? async () => {
              try {
                try { remoteConnWrapper.socket?.close(); } catch (e) {}
                remoteConnWrapper.socket = null;
                const retrySocket = await connectViaActiveProxy(activeProxyIp, activeProxyMode, addr, port, validUUID || reqUUID, proxyEnableFallback, null);
                remoteConnWrapper.socket = retrySocket;
                retrySocket.closed.catch(() => {}).finally(() => closeSocketQuietly(serverSock));
                connectStreams(retrySocket, serverSock, respHeader, null, (b) => { addBytes(b); });
              } catch (e) {}
            } : null;
            connectStreams(s, serverSock, respHeader, retryWithProxy, (b) => { addBytes(b); });
          };
          const task = (async () => {
            await establishConnection(addr, port, dataPayload, true);
          })();
          remoteConnWrapper.connectingPromise = task;
          try {
            await task;
          } finally {
            if (remoteConnWrapper.connectingPromise === task) {
              remoteConnWrapper.connectingPromise = null;
            }
          }
        };
        remoteConnWrapper.retryConnect = async () => {
          if (!activeProxyIp) return;
          try {
            try { remoteConnWrapper.socket?.close(); } catch (e) {}
            remoteConnWrapper.socket = null;
            const s = await connectViaActiveProxy(activeProxyIp, activeProxyMode, addr, port, validUUID || reqUUID, proxyEnableFallback, null);
            remoteConnWrapper.socket = s;
            s.closed.catch(() => {}).finally(() => closeSocketQuietly(serverSock));
            connectStreams(s, serverSock, respHeader, null, (b) => { addBytes(b); });
          } catch (e) {}
        };
        await connectTCP(rawData, true);
      } catch (e) {
        serverSock.close();
      }
    }
  };
  const handleWsError = (err) => {
    if (wsFailed) return;
    wsFailed = true;
    wsStopped = true;
    wsQueueBytes = 0;
    wsQueueItems = 0;
    upstreamQueue.clear();
    releaseRemoteWriter();
    closeSocketQuietly(serverSock);
    setOffline();
  };
  const pushToChain = (task) => {
    wsChain = wsChain.then(task).catch(handleWsError);
  };
  serverSock.addEventListener('message', (event) => {
    if (wsStopped || wsFailed) return;
    const size = event.data.byteLength || 0;
    const nextBytes = wsQueueBytes + size;
    const nextItems = wsQueueItems + 1;
    if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
      handleWsError(new Error('ws queue overflow'));
      return;
    }
    wsQueueBytes = nextBytes;
    wsQueueItems = nextItems;
    pushToChain(async () => {
      wsQueueBytes = Math.max(0, wsQueueBytes - size);
      wsQueueItems = Math.max(0, wsQueueItems - 1);
      if (wsFailed) return;
      await processWsMessage(event.data);
    });
  });
  serverSock.addEventListener('close', () => {
    clearInterval(heartbeat);
    closeSocketQuietly(serverSock);
    setOffline();
    if (wsFinished) return;
    wsFinished = true;
    wsStopped = true;
    pushToChain(async () => {
      if (wsFailed) return;
      await upstreamQueue.awaitEmpty();
      releaseRemoteWriter();
    });
  });
  serverSock.addEventListener('error', (err) => {
    handleWsError(err);
  });
  return new Response(null, { status: 101, webSocket: clientSock });
}
async function getCfUsage(env) {
  const cfToken = await DbService.getCfToken(env);
  const cfAccountId = await DbService.getCfAccountIdResolved(env);
  if (!cfToken || !cfAccountId) return { today: 0, total: 0 };
  try {
    const now = new Date();
    const startOfDay = new Date(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()).toISOString();
    const thirtyDaysAgo = new Date(now.getTime() - (30 * 24 * 60 * 60 * 1000)).toISOString();
    const q = `query {
      viewer {
        accounts(filter: {accountTag: "${cfAccountId}"}) {
          today: workersInvocationsAdaptive(limit: 10, filter: {datetime_geq: "${startOfDay}"}) {
            sum { requests }
          }
          total: workersInvocationsAdaptive(limit: 10, filter: {datetime_geq: "${thirtyDaysAgo}"}) {
            sum { requests }
          }
        }
      }
    }`;
    const res = await fetchWithTimeout("https://api.cloudflare.com/client/v4/graphql", {
      method: "POST",
      headers: { "Authorization": "Bearer " + cfToken, "Content-Type": "application/json" },
      body: JSON.stringify({ query: q })
    }, 5000);
    const j = await res.json();
    const acc = j?.data?.viewer?.accounts?.[0];
    const todayReqs = acc?.today?.[0]?.sum?.requests || 0;
    const totalReqs = acc?.total?.[0]?.sum?.requests || todayReqs;
    return { today: todayReqs, total: totalReqs };
  } catch (e) { return { today: 0, total: 0 }; }
}
function isIPv4(value) {
  const parts = String(value || '').split('.');
  return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}
function flagEmojiFromCountryCode(cc) {
  const code = String(cc || '').trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return '';
  const codePoints = code.split('').map(ch => 127397 + ch.charCodeAt(0));
  try {
    return String.fromCodePoint(...codePoints);
  } catch (e) {
    return '';
  }
}
function stripIPv6Brackets(hostname = '') {
  const host = String(hostname || '').trim();
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}
function isIPHostname(hostname = '') {
  const host = stripIPv6Brackets(hostname);
  if (isIPv4(host)) return true;
  if (!host.includes(':')) return false;
  try {
    new URL(`http://[${host}]/`);
    return true;
  } catch (e) {
    return false;
  }
}
function convertToUint8Array(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new Uint8Array(data || 0);
}
function concatBytes(...chunkList) {
  const chunks = chunkList.map(convertToUint8Array);
  const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    result.set(c, offset);
    offset += c.byteLength;
  }
  return result;
}
function closeSocketQuietly(socket) {
  try {
    if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
      socket.close();
    }
  } catch (e) {}
}
async function dohQuery(domain, recordType) { 
  const cacheKey = `${domain}:${recordType}`;
  if (dnsAnswerCache.has(cacheKey)) {
    const cached = dnsAnswerCache.get(cacheKey);
    if (Date.now() < cached.expires) return cached.data;
    dnsAnswerCache.delete(cacheKey);
  }
  try {
    const typeMap = { 'A': 1, 'AAAA': 28, 'TXT': 16 };
    const qtype = typeMap[recordType.toUpperCase()] || 1;
    const encodeDomain = (name) => {
      const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
      const bufs = [];
      for (const label of parts) {
        const enc = new TextEncoder().encode(label);
        bufs.push(new Uint8Array([enc.length]), enc);
      }
      bufs.push(new Uint8Array([0]));
      return concatBytes(...bufs);
    };
    const qname = encodeDomain(domain);
    const query = new Uint8Array(12 + qname.length + 4);
    const qview = new DataView(query.buffer);
    qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
    qview.setUint16(2, 0x0100); 
    qview.setUint16(4, 1); 
    query.set(qname, 12);
    qview.setUint16(12 + qname.length, qtype);
    qview.setUint16(12 + qname.length + 2, 1);
    const response = await fetch(DOH_RESOLVER_URL, { 
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message',
      },
      body: query,
    });
    if (!response.ok) return [];
    const buf = new Uint8Array(await response.arrayBuffer());
    const dv = new DataView(buf.buffer);
    const qdcount = dv.getUint16(4);
    const ancount = dv.getUint16(6);
    const parseName = (pos) => {
      const labels = [];
      let p = pos, jumped = false, endPos = -1, safe = 128;
      while (p < buf.length && safe-- > 0) {
        const len = buf[p];
        if (len === 0) { if (!jumped) endPos = p + 1; break; }
        if ((len & 0xC0) === 0xC0) {
          if (!jumped) endPos = p + 2;
          p = ((len & 0x3F) << 8) | buf[p + 1];
          jumped = true;
          continue;
        } 
        labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
        p += len + 1;
      }
      if (endPos === -1) endPos = p + 1;
      return [labels.join('.'), endPos];
    };
    let offset = 12;
    for (let i = 0; i < qdcount; i++) {
      const [, end] = parseName(offset);
      offset = Number(end) + 4;
    }
    const answers = [];
    for (let i = 0; i < ancount && offset < buf.length; i++) {
      const [name, nameEnd] = parseName(offset);
      offset = Number(nameEnd);
      const type = dv.getUint16(offset); offset += 2;
      offset += 2; 
      const ttl = dv.getUint32(offset); offset += 4;
      const rdlen = dv.getUint16(offset); offset += 2;
      const rdata = buf.slice(offset, offset + rdlen);
      offset += rdlen;
      let data;
      if (type === 1 && rdlen === 4) {
        data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
      } else if (type === 28 && rdlen === 16) {
        const segs = [];
        for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
        data = segs.join(':');
      } else if (type === 16) {
        let tOff = 0;
        const parts = [];
        while (tOff < rdlen) {
          const tLen = rdata[tOff++];
          parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
          tOff += tLen;
        }
        data = parts.join('');
      } else {
        data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
      }
      answers.push({ name, type, TTL: ttl, data });
    }
    dnsAnswerCache.set(cacheKey, { data: answers, expires: Date.now() + dnsAnswerCache_TTL });
    return answers;
  } catch (e) {
    return [];
  }
}
function createUpstreamQueue({ getWriter, releaseWriter, retryConnect, closeConnection, name = 'UpstreamQueue' }) {
  let chunks = [];
  let head = 0;
  let queuedBytes = 0;
  let draining = false;
  let closed = false;
  let bundleBuffer = null;
  let idleResolvers = [];
  let activeCompletions = null;
  const settleCompletions = (completions, err = null) => {
    if (!completions) return;
    for (const comp of completions) {
      if (comp) {
        if (err) comp.reject(err);
        else comp.resolve();
      }
    }
  };
  const rejectQueued = (err) => {
    for (let i = head; i < chunks.length; i++) {
      const item = chunks[i];
      if (item && item.completions) settleCompletions(item.completions, err);
    }
  };
  const compact = () => {
    if (head > 32 && head * 2 >= chunks.length) {
      chunks = chunks.slice(head);
      head = 0;
    }
  };
  const resolveIdle = () => {
    if (queuedBytes || draining || !idleResolvers.length) return;
    const resolvers = idleResolvers;
    idleResolvers = [];
    for (const resolve of resolvers) resolve();
  };
  const clear = (err = null) => {
    const closeErr = err || (closed ? new Error(`${name}: queue closed`) : null);
    if (closeErr) {
      rejectQueued(closeErr);
      settleCompletions(activeCompletions, closeErr);
      activeCompletions = null;
    }
    chunks = [];
    head = 0;
    queuedBytes = 0;
    resolveIdle();
  };
  const shift = () => {
    if (head >= chunks.length) return null;
    const item = chunks[head];
    chunks[head++] = undefined;
    queuedBytes -= item.chunk.byteLength;
    compact();
    return item;
  };
  const bundle = () => {
    const first = shift();
    if (!first) return null;
    if (head >= chunks.length || first.chunk.byteLength >= UPSTREAM_BUNDLE_TARGET_BYTES) return first;
    let byteLength = first.chunk.byteLength;
    let end = head;
    let allowRetry = first.allowRetry;
    let completions = first.completions || null;
    while (end < chunks.length) {
      const next = chunks[end];
      const nextLength = byteLength + next.chunk.byteLength;
      if (nextLength > UPSTREAM_BUNDLE_TARGET_BYTES) break;
      byteLength = nextLength;
      allowRetry = allowRetry && next.allowRetry;
      if (next.completions) completions = completions ? completions.concat(next.completions) : next.completions;
      end++;
    }
    if (end === head) return first;
    const output = (bundleBuffer ||= new Uint8Array(UPSTREAM_BUNDLE_TARGET_BYTES));
    output.set(first.chunk);
    let offset = first.chunk.byteLength;
    while (head < end) {
      const next = chunks[head];
      chunks[head++] = undefined;
      queuedBytes -= next.chunk.byteLength;
      output.set(next.chunk, offset);
      offset += next.chunk.byteLength;
    }
    compact();
    return { chunk: output.subarray(0, byteLength), allowRetry, completions };
  };
  const drain = async () => {
    if (draining || closed) return;
    draining = true;
    try {
      for (; ;) {
        if (closed) break;
        const item = bundle();
        if (!item) break;
        let writer = getWriter();
        if (!writer) throw new Error(`${name}: remote writer unavailable`);
        const completions = item.completions || null;
        activeCompletions = completions;
        try {
          try {
            await writer.write(item.chunk);
          } catch (err) {
            releaseWriter?.();
            if (!item.allowRetry || typeof retryConnect !== 'function') throw err;
            await retryConnect();
            writer = getWriter();
            if (!writer) throw err;
            await writer.write(item.chunk);
          }
          settleCompletions(completions);
        } catch (err) {
          settleCompletions(completions, err);
          throw err;
        } finally {
          if (activeCompletions === completions) activeCompletions = null;
        }
      }
    } catch (err) {
      closed = true;
      clear(err);
      try { closeConnection?.(err); } catch (_) {}
    } finally {
      draining = false;
      if (!closed && head < chunks.length) queueMicrotask(drain);
      else resolveIdle();
    }
  };
  const enqueue = (data, allowRetry = true, waitForFlush = false) => {
    if (closed) return false;
    if (!getWriter()) return false;
    const chunk = convertToUint8Array(data);
    if (!chunk.byteLength) return true;
    const nextBytes = queuedBytes + chunk.byteLength;
    const nextItems = chunks.length - head + 1;
    if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
      closed = true;
      const err = Object.assign(new Error(`${name}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
      clear(err);
      try { closeConnection?.(err); } catch (_) {}
      throw err;
    }
    let completionPromise = null;
    let completions = null;
    if (waitForFlush) {
      completions = [];
      completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
    }
    chunks.push({ chunk, allowRetry, completions });
    queuedBytes = nextBytes;
    if (!draining) queueMicrotask(drain);
    return waitForFlush ? completionPromise.then(() => true) : true;
  };
  return {
    writeAndAwait(data, allowRetry = true) { return enqueue(data, allowRetry, true); },
    async awaitEmpty() {
      if (!queuedBytes && !draining) return;
      await new Promise(resolve => idleResolvers.push(resolve));
    },
    clear() { closed = true; clear(); }
  };
}
function createDownstreamSender(webSocket, headerData = null) {
  const packetCap = DOWNSTREAM_CHUNK_BYTES;
  const tailBytes = DOWNSTREAM_CHUNK_TAIL_MIN;
  const lowWaterBytes = Math.max(4096, tailBytes << 3);
  let header = headerData;
  let pendingBuffer = new Uint8Array(packetCap);
  let pendingBytes = 0;
  let flushTimer = null;
  let microtaskQueued = false;
  let generation = 0;
  let scheduledGeneration = 0;
  let waitRounds = 0;
  let flushPromise = null;
  const sendRawChunk = async (chunk) => {
    if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
    webSocket.send(chunk);
  };
  const attachResponseHeader = (chunk) => {
    if (!header) return chunk;
    const merged = new Uint8Array(header.length + chunk.byteLength);
    merged.set(header, 0);
    merged.set(chunk, header.length);
    header = null;
    return merged;
  };
  const flush = async () => {
    while (flushPromise) await flushPromise;
    if (flushTimer) clearTimeout(flushTimer);
    flushTimer = null;
    microtaskQueued = false;
    if (!pendingBytes) return;
    const output = pendingBuffer.subarray(0, pendingBytes).slice();
    pendingBuffer = new Uint8Array(packetCap);
    pendingBytes = 0;
    waitRounds = 0;
    flushPromise = sendRawChunk(output).finally(() => { flushPromise = null; });
    return flushPromise;
  };
  const scheduleFlush = () => {
    if (flushTimer || microtaskQueued) return;
    microtaskQueued = true;
    scheduledGeneration = generation;
    queueMicrotask(() => {
      microtaskQueued = false;
      if (!pendingBytes || flushTimer) return;
      if (packetCap - pendingBytes < tailBytes) {
        flush().catch(() => closeSocketQuietly(webSocket));
        return;
      }
      flushTimer = setTimeout(() => {
        flushTimer = null;
        if (!pendingBytes) return;
        if (packetCap - pendingBytes < tailBytes) {
          flush().catch(() => closeSocketQuietly(webSocket));
          return;
        }
        if (waitRounds < 2 && (generation !== scheduledGeneration || pendingBytes < lowWaterBytes)) {
          waitRounds++;
          scheduledGeneration = generation;
          scheduleFlush();
          return;
        }
        flush().catch(() => closeSocketQuietly(webSocket));
      }, Math.max(DOWNSTREAM_FLUSH_DELAY_MS, 1));
    });
  };
  return {
    async sendDirect(data) {
      let chunk = convertToUint8Array(data);
      if (!chunk.byteLength) return;
      chunk = attachResponseHeader(chunk);
      await sendRawChunk(chunk);
    },
    async send(data) {
      let chunk = convertToUint8Array(data);
      if (!chunk.byteLength) return;
      chunk = attachResponseHeader(chunk);
      let offset = 0;
      const totalBytes = chunk.byteLength;
      while (offset < totalBytes) {
        if (!pendingBytes && totalBytes - offset >= packetCap) {
          const sendBytes = Math.min(packetCap, totalBytes - offset);
          const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
          await sendRawChunk(view);
          offset += sendBytes;
          continue;
        }
        const copyBytes = Math.min(packetCap - pendingBytes, totalBytes - offset);
        pendingBuffer.set(chunk.subarray(offset, offset + copyBytes), pendingBytes);
        pendingBytes += copyBytes;
        offset += copyBytes;
        generation++;
        if (pendingBytes === packetCap || packetCap - pendingBytes < tailBytes) await flush();
        else scheduleFlush();
      }
    },
    flush
  };
}
async function waitForBackpressure(ws) {
  if (typeof ws.bufferedAmount === 'number') {
    while (ws.bufferedAmount > 256 * 1024) {
      await new Promise(r => setTimeout(r, 100));
    }
  }
}
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, onBytes) {
  let header = headerData, hasData = false, reader, useBYOB = false;
  const BYOB_LIMIT = 64 * 1024;
  const downstreamSender = createDownstreamSender(webSocket, header);
  header = null;
  try { 
    reader = remoteSocket.readable.getReader({ mode: 'byob' }); 
    useBYOB = true; 
  } catch (e) { 
    reader = remoteSocket.readable.getReader(); 
  }
  try {
    if (!useBYOB) {
      while (true) {
        await waitForBackpressure(webSocket);
        const { done, value } = await reader.read();
        if (done) break;
        if (!value || value.byteLength === 0) continue;
        hasData = true;
        if (typeof onBytes === 'function') onBytes(value.byteLength);
        await downstreamSender.send(value);
      }
    } else {
      let readBuffer = new ArrayBuffer(BYOB_LIMIT);
      while (true) {
        await waitForBackpressure(webSocket);
        const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOB_LIMIT));
        if (done) break;
        if (!value || value.byteLength === 0) continue;
        hasData = true;
        if (typeof onBytes === 'function') onBytes(value.byteLength);
        if (value.byteLength >= DOWNSTREAM_CHUNK_BYTES) {
          await downstreamSender.flush();
          await downstreamSender.sendDirect(value);
          readBuffer = new ArrayBuffer(BYOB_LIMIT);
        } else {
          await downstreamSender.send(value);
          readBuffer = value.buffer.byteLength >= BYOB_LIMIT ? value.buffer : new ArrayBuffer(BYOB_LIMIT);
        }
      }
    }
    await downstreamSender.flush();
  } catch (err) { 
    closeSocketQuietly(webSocket);
  } finally { 
    try { reader.cancel(); } catch (e) {} 
    try { reader.releaseLock(); } catch (e) {} 
  }
  if (!hasData && retryFunc) await retryFunc();
}
async function buildRaceCandidates(address, port) {
  if (!RACE_DIAL_ENABLED || isIPHostname(address)) return null;
  const [aRecords, aaaaRecords] = await Promise.all([
    dohQuery(address, 'A'),
    dohQuery(address, 'AAAA')
  ]);
  const ipv4List = [...new Set(aRecords.flatMap(r => {
    return r.type === 1 && typeof r.data === 'string' && isIPv4(r.data) ? [r.data] : [];
  }))];
  const ipv6List = [...new Set(aaaaRecords.flatMap(r => {
    return r.type === 28 && typeof r.data === 'string' && isIPHostname(r.data) ? [r.data] : [];
  }))];
  const limit = Math.max(1, TCP_DIAL_CONCURRENCY | 0);
  const ipList = ipv4List.length >= limit
    ? ipv4List.slice(0, limit)
    : ipv4List.concat(ipv6List.slice(0, limit - ipv4List.length));
  if (ipList.length === 0) return null;
  return ipList.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
}
async function openTcpConnection(host, port, timeoutMs = 1500) {
  const connectFn = await loadTcpConnect();
  const socket = connectFn({ hostname: host, port });
  await Promise.race([
    socket.opened,
    new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), timeoutMs))
  ]);
  return socket;
}
async function writeInitialTcpData(socket, initialData) {
  if (!initialData || !initialData.byteLength) return;
  const w = socket.writable.getWriter();
  try {
    await w.write(convertToUint8Array(initialData));
  } finally {
    w.releaseLock();
  }
}
async function raceOpenTcpConnections(candidates, initialData) {
  if (candidates.length === 1) {
    const s = await openTcpConnection(candidates[0].hostname, candidates[0].port);
    await writeInitialTcpData(s, initialData);
    return { socket: s, candidate: candidates[0] };
  }
  const attempts = candidates.map(c =>
    openTcpConnection(c.hostname, c.port).then(socket => ({ socket, candidate: c }))
  );
  let winner = null;
  try {
    winner = await Promise.any(attempts);
    await writeInitialTcpData(winner.socket, initialData);
    return winner;
  } finally {
    if (winner) {
      for (const attempt of attempts) {
        attempt.then(({ socket }) => {
          if (socket !== winner.socket) {
            try { socket.close(); } catch (e) {}
          }
        }).catch(() => {});
      }
    }
  }
}
async function connectSocks5(socks5Config, targetHost, targetPort, initialData) {
  let auth = null;
  let hostPort = String(socks5Config || '').trim();
  if (hostPort.includes('@')) {
    const atIdx = hostPort.lastIndexOf('@');
    const credPart = hostPort.slice(0, atIdx);
    hostPort = hostPort.slice(atIdx + 1);
    const colonIdx = credPart.indexOf(':');
    if (colonIdx >= 0) {
      auth = { user: credPart.slice(0, colonIdx), pass: credPart.slice(colonIdx + 1) };
    }
  }
  const parts = hostPort.split(':');
  const sHost = parts[0];
  const sPort = parseInt(parts[1], 10) || 1080;

  const connectFn = await loadTcpConnect();
  const socket = connectFn({ hostname: sHost, port: sPort });
  await Promise.race([
    socket.opened,
    new Promise((_, reject) => setTimeout(() => reject(new Error('socks5 timeout')), 4000))
  ]);
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();

  const readExact = async (n) => {
    let buf = new Uint8Array(0);
    while (buf.byteLength < n) {
      const { value, done } = await reader.read();
      if (done) throw new Error('socks5 connection closed');
      const merged = new Uint8Array(buf.byteLength + value.byteLength);
      merged.set(buf, 0);
      merged.set(value, buf.byteLength);
      buf = merged;
    }
    return buf;
  };

  const methods = auth ? [0x00, 0x02] : [0x00];
  await writer.write(new Uint8Array([0x05, methods.length, ...methods]));
  let resp = await readExact(2);
  if (resp[0] !== 0x05) throw new Error('socks5 handshake failed');
  const method = resp[1];

  if (method === 0x02) {
    if (!auth) throw new Error('socks5 server requires auth (user:pass@host:port)');
    const userBytes = new TextEncoder().encode(auth.user);
    const passBytes = new TextEncoder().encode(auth.pass);
    await writer.write(new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]));
    resp = await readExact(2);
    if (resp[1] !== 0x00) throw new Error('socks5 auth failed');
  } else if (method !== 0x00) {
    throw new Error('socks5: no acceptable auth method');
  }

  const isIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(targetHost);
  let atyp, addrBytes;
  if (isIPv4) {
    atyp = 0x01;
    addrBytes = new Uint8Array(targetHost.split('.').map(Number));
  } else {
    atyp = 0x03;
    const domainBytes = new TextEncoder().encode(targetHost);
    addrBytes = new Uint8Array([domainBytes.length, ...domainBytes]);
  }
  const portBytes = new Uint8Array([(targetPort >> 8) & 0xff, targetPort & 0xff]);
  await writer.write(new Uint8Array([0x05, 0x01, 0x00, atyp, ...addrBytes, ...portBytes]));

  resp = await readExact(4);
  if (resp[1] !== 0x00) throw new Error('socks5 connect failed, code=' + resp[1]);
  const boundAtyp = resp[3];
  if (boundAtyp === 0x01) await readExact(4 + 2);
  else if (boundAtyp === 0x03) { const len = (await readExact(1))[0]; await readExact(len + 2); }
  else if (boundAtyp === 0x04) await readExact(16 + 2);

  writer.releaseLock();
  reader.releaseLock();

  if (initialData && initialData.byteLength) {
    const w = socket.writable.getWriter();
    await w.write(convertToUint8Array(initialData));
    w.releaseLock();
  }
  return socket;
}
async function connectViaActiveProxy(activeProxyIp, activeProxyMode, targetAddr, targetPort, uuid, enableFallback, payload) {
  if (activeProxyMode === 'socks5') {
    return connectSocks5(activeProxyIp, targetAddr, targetPort, payload);
  }
  return connectProxyCDN(activeProxyIp, targetAddr, targetPort, uuid, enableFallback, payload);
}
async function connectProxyCDN(proxyIP, targetHost, targetPort, uuid, enableFallback, initialData = null) {
  const allProxies = await CdnProxyService.resolveProxyAddresses(proxyIP, targetHost, uuid);
  const limit = Math.max(1, TCP_DIAL_CONCURRENCY | 0);
  if (allProxies.length > 0) {
    for (let i = 0; i < allProxies.length; i += limit) {
      const candidates = [];
      for (let j = 0; j < limit && i + j < allProxies.length; j++) {
        const idx = (cachedProxyResolveIndex + i + j) % allProxies.length;
        const [proxyAddr, proxyPort] = allProxies[idx];
        candidates.push({ hostname: proxyAddr, port: proxyPort, index: idx });
      }
      try {
        const result = await raceOpenTcpConnections(candidates, initialData);
        cachedProxyResolveIndex = result.candidate.index;
        return result.socket;
      } catch (e) {}
    }
  }
  if (enableFallback) {
    try {
      return await connectDirect(targetHost, targetPort, initialData);
    } catch (e) {}
   }
   throw new Error('All CDN proxy connections failed');
}
async function connectDirect(address, port, initialData = null) {
  const raceCandidates = await buildRaceCandidates(address, port);
  const candidates = raceCandidates || Array.from({ length: TCP_DIAL_CONCURRENCY }, () => ({ hostname: address, port }));
  const openConnection = async (host, prt) => {
    const connectFn = await loadTcpConnect();
    const socket = connectFn({ hostname: host, port: prt });
    await Promise.race([
      socket.opened,
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 1500))
    ]);
    return socket;
  };
  if (candidates.length === 1) {
    const s = await openConnection(candidates[0].hostname, candidates[0].port);
    if (initialData && initialData.byteLength > 0) {
      const w = s.writable.getWriter();
      await w.write(convertToUint8Array(initialData));
      w.releaseLock();
    }
    return s;
  }
  const attempts = candidates.map(c => openConnection(c.hostname, c.port).then(socket => ({ socket, candidate: c })));
  let winner = null;
  try {
    winner = await Promise.any(attempts);
    if (initialData && initialData.byteLength > 0) {
      const w = winner.socket.writable.getWriter();
      await w.write(convertToUint8Array(initialData));
      w.releaseLock();
    }
    return winner.socket;
  } finally {
    if (winner) {
      for (const attempt of attempts) {
        attempt.then(({ socket }) => {
          if (socket !== winner.socket) {
            try { socket.close(); } catch (e) {}
          }
        }).catch(() => {});
      }
    }
  }
}
async function forwardVlessUDP(udpChunk, webSocket, respHeader, onBytes) {
  const requestData = convertToUint8Array(udpChunk);
  try {
    const connectFn = await loadTcpConnect();
    const tcpSocket = connectFn({ hostname: '8.8.4.4', port: 53 });
    let vlessHeader = respHeader;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(requestData);
    writer.releaseLock();
    await tcpSocket.readable.pipeTo(new WritableStream({
      async write(chunk) {
        const response = convertToUint8Array(chunk);
        if (typeof onBytes === 'function') onBytes(response.byteLength);
        if (webSocket.readyState !== WebSocket.OPEN) return;
        if (vlessHeader) {
          const merged = new Uint8Array(vlessHeader.length + response.byteLength);
          merged.set(vlessHeader, 0);
          merged.set(response, vlessHeader.length);
          webSocket.send(merged.buffer);
          vlessHeader = null;
        } else {
          webSocket.send(response);
        }
      }
    }));
  } catch (e) {}
}
function extractUUIDFromVless(data) {
  if (data.byteLength < 17) return null;
  const hex = [...data.slice(1, 17)].map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}
function getRequestDateKey() {
  return new Date().toISOString().split('T')[0];
}
function getUserReqUsageToday(user, username) {
  const pending = userRequestPending.get(username) || 0;
  const today = getRequestDateKey();
  const dbToday = (user && user.req_last_date === today) ? (parseInt(user.used_requests_today) || 0) : 0;
  return dbToday + pending;
}
function getUserReqUsageTotal(user, username) {
  const pending = userRequestPending.get(username) || 0;
  return (parseInt(user?.used_requests) || 0) + pending;
}
function getUserReqUsage(user, username) {
  return getUserReqUsageToday(user, username);
}
function isUserRequestLimitExceeded(user, username) {
  if (!user) return false;
  if (user.max_requests && user.max_requests > 0 && getUserReqUsageTotal(user, username) >= user.max_requests) return true;
  if (user.max_requests_daily && user.max_requests_daily > 0 && getUserReqUsageToday(user, username) >= user.max_requests_daily) return true;
  return false;
}
function getUserRequestLimitReason(user, username) {
  if (!user) return null;
  if (user.max_requests && user.max_requests > 0 && getUserReqUsageTotal(user, username) >= user.max_requests) return 'total';
  if (user.max_requests_daily && user.max_requests_daily > 0 && getUserReqUsageToday(user, username) >= user.max_requests_daily) return 'daily';
  return null;
}
async function resolveRequestUsername(url, env) {
  try {
    const workerCfg = await WorkerConfigService.loadSettings(env);
    const subPath = workerCfg.subPagePath || WORKER_CONFIG_DEFAULTS.subPagePath;
    if (pathStartsWithSegment(url.pathname, subPath)) {
      const key = extractSegmentKey(url.pathname, subPath);
      if (!key) return null;
      const user = await env.DB.prepare("SELECT username FROM users WHERE username = ? OR uuid = ?").bind(key, key).first();
      return user?.username || null;
    }
    const statusPath = workerCfg.statusPagePath || WORKER_CONFIG_DEFAULTS.statusPagePath;
    if (pathStartsWithSegment(url.pathname, statusPath)) {
      const key = extractSegmentKey(url.pathname, statusPath);
      if (!key) return null;
      const user = await StatusUrlService.resolveUser(env.DB, key);
      return user?.username || null;
    }
    const logsPath = workerCfg.logsPagePath || WORKER_CONFIG_DEFAULTS.logsPagePath;
    if (pathStartsWithSegment(url.pathname, logsPath)) {
      const key = extractSegmentKey(url.pathname, logsPath);
      if (!key) return null;
      const user = await env.DB.prepare("SELECT username FROM users WHERE username = ? OR uuid = ?").bind(key, key).first();
      return user?.username || null;
    }
  } catch (e) {}
  return null;
}
async function flushUserRequestCounts(env, username) {
  const pending = userRequestPending.get(username) || 0;
  if (pending <= 0) return;
  userRequestPending.set(username, 0);
  const today = getRequestDateKey();
  try {
    const row = await env.DB.prepare("SELECT used_requests, used_requests_today, req_last_date FROM users WHERE username = ?").bind(username).first();
    if (!row) return;
    const totalUsed = (parseInt(row.used_requests) || 0) + pending;
    let todayUsed = (row.req_last_date === today) ? (parseInt(row.used_requests_today) || 0) : 0;
    todayUsed += pending;
    await env.DB.prepare("UPDATE users SET used_requests = ?, used_requests_today = ?, req_last_date = ? WHERE username = ?").bind(totalUsed, todayUsed, today, username).run();
  } catch (e) {
    userRequestPending.set(username, (userRequestPending.get(username) || 0) + pending);
  }
}
function trackUserRequest(username, env, ctx) {
  if (!username) return;
  userRequestPending.set(username, (userRequestPending.get(username) || 0) + 1);
  const now = Date.now();
  const lastFlush = userRequestLastFlush.get(username) || 0;
  if (now - lastFlush > 15000) {
    userRequestLastFlush.set(username, now);
    const task = async () => { await flushUserRequestCounts(env, username); };
    if (ctx) ctx.waitUntil(task());
    else task();
  }
}
async function getTopRequestUsers(env, limit = 3) {
  try {
    const { results } = await env.DB.prepare(
      "SELECT username, used_requests, max_requests, req_last_date, used_requests_today FROM users WHERE is_system != 1 AND max_requests > 0 ORDER BY used_requests DESC LIMIT 30"
    ).all();
    return (results || [])
      .map(u => ({
        username: u.username,
        used: getUserReqUsageTotal(u, u.username),
        max: u.max_requests
      }))
      .filter(u => u.used > 0 && u.max > 0)
      .sort((a, b) => (b.used / b.max) - (a.used / a.max))
      .slice(0, limit);
  } catch (e) {
    return [];
  }
}
function trackRequest(env, ctx) {
    pendingRequestCount++;
    const now = Date.now();
    if (now - lastRequestFlushAt > 15000 && pendingRequestCount > 0) {
        lastRequestFlushAt = now;
        const countToSave = pendingRequestCount;
        pendingRequestCount = 0;
        const task = async () => {
            try {
                const today = new Date().toISOString().split('T')[0];
                await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_total', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?").bind(String(countToSave), String(countToSave)).run();
                const lastDateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_last_date'").first();
                if (!lastDateRow || lastDateRow.value !== today) {
                    await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_last_date', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(today, today).run();
                    await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(countToSave), String(countToSave)).run();
                } else {
                    await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?").bind(String(countToSave), String(countToSave)).run();
                }
            } catch (e) {}
        };
        if (ctx) ctx.waitUntil(task());
        else task();
    }
}
const NEXA_ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1080 1093"><defs><linearGradient id="litGrad" x1="0%" y1="0%" x2="95%" y2="100%"><stop offset="0%" stop-color="#79E62A"/><stop offset="45%" stop-color="#3FB53A"/><stop offset="100%" stop-color="#1E8A2E"/></linearGradient></defs><path d="M 1079.8,2.8 L 968.8,1.0 L 922.8,10.0 L 868.2,39.2 L 822.2,96.5 L 806.0,158.8 L 803.2,520.8 L 315.5,12.2 L 2.2,13.2 L 2.0,225.0 L 164.0,394.0 L 67.2,466.2 L 27.2,524.2 L 8.0,577.8 L 2.0,625.8 L 2.0,1092.8 L 132.0,1092.8 L 161.0,1083.8 L 221.0,1044.8 L 250.8,999.0 L 263.8,947.0 L 267.2,524.0 L 820.2,1087.5 L 1079.8,1088.8 L 1079.8,856.8 L 914.2,682.5 L 963.2,651.5 L 1019.5,595.2 L 1053.8,542.0 L 1073.8,486.0 L 1079.8,447.0 Z" fill="url(#litGrad)" fill-rule="evenodd"/><path d="M 616.0,340.0 L 615.0,341.8 L 615.0,501.2 L 616.0,504.5 L 616.0,522.2 L 618.0,529.5 L 619.0,540.2 L 626.0,567.8 L 640.0,600.0 L 654.5,623.8 L 666.5,638.8 L 686.0,658.2 L 697.0,667.2 L 712.8,677.8 L 739.8,691.2 L 767.2,699.8 L 790.5,703.8 L 806.0,703.5 L 806.8,616.5 L 805.8,608.5 L 806.8,605.2 L 806.8,594.5 L 805.8,591.2 L 805.2,537.0 L 675.5,402.2 L 618.0,340.2 Z M 218.2,389.0 L 224.5,392.0 L 232.5,405.2 L 254.0,408.2 L 256.2,421.5 L 259.8,420.5 L 263.0,471.5 L 262.2,574.5 L 268.2,524.2 L 279.5,531.0 L 819.8,1087.0 L 831.8,1089.8 L 1079.8,1088.8 L 1079.8,1084.0 L 1073.2,1088.2 L 824.2,1087.0 L 449.0,703.8 L 448.8,573.5 L 445.8,539.5 L 427.2,485.8 L 401.2,448.0 L 380.8,427.5 L 359.0,412.0 L 317.8,393.0 L 280.2,385.0 L 241.5,385.0 Z" fill="#164A18" fill-rule="evenodd"/></svg>`;
const NEXA_LOGO_URL = `data:image/svg+xml;charset=UTF-8,${encodeURIComponent(NEXA_ICON_SVG)}`;
const NEXA_FAVICON_TAGS = `
    <link rel="icon" type="image/svg+xml" href="${NEXA_LOGO_URL}">
    <link rel="shortcut icon" href="${NEXA_LOGO_URL}">
    <link rel="apple-touch-icon" href="${NEXA_LOGO_URL}">`;
const NEXA_THEME_COLOR_ADMIN = `<meta name="theme-color" content="#059669" id="nexa-theme-color" data-theme-light="#059669" data-theme-dark="#090b12">`;
const NEXA_THEME_COLOR_USER = `<meta name="theme-color" content="#6b9e8f" id="nexa-theme-color" data-theme-light="#6b9e8f" data-theme-dark="#131816">`;
const NEXA_THEME_COLOR_SETUP = `<meta name="theme-color" content="#3FB53A" id="nexa-theme-color" data-theme-light="#3FB53A" data-theme-dark="#0c1210">`;
const NEXA_THEME_COLOR_SYNC_SCRIPT = `<script>(function(){function syncThemeColor(){var m=document.getElementById('nexa-theme-color');if(!m||!m.dataset.themeLight)return;m.content=document.documentElement.classList.contains('dark')?m.dataset.themeDark:m.dataset.themeLight;}syncThemeColor();try{new MutationObserver(syncThemeColor).observe(document.documentElement,{attributes:true,attributeFilter:['class']});}catch(e){}})();</script>`;
const NEXA_USER_THEME_SCRIPT = `<script>
        (function() {
            try {
                var theme = localStorage.getItem('nexa-theme');
                if (!theme) {
                    var legacy = ['status-theme', 'guide-theme', 'proxyip-theme'];
                    for (var i = 0; i < legacy.length; i++) {
                        var v = localStorage.getItem(legacy[i]);
                        if (v === 'dark' || v === 'light') {
                            theme = v;
                            localStorage.setItem('nexa-theme', v);
                            break;
                        }
                    }
                }
                if (theme === 'dark' || (!theme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                    document.documentElement.classList.add('dark');
                } else {
                    document.documentElement.classList.remove('dark');
                }
            } catch (e) {}
        })();
        function toggleNexaTheme() {
            var root = document.documentElement;
            var isDark = root.classList.toggle('dark');
            localStorage.setItem('nexa-theme', isDark ? 'dark' : 'light');
        }
    </script>`;
const NEXA_USER_THEME_TOGGLE = `<button type="button" onclick="toggleNexaTheme()" class="theme-toggle-btn fixed top-4 left-4 z-50 p-2.5 rounded-xl hover:opacity-80 shadow-sm transition" title="تغییر تم">
        <svg class="w-5 h-5 hidden dark:block text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m12.728 0l-.707-.707M6.343 6.343l-.707-.707M14 12a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
        <svg class="w-5 h-5 block dark:hidden" style="color: var(--text-muted)" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
    </button>`;
const NEXA_USER_THEME_VARS = `
        :root {
            --page-bg: #f2f6f4;
            --page-bg2: #e8efeb;
            --card-bg: rgba(255, 255, 255, 0.97);
            --card-border: #d4e0da;
            --stat-bg: #f8faf9;
            --stat-border: #dde8e3;
            --section-bg: #f5f9f7;
            --section-border: #dde8e3;
            --text-main: #2c3833;
            --text-muted: #6b8078;
            --accent: #6b9e8f;
            --accent2: #82a8b8;
            --btn-bg: #ffffff;
            --btn-border: #cdd8d3;
            --toggle-bg: #ffffff;
            --toggle-border: #cdd8d3;
            --tab-bg: #ffffff;
            --tab-border: #cdd8d3;
            --tab-text: #5a6e66;
            --step-bg: #e4f0eb;
            --step-text: #4a7d6e;
            --success-bg: #edf7f1;
            --success-border: #b8dcc8;
            --success-text: #3d6b58;
            --link-color: #5a8f80;
            --divider: #cdd8d3;
            --info-bg: #f0f6f3;
            --info-border: #c8dcd3;
        }
        html.dark {
            --page-bg: #131816;
            --page-bg2: #1a211e;
            --card-bg: rgba(28, 34, 31, 0.97);
            --card-border: #2d3a35;
            --stat-bg: #222a27;
            --stat-border: #33403b;
            --section-bg: #222a27;
            --section-border: #33403b;
            --text-main: #e4ece8;
            --text-muted: #93a69e;
            --accent: #8fbfb0;
            --accent2: #9ec4d4;
            --btn-bg: #222a27;
            --btn-border: #3a4842;
            --toggle-bg: #222a27;
            --toggle-border: #3a4842;
            --tab-bg: #222a27;
            --tab-border: #3a4842;
            --tab-text: #93a69e;
            --step-bg: #2a3832;
            --step-text: #8fbfb0;
            --success-bg: #1a2e26;
            --success-border: #2d4a3e;
            --success-text: #8fd4b0;
            --link-color: #8fbfb0;
            --divider: #3a4842;
            --info-bg: #1a2822;
            --info-border: #2d4038;
        }`;
const NEXA_USER_THEME_COMMON = `
        .theme-toggle-btn { background: var(--toggle-bg); border: 1px solid var(--toggle-border); }
        .back-btn { background: var(--tab-bg); border: 1px solid var(--tab-border); color: var(--text-main); }
        .text-accent { color: var(--accent); }
        .text-accent2 { color: var(--accent2); }
        .bg-accent-soft { background: color-mix(in srgb, var(--accent) 14%, transparent); }
        .bg-accent2-soft { background: color-mix(in srgb, var(--accent2) 14%, transparent); }`;
const NEXA_USER_SHELL_CSS = `
        .user-shell-page { background: linear-gradient(160deg, var(--page-bg) 0%, var(--page-bg2) 55%, color-mix(in srgb, var(--accent) 8%, var(--page-bg2)) 100%); color: var(--text-main); min-height: 100vh; }
        .st-shell { max-width: 72rem; margin: 0 auto; padding: 1rem 1rem 2.5rem; }
        .st-topbar { display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-bottom: 1.25rem; padding-bottom: 1rem; border-bottom: 1px solid var(--stat-border); flex-wrap: wrap; }
        .st-brand { display: flex; align-items: center; gap: 0.75rem; min-width: 0; }
        .st-brand-logo { width: 2.75rem; height: 2.75rem; border-radius: 0.9rem; overflow: hidden; flex-shrink: 0; box-shadow: 0 8px 24px color-mix(in srgb, var(--accent) 25%, transparent); }
        .st-brand-title { font-size: 1.05rem; font-weight: 900; line-height: 1.2; color: var(--text-main); }
        .st-brand-sub { font-size: 0.7rem; color: var(--text-muted); }
        .st-topbar-actions { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
        .st-layout { display: grid; grid-template-columns: 1fr; gap: 1rem; }
        @media (min-width: 1024px) { .st-layout { grid-template-columns: minmax(0, 0.95fr) minmax(0, 1.55fr); gap: 1.25rem; align-items: start; } }
        .st-panel { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 1.35rem; backdrop-filter: blur(12px); box-shadow: 0 10px 40px color-mix(in srgb, var(--text-main) 6%, transparent); }
        .st-profile { padding: 1.25rem; display: flex; flex-direction: column; gap: 1rem; }
        .st-guide-support { margin-top: auto; }
        @media (min-width: 640px) { .st-profile { padding: 1.5rem; } }
        .st-profile-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 0.75rem; flex-wrap: wrap; }
        .st-user-block { min-width: 0; }
        .st-user-label { font-size: 0.68rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.35rem; }
        .st-user-name { font-size: clamp(1.2rem, 3.5vw, 1.75rem); font-weight: 900; font-family: ui-monospace, monospace; color: var(--text-main); word-break: break-all; line-height: 1.15; }
        .st-page-title { font-size: clamp(1.25rem, 3.5vw, 1.65rem); font-weight: 900; color: var(--text-main); line-height: 1.2; }
        .st-page-desc { font-size: 0.78rem; line-height: 1.7; color: var(--text-muted); margin-top: 0.5rem; }
        .st-badge { display: inline-flex; align-items: center; gap: 0.55rem; padding: 0.55rem 0.95rem; border-radius: 9999px; border: 2px solid; font-size: 0.78rem; font-weight: 800; max-width: 100%; }
        .st-badge-text { line-height: 1.35; }
        .st-side-note { padding: 1rem 0 0; border-top: 1px solid var(--stat-border); font-size: 0.75rem; line-height: 1.7; color: var(--text-muted); }
        .st-metrics { display: grid; grid-template-columns: 1fr; gap: 0.85rem; }
        @media (min-width: 640px) { .st-metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
        .st-metric { background: var(--stat-bg); border: 1px solid var(--stat-border); border-radius: 1.15rem; padding: 1rem 1.1rem; position: relative; overflow: hidden; min-height: 10rem; display: flex; flex-direction: column; }
        .st-metric::before { content: ''; position: absolute; inset-inline: 0; top: 0; height: 3px; background: linear-gradient(90deg, var(--accent), transparent); }
        .st-metric.time::before, .st-metric.accent2::before { background: linear-gradient(90deg, var(--accent2), transparent); }
        .st-metric-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 0.75rem; margin-bottom: 0.85rem; }
        .st-metric-title { font-size: 0.72rem; font-weight: 800; color: var(--text-muted); display: flex; align-items: center; gap: 0.45rem; }
        .st-metric-icon { width: 1.75rem; height: 1.75rem; border-radius: 0.55rem; display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0; }
        .st-metric-pct, .st-metric-hero { font-size: clamp(1.35rem, 4.5vw, 1.85rem); font-weight: 900; line-height: 1; direction: ltr; text-align: left; }
        .st-metric-pct.vol, .st-metric-hero.accent { color: var(--accent); }
        .st-metric-pct.time, .st-metric-hero.accent2 { color: var(--accent2); }
        .progress-track { background: color-mix(in srgb, var(--text-muted) 16%, transparent); height: 0.55rem; border-radius: 9999px; overflow: hidden; margin-bottom: 0.85rem; }
        .stat-bar-progress { height: 100%; border-radius: 9999px; transition: width 1s ease, background-color 0.3s; min-width: 0; }
        .st-metric-meta { margin-top: auto; display: grid; gap: 0.35rem; font-size: 0.74rem; color: var(--text-muted); }
        .st-metric-meta strong { color: var(--text-main); font-weight: 800; }
        .st-content-wrap { padding: 1.1rem; }
        @media (min-width: 640px) { .st-content-wrap { padding: 1.25rem; } }
        .st-actions-title, .st-section-title { font-size: 0.82rem; font-weight: 800; margin-bottom: 0.85rem; color: var(--text-main); display: flex; align-items: center; gap: 0.5rem; }
        .st-actions { display: grid; grid-template-columns: 1fr; gap: 0.65rem; }
        @media (min-width: 640px) { .st-actions { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
        .st-action { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; padding: 0.9rem 1rem; border-radius: 1rem; background: var(--btn-bg); border: 1px solid var(--btn-border); font-size: 0.76rem; font-weight: 800; transition: transform 0.15s ease, box-shadow 0.15s ease, opacity 0.15s ease; text-align: right; min-height: 3.35rem; }
        .st-action:hover { transform: translateY(-1px); box-shadow: 0 8px 24px color-mix(in srgb, var(--accent) 12%, transparent); opacity: 0.95; }
        .st-action-label { display: flex; align-items: center; gap: 0.55rem; color: var(--text-main); min-width: 0; }
        .st-action-arrow { color: var(--accent); flex-shrink: 0; }
        .st-action.guide, .st-action.primary { grid-column: 1 / -1; background: linear-gradient(135deg, var(--accent), var(--accent2)); border: none; color: #fff; }
        .st-action.guide .st-action-label, .st-action.guide .st-action-arrow, .st-action.primary .st-action-label, .st-action.primary .st-action-arrow { color: #fff; }
        .st-tabs { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem; }
        .st-tab { padding: 0.55rem 0.95rem; border-radius: 0.85rem; font-size: 0.76rem; font-weight: 800; background: var(--tab-bg); border: 1px solid var(--tab-border); color: var(--tab-text); transition: 0.2s ease; display: inline-flex; align-items: center; gap: 0.4rem; }
        .st-tab.active { background: linear-gradient(135deg, var(--accent), var(--accent2)); color: #fff; border-color: transparent; }
        .st-step { background: var(--section-bg); border: 1px solid var(--section-border); border-radius: 1rem; padding: 0.95rem 1.05rem; font-size: 0.8rem; line-height: 1.75; color: var(--text-muted); }
        .st-step-num { min-width: 1.65rem; height: 1.65rem; display: inline-flex; align-items: center; justify-content: center; border-radius: 0.5rem; background: var(--step-bg); color: var(--step-text); font-size: 0.72rem; font-weight: 800; margin-left: 0.45rem; vertical-align: middle; }
        .st-info-row { display: flex; justify-content: space-between; align-items: center; gap: 1rem; padding: 0.6rem 0; border-bottom: 1px solid var(--stat-border); font-size: 0.8rem; }
        .st-info-row:last-child { border-bottom: none; }
        .st-info-label { color: var(--text-muted); font-weight: 700; }
        .st-info-value { color: var(--text-main); font-weight: 800; text-align: left; direction: ltr; }
        .st-log-row { background: var(--stat-bg); border: 1px solid var(--stat-border); border-radius: 1rem; padding: 0.85rem 1rem; }
        .st-table-wrap { overflow-x: auto; border-radius: 1rem; border: 1px solid var(--stat-border); }
        .st-table { width: 100%; font-size: 0.78rem; border-collapse: collapse; }
        .st-table thead th { background: color-mix(in srgb, var(--accent) 10%, var(--stat-bg)); color: var(--text-main); padding: 0.75rem 1rem; text-align: right; font-weight: 800; white-space: nowrap; }
        .st-table tbody td { padding: 0.75rem 1rem; border-top: 1px solid var(--stat-border); }
        .st-table tbody tr:hover { background: color-mix(in srgb, var(--accent) 6%, transparent); }
        .telegram-link { background: var(--btn-bg); border: 1px solid var(--btn-border); color: var(--text-muted); display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.65rem 1.1rem; border-radius: 9999px; font-size: 0.78rem; font-weight: 800; transition: 0.2s ease; }
        .telegram-link:hover { color: var(--accent); box-shadow: 0 8px 24px color-mix(in srgb, var(--accent) 10%, transparent); }
        .st-empty-icon { width: 4rem; height: 4rem; border-radius: 9999px; display: flex; align-items: center; justify-content: center; margin: 0 auto 1rem; background: color-mix(in srgb, #ef4444 12%, transparent); border: 2px solid color-mix(in srgb, #ef4444 35%, transparent); }
        .st-refresh-btn { font-size: 0.72rem; font-weight: 800; padding: 0.4rem 0.75rem; border-radius: 0.65rem; border: 1px solid var(--stat-border); color: var(--accent); background: var(--btn-bg); transition: 0.15s ease; }
        .st-refresh-btn:hover { opacity: 0.9; }
        .st-metric.full { grid-column: 1 / -1; }
        .st-ip-form { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem; }
        .st-ip-input { flex: 1 1 12rem; min-width: 0; padding: 0.65rem 0.85rem; border-radius: 0.75rem; border: 1px solid var(--stat-border); background: var(--btn-bg); color: var(--text-main); font-family: ui-monospace, monospace; font-size: 0.82rem; direction: ltr; text-align: left; }
        .st-ip-input:focus { outline: none; box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 35%, transparent); }`;
const NEXA_SERVICE_PAGE_VARS = `
        :root {
            --admin-bg: #f4f8f6; --admin-bg2: #e8f2ed; --admin-card: #ffffff; --admin-border: #dfe8e4;
            --admin-text: #111827; --admin-muted: #64748b; --admin-primary: #059669; --admin-primary-soft: #ecfdf5;
            --admin-accent: #0d9488; --admin-shadow: 0 4px 28px -8px rgba(5,150,105,0.1), 0 2px 8px -2px rgba(15,23,42,0.06);
            --admin-shadow-lg: 0 12px 40px -12px rgba(5,150,105,0.18); --admin-progress-track: #e2e8f4;
            --admin-input-bg: #f8fafc; --admin-glow: rgba(5,150,105,0.35);
        }
        html.dark {
            --admin-bg: #090b12; --admin-bg2: #0f1219; --admin-card: #141824; --admin-border: #252d42;
            --admin-text: #e8ecf5; --admin-muted: #8b95a8; --admin-primary: #34d399; --admin-primary-soft: rgba(16,185,129,0.14);
            --admin-accent: #2dd4bf; --admin-shadow: 0 4px 28px -8px rgba(0,0,0,0.55);
            --admin-shadow-lg: 0 12px 40px -12px rgba(0,0,0,0.65); --admin-progress-track: #252d42;
            --admin-input-bg: #1a2030; --admin-glow: rgba(52,211,153,0.25);
        }`;
const NEXA_ANNOUNCE_BANNER_CSS = `
        .adm-announce-banner,
        .svc-announce-banner {
            position: relative;
            overflow: hidden;
            border-radius: 1rem;
            font-size: clamp(0.78rem, 2.4vw, 0.875rem);
            line-height: 1.65;
            border: 1px solid color-mix(in srgb, var(--admin-primary) 30%, var(--admin-border));
            background:
                linear-gradient(135deg,
                    color-mix(in srgb, var(--admin-primary) 9%, var(--admin-card)) 0%,
                    color-mix(in srgb, var(--admin-accent) 5%, var(--admin-card)) 55%,
                    var(--admin-card) 100%);
            color: var(--admin-text);
            box-shadow:
                0 6px 28px -10px var(--admin-glow),
                inset 0 1px 0 color-mix(in srgb, #fff 10%, transparent);
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }
        html.dark .adm-announce-banner,
        html.dark .svc-announce-banner {
            background:
                linear-gradient(135deg,
                    color-mix(in srgb, var(--admin-primary) 16%, var(--admin-card)) 0%,
                    color-mix(in srgb, var(--admin-accent) 9%, var(--admin-bg2)) 60%,
                    color-mix(in srgb, var(--admin-primary) 4%, var(--admin-card)) 100%);
            box-shadow:
                0 8px 32px -12px var(--admin-glow),
                inset 0 1px 0 color-mix(in srgb, var(--admin-primary) 12%, transparent);
        }
        .adm-announce-banner::before,
        .svc-announce-banner::before {
            content: '';
            position: absolute;
            inset-inline-start: 0;
            top: 0.6rem;
            bottom: 0.6rem;
            width: 3px;
            border-radius: 0 3px 3px 0;
            background: linear-gradient(180deg, var(--admin-primary), var(--admin-accent));
            box-shadow: 0 0 14px var(--admin-glow);
        }
        .adm-announce-banner::after,
        .svc-announce-banner::after {
            content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(105deg, transparent 38%, color-mix(in srgb, var(--admin-primary) 8%, transparent) 50%, transparent 62%);
            animation: nexa-announce-shimmer 5.5s ease-in-out infinite;
            pointer-events: none;
        }
        @keyframes nexa-announce-shimmer {
            0% { transform: translateX(-130%) skewX(-10deg); opacity: 0; }
            12% { opacity: 1; }
            88% { opacity: 1; }
            100% { transform: translateX(230%) skewX(-10deg); opacity: 0; }
        }
        .adm-announce-banner {
            margin: 0.75rem 0.85rem 0;
            padding: 0.85rem 1rem 0.85rem 1.15rem;
        }
        @media (min-width: 768px) {
            .adm-announce-banner {
                margin: 0.85rem 1.5rem 0;
                padding: 0.95rem 1.15rem 0.95rem 1.3rem;
            }
        }
        .svc-announce-banner {
            margin-bottom: clamp(0.75rem, 2.5vw, 1rem);
            padding: 0.85rem 1rem 0.85rem 1.15rem;
        }
        @media (min-width: 640px) {
            .svc-announce-banner { padding: 0.95rem 1.15rem 0.95rem 1.3rem; }
        }
        .adm-announce-inner,
        .svc-announce-inner {
            display: flex;
            align-items: flex-start;
            gap: clamp(0.65rem, 2vw, 0.9rem);
            position: relative;
            z-index: 1;
            max-width: 100%;
        }
        @media (min-width: 480px) {
            .adm-announce-inner,
            .svc-announce-inner { align-items: center; }
        }
        .adm-announce-icon,
        .svc-announce-icon {
            flex-shrink: 0;
            width: clamp(2rem, 6vw, 2.5rem);
            height: clamp(2rem, 6vw, 2.5rem);
            border-radius: 0.75rem;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: var(--admin-primary-soft);
            color: var(--admin-primary);
            border: 1px solid color-mix(in srgb, var(--admin-primary) 28%, var(--admin-border));
            box-shadow: 0 4px 14px -4px var(--admin-glow);
            animation: nexa-announce-icon-pulse 3.5s ease-in-out infinite;
        }
        html.dark .adm-announce-icon,
        html.dark .svc-announce-icon {
            background: color-mix(in srgb, var(--admin-primary) 18%, var(--admin-card));
        }
        @keyframes nexa-announce-icon-pulse {
            0%, 100% { box-shadow: 0 4px 14px -4px var(--admin-glow); transform: scale(1); }
            50% { box-shadow: 0 6px 22px -2px var(--admin-glow); transform: scale(1.03); }
        }
        .adm-announce-body,
        .svc-announce-body {
            flex: 1;
            min-width: 0;
            word-break: break-word;
            color: var(--admin-text);
            font-weight: 500;
        }
        .adm-announce-body a,
        .svc-announce-body a,
        .announce-link {
            color: var(--admin-primary);
            text-decoration: none;
            font-weight: 700;
            word-break: break-all;
            border-bottom: 1px dashed color-mix(in srgb, var(--admin-primary) 45%, transparent);
            transition: color 0.15s ease, border-color 0.15s ease;
        }
        .adm-announce-body a:hover,
        .svc-announce-body a:hover,
        .announce-link:hover {
            color: var(--admin-accent);
            border-bottom-color: var(--admin-accent);
        }
        .adm-announce-banner.hidden,
        .svc-announce-banner.hidden { display: none; }`;
const NEXA_SERVICE_PAGE_CSS = `
        html { background: var(--admin-bg); }
        body.svc-page {
            font-family: 'Vazirmatn', sans-serif; min-height: 100vh; color: var(--admin-text);
            background:
                radial-gradient(ellipse 80% 60% at 100% 0%, color-mix(in srgb, var(--admin-primary) 8%, transparent), transparent 55%),
                radial-gradient(ellipse 60% 50% at 0% 100%, color-mix(in srgb, var(--admin-accent) 6%, transparent), transparent 50%),
                linear-gradient(155deg, var(--admin-bg) 0%, var(--admin-bg2) 100%);
            transition: background 0.3s, color 0.3s;
        }
        .svc-wrap { max-width: 72rem; margin: 0 auto; padding: 1rem 1rem 2.5rem; }
        .svc-header {
            display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap;
            margin-bottom: 1.5rem; padding: 0.85rem 1.15rem; border-radius: 1.15rem;
            background: color-mix(in srgb, var(--admin-card) 88%, transparent); border: 1px solid var(--admin-border);
            box-shadow: var(--admin-shadow); backdrop-filter: blur(12px);
        }
        .svc-brand { display: flex; align-items: center; gap: 0.75rem; min-width: 0; }
        .svc-brand-logo { width: 2.75rem; height: 2.75rem; border-radius: 0.85rem; overflow: hidden; flex-shrink: 0; box-shadow: 0 6px 20px var(--admin-glow); }
        .svc-brand-title { font-size: 1.05rem; font-weight: 900; line-height: 1.2; color: var(--admin-text); }
        .svc-brand-sub { font-size: 0.7rem; color: var(--admin-muted); margin-top: 0.1rem; }
        .svc-header-actions { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
        .svc-theme-btn {
            padding: 0.55rem; border-radius: 0.75rem; background: var(--admin-card); border: 1px solid var(--admin-border);
            color: var(--admin-muted); cursor: pointer; transition: 0.15s ease; display: inline-flex; align-items: center; justify-content: center;
        }
        .svc-theme-btn:hover { background: var(--admin-primary-soft); border-color: color-mix(in srgb, var(--admin-primary) 40%, var(--admin-border)); color: var(--admin-primary); }
        .svc-back-btn {
            padding: 0.55rem 1rem; border-radius: 0.75rem; font-size: 0.75rem; font-weight: 800;
            background: var(--admin-card); border: 1px solid var(--admin-border); color: var(--admin-text);
            transition: 0.15s ease; display: inline-flex; align-items: center; gap: 0.4rem;
        }
        .svc-back-btn:hover { background: var(--admin-primary-soft); border-color: color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border)); color: var(--admin-primary); }
        .svc-grid { display: grid; grid-template-columns: 1fr; gap: 1rem; }
        @media (min-width: 1024px) { .svc-grid { grid-template-columns: minmax(0, 0.9fr) minmax(0, 1.6fr); gap: 1.25rem; align-items: start; } }
        .svc-card {
            background: var(--admin-card); border: 1px solid var(--admin-border); border-radius: 1.15rem;
            box-shadow: var(--admin-shadow); color: var(--admin-text); transition: border-color 0.2s, box-shadow 0.2s;
        }
        .svc-card:hover { border-color: color-mix(in srgb, var(--admin-primary) 28%, var(--admin-border)); }
        .svc-sidebar { padding: 1.35rem; display: flex; flex-direction: column; gap: 1rem; }
        .svc-label { font-size: 0.68rem; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; color: var(--admin-muted); margin-bottom: 0.35rem; }
        .svc-username { font-size: clamp(1.15rem, 3.5vw, 1.65rem); font-weight: 900; font-family: ui-monospace, monospace; color: var(--admin-text); word-break: break-all; line-height: 1.15; }
        .svc-desc { font-size: 0.78rem; line-height: 1.75; color: var(--admin-muted); }
        .svc-status {
            display: inline-flex; align-items: center; gap: 0.55rem; padding: 0.55rem 0.95rem;
            border-radius: 9999px; border: 2px solid; font-size: 0.76rem; font-weight: 800; max-width: 100%;
        }
        .svc-status.active { background: color-mix(in srgb, var(--admin-primary) 12%, var(--admin-card)); border-color: color-mix(in srgb, var(--admin-primary) 45%, var(--admin-border)); color: var(--admin-primary); }
        .svc-status.inactive { background: color-mix(in srgb, #ef4444 10%, var(--admin-card)); border-color: color-mix(in srgb, #ef4444 40%, var(--admin-border)); color: #ef4444; }
        html.dark .svc-status.inactive { color: #f87171; }
        .svc-status-icon { width: 1.65rem; height: 1.65rem; border-radius: 9999px; display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0; }
        .svc-status.active .svc-status-icon { background: color-mix(in srgb, var(--admin-primary) 20%, transparent); }
        .svc-status.inactive .svc-status-icon { background: color-mix(in srgb, #ef4444 18%, transparent); }
        .svc-tg-link {
            display: inline-flex; align-items: center; justify-content: center; gap: 0.5rem; width: 100%;
            padding: 0.7rem 1.1rem; border-radius: 0.85rem; font-size: 0.78rem; font-weight: 800;
            background: color-mix(in srgb, var(--admin-primary) 8%, var(--admin-card)); border: 1px solid color-mix(in srgb, var(--admin-primary) 30%, var(--admin-border));
            color: var(--admin-primary); transition: 0.15s ease; margin-top: auto;
        }
        .svc-tg-link:hover { background: color-mix(in srgb, var(--admin-primary) 14%, var(--admin-card)); box-shadow: 0 6px 20px -6px var(--admin-glow); }
        .svc-metrics { display: grid; grid-template-columns: 1fr; gap: 0.85rem; }
        @media (min-width: 640px) { .svc-metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
        .svc-stat {
            background: var(--admin-card); border: 1px solid var(--admin-border); border-radius: 1.15rem;
            box-shadow: var(--admin-shadow); padding: 1.15rem 1.2rem; position: relative; overflow: hidden;
            min-height: 9.5rem; display: flex; flex-direction: column; transition: border-color 0.25s, transform 0.25s, box-shadow 0.25s;
        }
        .svc-stat:hover { border-color: color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border)); transform: translateY(-2px); box-shadow: var(--admin-shadow-lg); }
        .svc-stat::before {
            content: ''; position: absolute; top: 0; inset-inline: 0; height: 3px;
            background: linear-gradient(90deg, var(--admin-primary), var(--admin-accent), transparent);
        }
        .svc-stat.accent::before { background: linear-gradient(90deg, var(--admin-accent), var(--admin-primary), transparent); }
        .svc-stat-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 0.75rem; margin-bottom: 0.85rem; }
        .svc-stat-title { font-size: 0.72rem; font-weight: 800; color: var(--admin-muted); display: flex; align-items: center; gap: 0.45rem; }
        .svc-stat-icon { width: 1.75rem; height: 1.75rem; border-radius: 0.55rem; display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0; background: var(--admin-primary-soft); color: var(--admin-primary); }
        .svc-stat.accent .svc-stat-icon { background: color-mix(in srgb, var(--admin-accent) 14%, transparent); color: var(--admin-accent); }
        .svc-stat-pct { font-size: clamp(1.3rem, 4vw, 1.75rem); font-weight: 900; line-height: 1; direction: ltr; text-align: left; color: var(--admin-primary); }
        .svc-stat.accent .svc-stat-pct { color: var(--admin-accent); }
        .svc-progress { background: var(--admin-progress-track); height: 0.5rem; border-radius: 9999px; overflow: hidden; margin-bottom: 0.85rem; }
        .svc-progress-bar { height: 100%; border-radius: 9999px; transition: width 1s ease, background-color 0.3s; min-width: 0; background: var(--admin-primary); }
        .svc-stat.accent .svc-progress-bar { background: var(--admin-accent); }
        .svc-stat-meta { margin-top: auto; display: grid; gap: 0.3rem; font-size: 0.74rem; color: var(--admin-muted); }
        .svc-stat-meta strong { color: var(--admin-text); font-weight: 800; }
        .svc-panel { padding: 1.2rem; }
        @media (min-width: 640px) { .svc-panel { padding: 1.35rem; } }
        .svc-section-title { font-size: 0.82rem; font-weight: 800; margin-bottom: 1rem; color: var(--admin-text); display: flex; align-items: center; gap: 0.5rem; }
        .svc-actions { display: grid; grid-template-columns: 1fr; gap: 0.65rem; }
        @media (min-width: 640px) { .svc-actions { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
        .svc-action {
            display: flex; align-items: center; justify-content: space-between; gap: 0.75rem;
            padding: 0.9rem 1rem; border-radius: 0.85rem; background: color-mix(in srgb, var(--admin-bg) 40%, var(--admin-card));
            border: 1px solid var(--admin-border); font-size: 0.76rem; font-weight: 800;
            transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease; text-align: right; min-height: 3.25rem; cursor: pointer; color: var(--admin-text);
        }
        .svc-action:hover { transform: translateY(-1px); border-color: color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border)); box-shadow: 0 6px 20px -6px var(--admin-glow); }
        .svc-action-label { display: flex; align-items: center; gap: 0.55rem; min-width: 0; }
        .svc-action-icon { color: var(--admin-primary); flex-shrink: 0; }
        .svc-action-arrow { color: var(--admin-primary); flex-shrink: 0; opacity: 0.7; }
        .svc-action.vless { background: rgba(249,115,22,0.1); border-color: rgba(249,115,22,0.28); color: #ea580c; }
        .svc-action.vless .svc-action-icon, .svc-action.vless .svc-action-arrow { color: #ea580c; }
        .svc-action.sub { background: var(--admin-primary-soft); border-color: color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border)); color: var(--admin-primary); }
        .svc-action.sub .svc-action-icon, .svc-action.sub .svc-action-arrow { color: var(--admin-primary); }
        .svc-action.qr { background: rgba(6,182,212,0.1); border-color: rgba(6,182,212,0.28); color: #0891b2; }
        .svc-action.qr .svc-action-icon, .svc-action.qr .svc-action-arrow { color: #0891b2; }
        .svc-action.guide { background: linear-gradient(135deg, var(--admin-primary), var(--admin-accent)); border: none; color: #fff; box-shadow: 0 4px 18px -4px var(--admin-glow); text-decoration: none; }
        .svc-action.guide .svc-action-icon, .svc-action.guide .svc-action-arrow, .svc-action.guide .svc-action-label { color: #fff; }
        .svc-action.guide:hover { filter: brightness(1.06); box-shadow: 0 8px 24px -6px var(--admin-glow); }
        .svc-badge-count {
            display: inline-flex; align-items: center; padding: 0.45rem 0.85rem; border-radius: 9999px;
            font-size: 0.74rem; font-weight: 800; background: var(--admin-primary-soft); color: var(--admin-primary);
            border: 1px solid color-mix(in srgb, var(--admin-primary) 30%, var(--admin-border));
        }
        .svc-btn-sm {
            font-size: 0.72rem; font-weight: 800; padding: 0.45rem 0.8rem; border-radius: 0.65rem;
            border: 1px solid var(--admin-border); color: var(--admin-primary); background: var(--admin-card); transition: 0.15s ease; cursor: pointer;
        }
        .svc-btn-sm:hover { background: var(--admin-primary-soft); border-color: color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border)); }
        .svc-btn-sm.danger { color: #ef4444; border-color: color-mix(in srgb, #ef4444 35%, var(--admin-border)); }
        .svc-btn-sm.danger:hover { background: color-mix(in srgb, #ef4444 10%, var(--admin-card)); }
        .svc-log-list { display: flex; flex-direction: column; gap: 0.65rem; max-height: 65vh; overflow-y: auto; padding-inline-end: 0.15rem; }
        .svc-log-item {
            background: color-mix(in srgb, var(--admin-bg) 35%, var(--admin-card)); border: 1px solid var(--admin-border);
            border-radius: 0.85rem; padding: 0.9rem 1rem; border-inline-start: 3px solid var(--admin-primary);
            transition: border-color 0.15s ease, box-shadow 0.15s ease;
        }
        .svc-log-item:hover { border-color: color-mix(in srgb, var(--admin-primary) 30%, var(--admin-border)); box-shadow: 0 4px 16px -6px var(--admin-glow); }
        .svc-log-item.type-ping { border-inline-start-color: #f59e0b; }
        .svc-log-item.type-config { border-inline-start-color: var(--admin-accent); }
        .svc-log-item.type-ip { border-inline-start-color: #38bdf8; }
        .svc-log-item.type-connect { border-inline-start-color: var(--admin-primary); }
        .svc-log-badge { display: inline-block; font-size: 0.68rem; font-weight: 800; padding: 0.2rem 0.55rem; border-radius: 9999px; }
        .svc-log-badge.connect { background: var(--admin-primary-soft); color: var(--admin-primary); }
        .svc-log-badge.ping { background: color-mix(in srgb, #f59e0b 14%, transparent); color: #d97706; }
        html.dark .svc-log-badge.ping { color: #fbbf24; }
        .svc-log-badge.config { background: color-mix(in srgb, var(--admin-accent) 14%, transparent); color: var(--admin-accent); }
        .svc-log-badge.ip { background: color-mix(in srgb, #38bdf8 14%, transparent); color: #0284c7; }
        html.dark .svc-log-badge.ip { color: #38bdf8; }
        .svc-log-badge.default { background: var(--admin-primary-soft); color: var(--admin-primary); }
        .svc-log-ip { font-size: 0.85rem; font-weight: 800; font-family: ui-monospace, monospace; color: var(--admin-primary); direction: ltr; }
        .svc-log-time { font-size: 0.78rem; font-weight: 700; font-family: ui-monospace, monospace; color: var(--admin-muted); direction: ltr; flex-shrink: 0; }
        .svc-log-details { font-size: 0.72rem; color: var(--admin-muted); margin-top: 0.25rem; }
        .svc-empty { text-align: center; padding: 3rem 1rem; color: var(--admin-muted); font-size: 0.85rem; }
        .svc-qr-modal { background: var(--admin-card); border: 1px solid var(--admin-border); color: var(--admin-text); }
        .svc-qr-close {
            width: 100%; padding: 0.65rem; font-weight: 700; border-radius: 0.75rem; font-size: 0.82rem;
            background: color-mix(in srgb, var(--admin-primary) 10%, var(--admin-card)); border: 1px solid color-mix(in srgb, var(--admin-primary) 30%, var(--admin-border));
            color: var(--admin-primary); transition: 0.15s ease; cursor: pointer;
        }
        .svc-qr-close:hover { background: color-mix(in srgb, var(--admin-primary) 16%, var(--admin-card)); }
        .svc-tabs { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem; }
        .svc-tab {
            padding: 0.55rem 0.95rem; border-radius: 0.85rem; font-size: 0.76rem; font-weight: 800;
            background: color-mix(in srgb, var(--admin-bg) 40%, var(--admin-card)); border: 1px solid var(--admin-border);
            color: var(--admin-muted); transition: 0.2s ease; display: inline-flex; align-items: center; gap: 0.4rem; cursor: pointer;
        }
        .svc-tab:hover { border-color: color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border)); color: var(--admin-text); }
        .svc-tab.active { background: linear-gradient(135deg, var(--admin-primary), var(--admin-accent)); color: #fff; border-color: transparent; box-shadow: 0 4px 14px -4px var(--admin-glow); }
        .svc-step {
            background: color-mix(in srgb, var(--admin-bg) 35%, var(--admin-card)); border: 1px solid var(--admin-border);
            border-radius: 0.85rem; padding: 0.95rem 1.05rem; font-size: 0.8rem; line-height: 1.75; color: var(--admin-muted);
        }
        .svc-step strong { color: var(--admin-text); }
        .svc-step-num {
            min-width: 1.65rem; height: 1.65rem; display: inline-flex; align-items: center; justify-content: center;
            border-radius: 0.5rem; background: var(--admin-primary-soft); color: var(--admin-primary);
            font-size: 0.72rem; font-weight: 800; margin-left: 0.45rem; vertical-align: middle;
        }
        .svc-guide-link { color: var(--admin-primary); word-break: break-all; font-weight: 700; }
        .svc-guide-link:hover { color: var(--admin-accent); }
        .svc-support-link { color: var(--admin-primary); font-weight: 700; }
        .svc-support-link:hover { color: var(--admin-accent); }
        .svc-subsection-title { font-size: 0.82rem; font-weight: 800; margin-bottom: 0.75rem; color: var(--admin-text); display: flex; align-items: center; gap: 0.45rem; }
        .svc-divider { text-align: center; font-size: 0.82rem; margin: 1.5rem 0; color: var(--admin-border); }
        .svc-footnote { text-align: center; font-size: 0.78rem; padding-top: 0.5rem; color: var(--admin-muted); display: flex; align-items: center; justify-content: center; gap: 0.4rem; flex-wrap: wrap; }` + NEXA_ANNOUNCE_BANNER_CSS;
const NEXA_SERVICE_THEME_TOGGLE = `<button type="button" onclick="toggleNexaTheme()" class="svc-theme-btn" title="تغییر تم">
        <svg class="w-5 h-5 hidden dark:block text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m12.728 0l-.707-.707M6.343 6.343l-.707-.707M14 12a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
        <svg class="w-5 h-5 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="color: var(--admin-muted)"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
    </button>`;
const NEXA_TOAST_CSS = `
        #nexa-toast-container {
            position: fixed;
            bottom: 1.25rem;
            left: 50%;
            transform: translateX(-50%);
            z-index: 99999;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 0.5rem;
            pointer-events: none;
            width: min(420px, calc(100vw - 2rem));
        }
        .nexa-toast {
            width: 100%;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.875rem 1.125rem;
            border-radius: 1rem;
            background: var(--toast-bg, var(--card-bg, var(--admin-card, rgba(255,255,255,0.97))));
            border: 1px solid var(--toast-border, var(--card-border, var(--admin-border, #b8dcc8)));
            color: var(--toast-text, var(--text-main, var(--admin-text, #2c3833)));
            box-shadow: 0 12px 40px rgba(15, 23, 42, 0.15), 0 2px 8px rgba(15, 23, 42, 0.06);
            backdrop-filter: blur(12px);
            font-size: 0.875rem;
            font-weight: 600;
            direction: rtl;
            opacity: 0;
            transform: translateY(1.25rem);
            animation: nexaToastIn 0.35s cubic-bezier(0.21, 1.02, 0.73, 1) forwards;
        }
        .nexa-toast.success {
            border-color: color-mix(in srgb, var(--toast-accent, var(--accent, var(--admin-primary, #6b9e8f))) 45%, var(--toast-border, var(--card-border, #b8dcc8)));
        }
        .nexa-toast.error {
            border-color: #f87171;
        }
        .nexa-toast-icon {
            flex-shrink: 0;
            width: 1.75rem;
            height: 1.75rem;
            border-radius: 9999px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: color-mix(in srgb, var(--toast-accent, var(--accent, var(--admin-primary, #6b9e8f))) 18%, transparent);
            color: var(--toast-accent, var(--accent, var(--admin-primary, #6b9e8f)));
            font-size: 0.85rem;
            font-weight: 800;
        }
        .nexa-toast.error .nexa-toast-icon {
            background: rgba(248, 113, 113, 0.15);
            color: #f87171;
        }
        .nexa-toast-msg { flex: 1; line-height: 1.5; }
        @keyframes nexaToastIn {
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes nexaToastOut {
            to { opacity: 0; transform: translateY(0.75rem); }
        }
        .nexa-toast.hide {
            animation: nexaToastOut 0.4s ease forwards;
        }`;
const NEXA_TOAST_HTML = `<div id="nexa-toast-container" aria-live="polite"></div>`;
const NEXA_TOAST_SCRIPT = `<script>
        window.showNexaToast = function(message, type) {
            type = type || 'success';
            var container = document.getElementById('nexa-toast-container');
            if (!container) return;
            var toast = document.createElement('div');
            toast.className = 'nexa-toast ' + type;
            var iconEl = document.createElement('span');
            iconEl.className = 'nexa-toast-icon';
            iconEl.textContent = type === 'error' ? '✕' : '✓';
            var msgEl = document.createElement('span');
            msgEl.className = 'nexa-toast-msg';
            msgEl.textContent = message;
            toast.appendChild(iconEl);
            toast.appendChild(msgEl);
            container.appendChild(toast);
            setTimeout(function() {
                toast.classList.add('hide');
                setTimeout(function() { if (toast.parentNode) toast.remove(); }, 400);
            }, 5000);
        };
    </script>`;
const NEXA_CONFIRM_CSS = `
        #nexa-confirm-overlay {
            position: fixed;
            inset: 0;
            z-index: 100000;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
            background: rgba(15, 23, 42, 0.5);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.25s ease;
        }
        #nexa-confirm-overlay.active {
            opacity: 1;
            pointer-events: auto;
        }
        .nexa-confirm-card {
            width: min(400px, 100%);
            padding: 1.5rem;
            border-radius: 1.25rem;
            background: color-mix(in srgb, var(--confirm-bg, var(--card-bg, var(--admin-card, #ffffff))) 88%, transparent);
            border: 1px solid color-mix(in srgb, var(--confirm-border, var(--card-border, var(--admin-border, #dde4ec))) 70%, rgba(255,255,255,0.4));
            box-shadow: 0 24px 60px rgba(15, 23, 42, 0.28), inset 0 1px 0 rgba(255,255,255,0.25);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            transform: scale(0.92) translateY(12px);
            transition: transform 0.28s cubic-bezier(0.21, 1.02, 0.73, 1);
            direction: rtl;
            text-align: center;
        }
        #nexa-confirm-overlay.active .nexa-confirm-card {
            transform: scale(1) translateY(0);
        }
        .nexa-confirm-icon {
            width: 3rem;
            height: 3rem;
            margin: 0 auto 1rem;
            border-radius: 9999px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: color-mix(in srgb, var(--toast-accent, var(--accent, var(--admin-primary, #0f766e))) 14%, transparent);
            color: var(--toast-accent, var(--accent, var(--admin-primary, #0f766e)));
        }
        .nexa-confirm-icon.danger {
            background: rgba(239, 68, 68, 0.12);
            color: #ef4444;
        }
        .nexa-confirm-title {
            font-size: 1rem;
            font-weight: 800;
            color: var(--confirm-text, var(--text-main, var(--admin-text, #1e293b)));
            margin-bottom: 0.5rem;
        }
        .nexa-confirm-message {
            font-size: 0.875rem;
            color: var(--confirm-muted, var(--text-muted, var(--admin-muted, #64748b)));
            line-height: 1.65;
            margin-bottom: 1.25rem;
        }
        .nexa-confirm-actions {
            display: flex;
            gap: 0.75rem;
        }
        .nexa-confirm-btn {
            flex: 1;
            padding: 0.75rem 1rem;
            border-radius: 0.875rem;
            font-size: 0.875rem;
            font-weight: 700;
            border: 1px solid transparent;
            cursor: pointer;
            transition: all 0.2s;
        }
        .nexa-confirm-cancel {
            background: color-mix(in srgb, var(--confirm-muted, var(--admin-muted, #64748b)) 10%, transparent);
            border-color: var(--confirm-border, var(--admin-border, #dde4ec));
            color: var(--confirm-text, var(--admin-text, #1e293b));
        }
        .nexa-confirm-cancel:hover { opacity: 0.85; }
        .nexa-confirm-ok {
            background: linear-gradient(135deg, var(--toast-accent, var(--accent, var(--admin-primary, #0f766e))), color-mix(in srgb, var(--admin-primary, #0f766e) 65%, #0369a1));
            color: #fff;
            box-shadow: 0 4px 14px -3px color-mix(in srgb, var(--admin-primary, #0f766e) 45%, transparent);
        }
        .nexa-confirm-ok:hover { filter: brightness(1.06); }
        .nexa-confirm-ok.danger {
            background: linear-gradient(135deg, #ef4444, #dc2626);
            box-shadow: 0 4px 14px -3px rgba(239, 68, 68, 0.4);
        }`;
const NEXA_CONFIRM_HTML = `<div id="nexa-confirm-overlay" aria-hidden="true">
        <div class="nexa-confirm-card" role="dialog" aria-modal="true" aria-labelledby="nexa-confirm-title">
            <div id="nexa-confirm-icon" class="nexa-confirm-icon">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
            </div>
            <div id="nexa-confirm-title" class="nexa-confirm-title">تأیید عملیات</div>
            <div id="nexa-confirm-message" class="nexa-confirm-message"></div>
            <div class="nexa-confirm-actions">
                <button type="button" id="nexa-confirm-cancel" class="nexa-confirm-btn nexa-confirm-cancel">انصراف</button>
                <button type="button" id="nexa-confirm-ok" class="nexa-confirm-btn nexa-confirm-ok">تأیید</button>
            </div>
        </div>
    </div>`;
const NEXA_CONFIRM_SCRIPT = `<script>
        window.showNexaConfirm = function(message, options) {
            options = options || {};
            return new Promise(function(resolve) {
                var overlay = document.getElementById('nexa-confirm-overlay');
                if (!overlay) { resolve(window.confirm(message)); return; }
                var titleEl = document.getElementById('nexa-confirm-title');
                var msgEl = document.getElementById('nexa-confirm-message');
                var iconEl = document.getElementById('nexa-confirm-icon');
                var okBtn = document.getElementById('nexa-confirm-ok');
                var cancelBtn = document.getElementById('nexa-confirm-cancel');
                titleEl.textContent = options.title || 'تأیید عملیات';
                msgEl.textContent = message;
                okBtn.textContent = options.confirmText || 'تأیید';
                cancelBtn.textContent = options.cancelText || 'انصراف';
                okBtn.classList.toggle('danger', !!options.danger);
                iconEl.classList.toggle('danger', !!options.danger);
                function cleanup(result) {
                    overlay.classList.remove('active');
                    overlay.setAttribute('aria-hidden', 'true');
                    okBtn.removeEventListener('click', onOk);
                    cancelBtn.removeEventListener('click', onCancel);
                    overlay.removeEventListener('click', onOverlay);
                    document.removeEventListener('keydown', onKey);
                    resolve(result);
                }
                function onOk() { cleanup(true); }
                function onCancel() { cleanup(false); }
                function onOverlay(e) { if (e.target === overlay) cleanup(false); }
                function onKey(e) {
                    if (e.key === 'Escape') cleanup(false);
                    if (e.key === 'Enter') cleanup(true);
                }
                okBtn.addEventListener('click', onOk);
                cancelBtn.addEventListener('click', onCancel);
                overlay.addEventListener('click', onOverlay);
                document.addEventListener('keydown', onKey);
                overlay.classList.add('active');
                overlay.setAttribute('aria-hidden', 'false');
                cancelBtn.focus();
            });
        };
    </script>`;
const NEXA_QR_SCRIPT = `<script>
        window.NEXA_QR_MAX_LEN = 2200;
        window.nexaQrState = { mode: 'direct', directText: '', title: '', username: '', subLinkUrl: '', getVless: null };
        window.nexaBuildSubscriptionNoise = function() {
            return [
                '# System Update Feed: OK',
                '# Sync Code: ' + Math.random().toString(36).slice(2, 10),
                '# Version: 2.10.1',
                '# Description: Secure Node Configurations',
                ''
            ].join('\\n');
        };
        window.nexaEncodeSubscriptionBase64 = function(plainText) {
            return btoa(unescape(encodeURIComponent(plainText)));
        };
        window.nexaGetPrimaryVlessLink = function(vlessMultiline) {
            const lines = String(vlessMultiline || '').split('\\n').map(function(l) { return l.trim(); }).filter(Boolean);
            const real = lines.find(function(l) {
                return !l.startsWith('#') && l.indexOf('@') > -1 && l.indexOf('@127.0.0.1:17') === -1;
            });
            return real || lines.find(function(l) { return !l.startsWith('#') && l.indexOf('@') > -1; }) || '';
        };
        window.nexaBuildSubscriptionQrText = function(vlessText, subLinkUrl) {
            return subLinkUrl || '';
        };
        window.renderQrCode = function(box, text, size) {
            if (!box || !text || typeof QRCode === 'undefined') return;
            box.innerHTML = '';
            new QRCode(box, {
                text: text,
                width: size || 192,
                height: size || 192,
                colorDark: '#000000',
                colorLight: '#ffffff',
                correctLevel: QRCode.CorrectLevel.L
            });
        };
        window.nexaResolveQrText = function() {
            const st = window.nexaQrState || {};
            if (st.mode === 'direct') return st.directText || '';
            let vlessText = '';
            if (typeof st.getVless === 'function') {
                try { vlessText = st.getVless(st.username) || ''; } catch (e) { vlessText = ''; }
            }
            return nexaBuildSubscriptionQrText(vlessText, st.subLinkUrl || '');
        };
        window.toggleQRModal = function(show, opts, title) {
            const modal = document.getElementById('qr-modal');
            if (!modal) return;
            const card = document.getElementById('qr-modal-card') || modal.querySelector(':scope > div');
            const qrBox = document.getElementById('qrcode-box');
            const titleEl = document.getElementById('qr-modal-title');
            if (show) {
                if (typeof opts === 'string') {
                    window.nexaQrState = { mode: 'direct', directText: opts, title: title || '', username: '', subLinkUrl: '', getVless: null };
                } else {
                    window.nexaQrState = Object.assign({ mode: 'sub', directText: '', title: '', username: '', subLinkUrl: '', getVless: null }, opts || {});
                }
                if (titleEl) titleEl.textContent = window.nexaQrState.title || (typeof adminT === 'function' ? adminT('qr_scan') : 'اسکن کد QR');
                window.renderQrCode(qrBox, window.nexaResolveQrText(), 192);
                modal.classList.remove('opacity-0', 'pointer-events-none');
                modal.classList.add('opacity-100', 'pointer-events-auto');
                if (card) {
                    card.classList.remove('opacity-0', 'scale-95');
                    card.classList.add('opacity-100', 'scale-100');
                }
                document.body.style.overflow = 'hidden';
            } else {
                modal.classList.remove('opacity-100', 'pointer-events-auto');
                modal.classList.add('opacity-0', 'pointer-events-none');
                if (card) {
                    card.classList.remove('opacity-100', 'scale-100');
                    card.classList.add('opacity-0', 'scale-95');
                }
                document.body.style.overflow = '';
            }
        };
    </script>`;
const NEXA_ANNOUNCE_LINKIFY_SCRIPT = `<script>
        window.escapeAnnounceHtml = function(text) {
            return String(text)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;');
        };
        window.linkifyAnnounceText = function(text) {
            const escaped = escapeAnnounceHtml(text);
            const linked = escaped.replace(/(https?:\\/\\/[^\\s<]+[^\\s<.,;:!?)\\]}'"]|www\\.[^\\s<]+[^\\s<.,;:!?)\\]}'"])/gi, function(url) {
                const href = url.indexOf('www.') === 0 ? 'https://' + url : url;
                return '<a href="' + href + '" target="_blank" rel="noopener noreferrer" class="announce-link">' + url + '</a>';
            });
            return linked.replace(/\\n/g, '<br>');
        };
        window.renderAnnounceBanner = function(bannerId, bodyId, text) {
            const banner = document.getElementById(bannerId);
            if (!banner) return;
            const message = String(text || '').trim();
            const bodyEl = bodyId ? document.getElementById(bodyId) : banner;
            if (!message) {
                banner.classList.add('hidden');
                if (bodyEl) bodyEl.innerHTML = '';
                return;
            }
            if (bodyEl) bodyEl.innerHTML = linkifyAnnounceText(message);
            banner.classList.remove('hidden');
        };
    </script>`;
const NEXA_ADMIN_SHELL_CSS = `
        body { font-family: 'Vazirmatn', sans-serif; }
        :root {
            --admin-bg: #f4f8f6;
            --admin-bg2: #e8f2ed;
            --admin-card: #ffffff;
            --admin-border: #dfe8e4;
            --admin-text: #111827;
            --admin-muted: #64748b;
            --admin-primary: #059669;
            --admin-primary-soft: #ecfdf5;
            --admin-accent: #0d9488;
            --admin-header: rgba(255, 255, 255, 0.82);
            --admin-sidebar: #ffffff;
            --admin-sidebar-text: #64748b;
            --admin-sidebar-active: #059669;
            --admin-sidebar-title: #111827;
            --admin-sidebar-sub: #94a3b8;
            --admin-sidebar-border: #e2e8f0;
            --admin-sidebar-label: #94a3b8;
            --admin-sidebar-hover-bg: rgba(5, 150, 105, 0.06);
            --admin-sidebar-hover-text: #111827;
            --admin-sidebar-btn-bg: #f8fafc;
            --admin-sidebar-btn-text: #475569;
            --admin-sidebar-btn-border: #dfe4f0;
            --admin-sidebar-active-text: #059669;
            --admin-shadow: 0 4px 28px -8px rgba(5, 150, 105, 0.1), 0 2px 8px -2px rgba(15, 23, 42, 0.06);
            --admin-shadow-lg: 0 12px 40px -12px rgba(5, 150, 105, 0.18);
            --admin-progress-track: #e2e8f4;
            --admin-input-bg: #f8fafc;
            --admin-glow: rgba(5, 150, 105, 0.35);
        }
        html.dark {
            --admin-bg: #090b12;
            --admin-bg2: #0f1219;
            --admin-card: #141824;
            --admin-border: #252d42;
            --admin-text: #e8ecf5;
            --admin-muted: #8b95a8;
            --admin-primary: #34d399;
            --admin-primary-soft: rgba(16, 185, 129, 0.14);
            --admin-accent: #2dd4bf;
            --admin-header: rgba(20, 24, 36, 0.88);
            --admin-sidebar: #06070d;
            --admin-sidebar-text: #7c8699;
            --admin-sidebar-active: #34d399;
            --admin-sidebar-title: #ffffff;
            --admin-sidebar-sub: rgba(255,255,255,0.55);
            --admin-sidebar-border: rgba(255,255,255,0.08);
            --admin-sidebar-label: rgba(255,255,255,0.35);
            --admin-sidebar-hover-bg: rgba(255,255,255,0.08);
            --admin-sidebar-hover-text: #ffffff;
            --admin-sidebar-btn-bg: rgba(255,255,255,0.06);
            --admin-sidebar-btn-text: rgba(255,255,255,0.92);
            --admin-sidebar-btn-border: rgba(255,255,255,0.15);
            --admin-sidebar-active-text: #ffffff;
            --admin-shadow: 0 4px 28px -8px rgba(0, 0, 0, 0.55);
            --admin-shadow-lg: 0 12px 40px -12px rgba(0, 0, 0, 0.65);
            --admin-progress-track: #252d42;
            --admin-input-bg: #1a2030;
            --admin-glow: rgba(52, 211, 153, 0.25);
        }
        html { background: var(--admin-bg); }
        html, body.adm-app { min-height: 100vh; }
        .adm-app {
            display: flex; flex-direction: row; min-height: 100vh;
            background:
                radial-gradient(ellipse 80% 60% at 100% 0%, color-mix(in srgb, var(--admin-primary) 8%, transparent), transparent 55%),
                radial-gradient(ellipse 60% 50% at 0% 100%, color-mix(in srgb, var(--admin-accent) 6%, transparent), transparent 50%),
                linear-gradient(155deg, var(--admin-bg) 0%, var(--admin-bg2) 100%);
            color: var(--admin-text);
        }
        .adm-main-wrap { flex: 1; min-width: 0; display: flex; flex-direction: column; background: transparent; }
        .adm-sidebar-backdrop {
            display: block; position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 45;
            opacity: 0; visibility: hidden; pointer-events: none; transition: opacity 0.25s, visibility 0.25s;
        }
        .adm-sidebar-backdrop.open { opacity: 1; visibility: visible; pointer-events: auto; }
        @media (min-width: 1024px) { .adm-sidebar-backdrop { display: none !important; } }
        .adm-sidebar {
            width: 17rem; flex-shrink: 0; direction: inherit;
            background: var(--admin-sidebar);
            color: var(--admin-sidebar-text);
            display: flex; flex-direction: column; position: fixed; top: 0; bottom: 0; inset-inline-start: 0; z-index: 50;
            border-inline-end: 1px solid var(--admin-sidebar-border); transition: transform 0.28s ease, background 0.2s ease;
        }
        html.dark .adm-sidebar {
            background: linear-gradient(180deg, color-mix(in srgb, var(--admin-sidebar) 92%, #064e3b) 0%, var(--admin-sidebar) 100%);
        }
        html[dir="ltr"] .adm-sidebar:not(.open) { transform: translateX(-100%); box-shadow: 8px 0 32px rgba(0,0,0,0.15); }
        html[dir="rtl"] .adm-sidebar:not(.open) { transform: translateX(100%); box-shadow: -8px 0 32px rgba(0,0,0,0.15); }
        .adm-sidebar.open { transform: translateX(0); box-shadow: none; }
        html[dir="ltr"] .adm-sidebar.open { box-shadow: 8px 0 32px rgba(0,0,0,0.15); }
        html[dir="rtl"] .adm-sidebar.open { box-shadow: -8px 0 32px rgba(0,0,0,0.15); }
        @media (min-width: 1024px) {
            .adm-sidebar { position: sticky; top: 0; height: 100vh; transform: none !important; box-shadow: none !important; border-inline-end: 1px solid var(--admin-sidebar-border); transition: width 0.25s ease; }
            .adm-sidebar.collapsed { width: 4.5rem; }
            .adm-sidebar.collapsed .adm-sidebar-brand-text,
            .adm-sidebar.collapsed .adm-nav-label,
            .adm-sidebar.collapsed .adm-nav-item span,
            .adm-sidebar.collapsed .adm-sidebar-collapse-btn span,
            .adm-sidebar.collapsed .adm-logout-btn span,
            .adm-sidebar.collapsed .adm-panel-version { display: none; }
            .adm-sidebar.collapsed .adm-sidebar-brand { padding: 1rem 0.65rem; }
            .adm-sidebar.collapsed .adm-sidebar-brand > .flex { justify-content: center; }
            .adm-sidebar.collapsed .adm-nav-item { justify-content: center; padding-inline: 0.65rem; }
            .adm-sidebar.collapsed .adm-sidebar-collapse-btn,
            .adm-sidebar.collapsed .adm-logout-btn { justify-content: center; }
        }
        html[dir="rtl"] .adm-icon-flip { transform: scaleX(-1); }
        .adm-sidebar-collapse-btn {
            display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; width: 100%;
            padding: 0.65rem 0.85rem; border-radius: 0.75rem; background: var(--admin-sidebar-btn-bg); color: var(--admin-sidebar-btn-text);
            font-size: 0.78rem; font-weight: 700; border: 1px solid var(--admin-sidebar-btn-border); cursor: pointer;
            transition: 0.15s ease; margin-bottom: 0.75rem;
        }
        .adm-sidebar-collapse-btn:hover { background: var(--admin-sidebar-hover-bg); color: var(--admin-sidebar-hover-text); }
        .adm-collapse-chevron { width: 1rem; height: 1rem; flex-shrink: 0; transition: transform 0.2s ease; opacity: 0.85; }
        html[dir="ltr"] .adm-sidebar.collapsed .adm-collapse-chevron { transform: rotate(180deg); }
        html[dir="rtl"] .adm-sidebar:not(.collapsed) .adm-collapse-chevron { transform: scaleX(-1); }
        html[dir="rtl"] .adm-sidebar.collapsed .adm-collapse-chevron { transform: scaleX(-1) rotate(180deg); }
        .adm-sidebar-brand { padding: 1.35rem 1.25rem 1rem; border-bottom: 1px solid var(--admin-sidebar-border); }
        .adm-sidebar-logo { width: 2.75rem; height: 2.75rem; border-radius: 0.85rem; background: transparent; display: flex; align-items: center; justify-content: center; overflow: hidden; padding: 0; }
        .adm-sidebar-logo img { width: 100%; height: 100%; object-fit: contain; display: block; }
        .adm-sidebar-title { font-size: 1rem; font-weight: 900; color: var(--admin-sidebar-title); line-height: 1.2; }
        .adm-sidebar-sub { font-size: 0.68rem; color: var(--admin-sidebar-sub); margin-top: 0.15rem; }
        .adm-nav { padding: 1rem 0.75rem; flex: 1; display: flex; flex-direction: column; gap: 0.35rem; overflow-y: auto; }
        .adm-nav-label { font-size: 0.65rem; font-weight: 800; letter-spacing: 0.06em; text-transform: uppercase; color: var(--admin-sidebar-label); padding: 0.5rem 0.75rem 0.25rem; }
        .adm-nav-item {
            display: flex; align-items: center; gap: 0.65rem; padding: 0.7rem 0.85rem; border-radius: 0.75rem;
            font-size: 0.82rem; font-weight: 700; color: var(--admin-sidebar-text); transition: 0.15s ease; border: 1px solid transparent;
            text-align: start;
        }
        .adm-nav-item:hover { background: var(--admin-sidebar-hover-bg); color: var(--admin-sidebar-hover-text); }
        .adm-nav-item.active {
            background: color-mix(in srgb, var(--admin-primary) 22%, transparent);
            border-color: color-mix(in srgb, var(--admin-primary) 40%, transparent);
            color: var(--admin-sidebar-active-text);
            box-shadow: inset 3px 0 0 var(--admin-sidebar-active), 0 4px 16px -4px var(--admin-glow);
        }
        .adm-nav-item svg { width: 1.15rem; height: 1.15rem; flex-shrink: 0; opacity: 0.85; }
        .adm-sidebar-foot { padding: 1rem; border-top: 1px solid var(--admin-sidebar-border); display: flex; flex-direction: column; gap: 0.75rem; }
        .adm-social-row { display: flex; align-items: center; justify-content: center; gap: 0.45rem; flex-wrap: wrap; }
        .adm-social-icon-btn {
            width: 2.25rem; height: 2.25rem; border-radius: 0.55rem; border: 1px solid var(--admin-sidebar-btn-border);
            background: var(--admin-sidebar-btn-bg); color: var(--admin-sidebar-btn-text); display: inline-flex;
            align-items: center; justify-content: center; transition: 0.15s ease; flex-shrink: 0;
        }
        .adm-social-icon-btn:hover { background: var(--admin-sidebar-hover-bg); color: var(--admin-sidebar-hover-text); border-color: color-mix(in srgb, var(--admin-primary) 35%, var(--admin-sidebar-btn-border)); }
        .adm-social-icon-btn svg { width: 1.05rem; height: 1.05rem; }
        .adm-social-icon-btn.tg { color: #38bdf8; }
        .adm-social-icon-btn.yt { color: #f87171; }
        .adm-social-icon-btn.ig { color: #f472b6; }
        .adm-social-icon-btn.web { color: #34d399; }
        .adm-topbar {
            position: sticky; top: 0; z-index: 40; display: flex; align-items: center; justify-content: space-between; gap: 0.75rem;
            padding: 0.85rem 1rem; background: var(--admin-header); backdrop-filter: blur(16px) saturate(1.4);
            border-bottom: 1px solid color-mix(in srgb, var(--admin-border) 80%, transparent);
            box-shadow: 0 1px 0 color-mix(in srgb, var(--admin-primary) 6%, transparent);
        }
        @media (min-width: 768px) { .adm-topbar { padding: 0.85rem 1.5rem; } }
        .adm-topbar-start { display: flex; align-items: center; gap: 0.75rem; min-width: 0; }
        .adm-menu-btn {
            display: flex; align-items: center; justify-content: center; width: 2.5rem; height: 2.5rem; border-radius: 0.75rem;
            background: var(--admin-card); border: 1px solid var(--admin-border); color: var(--admin-muted);
        }
        @media (min-width: 1024px) { .adm-menu-btn { display: none; } }
        .adm-page-title { font-size: 1.05rem; font-weight: 900; color: var(--admin-text); line-height: 1.2; }
        .adm-page-desc { font-size: 0.72rem; color: var(--admin-muted); }
        .adm-topbar-actions { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; justify-content: flex-end; }
        .adm-update-overlay {
            position: fixed; inset: 0; z-index: 9999;
            display: none; align-items: center; justify-content: center;
            background: color-mix(in srgb, var(--admin-bg, #0f172a) 88%, transparent);
            backdrop-filter: blur(8px);
        }
        .adm-update-overlay.show { display: flex; }
        .adm-update-overlay-card {
            max-width: 22rem; width: calc(100% - 2rem); padding: 1.25rem 1.35rem;
            border-radius: 1rem; background: var(--admin-card); border: 1px solid var(--admin-border);
            box-shadow: var(--admin-shadow); text-align: center;
        }
        .adm-update-overlay-title { font-size: 0.95rem; font-weight: 800; color: var(--admin-text); margin-bottom: 0.45rem; }
        .adm-update-overlay-msg { font-size: 0.78rem; color: var(--admin-muted); line-height: 1.6; white-space: pre-wrap; }
        .adm-update-spinner {
            width: 2rem; height: 2rem; margin: 0 auto 0.85rem;
            border: 3px solid color-mix(in srgb, var(--admin-primary) 25%, transparent);
            border-top-color: var(--admin-primary); border-radius: 9999px;
            animation: admUpdateSpin 0.8s linear infinite;
        }
        @keyframes admUpdateSpin { to { transform: rotate(360deg); } }
        .adm-update-actions {
            display: none; flex-direction: column; gap: 0.5rem; margin-top: 1rem;
        }
        .adm-update-actions.show { display: flex; }
        .adm-update-btn {
            width: 100%; padding: 0.65rem 1rem; border-radius: 0.75rem;
            font-size: 0.82rem; font-weight: 800; cursor: pointer; border: none; transition: 0.15s ease;
        }
        .adm-update-btn.primary { background: var(--admin-primary); color: #fff; }
        .adm-update-btn.primary:hover { filter: brightness(1.05); }
        .adm-update-btn.secondary {
            background: transparent; color: var(--admin-muted);
            border: 1px solid var(--admin-border);
        }
        .adm-update-btn.secondary:hover { color: var(--admin-text); border-color: color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border)); }
        .adm-panel-update-versions {
            display: grid; grid-template-columns: 1fr 1fr; gap: 0.65rem; margin-top: 0.85rem;
        }
        .adm-panel-update-ver {
            padding: 0.75rem 0.85rem; border-radius: 0.75rem;
            background: color-mix(in srgb, var(--admin-primary) 5%, var(--admin-card));
            border: 1px solid var(--admin-border); font-size: 0.75rem; color: var(--admin-muted);
        }
        .adm-panel-update-ver strong { display: block; margin-top: 0.25rem; font-size: 0.88rem; color: var(--admin-text); font-family: ui-monospace, monospace; }
        .adm-nav-update-badge {
            display: none; margin-inline-start: auto; min-width: 1.15rem; height: 1.15rem; padding: 0 0.3rem;
            border-radius: 9999px; background: #f59e0b; color: #fff; font-size: 0.62rem; font-weight: 900;
            align-items: center; justify-content: center;
        }
        .adm-lang-switch {
            display: flex; align-items: center; gap: 0.15rem; padding: 0.2rem;
            background: var(--admin-card); border: 1px solid var(--admin-border); border-radius: 0.65rem;
        }
        .adm-lang-btn {
            min-width: 2.1rem; padding: 0.35rem 0.55rem; border-radius: 0.45rem; font-size: 0.72rem; font-weight: 800;
            color: var(--admin-muted); background: transparent; border: none; cursor: pointer; transition: 0.15s ease;
        }
        .adm-lang-btn.active {
            background: var(--admin-primary-soft); color: var(--admin-primary);
            box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--admin-primary) 35%, transparent), 0 2px 8px -2px var(--admin-glow);
        }
        .adm-theme-btn {
            display: flex; align-items: center; justify-content: center; width: 2.35rem; height: 2.35rem;
            border-radius: 0.65rem; background: var(--admin-card); border: 1px solid var(--admin-border);
            color: var(--admin-primary); cursor: pointer; transition: 0.15s ease;
        }
        .adm-theme-btn:hover { background: var(--admin-primary-soft); border-color: color-mix(in srgb, var(--admin-primary) 40%, var(--admin-border)); }
        .adm-section { display: none; }
        .adm-section.active { display: block; }
        .adm-logout-btn {
            display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; width: 100%; padding: 0.65rem 0.85rem;
            border-radius: 0.75rem; background: var(--admin-sidebar-btn-bg); color: var(--admin-sidebar-btn-text); font-size: 0.78rem; font-weight: 700;
            border: 1px solid var(--admin-sidebar-btn-border); transition: 0.15s ease; cursor: pointer;
        }
        .adm-logout-btn:hover { background: var(--admin-sidebar-hover-bg); color: var(--admin-sidebar-hover-text); border-color: color-mix(in srgb, var(--admin-primary) 35%, var(--admin-sidebar-btn-border)); }
        .adm-sidebar-divider { border: none; border-top: 1px solid var(--admin-sidebar-border); margin: 0.25rem 0 0; }
        .adm-panel-version { text-align: center; font-size: 0.68rem; font-weight: 600; color: var(--admin-sidebar-sub); letter-spacing: 0.02em; padding: 0.15rem 0; }
        .adm-about-social-row { display: flex; align-items: center; justify-content: center; gap: 0.65rem; flex-wrap: wrap; padding: 0.5rem 0; }
        .adm-about-social-row .adm-social-icon-btn { width: 2.75rem; height: 2.75rem; border-radius: 0.65rem; }
        .adm-about-social-row .adm-social-icon-btn svg { width: 1.2rem; height: 1.2rem; }
        .adm-about-wrap { max-width: 52rem; margin: 0 auto; display: flex; flex-direction: column; gap: 1rem; }
        .adm-about-hero { padding: 1.75rem 1.5rem; text-align: center; position: relative; overflow: hidden; }
        .adm-about-hero::before {
            content: ''; position: absolute; inset: -40% -20% auto auto; width: 55%; height: 70%;
            background: radial-gradient(circle, color-mix(in srgb, var(--admin-primary) 14%, transparent), transparent 68%);
            pointer-events: none;
        }
        .adm-about-hero > * { position: relative; }
        .adm-about-logo { width: 4rem; height: 4rem; margin: 0 auto 1rem; border-radius: 1rem; overflow: hidden; }
        .adm-about-logo img { width: 100%; height: 100%; object-fit: contain; }
        .adm-about-kicker {
            display: inline-block; font-size: 0.68rem; font-weight: 700; letter-spacing: 0.06em;
            color: var(--admin-primary); border: 1px solid color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border));
            background: var(--admin-primary-soft); padding: 0.3rem 0.75rem; border-radius: 9999px; margin-bottom: 0.85rem;
        }
        .adm-about-hero-title { font-size: 1.35rem; font-weight: 900; line-height: 1.45; color: var(--admin-text); margin-bottom: 0.65rem; }
        .adm-about-hero-desc { font-size: 0.88rem; line-height: 1.8; color: var(--admin-muted); max-width: 36rem; margin: 0 auto; }
        .adm-about-main { padding: 1.5rem; }
        .adm-about-main-title { font-size: 1.1rem; font-weight: 900; color: var(--admin-text); margin-bottom: 0.55rem; }
        .adm-about-main-desc { font-size: 0.86rem; line-height: 1.85; color: var(--admin-muted); margin-bottom: 1.25rem; }
        .adm-about-features {
            display: grid; grid-template-columns: 1fr; gap: 0.75rem;
        }
        @media (min-width: 640px) { .adm-about-features { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
        .adm-about-feature {
            background: color-mix(in srgb, var(--admin-primary) 4%, var(--admin-card));
            border: 1px solid var(--admin-border); border-radius: 1rem; padding: 1.1rem 1rem;
            transition: border-color 0.2s, transform 0.2s;
        }
        .adm-about-feature:hover {
            border-color: color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border));
            transform: translateY(-1px);
        }
        .adm-about-feature-icon {
            width: 2.25rem; height: 2.25rem; border-radius: 0.65rem;
            background: var(--admin-primary-soft); border: 1px solid color-mix(in srgb, var(--admin-primary) 30%, var(--admin-border));
            display: flex; align-items: center; justify-content: center; margin-bottom: 0.75rem;
            color: var(--admin-primary);
        }
        .adm-about-feature-icon svg { width: 1.05rem; height: 1.05rem; }
        .adm-about-feature h4 { font-size: 0.88rem; font-weight: 800; color: var(--admin-text); margin-bottom: 0.35rem; }
        .adm-about-feature p { font-size: 0.78rem; line-height: 1.7; color: var(--admin-muted); }
        .adm-about-social-card { padding: 1.35rem 1.25rem; text-align: center; }
        .adm-about-social-desc { font-size: 0.8rem; color: var(--admin-muted); margin-bottom: 1rem; line-height: 1.7; }
        .adm-tg-card {
            background: var(--admin-card); border: 1px solid var(--admin-border); border-radius: 1.15rem;
            box-shadow: var(--admin-shadow); padding: 1.25rem; margin-bottom: 1rem;
        }
        .adm-tg-toggle { position: relative; width: 2.75rem; height: 1.5rem; border-radius: 9999px; background: var(--admin-progress-track); transition: 0.2s; cursor: pointer; flex-shrink: 0; }
        .adm-tg-toggle.on { background: var(--admin-primary); }
        .adm-tg-toggle::after {
            content: ''; position: absolute; top: 0.15rem; inset-inline-end: 0.15rem; width: 1.2rem; height: 1.2rem;
            border-radius: 9999px; background: #fff; transition: 0.2s; box-shadow: 0 1px 3px rgba(0,0,0,0.2);
        }
        .adm-tg-toggle.on::after { inset-inline-end: auto; inset-inline-start: 0.15rem; }
        .adm-content { padding: 1rem; flex: 1; background: transparent; }
        @media (min-width: 768px) { .adm-content { padding: 1.25rem 1.5rem 2rem; } }
        .adm-bento { display: grid; grid-template-columns: 1fr; gap: 0.85rem; margin-bottom: 1.25rem; }
        @media (min-width: 640px) { .adm-bento { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
        @media (min-width: 1280px) { .adm-bento { grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 1rem; } }
        .adm-bento-span-3 { grid-column: span 1; }
        @media (min-width: 1280px) { .adm-bento-span-3 { grid-column: span 3; } .adm-bento-span-4 { grid-column: span 4; } }
        .admin-shell { color: var(--admin-text); }
        .admin-header { background: transparent; border: none; box-shadow: none; }
        .admin-card { background: var(--admin-card); border: 1px solid var(--admin-border); box-shadow: var(--admin-shadow); border-radius: 1.15rem; color: var(--admin-text); transition: border-color 0.2s, box-shadow 0.2s; }
        .admin-card:hover { border-color: color-mix(in srgb, var(--admin-primary) 28%, var(--admin-border)); }
        .admin-stat {
            background: var(--admin-card); border: 1px solid var(--admin-border); box-shadow: var(--admin-shadow);
            border-radius: 1.15rem; position: relative; overflow: hidden; color: var(--admin-text);
            transition: border-color 0.25s, box-shadow 0.25s, transform 0.25s; height: 100%;
        }
        .admin-stat:hover { border-color: color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border)); transform: translateY(-2px); box-shadow: var(--admin-shadow-lg); }
        .admin-stat::before {
            content: ''; position: absolute; top: 0; right: 0; width: 100%; height: 3px;
            background: linear-gradient(90deg, var(--admin-primary), var(--admin-accent), transparent); border-radius: 1.15rem 1.15rem 0 0;
        }
        .admin-stat.danger { border-color: #ef4444; box-shadow: 0 0 20px rgba(239,68,68,0.25); animation: adm-pulse 2s infinite; }
        @keyframes adm-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.92; } }
        .admin-toolbar { background: var(--admin-card); border: 1px solid var(--admin-border); box-shadow: var(--admin-shadow); border-radius: 1.15rem; }
        .admin-table-wrap { background: var(--admin-card); border: 1px solid var(--admin-border); box-shadow: var(--admin-shadow); border-radius: 1.15rem; }
        .admin-table-head { background: linear-gradient(135deg, color-mix(in srgb, var(--admin-primary) 7%, var(--admin-card)), var(--admin-card)); color: var(--admin-muted); }
        .admin-btn-icon {
            background: var(--admin-card); border: 1px solid var(--admin-border); color: var(--admin-muted); transition: all 0.2s; border-radius: 0.75rem;
        }
        .admin-btn-icon:hover {
            border-color: color-mix(in srgb, var(--admin-primary) 40%, var(--admin-border));
            color: var(--admin-primary); background: var(--admin-primary-soft);
        }
        .admin-btn-primary {
            background: linear-gradient(135deg, var(--admin-primary) 0%, var(--admin-accent) 100%);
            color: #fff; box-shadow: 0 4px 18px -4px var(--admin-glow); border-radius: 0.85rem;
            transition: filter 0.2s, transform 0.15s, box-shadow 0.2s;
        }
        .admin-btn-primary:hover { filter: brightness(1.07); transform: translateY(-1px); box-shadow: 0 8px 24px -6px var(--admin-glow); }
        .admin-input, .admin-input option {
            background: var(--admin-input-bg); border: 1px solid var(--admin-border); color: var(--admin-text); border-radius: 0.85rem;
        }
        .admin-input:focus {
            outline: none; border-color: color-mix(in srgb, var(--admin-primary) 50%, var(--admin-border));
            box-shadow: 0 0 0 3px var(--admin-primary-soft);
        }
        .admin-section-title { color: var(--admin-text); }
        .admin-brand { color: var(--admin-primary); }
        .admin-row:hover { background: color-mix(in srgb, var(--admin-primary) 4%, var(--admin-card)); }
        .admin-row.is-selected {
            background: color-mix(in srgb, var(--admin-primary) 12%, var(--admin-card));
            box-shadow: inset 3px 0 0 var(--admin-primary);
        }
        .admin-row.is-selected:hover { background: color-mix(in srgb, var(--admin-primary) 16%, var(--admin-card)); }
        .adm-user-card.is-selected {
            background: color-mix(in srgb, var(--admin-primary) 10%, var(--admin-card));
            border-color: color-mix(in srgb, var(--admin-primary) 50%, var(--admin-border));
            box-shadow: 0 0 0 2px color-mix(in srgb, var(--admin-primary) 22%, transparent), inset 3px 0 0 var(--admin-primary);
        }
        .adm-select-cb {
            appearance: none; -webkit-appearance: none;
            width: 1.15rem; height: 1.15rem; border-radius: 0.45rem;
            border: 2px solid color-mix(in srgb, var(--admin-border) 85%, var(--admin-muted));
            background: color-mix(in srgb, var(--admin-input-bg) 80%, var(--admin-card));
            cursor: pointer; transition: all 0.2s ease; flex-shrink: 0; position: relative;
            box-shadow: inset 0 1px 2px rgba(0,0,0,0.12);
        }
        .adm-select-cb:hover {
            border-color: color-mix(in srgb, var(--admin-primary) 60%, var(--admin-border));
            background: color-mix(in srgb, var(--admin-primary) 10%, var(--admin-input-bg));
            box-shadow: 0 0 0 3px color-mix(in srgb, var(--admin-primary) 15%, transparent);
        }
        .adm-select-cb:checked {
            background: linear-gradient(145deg, var(--admin-primary), var(--admin-accent));
            border-color: color-mix(in srgb, var(--admin-primary) 85%, #fff);
            box-shadow: 0 2px 10px -2px var(--admin-glow), inset 0 1px 0 rgba(255,255,255,0.2);
        }
        .adm-select-cb:checked::after {
            content: ''; position: absolute; top: 45%; left: 50%;
            width: 0.32rem; height: 0.58rem; border: 2.5px solid #fff;
            border-top: 0; border-left: 0; transform: translate(-50%, -50%) rotate(45deg);
        }
        .adm-select-cb:focus-visible {
            outline: none;
            box-shadow: 0 0 0 3px var(--admin-primary-soft);
        }
        .adm-select-cb:checked:focus-visible {
            box-shadow: 0 0 0 3px var(--admin-primary-soft), 0 2px 10px -2px color-mix(in srgb, var(--admin-primary) 55%, transparent);
        }
        .adm-section-head { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; margin-bottom: 1rem; flex-wrap: wrap; }
        .adm-users-panel { background: var(--admin-card); border: 1px solid var(--admin-border); border-radius: 1.25rem; box-shadow: var(--admin-shadow); overflow: hidden; color: var(--admin-text); }
        .adm-users-panel-head { padding: 1rem 1.15rem; border-bottom: 1px solid var(--admin-border); display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; flex-wrap: wrap; background: linear-gradient(135deg, color-mix(in srgb, var(--admin-primary) 6%, var(--admin-card)), var(--admin-card)); }
        .adm-user-cards { display: grid; grid-template-columns: 1fr; gap: 0.85rem; padding: 0.85rem; }
        @media (min-width: 640px) { .adm-user-cards { grid-template-columns: repeat(2, minmax(0, 1fr)); padding: 1rem; } }
        @media (min-width: 1024px) { .adm-user-cards { display: none !important; } }
        .adm-user-card {
            background: color-mix(in srgb, var(--admin-bg) 35%, var(--admin-card)); border: 1px solid var(--admin-border);
            border-radius: 1rem; padding: 1rem; display: flex; flex-direction: column; gap: 0.75rem; color: var(--admin-text);
        }
        .adm-user-card-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 0.5rem; }
        .adm-user-card-name { font-weight: 900; font-size: 0.95rem; color: var(--admin-text); word-break: break-all; }
        .adm-user-card-meta { display: grid; grid-template-columns: 1fr 1fr; gap: 0.65rem; }
        .adm-user-card-actions { display: flex; flex-wrap: wrap; gap: 0.35rem; }
        .adm-user-card-actions button { padding: 0.45rem; border-radius: 0.55rem; border: 1px solid var(--admin-border); background: var(--admin-card); color: var(--admin-text); }
        .adm-table-desktop { display: none; }
        @media (min-width: 1024px) { .adm-table-desktop { display: block; } }
        .adm-bulk-bar { border-radius: 1rem; padding: 0.85rem 1rem; margin-bottom: 1rem; background: linear-gradient(135deg, color-mix(in srgb, var(--admin-primary) 10%, var(--admin-card)), var(--admin-card)); border: 1px solid color-mix(in srgb, var(--admin-primary) 28%, var(--admin-border)); color: var(--admin-text); }
        .adm-progress-track { background: var(--admin-progress-track); border-radius: 9999px; height: 0.375rem; overflow: hidden; }
        .adm-muted { color: var(--admin-muted); }
        html.dark .adm-app .bg-white { background-color: var(--admin-card) !important; }
        html.dark .adm-app .bg-gray-50 { background-color: var(--admin-input-bg) !important; }
        html.dark .adm-app .bg-gray-100 { background-color: color-mix(in srgb, var(--admin-card) 85%, var(--admin-border)) !important; }
        html.dark .adm-app .bg-gray-200 { background-color: var(--admin-progress-track) !important; }
        html.dark .adm-app .border-gray-200, html.dark .adm-app .border-gray-300 { border-color: var(--admin-border) !important; }
        html.dark .adm-app .text-gray-900, html.dark .adm-app .text-gray-800, html.dark .adm-app .text-gray-700 { color: var(--admin-text) !important; }
        html.dark .adm-app .text-gray-500, html.dark .adm-app .text-gray-600, html.dark .adm-app .text-gray-400 { color: var(--admin-muted) !important; }
        html.dark .adm-app select, html.dark .adm-app textarea, html.dark .adm-app input:not([type=checkbox]):not([type=radio]) {
            background-color: var(--admin-input-bg) !important; border-color: var(--admin-border) !important; color: var(--admin-text) !important;
        }
        html.dark .adm-app #users-tbody td, html.dark .adm-app .admin-table-wrap { color: var(--admin-text); }
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: var(--admin-bg); border-radius: 4px; }
        ::-webkit-scrollbar-thumb { background: var(--admin-border); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--admin-muted); }
        * { scrollbar-width: thin; scrollbar-color: var(--admin-border) var(--admin-bg); }
        .port-chip {
            display: flex; align-items: center; justify-content: center; gap: 0.45rem;
            padding: 0.55rem 0.75rem; border-radius: 0.75rem; font-size: 0.78rem; font-weight: 800;
            border: 1.5px solid transparent; transition: all 0.2s ease; cursor: pointer; user-select: none;
        }
        .port-chip-check { display: none; width: 1rem; height: 1rem; flex-shrink: 0; }
        .port-chip-tls {
            border-color: rgba(5, 150, 105, 0.55); background: rgba(16, 185, 129, 0.16); color: #047857;
        }
        html.dark .port-chip-tls {
            border-color: rgba(52, 211, 153, 0.65); background: rgba(5, 150, 105, 0.28); color: #a7f3d0;
        }
        .port-chip-tls:hover { background: rgba(16, 185, 129, 0.24); border-color: rgba(5, 150, 105, 0.75); }
        html.dark .port-chip-tls:hover { background: rgba(5, 150, 105, 0.38); border-color: #34d399; }
        .peer:checked ~ .port-chip-tls {
            background: linear-gradient(135deg, rgba(5, 150, 105, 0.32), rgba(16, 185, 129, 0.22));
            border-color: #059669; color: #064e3b;
            box-shadow: 0 0 0 2px rgba(16, 185, 129, 0.3), inset 0 1px 0 rgba(255,255,255,0.15);
        }
        html.dark .peer:checked ~ .port-chip-tls {
            background: linear-gradient(135deg, rgba(5, 150, 105, 0.65), rgba(4, 120, 87, 0.45));
            border-color: #6ee7b7; color: #ecfdf5;
            box-shadow: 0 0 0 2px rgba(52, 211, 153, 0.45), 0 0 16px rgba(16, 185, 129, 0.35);
        }
        .peer:checked ~ .port-chip-tls .port-chip-check { display: block; color: #059669; }
        html.dark .peer:checked ~ .port-chip-tls .port-chip-check { color: #d1fae5; }
        .port-chip-nontls {
            border-color: rgba(124, 58, 237, 0.55); background: rgba(139, 92, 246, 0.16); color: #6d28d9;
        }
        html.dark .port-chip-nontls {
            border-color: rgba(167, 139, 250, 0.65); background: rgba(109, 40, 217, 0.28); color: #ddd6fe;
        }
        .port-chip-nontls:hover { background: rgba(139, 92, 246, 0.24); border-color: rgba(124, 58, 237, 0.75); }
        html.dark .port-chip-nontls:hover { background: rgba(109, 40, 217, 0.38); border-color: #a78bfa; }
        .peer:checked ~ .port-chip-nontls {
            background: linear-gradient(135deg, rgba(124, 58, 237, 0.32), rgba(139, 92, 246, 0.22));
            border-color: #7c3aed; color: #4c1d95;
            box-shadow: 0 0 0 2px rgba(139, 92, 246, 0.3), inset 0 1px 0 rgba(255,255,255,0.15);
        }
        html.dark .peer:checked ~ .port-chip-nontls {
            background: linear-gradient(135deg, rgba(124, 58, 237, 0.65), rgba(109, 40, 217, 0.45));
            border-color: #c4b5fd; color: #f5f3ff;
            box-shadow: 0 0 0 2px rgba(167, 139, 250, 0.45), 0 0 16px rgba(139, 92, 246, 0.3);
        }
        .peer:checked ~ .port-chip-nontls .port-chip-check { display: block; color: #7c3aed; }
        html.dark .peer:checked ~ .port-chip-nontls .port-chip-check { color: #ede9fe; }
        .num-stepper { position: relative; }
        .num-stepper-input {
            -moz-appearance: textfield;
        }
        .num-stepper-input::-webkit-outer-spin-button,
        .num-stepper-input::-webkit-inner-spin-button {
            -webkit-appearance: none; margin: 0;
        }
        .num-stepper-controls {
            position: absolute; inset-inline-end: 0.35rem; top: 50%; transform: translateY(-50%);
            display: flex; flex-direction: column; gap: 2px; z-index: 2;
        }
        .num-stepper-input { padding-inline-end: 2.5rem; }
        .num-stepper-btn {
            width: 1.35rem; height: 1.05rem; display: flex; align-items: center; justify-content: center;
            border-radius: 0.35rem; border: 1px solid var(--admin-border);
            background: color-mix(in srgb, var(--admin-card) 70%, var(--admin-border));
            color: var(--admin-text); cursor: pointer; padding: 0; transition: 0.15s ease;
            line-height: 1;
        }
        .num-stepper-btn:hover {
            background: var(--admin-primary-soft); border-color: color-mix(in srgb, var(--admin-primary) 45%, var(--admin-border));
            color: var(--admin-primary);
        }
        .num-stepper-btn:active { transform: scale(0.94); }
        .num-stepper-btn svg { width: 0.65rem; height: 0.65rem; pointer-events: none; }
        .adm-dash-grid { display: grid; grid-template-columns: 1fr; gap: 1.15rem; }
        @media (min-width: 1024px) { .adm-dash-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
        .adm-dash-card {
            background: var(--admin-card); border: 1px solid var(--admin-border); border-radius: 1.15rem;
            box-shadow: var(--admin-shadow); padding: 1.35rem; position: relative; overflow: hidden;
            transition: border-color 0.25s, box-shadow 0.25s, transform 0.25s;
        }
        .adm-dash-card::before {
            content: ''; position: absolute; top: 0; inset-inline: 0; height: 3px;
            background: linear-gradient(90deg, var(--admin-primary), var(--admin-accent), transparent);
            opacity: 0.55;
        }
        .adm-dash-card:hover { border-color: color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border)); box-shadow: var(--admin-shadow-lg); transform: translateY(-2px); }
        .adm-dash-card-title { font-size: 0.82rem; font-weight: 800; color: var(--admin-muted); margin-bottom: 1rem; display: flex; align-items: center; gap: 0.45rem; }
        .adm-dash-card-head { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; margin-bottom: 1rem; }
        .adm-dash-card-head .adm-dash-card-title { margin-bottom: 0; }
        .adm-dash-refresh-btn { display: inline-flex; align-items: center; justify-content: center; gap: 0.4rem; padding: 0.5rem 0.8rem; border-radius: 0.7rem; border: 1px solid var(--admin-border); background: var(--admin-input-bg); color: var(--admin-primary); font-size: 0.72rem; font-weight: 800; cursor: pointer; transition: 0.15s ease; }
        .adm-dash-refresh-btn:hover { background: var(--admin-primary-soft); }
        .adm-dash-refresh-btn:disabled { opacity: 0.65; cursor: wait; }
        .adm-dash-geo-stack { display: flex; flex-direction: column; gap: 1rem; }
        .adm-dash-geo-block { background: color-mix(in srgb, var(--admin-input-bg) 80%, transparent); border: 1px solid var(--admin-border); border-radius: 0.95rem; padding: 0.95rem; }
        .adm-dash-geo-block-title { font-size: 0.72rem; font-weight: 900; color: var(--admin-muted); margin-bottom: 0.8rem; }
        .adm-dash-ip-row { display: flex; align-items: flex-start; gap: 1rem; }
        .adm-dash-flag { font-size: 2.5rem; line-height: 1; flex-shrink: 0; }
        .adm-dash-ip { font-family: ui-monospace, monospace; font-size: 1.15rem; font-weight: 800; color: var(--admin-text); direction: ltr; text-align: start; word-break: break-all; }
        .adm-dash-location { font-size: 0.84rem; color: var(--admin-muted); margin-top: 0.5rem; line-height: 1.7; }
        .adm-dash-geo-details { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.65rem 1rem; margin-top: 1rem; }
        @media (min-width: 640px) { .adm-dash-geo-details { grid-template-columns: repeat(4, minmax(0, 1fr)); } }
        .adm-dash-geo-item { background: var(--admin-input-bg); border: 1px solid var(--admin-border); border-radius: 0.75rem; padding: 0.65rem 0.75rem; }
        .adm-dash-geo-label { font-size: 0.65rem; font-weight: 800; color: var(--admin-muted); text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 0.2rem; }
        .adm-dash-geo-value { font-size: 0.82rem; font-weight: 700; color: var(--admin-text); word-break: break-word; }
        .adm-dash-geo { grid-column: 1 / -1; }
        .adm-dash-geo-inner { display: grid; grid-template-columns: 1fr; gap: 1.25rem; align-items: stretch; }
        @media (min-width: 900px) { .adm-dash-geo-inner { grid-template-columns: minmax(0, 1fr) minmax(280px, 380px); } }
        .adm-dash-map-panel { display: flex; flex-direction: column; height: 100%; min-height: 0; }
        .adm-dash-map-wrap { border-radius: 0.95rem; overflow: hidden; border: 1px solid var(--admin-border); background: var(--admin-input-bg); min-height: 220px; flex: 1; display: flex; flex-direction: column; }
        .adm-dash-map-container { width: 100%; flex: 1; min-height: 0; height: 100%; z-index: 0; }
        .adm-dash-map-container .leaflet-control-attribution { font-size: 0.6rem; }
        .adm-dash-map-empty { display: flex; align-items: center; justify-content: center; flex: 1; min-height: 220px; font-size: 0.82rem; color: var(--admin-muted); padding: 1rem; text-align: center; }
        .adm-ip-scanner-page { display: flex; justify-content: center; padding: 2rem 0; }
        .adm-ip-scanner-card {
            width: 100%; max-width: 28rem; text-align: center; padding: 2.5rem 2rem; border-radius: 1.15rem;
            border: 1px dashed color-mix(in srgb, var(--admin-primary) 38%, var(--admin-border));
            background: linear-gradient(160deg, color-mix(in srgb, var(--admin-primary) 10%, var(--admin-card)), var(--admin-card));
            box-shadow: var(--admin-shadow);
        }
        .adm-ip-scanner-icon {
            display: inline-flex; align-items: center; justify-content: center; width: 4rem; height: 4rem; border-radius: 1.1rem;
            margin-bottom: 1.25rem; background: var(--admin-primary-soft); color: var(--admin-primary);
        }
        .adm-ip-scanner-icon svg { width: 2rem; height: 2rem; }
        .adm-ip-scanner-title { font-size: 1.15rem; font-weight: 900; color: var(--admin-text); margin-bottom: 0.5rem; }
        .adm-ip-scanner-desc { font-size: 0.85rem; font-weight: 700; color: var(--admin-muted); line-height: 1.7; margin-bottom: 1.25rem; }
        .adm-ip-scanner-badge {
            display: inline-flex; align-items: center; justify-content: center; padding: 0.55rem 1rem; border-radius: 9999px;
            font-size: 0.78rem; font-weight: 900; color: var(--admin-primary);
            background: color-mix(in srgb, var(--admin-primary) 14%, transparent);
            border: 1px solid color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border));
        }
        .adm-ip-scanner-wrap { max-width: 42rem; margin: 0 auto; }
        .adm-ip-scanner-panel {
            background: var(--admin-card); border: 1px solid var(--admin-border); border-radius: 1.15rem;
            box-shadow: var(--admin-shadow); padding: 1.35rem; margin-bottom: 1rem;
        }
        .adm-ip-scanner-panel.hero { border-color: color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border)); }
        .adm-ip-scanner-sub { font-size: 0.82rem; font-weight: 700; color: var(--admin-muted); line-height: 1.7; margin-bottom: 1rem; }
        .adm-ip-scanner-fields { display: flex; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 1rem; }
        .adm-ip-scanner-field { flex: 1; min-width: 7rem; }
        .adm-ip-scanner-field label { display: block; font-size: 0.68rem; font-weight: 800; color: var(--admin-muted); margin-bottom: 0.35rem; }
        .adm-ip-scanner-field input {
            width: 100%; background: var(--admin-input-bg); border: 1px solid var(--admin-border); border-radius: 0.7rem;
            color: var(--admin-text); padding: 0.65rem 0.75rem; font-size: 0.85rem; font-family: ui-monospace, monospace; direction: ltr; text-align: center;
        }
        .adm-ip-scanner-field input:focus { outline: none; border-color: var(--admin-primary); }
        .adm-ip-scanner-ports { margin-bottom: 1rem; }
        .adm-ip-scanner-ports-label { display: block; font-size: 0.68rem; font-weight: 800; color: var(--admin-muted); margin-bottom: 0.45rem; }
        .adm-ip-scanner-ports-grid { display: flex; flex-wrap: wrap; gap: 0.4rem; }
        .adm-ip-scanner-port-chip {
            display: inline-flex; align-items: center; gap: 0.35rem; padding: 0.35rem 0.65rem; border-radius: 0.55rem;
            font-size: 0.72rem; font-weight: 800; font-family: ui-monospace, monospace; cursor: pointer;
            background: var(--admin-input-bg); border: 1px solid var(--admin-border); color: var(--admin-text); transition: 0.15s ease;
        }
        .adm-ip-scanner-port-chip:has(input:checked) {
            background: var(--admin-primary-soft); border-color: color-mix(in srgb, var(--admin-primary) 40%, var(--admin-border)); color: var(--admin-primary);
        }
        .adm-ip-scanner-port-chip input { accent-color: var(--admin-primary); cursor: pointer; }
        .adm-ip-scanner-run {
            display: flex; align-items: center; justify-content: center; gap: 0.45rem; width: 100%;
            padding: 0.8rem 1rem; border-radius: 0.8rem; font-size: 0.88rem; font-weight: 900; border: none; cursor: pointer;
            background: linear-gradient(135deg, var(--admin-primary), var(--admin-accent)); color: #fff;
            box-shadow: 0 4px 16px -4px var(--admin-glow); transition: 0.15s ease;
        }
        .adm-ip-scanner-run:hover:not(:disabled) { filter: brightness(1.05); transform: translateY(-1px); }
        .adm-ip-scanner-run:disabled { opacity: 0.55; cursor: wait; transform: none; }
        .adm-ip-scanner-bar {
            height: 0.55rem; border-radius: 9999px; background: var(--admin-input-bg); border: 1px solid var(--admin-border);
            overflow: hidden; margin: 1rem 0 0.65rem; display: none;
        }
        .adm-ip-scanner-bar i { display: block; height: 100%; width: 0; background: linear-gradient(90deg, var(--admin-primary), var(--admin-accent)); transition: width 0.25s ease; }
        .adm-ip-scanner-status { text-align: center; font-size: 0.75rem; font-weight: 700; color: var(--admin-muted); min-height: 1.1rem; }
        .adm-ip-scanner-results { display: none; }
        .adm-ip-scanner-results-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 0.5rem; margin-bottom: 0.75rem; }
        .adm-ip-scanner-results-title { font-size: 0.85rem; font-weight: 900; color: var(--admin-text); }
        .adm-ip-scanner-results-count { font-size: 0.72rem; font-weight: 800; color: var(--admin-primary); }
        .adm-ip-scanner-output {
            background: var(--admin-input-bg); border: 1px solid var(--admin-border); border-radius: 0.85rem;
            padding: 0.85rem 1rem; font-family: ui-monospace, monospace; font-size: 0.82rem; color: var(--admin-accent);
            direction: ltr; text-align: left; line-height: 1.75; min-height: 4.5rem; max-height: 16rem; overflow: auto; white-space: pre;
        }
        .adm-ip-scanner-actions { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.85rem; }
        .adm-ip-scanner-action {
            flex: 1; min-width: 8rem; padding: 0.65rem 0.85rem; border-radius: 0.75rem; font-size: 0.75rem; font-weight: 800;
            cursor: pointer; transition: 0.15s ease; border: 1px solid var(--admin-border); background: var(--admin-input-bg); color: var(--admin-text);
        }
        .adm-ip-scanner-action.primary {
            background: var(--admin-primary-soft); color: var(--admin-primary);
            border-color: color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border));
        }
        .adm-ip-scanner-action:hover { border-color: color-mix(in srgb, var(--admin-primary) 40%, var(--admin-border)); color: var(--admin-primary); }
        .adm-ip-scanner-grid { display: grid; grid-template-columns: 1fr; gap: 1rem; margin-top: 0.5rem; }
        @media (min-width: 52rem) { .adm-ip-scanner-grid { grid-template-columns: 1fr 1fr; } }
        .adm-ip-scanner-section-title { font-size: 0.88rem; font-weight: 900; color: var(--admin-text); margin-bottom: 0.25rem; }
        .adm-ip-scanner-section-count { font-size: 0.72rem; font-weight: 800; color: var(--admin-primary); }
        .adm-ip-pool-textarea {
            width: 100%; min-height: 12rem; max-height: 28rem; margin-bottom: 0.75rem; box-sizing: border-box;
            background: var(--admin-input-bg); border: 1px solid var(--admin-border); border-radius: 0.75rem;
            color: var(--admin-text); padding: 0.75rem 0.85rem; font-size: 0.78rem; font-family: ui-monospace, monospace;
            direction: ltr; text-align: start; resize: vertical; line-height: 1.55; tab-size: 2; white-space: pre;
        }
        .adm-ip-pool-textarea:focus { outline: none; border-color: var(--admin-primary); }
        .adm-ip-pool-textarea::placeholder { color: var(--admin-muted); opacity: 0.75; }
        .adm-ip-source-tabs { display: flex; gap: 0.4rem; margin-bottom: 0.85rem; }
        .adm-ip-source-tab {
            flex: 1; padding: 0.55rem 0.75rem; border-radius: 0.7rem; border: 1px solid var(--admin-border);
            background: var(--admin-input-bg); color: var(--admin-muted); font-size: 0.75rem; font-weight: 800;
            cursor: pointer; transition: 0.15s ease;
        }
        .adm-ip-source-tab:hover { border-color: color-mix(in srgb, var(--admin-primary) 30%, var(--admin-border)); color: var(--admin-text); }
        .adm-ip-source-tab.active { background: var(--admin-primary-soft); color: var(--admin-primary); border-color: color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border)); }
        .adm-ip-smart-link {
            display: block; font-family: ui-monospace, monospace; font-size: 0.78rem; font-weight: 800;
            color: var(--admin-primary); background: var(--admin-input-bg); border: 1px solid var(--admin-border);
            border-radius: 0.75rem; padding: 0.85rem 1rem; word-break: break-all; direction: ltr; text-align: start;
            text-decoration: none;
        }
        .adm-ip-smart-link:hover { border-color: color-mix(in srgb, var(--admin-primary) 40%, var(--admin-border)); }
        .adm-ip-smart-desc { font-size: 0.75rem; font-weight: 700; color: var(--admin-muted); line-height: 1.7; margin-bottom: 0.75rem; }
        .adm-ip-server-field { margin-bottom: 0.75rem; }
        .adm-ip-server-field label { display: block; font-size: 0.68rem; font-weight: 800; color: var(--admin-muted); margin-bottom: 0.35rem; }
        .adm-ip-server-field select {
            width: 100%; background: var(--admin-input-bg); border: 1px solid var(--admin-border); border-radius: 0.7rem;
            color: var(--admin-text); padding: 0.6rem 0.75rem; font-size: 0.82rem; font-weight: 700;
        }
        .adm-ip-server-field select:focus { outline: none; border-color: var(--admin-primary); }
        .adm-cdn-proxy-stack { display: flex; flex-direction: column; gap: 1rem; margin-top: 1rem; }
        .adm-cdn-cf-banner {
            display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 0.75rem;
            padding: 0.85rem 1rem; border-radius: 0.85rem;
            background: color-mix(in srgb, var(--admin-primary) 10%, var(--admin-card));
            border: 1px solid color-mix(in srgb, var(--admin-primary) 28%, var(--admin-border));
        }
        .adm-cdn-cf-banner-text { font-size: 0.78rem; font-weight: 700; color: var(--admin-text); line-height: 1.7; flex: 1; min-width: 12rem; }
        .adm-cdn-cf-banner-actions { display: inline-flex; align-items: center; gap: 0.5rem; flex-shrink: 0; }
        .adm-cdn-cf-banner-close {
            display: inline-flex; align-items: center; justify-content: center; width: 1.75rem; height: 1.75rem;
            border-radius: 0.5rem; border: 0; background: transparent; color: var(--admin-muted); cursor: pointer;
        }
        .adm-cdn-cf-banner-close:hover { background: color-mix(in srgb, var(--admin-border) 50%, transparent); color: var(--admin-text); }
        .adm-cdn-access-panel { border-color: color-mix(in srgb, var(--admin-primary) 30%, var(--admin-border)); }
        .adm-cdn-finder-panel { border-color: color-mix(in srgb, var(--admin-accent) 24%, var(--admin-border)); }
        .adm-cdn-panel-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 0.5rem; margin-bottom: 0.75rem; }
        .adm-cdn-panel-title { display: inline-flex; align-items: center; gap: 0.45rem; font-size: 0.9rem; font-weight: 900; color: var(--admin-text); }
        .adm-cdn-panel-title svg { width: 1.1rem; height: 1.1rem; color: var(--admin-primary); flex-shrink: 0; }
        .adm-cdn-fields { display: grid; grid-template-columns: 1fr; gap: 0.75rem; }
        @media (min-width: 40rem) { .adm-cdn-fields.two-col { grid-template-columns: 1fr 1fr; } }
        .adm-cdn-field label { display: block; font-size: 0.68rem; font-weight: 800; color: var(--admin-muted); margin-bottom: 0.35rem; }
        .adm-cdn-field-hint { font-size: 0.68rem; font-weight: 600; color: var(--admin-muted); line-height: 1.65; margin-top: 0.35rem; }
        .adm-cdn-sec { margin-top: 0.75rem; }
        .adm-cdn-msg { margin-top: 0.65rem; font-size: 0.72rem; font-weight: 700; line-height: 1.6; min-height: 1.1rem; }
        .adm-cdn-msg.ok { color: #059669; }
        .adm-cdn-msg.bad { color: #dc2626; }
        .adm-cdn-msg.info { color: var(--admin-muted); }
        .adm-cdn-rotate-row { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: flex-end; margin-top: 0.65rem; }
        .adm-cdn-rotate-row .adm-cdn-field { flex: 1; min-width: 7rem; margin: 0; }
        .adm-cdn-rotate-row .adm-cdn-field.narrow { flex: 0 0 7rem; max-width: 7rem; }
        .adm-um-ip-btns { display: inline-flex; flex-wrap: wrap; gap: 0.35rem; }
        .adm-dash-map-zoom-btn { width: 100%; padding: 0.55rem 0.75rem; border: 0; border-top: 1px solid var(--admin-border); background: var(--admin-card); color: var(--admin-primary); font-size: 0.75rem; font-weight: 800; cursor: pointer; transition: background 0.15s ease; }
        .adm-dash-map-zoom-btn:hover { background: var(--admin-primary-soft); }
        .adm-dash-map-mode { display: flex; gap: 0.35rem; margin-bottom: 0.5rem; }
        .adm-dash-map-mode-btn { flex: 1; padding: 0.45rem 0.55rem; border-radius: 0.65rem; border: 1px solid var(--admin-border); background: var(--admin-input-bg); color: var(--admin-muted); font-size: 0.68rem; font-weight: 800; cursor: pointer; transition: 0.15s ease; }
        .adm-dash-map-mode-btn:hover { border-color: color-mix(in srgb, var(--admin-primary) 30%, var(--admin-border)); color: var(--admin-text); }
        .adm-dash-map-mode-btn.active { background: var(--admin-primary-soft); color: var(--admin-primary); border-color: color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border)); }
        .adm-dash-action-row { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.75rem; }
        .adm-dash-copy-btn { display: inline-flex; align-items: center; justify-content: center; gap: 0.45rem; padding: 0.7rem 1.1rem; border-radius: 0.75rem; background: color-mix(in srgb, var(--admin-primary) 12%, var(--admin-card)); color: var(--admin-primary); border: 1px solid color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border)); font-size: 0.78rem; font-weight: 800; cursor: pointer; transition: 0.15s ease; }
        .adm-dash-copy-btn:hover { background: color-mix(in srgb, var(--admin-primary) 18%, var(--admin-card)); }
        a.adm-nav-item { text-decoration: none; }
        .adm-dash-live-badge { display: inline-flex; align-items: center; gap: 0.35rem; font-size: 0.68rem; font-weight: 800; color: var(--admin-muted); margin-bottom: 0.75rem; }
        .adm-dash-live-dot { width: 0.45rem; height: 0.45rem; border-radius: 9999px; background: var(--admin-muted); }
        .adm-dash-req-value { font-size: 2.25rem; font-weight: 900; color: var(--admin-accent); line-height: 1; }
        .adm-dash-req-meta { font-size: 0.75rem; color: var(--admin-muted); margin-top: 0.65rem; line-height: 1.6; }
        .adm-dash-top-req { margin-top: 1rem; padding-top: 0.85rem; border-top: 1px solid color-mix(in srgb, var(--admin-border) 55%, transparent); }
        .adm-dash-top-req-title { font-size: 0.7rem; font-weight: 800; color: var(--admin-muted); text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 0.55rem; }
        .adm-dash-top-req-list { display: flex; flex-direction: column; gap: 0.45rem; }
        .adm-dash-top-req-item { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; font-size: 0.78rem; }
        .adm-dash-top-req-name { font-weight: 700; color: var(--admin-text); min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .adm-dash-top-req-val { font-weight: 800; color: var(--admin-accent); font-family: ui-monospace, monospace; flex-shrink: 0; }
        .adm-dash-top-req-empty { font-size: 0.75rem; color: var(--admin-muted); }
        .adm-dash-req-bar { width: 100%; height: 0.55rem; border-radius: 9999px; background: color-mix(in srgb, var(--admin-border) 60%, transparent); overflow: hidden; margin-top: 0.85rem; }
        .adm-dash-req-bar-fill { height: 100%; border-radius: 9999px; background: linear-gradient(90deg, var(--admin-primary), var(--admin-accent)); transition: width 0.4s ease; }
        .adm-dash-service { grid-column: 1 / -1; }
        @media (min-width: 1024px) { .adm-dash-service { grid-column: auto; } }
        .adm-dash-service-inner { display: flex; flex-direction: column; gap: 1.25rem; }
        @media (min-width: 768px) { .adm-dash-service-inner { flex-direction: row; align-items: center; justify-content: space-between; } }
        .adm-dash-sub-link { font-family: ui-monospace, monospace; font-size: 0.78rem; color: var(--admin-primary); background: var(--admin-input-bg); border: 1px solid var(--admin-border); border-radius: 0.75rem; padding: 0.75rem 0.9rem; word-break: break-all; direction: ltr; text-align: start; }
        .adm-dash-qr-wrap { display: flex; flex-direction: column; align-items: center; flex-shrink: 0; }
        .adm-dash-qr-box { width: 9.5rem; height: 9.5rem; display: flex; align-items: center; justify-content: center; background: #fff; border-radius: 0.85rem; border: 1px solid var(--admin-border); cursor: pointer; }
        .adm-dash-manage-btn { display: inline-flex; align-items: center; justify-content: center; gap: 0.45rem; padding: 0.7rem 1.1rem; border-radius: 0.75rem; background: var(--admin-primary-soft); color: var(--admin-primary); border: 1px solid color-mix(in srgb, var(--admin-primary) 35%, var(--admin-border)); font-size: 0.78rem; font-weight: 800; cursor: pointer; transition: 0.15s ease; margin-top: 0; }
        .adm-dash-manage-btn:hover { background: color-mix(in srgb, var(--admin-primary) 18%, var(--admin-card)); }
        .adm-node-card { background: var(--admin-card); border: 1px solid var(--admin-border); border-radius: 1.15rem; box-shadow: var(--admin-shadow); padding: 1.25rem; max-width: 56rem; margin: 0 auto; }
        @media (min-width: 640px) { .adm-node-card { padding: 1.5rem; } }
        .adm-node-head { display: flex; flex-wrap: wrap; align-items: flex-start; justify-content: space-between; gap: 0.85rem 1rem; margin-bottom: 1.15rem; padding-bottom: 1rem; border-bottom: 1px solid var(--admin-border); }
        .adm-node-head-main { display: flex; align-items: flex-start; gap: 0.75rem; min-width: 0; flex: 1 1 14rem; }
        .adm-node-head-icon { display: inline-flex; align-items: center; justify-content: center; width: 2.35rem; height: 2.35rem; border-radius: 0.75rem; background: var(--admin-primary-soft); color: var(--admin-primary); border: 1px solid color-mix(in srgb, var(--admin-primary) 30%, var(--admin-border)); flex-shrink: 0; }
        .adm-node-title { font-size: 0.95rem; font-weight: 900; color: var(--admin-text); line-height: 1.35; }
        .adm-node-desc { font-size: 0.72rem; font-weight: 600; color: var(--admin-muted); line-height: 1.7; margin-top: 0.3rem; max-width: 36rem; }
        .adm-node-refresh-btn { display: inline-flex; align-items: center; justify-content: center; padding: 0.5rem 0.95rem; border-radius: 0.65rem; background: var(--admin-input-bg); color: var(--admin-text); border: 1px solid var(--admin-border); font-size: 0.72rem; font-weight: 800; cursor: pointer; transition: 0.15s ease; flex-shrink: 0; }
        .adm-node-refresh-btn:hover:not(:disabled) { border-color: color-mix(in srgb, var(--admin-primary) 40%, var(--admin-border)); color: var(--admin-primary); }
        .adm-node-refresh-btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .adm-node-list { display: flex; flex-direction: column; gap: 0.65rem; }
        .adm-node-item { display: flex; flex-wrap: wrap; align-items: center; gap: 0.6rem 0.75rem; background: var(--admin-input-bg); border: 1px solid var(--admin-border); border-radius: 0.85rem; padding: 0.75rem 0.85rem; transition: border-color 0.15s ease; }
        .adm-node-item:hover { border-color: color-mix(in srgb, var(--admin-primary) 28%, var(--admin-border)); }
        .adm-node-port { display: inline-flex; align-items: center; justify-content: center; min-width: 3.4rem; padding: 0.32rem 0.6rem; border-radius: 0.55rem; background: color-mix(in srgb, var(--admin-primary) 12%, transparent); color: var(--admin-primary); border: 1px solid color-mix(in srgb, var(--admin-primary) 30%, var(--admin-border)); font-size: 0.74rem; font-weight: 900; font-family: ui-monospace, monospace; direction: ltr; flex-shrink: 0; }
        .adm-node-link { flex: 1 1 12rem; min-width: 0; font-family: ui-monospace, monospace; font-size: 0.7rem; color: var(--admin-accent); word-break: break-all; direction: ltr; text-align: start; line-height: 1.55; }
        .adm-node-actions { display: inline-flex; align-items: center; gap: 0.45rem; flex-shrink: 0; margin-inline-start: auto; }
        .adm-node-copy, .adm-node-qr { display: inline-flex; align-items: center; justify-content: center; min-width: 2.6rem; padding: 0.42rem 0.75rem; border-radius: 0.6rem; background: color-mix(in srgb, var(--admin-primary) 10%, var(--admin-card)); color: var(--admin-primary); border: 1px solid color-mix(in srgb, var(--admin-primary) 32%, var(--admin-border)); font-size: 0.68rem; font-weight: 800; cursor: pointer; transition: 0.15s ease; }
        .adm-node-copy:hover, .adm-node-qr:hover { background: color-mix(in srgb, var(--admin-primary) 18%, var(--admin-card)); box-shadow: 0 0 14px -4px var(--admin-glow); }
        .adm-node-qr { background: color-mix(in srgb, var(--admin-accent) 10%, var(--admin-card)); color: var(--admin-accent); border-color: color-mix(in srgb, var(--admin-accent) 32%, var(--admin-border)); }
        .adm-node-qr:hover { background: color-mix(in srgb, var(--admin-accent) 18%, var(--admin-card)); }
        .adm-node-loading, .adm-node-empty { text-align: center; padding: 2.5rem 1rem; font-size: 0.8rem; font-weight: 600; color: var(--admin-muted); }
        .adm-guide-layout { max-width: 52rem; margin: 0 auto; }
        .adm-guide-card { background: var(--admin-card); border: 1px solid var(--admin-border); border-radius: 1.15rem; box-shadow: var(--admin-shadow); overflow: hidden; }
        .adm-guide-toolbar { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 0.75rem; padding: 1rem 1.25rem; border-bottom: 1px solid var(--admin-border); background: var(--admin-input-bg); }
        .adm-guide-tabs { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0; }
        .adm-guide-tab { padding: 0.55rem 0.95rem; border-radius: 0.85rem; font-size: 0.76rem; font-weight: 800; background: var(--admin-card); border: 1px solid var(--admin-border); color: var(--admin-muted); transition: 0.2s ease; display: inline-flex; align-items: center; gap: 0.4rem; cursor: pointer; }
        .adm-guide-tab.active { background: linear-gradient(135deg, var(--admin-primary), var(--admin-accent)); color: #fff; border-color: transparent; box-shadow: 0 4px 14px -4px var(--admin-glow); }
        .adm-guide-body { padding: 1.1rem; }
        @media (min-width: 640px) { .adm-guide-body { padding: 1.25rem; } }
        .adm-guide-section-title { font-size: 0.82rem; font-weight: 800; margin-bottom: 0.85rem; color: var(--admin-text); display: flex; align-items: center; gap: 0.5rem; }
        .adm-guide-step { background: var(--admin-input-bg); border: 1px solid var(--admin-border); border-radius: 1rem; padding: 0.95rem 1.05rem; font-size: 0.8rem; line-height: 1.75; color: var(--admin-muted); }
        .adm-guide-step-num { min-width: 1.65rem; height: 1.65rem; display: inline-flex; align-items: center; justify-content: center; border-radius: 0.5rem; background: var(--admin-primary-soft); color: var(--admin-primary); font-size: 0.72rem; font-weight: 800; margin-left: 0.45rem; vertical-align: middle; }
        .adm-guide-link { color: var(--admin-primary); word-break: break-all; font-weight: 700; }
        .adm-guide-support { color: var(--admin-primary); font-weight: 700; }
        .adm-settings-stack { display: flex; flex-direction: column; gap: 1.25rem; max-width: 42rem; margin: 0 auto; width: 100%; }
        .adm-app .admin-toolbar, .adm-app .admin-table-wrap, .adm-app .adm-tg-card, .adm-app .adm-guide-card {
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        html.dark .adm-dash-qr-box { background: #f8fafc; }`;
        const NEXA_USERS_REDESIGN_CSS = `
    /* ── Users section — cyber glass theme ── */
    #section-users {
        --u-glass: color-mix(in srgb, var(--admin-card) 72%, transparent);
        --u-glass-border: color-mix(in srgb, var(--admin-primary) 18%, var(--admin-border));
        --u-neon: var(--admin-primary);
        --u-neon-glow: var(--admin-glow);
        --u-surface: color-mix(in srgb, var(--admin-input-bg) 55%, var(--admin-card));
    }
    html.dark #section-users {
        --u-glass: color-mix(in srgb, var(--admin-card) 55%, transparent);
        --u-glass-border: color-mix(in srgb, var(--admin-primary) 28%, var(--admin-border));
    }
    .adm-users-layout { display: flex; flex-direction: column; gap: 1.25rem; position: relative; }
    .adm-users-layout::before {
        content: ''; position: absolute; inset: -1rem; z-index: -1; pointer-events: none; opacity: 0.45;
        background:
            radial-gradient(circle at 15% 20%, color-mix(in srgb, var(--admin-primary) 14%, transparent), transparent 42%),
            radial-gradient(circle at 85% 75%, color-mix(in srgb, var(--admin-accent) 10%, transparent), transparent 38%);
    }
    .adm-users-stats { display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.75rem; }
    @media (min-width: 768px) { .adm-users-stats { grid-template-columns: repeat(4, 1fr); gap: 0.85rem; } }
    .adm-users-stat-card {
        background: var(--u-glass); backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px);
        border: 1px solid var(--u-glass-border); border-radius: 1rem;
        padding: 1rem 1.05rem; position: relative; overflow: hidden; transition: 0.28s cubic-bezier(0.4,0,0.2,1);
        display: flex; align-items: center; gap: 0.85rem;
    }
    .adm-users-stat-card::after {
        content: ''; position: absolute; bottom: 0; inset-inline: 0; height: 2px;
        background: linear-gradient(90deg, transparent, var(--u-neon), transparent); opacity: 0; transition: opacity 0.28s;
    }
    .adm-users-stat-card:hover { transform: translateY(-3px); box-shadow: 0 12px 36px -10px var(--u-neon-glow); border-color: color-mix(in srgb, var(--admin-primary) 45%, var(--admin-border)); }
    .adm-users-stat-card:hover::after { opacity: 1; }
    .adm-users-stat-icon {
        width: 2.65rem; height: 2.65rem; border-radius: 0.75rem; display: flex; align-items: center; justify-content: center; flex-shrink: 0;
        background: linear-gradient(135deg, color-mix(in srgb, var(--admin-primary) 22%, transparent), color-mix(in srgb, var(--admin-accent) 12%, transparent));
        color: var(--admin-primary); border: 1px solid color-mix(in srgb, var(--admin-primary) 25%, transparent);
        box-shadow: 0 0 20px -6px var(--u-neon-glow);
    }
    .adm-users-stat-card.info .adm-users-stat-icon { background: linear-gradient(135deg, rgba(59,130,246,0.22), rgba(99,102,241,0.1)); color: #60a5fa; border-color: rgba(59,130,246,0.3); box-shadow: 0 0 20px -6px rgba(59,130,246,0.35); }
    .adm-users-stat-card.warn .adm-users-stat-icon { background: linear-gradient(135deg, rgba(245,158,11,0.22), rgba(251,191,36,0.08)); color: #fbbf24; border-color: rgba(245,158,11,0.3); box-shadow: 0 0 20px -6px rgba(245,158,11,0.3); }
    .adm-users-stat-card.danger .adm-users-stat-icon { background: linear-gradient(135deg, rgba(239,68,68,0.22), rgba(248,113,113,0.08)); color: #f87171; border-color: rgba(239,68,68,0.3); box-shadow: 0 0 20px -6px rgba(239,68,68,0.3); }
    .adm-users-stat-icon svg { width: 1.15rem; height: 1.15rem; }
    .adm-users-stat-body { min-width: 0; flex: 1; }
    .adm-users-stat-label { font-size: 0.65rem; font-weight: 700; color: var(--admin-muted); margin-bottom: 0.3rem; letter-spacing: 0.06em; text-transform: uppercase; }
    .adm-users-stat-value {
        font-size: 1.65rem; font-weight: 900; line-height: 1; font-variant-numeric: tabular-nums;
        background: linear-gradient(135deg, var(--admin-text), color-mix(in srgb, var(--admin-primary) 55%, var(--admin-text)));
        -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
    }

    /* ── Toolbar ── */
    .adm-users-toolbar {
        background: var(--u-glass); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
        border: 1px solid var(--u-glass-border); border-radius: 1rem;
        box-shadow: 0 8px 32px -12px var(--u-neon-glow); padding: 0.85rem 1rem;
        display: flex; flex-direction: column; gap: 0.75rem;
    }
    @media (min-width: 768px) {
        .adm-users-toolbar { flex-direction: row; align-items: center; justify-content: space-between; padding: 0.9rem 1.15rem; }
    }
    .adm-users-search-wrap { position: relative; width: 100%; }
    @media (min-width: 768px) { .adm-users-search-wrap { max-width: 24rem; } }
    .adm-users-search-wrap .adm-users-search-icon {
        position: absolute; inset-block: 0; inset-inline-end: 0.9rem; display: flex; align-items: center;
        pointer-events: none; color: var(--admin-muted); transition: color 0.2s;
    }
    .adm-users-search-wrap:focus-within .adm-users-search-icon { color: var(--admin-primary); }
    .adm-users-search-wrap input {
        padding-inline-end: 2.6rem !important;
        background: var(--u-surface) !important;
        border-color: color-mix(in srgb, var(--admin-border) 80%, transparent) !important;
        transition: border-color 0.2s, box-shadow 0.2s !important;
    }
    .adm-users-search-wrap input:focus {
        border-color: color-mix(in srgb, var(--admin-primary) 55%, var(--admin-border)) !important;
        box-shadow: 0 0 0 3px color-mix(in srgb, var(--admin-primary) 12%, transparent), 0 0 24px -6px var(--u-neon-glow) !important;
    }
    .adm-users-filters { display: flex; flex-wrap: wrap; gap: 0.45rem; width: 100%; }
    @media (min-width: 768px) { .adm-users-filters { width: auto; justify-content: flex-end; } }
    .adm-users-filters select {
        min-width: 9.5rem; background: var(--u-surface) !important;
        border-color: color-mix(in srgb, var(--admin-border) 80%, transparent) !important;
        font-size: 0.75rem !important; font-weight: 700 !important;
    }

    /* ── Bulk bar ── */
    .adm-bulk-bar {
        border-radius: 0.9rem; padding: 0.85rem 1rem; margin-bottom: 0;
        background: linear-gradient(135deg, color-mix(in srgb, var(--admin-primary) 16%, var(--u-glass)), var(--u-glass));
        backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
        border: 1px solid color-mix(in srgb, var(--admin-primary) 38%, var(--admin-border));
        box-shadow: 0 0 32px -8px var(--u-neon-glow), inset 0 1px 0 color-mix(in srgb, var(--admin-primary) 15%, transparent);
    }
    .adm-bulk-btn {
        display: inline-flex; align-items: center; justify-content: center; gap: 0.3rem;
        padding: 0.48rem 0.8rem; border-radius: 0.55rem; font-size: 0.68rem; font-weight: 700;
        border: 1px solid color-mix(in srgb, var(--admin-border) 70%, transparent);
        background: color-mix(in srgb, var(--admin-card) 60%, transparent); color: var(--admin-text);
        transition: 0.2s ease; cursor: pointer; white-space: nowrap;
    }
    .adm-bulk-btn:hover { border-color: color-mix(in srgb, var(--admin-primary) 50%, var(--admin-border)); color: var(--admin-primary); box-shadow: 0 0 16px -4px var(--u-neon-glow); }
    .adm-bulk-btn.primary { background: linear-gradient(135deg, var(--admin-primary), var(--admin-accent)); color: #fff; border-color: transparent; box-shadow: 0 4px 20px -4px var(--u-neon-glow); }
    .adm-bulk-btn.primary:hover { filter: brightness(1.08); color: #fff; transform: translateY(-1px); }
    .adm-bulk-btn.success:hover { border-color: #10b981; color: #10b981; box-shadow: 0 0 16px -4px rgba(16,185,129,0.35); }
    .adm-bulk-btn.warn:hover { border-color: #f59e0b; color: #f59e0b; box-shadow: 0 0 16px -4px rgba(245,158,11,0.3); }
    .adm-bulk-btn.danger:hover { border-color: #ef4444; color: #ef4444; box-shadow: 0 0 16px -4px rgba(239,68,68,0.3); }

    /* ── Users panel & table ── */
    .adm-users-panel {
        background: var(--u-glass); backdrop-filter: blur(18px); -webkit-backdrop-filter: blur(18px);
        border: 1px solid var(--u-glass-border); border-radius: 1.1rem;
        box-shadow: 0 16px 48px -16px var(--u-neon-glow); overflow: hidden; color: var(--admin-text);
        position: relative;
    }
    .adm-users-panel::before {
        content: ''; position: absolute; top: 0; inset-inline: 0; height: 1px;
        background: linear-gradient(90deg, transparent 5%, var(--admin-primary) 50%, transparent 95%); opacity: 0.7;
    }
    .adm-users-panel-head {
        padding: 1.15rem 1.35rem; border-bottom: 1px solid color-mix(in srgb, var(--admin-border) 60%, transparent);
        display: flex; align-items: center; justify-content: space-between; gap: 0.85rem; flex-wrap: wrap;
        background: linear-gradient(180deg, color-mix(in srgb, var(--admin-primary) 6%, transparent), transparent);
    }
    .adm-users-panel-title {
        font-size: 1rem; font-weight: 900; color: var(--admin-text);
        display: flex; align-items: center; gap: 0.55rem; letter-spacing: -0.01em;
    }
    .adm-users-count-badge {
        font-size: 0.62rem; font-weight: 800; padding: 0.22rem 0.6rem; border-radius: 9999px;
        background: linear-gradient(135deg, color-mix(in srgb, var(--admin-primary) 25%, transparent), color-mix(in srgb, var(--admin-accent) 15%, transparent));
        color: var(--admin-primary); border: 1px solid color-mix(in srgb, var(--admin-primary) 35%, transparent);
        box-shadow: 0 0 12px -3px var(--u-neon-glow);
    }
    .adm-users-panel-actions { display: flex; align-items: center; gap: 0.55rem; flex-wrap: wrap; }
    .adm-users-select-all {
        display: none; align-items: center; gap: 0.45rem; font-size: 0.7rem; font-weight: 700;
        padding: 0.5rem 0.85rem; border-radius: 0.55rem;
        border: 1px solid color-mix(in srgb, var(--admin-border) 70%, transparent);
        background: var(--u-surface); color: var(--admin-muted); cursor: pointer; transition: 0.2s;
    }
    @media (min-width: 640px) { .adm-users-select-all { display: flex; } }
    .adm-users-select-all:hover { border-color: color-mix(in srgb, var(--admin-primary) 45%, var(--admin-border)); color: var(--admin-primary); }
    .adm-users-add-btn {
        display: inline-flex; align-items: center; justify-content: center; gap: 0.45rem;
        padding: 0.58rem 1.15rem; border-radius: 0.6rem; font-size: 0.74rem; font-weight: 800;
        background: linear-gradient(135deg, var(--admin-primary) 0%, var(--admin-accent) 100%);
        color: #fff; border: none; cursor: pointer; transition: 0.25s ease;
        box-shadow: 0 4px 24px -4px var(--u-neon-glow), inset 0 1px 0 rgba(255,255,255,0.15);
        position: relative; overflow: hidden;
    }
    .adm-users-add-btn::after {
        content: ''; position: absolute; inset: 0; background: linear-gradient(135deg, transparent 40%, rgba(255,255,255,0.12));
        opacity: 0; transition: opacity 0.25s;
    }
    .adm-users-add-btn:hover { filter: brightness(1.1); transform: translateY(-2px); box-shadow: 0 8px 32px -6px var(--u-neon-glow); }
    .adm-users-add-btn:hover::after { opacity: 1; }
    .adm-users-add-btn svg { width: 1.05rem; height: 1.05rem; position: relative; z-index: 1; }
    .adm-users-add-btn span { position: relative; z-index: 1; }
    .adm-users-table-wrap { overflow-x: auto; scrollbar-width: thin; }
    .adm-users-table { width: 100%; border-collapse: separate; border-spacing: 0; text-align: right; }
    .adm-users-table thead tr {
        background: color-mix(in srgb, var(--admin-primary) 4%, var(--u-surface));
        border-bottom: 1px solid color-mix(in srgb, var(--admin-border) 55%, transparent);
    }
    .adm-users-table th {
        padding: 0.75rem 1rem; font-size: 0.62rem; font-weight: 800; color: var(--admin-muted);
        text-transform: uppercase; letter-spacing: 0.08em; white-space: nowrap;
    }
    .adm-users-table td {
        padding: 0.9rem 1rem; vertical-align: middle;
        border-bottom: 1px solid color-mix(in srgb, var(--admin-border) 40%, transparent);
    }
    .adm-users-table tbody tr.admin-row:last-child td { border-bottom: none; }
    #section-users .admin-row {
        transition: background 0.2s ease, box-shadow 0.2s ease;
    }
    #section-users .admin-row:hover {
        background: color-mix(in srgb, var(--admin-primary) 5%, transparent);
        box-shadow: inset 3px 0 0 var(--admin-primary);
    }
    #section-users .admin-row.is-selected {
        background: color-mix(in srgb, var(--admin-primary) 10%, transparent);
        box-shadow: inset 3px 0 0 var(--admin-primary), 0 0 24px -12px var(--u-neon-glow);
    }
    .adm-users-loading {
        display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.85rem;
        padding: 3.5rem 1.5rem; background: var(--u-glass); border: 1px solid var(--u-glass-border);
        border-radius: 1rem; box-shadow: 0 8px 32px -12px var(--u-neon-glow);
    }
    .adm-users-loading-spinner {
        width: 2.5rem; height: 2.5rem; border: 2px solid color-mix(in srgb, var(--admin-border) 60%, transparent);
        border-top-color: var(--admin-primary); border-radius: 50%;
        animation: adm-spin 0.7s linear infinite;
        box-shadow: 0 0 20px -4px var(--u-neon-glow);
    }
    @keyframes adm-spin { to { transform: rotate(360deg); } }
    .adm-users-empty {
        padding: 3.5rem 1.5rem; text-align: center;
        display: flex; flex-direction: column; align-items: center; gap: 0.85rem;
    }
    .adm-users-empty-icon {
        width: 4rem; height: 4rem; border-radius: 1.1rem; display: flex; align-items: center; justify-content: center;
        background: linear-gradient(135deg, color-mix(in srgb, var(--admin-primary) 20%, transparent), color-mix(in srgb, var(--admin-accent) 10%, transparent));
        color: var(--admin-primary); border: 1px solid color-mix(in srgb, var(--admin-primary) 30%, transparent);
        box-shadow: 0 0 28px -6px var(--u-neon-glow);
    }
    .adm-users-empty-icon svg { width: 1.85rem; height: 1.85rem; }

    /* ── User identity ── */
    .adm-user-identity { display: flex; align-items: flex-start; gap: 0.7rem; min-width: 0; }
    .adm-user-avatar {
        width: 2.35rem; height: 2.35rem; border-radius: 0.65rem; flex-shrink: 0;
        display: flex; align-items: center; justify-content: center;
        font-size: 0.85rem; font-weight: 900; text-transform: uppercase;
        background: linear-gradient(135deg, color-mix(in srgb, var(--admin-primary) 30%, transparent), color-mix(in srgb, var(--admin-accent) 18%, transparent));
        color: var(--admin-primary); border: 1px solid color-mix(in srgb, var(--admin-primary) 35%, transparent);
        box-shadow: 0 0 16px -4px var(--u-neon-glow);
    }
    .adm-user-identity-body { min-width: 0; flex: 1; display: flex; flex-direction: column; gap: 0.45rem; }
    .adm-user-name {
        font-weight: 900; font-size: 0.86rem; color: var(--admin-text); word-break: break-all;
        font-family: ui-monospace, 'Vazirmatn', monospace; letter-spacing: -0.02em;
    }
    .adm-user-badges { display: flex; align-items: center; gap: 0.3rem; flex-wrap: wrap; }

    /* ── Badges ── */
    .adm-ub-badge {
        display: inline-flex; align-items: center; gap: 0.25rem; padding: 0.18rem 0.55rem;
        font-size: 0.58rem; font-weight: 800; border-radius: 9999px; letter-spacing: 0.03em;
        text-transform: uppercase; backdrop-filter: blur(4px);
    }
    .adm-ub-badge.success { background: color-mix(in srgb, #10b981 18%, transparent); color: #10b981; border: 1px solid color-mix(in srgb, #10b981 35%, transparent); }
    .adm-ub-badge.danger { background: color-mix(in srgb, #ef4444 15%, transparent); color: #ef4444; border: 1px solid color-mix(in srgb, #ef4444 30%, transparent); }
    .adm-ub-badge.warn { background: color-mix(in srgb, #f59e0b 15%, transparent); color: #f59e0b; border: 1px solid color-mix(in srgb, #f59e0b 30%, transparent); }
    .adm-ub-badge.info { background: color-mix(in srgb, #3b82f6 14%, transparent); color: #60a5fa; border: 1px solid color-mix(in srgb, #3b82f6 28%, transparent); }
    .adm-ub-badge.muted { background: color-mix(in srgb, var(--admin-muted) 10%, transparent); color: var(--admin-muted); border: 1px solid color-mix(in srgb, var(--admin-border) 80%, transparent); }
    .adm-ub-badge.online {
        background: linear-gradient(135deg, #10b981, #059669); color: #fff; border: none;
        box-shadow: 0 0 14px -2px rgba(16,185,129,0.55); animation: adm-pulse-online 2.5s ease-in-out infinite;
    }
    .adm-ub-badge.online::before {
        content: ''; width: 0.35rem; height: 0.35rem; border-radius: 50%; background: #fff;
        animation: adm-dot-pulse 1.5s ease-in-out infinite;
    }
    @keyframes adm-pulse-online { 0%, 100% { box-shadow: 0 0 14px -2px rgba(16,185,129,0.55); } 50% { box-shadow: 0 0 20px 0 rgba(16,185,129,0.4); } }
    @keyframes adm-dot-pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.5; transform: scale(0.7); } }

    /* ── Progress bars ── */
    .adm-up-wrap { display: flex; flex-direction: column; gap: 0.38rem; width: 100%; min-width: 8rem; }
    .adm-up-meta { display: flex; justify-content: space-between; font-size: 0.62rem; font-weight: 700; color: var(--admin-muted); gap: 0.5rem; }
    .adm-up-track {
        width: 100%; height: 0.3rem; border-radius: 9999px;
        background: color-mix(in srgb, var(--admin-progress-track) 80%, transparent);
        overflow: hidden; position: relative;
    }
    .adm-up-fill {
        height: 100%; border-radius: 9999px; transition: width 0.6s cubic-bezier(0.4,0,0.2,1);
        position: relative; overflow: hidden;
    }
    .adm-up-fill::after {
        content: ''; position: absolute; inset: 0;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.25), transparent);
        animation: adm-shimmer 2.5s ease-in-out infinite;
    }
    @keyframes adm-shimmer { 0% { transform: translateX(-100%); } 100% { transform: translateX(100%); } }
    .adm-up-fill.vol-low { background: linear-gradient(90deg, #10b981, #34d399); box-shadow: 0 0 10px -2px rgba(16,185,129,0.5); }
    .adm-up-fill.vol-mid { background: linear-gradient(90deg, #f59e0b, #fbbf24); box-shadow: 0 0 10px -2px rgba(245,158,11,0.4); }
    .adm-up-fill.vol-high { background: linear-gradient(90deg, #ef4444, #f87171); box-shadow: 0 0 10px -2px rgba(239,68,68,0.45); }
    .adm-up-fill.vol-unlimited { background: linear-gradient(90deg, var(--admin-primary), var(--admin-accent)); box-shadow: 0 0 10px -2px var(--u-neon-glow); }
    .adm-up-fill.exp-high { background: linear-gradient(90deg, #10b981, #34d399); box-shadow: 0 0 10px -2px rgba(16,185,129,0.5); }
    .adm-up-fill.exp-mid { background: linear-gradient(90deg, #f59e0b, #fbbf24); box-shadow: 0 0 10px -2px rgba(245,158,11,0.4); }
    .adm-up-fill.exp-low { background: linear-gradient(90deg, #ef4444, #f87171); box-shadow: 0 0 10px -2px rgba(239,68,68,0.45); }
    .adm-up-fill.exp-unlimited { background: linear-gradient(90deg, var(--admin-primary), var(--admin-accent)); box-shadow: 0 0 10px -2px var(--u-neon-glow); }

    /* ── Action toolbar (unified ghost buttons) ── */
    .adm-act-bar {
        display: inline-flex; align-items: center; gap: 0.2rem; flex-wrap: wrap;
        padding: 0.25rem; border-radius: 0.65rem;
        background: color-mix(in srgb, var(--u-surface) 80%, transparent);
        border: 1px solid color-mix(in srgb, var(--admin-border) 50%, transparent);
    }
    .adm-ua-btn, .adm-act-btn {
        display: inline-flex; align-items: center; justify-content: center;
        width: 1.85rem; height: 1.85rem; border-radius: 0.45rem;
        border: 1px solid transparent; background: transparent;
        color: var(--admin-muted); cursor: pointer; transition: 0.2s ease; flex-shrink: 0;
        position: relative;
    }
    .adm-ua-btn svg, .adm-act-btn svg { width: 0.9rem; height: 0.9rem; }
    .adm-ua-btn:hover, .adm-act-btn:hover { transform: translateY(-1px); color: var(--admin-text); }
    .adm-ua-btn.act-edit:hover, .adm-act-btn.act-edit:hover { background: color-mix(in srgb, #3b82f6 18%, transparent); color: #60a5fa; border-color: color-mix(in srgb, #3b82f6 30%, transparent); box-shadow: 0 0 12px -3px rgba(59,130,246,0.4); }
    .adm-ua-btn.act-toggle-on:hover, .adm-act-btn.act-toggle-on:hover { background: color-mix(in srgb, #f59e0b 18%, transparent); color: #fbbf24; border-color: color-mix(in srgb, #f59e0b 30%, transparent); box-shadow: 0 0 12px -3px rgba(245,158,11,0.35); }
    .adm-ua-btn.act-toggle-off:hover, .adm-act-btn.act-toggle-off:hover { background: color-mix(in srgb, #10b981 18%, transparent); color: #34d399; border-color: color-mix(in srgb, #10b981 30%, transparent); box-shadow: 0 0 12px -3px rgba(16,185,129,0.35); }
    .adm-ua-btn.act-reset:hover, .adm-act-btn.act-reset:hover { background: color-mix(in srgb, #f97316 16%, transparent); color: #fb923c; border-color: color-mix(in srgb, #f97316 28%, transparent); box-shadow: 0 0 12px -3px rgba(249,115,22,0.35); }
    .adm-ua-btn.act-time:hover, .adm-act-btn.act-time:hover { background: color-mix(in srgb, #06b6d4 16%, transparent); color: #22d3ee; border-color: color-mix(in srgb, #06b6d4 28%, transparent); box-shadow: 0 0 12px -3px rgba(6,182,212,0.35); }
    .adm-ua-btn.act-save:hover, .adm-act-btn.act-save:hover, .adm-ua-btn.save:hover { background: color-mix(in srgb, #8b5cf6 16%, transparent); color: #a78bfa; border-color: color-mix(in srgb, #8b5cf6 28%, transparent); box-shadow: 0 0 12px -3px rgba(139,92,246,0.35); }
    .adm-ua-btn.act-save.active, .adm-act-btn.act-save.active, .adm-ua-btn.blue { background: color-mix(in srgb, #8b5cf6 20%, transparent); color: #a78bfa; border-color: color-mix(in srgb, #8b5cf6 35%, transparent); }
    .adm-ua-btn.act-delete:hover, .adm-act-btn.act-delete:hover, .adm-ua-btn.red:hover { background: color-mix(in srgb, #ef4444 16%, transparent); color: #f87171; border-color: color-mix(in srgb, #ef4444 28%, transparent); box-shadow: 0 0 12px -3px rgba(239,68,68,0.35); }
    .adm-ua-btn.emerald, .adm-ua-btn.amber, .adm-ua-btn.orange, .adm-ua-btn.cyan, .adm-ua-btn.yellow, .adm-ua-btn.blue, .adm-ua-btn.red, .adm-ua-btn.save { background: transparent; border-color: transparent; color: var(--admin-muted); }

    /* ── Sub-link chips ── */
    .adm-sub-group { display: flex; flex-direction: column; gap: 0.4rem; min-width: 9rem; }
    .adm-sub-row { display: flex; gap: 0.35rem; }
    .adm-sub-row .adm-ul-btn { flex: 1; min-width: 0; min-height: 2.15rem; }
    .adm-ul-btn {
        display: inline-flex; align-items: center; justify-content: center; gap: 0.3rem; flex: 1;
        padding: 0.42rem 0.65rem; border-radius: 0.5rem; font-size: 0.64rem; font-weight: 700;
        border: 1px solid color-mix(in srgb, var(--admin-border) 60%, transparent);
        background: color-mix(in srgb, var(--u-surface) 70%, transparent);
        color: var(--admin-muted); cursor: pointer; transition: 0.2s ease;
    }
    .adm-ul-btn:hover { color: var(--admin-primary); border-color: color-mix(in srgb, var(--admin-primary) 40%, var(--admin-border)); background: color-mix(in srgb, var(--admin-primary) 8%, transparent); box-shadow: 0 0 14px -4px var(--u-neon-glow); }
    .adm-ul-btn.sub-main { color: var(--admin-primary); border-color: color-mix(in srgb, var(--admin-primary) 30%, var(--admin-border)); }
    .adm-ul-btn.sub-main:hover { background: color-mix(in srgb, var(--admin-primary) 14%, transparent); }
    .adm-ul-btn.icon-only { flex: 0; padding: 0.42rem 0.5rem; min-width: 2rem; }
    .adm-ul-btn.violet:hover { color: #a78bfa; border-color: color-mix(in srgb, #8b5cf6 35%, var(--admin-border)); box-shadow: 0 0 14px -4px rgba(139,92,246,0.3); }
    .adm-ul-btn.blue:hover { color: #60a5fa; border-color: color-mix(in srgb, #3b82f6 35%, var(--admin-border)); box-shadow: 0 0 14px -4px rgba(59,130,246,0.3); }
    .adm-ul-btn.violet, .adm-ul-btn.blue { background: color-mix(in srgb, var(--u-surface) 70%, transparent); color: var(--admin-muted); }

    /* ── Protocol & ports ── */
    .adm-proto-badge {
        display: inline-flex; align-items: center; gap: 0.3rem; padding: 0.3rem 0.65rem;
        font-size: 0.62rem; font-weight: 800; border-radius: 0.45rem; letter-spacing: 0.06em;
        background: linear-gradient(135deg, color-mix(in srgb, var(--admin-primary) 18%, transparent), color-mix(in srgb, var(--admin-accent) 10%, transparent));
        color: var(--admin-primary); border: 1px solid color-mix(in srgb, var(--admin-primary) 30%, transparent);
        font-family: ui-monospace, monospace;
    }
    .adm-proto-badge::before { content: ''; width: 0.35rem; height: 0.35rem; border-radius: 50%; background: var(--admin-primary); box-shadow: 0 0 6px var(--u-neon-glow); }
    .adm-port-tag {
        display: inline-block; padding: 0.15rem 0.45rem; font-size: 0.6rem; font-weight: 800;
        border-radius: 0.35rem; font-family: ui-monospace, monospace; letter-spacing: 0.02em;
    }
    .adm-port-tag.tls { background: color-mix(in srgb, #10b981 14%, transparent); color: #34d399; border: 1px solid color-mix(in srgb, #10b981 28%, transparent); }
    .adm-port-tag.nontls { background: color-mix(in srgb, #8b5cf6 14%, transparent); color: #a78bfa; border: 1px solid color-mix(in srgb, #8b5cf6 28%, transparent); }
    .adm-date-cell { font-size: 0.72rem; font-weight: 600; color: var(--admin-muted); font-variant-numeric: tabular-nums; white-space: nowrap; font-family: ui-monospace, monospace; }
    .adm-plain-val { font-family: inherit; font-size: 0.78rem; font-weight: 600; color: var(--admin-text); line-height: 1.5; }

    /* ── Mobile user cards ── */
    .adm-user-cards { display: grid; grid-template-columns: 1fr; gap: 0.75rem; padding: 0.85rem; }
    @media (min-width: 640px) { .adm-user-cards { grid-template-columns: repeat(2, minmax(0, 1fr)); padding: 1rem; } }
    @media (min-width: 1024px) { .adm-user-cards { display: none !important; } }
    .adm-user-card {
        border-radius: 0.9rem; padding: 1rem; display: flex; flex-direction: column; gap: 0.75rem;
        background: var(--u-glass); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
        border: 1px solid var(--u-glass-border); color: var(--admin-text); transition: 0.25s ease;
        position: relative; overflow: hidden;
    }
    .adm-user-card::before {
        content: ''; position: absolute; top: 0; inset-inline: 0; height: 2px;
        background: linear-gradient(90deg, transparent, var(--admin-primary), transparent); opacity: 0; transition: opacity 0.25s;
    }
    .adm-user-card:hover { border-color: color-mix(in srgb, var(--admin-primary) 40%, var(--admin-border)); box-shadow: 0 8px 32px -10px var(--u-neon-glow); transform: translateY(-2px); }
    .adm-user-card:hover::before { opacity: 0.8; }
    #section-users .adm-user-card.is-selected {
        border-color: color-mix(in srgb, var(--admin-primary) 55%, var(--admin-border));
        box-shadow: 0 0 0 1px color-mix(in srgb, var(--admin-primary) 25%, transparent), 0 8px 32px -10px var(--u-neon-glow);
        background: color-mix(in srgb, var(--admin-primary) 6%, var(--u-glass));
    }
    .adm-user-card-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 0.5rem; }
    .adm-user-card-name { font-weight: 900; font-size: 0.9rem; color: var(--admin-text); word-break: break-all; font-family: ui-monospace, monospace; }
    .adm-user-card-meta { display: flex; gap: 0.6rem; align-items: stretch; }
.adm-meta-col { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 0.6rem; }
    .adm-user-card-actions {
        display: flex; flex-wrap: wrap; gap: 0.35rem; padding-top: 0.5rem;
        border-top: 1px solid color-mix(in srgb, var(--admin-border) 50%, transparent);
    }
    
    .adm-user-card-actions .adm-act-bar {
        display: flex;
        flex-wrap: wrap;
        width: 100%;
        justify-content: flex-start;
    }

    /* ── User modal ── */
    .adm-um-overlay {
        position: fixed; inset: 0; z-index: 50; display: flex; align-items: center; justify-content: center;
        padding: 1rem; background: rgba(0,0,0,0.55); backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);
        opacity: 0; pointer-events: none; transition: opacity 0.25s ease;
    }
    .adm-um-overlay.open { opacity: 1; pointer-events: auto; }
    .adm-um-dialog {
        width: 100%; max-width: 32rem; max-height: 90vh; display: flex; flex-direction: column;
        background: var(--admin-card); border: 1px solid var(--admin-border); border-radius: 1.35rem;
        box-shadow: 0 24px 64px -16px rgba(0,0,0,0.35), 0 0 0 1px color-mix(in srgb, var(--admin-primary) 8%, transparent);
        overflow: hidden; opacity: 0; transform: scale(0.96) translateY(8px);
        transition: opacity 0.25s ease, transform 0.25s ease;
    }
    .adm-um-overlay.open .adm-um-dialog { opacity: 1; transform: scale(1) translateY(0); }
    .adm-um-header {
        position: relative; padding: 1.25rem 1.35rem 1.1rem; border-bottom: 1px solid var(--admin-border);
        background: linear-gradient(135deg, color-mix(in srgb, var(--admin-primary) 14%, var(--admin-card)), var(--admin-card));
        display: flex; align-items: flex-start; justify-content: space-between; gap: 0.75rem;
    }
    .adm-um-header::before {
        content: ''; position: absolute; inset-inline: 0; top: 0; height: 3px;
        background: linear-gradient(90deg, var(--admin-primary), var(--admin-accent), transparent);
    }
    .adm-um-header-start { display: flex; align-items: flex-start; gap: 0.85rem; min-width: 0; }
    .adm-um-header-icon {
        width: 2.75rem; height: 2.75rem; border-radius: 0.85rem; flex-shrink: 0;
        display: flex; align-items: center; justify-content: center;
        background: linear-gradient(135deg, var(--admin-primary), var(--admin-accent)); color: #fff;
        box-shadow: 0 4px 14px -4px var(--admin-glow);
    }
    .adm-um-header-icon svg { width: 1.35rem; height: 1.35rem; }
    .adm-um-title { font-size: 1rem; font-weight: 900; color: var(--admin-text); line-height: 1.3; }
    .adm-um-subtitle { font-size: 0.72rem; color: var(--admin-muted); margin-top: 0.2rem; font-weight: 600; }
    .adm-um-close {
        width: 2rem; height: 2rem; border-radius: 0.55rem; border: 1px solid var(--admin-border);
        background: var(--admin-card); color: var(--admin-muted); display: flex; align-items: center; justify-content: center;
        cursor: pointer; transition: 0.15s; flex-shrink: 0;
    }
    .adm-um-close:hover { background: rgba(239,68,68,0.08); border-color: rgba(239,68,68,0.25); color: #dc2626; }
    .adm-um-form { display: flex; flex-direction: column; flex: 1; min-height: 0; overflow: hidden; }
    .adm-um-body { padding: 1.15rem 1.35rem; overflow-y: auto; flex: 1; overscroll-behavior: contain; display: flex; flex-direction: column; gap: 1.1rem; }
    .adm-um-section {
        background: color-mix(in srgb, var(--admin-input-bg) 60%, var(--admin-card));
        border: 1px solid var(--admin-border); border-radius: 1rem; padding: 1rem; display: flex; flex-direction: column; gap: 0.85rem;
    }
    .adm-um-section-head {
        display: flex; align-items: center; gap: 0.5rem; font-size: 0.72rem; font-weight: 900;
        color: var(--admin-primary); text-transform: uppercase; letter-spacing: 0.05em;
        padding-bottom: 0.5rem; border-bottom: 1px solid color-mix(in srgb, var(--admin-border) 80%, transparent);
    }
    .adm-um-section-head svg { width: 0.95rem; height: 0.95rem; opacity: 0.85; }
    .adm-um-field label {
        display: block; font-size: 0.68rem; font-weight: 800; color: var(--admin-muted);
        margin-bottom: 0.4rem; letter-spacing: 0.03em;
    }
    .adm-um-field input, .adm-um-field select, .adm-um-field textarea {
        width: 100%; padding: 0.6rem 0.85rem; font-size: 0.82rem; font-weight: 600;
        background: var(--admin-card); border: 1px solid var(--admin-border); border-radius: 0.75rem;
        color: var(--admin-text); transition: border-color 0.15s, box-shadow 0.15s;
    }
    .adm-um-field input:focus, .adm-um-field select:focus, .adm-um-field textarea:focus {
        outline: none; border-color: color-mix(in srgb, var(--admin-primary) 50%, var(--admin-border));
        box-shadow: 0 0 0 3px var(--admin-primary-soft);
    }
    .adm-um-field textarea { font-family: ui-monospace, monospace; font-size: 0.75rem; resize: vertical; }
    .adm-um-field .adm-um-hint { font-size: 0.62rem; color: var(--admin-muted); margin-top: 0.35rem; line-height: 1.5; }
    .adm-um-grid-3 { display: grid; grid-template-columns: 1fr; gap: 0.75rem; }
    @media (min-width: 480px) { .adm-um-grid-3 { grid-template-columns: repeat(2, 1fr); } }
    @media (min-width: 768px) { .adm-um-grid-3 { grid-template-columns: repeat(4, 1fr); } }
    .adm-um-ports-group {
        background: var(--admin-card); border: 1px solid var(--admin-border); border-radius: 0.85rem; padding: 0.85rem;
    }
    .adm-um-ports-label {
        display: flex; align-items: center; gap: 0.4rem; font-size: 0.7rem; font-weight: 800; margin-bottom: 0.65rem;
    }
    .adm-um-ports-label .dot { width: 0.45rem; height: 0.45rem; border-radius: 50%; }
    .adm-um-ports-label.tls { color: #059669; }
    .adm-um-ports-label.tls .dot { background: #10b981; }
    .adm-um-ports-label.nontls { color: #7c3aed; }
    .adm-um-ports-label.nontls .dot { background: #8b5cf6; }
    .adm-um-ip-btn {
        display: inline-flex; align-items: center; gap: 0.25rem; padding: 0.3rem 0.6rem;
        font-size: 0.65rem; font-weight: 800; border-radius: 0.5rem; cursor: pointer; transition: 0.15s;
        background: var(--admin-primary-soft); color: var(--admin-primary); border: 1px solid color-mix(in srgb, var(--admin-primary) 30%, transparent);
    }
    .adm-um-ip-btn:hover { background: color-mix(in srgb, var(--admin-primary) 18%, var(--admin-card)); }
    .adm-um-footer {
        padding: 1rem 1.35rem; border-top: 1px solid var(--admin-border);
        background: color-mix(in srgb, var(--admin-input-bg) 50%, var(--admin-card));
        display: flex; gap: 0.65rem;
    }
    .adm-um-btn-cancel {
        flex: 1; padding: 0.7rem 1rem; border-radius: 0.8rem; font-size: 0.8rem; font-weight: 800;
        background: var(--admin-input-bg); border: 1px solid var(--admin-border); color: var(--admin-muted);
        cursor: pointer; transition: 0.15s;
    }
    .adm-um-btn-cancel:hover { background: var(--admin-card); color: var(--admin-text); border-color: color-mix(in srgb, var(--admin-muted) 40%, var(--admin-border)); }
    .adm-um-btn-submit {
        flex: 1; padding: 0.7rem 1rem; border-radius: 0.8rem; font-size: 0.8rem; font-weight: 800;
        background: linear-gradient(135deg, var(--admin-primary), var(--admin-accent)); color: #fff;
        border: none; cursor: pointer; transition: 0.2s; box-shadow: 0 4px 16px -4px var(--admin-glow);
    }
    .adm-um-btn-submit:hover { filter: brightness(1.06); transform: translateY(-1px); }
    .adm-um-btn-submit:disabled { opacity: 0.6; cursor: wait; transform: none; }
    .adm-um-field .num-stepper-input { padding-inline-end: 2.5rem !important; padding-inline-start: 0.75rem !important; }
    .adm-um-sys-notice {
        display: flex; align-items: flex-start; gap: 0.6rem; padding: 0.75rem 0.9rem;
        background: color-mix(in srgb, var(--admin-primary) 10%, var(--admin-card));
        border: 1px solid color-mix(in srgb, var(--admin-primary) 28%, var(--admin-border));
        border-radius: 0.75rem; font-size: 0.72rem; color: var(--admin-muted); line-height: 1.6;
    }
    .adm-um-sys-notice svg { width: 1.1rem; height: 1.1rem; flex-shrink: 0; color: var(--admin-primary); margin-top: 0.1rem; }
    .adm-um-sys-notice strong { color: var(--admin-primary); font-weight: 900; }
` + NEXA_ANNOUNCE_BANNER_CSS;
function buildSetupStatusRow(label, connected, detail, labelKey, detailKey) {
  const statusClass = connected
    ? 'setup-row-ok'
    : 'setup-row-err';
  const dotClass = connected ? 'bg-emerald-500' : 'bg-red-500';
  const labelAttr = labelKey ? ` data-i18n="${labelKey}"` : '';
  const detailAttr = detailKey ? ` data-i18n="${detailKey}"` : '';
  const detailHtml = detail
    ? `<div class="text-xs mt-1 opacity-80 font-mono break-all setup-row-detail"${detailAttr}>${detail}</div>`
    : '';
  return `<div class="flex items-start gap-3 p-3 rounded-xl border setup-status-row ${statusClass}">
    <span class="w-2.5 h-2.5 rounded-full ${dotClass} mt-1.5 shrink-0"></span>
    <div class="flex-1 min-w-0">
      <div class="flex items-center justify-between gap-2">
        <span class="text-sm font-bold"${labelAttr}>${label}</span>
        <span class="text-xs font-bold setup-status-badge" data-i18n="${connected ? 'status_connected' : 'status_disconnected'}">${connected ? 'متصل' : 'متصل نیست'}</span>
      </div>
      ${detailHtml}
    </div>
  </div>`;
}
function buildSetupI18n(status) {
  const d1LabelFa = status.d1_database_name
    ? `D1: ${status.d1_database_name}`
    : `D1 Database (binding: ${status.d1_binding_name})`;
  const d1OkFa = status.d1_database_name
    ? `نام دیتابیس: ${status.d1_database_name}${status.d1_database_id ? '\nایدی دیتابیس: ' + status.d1_database_id : ''}`
    : `binding: ${status.d1_binding_name}${status.d1_database_id ? '\nایدی دیتابیس: ' + status.d1_database_id : ''}`;
  const d1OkEn = status.d1_database_name
    ? `Database: ${status.d1_database_name}${status.d1_database_id ? '\nDatabase ID: ' + status.d1_database_id : ''}`
    : `binding: ${status.d1_binding_name}${status.d1_database_id ? '\nDatabase ID: ' + status.d1_database_id : ''}`;
  const adminErrFa = status.admin_legacy_d1
    ? 'رمز قدیمی در D1 — متغیر ADMIN (Text) را در ورکر تنظیم کنید'
    : 'رمز عبور هنوز تنظیم نشده';
  const adminErrEn = status.admin_legacy_d1
    ? 'Legacy password in D1 — set ADMIN (Text) in Worker'
    : 'Password not set yet';
  return {
    fa: {
      page_title: 'راه‌اندازی اولیه — Nexa Panel',
      setup_title: 'راه‌اندازی اولیه Nexa Panel',
      setup_subtitle: 'وضعیت اتصالات را بررسی کنید و رمز عبور پنل را تنظیم نمایید.',
      status_connected: 'متصل',
      status_disconnected: 'متصل نیست',
      d1_label: d1LabelFa,
      d1_ok: d1OkFa,
      d1_err: status.d1_error || 'اتصال D1 برقرار نیست',
      admin_label: 'ADMIN (Text)',
      admin_ok: 'رمز عبور تنظیم شده',
      admin_err: adminErrFa,
      cf_token_label: 'CF_TOKEN',
      cf_token_ok: 'متغیر محیطی تنظیم شده',
      cf_token_err: 'متغیر CF_TOKEN یافت نشد',
      cf_ac_id_label: 'CF_AC_ID',
      cf_ac_id_ok: 'خودکار از توکن دریافت شد',
      cf_ac_id_err: 'Account ID از توکن یافت نشد — CF_TOKEN را بررسی کنید',
      pwd_label: 'رمز عبور پنل',
      pwd_placeholder: 'رمز عبور را وارد کنید',
      pwd_confirm_label: 'تکرار رمز عبور',
      pwd_confirm_placeholder: 'رمز عبور را دوباره وارد کنید',
      pwd_submit: 'تنظیم رمز عبور',
      pwd_saving: 'در حال ذخیره...',
      pwd_mismatch: 'رمز عبور و تکرار آن یکسان نیستند',
      pwd_minlength: 'رمز عبور باید حداقل ۴ کاراکتر باشد',
      pwd_required: 'لطفاً رمز عبور را وارد کنید',
      pwd_error: 'خطا در تنظیم رمز عبور',
      pwd_success: 'رمز عبور با موفقیت تنظیم شد. در حال ورود به پنل...',
      enter_success: 'در حال ورود به پنل...',
      server_error: 'خطا در ارتباط با سرور',
      admin_change_title: 'یک رمز عبور برای ورود به پنل وارد کنید',
      admin_change_desc: 'رمز عبور در متغیر ADMIN (نوع Text) در Cloudflare Workers ذخیره می‌شود.',
      admin_change_path: 'برای تغییر رمز، از بخش تنظیمات پنل استفاده کنید.',
      admin_text_note: 'نوع متغیر ADMIN باید Text باشد.',
      admin_set_title: 'تنظیم رمز عبور پنل',
      admin_set_desc: 'برای اولین بار، رمز عبور را در فرم زیر وارد کنید. پس از تنظیم همه موارد، می‌توانید وارد پنل شوید.',
      admin_set_alt: 'همچنین می‌توانید متغیر ADMIN را مستقیماً در Cloudflare Workers تنظیم کنید (نوع Text).',
      admin_cf_required: 'ابتدا متغیر CF_TOKEN را در ورکر تنظیم کنید.',
      setup_missing_vars: 'برای ورود به پنل، D1 باید متصل باشد و متغیرهای ADMIN و CF_TOKEN تنظیم شده باشند.',
      enter_panel: 'ورود به پنل',
      setup_cf_token_title: 'به‌روزرسانی توکن Cloudflare',
      setup_cf_token_invalid_msg: 'توکن CF_TOKEN معتبر نیست یا منقضی شده. توکن API جدید کلودفلر را وارد و ذخیره کنید.',
      setup_cf_token_placeholder: 'Cloudflare API Token',
      setup_cf_token_submit: 'ذخیره توکن',
      setup_cf_token_saving: 'در حال ذخیره...',
      setup_cf_token_success: 'توکن با موفقیت ذخیره شد. در حال بازگشت به پنل...',
      setup_cf_token_error: 'خطا در ذخیره توکن',
      setup_cf_token_required: 'توکن API کلودفلر را وارد کنید',
      setup_back_panel: 'بازگشت به پنل'
    },
    en: {
      page_title: 'Initial Setup — Nexa Panel',
      setup_title: 'Nexa Panel Initial Setup',
      setup_subtitle: 'Check connection status and set the panel password.',
      status_connected: 'Connected',
      status_disconnected: 'Not connected',
      d1_label: d1LabelFa,
      d1_ok: d1OkEn,
      d1_err: status.d1_error || 'D1 connection is not available',
      admin_label: 'ADMIN (Text)',
      admin_ok: 'Password configured',
      admin_err: adminErrEn,
      cf_token_label: 'CF_TOKEN',
      cf_token_ok: 'Environment variable configured',
      cf_token_err: 'CF_TOKEN variable not found',
      cf_ac_id_label: 'CF_AC_ID',
      cf_ac_id_ok: 'Auto-detected from token',
      cf_ac_id_err: 'Account ID not found from token — check CF_TOKEN',
      pwd_label: 'Panel password',
      pwd_placeholder: 'Enter password',
      pwd_confirm_label: 'Confirm password',
      pwd_confirm_placeholder: 'Re-enter password',
      pwd_submit: 'Set password',
      pwd_saving: 'Saving...',
      pwd_mismatch: 'Passwords do not match',
      pwd_minlength: 'Password must be at least 4 characters',
      pwd_required: 'Please enter a password',
      pwd_error: 'Failed to set password',
      pwd_success: 'Password set successfully. Entering panel...',
      enter_success: 'Entering panel...',
      server_error: 'Server connection error',
      admin_change_title: 'Enter a password to log in to the panel',
      admin_change_desc: 'Password is stored in the ADMIN variable (Text type) in Cloudflare Workers.',
      admin_change_path: 'To change your password, use the panel settings section.',
      admin_text_note: 'ADMIN variable type must be Text.',
      admin_set_title: 'Set panel password',
      admin_set_desc: 'Enter your password below for the first time. Once everything is configured, you can enter the panel.',
      admin_set_alt: 'You can also set the ADMIN variable directly in Cloudflare Workers (type Text).',
      admin_cf_required: 'Configure CF_TOKEN in your Worker first.',
      setup_missing_vars: 'To enter the panel, D1 must be connected and ADMIN and CF_TOKEN must be configured.',
      enter_panel: 'Enter panel',
      setup_cf_token_title: 'Update Cloudflare Token',
      setup_cf_token_invalid_msg: 'CF_TOKEN is invalid or expired. Enter and save a new Cloudflare API token.',
      setup_cf_token_placeholder: 'Cloudflare API Token',
      setup_cf_token_submit: 'Save token',
      setup_cf_token_saving: 'Saving...',
      setup_cf_token_success: 'Token saved successfully. Returning to panel...',
      setup_cf_token_error: 'Failed to save token',
      setup_cf_token_required: 'Enter Cloudflare API Token',
      setup_back_panel: 'Back to panel'
    }
  };
}
function buildSetupHtml(status, options) {
  options = options || {};
  const cfTokenMode = !!options.cfTokenMode;
  const setupI18n = buildSetupI18n(status);
  const dbName = status.d1_database_name || null;
  const d1Label = dbName
    ? `D1: ${dbName}`
    : `D1 Database (binding: ${status.d1_binding_name})`;
  const d1Detail = status.d1_connected
    ? (dbName
      ? `نام دیتابیس: ${dbName}${status.d1_database_id ? '\nایدی دیتابیس: ' + status.d1_database_id : ''}`
      : `binding: ${status.d1_binding_name}${status.d1_database_id ? '\nایدی دیتابیس: ' + status.d1_database_id : ''}`)
    : (status.d1_error || 'اتصال D1 برقرار نیست');
  const hasAdmin = status.admin_from_env;
  const statusRows = [
    buildSetupStatusRow(d1Label, status.d1_connected, d1Detail, 'd1_label', status.d1_connected ? 'd1_ok' : 'd1_err'),
    buildSetupStatusRow('ADMIN (Text)', hasAdmin, hasAdmin ? 'رمز عبور تنظیم شده' : (status.admin_legacy_d1 ? 'رمز قدیمی در D1 یافت شد — متغیر ADMIN (Text) را در ورکر تنظیم کنید' : 'رمز عبور هنوز تنظیم نشده'), 'admin_label', hasAdmin ? 'admin_ok' : 'admin_err'),
    buildSetupStatusRow('CF_TOKEN', cfTokenMode ? false : status.cf_api_token, cfTokenMode ? 'توکن معتبر نیست — توکن جدید وارد کنید' : (status.cf_api_token ? 'متغیر محیطی تنظیم شده' : 'متغیر CF_TOKEN یافت نشد'), 'cf_token_label', cfTokenMode ? 'setup_cf_token_invalid_msg' : (status.cf_api_token ? 'cf_token_ok' : 'cf_token_err')),
    buildSetupStatusRow('CF_AC_ID', status.cf_account_id, status.cf_account_id ? (status.cf_account_id_auto ? 'خودکار از توکن دریافت شد' : 'متغیر محیطی تنظیم شده') + (status.cf_account_id_value ? '\n' + status.cf_account_id_value : '') : 'Account ID از توکن یافت نشد — CF_TOKEN را بررسی کنید', 'cf_ac_id_label', status.cf_account_id ? 'cf_ac_id_ok' : 'cf_ac_id_err')
  ].join('');
  const canProceed = status.setup_ready;
  const canSetPassword = !hasAdmin && status.d1_connected && status.cf_api_token;
  const legacyAdminHint = !hasAdmin && status.admin_legacy_d1 ? '<p class="text-sm setup-warn rounded-xl p-3 mb-4">رمز عبور قدیمی در دیتابیس D1 ذخیره شده بود. برای ادامه، متغیر <code class="setup-code px-1 py-0.5 rounded font-mono">ADMIN</code> (نوع Text) را در فرم زیر یا در Cloudflare Workers تنظیم کنید.</p>' : '';
  const passwordForm = canSetPassword ? `
        <form id="setup-form" class="space-y-3 mb-5" novalidate>
            <div>
                <label for="setup-password" class="block text-sm font-bold setup-label mb-1" data-i18n="pwd_label">رمز عبور پنل</label>
                <input type="password" id="setup-password" required minlength="4" autocomplete="new-password"
                    class="setup-input w-full px-4 py-2.5 border rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-teal-500/30 focus:border-teal-500"
                    data-i18n-placeholder="pwd_placeholder" placeholder="رمز عبور را وارد کنید">
            </div>
            <div>
                <label for="setup-password-confirm" class="block text-sm font-bold setup-label mb-1" data-i18n="pwd_confirm_label">تکرار رمز عبور</label>
                <input type="password" id="setup-password-confirm" required minlength="4" autocomplete="new-password"
                    class="setup-input w-full px-4 py-2.5 border rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-teal-500/30 focus:border-teal-500"
                    data-i18n-placeholder="pwd_confirm_placeholder" placeholder="رمز عبور را دوباره وارد کنید">
            </div>
            <p id="setup-error" class="hidden" aria-hidden="true"></p>
            <button type="submit" id="setup-submit" class="setup-submit w-full py-3 font-bold rounded-xl text-sm transition shadow-md" data-i18n="pwd_submit">
                تنظیم رمز عبور
            </button>
        </form>` : '';
  const adminInfo = cfTokenMode ? '' : (hasAdmin && status.admin_from_env ? `
        <div class="setup-info setup-info-ok p-4 rounded-xl text-sm leading-relaxed mb-5">
            <p class="font-bold mb-2" data-i18n="admin_change_title">یک رمز عبور برای ورود به پنل وارد کنید</p>
            <p data-i18n="admin_change_desc">رمز عبور در متغیر <code class="setup-code px-1.5 py-0.5 rounded font-mono text-xs">ADMIN</code> (نوع Text) در Cloudflare Workers ذخیره می‌شود.</p>
            <p class="mt-2" data-i18n="admin_change_path">برای تغییر رمز، از بخش تنظیمات پنل استفاده کنید.</p>
            <p class="mt-2 text-xs opacity-80" data-i18n="admin_text_note">نوع متغیر ADMIN باید <strong>Text</strong> باشد.</p>
        </div>` : (!hasAdmin ? `
        <div class="setup-info setup-info-hint p-4 rounded-xl text-sm leading-relaxed mb-5">
            <p class="font-bold mb-2" data-i18n="admin_set_title">تنظیم رمز عبور پنل</p>
            <p data-i18n="admin_set_desc">برای اولین بار، رمز عبور را در فرم زیر وارد کنید. پس از تنظیم همه موارد، می‌توانید وارد پنل شوید.</p>
            <p class="mt-2 text-xs opacity-80" data-i18n="admin_set_alt">همچنین می‌توانید متغیر <code class="setup-code px-1 py-0.5 rounded font-mono">ADMIN</code> را مستقیماً در Cloudflare Workers تنظیم کنید (نوع <strong>Text</strong>).</p>
            ${!status.cf_api_token ? '<p class="mt-2 text-xs setup-warn" data-i18n="admin_cf_required">ابتدا متغیر CF_TOKEN را در ورکر تنظیم کنید.</p>' : ''}
        </div>` : ''));
  const missingVarsMsg = !canProceed && !passwordForm && !cfTokenMode
    ? '<p class="text-sm setup-error rounded-xl p-3 mb-4" data-i18n="setup_missing_vars">برای ورود به پنل، D1 باید متصل باشد و متغیرهای ADMIN و CF_TOKEN تنظیم شده باشند.</p>'
    : '';
  const cfTokenForm = cfTokenMode ? `
        <div class="setup-info setup-info-hint p-4 rounded-xl text-sm leading-relaxed mb-5">
            <p class="font-bold mb-2" data-i18n="setup_cf_token_title">به‌روزرسانی توکن Cloudflare</p>
            <p data-i18n="setup_cf_token_invalid_msg">توکن CF_TOKEN معتبر نیست یا منقضی شده. توکن API جدید کلودفلر را وارد و ذخیره کنید.</p>
        </div>
        <form id="setup-cf-form" class="space-y-3 mb-5" novalidate>
            <div>
                <label for="setup-cf-token" class="block text-sm font-bold setup-label mb-1" data-i18n="cf_token_label">CF_TOKEN</label>
                <input type="password" id="setup-cf-token" required dir="ltr" autocomplete="off"
                    class="setup-input w-full px-4 py-2.5 border rounded-xl text-sm font-mono focus:outline-none focus:ring-2 focus:ring-teal-500/30 focus:border-teal-500"
                    data-i18n-placeholder="setup_cf_token_placeholder" placeholder="Cloudflare API Token">
            </div>
            <p id="setup-cf-error" class="hidden setup-error rounded-xl p-3 text-sm" aria-hidden="true"></p>
            <button type="submit" id="setup-cf-submit" class="setup-submit w-full py-3 font-bold rounded-xl text-sm transition shadow-md" data-i18n="setup_cf_token_submit">
                ذخیره توکن
            </button>
        </form>` : '';
  const panelEntryBlock = cfTokenMode
    ? '<a href="/admin" class="setup-enter-btn block w-full py-3 font-bold rounded-xl text-sm transition text-center" data-i18n="setup_back_panel">بازگشت به پنل</a>'
    : (canProceed
      ? '<a href="/admin" class="setup-enter-btn block w-full py-3 font-bold rounded-xl text-sm transition text-center" data-i18n="enter_panel">ورود به پنل</a>'
      : '<button type="button" disabled class="setup-enter-disabled w-full py-3 font-bold rounded-xl text-sm" data-i18n="enter_panel">ورود به پنل</button>');
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    ${NEXA_THEME_COLOR_SETUP}
    ${NEXA_FAVICON_TAGS}
    ${NEXA_THEME_COLOR_SYNC_SCRIPT}
    <title data-i18n="page_title">راه‌اندازی اولیه — Nexa Panel</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>tailwind.config = { darkMode: 'class', theme: { extend: { fontFamily: { sans: ['Vazirmatn', 'sans-serif'] } } } }</script>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <style>
        body { font-family: 'Vazirmatn', sans-serif; }
        .setup-bg {
            background: linear-gradient(145deg, #f8fafc 0%, #ffffff 45%, #ecfdf5 100%);
            transition: background 0.3s, color 0.3s;
        }
        html.dark .setup-bg {
            background: linear-gradient(145deg, #0c1210 0%, #111916 45%, #0f1512 100%);
        }
        .setup-card {
            background: rgba(255,255,255,0.95);
            border: 1px solid rgba(63,181,58,0.12);
            box-shadow: 0 24px 60px rgba(30,138,46,0.1);
        }
        html.dark .setup-card {
            background: rgba(20,28,24,0.92);
            border-color: rgba(63,181,58,0.22);
            box-shadow: 0 24px 60px rgba(0,0,0,0.45);
        }
        .setup-tool-btn {
            display: inline-flex; align-items: center; justify-content: center;
            width: 2.5rem; height: 2.5rem; border-radius: 0.85rem;
            border: 1px solid rgba(63,181,58,0.18);
            background: rgba(255,255,255,0.75); color: #475569; transition: all 0.2s;
        }
        html.dark .setup-tool-btn {
            background: rgba(30,40,35,0.85);
            border-color: rgba(63,181,58,0.25); color: #94a3b8;
        }
        .setup-tool-btn:hover { border-color: rgba(63,181,58,0.45); transform: translateY(-1px); }
        .setup-lang-switch {
            display: inline-flex; padding: 0.2rem; border-radius: 0.85rem;
            border: 1px solid rgba(63,181,58,0.18); background: rgba(255,255,255,0.75);
        }
        html.dark .setup-lang-switch {
            background: rgba(30,40,35,0.85); border-color: rgba(63,181,58,0.25);
        }
        .setup-lang-btn {
            min-width: 2.4rem; padding: 0.35rem 0.55rem; border-radius: 0.65rem;
            font-size: 0.72rem; font-weight: 800; color: #64748b; transition: all 0.2s;
        }
        .setup-lang-btn.active {
            background: linear-gradient(135deg, #3FB53A, #1E8A2E);
            color: #fff; box-shadow: 0 4px 14px rgba(30,138,46,0.35);
        }
        .setup-row-detail { white-space: pre-line; }
        .setup-row-ok { background: #ecfdf5; border-color: #a7f3d0; color: #065f46; }
        html.dark .setup-row-ok { background: rgba(16,185,129,0.12); border-color: rgba(16,185,129,0.3); color: #6ee7b7; }
        .setup-row-err { background: #fef2f2; border-color: #fecaca; color: #991b1b; }
        html.dark .setup-row-err { background: rgba(239,68,68,0.1); border-color: rgba(239,68,68,0.28); color: #fca5a5; }
        .setup-label { color: #374151; }
        html.dark .setup-label { color: #d1d5db; }
        .setup-input {
            border-color: #e5e7eb; background: #f9fafb; color: #111827;
        }
        html.dark .setup-input {
            border-color: #2d3b34; background: #1a2420; color: #e2e8f0;
        }
        .setup-error { color: #dc2626; background: #fef2f2; border: 1px solid #fecaca; }
        html.dark .setup-error { color: #fca5a5; background: rgba(239,68,68,0.1); border-color: rgba(239,68,68,0.28); }
        .setup-submit {
            background: linear-gradient(135deg, #0d9488, #0f766e); color: #fff;
            box-shadow: 0 10px 28px rgba(15,118,110,0.3);
        }
        .setup-submit:hover:not(:disabled) { filter: brightness(1.06); }
        .setup-submit:disabled { opacity: 0.65; cursor: wait; }
        .setup-info-ok { background: #ecfdf5; border: 1px solid #a7f3d0; color: #065f46; }
        html.dark .setup-info-ok { background: rgba(16,185,129,0.1); border-color: rgba(16,185,129,0.28); color: #6ee7b7; }
        .setup-info-hint { background: #f0fdfa; border: 1px solid #99f6e4; color: #134e4a; }
        html.dark .setup-info-hint { background: rgba(20,184,166,0.1); border-color: rgba(20,184,166,0.28); color: #5eead4; }
        .setup-code { background: rgba(255,255,255,0.7); }
        html.dark .setup-code { background: rgba(0,0,0,0.25); }
        .setup-warn { color: #b45309; }
        html.dark .setup-warn { color: #fbbf24; }
        .setup-enter-btn {
            background: linear-gradient(135deg, #0d9488, #0f766e); color: #fff;
            box-shadow: 0 10px 28px rgba(15,118,110,0.3);
        }
        .setup-enter-btn:hover { filter: brightness(1.06); }
        .setup-enter-disabled { background: #e5e7eb; color: #9ca3af; cursor: not-allowed; }
        html.dark .setup-enter-disabled { background: #1f2937; color: #6b7280; }
        .setup-divider { border-color: #f3f4f6; }
        html.dark .setup-divider { border-color: #1f2937; }
        ${NEXA_TOAST_CSS}
        #nexa-toast-container { z-index: 100000; }
        .setup-page .nexa-toast {
            background: rgba(255, 255, 255, 0.97);
            border-color: #a7f3d0;
            color: #134e4a;
            opacity: 1;
            transform: none;
        }
        .setup-page .nexa-toast.error {
            border-color: #f87171;
            color: #991b1b;
        }
        html.dark .setup-page .nexa-toast {
            background: rgba(20, 28, 24, 0.97);
            border-color: rgba(63, 181, 58, 0.25);
            color: #e2e8f0;
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.45), 0 2px 8px rgba(0, 0, 0, 0.2);
        }
        html.dark .setup-page .nexa-toast.error { border-color: #f87171; color: #fca5a5; }
    </style>
    <script>
        (function() {
            try {
                var theme = localStorage.getItem('color-theme') || localStorage.getItem('nexa-theme');
                if (theme === 'dark' || (!theme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                    document.documentElement.classList.add('dark');
                }
                var lang = localStorage.getItem('nexa-admin-lang') || 'fa';
                document.documentElement.lang = lang;
                document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
            } catch (e) {}
        })();
    </script>
</head>
<body class="setup-page setup-bg text-gray-900 dark:text-gray-100 min-h-screen flex items-center justify-center p-4 transition-colors duration-300">
    ${NEXA_TOAST_HTML}
    <div class="fixed top-4 inset-x-4 z-40 flex items-center justify-between pointer-events-none">
        <div class="pointer-events-auto flex items-center gap-2 ms-auto">
            <div class="setup-lang-switch">
                <button type="button" id="setup-lang-fa" class="setup-lang-btn active">فا</button>
                <button type="button" id="setup-lang-en" class="setup-lang-btn">EN</button>
            </div>
            <button type="button" id="setup-theme-btn" class="setup-tool-btn" title="Theme">
                <svg class="w-5 h-5 hidden dark:block text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m12.728 0l-.707-.707M6.343 6.343l-.707-.707M14 12a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
                <svg class="w-5 h-5 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
            </button>
        </div>
    </div>
    <div class="w-full max-w-lg setup-card rounded-3xl p-8">
        <div class="text-center mb-6">
            <div class="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-emerald-50 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400 mb-4 shadow-sm overflow-hidden">
                <img src="${NEXA_LOGO_URL}" alt="Nexa Panel" class="w-10 h-10 object-contain">
            </div>
            <h2 class="text-xl font-bold text-gray-900 dark:text-white" data-i18n="setup_title">راه‌اندازی اولیه Nexa Panel</h2>
            <p class="text-sm text-gray-500 dark:text-gray-400 mt-2 leading-relaxed" data-i18n="setup_subtitle">وضعیت اتصالات را بررسی کنید و رمز عبور پنل را تنظیم نمایید.</p>
        </div>
        <div class="space-y-2 mb-6" id="status-list">
            ${statusRows}
        </div>
        ${legacyAdminHint}
        ${adminInfo}
        ${passwordForm}
        ${cfTokenForm}
        ${missingVarsMsg}
        <div class="mt-6 pt-4 border-t setup-divider" id="setup-enter-wrap">
        ${panelEntryBlock}
        </div>
    </div>
    <script>
        var SETUP_I18N = ${JSON.stringify(setupI18n)};
        function setupT(key) {
            var lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            return (SETUP_I18N[lang] || SETUP_I18N.fa)[key] || key;
        }
        function applySetupI18n(lang) {
            var dict = SETUP_I18N[lang] || SETUP_I18N.fa;
            document.querySelectorAll('[data-i18n]').forEach(function(el) {
                var key = el.getAttribute('data-i18n');
                if (!dict[key]) return;
                if (key === 'page_title') {
                    document.title = dict[key];
                    return;
                }
                if (el.children.length === 0) {
                    el.textContent = dict[key];
                }
            });
            document.querySelectorAll('[data-i18n-placeholder]').forEach(function(el) {
                var key = el.getAttribute('data-i18n-placeholder');
                if (dict[key]) el.placeholder = dict[key];
            });
        }
        function setSetupLang(lang) {
            localStorage.setItem('nexa-admin-lang', lang);
            document.documentElement.lang = lang;
            document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
            var faBtn = document.getElementById('setup-lang-fa');
            var enBtn = document.getElementById('setup-lang-en');
            if (faBtn) faBtn.classList.toggle('active', lang === 'fa');
            if (enBtn) enBtn.classList.toggle('active', lang === 'en');
            applySetupI18n(lang);
        }
        function toggleSetupTheme() {
            var root = document.documentElement;
            var isDark = root.classList.toggle('dark');
            localStorage.setItem('color-theme', isDark ? 'dark' : 'light');
            localStorage.setItem('nexa-theme', isDark ? 'dark' : 'light');
        }
        function showSetupToast(message, type) {
            type = type || 'success';
            var container = document.getElementById('nexa-toast-container');
            if (!container) return;
            container.innerHTML = '';
            var toast = document.createElement('div');
            toast.className = 'nexa-toast ' + type;
            toast.style.direction = document.documentElement.dir || 'rtl';
            var iconEl = document.createElement('span');
            iconEl.className = 'nexa-toast-icon';
            iconEl.textContent = type === 'error' ? '✕' : '✓';
            var msgEl = document.createElement('span');
            msgEl.className = 'nexa-toast-msg';
            msgEl.textContent = message;
            toast.appendChild(iconEl);
            toast.appendChild(msgEl);
            container.appendChild(toast);
            requestAnimationFrame(function() {
                toast.style.opacity = '1';
                toast.style.transform = 'translateY(0)';
            });
            clearTimeout(window._setupToastTimer);
            window._setupToastTimer = setTimeout(function() {
                toast.classList.add('hide');
                setTimeout(function() { if (toast.parentNode) toast.remove(); }, 400);
            }, type === 'success' ? 3500 : 5000);
        }
        window.showNexaToast = showSetupToast;

        document.getElementById('setup-lang-fa').addEventListener('click', function() { setSetupLang('fa'); });
        document.getElementById('setup-lang-en').addEventListener('click', function() { setSetupLang('en'); });
        document.getElementById('setup-theme-btn').addEventListener('click', toggleSetupTheme);
        setSetupLang(localStorage.getItem('nexa-admin-lang') || 'fa');

        var form = document.getElementById('setup-form');
        if (form) {
            var submitBtn = document.getElementById('setup-submit');
            form.addEventListener('submit', async function(e) {
                e.preventDefault();
                var password = document.getElementById('setup-password').value.trim();
                var confirmPassword = document.getElementById('setup-password-confirm').value.trim();
                if (!password) {
                    showSetupToast(setupT('pwd_required'), 'error');
                    return;
                }
                if (password.length < 4) {
                    showSetupToast(setupT('pwd_minlength'), 'error');
                    return;
                }
                if (password !== confirmPassword) {
                    showSetupToast(setupT('pwd_mismatch'), 'error');
                    return;
                }
                submitBtn.disabled = true;
                submitBtn.textContent = setupT('pwd_saving');
                try {
                    var res = await fetch('/api/setup', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ password: password, confirmPassword: confirmPassword })
                    });
                    var data;
                    try {
                        data = await res.json();
                    } catch (parseErr) {
                        showSetupToast(setupT('server_error'), 'error');
                        submitBtn.disabled = false;
                        submitBtn.textContent = setupT('pwd_submit');
                        return;
                    }
                    if (!res.ok) {
                        showSetupToast(data.error || setupT('pwd_error'), 'error');
                        submitBtn.disabled = false;
                        submitBtn.textContent = setupT('pwd_submit');
                        return;
                    }
                    showSetupToast(setupT('pwd_success'), 'success');
                    var enterWrap = document.getElementById('setup-enter-wrap');
                    if (enterWrap) {
                        enterWrap.innerHTML = '<a href="/admin" class="setup-enter-btn block w-full py-3 font-bold rounded-xl text-sm transition text-center" data-i18n="enter_panel">' + setupT('enter_panel') + '</a>';
                    }
                    setTimeout(function() { window.location.href = '/admin'; }, 1500);
                } catch (err) {
                    showSetupToast(setupT('server_error'), 'error');
                    submitBtn.disabled = false;
                    submitBtn.textContent = setupT('pwd_submit');
                }
            });
        }
        var enterPanelLink = document.querySelector('a.setup-enter-btn');
        if (enterPanelLink) {
            enterPanelLink.addEventListener('click', function(e) {
                e.preventDefault();
                showSetupToast(setupT('enter_success'), 'success');
                setTimeout(function() { window.location.href = '/admin'; }, 800);
            });
        }
        var cfForm = document.getElementById('setup-cf-form');
        if (cfForm) {
            var cfSubmitBtn = document.getElementById('setup-cf-submit');
            var cfErrorEl = document.getElementById('setup-cf-error');
            cfForm.addEventListener('submit', async function(e) {
                e.preventDefault();
                var cfToken = (document.getElementById('setup-cf-token') || {}).value || '';
                cfErrorEl.classList.add('hidden');
                cfErrorEl.textContent = '';
                if (!cfToken.trim()) {
                    cfErrorEl.textContent = setupT('setup_cf_token_required');
                    cfErrorEl.classList.remove('hidden');
                    return;
                }
                cfSubmitBtn.disabled = true;
                cfSubmitBtn.textContent = setupT('setup_cf_token_saving');
                try {
                    var res = await fetch('/api/cf-credentials', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ cf_token: cfToken.trim() })
                    });
                    var data;
                    try {
                        data = await res.json();
                    } catch (parseErr) {
                        cfErrorEl.textContent = setupT('server_error');
                        cfErrorEl.classList.remove('hidden');
                        cfSubmitBtn.disabled = false;
                        cfSubmitBtn.textContent = setupT('setup_cf_token_submit');
                        return;
                    }
                    if (!res.ok) {
                        if (res.status === 401) {
                            window.location.href = '/admin';
                            return;
                        }
                        cfErrorEl.textContent = data.error || setupT('setup_cf_token_error');
                        cfErrorEl.classList.remove('hidden');
                        cfSubmitBtn.disabled = false;
                        cfSubmitBtn.textContent = setupT('setup_cf_token_submit');
                        return;
                    }
                    showSetupToast(setupT('setup_cf_token_success'), 'success');
                    setTimeout(function() { window.location.href = '/admin'; }, 1500);
                } catch (err) {
                    cfErrorEl.textContent = setupT('server_error');
                    cfErrorEl.classList.remove('hidden');
                    cfSubmitBtn.disabled = false;
                    cfSubmitBtn.textContent = setupT('setup_cf_token_submit');
                }
            });
        }
    </script>
</body>
</html>`;
}
function buildNexaStatusPage(startedAtMs) {
  const started = Number(startedAtMs) || Date.now();
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nexa</title>
${NEXA_FAVICON_TAGS}
<link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet">
<style>
  :root{
    --bg:#f4f8f6;--bg2:#e8f2ed;--card:#fff;--card2:#eef5f1;--text:#111827;--muted:#64748b;
    --accent:#3FB53A;--accent2:#1E8A2E;--border:#dfe8e4;--glow:rgba(63,181,58,0.28);
  }
  html.dark{
    --bg:#0b0f0d;--bg2:#0f1512;--card:#131a17;--card2:#0f1512;--text:#e8ece9;--muted:#8b95a8;
    --accent:#79E62A;--accent2:#3FB53A;--border:#22302a;--glow:rgba(121,230,42,0.22);
  }
  *{box-sizing:border-box;}
  body{
    margin:0;min-height:100vh;font-family:'Vazirmatn',sans-serif;color:var(--text);
    display:flex;align-items:center;justify-content:center;transition:background .3s,color .3s;
    background:
      radial-gradient(ellipse 70% 55% at 15% 10%, color-mix(in srgb, var(--accent) 10%, transparent), transparent 55%),
      radial-gradient(ellipse 60% 50% at 90% 90%, color-mix(in srgb, var(--accent2) 8%, transparent), transparent 50%),
      linear-gradient(155deg, var(--bg) 0%, var(--bg2) 100%);
  }
  .card{
    max-width:30rem;width:100%;margin:1rem;padding:2.75rem 2.25rem;text-align:center;position:relative;
    border-radius:1.75rem;
    background: linear-gradient(160deg, var(--card) 0%, var(--card2) 100%);
    border:1px solid color-mix(in srgb, var(--accent) 22%, var(--border));
    box-shadow:
      0 1px 0 color-mix(in srgb, #fff 25%, transparent) inset,
      0 -20px 40px -30px color-mix(in srgb, var(--accent) 30%, transparent) inset,
      0 24px 60px -18px rgba(0,0,0,.22),
      0 8px 24px -12px var(--glow);
    overflow:hidden;
  }
  .card::before{
    content:'';position:absolute;inset-inline:0;top:0;height:3px;
    background:linear-gradient(90deg, transparent, var(--accent), var(--accent2), transparent);
    opacity:.85;
  }
  .logo{
    width:5rem;height:5rem;margin:0 auto 1.35rem;border-radius:1.15rem;overflow:hidden;position:relative;
    box-shadow:0 14px 30px -10px var(--glow), 0 2px 8px rgba(0,0,0,.1);
    transform:translateZ(0);
    animation:float 4s ease-in-out infinite;
  }
  @keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
  .logo img{width:100%;height:100%;object-fit:contain;}
  h1{font-size:1.5rem;font-weight:900;margin:0 0 .6rem;letter-spacing:.01em;}
  .sub{font-size:.85rem;color:var(--muted);margin:0 0 .5rem;line-height:1.7;}
  .dot{
    display:inline-block;width:.55rem;height:.55rem;border-radius:9999px;
    background:radial-gradient(circle at 30% 30%, #fff, var(--accent));
    margin-inline-end:.45rem;box-shadow:0 0 12px var(--accent), 0 0 2px var(--accent);
    animation:pulse 1.8s infinite;
  }
  @keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.55;transform:scale(.85)}}
  .uptime{
    margin-top:1.85rem;padding-top:1.35rem;border-top:1px solid color-mix(in srgb, var(--accent) 15%, var(--border));
    font-size:.8rem;color:var(--muted);
  }
  .uptime b{
    color:var(--text);font-family:ui-monospace,monospace;display:block;margin-top:.5rem;font-size:1.15rem;
    letter-spacing:.03em;
    text-shadow:0 0 18px var(--glow);
  }
  .theme-btn{
    position:fixed;top:1rem;left:1rem;width:2.5rem;height:2.5rem;border-radius:.85rem;
    background:var(--card);border:1px solid var(--border);color:var(--muted);
    display:flex;align-items:center;justify-content:center;cursor:pointer;transition:all .2s;
    box-shadow:0 6px 16px -6px rgba(0,0,0,.15);
  }
  .theme-btn:hover{border-color:color-mix(in srgb, var(--accent) 40%, var(--border));transform:translateY(-1px);}
  .theme-btn svg{width:1.2rem;height:1.2rem;}
</style>
</head>
<body>
<button class="theme-btn" onclick="(function(){document.documentElement.classList.toggle('dark');try{localStorage.setItem('nexa-status-theme',document.documentElement.classList.contains('dark')?'dark':'light');}catch(e){}})()" title="تغییر تم">
  <svg class="hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="color:#facc15"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m12.728 0l-.707-.707M6.343 6.343l-.707-.707M14 12a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
  <svg class="block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
</button>
<div class="card">
  <div class="logo"><img src="${NEXA_LOGO_URL}" alt="Nexa"></div>
  <h1><span class="dot"></span>Nexa</h1>
  <p class="sub">نکسا در حال حاضر فعال است و به درستی کار می‌کند.</p>
  <p class="sub" dir="ltr">Nexa is currently up and running.</p>
  <div class="uptime">
    مدت زمان روشن بودن پنل / Panel uptime
    <b id="uptime-val">--</b>
  </div>
</div>
<script>
(function(){
  try{
    var t=localStorage.getItem('nexa-status-theme');
    if(t==='dark'||(!t&&window.matchMedia('(prefers-color-scheme: dark)').matches)) document.documentElement.classList.add('dark');
  }catch(e){}
  try{
    var isDarkInit = document.documentElement.classList.contains('dark');
    var iconEl = document.getElementById('nexa-theme-icon');
    if(iconEl){
      iconEl.innerHTML = isDarkInit
        ? '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m12.728 0l-.707-.707M6.343 6.343l-.707-.707M14 12a2 2 0 11-4 0 2 2 0 014 0z"></path>'
        : '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path>';
    }
  }catch(e){}
  var started=${started};
  function fmt(ms){
    var s=Math.floor(ms/1000);
    var d=Math.floor(s/86400); s%=86400;
    var h=Math.floor(s/3600); s%=3600;
    var m=Math.floor(s/60); s%=60;
    var hh=(h<10?'0':'')+h, mm=(m<10?'0':'')+m, ss=(s<10?'0':'')+s;
    return (d?d+' روز، ':'') + hh+':'+mm+':'+ss;
  }
  function tick(){ document.getElementById('uptime-val').textContent = fmt(Date.now()-started); }
  tick();
  setInterval(tick, 1000);
})();
</script>
</body>
</html>`;
}
const HTML_TEMPLATES = {
  nginx: `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>`,
  login: `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    ${NEXA_THEME_COLOR_ADMIN}
    ${NEXA_FAVICON_TAGS}
    ${NEXA_THEME_COLOR_SYNC_SCRIPT}
    <title data-i18n="page_title">ورود — Nexa Panel</title>
    <script>
        (function() {
            try {
                var t = localStorage.getItem('color-theme');
                if (t === 'dark' || (!t && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                    document.documentElement.classList.add('dark');
                }
                var lang = localStorage.getItem('nexa-admin-lang') || 'fa';
                document.documentElement.lang = lang;
                document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
            } catch (e) {}
        })();
    </script>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: { sans: ['Vazirmatn', 'sans-serif'] }
                }
            }
        }
    </script>
    <style>
        body { font-family: 'Vazirmatn', sans-serif; }
        .login-bg {
            background:
                radial-gradient(ellipse 80% 60% at 20% 10%, rgba(63, 181, 58, 0.18), transparent 55%),
                radial-gradient(ellipse 70% 50% at 85% 85%, rgba(30, 138, 46, 0.14), transparent 50%),
                linear-gradient(145deg, #f4f9f5 0%, #eef6f0 45%, #e8f2ec 100%);
        }
        html.dark .login-bg {
            background:
                radial-gradient(ellipse 80% 60% at 20% 10%, rgba(63, 181, 58, 0.12), transparent 55%),
                radial-gradient(ellipse 70% 50% at 85% 85%, rgba(30, 138, 46, 0.1), transparent 50%),
                linear-gradient(145deg, #0c1210 0%, #111916 45%, #0f1512 100%);
        }
        .login-card {
            backdrop-filter: blur(12px);
            background: rgba(255, 255, 255, 0.92);
            border: 1px solid rgba(63, 181, 58, 0.15);
            box-shadow: 0 24px 60px rgba(30, 138, 46, 0.12), 0 0 0 1px rgba(255,255,255,0.6) inset;
        }
        html.dark .login-card {
            background: rgba(20, 28, 24, 0.88);
            border-color: rgba(63, 181, 58, 0.22);
            box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45), 0 0 0 1px rgba(255,255,255,0.04) inset;
        }
        .login-tool-btn {
            display: inline-flex; align-items: center; justify-content: center;
            width: 2.5rem; height: 2.5rem; border-radius: 0.85rem;
            border: 1px solid rgba(63, 181, 58, 0.18);
            background: rgba(255,255,255,0.75);
            color: #475569; transition: all 0.2s;
        }
        html.dark .login-tool-btn {
            background: rgba(30, 40, 35, 0.85);
            border-color: rgba(63, 181, 58, 0.25);
            color: #94a3b8;
        }
        .login-tool-btn:hover { border-color: rgba(63, 181, 58, 0.45); transform: translateY(-1px); }
        .login-lang-switch {
            display: inline-flex; padding: 0.2rem; border-radius: 0.85rem;
            border: 1px solid rgba(63, 181, 58, 0.18);
            background: rgba(255,255,255,0.75);
        }
        html.dark .login-lang-switch {
            background: rgba(30, 40, 35, 0.85);
            border-color: rgba(63, 181, 58, 0.25);
        }
        .login-lang-btn {
            min-width: 2.4rem; padding: 0.35rem 0.55rem; border-radius: 0.65rem;
            font-size: 0.72rem; font-weight: 800; color: #64748b; transition: all 0.2s;
        }
        .login-lang-btn.active {
            background: linear-gradient(135deg, #3FB53A, #1E8A2E);
            color: #fff; box-shadow: 0 4px 14px rgba(30, 138, 46, 0.35);
        }
        .login-logo-wrap {
            width: 4.5rem; height: 4.5rem; border-radius: 1.25rem;
            background: linear-gradient(145deg, rgba(121,230,42,0.12), rgba(30,138,46,0.08));
            border: 1px solid rgba(63, 181, 58, 0.2);
            box-shadow: 0 12px 32px rgba(30, 138, 46, 0.15);
            display: inline-flex; align-items: center; justify-content: center; overflow: hidden;
        }
        .login-logo-wrap img { width: 2.75rem; height: 2.75rem; object-fit: contain; }
        .login-input {
            width: 100%; padding: 0.85rem 2.75rem 0.85rem 1rem;
            border-radius: 0.95rem; border: 1px solid #dbe5df;
            background: #f8fbf9; color: #1e293b; font-size: 0.875rem;
            transition: all 0.2s;
        }
        html[dir="rtl"] .login-input { padding: 0.85rem 1rem 0.85rem 2.75rem; }
        html.dark .login-input {
            background: #1a2420; border-color: #2d3b34; color: #e2e8f0;
        }
        .login-input:focus {
            outline: none; border-color: #3FB53A;
            box-shadow: 0 0 0 3px rgba(63, 181, 58, 0.18);
        }
        .login-pwd-toggle {
            position: absolute; top: 50%; transform: translateY(-50%);
            inset-inline-end: 0.75rem; padding: 0.35rem;
            border-radius: 0.55rem; color: #64748b; transition: color 0.2s;
        }
        .login-pwd-toggle:hover { color: #3FB53A; }
        .login-submit {
            width: 100%; padding: 0.85rem 1rem; border-radius: 0.95rem;
            background: linear-gradient(135deg, #3FB53A 0%, #1E8A2E 100%);
            color: #fff; font-weight: 800; font-size: 0.875rem;
            box-shadow: 0 10px 28px rgba(30, 138, 46, 0.35);
            transition: all 0.2s;
        }
        .login-submit:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 14px 32px rgba(30, 138, 46, 0.42); }
        .login-submit:disabled { opacity: 0.65; cursor: not-allowed; }
        .login-change-pwd {
            font-size: 0.8rem; font-weight: 700; color: #3FB53A;
            transition: color 0.2s;
        }
        .login-change-pwd:hover { color: #1E8A2E; }
        html.dark .login-change-pwd { color: #79E62A; }
        .login-modal-backdrop {
            position: fixed; inset: 0; z-index: 50;
            background: rgba(0,0,0,0.55); backdrop-filter: blur(4px);
            display: none; align-items: center; justify-content: center; padding: 1rem;
        }
        .login-modal-backdrop.open { display: flex; }
        .login-modal {
            width: 100%; max-width: 24rem; border-radius: 1.25rem;
            background: #fff; border: 1px solid rgba(63, 181, 58, 0.18);
            box-shadow: 0 24px 60px rgba(0,0,0,0.25); padding: 1.5rem;
        }
        html.dark .login-modal {
            background: #141c18; border-color: rgba(63, 181, 58, 0.25);
        }
    </style>
</head>
<body class="login-bg text-gray-900 dark:text-gray-100 min-h-screen flex items-center justify-center p-4 transition-colors duration-300">
    <div class="fixed top-4 inset-x-4 z-40 flex items-center justify-between pointer-events-none">
        <div class="pointer-events-auto flex items-center gap-2 ms-auto">
            <div class="login-lang-switch">
                <button type="button" id="login-lang-fa" class="login-lang-btn active" onclick="setLoginLang('fa')">فا</button>
                <button type="button" id="login-lang-en" class="login-lang-btn" onclick="setLoginLang('en')">EN</button>
            </div>
            <button type="button" onclick="toggleLoginTheme()" class="login-tool-btn" title="Theme">
                <svg class="w-5 h-5 hidden dark:block text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m12.728 0l-.707-.707M6.343 6.343l-.707-.707M14 12a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
                <svg class="w-5 h-5 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
            </button>
        </div>
    </div>

    <div class="w-full max-w-md login-card rounded-3xl p-8 relative">
        <div class="text-center mb-8">
            <div class="login-logo-wrap mb-5">
                <img src="${NEXA_LOGO_URL}" alt="Nexa Panel">
            </div>
            <h2 class="text-xl font-black text-gray-900 dark:text-white" data-i18n="login_title">ورود به Nexa Panel</h2>
            <p class="text-sm text-gray-500 dark:text-gray-400 mt-2 leading-relaxed" data-i18n="login_subtitle">Nexa Team — برای دسترسی، رمز عبور خود را وارد کنید.</p>
        </div>
        <form onsubmit="handleLogin(event)" class="space-y-5">
            <div>
                <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1.5" data-i18n="password_label">رمز عبور</label>
                <div class="relative">
                    <input type="password" id="password" class="login-input text-center font-mono" autocomplete="current-password" required>
                    <button type="button" onclick="toggleLoginPassword()" class="login-pwd-toggle" aria-label="Show password">
                        <svg id="login-eye-open" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path></svg>
                        <svg id="login-eye-closed" class="w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"></path></svg>
                    </button>
                </div>
            </div>
            <button type="submit" id="submit-btn" class="login-submit" data-i18n="login_btn">ورود</button>
        </form>
        <div class="mt-5 text-center">
            <button type="button" onclick="openForgotPwdModal()" class="login-change-pwd" data-i18n="forgot_pwd_link">فراموشی رمز عبور</button>
        </div>
    </div>

    <div id="forgot-pwd-modal" class="login-modal-backdrop" onclick="if(event.target===this)closeForgotPwdModal()">
        <div class="login-modal" role="dialog" aria-modal="true">
            <div class="flex items-start justify-between gap-3 mb-4">
                <div>
                    <h3 class="text-lg font-black text-gray-900 dark:text-white" data-i18n="forgot_pwd_title">فراموشی رمز عبور</h3>
                    <p class="text-sm text-gray-500 dark:text-gray-400 mt-3 leading-relaxed" data-i18n="forgot_pwd_desc">اگر به پنل دسترسی دارید، از بخش تنظیمات پنل می‌توانید با وارد کردن رمز فعلی، رمز جدید تنظیم کنید. رمز در متغیر ADMIN (نوع Text) ذخیره می‌شود.</p>
                </div>
                <button type="button" onclick="closeForgotPwdModal()" class="login-tool-btn shrink-0">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-4 rounded-xl text-sm leading-relaxed" style="background: color-mix(in srgb, #3FB53A 10%, transparent); border: 1px solid color-mix(in srgb, #3FB53A 25%, transparent); color: #1E8A2E;">
                <p class="text-xs text-center" data-i18n="forgot_pwd_hint">مسیر: پنل &gt; تنظیمات پنل &gt; تغییر رمز عبور</p>
            </div>
            <button type="button" onclick="closeForgotPwdModal()" class="login-submit mt-4" data-i18n="forgot_pwd_close">متوجه شدم</button>
        </div>
    </div>

    <script>
        var LOGIN_I18N = {
            fa: {
                page_title: 'ورود — Nexa Panel',
                login_title: 'ورود به Nexa Panel',
                login_subtitle: 'Nexa Team — برای دسترسی، رمز عبور خود را وارد کنید.',
                password_label: 'رمز عبور',
                login_btn: 'ورود',
                login_checking: 'در حال بررسی...',
                login_error: '❌ رمز عبور اشتباه است!',
                server_error: 'خطا در ارتباط با سرور',
                forgot_pwd_link: 'فراموشی رمز عبور',
                forgot_pwd_title: 'فراموشی رمز عبور',
                forgot_pwd_desc: 'اگر به پنل دسترسی دارید، از بخش تنظیمات پنل می‌توانید با وارد کردن رمز فعلی، رمز جدید تنظیم کنید. رمز در متغیر ADMIN (نوع Text) ذخیره می‌شود.',
                forgot_pwd_hint: 'مسیر: انتخاب ورکر > تنظیمات ورکر > تغیر متغیر ADMIN به رمز دلخواه',
                forgot_pwd_close: 'متوجه شدم'
            },
            en: {
                page_title: 'Login — Nexa Panel',
                login_title: 'Login to Nexa Panel',
                login_subtitle: 'Nexa Team — Enter your password to access the panel.',
                password_label: 'Password',
                login_btn: 'Login',
                login_checking: 'Checking...',
                login_error: '❌ Incorrect password!',
                server_error: 'Server connection error',
                forgot_pwd_link: 'Forgot Password',
                forgot_pwd_title: 'Forgot Password',
                forgot_pwd_desc: 'If you have panel access, go to Panel Settings and change your password by entering the current one. Password is stored in the ADMIN variable (Text type).',
                forgot_pwd_hint: 'Path: Panel > Panel Settings > Change password',
                forgot_pwd_close: 'Got it'
            }
        };
        function loginT(key) {
            var lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            return (LOGIN_I18N[lang] || LOGIN_I18N.fa)[key] || key;
        }
        function applyLoginI18n(lang) {
            var dict = LOGIN_I18N[lang] || LOGIN_I18N.fa;
            document.querySelectorAll('[data-i18n]').forEach(function(el) {
                var key = el.getAttribute('data-i18n');
                if (dict[key]) {
                    if (key === 'page_title') document.title = dict[key];
                    else el.textContent = dict[key];
                }
            });
        }
        function setLoginLang(lang) {
            localStorage.setItem('nexa-admin-lang', lang);
            document.documentElement.lang = lang;
            document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
            document.getElementById('login-lang-fa').classList.toggle('active', lang === 'fa');
            document.getElementById('login-lang-en').classList.toggle('active', lang === 'en');
            applyLoginI18n(lang);
        }
        function toggleLoginTheme() {
            var root = document.documentElement;
            var isDark = root.classList.toggle('dark');
            localStorage.setItem('color-theme', isDark ? 'dark' : 'light');
        }
        function toggleLoginPassword() {
            var input = document.getElementById('password');
            var open = document.getElementById('login-eye-open');
            var closed = document.getElementById('login-eye-closed');
            var show = input.type === 'password';
            input.type = show ? 'text' : 'password';
            open.classList.toggle('hidden', show);
            closed.classList.toggle('hidden', !show);
        }
        function openForgotPwdModal() {
            document.getElementById('forgot-pwd-modal').classList.add('open');
        }
        function closeForgotPwdModal() {
            document.getElementById('forgot-pwd-modal').classList.remove('open');
        }
        async function handleLogin(event) {
            event.preventDefault();
            var password = document.getElementById('password').value;
            var btn = document.getElementById('submit-btn');
            btn.disabled = true;
            btn.innerText = loginT('login_checking');
            try {
                var res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: password })
                });
                var data = await res.json();
                if (res.ok && data.success) {
                    window.location.reload();
                } else {
                    alert(loginT('login_error'));
                }
            } catch (err) {
                alert(loginT('server_error'));
            } finally {
                btn.disabled = false;
                btn.innerText = loginT('login_btn');
            }
        }
        setLoginLang(localStorage.getItem('nexa-admin-lang') || 'fa');
    </script>
</body>
</html>`,
  panel: `
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    ${NEXA_THEME_COLOR_ADMIN}
    ${NEXA_FAVICON_TAGS}
    ${NEXA_THEME_COLOR_SYNC_SCRIPT}
    <title>Nexa Team Panel</title>
    <script>
        (function() {
            try {
                var t = localStorage.getItem('color-theme');
                if (t === 'dark' || (!t && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                    document.documentElement.classList.add('dark');
                }
                var lang = localStorage.getItem('nexa-admin-lang') || 'fa';
                document.documentElement.lang = lang;
                document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
            } catch (e) {}
        })();
    </script>
    <script>
        const originalWarn = console.warn;
        console.warn = (...args) => {
            if (typeof args[0] === 'string' && args[0].includes('cdn.tailwindcss.com')) return;
            originalWarn(...args);
        };
    </script>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.js"></script>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: { sans: ['Vazirmatn', 'sans-serif'] },
                    colors: {
                        admin: {
                            bg: '#f4f8f6',
                            card: '#ffffff',
                            border: '#dfe8e4',
                            muted: '#64748b',
                            primary: '#059669',
                            'primary-light': '#10b981',
                            sidebar: '#ffffff',
                            accent: '#0d9488'
                        },
                        amoled: { bg: '#0b0f14', card: '#111827', input: '#1a2332', border: '#243044' }
                    }
                }
            }
        }
    </script>
    <style>
        ${NEXA_ADMIN_SHELL_CSS}
        ${NEXA_USERS_REDESIGN_CSS}
        ${NEXA_TOAST_CSS}
        ${NEXA_CONFIRM_CSS}
    </style>
</head>
<body class="adm-app admin-shell transition-colors duration-200">
    <div id="adm-sidebar-backdrop" class="adm-sidebar-backdrop" onclick="toggleAdminSidebar(false)"></div>
    <aside id="adm-sidebar" class="adm-sidebar">
        <div class="adm-sidebar-brand">
            <div class="flex items-center gap-3">
                <div class="adm-sidebar-logo">
                    <img src="${NEXA_LOGO_URL}" alt="Nexa Panel">
                </div>
                <div class="adm-sidebar-brand-text">
                    <div class="adm-sidebar-title" dir="ltr">Nexa Panel</div>
                    <div class="adm-sidebar-sub" data-i18n="panel_subtitle">پنل مدیریت</div>
                </div>
            </div>
        </div>
        <nav class="adm-nav">
            <div class="adm-nav-label" data-i18n="nav_main">منوی اصلی</div>
            <button type="button" data-section="dashboard" class="adm-nav-item active w-full" onclick="switchAdminSection('dashboard')">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"></path></svg>
                <span data-i18n="nav_dashboard">داشبورد</span>
            </button>
            <button type="button" data-section="users" class="adm-nav-item w-full" onclick="switchAdminSection('users')">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
                <span data-i18n="nav_users">مدیریت کاربران</span>
            </button>
            <button type="button" data-section="guide" class="adm-nav-item w-full" onclick="switchAdminSection('guide')">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"></path></svg>
                <span data-i18n="nav_guide">آموزش اتصال</span>
            </button>
            <button type="button" data-section="node-server" class="adm-nav-item w-full" onclick="switchAdminSection('node-server')">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path></svg>
                <span data-i18n="nav_node_server">سرور نود</span>
            </button>
            <button type="button" data-section="ip-scanner" class="adm-nav-item w-full" onclick="switchAdminSection('ip-scanner')">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                <span data-i18n="nav_ip_scanner">اسکنر IP تمیز</span>
            </button>
            <button type="button" data-section="cdn-proxy" class="adm-nav-item w-full" onclick="switchAdminSection('cdn-proxy')">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z"></path></svg>
                <span data-i18n="nav_cdn_proxy">پروکسی CDN</span>
            </button>
            <button type="button" data-section="logs" class="adm-nav-item w-full" onclick="switchAdminSection('logs')">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                <span data-i18n="nav_logs">لاگ فعالیت</span>
            </button>
            <button type="button" data-section="settings" class="adm-nav-item w-full" onclick="switchAdminSection('settings')">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543-.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
                <span data-i18n="nav_settings">تنظیمات پنل</span>
                <span id="adm-nav-update-badge" class="adm-nav-update-badge">!</span>
            </button>
            <button type="button" data-section="panel-control" class="adm-nav-item w-full" onclick="switchAdminSection('panel-control')">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v9m6.364-6.364a9 9 0 11-12.728 0"></path></svg>
                <span data-i18n="nav_panel_control">کنترل پنل</span>
            </button>
            <button type="button" data-section="about" class="adm-nav-item w-full" onclick="switchAdminSection('about')">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                <span data-i18n="nav_about">درباره ما</span>
            </button>
        </nav>
        <div class="adm-sidebar-foot">
            <button type="button" class="adm-sidebar-collapse-btn" onclick="toggleSidebarCollapse()" data-i18n-aria-label="aria_collapse" aria-label="جمع کردن منو">
                <span data-i18n="nav_collapse">جمع کردن منو</span>
                <svg class="adm-collapse-chevron" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"></path></svg>
            </button>
            <button type="button" onclick="logoutAdmin()" class="adm-logout-btn">
                <span data-i18n="nav_logout">خروج</span>
                <svg class="w-4 h-4 adm-icon-flip" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path></svg>
            </button>
            <hr class="adm-sidebar-divider">
            <div class="adm-panel-version" data-i18n="panel_version">نسخه ${PANEL_VERSION}</div>
        </div>
    </aside>
    <div class="adm-main-wrap">
        <header class="adm-topbar">
            <div class="adm-topbar-start">
                <button type="button" class="adm-menu-btn" onclick="toggleAdminSidebar()" data-i18n-aria-label="aria_menu" aria-label="منو">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path></svg>
                </button>
                <div>
                    <div class="adm-page-title" id="adm-page-title">داشبورد</div>
                    <div class="adm-page-desc" id="adm-page-desc">آمار کلی پنل و وضعیت سرویس‌ها</div>
                </div>
                <button type="button" onclick="openSectionHelp()" class="adm-theme-btn" title="آموزش این بخش" style="color:#f59e0b">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                </button>
            </div>
            <div class="adm-topbar-actions">
                <div class="adm-lang-switch">
                    <button type="button" id="lang-fa" class="adm-lang-btn active" onclick="setAdminLang('fa')">فا</button>
                    <button type="button" id="lang-en" class="adm-lang-btn" onclick="setAdminLang('en')">EN</button>
                </div>
                <button type="button" id="theme-toggle" class="adm-theme-btn" data-i18n-title="theme_toggle" title="تغییر تم">
                    <svg id="sun-icon" class="w-5 h-5 hidden dark:block text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m12.728 0l-.707-.707M6.343 6.343l-.707-.707M14 12a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
                    <svg id="moon-icon" class="w-5 h-5 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
                </button>
            </div>
        </header>
        <div id="adm-announce-banner" class="adm-announce-banner hidden" role="status" aria-live="polite">
            <div class="adm-announce-inner">
                <span class="adm-announce-icon" aria-hidden="true">
                    <svg class="w-[1.05rem] h-[1.05rem] sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z"/></svg>
                </span>
                <div id="adm-announce-body" class="adm-announce-body"></div>
            </div>
        </div>
        <main class="adm-content">
<div id="section-dashboard" class="adm-section active">
<div class="adm-dash-grid">
    <div class="adm-dash-card adm-dash-service">
        <div class="adm-dash-card-title" data-i18n="dash_sub_title">لینک اشتراک اصلی</div>
        <div class="adm-dash-service-inner">
            <div class="flex-1 min-w-0 space-y-3">
                <div class="adm-dash-sub-link" id="dash-sub-link">—</div>
                <div class="adm-dash-action-row">
                    <button type="button" class="adm-dash-manage-btn" onclick="openSystemUserEdit()">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg>
                        <span data-i18n="dash_manage_btn">برای مدیریت این سرویس کلیک کنید</span>
                    </button>
                    <button type="button" class="adm-dash-copy-btn" onclick="copyDashboardSubLink()">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
                        <span data-i18n="dash_copy_sub">کپی اشتراک</span>
                    </button>
                </div>
            </div>
            <div class="adm-dash-qr-wrap">
                <div id="dashboard-qr-box" class="adm-dash-qr-box" role="button" tabindex="0" title="بزرگ‌نمایی QR" data-i18n-title="dash_qr_zoom_title" onclick="openDashboardQrModal()" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();openDashboardQrModal();}"></div>
            </div>
        </div>
    </div>
    <div class="adm-dash-card" id="dash-req-card">
        <div class="adm-dash-card-title" data-i18n="dash_worker_usage">مصرف ریکوئست Worker</div>
        <div class="adm-dash-live-badge"><span data-i18n="dash_reset_label">ریست ساعت:</span> <span id="dash-req-reset">—</span></div>
        <div class="flex items-baseline gap-2">
            <div class="adm-dash-req-value" id="dash-req-today">0</div>
            <span class="text-sm font-bold adm-muted">/ 100k</span>
        </div>
        <div class="adm-dash-req-bar"><div class="adm-dash-req-bar-fill" id="dash-req-progress" style="width:0%"></div></div>
        <div class="adm-dash-req-meta" data-i18n="dash_reset_meta">ریست ریکوئست‌ها در ساعت 3:30 به وقت تهران</div>
        <div class="adm-dash-top-req" id="dash-top-req-section">
            <div class="adm-dash-top-req-title" data-i18n="dash_top_req_title">بیشترین مصرف ریکوئست کل</div>
            <div id="dash-top-req-list" class="adm-dash-top-req-list"></div>
        </div>
    </div>
    <div class="adm-dash-card adm-dash-geo">
        <div class="adm-dash-card-head">
            <div class="adm-dash-card-title">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 11a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
                <span data-i18n="dash_ip_title">مشخصات IP شما</span>
            </div>
            <button type="button" id="dash-refresh-btn" class="adm-dash-refresh-btn" onclick="loadDashboard(true)" data-i18n="refresh">بروزرسانی</button>
        </div>
        <div class="adm-dash-geo-inner">
            <div class="adm-dash-geo-stack">
                <div class="adm-dash-geo-block">
                    <div class="adm-dash-geo-block-title" data-i18n="dash_via_server">از طریق این سرور</div>
                    <div class="adm-dash-ip-row">
                        <span class="adm-dash-flag" id="dash-visitor-flag">🌐</span>
                        <div class="min-w-0 flex-1">
                            <div class="adm-dash-ip" id="dash-visitor-ip">—</div>
                            <div class="adm-dash-location" id="dash-visitor-location" data-i18n="dash_fetching_loc">در حال دریافت موقعیت...</div>
                        </div>
                    </div>
                    <div class="adm-dash-geo-details">
                        <div class="adm-dash-geo-item"><div class="adm-dash-geo-label" data-i18n="dash_city">شهر</div><div class="adm-dash-geo-value" id="dash-geo-city">—</div></div>
                        <div class="adm-dash-geo-item"><div class="adm-dash-geo-label" data-i18n="dash_region">منطقه</div><div class="adm-dash-geo-value" id="dash-geo-region">—</div></div>
                        <div class="adm-dash-geo-item"><div class="adm-dash-geo-label" data-i18n="dash_country">کشور</div><div class="adm-dash-geo-value" id="dash-geo-country">—</div></div>
                        <div class="adm-dash-geo-item"><div class="adm-dash-geo-label">ISP</div><div class="adm-dash-geo-value" id="dash-geo-isp">—</div></div>
                    </div>
                </div>
                <div class="adm-dash-geo-block">
                    <div class="adm-dash-geo-block-title" data-i18n="dash_direct_ip">IP مستقیم (بدون پروکسی)</div>
                    <div class="adm-dash-ip-row">
                        <span class="adm-dash-flag" id="dash-direct-flag">🌐</span>
                        <div class="min-w-0 flex-1">
                            <div class="adm-dash-ip" id="dash-direct-ip">—</div>
                            <div class="adm-dash-location" id="dash-direct-location" data-i18n="dash_click_refresh">برای دریافت، بروزرسانی را بزنید</div>
                        </div>
                    </div>
                    <div class="adm-dash-geo-details">
                        <div class="adm-dash-geo-item"><div class="adm-dash-geo-label" data-i18n="dash_city">شهر</div><div class="adm-dash-geo-value" id="dash-direct-city">—</div></div>
                        <div class="adm-dash-geo-item"><div class="adm-dash-geo-label" data-i18n="dash_region">منطقه</div><div class="adm-dash-geo-value" id="dash-direct-region">—</div></div>
                        <div class="adm-dash-geo-item"><div class="adm-dash-geo-label" data-i18n="dash_country">کشور</div><div class="adm-dash-geo-value" id="dash-direct-country">—</div></div>
                        <div class="adm-dash-geo-item"><div class="adm-dash-geo-label">ISP</div><div class="adm-dash-geo-value" id="dash-direct-isp">—</div></div>
                    </div>
                </div>
            </div>
            <div class="adm-dash-map-panel">
                <div class="adm-dash-map-mode" id="dash-map-mode-toggle">
                    <button type="button" id="dash-map-mode-visitor" class="adm-dash-map-mode-btn active" onclick="setDashboardMapMode('visitor')" data-i18n="dash_map_via_server">نقشه: از طریق سرور</button>
                    <button type="button" id="dash-map-mode-direct" class="adm-dash-map-mode-btn" onclick="setDashboardMapMode('direct')" data-i18n="dash_map_direct">نقشه: IP مستقیم</button>
                </div>
                <div class="adm-dash-map-wrap">
                    <div id="dash-visitor-map" class="adm-dash-map-empty" data-i18n="dash_loading_map">در حال بارگذاری نقشه...</div>
                    <button type="button" id="dash-map-zoom-btn" class="adm-dash-map-zoom-btn" onclick="openDashboardMapModal()" style="display:none" data-i18n="dash_zoom_map">بزرگ‌نمایی</button>
                </div>
            </div>
        </div>
    </div>
</div>
</div>
<div id="section-users" class="adm-section">
    <div class="adm-users-layout">
        <div class="adm-users-stats" id="adm-users-stats">
            <div class="adm-users-stat-card">
                <div class="adm-users-stat-icon">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
                </div>
                <div class="adm-users-stat-body">
                    <div class="adm-users-stat-label" data-i18n="stat_total">کل کاربران</div>
                    <div class="adm-users-stat-value" id="stat-total">۰</div>
                </div>
            </div>
            <div class="adm-users-stat-card info">
                <div class="adm-users-stat-icon">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5.636 18.364a9 9 0 010-12.728m12.728 0a9 9 0 010 12.728m-9.9-2.829a5 5 0 010-7.07m7.072 0a5 5 0 010 7.07M13 12a1 1 0 11-2 0 1 1 0 012 0z"></path></svg>
                </div>
                <div class="adm-users-stat-body">
                    <div class="adm-users-stat-label" data-i18n="stat_online">آنلاین</div>
                    <div class="adm-users-stat-value" id="stat-online">۰</div>
                </div>
            </div>
            <div class="adm-users-stat-card warn">
                <div class="adm-users-stat-icon">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                </div>
                <div class="adm-users-stat-body">
                    <div class="adm-users-stat-label" data-i18n="stat_inactive">غیرفعال</div>
                    <div class="adm-users-stat-value" id="stat-inactive">۰</div>
                </div>
            </div>
            <div class="adm-users-stat-card danger">
                <div class="adm-users-stat-icon">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                </div>
                <div class="adm-users-stat-body">
                    <div class="adm-users-stat-label" data-i18n="stat_expired">منقضی</div>
                    <div class="adm-users-stat-value" id="stat-expired">۰</div>
                </div>
            </div>
        </div>
        <div class="adm-users-toolbar">
            <div class="adm-users-search-wrap">
                <input type="text" id="search-input" oninput="filterAndRenderUsers()" data-i18n-placeholder="search_placeholder" placeholder="جستجوی با نام سرویس ..." class="admin-input w-full py-2.5 text-sm">
                <div class="adm-users-search-icon">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                </div>
            </div>
            <div class="adm-users-filters">
                <select id="filter-status" onchange="filterAndRenderUsers()" class="admin-input px-3 py-2.5 text-sm cursor-pointer">
                    <option value="all" data-i18n="filter_all">همه</option>
                    <option value="active" data-i18n="filter_active">فعال</option>
                    <option value="inactive" data-i18n="filter_inactive">غیرفعال</option>
                    <option value="online" data-i18n="filter_online">آنلاین</option>
                    <option value="offline" data-i18n="filter_offline">آفلاین</option>
                    <option value="expired" data-i18n="filter_expired">منقضی / تمام شده</option>
                </select>
                <select id="sort-users" onchange="filterAndRenderUsers()" class="admin-input px-3 py-2.5 text-sm cursor-pointer">
                    <option value="newest" data-i18n="sort_newest">جدیدترین</option>
                    <option value="name" data-i18n="sort_name">نام کاربری (الفبا)</option>
                    <option value="usage-desc" data-i18n="sort_usage_desc">بیشترین مصرف</option>
                    <option value="usage-asc" data-i18n="sort_usage_asc">کمترین مصرف</option>
                    <option value="expiry-asc" data-i18n="sort_expiry_asc">کمترین زمان باقی‌مانده</option>
                </select>
            </div>
        </div>
        <div id="bulk-toolbar" class="hidden adm-bulk-bar">
            <div class="flex flex-col lg:flex-row lg:items-center gap-3 justify-between">
                <div class="flex items-center gap-3 flex-wrap">
                    <span id="bulk-selected-count" class="text-sm font-black admin-brand">۰ سرویس انتخاب شده</span>
                    <button type="button" onclick="clearUserSelection()" class="adm-bulk-btn" data-i18n="bulk_deselect">لغو انتخاب</button>
                </div>
                <div class="flex flex-wrap gap-2">
                    <button type="button" onclick="openBulkEditModal()" class="adm-bulk-btn primary" data-i18n="bulk_edit">ویرایش گروهی</button>
                    <button type="button" onclick="runBulkAction('activate')" class="adm-bulk-btn success" data-i18n="bulk_activate">فعال</button>
                    <button type="button" onclick="runBulkAction('deactivate')" class="adm-bulk-btn warn" data-i18n="bulk_deactivate">قطع</button>
                    <button type="button" onclick="runBulkAction('reset_volume')" class="adm-bulk-btn" data-i18n="bulk_reset_vol">ریست حجم</button>
                    <button type="button" onclick="runBulkAction('reset_time')" class="adm-bulk-btn" data-i18n="bulk_reset_time">ریست زمان</button>
                    <button type="button" onclick="runBulkAction('reset_requests')" class="adm-bulk-btn" data-i18n="bulk_reset_req">ریست ریکوئست کل</button>
                    <button type="button" onclick="runBulkAction('enable_save')" class="adm-bulk-btn" data-i18n="bulk_save">ذخیره</button>
                    <button type="button" onclick="runBulkAction('delete')" class="adm-bulk-btn danger" data-i18n="bulk_delete">حذف</button>
                </div>
            </div>
        </div>
        <div class="adm-users-panel">
            <div class="adm-users-panel-head">
                <div>
                    <div class="adm-users-panel-title">
                        <span data-i18n="users_list_title">لیست کاربران</span>
                        <span class="adm-users-count-badge" id="users-count-badge">۰</span>
                    </div>
                    <p class="text-[10px] mt-1 adm-muted font-semibold tracking-wide" data-i18n="users_list_desc">مدیریت سرویس‌ها</p>
                </div>
                <div class="adm-users-panel-actions">
                    <label class="adm-users-select-all">
                        <input type="checkbox" id="select-all-users" class="adm-select-cb" onchange="toggleSelectAllFiltered(this.checked)" data-i18n-title="select_all" title="انتخاب همه">
                        <span data-i18n="select_all">انتخاب همه</span>
                    </label>
                    <button type="button" onclick="openCreateModal()" class="adm-users-add-btn" data-i18n-title="add_user" title="افزودن کاربر">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"></path></svg>
                        <span data-i18n="new_user">کاربر جدید</span>
                    </button>
                </div>
            </div>
            <div id="loading-state" class="adm-users-loading">
                <div class="adm-users-loading-spinner"></div>
                <span class="text-sm font-bold adm-muted" data-i18n="users_loading">در حال بارگذاری کاربران...</span>
            </div>
            <div id="users-cards-container" class="adm-user-cards hidden"></div>
            <div id="users-table-container" class="hidden adm-table-desktop adm-users-table-wrap">
            <table class="adm-users-table">
                <thead>
                    <tr>
                        <th class="w-10"><input type="checkbox" class="adm-select-cb" onchange="document.getElementById('select-all-users').checked=this.checked;toggleSelectAllFiltered(this.checked)" title="انتخاب همه"></th>
                        <th data-i18n="th_user_ops">نام کاربر و عملیات</th>
                        <th data-i18n="th_sub_link">لینک ساب</th>
                        <th data-i18n="th_protocol">پروتکل</th>
                        <th data-i18n="th_port">پورت</th>
                        <th data-i18n="th_volume">وضعیت حجم</th>
                        <th data-i18n="th_expiry">وضعیت اعتبار</th>
                        <th data-i18n="th_requests">مصرف ریکوئست</th>
                        <th data-i18n="th_created">تاریخ ساخت</th>
                    </tr>
                </thead>
                <tbody id="users-tbody"></tbody>
            </table>
            </div>
            <div id="empty-state" class="hidden adm-users-empty">
                <div class="adm-users-empty-icon">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
                </div>
                <p class="text-sm font-bold adm-muted">کاربری وجود ندارد</p>
                <p class="text-xs adm-muted">برای ساخت اولین کاربر روی «کاربر جدید» کلیک کنید</p>
                <button type="button" onclick="openCreateModal()" class="adm-users-add-btn mt-1">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"></path></svg>
                    افزودن کاربر
                </button>
            </div>
        </div>
    </div>
</div>
<div id="section-guide" class="adm-section">
    <div class="adm-guide-layout">
        <div class="adm-guide-card">
            <div class="adm-guide-toolbar">
                <div class="adm-guide-tabs">
                    <button type="button" data-i18n="guide_tab_android" onclick="showAdminGuideTab('android')" id="adm-guide-tab-android" class="adm-guide-tab active">اندروید</button>
                    <button type="button" data-i18n="guide_tab_ios"  onclick="showAdminGuideTab('ios')" id="adm-guide-tab-ios" class="adm-guide-tab">آیفون</button>
                    <button type="button" data-i18n="guide_tab_desktop" onclick="showAdminGuideTab('desktop')" id="adm-guide-tab-desktop" class="adm-guide-tab">ویندوز / مک</button>
                </div>
            </div>
            <div id="adm-guide-panel-android" class="adm-guide-body">
                <div class="adm-guide-section-title">راهنمای اتصال — اندروید</div>
                <div class="space-y-3">
                    <div class="adm-guide-step"><span class="adm-guide-step-num">1</span> اپ V2rayNG را از لینک زیر دانلود کنید:<br><a href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" rel="noopener noreferrer" class="adm-guide-link">https://github.com/2dust/v2rayNG/releases/latest</a></div>
                    <div class="adm-guide-step"><span class="adm-guide-step-num">2</span> اپ را باز کنید</div>
                    <div class="adm-guide-step"><span class="adm-guide-step-num">3</span> روی آیکون + در بالا راست بزنید</div>
                    <div class="adm-guide-step"><span class="adm-guide-step-num">4</span> گزینه <strong>Import config from clipboard</strong> را انتخاب کنید<br><span class="text-xs opacity-70">(لینک کانفیگ باید از قبل کپی شده باشد)</span></div>
                    <div class="adm-guide-step"><span class="adm-guide-step-num">5</span> کانفیگ در لیست ظاهر می‌شود — روی آن بزنید تا انتخاب شود</div>
                    <div class="adm-guide-step"><span class="adm-guide-step-num">6</span> دکمه اتصال پایین صفحه را بزنید، اکنون با موفقیت متصل شدید.</div>
                    <p class="text-center text-sm pt-2" style="color: var(--admin-muted)">نتوانستید متصل شوید؟ <a href="https://t.me/nexateam_bot" target="_blank" rel="noopener noreferrer" class="adm-guide-support">از قسمت پشتیبانی در بات کمک بگیرید</a></p>
                </div>
            </div>
            <div id="adm-guide-panel-ios" class="adm-guide-body hidden">
                <div class="adm-guide-section-title">راهنمای اتصال — آیفون (iOS)</div>
                <div class="space-y-3">
                    <div class="adm-guide-step"><span class="adm-guide-step-num">1</span> اپ Streisand را از App Store دانلود کنید:<br><a href="https://apps.apple.com/app/streisand/id6450534064" target="_blank" rel="noopener noreferrer" class="adm-guide-link">https://apps.apple.com/app/streisand/id6450534064</a></div>
                    <div class="adm-guide-step"><span class="adm-guide-step-num">2</span> اپ را باز کنید</div>
                    <div class="adm-guide-step"><span class="adm-guide-step-num">3</span> روی + در بالا راست بزنید</div>
                    <div class="adm-guide-step"><span class="adm-guide-step-num">4</span> گزینه <strong>Import from Clipboard</strong> را بزنید<br><span class="text-xs opacity-70">(لینک کانفیگ باید از قبل کپی شده باشد)</span></div>
                    <div class="adm-guide-step"><span class="adm-guide-step-num">5</span> کانفیگ اضافه شد — کنارش Connect را بزنید</div>
                    <div class="adm-guide-step"><span class="adm-guide-step-num">6</span> در پنجره‌ای که باز می‌شود Allow را بزنید</div>
                    <p class="text-center text-sm pt-2" style="color: var(--admin-muted)">نتوانستید متصل شوید؟ <a href="https://t.me/nexateam_bot" target="_blank" rel="noopener noreferrer" class="adm-guide-support">از قسمت پشتیبانی در بات کمک بگیرید</a></p>
                </div>
            </div>
            <div id="adm-guide-panel-desktop" class="adm-guide-body hidden">
                <div class="adm-guide-section-title">راهنمای اتصال — ویندوز / مک</div>
                <h4 class="text-sm font-bold mb-3" style="color: var(--admin-text)">ویندوز</h4>
                <div class="space-y-3 mb-6">
                    <div class="adm-guide-step"><span class="adm-guide-step-num">1</span> نرم‌افزار v2rayN را دانلود کنید:<br><a href="https://github.com/2dust/v2rayN/releases/latest" target="_blank" rel="noopener noreferrer" class="adm-guide-link">https://github.com/2dust/v2rayN/releases/latest</a></div>
                    <div class="adm-guide-step"><span class="adm-guide-step-num">2</span> فایل zip را extract کنید و v2rayN.exe را اجرا کنید</div>
                    <div class="adm-guide-step"><span class="adm-guide-step-num">3</span> در تسک‌بار روی آیکون برنامه راست‌کلیک کنید</div>
                    <div class="adm-guide-step"><span class="adm-guide-step-num">4</span> گزینه + را بزنید و نام دلخواه و لینک کپی شده را وارد کنید</div>
                    <div class="adm-guide-step"><span class="adm-guide-step-num">5</span> از منوی بالا روی گروه اشتراک زده و گزینه سوم را بزنید</div>
                    <div class="adm-guide-step"><span class="adm-guide-step-num">6</span> برای متصل شدن در پایین صفحه گزینه پاک کردن سیستم پروکسی را روی گزینه دوم بگذارید</div>
                </div>
                <h4 class="text-sm font-bold mb-3" style="color: var(--admin-text)">مک</h4>
                <div class="space-y-3">
                    <div class="adm-guide-step"><span class="adm-guide-step-num">1</span> اپ FoXray را از Mac App Store دانلود کنید</div>
                    <div class="adm-guide-step"><span class="adm-guide-step-num">2</span> روی + بزنید و Import from clipboard را انتخاب کنید</div>
                    <div class="adm-guide-step"><span class="adm-guide-step-num">3</span> کانفیگ را انتخاب و Connect بزنید</div>
                    <p class="text-center text-sm pt-2" style="color: var(--admin-muted)">نتوانستید متصل شوید؟ <a href="https://t.me/nexateam_bot" target="_blank" rel="noopener noreferrer" class="adm-guide-support">از قسمت پشتیبانی در بات کمک بگیرید</a></p>
                </div>
            </div>
        </div>
    </div>
</div>
<div id="section-node-server" class="adm-section">
    <div class="adm-node-card">
        <div class="adm-node-head">
            <div class="adm-node-head-main">
                <div class="adm-node-head-icon">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path></svg>
                </div>
                <div>
                    <h3 class="adm-node-title" data-i18n="node_server_title">نود اصلی</h3>
                    <p class="adm-node-desc" data-i18n="node_server_desc">نود شما روی همه‌ی پورت‌های TLS کلودفلر، با استفاده‌ی مستقیم از دامنه‌ی ورکر، جدا از اشتراک، هر پورت را کپی کنید.</p>
                </div>
            </div>
        </div>
        <div id="node-server-loading" class="adm-node-loading" data-i18n="loading">در حال بارگذاری...</div>
        <div id="node-server-empty" class="adm-node-empty hidden" data-i18n="node_server_empty">کانفیگ نودی در دسترس نیست</div>
        <div id="node-server-list" class="adm-node-list hidden"></div>
    </div>
</div>
<div id="section-ip-scanner" class="adm-section">
    <div class="adm-ip-scanner-wrap">
        <div class="adm-ip-scanner-panel hero">
            <h3 class="adm-ip-scanner-title" data-i18n="nav_ip_scanner">اسکنر IP تمیز</h3>
            <p class="adm-ip-scanner-sub" data-i18n="ip_scanner_desc">سریع‌ترین آی‌پی‌های تمیز کلودفلر را برای شبکه‌تان پیدا کنید</p>
            <div class="adm-ip-scanner-fields">
                <div class="adm-ip-scanner-field" style="flex:1 1 100%">
                    <label for="ip-scan-total" data-i18n="ip_scan_total">تعداد IP تست</label>
                    <input id="ip-scan-total" type="number" min="20" max="400" value="140">
                </div>
            </div>
            <div class="adm-ip-scanner-ports">
                <span class="adm-ip-scanner-ports-label" data-i18n="ip_scan_ports_label">پورت‌های اسکن</span>
                <div class="adm-ip-scanner-ports-grid" id="ip-scan-ports">
                    <label class="adm-ip-scanner-port-chip"><input type="checkbox" class="ip-scan-port-cb" value="443" checked><span>443</span></label>
                    <label class="adm-ip-scanner-port-chip"><input type="checkbox" class="ip-scan-port-cb" value="2053" checked><span>2053</span></label>
                    <label class="adm-ip-scanner-port-chip"><input type="checkbox" class="ip-scan-port-cb" value="2083" checked><span>2083</span></label>
                    <label class="adm-ip-scanner-port-chip"><input type="checkbox" class="ip-scan-port-cb" value="2087" checked><span>2087</span></label>
                    <label class="adm-ip-scanner-port-chip"><input type="checkbox" class="ip-scan-port-cb" value="2096" checked><span>2096</span></label>
                    <label class="adm-ip-scanner-port-chip"><input type="checkbox" class="ip-scan-port-cb" value="8443" checked><span>8443</span></label>
                </div>
            </div>
            <button type="button" id="ip-scan-run-btn" class="adm-ip-scanner-run" onclick="runCleanIpScanner()">
                <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                <span data-i18n="ip_scan_start">شروع اسکن</span>
            </button>
            <div class="adm-ip-scanner-bar" id="ip-scan-bar"><i></i></div>
            <div class="adm-ip-scanner-status" id="ip-scan-status" role="status"></div>
        </div>
        <div class="adm-ip-scanner-panel adm-ip-scanner-results" id="ip-scan-results-panel">
            <div class="adm-ip-scanner-results-head">
                <span class="adm-ip-scanner-results-title" data-i18n="ip_scan_results">نتایج آی‌پی تمیز</span>
                <span class="adm-ip-scanner-results-count" id="ip-scan-results-count"></span>
            </div>
            <div class="adm-ip-scanner-output" id="ip-scan-output"></div>
        </div>
        <div class="adm-ip-scanner-panel">
            <div class="adm-ip-scanner-results-head">
                <span class="adm-ip-scanner-section-title" data-i18n="ip_scan_source_title">منبع آی‌پی تمیز</span>
                <span class="adm-ip-scanner-section-count" id="ip-pool-count"></span>
            </div>
            <div class="adm-ip-source-tabs">
                <button type="button" id="ip-source-tab-smart" class="adm-ip-source-tab" onclick="setCleanIpSourceMode('smart')" data-i18n="ip_scan_source_smart">هوشمند</button>
                <button type="button" id="ip-source-tab-pool" class="adm-ip-source-tab active" onclick="setCleanIpSourceMode('pool')" data-i18n="ip_scan_source_pool">مخزن ایپی تمیز</button>
            </div>
            <div id="ip-source-smart-view">
                <p class="adm-ip-smart-desc" data-i18n="ip_scan_smart_desc">در حالت هوشمند، آی‌پی‌های تمیز از لینک زیر دریافت می‌شوند:</p>
                <span id="ip-smart-url-link" class="adm-ip-smart-link">${REMOTE_CLEAN_IPS_URL}</span>
            </div>
            <div id="ip-source-pool-view" class="hidden">
                <p class="adm-ip-scanner-sub" style="margin-bottom:0.75rem" data-i18n="ip_scan_pool_desc">مدیریت آی‌پی‌های ذخیره‌شده در مخزن پنل</p>
                <textarea id="ip-pool-textarea" class="adm-ip-pool-textarea" rows="10" spellcheck="false" autocomplete="off" dir="ltr" oninput="updateScannerPoolCount()" data-i18n-placeholder="ip_scan_pool_textarea_ph" placeholder="1.2.3.4&#10;1.2.3.4:443"></textarea>
                <div class="adm-ip-scanner-actions">
                    <button type="button" class="adm-ip-scanner-action primary" onclick="saveScannerPool()" data-i18n="ip_scan_pool_save">ذخیره مخزن</button>
                    <button type="button" class="adm-ip-scanner-action" onclick="clearScannerPool()" data-i18n="ip_scan_pool_clear">پاک کردن همه</button>
                </div>
            </div>
        </div>
        <p class="adm-ip-scanner-sub" style="text-align:center;margin-top:0.5rem" data-i18n="ip_scan_foot">اسکن کاملاً در مرورگر شما انجام می‌شود</p>
    </div>
</div>
<div id="section-cdn-proxy" class="adm-section">
    <div class="adm-ip-scanner-wrap">
        <div id="cdn-cf-token-banner" class="adm-cdn-cf-banner hidden">
            <p class="adm-cdn-cf-banner-text" data-i18n="cdn_cf_banner_text">برای بروزرسانی خودکار و نمایش «مصرف ورکر»، یک‌بار توکن Cloudflare را وصل کن، کمتر از یک دقیقه.</p>
            <div class="adm-cdn-cf-banner-actions">
                <button type="button" class="adm-ip-scanner-action primary" onclick="switchAdminSection('settings')" data-i18n="cdn_cf_connect">اتصال توکن</button>
                <button type="button" class="adm-cdn-cf-banner-close" onclick="dismissCdnCfBanner()" aria-label="×">×</button>
            </div>
        </div>
        <div class="adm-cdn-proxy-stack">
            <div class="adm-ip-scanner-panel adm-cdn-access-panel">
                <div class="adm-cdn-panel-head">
                    <span class="adm-cdn-panel-title">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z"></path></svg>
                        <span data-i18n="cdn_access_title">دسترسی CDN کلودفلر</span>
                    </span>
                </div>
                <p class="adm-ip-scanner-sub" style="margin-bottom:0.75rem" data-i18n="cdn_access_desc">از بخش یافتن پروکسی میتوانید پروکسی ایپی مد نظر خود را دریافت کنید.</p>
                <div class="adm-cdn-fields">
                    <div class="adm-cdn-field">
                        <label for="cdn-proxy-mode" data-i18n="cdn_mode_label">حالت</label>
                        <select id="cdn-proxy-mode" class="admin-input w-full px-3 py-2.5 text-sm" onchange="cdnProxyApplyMode()">
                            <option value="proxyip">PROXYIP</option>
                        </select>
                    </div>
                </div>
                <div class="adm-cdn-sec" id="cdn-sec-proxyip">
                    <div class="adm-cdn-field">
                        <label for="cdn-proxyip-input" data-i18n="cdn_proxyip_label">آدرس PROXYIP (هر خط یک پروکسی)</label>
                        <textarea id="cdn-proxyip-input" dir="ltr" rows="4" placeholder="auto&#10;1.2.3.4#DE&#10;5.6.7.8:443#FR" class="admin-input w-full px-3 py-2.5 text-xs font-mono"></textarea>
                        <p class="adm-cdn-field-hint" data-i18n-html="cdn_proxyip_hint">هر خط = یک لوکیشن. اگه می‌خوای پرچم کشورش هم توی اسم کانفیگ بیاد، انتهای اون خط بنویس <code>#کدکشور</code> (مثال: <code>1.2.3.4#DE</code> یا <code>5.6.7.8:2053#US</code>)</p>
                    </div>
                </div>
                <div class="adm-ip-scanner-actions" style="margin-top:0.85rem">
                    <button type="button" class="adm-ip-scanner-action primary" onclick="saveCdnProxySettings()" id="save-cdn-proxy-btn" data-i18n="cdn_save">ذخیره</button>
                </div>
                <div class="adm-cdn-msg info" id="cdn-proxy-msg"></div>
            </div>
            <div class="adm-ip-scanner-panel adm-cdn-finder-panel">
                <div class="adm-cdn-panel-head">
                    <span class="adm-cdn-panel-title" data-i18n="cdn_finder_title">یافتن پروکسی</span>
                    <button type="button" class="adm-ip-scanner-action" onclick="loadCdnProxyPublicList()" id="cdn-proxy-list-btn" data-i18n="cdn_finder_load">دریافت فهرست</button>
                </div>
                <p class="adm-ip-scanner-sub" style="margin-bottom:0.75rem" data-i18n="cdn_finder_desc">شما میتوانید با لود فهرست ها از پروکسی 68 کشور استفاده کنید. </p>
                <div class="adm-cdn-fields two-col">
                    <div class="adm-cdn-field">
                        <label for="cdn-proxy-country" data-i18n="cdn_country_label">کشور</label>
                        <select id="cdn-proxy-country" class="admin-input w-full px-3 py-2.5 text-sm" onchange="cdnProxyCountryChange()">
                            <option value="">-</option>
                        </select>
                    </div>
                    <div class="adm-cdn-field">
                        <label for="cdn-proxy-pick" data-i18n="cdn_pick_label">پروکسی</label>
                        <select id="cdn-proxy-pick" class="admin-input w-full px-3 py-2.5 text-sm" onchange="cdnProxyUpdateUseBtn()">
                            <option value="">-</option>
                        </select>
                    </div>
                </div>
                <div class="adm-ip-scanner-actions" style="margin-top:0.85rem">
                    <button type="button" class="adm-ip-scanner-action primary" onclick="useCdnProxySelection()" id="cdn-proxy-use-btn" disabled data-i18n="cdn_use_selected">استفاده از انتخاب</button>
                </div>
                <div class="adm-cdn-msg info" id="cdn-proxy-more-msg"></div>
            </div>
        </div>
    </div>
</div>
<div id="section-logs" class="adm-section">
    <div class="adm-tg-card">
        <div class="flex items-center justify-between gap-3 mb-4">
            <h3 class="text-base font-black" style="color: var(--admin-text)" data-i18n="tg_notify_title">اعلان‌های تلگرام</h3>
            <span id="tg-notify-badge" class="text-xs font-bold px-2.5 py-1 rounded-full bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800">● <span data-i18n="tg_status_off">خاموش</span></span>
        </div>
        <div class="flex items-center justify-between gap-3 mb-4">
            <span class="text-sm font-bold" style="color: var(--admin-text)" data-i18n="tg_enable">فعال‌سازی اعلان تلگرام</span>
            <div id="tg-notify-toggle" class="adm-tg-toggle" onclick="toggleTgNotifySwitch()" role="switch" aria-checked="false"></div>
        </div>
        <div class="space-y-4">
            <div>
                <label class="block text-sm font-medium mb-1.5" style="color: var(--admin-muted)" data-i18n="tg_token">توکن ربات</label>
                <input type="text" id="tg-bot-token" dir="ltr" placeholder="123456789:ABC..." class="admin-input w-full px-3 py-2.5 text-sm font-mono" oninput="scheduleTelegramSave()" onblur="saveTelegramNotify(true)">
            </div>
            <div>
                <label class="block text-sm font-medium mb-1.5" style="color: var(--admin-muted)" data-i18n="tg_chat_id">شناسه چت / کاربر</label>
                <textarea id="tg-chat-ids" rows="3" dir="ltr" placeholder="123456789&#10;-1001234567890" class="admin-input w-full px-3 py-2.5 text-sm font-mono" oninput="scheduleTelegramSave()" onblur="saveTelegramNotify(true)"></textarea>
                <p class="text-[11px] mt-1.5" style="color: var(--admin-muted)" data-i18n-html="tg_chat_hint">برای دریافت شناسه چت خود به بات ما مراجعه کنید و ایدی عددی خود را دریافت کنید . ادرس بات : <a href="https://t.me/nexateam_bot" target="_blank" rel="noopener noreferrer">برای انتقال به بات تلگرام کلیک کنید .</a></p>
            </div>
            <button type="button" onclick="saveTelegramNotify()" id="save-tg-notify-btn" class="admin-btn-primary px-5 py-2.5 text-sm font-bold" data-i18n="save">ذخیره</button>
        </div>
    </div>
    <div class="admin-card overflow-hidden">
        <div class="px-5 py-4 border-b flex flex-wrap items-center justify-between gap-3" style="border-color: var(--admin-border)">
            <p class="text-sm" style="color: var(--admin-muted)" data-i18n="logs_desc">تمام رویدادهای مهم پنل</p>
            <div class="flex items-center gap-2">
                <span id="admin-log-count" class="text-xs font-bold admin-brand px-3 py-1 rounded-full" style="background: var(--admin-primary-soft)">۰</span>
                <button type="button" onclick="loadAdminLogs()" class="admin-btn-icon px-3 py-2 text-xs font-bold" data-i18n="refresh">بروزرسانی</button>
                <button type="button" onclick="clearAdminLogs()" class="admin-btn-icon px-3 py-2 text-xs font-bold text-red-500" data-i18n="clear_logs">حذف همه</button>
            </div>
        </div>
        <div id="admin-logs-loading" class="p-8 text-center text-sm" style="color: var(--admin-muted)" data-i18n="loading">در حال بارگذاری...</div>
        <div id="admin-logs-empty" class="hidden p-10 text-center text-sm" style="color: var(--admin-muted)" data-i18n="logs_empty">هنوز رویدادی ثبت نشده است.</div>
        <div class="overflow-x-auto">
            <table class="w-full text-sm hidden" id="admin-logs-table">
                <thead class="admin-table-head">
                    <tr>
                        <th class="px-4 py-3 text-right font-bold whitespace-nowrap" data-i18n="col_time">زمان</th>
                        <th class="px-4 py-3 text-right font-bold whitespace-nowrap" data-i18n="col_action">عملیات</th>
                        <th class="px-4 py-3 text-right font-bold" data-i18n="col_details">جزئیات</th>
                        <th class="px-4 py-3 text-right font-bold whitespace-nowrap">IP</th>
                    </tr>
                </thead>
                <tbody id="admin-logs-body" class="divide-y" style="divide-color: var(--admin-border)"></tbody>
            </table>
        </div>
    </div>
</div>
<div id="section-settings" class="adm-section">
    <div class="adm-settings-stack">
    <div class="admin-card p-6" id="panel-update-card">
        <h3 class="text-lg font-black mb-2" style="color: var(--admin-text)" data-i18n="panel_update_title">به‌روزرسانی پنل</h3>
        <p class="text-sm mb-1" style="color: var(--admin-muted)" data-i18n="panel_update_desc">نسخه جدید از سرور دریافت و پنل شما اپدیت و ویژگی های جدید اضافه خواهد شد.</p>
        <div class="adm-panel-update-versions">
            <div class="adm-panel-update-ver">
                <span data-i18n="panel_update_current">نسخه فعلی</span>
                <strong id="panel-update-current-ver">${PANEL_VERSION}</strong>
            </div>
            <div class="adm-panel-update-ver">
                <span data-i18n="panel_update_remote">نسخه سرور</span>
                <strong id="panel-update-remote-ver">—</strong>
            </div>
        </div>
        <p id="panel-update-status" class="text-xs mt-3" style="color: var(--admin-muted)"></p>
        <button type="button" onclick="triggerPanelUpdate()" id="panel-update-btn" class="admin-btn-primary w-full py-2.5 text-sm font-bold mt-4" data-i18n="panel_update_btn">به‌روزرسانی پنل</button>
    </div>
    <div class="admin-card p-6 space-y-4">
        <h3 class="text-lg font-black mb-1" style="color: var(--admin-text)" data-i18n="wc_protocol_title">تنظیمات ادرس صفحات</h3>
        <p class="text-xs mb-2" style="color: var(--admin-muted)" data-i18n="wc_protocol_desc">تنظیمات پروتکل، انتقال و مسیر اتصال کانفیگ‌ها</p>
        <div>
            <label class="block text-sm font-medium mb-1.5" style="color: var(--admin-muted)" data-i18n="wc_transport_path_label">مسیر انتقال</label>
            <input type="text" id="wc-transport-path" dir="ltr" class="admin-input w-full px-3 py-2.5 text-sm font-mono">
        </div>
        <div class="grid sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-2 border-t" style="border-color: var(--admin-border)">
            <div>
                <label class="block text-sm font-medium mb-1.5" style="color: var(--admin-muted)" data-i18n="wc_admin_page_path_label">آدرس پنل مدیریت</label>
                <input type="text" id="wc-admin-page-path" dir="ltr" class="admin-input w-full px-3 py-2.5 text-sm font-mono">
                <p class="text-xs mt-1.5" style="color: var(--admin-muted)" data-i18n="wc_path_empty_hint">خالی = پیش‌فرض</p>
            </div>
            <div>
                <label class="block text-sm font-medium mb-1.5" style="color: var(--admin-muted)" data-i18n="wc_status_path_label">آدرس صفحه وضعیت</label>
                <input type="text" id="wc-status-page-path" dir="ltr" class="admin-input w-full px-3 py-2.5 text-sm font-mono">
                <p class="text-xs mt-1.5" style="color: var(--admin-muted)" data-i18n="wc_path_empty_hint">خالی = پیش‌فرض</p>
            </div>
            <div>
                <label class="block text-sm font-medium mb-1.5" style="color: var(--admin-muted)" data-i18n="wc_sub_page_path_label">آدرس صفحه ساب</label>
                <input type="text" id="wc-sub-page-path" dir="ltr" class="admin-input w-full px-3 py-2.5 text-sm font-mono">
                <p class="text-xs mt-1.5" style="color: var(--admin-muted)" data-i18n="wc_sub_page_path_hint">مثال : /sub/(اسم سرویس)</p>
            </div>
            <div>
                <label class="block text-sm font-medium mb-1.5" style="color: var(--admin-muted)" data-i18n="wc_logs_page_path_label">آدرس صفحه لاگ‌ها</label>
                <input type="text" id="wc-logs-page-path" dir="ltr" class="admin-input w-full px-3 py-2.5 text-sm font-mono">
                <p class="text-xs mt-1.5" style="color: var(--admin-muted)" data-i18n="wc_logs_page_path_hint">مثال : /logs/(نام سرویس)</p>
            </div>
        </div>
        <div id="wc-admin-path-changed-banner" class="hidden text-xs rounded-xl px-3 py-2.5 font-bold" style="background: color-mix(in srgb, #f59e0b 12%, transparent); color: #b45309;"></div>
    </div>

    <div class="admin-card p-6 space-y-4">
        <h3 class="text-lg font-black mb-1" style="color: var(--admin-text)" data-i18n="wc_naming_title">نام‌گذاری کانفیگ‌ها</h3>
        <p class="text-xs mb-2" style="color: var(--admin-muted)" data-i18n="wc_naming_desc">در این بخش میتوانید نام کانفیگ ها را با متغیر های ارائه شده نامگذاری کنید.</p>
        <div>
            <label class="block text-sm font-medium mb-1.5" style="color: var(--admin-muted)" data-i18n="wc_first_remark_label">کانفیگ اول (غیرقابل تغییر)</label>
            <textarea id="wc-first-remark" rows="2" readonly class="admin-input w-full px-3 py-2.5 text-xs opacity-80"></textarea>
        </div>
        <div>
            <label class="block text-sm font-medium mb-1.5" style="color: var(--admin-muted)" data-i18n="wc_info_remark_label">کانفیگ مشخصات سرویس</label>
            <input type="text" id="wc-info-remark" class="admin-input w-full px-3 py-2.5 text-sm">
            <div class="text-xs mt-2 space-y-1" style="color: var(--admin-muted)">
                <div><code>{username}</code> — <span data-i18n="wc_var_username">نام کاربری سرویس</span></div>
                <div><code>{used}</code> — <span data-i18n="wc_var_used">حجم مصرف‌شده تا این لحظه</span></div>
                <div><code>{total}</code> — <span data-i18n="wc_var_total">حجم کل سرویس (∞ یعنی نامحدود)</span></div>
                <div><code>{dayremind}</code> — <span data-i18n="wc_var_dayremind">تعداد روزهای باقی‌مانده تا انقضا</span></div>
                <div><code>{expiry}</code> — <span data-i18n="wc_var_expiry">کل مدت اعتبار به روز (∞ یعنی نامحدود)</span></div>
                <div><code>{port}</code> — <span data-i18n="wc_var_port">پورتی که این کانفیگ خاص روی آن ساخته شده</span></div>
                <div><code>{proxyip}</code> — <span data-i18n="wc_var_proxyip">آدرس Proxy IP فعلیِ تنظیم‌شده در بخش «پروکسی CDN»</span></div>
                <div><code>{flag}</code> — <span data-i18n="wc_var_flag">پرچم کشوری که برای این پروکسی مشخص کردی (فرمت #کدکشور جلوی آی‌پی)</span></div>
            </div>
        </div>
        <div>
            <label class="block text-sm font-medium mb-1.5" style="color: var(--admin-muted)" data-i18n="wc_node_remark_label">نام کانفیگ‌های اتصال</label>
            <input type="text" id="wc-node-remark" class="admin-input w-full px-3 py-2.5 text-sm">
        </div>
        <button type="button" onclick="saveWorkerConfig()" id="save-worker-config-btn" class="admin-btn-primary w-full py-2.5 text-sm font-bold" data-i18n="wc_save_btn">ذخیره تنظیمات </button>
    </div>
    <div class="admin-card p-6">
        <h3 class="text-lg font-black mb-2" style="color: var(--admin-text)" data-i18n="nav_backup">بکاپ پنل</h3>
        <p class="text-sm mb-2" style="color: var(--admin-muted)" data-i18n="backup_desc">کاربران، تمام تنظیمات پنل، لاگ فعالیت و لاگ اتصال را دانلود یا بازیابی کنید.</p>
        <p class="text-xs mb-4 rounded-xl px-3 py-2" style="color: var(--admin-muted); background: var(--admin-primary-soft)" data-i18n="backup_includes">تمام بخش های پنل شامل میشود.</p>
        <div class="grid sm:grid-cols-2 gap-4">
            <button type="button" onclick="downloadBackup()" id="backup-download-btn" class="admin-card p-5 flex flex-col items-center gap-3 hover:border-emerald-400 transition">
                <div class="p-3 rounded-xl" style="background: var(--admin-primary-soft); color: var(--admin-primary)">
                    <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path></svg>
                </div>
                <span class="text-sm font-bold" data-i18n="backup_download">دریافت بکاپ</span>
            </button>
            <label id="backup-upload-btn" class="admin-card p-5 flex flex-col items-center gap-3 hover:border-emerald-400 transition cursor-pointer">
                <div class="p-3 rounded-xl" style="background: var(--admin-primary-soft); color: var(--admin-primary)">
                    <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M7.5 12L12 16.5m0 0L16.5 12M12 7.5v9"></path></svg>
                </div>
                <span class="text-sm font-bold" data-i18n="backup_upload">بارگذاری بکاپ</span>
                <input type="file" id="backup-file-input" accept=".json,application/json" class="hidden" onchange="restoreBackup(event)">
            </label>
        </div>
        <div class="mt-6 pt-6 border-t space-y-4" style="border-color: var(--admin-border)">
            <div class="flex items-center justify-between gap-3">
                <div>
                    <h4 class="text-sm font-bold" style="color: var(--admin-text)" data-i18n="backup_auto_title">بکاپ خودکار روزانه</h4>
                    <p class="text-xs mt-1" style="color: var(--admin-muted)" data-i18n="backup_auto_desc">هر روز ساعت ۰۰:۰۰ (به وقت تهران) بکاپ کامل به تلگرام ارسال می‌شود — نیاز به تنظیم توکن و شناسه چت در بخش لاگ فعالیت دارد.</p>
                </div>
                <div id="backup-auto-toggle" class="adm-tg-toggle" onclick="toggleBackupAutoSwitch()" role="switch" aria-checked="false"></div>
            </div>
            <div id="backup-auto-status" class="text-xs rounded-xl px-3 py-2.5 hidden" style="background: var(--admin-primary-soft); color: var(--admin-muted)"></div>
            <div id="backup-tg-hint" class="text-xs rounded-xl px-3 py-2.5 hidden" style="background: color-mix(in srgb, #f59e0b 12%, transparent); color: var(--admin-muted)" data-i18n="backup_tg_hint">برای ارسال بکاپ، ابتدا توکن ربات و شناسه چت را در بخش «لاگ فعالیت» تنظیم کنید.</div>
            <p class="text-[11px]" style="color: var(--admin-muted)" data-i18n="backup_cron_hint">برای اجرای دقیق ساعت ۰۰:۰۰، در Cloudflare Workers یک Cron Trigger با مقدار <code dir="ltr">30 20 * * *</code> اضافه کنید.</p>
            <button type="button" onclick="sendBackupToTelegram()" id="backup-tg-send-btn" class="admin-btn-primary w-full py-2.5 text-sm font-bold" data-i18n="backup_tg_send">ارسال بکاپ به تلگرام (تست)</button>
        </div>
        <div class="mt-6 pt-6 border-t" style="border-color: var(--admin-border)">
            <h4 class="text-sm font-bold mb-2" style="color: var(--admin-text)" data-i18n="reset_panel_title">بازنشانی تمام تنظیمات</h4>
            <p class="text-xs mb-4" style="color: var(--admin-muted)" data-i18n="reset_panel_desc">تمام کاربران، تنظیمات پروکسی، اعلان تلگرام و لاگ‌ها حذف می‌شوند. پنل مانند اولین ورود خواهد بود. رمز عبور مدیریت حفظ می‌شود.</p>
            <button type="button" onclick="resetAllSettings()" id="reset-panel-btn" class="w-full py-2.5 text-sm font-bold rounded-xl border transition text-red-600 hover:bg-red-50 dark:hover:bg-red-950/30" style="border-color: color-mix(in srgb, #ef4444 40%, var(--admin-border))" data-i18n="reset_panel_btn">بازنشانی تمام تنظیمات</button>
        </div>
    </div>
    <div class="admin-card p-6 space-y-4">
        <h3 class="text-lg font-black mb-2" style="color: var(--admin-text)" data-i18n="blocked_domains_title">مسدودسازی دامنه</h3>
        <p class="text-xs leading-relaxed" style="color: var(--admin-muted)" data-i18n="blocked_domains_desc">دامنه‌هایی که وارد کنید از طریق پروکسی باز نمی‌شوند. هر دامنه در یک خط.</p>
        <div class="flex items-center justify-between gap-3">
            <span class="text-sm font-bold" style="color: var(--admin-text)" data-i18n="blocked_domains_enable">فعال‌سازی مسدودسازی</span>
            <div id="blocked-domains-toggle" class="adm-tg-toggle" onclick="toggleBlockedDomainsSwitch()" role="switch" aria-checked="false"></div>
        </div>
        <div>
            <label class="block text-sm font-medium mb-1.5" style="color: var(--admin-muted)" data-i18n="blocked_domains_label">لیست دامنه‌های مسدود</label>
            <textarea id="blocked-domains-input" rows="4" dir="ltr" placeholder="example.com" class="admin-input w-full px-3 py-2.5 text-xs font-mono"></textarea>
            <p class="text-xs mt-1.5" style="color: var(--admin-muted)" data-i18n="blocked_domains_hint">مثال: example.com — زیردامنه‌ها هم مسدود می‌شوند</p>
        </div>
        <button type="button" onclick="saveBlockedDomains()" id="save-blocked-domains-btn" class="admin-btn-primary w-full py-2.5 text-sm font-bold" data-i18n="blocked_domains_save">ذخیره مسدودسازی</button>
        <div class="pt-4 mt-2 border-t" style="border-color: var(--admin-border)">
            <h4 class="text-sm font-black mb-2" style="color: var(--admin-text)" data-i18n="adult_block_title">مسدودسازی محتوای بزرگسال</h4>
            <div class="flex items-center justify-between gap-3">
                <span class="text-sm font-bold" style="color: var(--admin-text)" data-i18n="adult_block_label">فیلتر کردن محتوای بزرگ سال (+18)</span>
                <div id="adult-block-toggle" class="adm-tg-toggle" onclick="toggleAdultBlockSwitch()" role="switch" aria-checked="false"></div>
            </div>
            <button type="button" onclick="saveContentPolicy()" id="save-content-policy-btn" class="admin-btn-primary w-full py-2.5 text-sm font-bold mt-3" data-i18n="adult_block_save">ذخیره مسدودسازی بزرگسال</button>
        </div>
    </div>
    <div class="admin-card p-6 space-y-3">
        <h4 class="text-sm font-bold" style="color: var(--admin-text)" data-i18n="cf_creds_title">تنظیمات Cloudflare API</h4>
        <p class="text-xs" style="color: var(--admin-muted)" data-i18n="cf_creds_note">فقط CF_TOKEN را وارد کنید — Account ID خودکار از توکن دریافت و در ورکر ذخیره می‌شود.</p>
        <div>
            <label class="block text-sm font-medium mb-1.5" style="color: var(--admin-muted)" data-i18n="cf_token_label">CF_TOKEN</label>
            <input type="password" id="cf-token-input" dir="ltr" autocomplete="off" placeholder="Cloudflare API Token" class="admin-input w-full px-3 py-2.5 text-sm font-mono">
            <p id="cf-token-hint" class="hidden text-xs mt-1.5" style="color: var(--admin-muted)"></p>
        </div>
        <div>
            <label class="block text-sm font-medium mb-1.5" style="color: var(--admin-muted)" data-i18n="cf_ac_id_label">Account ID</label>
            <input type="text" id="cf-account-id-input" dir="ltr" autocomplete="off" placeholder="خودکار از توکن دریافت می‌شود" readonly class="admin-input w-full px-3 py-2.5 text-sm font-mono" style="opacity:0.85">
            <p id="cf-account-id-hint" class="text-xs mt-1.5" style="color: var(--admin-muted)" data-i18n="cf_ac_id_auto_hint">نیازی به وارد کردن دستی نیست</p>
        </div>
        <p id="cf-creds-error" class="hidden text-sm rounded-xl p-3" style="background: color-mix(in srgb, #ef4444 12%, var(--admin-card)); color: #dc2626; border: 1px solid color-mix(in srgb, #ef4444 30%, var(--admin-border));"></p>
        <button type="button" onclick="saveCfCredentials()" id="cf-creds-save-btn" class="admin-btn-primary w-full py-2.5 text-sm font-bold" data-i18n="cf_creds_save">ذخیره توکن</button>
    </div>
    <div class="admin-card p-6 space-y-3">
        <h4 class="text-sm font-bold" style="color: var(--admin-text)" data-i18n="pwd_info_title">تغییر رمز عبور مدیریت</h4>
        <p class="text-xs" style="color: var(--admin-muted)" data-i18n="pwd_storage_note">رمز عبور در متغیر ADMIN (نوع Text) در Cloudflare Workers ذخیره می‌شود.</p>
        <div>
            <label class="block text-sm font-medium mb-1.5" style="color: var(--admin-muted)" data-i18n="pwd_current_label">رمز عبور فعلی</label>
            <input type="password" id="pwd-current" autocomplete="current-password" class="admin-input w-full px-3 py-2.5 text-sm">
        </div>
        <div>
            <label class="block text-sm font-medium mb-1.5" style="color: var(--admin-muted)" data-i18n="pwd_new_label">رمز عبور جدید</label>
            <input type="password" id="pwd-new" minlength="4" autocomplete="new-password" class="admin-input w-full px-3 py-2.5 text-sm">
        </div>
        <div>
            <label class="block text-sm font-medium mb-1.5" style="color: var(--admin-muted)" data-i18n="pwd_confirm_label">تکرار رمز جدید</label>
            <input type="password" id="pwd-confirm" minlength="4" autocomplete="new-password" class="admin-input w-full px-3 py-2.5 text-sm">
        </div>
        <p id="pwd-change-error" class="hidden text-sm rounded-xl p-3" style="background: color-mix(in srgb, #ef4444 12%, var(--admin-card)); color: #dc2626; border: 1px solid color-mix(in srgb, #ef4444 30%, var(--admin-border));"></p>
        <button type="button" onclick="changeAdminPassword()" id="pwd-change-btn" class="admin-btn-primary w-full py-2.5 text-sm font-bold" data-i18n="pwd_change_btn">تغییر رمز عبور</button>
    </div>
    </div>
</div>
<div id="section-panel-control" class="adm-section">
    <div class="adm-settings-stack">
        <div class="admin-card p-6">
            <h3 class="text-lg font-black mb-2" style="color: var(--admin-text)" data-i18n="panel_control_restart_title">ری‌استارت پنل</h3>
            <p class="text-sm mb-4" style="color: var(--admin-muted)" data-i18n="panel_control_restart_desc">شمارشگر آپتایم و کش‌های موقت داخلی ورکر پاک‌سازی می‌شود. کاربران و تنظیمات شما دست‌نخورده باقی می‌مانند.</p>
            <button type="button" onclick="restartPanelAction()" id="panel-restart-btn" class="admin-btn-primary w-full py-2.5 text-sm font-bold" data-i18n="panel_control_restart_btn">ری‌استارت پنل</button>
        </div>
        <div class="admin-card p-6">
            <div class="flex items-center justify-between gap-3">
                <span class="text-sm font-bold" style="color: var(--admin-text)" data-i18n="panel_control_disable_label">خاموش کردن پنل مدیریت</span>
                <div id="panel-disabled-toggle" class="adm-tg-toggle" onclick="togglePanelDisabledSwitch()" role="switch" aria-checked="false"></div>
            </div>
            <p class="text-xs leading-relaxed mt-3" style="color: var(--admin-muted)" data-i18n="panel_control_disable_desc">با فعال شدن این گزینه، صفحه ورود و پنل مدیریت برای همه غیرقابل دسترسی می‌شود و صفحه وضعیت Nexa نمایش داده می‌شود. سرویس‌های VPN فعال باقی می‌مانند. برای بازگشت، آدرس را با <code dir="ltr">?unlock=1</code> باز کنید (مثال: <code dir="ltr">/admin?unlock=1</code>).</p>
        </div>
        <div class="admin-card p-6">
            <div class="flex items-center justify-between gap-3">
                <span class="text-sm font-bold" style="color: var(--admin-text)" data-i18n="kill_all_services_label">قطع تمامی سرویس‌ها</span>
                <div id="all-services-off-toggle" class="adm-tg-toggle" onclick="toggleAllServicesOffSwitch()" role="switch" aria-checked="false"></div>
            </div>
            <p class="text-xs leading-relaxed mt-3" style="color: var(--admin-muted)" data-i18n="kill_all_services_desc">با روشن شدن این گزینه تمامی سرویس‌ها متوقف و قطع خواهند شد در صورتی که مورد سو استفاده قرار گرفتید این گزینه را روشن کنید و با عوض کردن ادرس ها پنل خود را امن کنید .</p>
        </div>
    </div>
</div>
<div id="section-about" class="adm-section">
    <div class="adm-about-wrap">
        <div class="admin-card adm-about-hero">
            <div class="adm-about-logo">
                <img src="${NEXA_LOGO_URL}" alt="Nexa Panel">
            </div>
            <span class="adm-about-kicker" data-i18n="about_kicker">تیم توسعه‌ی زیرساخت آزاد</span>
            <h2 class="adm-about-hero-title" data-i18n="about_hero_title">عبور از فیلترینگ، با پنل خودت</h2>
            <p class="adm-about-hero-desc" data-i18n="about_hero_desc">NEXA گروهی از توسعه‌دهنده‌هاست که ابزارهای متن‌باز برای دسترسی آزاد به اینترنت می‌سازد — روی زیرساخت Cloudflare Workers، بدون واسطه، بدون فروش کانفیگ، و کاملاً در اختیار خودت.</p>
        </div>
        <div class="admin-card adm-about-social-card">
            <p class="text-sm font-black mb-1" style="color: var(--admin-text)" data-i18n="about_social">ما را در شبکه‌های اجتماعی دنبال کنید</p>
            <p class="adm-about-social-desc" data-i18n="about_social_desc">آموزش‌ها، به‌روزرسانی‌ها و اخبار تیم NEXA را از یوتیوب و تلگرام دنبال کن.</p>
            <div class="adm-about-social-row">
                <a href="https://www.irnexa.workers.dev/" target="_blank" rel="noopener noreferrer" class="adm-social-icon-btn web" title="وبسایت NEXA">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path></svg>
                </a>
                <a href="https://t.me/irnexa" target="_blank" rel="noopener noreferrer" class="adm-social-icon-btn tg" title="کانال تلگرام Nexa">
                    <svg viewBox="0 0 24 24" fill="currentColor"><path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/></svg>
                </a>
                <a href="https://www.youtube.com/@IR_NEXA" target="_blank" rel="noopener noreferrer" class="adm-social-icon-btn yt" title="YouTube">
                    <svg viewBox="0 0 24 24" fill="currentColor"><path d="M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z"/></svg>
                </a>
                <a href="https://github.com/farzadqavidel/nexa-panel" target="_blank" rel="noopener noreferrer" class="adm-social-icon-btn" title="GitHub">
                    <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
                </a>
            </div>
        </div>
        <div class="admin-card adm-about-main">
            <span class="adm-about-kicker" data-i18n="about_kicker2">درباره‌ی نکسا</span>
            <h3 class="adm-about-main-title" data-i18n="about_title">پنل شخصی، بدون واسطه و هزینه</h3>
            <p class="adm-about-main-desc" data-i18n="about_desc">NEXA به جای فروش سرویس، ابزار عمومی در اختیار می‌گذارد. هرکسی می‌تواند در چند دقیقه، روی اکانت Cloudflare خودش، پنل مدیریت اتصال شخصی‌اش را بالا بیاورد؛ سریع، پایدار و بدون نیاز به اعتماد به یک سرور واسط.</p>
            <div class="adm-about-features">
                <div class="adm-about-feature">
                    <div class="adm-about-feature-icon">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 18l6-6-6-6M8 6l-6 6 6 6"></path></svg>
                    </div>
                    <h4 data-i18n="about_f1_title">متن‌باز و شفاف</h4>
                    <p data-i18n="about_f1_desc">کد پنل کاملاً قابل مشاهده است؛ هرچه در پنل اجرا می‌شود را می‌توانی پیش از استفاده بررسی کنی.</p>
                </div>
                <div class="adm-about-feature">
                    <div class="adm-about-feature-icon">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                    </div>
                    <h4 data-i18n="about_f2_title">زیرساخت خودت</h4>
                    <p data-i18n="about_f2_desc">پنل روی حساب Cloudflare شخصی تو اجرا می‌شود؛ داده‌ها و اتصال‌ها از کانال هیچ سرور واسطی عبور نمی‌کند.</p>
                </div>
                <div class="adm-about-feature">
                    <div class="adm-about-feature-icon">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    </div>
                    <h4 data-i18n="about_f3_title">راه‌اندازی سریع</h4>
                    <p data-i18n="about_f3_desc">در کمتر از پنج دقیقه، بدون دانش عمیق برنامه‌نویسی، پنل شخصی‌ات آماده و در دسترس است.</p>
                </div>
                <div class="adm-about-feature">
                    <div class="adm-about-feature-icon">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z"></path></svg>
                    </div>
                    <h4 data-i18n="about_f4_title">بدون قصد فروش</h4>
                    <p data-i18n="about_f4_desc">هدف NEXA آموزش و در دسترس گذاشتن ابزار است، نه فروش کانفیگ یا اشتراک اینترنت.</p>
                </div>
            </div>
        </div>
    </div>
</div>
        </main>
    </div>
<div id="usage-warning-modal" class="fixed inset-0 z-[80] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out">
    <div class="w-full max-w-md bg-white dark:bg-amoled-card border border-orange-500/50 rounded-3xl shadow-2xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
        <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-orange-100 dark:bg-orange-900/30 text-orange-500 mb-4 shadow-inner">
            <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
        </div>
        <h3 class="font-black text-xl text-gray-900 dark:text-white mb-2">هشدار محدودیت درخواست روزانه</h3>
        <p class="text-sm text-gray-600 dark:text-gray-400 mb-6 leading-relaxed font-medium">
            درخواست‌های امروز کلودفلر شما از مرز ۹۰,۰۰۰ عبور کرده است. در صورت عبور از محدودیت رایگان ۱۰۰,۰۰۰ درخواست، دسترسی به پنل و اتصالات تا ساعت ۳:۳۰ بامداد (به وقت ایران) قطع خواهد شد.
        </p>
        <button onclick="closeUsageWarning()" class="w-full py-3.5 bg-orange-600 hover:bg-orange-700 text-white font-black rounded-xl text-sm transition duration-300 shadow-lg shadow-orange-500/25">
            متوجه شدم
        </button>
    </div>
</div>
    <div id="user-modal" class="adm-um-overlay" onclick="if(event.target===this)toggleModal(false)">
        <div id="user-modal-card" class="adm-um-dialog">
            <div class="adm-um-header">
                <div class="adm-um-header-start">
                    <div class="adm-um-header-icon">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z"></path></svg>
                    </div>
                    <div>
                        <h3 id="modal-title" class="adm-um-title">ایجاد کاربر جدید</h3>
                        <p id="modal-subtitle" class="adm-um-subtitle">تنظیمات سرویس VPN را وارد کنید</p>
                    </div>
                </div>
                <button type="button" onclick="toggleModal(false)" class="adm-um-close" aria-label="بستن">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <form id="create-user-form" class="adm-um-form" onsubmit="handleFormSubmit(event)">
                <div class="adm-um-body">
                <div class="adm-um-section" id="um-section-basic">
                    <div class="adm-um-section-head">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg>
                        اطلاعات پایه
                    </div>
                    <div id="um-sys-notice" class="hidden adm-um-sys-notice">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                        <span>سرویس اصلی همیشه <strong>نامحدود</strong> است. فقط پورت، آیپی تمیز، Fingerprint و Proxy IP قابل تغییر است.</span>
                    </div>
                    <div class="adm-um-field">
                        <label for="input-name">نام سرویس</label>
                        <input type="text" id="input-name" placeholder="مثال: ali" dir="ltr" required>
                    </div>
                    <div class="adm-um-grid-3" id="um-fields-quota">
                        <div class="adm-um-field" id="um-field-limit">
                            <label for="input-limit">حجم (GB)</label>
                            <div class="relative num-stepper">
                                <div class="num-stepper-controls">
                                    <button type="button" class="num-stepper-btn" data-step="1" aria-label="افزایش"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 15l7-7 7 7"></path></svg></button>
                                    <button type="button" class="num-stepper-btn" data-step="-1" aria-label="کاهش"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M19 9l-7 7-7-7"></path></svg></button>
                                </div>
                                <input type="number" id="input-limit" min="0" step="any" placeholder="نامحدود" class="num-stepper-input">
                            </div>
                        </div>
                        <div class="adm-um-field" id="um-field-expiry">
                            <label for="input-expiry">اعتبار (روز)</label>
                            <div class="relative num-stepper">
                                <div class="num-stepper-controls">
                                    <button type="button" class="num-stepper-btn" data-step="1" aria-label="افزایش"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 15l7-7 7 7"></path></svg></button>
                                    <button type="button" class="num-stepper-btn" data-step="-1" aria-label="کاهش"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M19 9l-7 7-7-7"></path></svg></button>
                                </div>
                                <input type="number" id="input-expiry" min="0" placeholder="نامحدود" class="num-stepper-input">
                            </div>
                        </div>
                        <div class="adm-um-field" id="um-field-max-req">
                            <label for="input-max-requests" data-i18n="um_max_conn">ریکوئست کل</label>
                            <div class="relative num-stepper">
                                <div class="num-stepper-controls">
                                    <button type="button" class="num-stepper-btn" data-step="1" aria-label="افزایش"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 15l7-7 7 7"></path></svg></button>
                                    <button type="button" class="num-stepper-btn" data-step="-1" aria-label="کاهش"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M19 9l-7 7-7-7"></path></svg></button>
                                </div>
                                <input type="number" id="input-max-requests" min="0" placeholder="نامحدود" class="num-stepper-input">
                            </div>
                        </div>
                        <div class="adm-um-field" id="um-field-max-req-daily">
                            <label for="input-max-requests-daily" data-i18n="um_max_req_daily">ریکوئست روزانه</label>
                            <div class="relative num-stepper">
                                <div class="num-stepper-controls">
                                    <button type="button" class="num-stepper-btn" data-step="1" aria-label="افزایش"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 15l7-7 7 7"></path></svg></button>
                                    <button type="button" class="num-stepper-btn" data-step="-1" aria-label="کاهش"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M19 9l-7 7-7-7"></path></svg></button>
                                </div>
                                <input type="number" id="input-max-requests-daily" min="0" placeholder="نامحدود" class="num-stepper-input">
                            </div>
                        </div>
                    </div>
                </div>
                <div class="adm-um-section">
                    <div class="adm-um-section-head">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.14 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"></path></svg>
                        پورت‌های اتصال
                    </div>
                    <div class="adm-um-ports-group">
                        <div class="adm-um-ports-label tls"><span class="dot"></span> پورت‌های امن (TLS)</div>
                        <div class="grid grid-cols-3 sm:grid-cols-4 gap-2" id="tls-ports-list"></div>
                    </div>
                    <div class="adm-um-ports-group">
                        <div class="adm-um-ports-label nontls"><span class="dot"></span> پورت‌های معمولی (Non-TLS)</div>
                        <div class="grid grid-cols-3 sm:grid-cols-4 gap-2" id="nontls-ports-list"></div>
                    </div>
                </div>
                <div class="adm-um-section">
                    <div class="adm-um-section-head">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"></path></svg>
                        تنظیمات پیشرفته
                    </div>
                    <div class="adm-um-field">
                        <div class="flex items-center justify-between mb-1">
                            <label for="input-ips">آیپی تمیز </label>
                            <div class="adm-um-ip-btns">
                                <button type="button" onclick="openIpSelectorModal()" class="adm-um-ip-btn" data-i18n="um_ip_pool">دریافت ایپی تمیز از سرور</button>
                                <button type="button" onclick="applyScannerPoolIps()" class="adm-um-ip-btn" data-i18n="um_scanner_pool">استفاده از مخزن اسکنر پنل</button>
                            </div>
                        </div>
                        <textarea id="input-ips" rows="2" placeholder="میتوانید ایپی تمیز خود را از مخزن پنل یا از سرور ما دریافت کنید" dir="ltr"></textarea>
                    </div>
                    <div class="adm-um-field" id="um-field-fingerprint">
                        <label for="fingerprint-select">Fingerprint </label>
                        <select id="fingerprint-select">
                            <option value="chrome" selected>Chrome — پیش‌فرض</option>
                            <option value="randomized">Randomized (پویا)</option>
                            <option value="firefox">Firefox</option>
                            <option value="safari">Safari</option>
                            <option value="ios">iOS Device</option>
                            <option value="android">Android Device</option>
                            <option value="edge">Microsoft Edge</option>
                            <option value="360">360 Browser</option>
                            <option value="qq">QQ Browser</option>
                        </select>
                    </div>
                    <div class="adm-um-field">
                        <label for="input-proxy-ip">
                            Proxy IP اختصاصی (اختیاری)
                        </label>
                        <textarea id="input-proxy-ip" rows="2" placeholder="در صورت خالی گذاشتن از ایپی پروکسی پنل استفاده میشود." dir="ltr"></textarea>
                        <p class="adm-um-hint">اگر خالی باشد، هنگام اتصال از پول CDN پیش‌فرض پنل استفاده می‌شود.</p>
                    </div>
                </div>
                </div>
                <div class="adm-um-footer">
                    <button type="button" onclick="toggleModal(false)" class="adm-um-btn-cancel">انصراف</button>
                    <button type="submit" id="submit-btn" class="adm-um-btn-submit">ایجاد کاربر</button>
                </div>
            </form>
        </div>
    </div>
    <div id="bulk-edit-modal" class="fixed inset-0 z-[55] flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-200 ease-out">
        <div id="bulk-edit-modal-card" class="w-full max-w-xl bg-white dark:bg-zinc-950 border border-gray-200 dark:border-zinc-850 rounded-2xl shadow-xl overflow-hidden transition-[opacity,transform] duration-200 opacity-0 scale-95 ease-out flex flex-col max-h-[90vh] transform-gpu">
            <div class="px-6 py-4 border-b border-gray-150 dark:border-zinc-800/80 flex justify-between items-center bg-gray-50/50 dark:bg-zinc-900/30">
                <div>
                    <h3 class="font-bold text-gray-900 dark:text-zinc-100 text-base">ویرایش گروهی</h3>
                    <p id="bulk-edit-subtitle" class="text-xs text-gray-500 dark:text-zinc-400 mt-1">۰ سرویس انتخاب شده</p>
                </div>
                <button type="button" onclick="toggleBulkEditModal(false)" class="p-1 rounded-lg hover:bg-gray-150 dark:hover:bg-zinc-800/60 text-gray-400 hover:text-gray-650 dark:hover:text-zinc-200 transition">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <form id="bulk-edit-form" class="p-6 space-y-4 overflow-y-auto flex-1 overscroll-contain" onsubmit="submitBulkEdit(event)">
                <div class="grid grid-cols-[auto,1fr] gap-3 items-center">
                    <input type="checkbox" id="bulk-apply-limit" class="w-4 h-4 rounded">
                    <div>
                        <label class="block text-xs font-bold text-gray-500 dark:text-zinc-400 mb-1.5">حجم (GB)</label>
                        <div class="relative num-stepper">
                            <div class="num-stepper-controls">
                                <button type="button" class="num-stepper-btn" data-step="1" aria-label="افزایش"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 15l7-7 7 7"></path></svg></button>
                                <button type="button" class="num-stepper-btn" data-step="-1" aria-label="کاهش"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M19 9l-7 7-7-7"></path></svg></button>
                            </div>
                            <input type="number" id="bulk-input-limit" min="0" step="any" placeholder="نامحدود" class="num-stepper-input w-full ps-3 py-2.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl text-sm">
                        </div>
                    </div>
                    <input type="checkbox" id="bulk-apply-expiry" class="w-4 h-4 rounded">
                    <div>
                        <label class="block text-xs font-bold text-gray-500 dark:text-zinc-400 mb-1.5">اعتبار (روز)</label>
                        <div class="relative num-stepper">
                            <div class="num-stepper-controls">
                                <button type="button" class="num-stepper-btn" data-step="1" aria-label="افزایش"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 15l7-7 7 7"></path></svg></button>
                                <button type="button" class="num-stepper-btn" data-step="-1" aria-label="کاهش"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M19 9l-7 7-7-7"></path></svg></button>
                            </div>
                            <input type="number" id="bulk-input-expiry" min="0" placeholder="نامحدود" class="num-stepper-input w-full ps-3 py-2.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl text-sm">
                        </div>
                    </div>
                    <input type="checkbox" id="bulk-apply-max-req" class="w-4 h-4 rounded">
                    <div>
                        <label class="block text-xs font-bold text-gray-500 dark:text-zinc-400 mb-1.5" data-i18n="um_max_conn">ریکوئست کل</label>
                        <div class="relative num-stepper">
                            <div class="num-stepper-controls">
                                <button type="button" class="num-stepper-btn" data-step="1" aria-label="افزایش"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 15l7-7 7 7"></path></svg></button>
                                <button type="button" class="num-stepper-btn" data-step="-1" aria-label="کاهش"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M19 9l-7 7-7-7"></path></svg></button>
                            </div>
                            <input type="number" id="bulk-input-max-req" min="0" placeholder="نامحدود" class="num-stepper-input w-full ps-3 py-2.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl text-sm">
                        </div>
                    </div>
                    <input type="checkbox" id="bulk-apply-max-req-daily" class="w-4 h-4 rounded">
                    <div>
                        <label class="block text-xs font-bold text-gray-500 dark:text-zinc-400 mb-1.5" data-i18n="um_max_req_daily">ریکوئست روزانه</label>
                        <div class="relative num-stepper">
                            <div class="num-stepper-controls">
                                <button type="button" class="num-stepper-btn" data-step="1" aria-label="افزایش"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 15l7-7 7 7"></path></svg></button>
                                <button type="button" class="num-stepper-btn" data-step="-1" aria-label="کاهش"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M19 9l-7 7-7-7"></path></svg></button>
                            </div>
                            <input type="number" id="bulk-input-max-req-daily" min="0" placeholder="نامحدود" class="num-stepper-input w-full ps-3 py-2.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl text-sm">
                        </div>
                    </div>
                </div>
                <div class="pt-2 border-t border-gray-100 dark:border-zinc-900">
                    <label class="flex items-center gap-2 text-xs font-bold text-gray-500 dark:text-zinc-400 mb-3 uppercase tracking-wider">
                        <input type="checkbox" id="bulk-apply-ports" class="w-4 h-4 rounded">
                        پورت‌های اتصال
                    </label>
                    <div class="space-y-3">
                        <div class="p-3 bg-gray-50/50 dark:bg-zinc-900/20 border border-gray-200/60 dark:border-zinc-850 rounded-xl">
                            <div class="text-[11px] font-bold text-blue-600 dark:text-blue-400 mb-2">🔒 TLS</div>
                            <div class="grid grid-cols-3 sm:grid-cols-4 gap-2" id="bulk-tls-ports-list"></div>
                        </div>
                        <div class="p-3 bg-gray-50/50 dark:bg-zinc-900/20 border border-gray-200/60 dark:border-zinc-850 rounded-xl">
                            <div class="text-[11px] font-bold text-amber-600 dark:text-amber-400 mb-2">🔓 Non-TLS</div>
                            <div class="grid grid-cols-3 sm:grid-cols-4 gap-2" id="bulk-nontls-ports-list"></div>
                        </div>
                    </div>
                </div>
                <div class="grid grid-cols-[auto,1fr] gap-3 items-start">
                    <input type="checkbox" id="bulk-apply-ips" class="w-4 h-4 rounded mt-2">
                    <div>
                        <div class="flex items-center justify-between mb-1.5">
                            <label class="block text-xs font-bold text-gray-500 dark:text-zinc-400">آیپی تمیز</label>
                            <div class="adm-um-ip-btns">
                                <button type="button" onclick="openIpSelectorModal('bulk-input-ips')" class="px-2 py-1 bg-emerald-50 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400 rounded-lg text-[11px] font-bold border border-emerald-200 dark:border-emerald-800" data-i18n="bulk_ip_pool">مخزن آیپی</button>
                                <button type="button" onclick="applyScannerPoolIps('bulk-input-ips')" class="px-2 py-1 bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 rounded-lg text-[11px] font-bold border border-blue-200 dark:border-blue-800" data-i18n="um_scanner_pool">استفاده از مخزن اسکنر پنل</button>
                            </div>
                        </div>
                        <textarea id="bulk-input-ips" rows="2" placeholder="میتوانید ایپی تمیز خود را از مخزن پنل یا از سرور ما دریافت کنید" class="w-full px-3 py-2.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl text-xs font-mono resize-none"></textarea>
                    </div>
                    <input type="checkbox" id="bulk-apply-proxy" class="w-4 h-4 rounded mt-2">
                    <div>
                        <label class="block text-xs font-bold text-gray-500 dark:text-zinc-400 mb-1.5">Proxy IP (CDN)</label>
                        <textarea id="bulk-input-proxy-ip" rows="2" placeholder="در صورت خالی گذاشتن از ایپی پروکسی پنل استفاده میشود." dir="ltr" class="w-full px-3 py-2.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl text-xs font-mono resize-none"></textarea>
                    </div>
                    <input type="checkbox" id="bulk-apply-fp" class="w-4 h-4 rounded mt-2">
                    <div>
                        <label class="block text-xs font-bold text-gray-500 dark:text-zinc-400 mb-1.5">Fingerprint</label>
                        <select id="bulk-fingerprint-select" class="w-full px-3 py-2.5 bg-gray-50 dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 rounded-xl text-xs font-semibold cursor-pointer">
                            <option value="chrome">🌐 Chrome</option>
                            <option value="firefox">🦊 Firefox</option>
                            <option value="safari">🧭 Safari</option>
                            <option value="ios">📱 iOS Device</option>
                            <option value="android">🤖 Android Device</option>
                            <option value="edge">🌀 Microsoft Edge</option>
                            <option value="360">🔒 360 Browser</option>
                            <option value="qq">💬 QQ Browser</option>
                            <option value="randomized">🎭 Randomized</option>
                        </select>
                    </div>
                </div>
                <div class="pt-4 flex gap-3">
                    <button type="button" onclick="toggleBulkEditModal(false)" class="flex-1 py-3 bg-gray-100 hover:bg-gray-200 dark:bg-zinc-800 dark:hover:bg-zinc-700/80 text-gray-700 dark:text-zinc-300 font-bold rounded-xl text-sm transition">انصراف</button>
                    <button type="submit" id="bulk-edit-submit" class="flex-1 py-3 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white font-bold rounded-xl text-sm transition shadow-md">اعمال روی انتخاب‌شده‌ها</button>
                </div>
            </form>
        </div>
    </div>
<div id="ip-selector-modal" class="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out">
    <div class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out">
        <div class="px-6 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50 dark:bg-zinc-900/50">
            <h3 class="font-bold text-gray-900 dark:text-zinc-100 text-sm">دریافت ایپی تمیز و دامنه پشت کلادفلر</h3>
            <button type="button" onclick="toggleIpSelectorModal(false)" class="text-gray-400 hover:text-gray-600 dark:hover:text-zinc-200">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
            </button>
        </div>
        <div class="p-6 space-y-4">
            <div id="ip-loading-state" class="text-center text-sm text-gray-500 dark:text-zinc-400 hidden">
                Loading Clean Ip
            </div>
            <div id="ip-selection-form" class="space-y-4">
                <div>
                    <label class="block text-xs font-medium mb-1.5 text-gray-700 dark:text-zinc-300">اوپراتور</label>
                    <select id="ip-operator-select" class="w-full px-3 py-2.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-xl text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-700 dark:text-zinc-300 cursor-pointer">
                        <option value="all">All</option>
                    </select>
                </div>
                <div>
                    <label class="block text-xs font-medium mb-1.5 text-gray-700 dark:text-zinc-300">تعداد</label>
                    <input type="number" id="ip-count-input" min="1" value="10" class="w-full px-3 py-2.5 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 text-xs font-mono text-center">
                </div>
            </div>
            <div class="pt-4 flex gap-3">
                <button type="button" onclick="toggleIpSelectorModal(false)" class="flex-1 py-2 bg-gray-100 hover:bg-gray-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 font-medium rounded-xl text-xs transition">لغو</button>
                <button type="button" onclick="applySelectedIps()" class="flex-1 py-2 bg-emerald-600 hover:bg-emerald-700 text-white font-medium rounded-xl text-xs transition">دریافت</button>
            </div>
        </div>
    </div>
</div>
    <div id="section-help-modal" class="fixed inset-0 z-[90] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out" onclick="if(event.target===this)closeSectionHelp()">
        <div id="section-help-modal-card" class="w-full max-w-sm admin-card shadow-xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
            <h3 id="section-help-title" class="font-bold mb-3 text-lg" style="color: var(--admin-text)">آموزش این بخش</h3>
            <p class="text-sm mb-5" style="color: var(--admin-muted)">برای آموزش این قسمت روی دکمه زیر کلیک کنید</p>
            <a id="section-help-link" href="#" target="_blank" rel="noopener noreferrer" class="admin-btn-primary block w-full py-2.5 text-sm font-bold">مشاهده آموزش</a>
            <button type="button" onclick="closeSectionHelp()" class="w-full py-2 mt-3 rounded-xl font-medium text-sm" style="background: var(--admin-input-bg); color: var(--admin-text)">بستن</button>
        </div>
    </div>
    <div id="qr-modal" class="fixed inset-0 z-[85] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out" onclick="if(event.target===this)window.toggleQRModal(false)">
        <div id="qr-modal-card" class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
            <h3 id="qr-modal-title" class="font-bold text-gray-900 dark:text-zinc-100 mb-4">اسکن کد QR</h3>
            <div class="bg-white p-3 rounded-xl inline-block mb-4 border border-gray-100">
                <div id="qrcode-box" class="flex justify-center items-center w-48 h-48 mx-auto"></div>
            </div>
            <button type="button" onclick="window.toggleQRModal(false)" class="w-full py-2 bg-gray-100 hover:bg-gray-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 font-medium rounded-lg text-sm transition text-gray-900 dark:text-zinc-100">بستن</button>
        </div>
    </div>
    <div id="dash-map-modal" class="fixed inset-0 z-[70] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out" onclick="if(event.target===this)closeDashboardMapModal()">
        <div id="dash-map-modal-card" class="w-full max-w-4xl bg-white dark:bg-zinc-950 border border-gray-200 dark:border-zinc-800 rounded-2xl shadow-2xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out">
            <div class="px-5 py-3 border-b border-gray-200 dark:border-zinc-800 flex items-center justify-between gap-3">
                <h3 class="font-bold text-gray-900 dark:text-zinc-100 text-sm">نقشه موقعیت تقریبی</h3>
                <button type="button" onclick="closeDashboardMapModal()" class="text-xs font-bold px-3 py-1.5 rounded-lg bg-gray-100 hover:bg-gray-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 text-gray-700 dark:text-zinc-200 transition">بستن</button>
            </div>
            <div id="dash-map-modal-container" class="w-full" style="height:min(70vh,520px)"></div>
        </div>
    </div>
    ${NEXA_QR_SCRIPT}
    ${NEXA_ANNOUNCE_LINKIFY_SCRIPT}
    <script>
        window.panelProxyIps = [];
        async function loadPanelProxySettings() {
            try {
                const res = await fetch('/api/proxy-ip');
                if (!res.ok) return;
                const data = await res.json();
                if (data.proxy_ips && data.proxy_ips.length) {
                    window.panelProxyIps = data.proxy_ips;
                } else if (data.proxy_ip) {
                    window.panelProxyIps = [data.proxy_ip];
                }
            } catch (e) {}
        }
        const tlsPorts = ['443', '2053', '2083', '2087', '2096', '8443'];
        const nonTlsPorts = ['80', '8080', '8880', '2052', '2082', '2086', '2095'];
        let isEditMode = false;
        let editingUsername = '';
        window.selectedUsernames = window.selectedUsernames || new Set();
        const SYSTEM_USER_LABEL = 'nexa-main';
        let dashboardMapCoords = null;
        let dashboardVisitorCoords = null;
        let dashboardDirectCoords = null;
        let dashboardMapMode = 'visitor';
        let dashboardMapLastRendered = null;
        let dashboardMapInstance = null;
        let dashboardMapModalInstance = null;
        let dashboardRefreshInFlight = false;
        function isSystemUserClient(user) {
            return user && (user.is_system === 1 || user.username === SYSTEM_USER_LABEL);
        }
        function formatReqCount(n) {
            n = Number(n) || 0;
            if (n >= 1000000) return (n / 1000000).toFixed(2) + 'M';
            if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
            return String(n);
        }
        function getCfRequestResetTimeLabel() {
            const now = new Date();
            const nextReset = new Date(Date.UTC(
                now.getUTCFullYear(),
                now.getUTCMonth(),
                now.getUTCDate() + 1,
                0, 0, 0, 0
            ));
            return nextReset.toLocaleTimeString('fa-IR', {
                hour: '2-digit',
                minute: '2-digit',
                timeZone: 'Asia/Tehran',
                hour12: false
            });
        }
        function openSubLinkQrModal(username, title) {
            const uname = username || window.systemUserUsername || '';
            if (typeof window.toggleQRModal !== 'function') return;
            window.toggleQRModal(true, getSubLink(uname), title || adminT('btn_qr_sub_link') || 'qrcode لینک ساب');
        }
        function openDashboardQrModal() {
            openSubLinkQrModal(window.systemUserUsername, adminT('btn_qr_sub_link') || 'qrcode لینک ساب');
        }
        function renderDashboardQR(username) {
            const qrBox = document.getElementById('dashboard-qr-box');
            if (!qrBox) return;
            const uname = username || window.systemUserUsername || '';
            window.renderQrCode(qrBox, getSubLink(uname), 128);
        }
        function dashEscapeHtml(str) {
            return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }
        function adminEncodedArg(value) {
            return "'" + encodeURIComponent(String(value || '')) + "'";
        }
        function adminUserDataAttrs(username) {
            return ' data-user="' + dashEscapeHtml(encodeURIComponent(String(username || ''))) + '"';
        }
        function initAdminClickDelegation() {
            if (window._adminClickDelegationReady) return;
            window._adminClickDelegationReady = true;
            document.addEventListener('click', function(e) {
                const navBtn = e.target.closest('.adm-nav-item[data-section]');
                if (navBtn) {
                    e.preventDefault();
                    e.stopPropagation();
                    switchAdminSection(navBtn.getAttribute('data-section'));
                    return;
                }
                const userBtn = e.target.closest('[data-user-action]');
                if (userBtn) {
                    e.preventDefault();
                    e.stopPropagation();
                    const action = userBtn.getAttribute('data-user-action');
                    const enc = userBtn.getAttribute('data-user') || '';
                    if (action === 'toggle-status') toggleUserStatus(enc);
                    else if (action === 'reset-volume') resetUserService(enc, 'volume');
                    else if (action === 'reset-time') resetUserService(enc, 'time');
                    else if (action === 'save') toggleSaveUser(enc);
                    else if (action === 'delete') deleteUser(enc);
                    else if (action === 'edit') editUser(enc);
                    else if (action === 'copy-sub') copySubLink(enc);
                    else if (action === 'sub-qr') showSubQR(enc);
                    else if (action === 'status') openStatusPage(enc);
                    else if (action === 'logs') openLogsPage(enc);
                    return;
                }
                if (e.target.closest('.adm-users-add-btn')) {
                    e.preventDefault();
                    e.stopPropagation();
                    openCreateModal();
                    return;
                }
                if (e.target.closest('#dash-refresh-btn')) {
                    e.preventDefault();
                    e.stopPropagation();
                    loadDashboard(true);
                    return;
                }
                if (e.target.closest('.adm-menu-btn')) {
                    e.preventDefault();
                    e.stopPropagation();
                    toggleAdminSidebar();
                    return;
                }
                if (e.target.closest('#adm-sidebar-backdrop')) {
                    e.preventDefault();
                    e.stopPropagation();
                    toggleAdminSidebar(false);
                    return;
                }
                if (e.target.closest('.adm-sidebar-collapse-btn')) {
                    e.preventDefault();
                    e.stopPropagation();
                    toggleSidebarCollapse();
                    return;
                }
                if (e.target.closest('.adm-logout-btn')) {
                    e.preventDefault();
                    e.stopPropagation();
                    logoutAdmin();
                    return;
                }
                if (e.target.closest('#lang-fa')) {
                    e.preventDefault();
                    e.stopPropagation();
                    setAdminLang('fa');
                    return;
                }
                if (e.target.closest('#lang-en')) {
                    e.preventDefault();
                    e.stopPropagation();
                    setAdminLang('en');
                    return;
                }
                if (e.target.closest('.adm-dash-manage-btn')) {
                    e.preventDefault();
                    e.stopPropagation();
                    openSystemUserEdit();
                    return;
                }
                if (e.target.closest('.adm-dash-copy-btn')) {
                    e.preventDefault();
                    e.stopPropagation();
                    copyDashboardSubLink();
                    return;
                }
                if (e.target.closest('#dashboard-qr-box')) {
                    e.preventDefault();
                    e.stopPropagation();
                    openDashboardQrModal();
                    return;
                }
            }, true);
        }
        function renderNodeServerConfigs(nodeConfigs) {
            const loadingEl = document.getElementById('node-server-loading');
            const emptyEl = document.getElementById('node-server-empty');
            const listEl = document.getElementById('node-server-list');
            if (!listEl) return;
            const configs = Array.isArray(nodeConfigs) ? nodeConfigs : [];
            window.nodeServerConfigs = configs;
            if (loadingEl) loadingEl.classList.add('hidden');
            if (!configs.length) {
                if (emptyEl) emptyEl.classList.remove('hidden');
                listEl.classList.add('hidden');
                listEl.innerHTML = '';
                return;
            }
            if (emptyEl) emptyEl.classList.add('hidden');
            listEl.classList.remove('hidden');
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            const dict = ADMIN_I18N[lang] || ADMIN_I18N.fa;
            const copyLabel = dict.node_server_copy || 'کپی';
            listEl.innerHTML = configs.map(function(cfg, idx) {
                return '<div class="adm-node-item">' +
                    '<span class="adm-node-port">' + dashEscapeHtml(cfg.port) + ':</span>' +
                    '<span class="adm-node-link">' + dashEscapeHtml(cfg.link) + '</span>' +
                    '<div class="adm-node-actions">' +
                        '<button type="button" class="adm-node-copy" onclick="copyNodeServerConfig(' + idx + ')">' + dashEscapeHtml(copyLabel) + '</button>' +
                    '</div>' +
                '</div>';
            }).join('');
        }
        function copyNodeServerConfig(idx) {
            const cfg = (window.nodeServerConfigs || [])[idx];
            if (!cfg || !cfg.link) return;
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            const dict = ADMIN_I18N[lang] || ADMIN_I18N.fa;
            navigator.clipboard.writeText(cfg.link).then(function() {
                showNexaToast(dict.toast_node_copied || 'کانفیگ نود کپی شد');
            }).catch(function() {
                showNexaToast(dict.toast_node_copy_fail || 'خطا در کپی کانفیگ نود', 'error');
            });
        }
        let nodeServerRefreshInFlight = false;
        async function loadNodeServer(showBusyState) {
            const loadingEl = document.getElementById('node-server-loading');
            const emptyEl = document.getElementById('node-server-empty');
            const listEl = document.getElementById('node-server-list');
            if (nodeServerRefreshInFlight) return;
            nodeServerRefreshInFlight = true;
            if (loadingEl && showBusyState) {
                loadingEl.classList.remove('hidden');
                if (emptyEl) emptyEl.classList.add('hidden');
                if (listEl) listEl.classList.add('hidden');
            }
            try {
                const res = await fetch('/api/dashboard?t=' + Date.now());
                if (!res.ok) throw new Error('Failed');
                const data = await res.json();
                const systemUser = data.systemUser || {};
                renderNodeServerConfigs(systemUser.nodeConfigs || []);
            } catch (e) {
                if (loadingEl) loadingEl.classList.add('hidden');
                if (emptyEl) {
                    emptyEl.classList.remove('hidden');
                    emptyEl.textContent = adminT('dash_load_error');
                }
                if (listEl) listEl.classList.add('hidden');
            } finally {
                nodeServerRefreshInFlight = false;
            }
        }
        function setDashboardMapMode(mode) {
            dashboardMapMode = mode === 'direct' ? 'direct' : 'visitor';
            const visitorBtn = document.getElementById('dash-map-mode-visitor');
            const directBtn = document.getElementById('dash-map-mode-direct');
            if (visitorBtn) visitorBtn.classList.toggle('active', dashboardMapMode === 'visitor');
            if (directBtn) directBtn.classList.toggle('active', dashboardMapMode === 'direct');
            applyDashboardMapForMode();
        }
        function applyDashboardMapForMode() {
            const coords = dashboardMapMode === 'direct' ? dashboardDirectCoords : dashboardVisitorCoords;
            if (coords && hasDashboardMapCoords(coords.lat, coords.lon)) {
                renderDashboardMap(coords.lat, coords.lon);
                return;
            }
            renderDashboardMap(null, null);
            const mapEl = document.getElementById('dash-visitor-map');
            if (!mapEl) return;
            if (dashboardMapMode === 'direct') {
                mapEl.textContent = dashboardDirectCoords
                    ? adminT('dash_map_no_coords')
                    : adminT('dash_click_refresh');
            } else {
                mapEl.textContent = adminT('dash_map_no_coords');
            }
        }
        function createDashboardLeafletMap(container, lat, lon, zoom) {
            if (typeof L === 'undefined') return null;
            const map = L.map(container, { zoomControl: true, attributionControl: true }).setView([lat, lon], zoom || 12);
            const tileLayers = [
                L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png', {
                    attribution: '© OpenStreetMap © CARTO',
                    subdomains: 'abcd',
                    maxZoom: 19
                }),
                L.tileLayer('https://{s}.tile.openstreetmap.de/{z}/{x}/{y}.png', {
                    attribution: '© OpenStreetMap',
                    maxZoom: 18
                })
            ];
            tileLayers[0].addTo(map);
            tileLayers[0].on('tileerror', function() {
                if (map.hasLayer(tileLayers[0])) {
                    map.removeLayer(tileLayers[0]);
                    tileLayers[1].addTo(map);
                }
            });
            L.marker([lat, lon]).addTo(map);
            setTimeout(function() { map.invalidateSize(); }, 100);
            return map;
        }
        function hasDashboardMapCoords(lat, lon) {
            return lat != null && lon != null && !isNaN(lat) && !isNaN(lon);
        }
        function renderDashboardMap(lat, lon) {
            const mapEl = document.getElementById('dash-visitor-map');
            const zoomBtn = document.getElementById('dash-map-zoom-btn');
            if (!mapEl) return;
            if (!hasDashboardMapCoords(lat, lon)) {
                dashboardMapCoords = null;
                if (dashboardMapInstance) {
                    dashboardMapInstance.remove();
                    dashboardMapInstance = null;
                }
                dashboardMapLastRendered = null;
                if (zoomBtn) zoomBtn.style.display = 'none';
                mapEl.className = 'adm-dash-map-empty';
                mapEl.textContent = adminT('dash_map_no_coords');
                return;
            }
            dashboardMapCoords = { lat: lat, lon: lon };
            if (zoomBtn) zoomBtn.style.display = '';
            const sameCoords = dashboardMapLastRendered &&
                dashboardMapLastRendered.lat === lat && dashboardMapLastRendered.lon === lon;
            if (sameCoords && dashboardMapInstance) {
                setTimeout(function() { dashboardMapInstance.invalidateSize(); }, 100);
                return;
            }
            dashboardMapLastRendered = { lat: lat, lon: lon };
            if (dashboardMapInstance) {
                dashboardMapInstance.remove();
                dashboardMapInstance = null;
            }
            mapEl.className = 'adm-dash-map-container';
            mapEl.innerHTML = '';
            if (typeof L === 'undefined') {
                mapEl.className = 'adm-dash-map-empty';
                mapEl.textContent = adminT('dash_map_unavailable');
                return;
            }
            dashboardMapInstance = createDashboardLeafletMap(mapEl, lat, lon, 12);
        }
        function openDashboardMapModal() {
            if (!dashboardMapCoords) return;
            const modal = document.getElementById('dash-map-modal');
            const card = document.getElementById('dash-map-modal-card');
            const container = document.getElementById('dash-map-modal-container');
            if (!modal || !card || !container) return;
            modal.classList.remove('opacity-0', 'pointer-events-none');
            modal.classList.add('opacity-100', 'pointer-events-auto');
            card.classList.remove('opacity-0', 'scale-95');
            card.classList.add('opacity-100', 'scale-100');
            container.innerHTML = '';
            if (dashboardMapModalInstance) {
                dashboardMapModalInstance.remove();
                dashboardMapModalInstance = null;
            }
            if (typeof L !== 'undefined') {
                dashboardMapModalInstance = createDashboardLeafletMap(container, dashboardMapCoords.lat, dashboardMapCoords.lon, 13);
            }
        }
        function closeDashboardMapModal() {
            const modal = document.getElementById('dash-map-modal');
            const card = document.getElementById('dash-map-modal-card');
            if (!modal || !card) return;
            modal.classList.remove('opacity-100', 'pointer-events-auto');
            modal.classList.add('opacity-0', 'pointer-events-none');
            card.classList.remove('opacity-100', 'scale-100');
            card.classList.add('opacity-0', 'scale-95');
            if (dashboardMapModalInstance) {
                dashboardMapModalInstance.remove();
                dashboardMapModalInstance = null;
            }
        }
        function renderDashboardGeo(prefix, data, fallbackLocation) {
            const ipEl = document.getElementById(prefix + '-ip');
            const locEl = document.getElementById(prefix + '-location');
            const flagEl = document.getElementById(prefix + '-flag');
            if (ipEl) ipEl.textContent = data.ip || '—';
            if (flagEl) flagEl.textContent = getFlagEmoji(data.countryCode);
            if (locEl) {
                const parts = [];
                if (data.city) parts.push(data.city);
                if (data.region && data.region !== data.city) parts.push(data.region);
                if (data.country) parts.push(data.country);
                locEl.textContent = parts.length ? parts.join(' · ') : (fallbackLocation || (data.ip ? 'موقعیت دقیق یافت نشد' : 'IP یافت نشد'));
            }
        }
        function renderDashboardGeoDetails(prefix, data) {
            const cityEl = document.getElementById(prefix + '-city');
            const regionEl = document.getElementById(prefix + '-region');
            const countryEl = document.getElementById(prefix + '-country');
            const ispEl = document.getElementById(prefix + '-isp');
            if (cityEl) cityEl.textContent = data.city || '—';
            if (regionEl) regionEl.textContent = data.region || '—';
            if (countryEl) countryEl.textContent = data.country ? (getFlagEmoji(data.countryCode) + ' ' + data.country) : '—';
            if (ispEl) ispEl.textContent = data.isp || '—';
        }
        function setDashboardDirectError(message) {
            renderDashboardGeo('dash-direct', {}, message || 'خطا در دریافت IP مستقیم');
            renderDashboardGeoDetails('dash-direct', {});
        }
        function renderDashboardData(data) {
            const visitor = data.visitor || {};
            const direct = data.direct || {};
            const requests = data.requests || {};
            const systemUser = data.systemUser || {};
            renderDashboardGeo('dash-visitor', visitor);
            renderDashboardGeoDetails('dash-geo', visitor);
            renderDashboardGeo('dash-direct', direct, direct.ip ? 'موقعیت دقیق یافت نشد' : 'IP مستقیم دریافت نشد');
            renderDashboardGeoDetails('dash-direct', direct);
            dashboardVisitorCoords = { lat: visitor.lat, lon: visitor.lon };
            try {
                applyDashboardMapForMode();
            } catch (mapErr) {
                const mapEl = document.getElementById('dash-visitor-map');
                if (mapEl) {
                    mapEl.className = 'adm-dash-map-empty';
                    mapEl.textContent = adminT('dash_map_unavailable');
                }
            }
            const cfToday = requests.today || 0;
            const todayEl = document.getElementById('dash-req-today');
            const progressEl = document.getElementById('dash-req-progress');
            const reqCard = document.getElementById('dash-req-card');
            const resetEl = document.getElementById('dash-req-reset');
            if (todayEl) todayEl.textContent = formatReqCount(cfToday);
            if (resetEl) resetEl.textContent = getCfRequestResetTimeLabel();
            if (progressEl) progressEl.style.width = Math.min((cfToday / 100000) * 100, 100) + '%';
            if (reqCard) reqCard.classList.toggle('admin-stat', false);
            if (reqCard && cfToday >= 90000) reqCard.style.boxShadow = '0 0 20px rgba(239,68,68,0.25)';
            else if (reqCard) reqCard.style.boxShadow = '';
            if (cfToday >= 90000) {
                const today = new Date().toISOString().split('T')[0];
                if (localStorage.getItem('nexa_usage_warned_date') !== today) {
                    const usageModal = document.getElementById('usage-warning-modal');
                    if (usageModal) {
                        const usageCard = usageModal.querySelector('div');
                        usageModal.classList.remove('opacity-0', 'pointer-events-none');
                        usageModal.classList.add('opacity-100', 'pointer-events-auto');
                        if (usageCard) {
                            usageCard.classList.remove('opacity-0', 'scale-95');
                            usageCard.classList.add('opacity-100', 'scale-100');
                        }
                    }
                }
            }
            const subLink = systemUser.subLink || '';
            window.systemUserUsername = systemUser.username || SYSTEM_USER_LABEL;
            const subEl = document.getElementById('dash-sub-link');
            if (subEl) subEl.textContent = subLink || '—';
            if (subLink) renderDashboardQR(window.systemUserUsername);
            renderDashboardTopRequestUsers(data.topRequestUsers || []);
        }
        function renderDashboardTopRequestUsers(topUsers) {
            const listEl = document.getElementById('dash-top-req-list');
            if (!listEl) return;
            const users = Array.isArray(topUsers) ? topUsers : [];
            if (!users.length) {
                listEl.innerHTML = '<div class="adm-dash-top-req-empty" data-i18n="dash_top_req_empty">هنوز مصرفی ثبت نشده</div>';
                return;
            }
            listEl.innerHTML = users.map(function(u, i) {
                const used = formatReqCount(u.used || 0);
                const max = u.max ? formatReqCount(u.max) : '∞';
                return '<div class="adm-dash-top-req-item">' +
                    '<span class="adm-dash-top-req-name">' + (i + 1) + '. ' + dashEscapeHtml(u.username || '—') + '</span>' +
                    '<span class="adm-dash-top-req-val">' + used + ' / ' + max + '</span>' +
                '</div>';
            }).join('');
        }
        async function fetchDashboardDirectGeo() {
            const directRes = await fetch('https://ipv4.geojs.io/v1/ip.json?nocache=' + Date.now(), { cache: 'no-store' });
            if (!directRes.ok) throw new Error('دریافت IP مستقیم ناموفق بود');
            const directJson = await directRes.json();
            const directIp = String(directJson.ip || '').trim();
            if (!directIp) throw new Error('IP مستقیم یافت نشد');
            let geoBody = {};
            try {
                const geoRes = await fetch('/my-ip/geo', {
                    method: 'POST',
                    headers: { 'Content-Type': 'text/plain' },
                    body: directIp
                });
                const geoJson = await geoRes.json();
                if (geoJson.success) geoBody = geoJson.body || {};
            } catch (e) {}
            if (!hasDashboardMapCoords(geoBody.lat, geoBody.lon) && directJson.latitude && directJson.longitude) {
                geoBody.lat = parseFloat(directJson.latitude);
                geoBody.lon = parseFloat(directJson.longitude);
            }
            if (!geoBody.ip) geoBody.ip = directIp;
            if (!geoBody.country && directJson.country) geoBody.country = directJson.country;
            if (!geoBody.countryCode && directJson.country_code) geoBody.countryCode = directJson.country_code;
            if (!geoBody.city && directJson.city) geoBody.city = directJson.city;
            if (!geoBody.region && directJson.region) geoBody.region = directJson.region;
            return geoBody;
        }
        async function loadDashboard(showBusyState) {
            const refreshBtn = document.getElementById('dash-refresh-btn');
            if (dashboardRefreshInFlight) return;
            dashboardRefreshInFlight = true;
            if (refreshBtn) {
                refreshBtn.disabled = true;
                refreshBtn.textContent = adminT('dash_updating');
            }
            try {
                if (showBusyState) {
                    const visitorLoc = document.getElementById('dash-visitor-location');
                    const directLoc = document.getElementById('dash-direct-location');
                    if (visitorLoc) visitorLoc.textContent = adminT('dash_updating');
                    if (directLoc) directLoc.textContent = adminT('dash_updating');
                }
                const controller = new AbortController();
                const timeoutId = setTimeout(function() { controller.abort(); }, 15000);
                let res;
                try {
                    res = await fetch('/api/dashboard?t=' + Date.now(), { signal: controller.signal });
                } finally {
                    clearTimeout(timeoutId);
                }
                if (!res.ok) throw new Error('dashboard_http_' + res.status);
                const data = await res.json();
                data.direct = {};
                renderDashboardData(data);
                fetchDashboardDirectGeo()
                    .then(function(directGeo) {
                        if (!directGeo) {
                            setDashboardDirectError(adminT('dash_direct_error'));
                            dashboardDirectCoords = null;
                            if (dashboardMapMode === 'direct') applyDashboardMapForMode();
                            return;
                        }
                        renderDashboardGeo('dash-direct', directGeo, directGeo.ip ? adminT('dash_loc_not_found') : adminT('dash_ip_not_found'));
                        renderDashboardGeoDetails('dash-direct', directGeo);
                        dashboardDirectCoords = { lat: directGeo.lat, lon: directGeo.lon };
                        if (dashboardMapMode === 'direct') applyDashboardMapForMode();
                    })
                    .catch(function() {
                        setDashboardDirectError(adminT('dash_direct_error'));
                        dashboardDirectCoords = null;
                        if (dashboardMapMode === 'direct') applyDashboardMapForMode();
                    });
            } catch (e) {
                const visitorLoc = document.getElementById('dash-visitor-location');
                if (visitorLoc) visitorLoc.textContent = adminT('dash_load_error');
                setDashboardDirectError(adminT('dash_direct_error'));
            } finally {
                dashboardRefreshInFlight = false;
                if (refreshBtn) {
                    refreshBtn.disabled = false;
                    refreshBtn.textContent = adminT('refresh');
                }
            }
        }
        async function openSystemUserEdit() {
            if (!window.allUsers || !window.allUsers.length) await loadUsers(true);
            const username = window.systemUserUsername || SYSTEM_USER_LABEL;
            const user = (window.allUsers || []).find(function(u) { return u.username === username; });
            if (user) editUser(encodeURIComponent(username));
            else showNexaToast('کاربر اصلی یافت نشد', 'error');
        }
        function copyDashboardSubLink() {
            const username = window.systemUserUsername || SYSTEM_USER_LABEL;
            copySubLink(encodeURIComponent(username));
        }
        function toggleAdminSidebar(force) {
            const sidebar = document.getElementById('adm-sidebar');
            const backdrop = document.getElementById('adm-sidebar-backdrop');
            if (!sidebar || !backdrop) return;
            const shouldOpen = force !== undefined ? !!force : !sidebar.classList.contains('open');
            sidebar.classList.toggle('open', shouldOpen);
            backdrop.classList.toggle('open', shouldOpen);
            document.body.style.overflow = shouldOpen && window.innerWidth < 1024 ? 'hidden' : '';
        }
        function toggleSidebarCollapse() {
            const sidebar = document.getElementById('adm-sidebar');
            if (!sidebar) return;
            if (window.innerWidth < 1024) {
                toggleAdminSidebar(false);
                return;
            }
            sidebar.classList.toggle('collapsed');
            localStorage.setItem('nexa-sidebar-collapsed', sidebar.classList.contains('collapsed') ? '1' : '0');
            updateSidebarCollapseLabel();
        }
        function updateSidebarCollapseLabel() {
            const sidebar = document.getElementById('adm-sidebar');
            const label = document.querySelector('.adm-sidebar-collapse-btn [data-i18n="nav_collapse"]');
            if (!sidebar || !label) return;
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            const dict = ADMIN_I18N[lang] || ADMIN_I18N.fa;
            label.textContent = sidebar.classList.contains('collapsed')
                ? adminT('nav_expand')
                : (dict.nav_collapse || adminT('nav_collapse'));
        }
        function initSidebarCollapse() {
            const sidebar = document.getElementById('adm-sidebar');
            if (!sidebar) return;
            if (window.innerWidth < 1024) {
                sidebar.classList.remove('collapsed');
                return;
            }
            if (localStorage.getItem('nexa-sidebar-collapsed') === '1') sidebar.classList.add('collapsed');
            updateSidebarCollapseLabel();
            window.addEventListener('resize', function() {
                if (window.innerWidth < 1024) sidebar.classList.remove('collapsed');
                else if (localStorage.getItem('nexa-sidebar-collapsed') === '1') sidebar.classList.add('collapsed');
                updateSidebarCollapseLabel();
            });
        }
        function initAdminSidebarClose() {
            document.addEventListener('click', function(e) {
                if (window.innerWidth >= 1024) return;
                const sidebar = document.getElementById('adm-sidebar');
                const backdrop = document.getElementById('adm-sidebar-backdrop');
                const menuBtn = document.querySelector('.adm-menu-btn');
                if (!sidebar || !sidebar.classList.contains('open')) return;
                if (sidebar.contains(e.target) || (menuBtn && menuBtn.contains(e.target))) return;
                toggleAdminSidebar(false);
            });
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape') toggleAdminSidebar(false);
            });
        }
        const ADMIN_I18N = {
          fa: {
          nav_main:'منوی اصلی',
          nav_dashboard:'داشبورد',
          nav_users:'مدیریت کاربران',
          nav_guide:'آموزش اتصال',
          nav_node_server:'سرور نود',
          nav_ip_scanner:'اسکنر IP تمیز',
          nav_cdn_proxy:'پروکسی CDN',
          nav_logs:'لاگ فعالیت',
          nav_wireguard:'سرویس WireGuard',
          nav_warp:'سرویس WARP',
          nav_settings:'تنظیمات پنل',
          nav_update_panel:'به‌روزرسانی پنل',
          nav_about:'درباره ما',
          nav_backup:'بکاپ پنل',
          nav_tg_channel:'کانال تلگرام Nexa',
          nav_tg_bot:'بات پشتیبانی Nexa',
          nav_collapse:'جمع کردن منو',
          nav_expand:'باز کردن',
          nav_logout:'خروج',
          panel_version:'نسخه ${PANEL_VERSION}',
          panel_subtitle:'پنل مدیریت',
          aria_menu:'منو',
          aria_collapse:'جمع کردن منو',
          aria_close:'بستن',
          theme_toggle:'تغییر تم',
          dash_sub_title:'لینک اشتراک اصلی',
          dash_manage_btn:'برای مدیریت این سرویس کلیک کنید',
          dash_copy_sub:'کپی اشتراک',
          node_server_title:'نود اصلی',
          node_server_desc:'نود شما روی همه‌ی پورت‌های TLS کلودفلر، با استفاده‌ی مستقیم از دامنه‌ی ورکر، جدا از اشتراک، هر پورت را کپی کنید.',
          node_server_empty:'کانفیگ نودی در دسترس نیست',
          node_server_copy:'کپی',
          node_server_qr:'QR',
          dash_worker_usage:'مصرف ریکوئست Worker',
          dash_reset_label:'ریست ساعت:',
          dash_reset_meta:'ریست ریکوئست‌ها در ساعت 3:30 به وقت تهران',
          dash_top_req_title:'بیشترین مصرف ریکوئست کل',
          dash_top_req_empty:'هنوز مصرفی ثبت نشده',
          dash_ip_title:'مشخصات IP شما',
          dash_via_server:'از طریق این سرور',
          dash_direct_ip:'IP مستقیم (بدون پروکسی)',
          dash_city:'شهر',
          dash_region:'منطقه',
          dash_country:'کشور',
          dash_fetching_loc:'در حال دریافت موقعیت...',
          dash_click_refresh:'برای دریافت، بروزرسانی را بزنید',
          dash_loading_map:'در حال بارگذاری نقشه...',
          dash_zoom_map:'بزرگ‌نمایی',
          dash_map_via_server:'نقشه: از طریق سرور',
          dash_map_direct:'نقشه: IP مستقیم',
          dash_updating:'در حال بروزرسانی...',
          ip_scanner_desc:'سریع‌ترین آی‌پی‌های تمیز کلودفلر را برای شبکه‌تان پیدا کنید',
          ip_scan_total:'تعداد ایپی مورد نظر برای تست',
          ip_scan_keep:'انتخاب بهترین ایپی ',
          ip_scan_ports_label:'پورت‌های اسکن',
          ip_scan_ports_required:'حداقل یک پورت انتخاب کنید',
          ip_scan_start:'شروع اسکن',
          ip_scan_results:'نتایج آی‌پی تمیز',
          cdn_cf_banner_text:'برای بروزرسانی خودکار و نمایش «مصرف ورکر»، یک‌بار توکن Cloudflare را وصل کن، کمتر از یک دقیقه.',
          cdn_cf_connect:'اتصال توکن',
          cdn_access_title:'دسترسی CDN کلودفلر',
          cdn_access_desc:'از بخش یافتن پروکسی میتوانید پروکسی ایپی مد نظر خود را دریافت کنید.',
          cdn_mode_label:'حالت',
          cdn_proxyip_label:'آدرس PROXYIP',
          cdn_proxyip_hint:'هر خط = یک لوکیشن. اگه می‌خوای پرچم کشورش هم توی اسم کانفیگ بیاد، انتهای اون خط بنویس <code>#کدکشور</code> (مثال: <code>1.2.3.4#DE</code> یا <code>5.6.7.8:2053#US</code>)',
          cdn_chain_label:'آدرس پروکسی',
          cdn_chain_hint:'هر پروکسی در یک خط. یکی = IP ثابت؛ دو تا سه = چرخش و جایگزینی خودکار.',
          cdn_rotate_label:'چرخش خودکار',
          cdn_rotate_off:'خاموش — همه',
          cdn_rotate_daily:'روزانه',
          cdn_rotate_weekly:'هفتگی',
          cdn_rotate_count:'تعداد فعال',
          cdn_rotate_hint:'با چند پروکسی، هر روز/هفته زیرمجموعه‌ای متفاوت ارائه می‌شود.',
          cdn_verify:'بررسی',
          cdn_save:'ذخیره',
          cdn_finder_title:'یافتن پروکسی',
          cdn_finder_load:'دریافت فهرست',
          cdn_finder_desc:'شما میتوانید با لود فهرست ها از پروکسی 68 کشور استفاده کنید. ',
          cdn_country_label:'کشور',
          cdn_pick_label:'پروکسی',
          cdn_use_selected:'استفاده از انتخاب',
          cdn_proxy_saved:'تنظیمات پروکسی CDN ذخیره شد',
          cdn_proxy_fetching:'در حال دریافت فهرست...',
          cdn_proxy_list_ok:'فهرست دریافت شد',
          cdn_proxy_list_stats:'{proxies} پروکسی — {countries} کشور',
          cdn_proxy_use_ok:'پر شد — اکنون ذخیره کنید',
          cdn_proxy_verify_proxyip:'PROXYIP نیاز به تست جدا ندارد — هنگام اتصال خودکار بررسی می‌شود. فقط ذخیره کنید.',
          cdn_proxy_verify_ok:'پروکسی در دسترس است',
          cdn_proxy_verify_fail:'پاسخی دریافت نشد',
          cdn_proxy_enter_first:'ابتدا آدرس پروکسی را وارد کنید',
          ip_scan_copy:'کپی نتایج',
          ip_scan_save_pool:'ذخیره در مخزن پنل',
          ip_scan_foot:'اسکن کاملاً در مرورگر شما انجام می‌شود',
          ip_scan_prep:'در حال آماده‌سازی…',
          ip_scan_testing:'در حال تست…',
          ip_scan_alive:' سالم',
          ip_scan_none:'هیچ IP سالمی پیدا نشد',
          ip_scan_found:' IP تمیز پیدا شد',
          ip_scan_saved_pool:'در مخزن پنل ذخیره شد',
          ip_scan_pool_empty:'مخزن اسکنر پنل خالی است',
          ip_scan_pool_applied:'آی‌پی‌های مخزن اسکنر اعمال شد',
          ip_scan_copied:'نتایج کپی شد',
          ip_scan_pool_count:'مخزن پنل: {count} آی‌پی',
          ip_scan_pool_title:'مخزن پنل',
          ip_scan_pool_desc:'مدیریت آی‌پی‌های ذخیره‌شده در مخزن پنل',
          ip_scan_source_title:'منبع آی‌پی تمیز',
          ip_scan_source_smart:'هوشمند',
          ip_scan_source_pool:'مخزن ایپی تمیز',
          ip_scan_smart_desc:'در حالت هوشمند، آی‌پی‌های تمیز از لینک زیر دریافت می‌شوند:',
          ip_scan_auto_saved:'نتایج اسکن در مخزن ذخیره شد',
          ip_scan_pool_textarea_ph:'هر خط یک IP — مثال: 1.2.3.4 یا 1.2.3.4:443',
          ip_scan_pool_save:'ذخیره مخزن',
          ip_scan_pool_clear:'پاک کردن همه',
          ip_scan_pool_saved:'مخزن ذخیره شد',
          ip_scan_pool_cleared:'مخزن پاک شد',
          ip_scan_pool_remove:'حذف',
          ip_scan_pool_max:'حداکثر ۵۰ آی‌پی در مخزن مجاز است',
          ip_scan_pool_clear_confirm:'همه آی‌پی‌های مخزن پاک شوند؟',
          ip_scan_server_title:'ایپی تمیز سرور',
          ip_scan_server_desc:'لیست آی‌پی‌های دریافتی از /clean-ip',
          ip_scan_server_operator:'اپراتور',
          ip_scan_server_all:'همه',
          ip_scan_server_refresh:'بروزرسانی',
          ip_scan_server_copy:'کپی',
          ip_scan_server_loading:'در حال بارگذاری…',
          ip_scan_server_empty:'لیست خالی است',
          dash_load_error:'خطا در بارگذاری داشبورد',
          dash_loc_not_found:'موقعیت دقیق یافت نشد',
          dash_ip_not_found:'IP یافت نشد',
          dash_map_unavailable:'نقشه در دسترس نیست',
          dash_map_no_coords:'موقعیت تقریبی روی نقشه در دسترس نیست',
          dash_direct_fetch_fail:'دریافت IP مستقیم ناموفق بود',
          dash_direct_ip_not_found:'IP مستقیم یافت نشد',
          dash_direct_error:'خطا در دریافت IP مستقیم',
          dash_direct_not_received:'IP مستقیم دریافت نشد',
          dash_main_user_not_found:'کاربر اصلی یافت نشد',
          stat_total:'کل کاربران',
          stat_online:'آنلاین',
          stat_inactive:'غیرفعال',
          stat_expired:'منقضی',
          users_loading:'در حال بارگذاری کاربران...',
          search_placeholder:'جستجوی با نام سرویس ...',
          filter_all:'همه',
          filter_active:'فعال',
          filter_inactive:'غیرفعال',
          filter_online:'آنلاین',
          filter_offline:'آفلاین',
          filter_expired:'منقضی / تمام شده',
          sort_newest:'جدیدترین',
          sort_name:'نام کاربری (الفبا)',
          sort_usage_desc:'بیشترین مصرف',
          sort_usage_asc:'کمترین مصرف',
          sort_expiry_asc:'کمترین زمان باقی‌مانده',
          bulk_selected:'{n} سرویس انتخاب شده',
          bulk_deselect:'لغو انتخاب',
          bulk_edit:'ویرایش گروهی',
          bulk_activate:'فعال',
          bulk_deactivate:'قطع',
          bulk_reset_vol:'ریست حجم',
          bulk_reset_time:'ریست زمان',
          bulk_reset_req:'ریست ریکوئست کل',
          bulk_save:'ذخیره',
          bulk_delete:'حذف',
          users_list_title:'لیست کاربران',
          users_list_desc:'مدیریت سرویس ها',
          select_all:'انتخاب همه',
          new_user:'کاربر جدید',
          add_user:'افزودن کاربر',
          th_user_ops:'نام کاربر و عملیات',
          th_sub_link:'لینک ساب',
          th_protocol:'پروتکل',
          th_port:'پورت',
          th_volume:'وضعیت حجم',
          th_expiry:'وضعیت اعتبار',
          th_requests:'مصرف ریکوئست',
          th_created:'تاریخ ساخت',
          empty_no_users:'کاربری وجود ندارد',
          empty_create_hint:'برای ساخت اولین کاربر روی «کاربر جدید» کلیک کنید',
          empty_no_results:'نتیجه‌ای یافت نشد',
          empty_no_match:'کاربری با مشخصات جستجو شده پیدا نشد',
          badge_main_service:'سرویس اصلی',
          badge_online:'● آنلاین',
          badge_offline:'آفلاین',
          badge_expired:'منقضی',
          badge_vol_done:'حجم تمام',
          badge_time_done:'زمان تمام',
          badge_disabled:'قطع',
          badge_active:'فعال',
          badge_temp:'موقت',
          btn_sub_link:'لینک ساب',
          btn_status:'وضعیت',
          btn_logs:'لاگ',
          btn_edit:'ویرایش',
          btn_delete:'حذف',
          btn_qr_sub:'qrcode اشتراک',
          btn_qr_sub_link:'qrcode لینک ساب',
          usage_label:'مصرف:',
          total_label:'کل:',
          remaining_label:'باقی‌مانده:',
          unlimited:'نامحدود',
          days_unit:'روز',
          activate_user:'فعال کردن کاربر',
          deactivate_user:'قطع کردن کاربر',
          reset_vol_title:'ریست حجم سرویس',
          reset_time_title:'ریست زمان سرویس',
          save_enabled:'ذخیره شده — حذف خودکار غیرفعال',
          save_disabled:'ذخیره (جلوگیری از حذف خودکار پس از انقضا)',
          guide_tab_android:'اندروید',
          guide_tab_ios:'آیفون',
          guide_tab_desktop:'ویندوز / مک',
          usage_warn_title:'هشدار محدودیت درخواست روزانه',
          usage_warn_body:'درخواست‌های امروز کلودفلر شما از مرز ۹۰,۰۰۰ عبور کرده است. در صورت عبور از محدودیت رایگان ۱۰۰,۰۰۰ درخواست، دسترسی به پنل و اتصالات تا ساعت ۳:۳۰ بامداد (به وقت ایران) قطع خواهد شد.',
          usage_warn_ok:'متوجه شدم',
          modal_create_title:'ایجاد کاربر جدید',
          modal_create_sub:'تنظیمات سرویس VPN را وارد کنید',
          modal_edit_title:'ویرایش کاربر',
          modal_edit_sub:'ویرایش تنظیمات «{name}»',
          modal_sys_title:'مدیریت سرویس اصلی',
          modal_sys_sub:'فقط پورت، آیپی تمیز و Proxy IP',
          modal_sys_notice:'سرویس اصلی همیشه <strong>نامحدود</strong> است. فقط پورت، آیپی تمیز و Proxy IP قابل تغییر است.',
          um_basic_info:'اطلاعات پایه',
          um_username:'نام سرویس',
          um_volume:'حجم (GB)',
          um_expiry:'اعتبار (روز)',
          um_max_conn:'ریکوئست کل',
          um_max_req_daily:'ریکوئست روزانه',
          um_ports:'پورت‌های اتصال',
          um_ports_tls:'پورت‌های امن (TLS)',
          um_ports_nontls:'پورت‌های معمولی (Non-TLS)',
          um_advanced:'تنظیمات پیشرفته',
          um_clean_ip:'آیپی تمیز ',
          um_ip_pool:'دریافت ایپی تمیز از سرور',
          um_scanner_pool:'استفاده از مخزن اسکنر پنل',
          um_fingerprint:'Fingerprint ',
          um_proxy_ip:'Proxy IP اختصاصی (اختیاری)',
          um_proxy_hint:'اگر خالی باشد، هنگام اتصال از پول CDN پیش‌فرض پنل استفاده می‌شود.',
          um_proxy_placeholder:'خالی = استفاده از پروکسی پنل',
          um_name_placeholder:'مثال: ali',
          fp_random:'Random (اتفاقی) — پیش‌فرض',
          fp_randomized:'Randomized (پویا)',
          cancel:'انصراف',
          create_user:'ایجاد کاربر',
          save_changes:'ذخیره تغییرات',
          save_settings:'ذخیره تنظیمات',
          creating:'در حال ایجاد...',
          saving:'در حال ذخیره تغییرات...',
          applying:'در حال اعمال...',
          bulk_edit_title:'ویرایش گروهی',
          bulk_apply:'اعمال روی انتخاب‌شده‌ها',
          bulk_clean_ip:'آیپی تمیز',
          bulk_ip_pool:'مخزن آیپی',
          ip_pool_title:'دریافت ایپی تمیز و دامنه پشت کلادفلر',
          ip_operator:'اوپراتور',
          ip_count:'تعداد',
          ip_fetch:'دریافت',
          qr_scan:'اسکن کد QR',
          map_title:'نقشه موقعیت تقریبی',
          close:'بستن',
          confirm_title:'تأیید عملیات',
          confirm_ok:'تأیید',
          confirm_cancel:'انصراف',
          confirm_yes:'بله، انجام شود',
          confirm_yes_delete:'بله، حذف شود',
          confirm_yes_reset:'بله، ریست شود',
          confirm_yes_restore:'بله، بازیابی شود',
          confirm_yes_logout:'بله، خروج',
          toast_select_service:'ابتدا حداقل یک سرویس را انتخاب کنید',
          toast_no_selected:'هیچ سرویسی انتخاب نشده است',
          toast_select_field:'حداقل یک فیلد را برای اعمال انتخاب کنید',
          toast_select_port:'حداقل یک پورت انتخاب کنید',
          toast_bulk_done:'عملیات گروهی روی {n} سرویس انجام شد',
          toast_bulk_edit_done:'ویرایش گروهی روی {n} سرویس انجام شد',
          toast_bulk_fail:'خطا در عملیات گروهی',
          toast_bulk_edit_fail:'خطا در ویرایش گروهی',
          toast_op_fail:'عملیات ناموفق بود',
          toast_sys_always_saved:'سرویس اصلی همیشه ذخیره است',
          toast_sys_status_locked:'وضعیت سرویس اصلی قابل تغییر نیست',
          toast_sys_reset_locked:'ریست حجم یا زمان سرویس اصلی مجاز نیست',
          toast_sys_no_delete:'این کاربر سیستمی است و قابل حذف نیست',
          toast_sub_copied:'لینک ساب با موفقیت کپی شد',
          toast_sub_copy_fail:'خطا در کپی کردن لینک ساب',
          toast_node_copied:'کانفیگ نود کپی شد',
          toast_node_copy_fail:'خطا در کپی کانفیگ نود',
          toast_user_deleted:'کاربر با موفقیت حذف شد',
          toast_user_not_found:'کاربر یافت نشد!',
          toast_conn_error:'خطا در برقراری ارتباط با سرور',
          toast_tg_saved:'تنظیمات تلگرام ذخیره شد',
          toast_save_fail:'خطا در ذخیره',
          toast_logs_cleared:'لاگ‌ها حذف شدند',
          toast_logs_load_fail:'خطا در بارگذاری لاگ‌ها',
          toast_backup_restored:'بکاپ با موفقیت بازیابی شد ({n} کاربر)',
          toast_backup_fail:'خطا در بازیابی',
          toast_backup_download_fail:'خطا در دریافت بکاپ',
          toast_reset_vol_ok:'ریست {type} با موفقیت انجام شد',
          toast_reset_vol:'حجم',
          toast_reset_time:'زمان',
          bulk_confirm_title:'عملیات گروهی',
          bulk_confirm_msg:'آیا از «{action}» مطمئن هستید؟',
          bulk_delete_n:'حذف {n} سرویس',
          bulk_activate_n:'فعال‌سازی {n} سرویس',
          bulk_deactivate_n:'قطع {n} سرویس',
          bulk_reset_vol_n:'ریست حجم {n} سرویس',
          bulk_reset_time_n:'ریست زمان {n} سرویس',
          bulk_reset_req_n:'ریست ریکوئست کل {n} سرویس',
          bulk_enable_save_n:'فعال‌سازی ذخیره برای {n} سرویس',
          reset_confirm_title:'ریست سرویس',
          reset_confirm_msg:'آیا از ریست {type} سرویس کاربر «{name}» مطمئن هستید؟',
          delete_user_title:'حذف کاربر',
          delete_user_msg:'آیا از حذف کاربر «{name}» مطمئن هستید؟',
          restore_confirm_title:'بازیابی بکاپ',
          restore_confirm_msg:'با بازیابی بکاپ، تمام کاربران و تنظیمات فعلی جایگزین می‌شوند. ادامه می‌دهید؟',
          clear_logs_confirm:'آیا از حذف همه لاگ‌های پنل مطمئن هستید؟',
          clear_logs_title:'حذف لاگ‌ها',
          logout_confirm:'آیا می‌خواهید از پنل خارج شوید؟',
          logout_title:'خروج از پنل',
          alert_select_port:'⚠️ لطفا حداقل یک پورت را برای اتصال انتخاب کنید!',
          alert_error:'خطا: {msg}',
          users_load_error:'خطا در دریافت اطلاعات از سرور',
          users_parse_error:'خطا در پردازش اطلاعات کاربران',
          update_title:'به‌روزرسانی پنل',
          update_msg:'در حال دریافت و نصب نسخه جدید...',
          update_available_title:'به‌روزرسانی موجود است',
          update_available_msg:'نسخه جدید {remote} در دسترس است.\\nنسخه فعلی پنل شما: {current}',
          update_later:'بعداً',
          update_complete:'اپدیت با موفقیت انجام شد',
          update_complete_reload:'در حال بارگذاری مجدد پنل...',
          update_failed:'خطا در به‌روزرسانی',
          update_failed_msg:'به‌روزرسانی پنل انجام نشد.',
          update_cf_token_redirect:'توکن CF_TOKEN معتبر نیست. در حال انتقال به صفحه راه‌اندازی...',
          panel_update_title:'به‌روزرسانی پنل',
          panel_update_desc:'نسخه جدید از سرور دریافت و پنل شما اپدیت و ویژگی های جدید اضافه خواهد شد.',
          panel_update_current:'نسخه فعلی',
          panel_update_remote:'نسخه سرور',
          panel_update_btn:'به‌روزرسانی پنل',
          panel_update_confirm:'نسخه جدید از سرور مدیریت دریافت و روی ورکر شما نصب می‌شود. ادامه می‌دهید؟',
          panel_update_available:'نسخه {remote} موجود است — نسخه فعلی شما {current}',
          panel_update_latest:'پنل شما به‌روز است.',
          increase:'افزایش',
          decrease:'کاهش',
          cf_token_required:'توکن API کلودفلر را وارد کنید',
          reset_panel_fail:'خطا در بازنشانی پنل',
          reset_panel_yes:'بله، بازنشانی شود',
          about_kicker:'تیم توسعه‌ی زیرساخت آزاد',
          about_hero_title:'عبور از فیلترینگ، با پنل خودت',
          about_hero_desc:'NEXA گروهی از توسعه‌دهنده‌هاست که ابزارهای متن‌باز برای دسترسی آزاد به اینترنت می‌سازد — روی زیرساخت Cloudflare Workers، بدون واسطه، بدون فروش کانفیگ، و کاملاً در اختیار خودت.',
          about_kicker2:'درباره‌ی نکسا',
          about_title:'پنل شخصی، بدون واسطه و هزینه',
          about_desc:'NEXA به جای فروش سرویس، ابزار عمومی در اختیار می‌گذارد. هرکسی می‌تواند در چند دقیقه، روی اکانت Cloudflare خودش، پنل مدیریت اتصال شخصی‌اش را بالا بیاورد؛ سریع، پایدار و بدون نیاز به اعتماد به یک سرور واسط.',
          about_f1_title:'متن‌باز و شفاف',
          about_f1_desc:'کد پنل کاملاً قابل مشاهده است؛ هرچه در پنل اجرا می‌شود را می‌توانی پیش از استفاده بررسی کنی.',
          about_f2_title:'زیرساخت خودت',
          about_f2_desc:'پنل روی حساب Cloudflare شخصی تو اجرا می‌شود؛ داده‌ها و اتصال‌ها از کانال هیچ سرور واسطی عبور نمی‌کند.',
          about_f3_title:'راه‌اندازی سریع',
          about_f3_desc:'در کمتر از پنج دقیقه، بدون دانش عمیق برنامه‌نویسی، پنل شخصی‌ات آماده و در دسترس است.',
          about_f4_title:'بدون قصد فروش',
          about_f4_desc:'هدف NEXA آموزش و در دسترس گذاشتن ابزار است، نه فروش کانفیگ یا اشتراک اینترنت.',
          about_social:'ما را در شبکه‌های اجتماعی دنبال کنید',
          about_social_desc:'آموزش‌ها، به‌روزرسانی‌ها و اخبار تیم NEXA را از یوتیوب و تلگرام دنبال کن.',
          tg_notify_title:'اعلان‌های تلگرام',
          tg_enable:'فعال‌سازی اعلان تلگرام',
          tg_token:'توکن ربات',
          tg_chat_id:'شناسه چت / کاربر',
          tg_chat_hint:'برای دریافت شناسه چت خود به بات ما مراجعه کنید و ایدی عددی خود را دریافت کنید . ادرس بات : <a href="https://t.me/nexateam_bot" target="_blank" rel="noopener noreferrer">https://t.me/nexateam_bot</a>',
          tg_status_on:'روشن',
          tg_status_off:'خاموش',
          save:'ذخیره',
          save_success:'تنظیمات با موفقیت ذخیره شد',
          logs_desc:'تمام رویدادهای مهم پنل',
          refresh:'بروزرسانی',
          clear_logs:'حذف همه',
          loading:'در حال بارگذاری...',
          logs_empty:'هنوز رویدادی ثبت نشده است.',
          col_time:'زمان',
          col_action:'عملیات',
          col_details:'جزئیات',
          backup_desc:'کاربران، تمام تنظیمات پنل، لاگ فعالیت و لاگ اتصال را دانلود یا بازیابی کنید.',
          backup_download:'دریافت بکاپ',
          backup_upload:'بارگذاری بکاپ',
          backup_includes:'تمام بخش های پنل شامل میشود.',
          backup_auto_title:'بکاپ خودکار روزانه',
          backup_auto_desc:'هر روز ساعت ۰۰:۰۰ (به وقت تهران) بکاپ کامل به تلگرام ارسال می‌شود — نیاز به تنظیم توکن و شناسه چت در بخش لاگ فعالیت دارد.',
          backup_tg_hint:'برای ارسال بکاپ، ابتدا توکن ربات و شناسه چت را در بخش «لاگ فعالیت» تنظیم کنید.',
          backup_cron_hint:'برای اجرای دقیق ساعت ۰۰:۰۰، در Cloudflare Workers یک Cron Trigger با مقدار 30 20 * * * اضافه کنید. (اگر پنل را با سایت یا ربات ساختید نیاز به تنظیم نیست .)',
          backup_tg_send:'ارسال بکاپ به تلگرام (تست)',
          backup_last_run:'آخرین بکاپ خودکار',
          backup_last_never:'هنوز اجرا نشده',
          backup_tg_sent:'بکاپ با موفقیت به تلگرام ارسال شد',
          backup_tg_fail:'خطا در ارسال بکاپ به تلگرام',
          backup_auto_saved:'تنظیمات بکاپ خودکار ذخیره شد',
          reset_panel_title:'بازنشانی تمام تنظیمات',
          reset_panel_desc:'تمام کاربران، تنظیمات پروکسی، اعلان تلگرام و لاگ‌ها حذف می‌شوند. پنل مانند اولین ورود خواهد بود. رمز عبور مدیریت حفظ می‌شود.',
          reset_panel_btn:'بازنشانی تمام تنظیمات',
          reset_panel_confirm:'با بازنشانی، تمام کاربران (به‌جز سرویس اصلی)، تنظیمات و لاگ‌ها حذف می‌شوند. این عمل قابل بازگشت نیست. ادامه می‌دهید؟',
          reset_panel_success:'پنل با موفقیت بازنشانی شد',
          pwd_info_title:'تغییر رمز عبور مدیریت',
          pwd_storage_note:'رمز عبور در متغیر ADMIN (نوع Text) در Cloudflare Workers ذخیره می‌شود.',
          pwd_current_label:'رمز عبور فعلی',
          pwd_new_label:'رمز عبور جدید',
          pwd_confirm_label:'تکرار رمز جدید',
          pwd_change_btn:'تغییر رمز عبور',
          pwd_change_success:'رمز عبور با موفقیت تغییر کرد',
          cf_creds_title:'تنظیمات Cloudflare API',
          cf_creds_note:'فقط CF_TOKEN را وارد کنید — Account ID خودکار از توکن دریافت و در ورکر ذخیره می‌شود.',
          cf_token_label:'CF_TOKEN',
          cf_ac_id_label:'Account ID',
          cf_ac_id_auto_hint:'نیازی به وارد کردن دستی نیست',
          cf_creds_save:'ذخیره توکن',
          cf_creds_success:'توکن با موفقیت ذخیره شد',
          cf_token_hint_set:'توکن فعلی تنظیم شده — برای تغییر، توکن جدید وارد کنید',
          kill_all_services_label:'قطع تمامی سرویس‌ها',
          kill_all_services_desc:'با روشن شدن این گزینه تمامی سرویس‌ها متوقف و قطع خواهند شد در صورتی که مورد سو استفاده قرار گرفتید این گزینه را روشن کنید و با عوض کردن ادرس ها پنل خود را امن کنید .',
          kill_all_services_on:'تمامی سرویس‌ها قطع شدند',
          kill_all_services_off:'سرویس‌ها مجدداً فعال شدند',
          proxy_save_base:'تنظیمات Proxy IP ذخیره شد',
          proxy_change_labels:{proxy_ips:'آدرس‌های Proxy IP (CDN)'},
          proxy_ips_label:'آدرس‌های Proxy IP (CDN)',
          proxy_ips_hint:'خالی = استفاده از پول CDN پیش‌فرض (در صورت خالی گذاشتن از ایپی پروکسی پنل استفاده میشود. و ...)',
          blocked_domains_title:'مسدودسازی دامنه',
          blocked_domains_desc:'دامنه‌هایی که وارد کنید از طریق پروکسی باز نمی‌شوند. هر دامنه در یک خط.',
          blocked_domains_enable:'فعال‌سازی مسدودسازی',
          blocked_domains_label:'لیست دامنه‌های مسدود',
          blocked_domains_hint:'مثال: example.com — زیردامنه‌ها هم مسدود می‌شوند',
          blocked_domains_save:'ذخیره مسدودسازی',
          blocked_domains_saved:'مسدودسازی دامنه ذخیره شد',
          wc_protocol_title:'تنظیمات ادرس صفحات',
          wc_protocol_desc:'تنظیمات انتقال، مسیر اتصال و آدرس صفحات',
          wc_protocol_label:'پروتکل',
          wc_transport_label:'حمل‌ونقل',
          wc_grpc_mode_label:'حالت gRPC',
          wc_fingerprint_label:'TLS Fingerprint',
          wc_tls_fragment_label:'TLS Fragment',
          wc_transport_path_label:'مسیر انتقال',
          wc_transport_path_hint:'وقتی در بخش «پروکسی CDN» یک Proxy IP ست کنید، این مقدار خودکار روی fixip_<proxy-ip> تنظیم می‌شود.',
          wc_var_username:'نام کاربری سرویس',
          wc_var_used:'حجم مصرف‌شده تا این لحظه',
          wc_var_total:'حجم کل سرویس (∞ یعنی نامحدود)',
          wc_var_dayremind:'تعداد روزهای باقی‌مانده تا انقضا',
          wc_var_expiry:'کل مدت اعتبار به روز (∞ یعنی نامحدود)',
          wc_var_port:'پورتی که این کانفیگ خاص روی آن ساخته شده',
          wc_var_proxyip:'آدرس Proxy IP فعلیِ تنظیم‌شده در بخش «پروکسی CDN»',
          wc_var_flag:'پرچم کشوری که برای این پروکسی مشخص کردی (فرمت #کدکشور جلوی آی‌پی)',
          adult_block_title:'مسدودسازی محتوای بزرگسال',
          adult_block_label:'فیلتر کردن محتوای بزرگ سال (+18)',
          adult_block_save:'ذخیره مسدودسازی بزرگسال',
          adult_block_saved:'مسدودسازی محتوای بزرگسال ذخیره شد',
          adult_block_save_fail:'خطا در ذخیره تنظیمات',
          adult_block_saving:'در حال ذخیره...',
          pwd_err_current_required:'رمز عبور فعلی را وارد کنید',
          pwd_err_minlength:'رمز عبور جدید باید حداقل ۴ کاراکتر باشد',
          pwd_err_mismatch:'رمز عبور جدید و تکرار آن یکسان نیستند',
          pwd_err_generic:'خطا در تغییر رمز عبور',
          dash_qr_zoom_title:'بزرگ‌نمایی QR',
          wc_skip_cert_label:'رد کردن اعتبارسنجی TLS',
          wc_random_path_label:'مسیر تصادفی',
          wc_path_empty_hint:'خالی = پیش‌فرض',
          wc_sub_page_path_label:'آدرس صفحه ساب',
          wc_sub_page_path_hint:'مثال : /sub/(اسم سرویس)',
          wc_logs_page_path_label:'آدرس صفحه لاگ‌ها',
          wc_logs_page_path_hint:'مثال : /logs/(نام سرویس)',
          resist_title:'سیاست مقاومت',
          resist_desc:'قوانین مسیریابی Clash/Sing-box — پروفایل ایران/سانسور بال',
          resist_profile_label:'پروفایل',
          resist_profile_custom:'سفارشی',
          resist_profile_iran_high:'ایران / سانسور بال',
          resist_domestic_bypass:'ترافیک ایران مستقیم',
          resist_block_quic:'مسدودسازی QUIC',
          resist_ad_block:'مسدودسازی تبلیغات',
          resist_malware_block:'مسدودسازی بدافزار',
          resist_phishing_block:'مسدودسازی فیشینگ',
          resist_bypass_sanctions:'دور زدن تحریم‌ها',
          resist_doh:'DNS رمزنگاری‌شده (DoH)',
          resist_anti_sanction_dns:'DNS ضدتحریم',
          resist_save_btn:'ذخیره سیاست مقاومت',
          wc_security_title:'امنیت',
          wc_security_desc:'ECH و اتصال به پنل مرکزی',
          wc_ech_enable_label:'فعال‌سازی ECH',
          wc_ech_sni_label:'ECH SNI',
          wc_ech_dns_label:'ECH DoH',
          wc_central_api_label:'Central API (اختیاری)',
          wc_sub_title:'اشتراک',
          wc_sub_desc:'نام اشتراک، آدرس تبدیل‌گر و صفحه وضعیت کاربر',
          wc_sub_name_label:'نام اشتراک',
          wc_sub_update_label:'بازه به‌روزرسانی (ساعت)',
          wc_admin_page_path_label:'آدرس پنل مدیریت',
          wc_status_path_label:'آدرس صفحه وضعیت',
          wc_status_path_hint:'مثلاً servicestat یا status — لینک نهایی: /آدرس/نام‌کاربر',
          wc_sub_converter_label:'API تبدیل اشتراک',
          wc_sub_config_label:'آدرس قوانین مسیریابی (.ini)',
          wc_sub_emoji_label:'پرچم ایموجی در نام نودها',
          wc_naming_title:'نام‌گذاری کانفیگ‌ها',
          wc_naming_desc:'در این بخش میتوانید نام کانفیگ ها را با متغیر های ارائه شده نامگذاری کنید.',
          wc_first_remark_label:'کانفیگ اول (غیرقابل تغییر)',
          wc_info_remark_label:'کانفیگ مشخصات سرویس',
          wc_vars_hint:'متغیرها: {username} {dayremind} {used} {total} {expiry} {port} — مثال dayremind روزهای باقیمانده را نشان می‌دهد',
          wc_node_remark_label:'نام کانفیگ‌های اتصال',
          wc_save_btn:'ذخیره تنظیمات ',
          coming_soon_title:'در حال توسعه',
          coming_soon_desc:'به زودی...',
          guide_android_title:'راهنمای اتصال — اندروید',
          guide_android_1:'اپ V2rayNG را از لینک زیر دانلود کنید:<br><a href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" rel="noopener noreferrer" class="adm-guide-link">https://github.com/2dust/v2rayNG/releases/latest</a>',
          guide_android_2:'اپ را باز کنید',
          guide_android_3:'روی آیکون + در بالا راست بزنید',
          guide_android_4:'گزینه <strong>Import config from clipboard</strong> را انتخاب کنید<br><span class="text-xs opacity-70">(لینک کانفیگ باید از قبل کپی شده باشد)</span>',
          guide_android_5:'کانفیگ در لیست ظاهر می‌شود — روی آن بزنید تا انتخاب شود',
          guide_android_6:'دکمه اتصال پایین صفحه را بزنید، اکنون با موفقیت متصل شدید.',
          guide_ios_title:'راهنمای اتصال — آیفون (iOS)',
          guide_ios_1:'اپ Streisand را از App Store دانلود کنید:<br><a href="https://apps.apple.com/app/streisand/id6450534064" target="_blank" rel="noopener noreferrer" class="adm-guide-link">https://apps.apple.com/app/streisand/id6450534064</a>',
          guide_ios_2:'اپ را باز کنید',
          guide_ios_3:'روی + در بالا راست بزنید',
          guide_ios_4:'گزینه <strong>Import from Clipboard</strong> را بزنید<br><span class="text-xs opacity-70">(لینک کانفیگ باید از قبل کپی شده باشد)</span>',
          guide_ios_5:'کانفیگ اضافه شد — کنارش Connect را بزنید',
          guide_ios_6:'در پنجره‌ای که باز می‌شود Allow را بزنید',
          guide_desktop_title:'راهنمای اتصال — ویندوز / مک',
          guide_windows:'ویندوز',
          guide_mac:'مک',
          guide_win_1:'نرم‌افزار v2rayN را دانلود کنید:<br><a href="https://github.com/2dust/v2rayN/releases/latest" target="_blank" rel="noopener noreferrer" class="adm-guide-link">https://github.com/2dust/v2rayN/releases/latest</a>',
          guide_win_2:'فایل zip را extract کنید و v2rayN.exe را اجرا کنید',
          guide_win_3:'در تسک‌بار روی آیکون برنامه راست‌کلیک کنید',
          guide_win_4:'گزینه + را بزنید و نام دلخواه و لینک کپی شده را وارد کنید',
          guide_win_5:'از منوی بالا روی گروه اشتراک زده و گزینه سوم را بزنید',
          guide_win_6:'برای متصل شدن در پایین صفحه گزینه پاک کردن سیستم پروکسی را روی گزینه دوم بگذارید',
          guide_mac_1:'اپ FoXray را از Mac App Store دانلود کنید',
          guide_mac_2:'روی + بزنید و Import from clipboard را انتخاب کنید',
          guide_mac_3:'کانفیگ را انتخاب و Connect بزنید',
          guide_support:'نتوانستید متصل شوید؟ <a href="https://t.me/nexateam_bot" target="_blank" rel="noopener noreferrer" class="adm-guide-support">از قسمت پشتیبانی در بات کمک بگیرید</a>'},
          en: {
          nav_main:'Main Menu',
          nav_dashboard:'Dashboard',
          nav_users:'User Management',
          nav_guide:'Connection Guide',
          nav_node_server:'Node Server',
          nav_ip_scanner:'Clean IP Scanner',
          nav_cdn_proxy:'CDN Proxy',
          nav_logs:'Activity Log',
          nav_wireguard:'WireGuard Service',
          nav_warp:'WARP Service',
          nav_settings:'Panel Settings',
          nav_update_panel:'Update Panel',
          nav_about:'About Us',
          nav_backup:'Panel Backup',
          nav_tg_channel:'Nexa Telegram Channel',
          nav_tg_bot:'Nexa Support Bot',
          nav_collapse:'Collapse',
          nav_expand:'Expand',
          nav_logout:'Logout',
          panel_version:'Version ${PANEL_VERSION}',
          panel_subtitle:'Admin Panel',
          aria_menu:'Menu',
          aria_collapse:'Collapse',
          aria_close:'Close',
          theme_toggle:'Toggle theme',
          dash_sub_title:'Main Subscription Link',
          dash_manage_btn:'Click to manage this service',
          dash_copy_sub:'Copy subscription',
          node_server_title:'Main Node',
          node_server_desc:'Your node on all Cloudflare TLS ports — use the Worker domain directly, separate from subscription. Copy each port.',
          node_server_empty:'No node configs available',
          node_server_copy:'Copy',
          node_server_qr:'QR',
          dash_worker_usage:'Worker Request Usage',
          dash_reset_label:'Reset at:',
          dash_reset_meta:'Requests reset daily at 3:30 AM Tehran time',
          dash_top_req_title:'Top total request usage',
          dash_top_req_empty:'No usage recorded yet',
          dash_ip_title:'Your IP Details',
          dash_via_server:'Via this server',
          dash_direct_ip:'Direct IP (no proxy)',
          dash_city:'City',
          dash_region:'Region',
          dash_country:'Country',
          dash_fetching_loc:'Fetching location...',
          dash_click_refresh:'Click refresh to fetch',
          dash_loading_map:'Loading map...',
          dash_zoom_map:'Zoom',
          dash_map_via_server:'Map: via server',
          dash_map_direct:'Map: direct IP',
          dash_updating:'Updating...',
          ip_scanner_desc:'Find the fastest Cloudflare clean IPs for your network',
          ip_scan_total:'Tests to run',
          ip_scan_keep:'Keep best',
          ip_scan_ports_label:'Scan ports',
          ip_scan_ports_required:'Select at least one port',
          ip_scan_start:'Start scan',
          ip_scan_results:'Clean IP results',
          cdn_cf_banner_text:'Connect your Cloudflare token once (under a minute) for auto-updates and Worker usage stats.',
          cdn_cf_connect:'Connect token',
          cdn_access_title:'Cloudflare CDN access',
          cdn_access_desc:'You can get the proxy IP of your choice from the Find Proxy section.',
          cdn_mode_label:'Mode',
          cdn_proxyip_label:'PROXYIP address',
          cdn_proxyip_hint:'One line = one location. To show a country flag in the config name, add <code>#COUNTRYCODE</code> at the end of the line (e.g. <code>1.2.3.4#DE</code> or <code>5.6.7.8:2053#US</code>)',
          cdn_chain_label:'Proxy address(es)',
          cdn_chain_hint:'One proxy per line. One = fixed IP; two-three = auto rotation and failover.',
          cdn_rotate_label:'Auto-rotate',
          cdn_rotate_off:'Off, use all',
          cdn_rotate_daily:'Daily',
          cdn_rotate_weekly:'Weekly',
          cdn_rotate_count:'Active count',
          cdn_rotate_hint:'With several proxies, a different subset is served each day/week.',
          cdn_verify:'Verify',
          cdn_save:'Save',
          cdn_finder_title:'Find proxies',
          cdn_finder_load:'Load list',
          cdn_finder_desc:'You can use proxies from 68 countries by loading lists.',
          cdn_country_label:'Country',
          cdn_pick_label:'Proxy',
          cdn_use_selected:'Use selected',
          cdn_proxy_saved:'CDN proxy settings saved',
          cdn_proxy_fetching:'Fetching list...',
          cdn_proxy_list_ok:'List loaded',
          cdn_proxy_list_stats:'{proxies} proxies — {countries} countries',
          cdn_proxy_use_ok:'Filled — now save',
          cdn_proxy_verify_proxyip:'PROXYIP needs no separate test — checked on connect. Just Save.',
          cdn_proxy_verify_ok:'Proxy reachable',
          cdn_proxy_verify_fail:'No response',
          cdn_proxy_enter_first:'Enter a proxy first',
          ip_scan_copy:'Copy results',
          ip_scan_save_pool:'Save to panel pool',
          ip_scan_foot:'Scan runs entirely in your browser',
          ip_scan_prep:'Preparing…',
          ip_scan_testing:'Testing…',
          ip_scan_alive:' alive',
          ip_scan_none:'No responsive IP found',
          ip_scan_found:' clean IPs found',
          ip_scan_saved_pool:'Saved to panel pool',
          ip_scan_pool_empty:'Panel scanner pool is empty',
          ip_scan_pool_applied:'Scanner pool IPs applied',
          ip_scan_copied:'Results copied',
          ip_scan_pool_count:'Panel pool: {count} IPs',
          ip_scan_pool_title:'Panel pool',
          ip_scan_pool_desc:'Manage IPs stored in the panel repository',
          ip_scan_source_title:'Clean IP source',
          ip_scan_source_smart:'Smart',
          ip_scan_source_pool:'Clean IP pool',
          ip_scan_smart_desc:'In Smart mode, clean IPs are fetched from this URL:',
          ip_scan_auto_saved:'Scan results saved to pool',
          ip_scan_pool_textarea_ph:'One IP per line — e.g. 1.2.3.4 or 1.2.3.4:443',
          ip_scan_pool_save:'Save pool',
          ip_scan_pool_clear:'Clear all',
          ip_scan_pool_saved:'Pool saved',
          ip_scan_pool_cleared:'Pool cleared',
          ip_scan_pool_remove:'Remove',
          ip_scan_pool_max:'Maximum 50 IPs allowed in pool',
          ip_scan_pool_clear_confirm:'Clear all pool IPs?',
          ip_scan_server_title:'Server clean IPs',
          ip_scan_server_desc:'IPs fetched from /clean-ip',
          ip_scan_server_operator:'Operator',
          ip_scan_server_all:'All',
          ip_scan_server_refresh:'Refresh',
          ip_scan_server_copy:'Copy',
          ip_scan_server_loading:'Loading…',
          ip_scan_server_empty:'List is empty',
          dash_load_error:'Failed to load dashboard',
          dash_loc_not_found:'Exact location not found',
          dash_ip_not_found:'IP not found',
          dash_map_unavailable:'Map unavailable',
          dash_map_no_coords:'Approximate map location unavailable',
          dash_direct_fetch_fail:'Failed to fetch direct IP',
          dash_direct_ip_not_found:'Direct IP not found',
          dash_direct_error:'Error fetching direct IP',
          dash_direct_not_received:'Direct IP not received',
          dash_main_user_not_found:'Main user not found',
          stat_total:'Total Users',
          stat_online:'Online',
          stat_inactive:'Inactive',
          stat_expired:'Expired',
          users_loading:'Loading users...',
          search_placeholder:'Search by service name...',
          filter_all:'All',
          filter_active:'Active',
          filter_inactive:'Inactive',
          filter_online:'Online',
          filter_offline:'Offline',
          filter_expired:'Expired / Finished',
          sort_newest:'Newest',
          sort_name:'Username (A–Z)',
          sort_usage_desc:'Highest usage',
          sort_usage_asc:'Lowest usage',
          sort_expiry_asc:'Least time remaining',
          bulk_selected:'{n} services selected',
          bulk_deselect:'Clear selection',
          bulk_edit:'Bulk edit',
          bulk_activate:'Activate',
          bulk_deactivate:'Disable',
          bulk_reset_vol:'Reset volume',
          bulk_reset_time:'Reset time',
          bulk_reset_req:'Reset total requests',
          bulk_save:'Save',
          bulk_delete:'Delete',
          users_list_title:'User List',
          users_list_desc:'Manage services',
          select_all:'Select all',
          new_user:'New user',
          add_user:'Add user',
          th_user_ops:'User & actions',
          th_sub_link:'Sub link',
          th_protocol:'Protocol',
          th_port:'Port',
          th_volume:'Volume status',
          th_expiry:'Expiry status',
          th_requests:'Request usage',
          th_created:'Created',
          empty_no_users:'No users yet',
          empty_create_hint:'Click "New user" to create your first user',
          empty_no_results:'No results found',
          empty_no_match:'No user matches your search',
          badge_main_service:'Main service',
          badge_online:'● Online',
          badge_offline:'Offline',
          badge_expired:'Expired',
          badge_vol_done:'Volume used up',
          badge_time_done:'Time expired',
          badge_disabled:'Disabled',
          badge_active:'Active',
          badge_temp:'Temporary',
          btn_sub_link:'Sub link',
          btn_status:'Status',
          btn_logs:'Logs',
          btn_edit:'Edit',
          btn_delete:'Delete',
          btn_qr_sub:'Subscription QR',
          btn_qr_sub_link:'Sub link QR',
          usage_label:'Used:',
          total_label:'Total:',
          remaining_label:'Remaining:',
          unlimited:'Unlimited',
          days_unit:'days',
          activate_user:'Activate user',
          deactivate_user:'Disable user',
          reset_vol_title:'Reset service volume',
          reset_time_title:'Reset service time',
          save_enabled:'Saved — auto-delete disabled',
          save_disabled:'Save (prevent auto-delete after expiry)',
          guide_tab_android:'Android',
          guide_tab_ios:'iPhone',
          guide_tab_desktop:'Windows / Mac',
          usage_warn_title:'Daily request limit warning',
          usage_warn_body:'Your Cloudflare requests today have exceeded 90,000. If you pass the free 100,000 request limit, panel access and connections will be blocked until 3:30 AM Tehran time.',
          usage_warn_ok:'Got it',
          modal_create_title:'Create new user',
          modal_create_sub:'Enter VPN service settings',
          modal_edit_title:'Edit user',
          modal_edit_sub:'Edit settings for "{name}"',
          modal_sys_title:'Manage main service',
          modal_sys_sub:'Only port, clean IP and Proxy IP',
          modal_sys_notice:'Main service is always <strong>unlimited</strong>. Only port, clean IP and Proxy IP can be changed.',
          um_basic_info:'Basic info',
          um_username:'Service name',
          um_volume:'Volume (GB)',
          um_expiry:'Expiry (days)',
          um_max_conn:'Total requests',
          um_max_req_daily:'Daily requests',
          um_ports:'Connection ports',
          um_ports_tls:'Secure ports (TLS)',
          um_ports_nontls:'Regular ports (Non-TLS)',
          um_advanced:'Advanced settings',
          um_clean_ip:'Cloudflare clean IP (optional)',
          um_ip_pool:'Clean IP pool',
          um_scanner_pool:'Use panel scanner pool',
          um_fingerprint:'Browser fingerprint simulator',
          um_proxy_ip:'Custom Proxy IP (optional)',
          um_proxy_hint:'If empty, the panel default CDN pool will be used on connect.',
          um_proxy_placeholder:'Empty = use panel proxy',
          um_name_placeholder:'e.g. ali',
          fp_random:'Random — default',
          fp_randomized:'Randomized (dynamic)',
          cancel:'Cancel',
          create_user:'Create user',
          save_changes:'Save changes',
          save_settings:'Save settings',
          creating:'Creating...',
          saving:'Saving changes...',
          applying:'Applying...',
          bulk_edit_title:'Bulk edit',
          bulk_apply:'Apply to selected',
          bulk_clean_ip:'Clean IP',
          bulk_ip_pool:'IP pool',
          ip_pool_title:'Clean IP & domain pool',
          ip_operator:'Operator',
          ip_count:'Count',
          ip_fetch:'Fetch',
          qr_scan:'Scan QR code',
          map_title:'Approximate location map',
          close:'Close',
          confirm_title:'Confirm action',
          confirm_ok:'Confirm',
          confirm_cancel:'Cancel',
          confirm_yes:'Yes, proceed',
          confirm_yes_delete:'Yes, delete',
          confirm_yes_reset:'Yes, reset',
          confirm_yes_restore:'Yes, restore',
          confirm_yes_logout:'Yes, logout',
          toast_select_service:'Select at least one service first',
          toast_no_selected:'No services selected',
          toast_select_field:'Select at least one field to apply',
          toast_select_port:'Select at least one port',
          toast_bulk_done:'Bulk action completed on {n} services',
          toast_bulk_edit_done:'Bulk edit applied to {n} services',
          toast_bulk_fail:'Bulk action failed',
          toast_bulk_edit_fail:'Bulk edit failed',
          toast_op_fail:'Operation failed',
          toast_sys_always_saved:'Main service is always saved',
          toast_sys_status_locked:'Main service status cannot be changed',
          toast_sys_reset_locked:'Cannot reset main service volume or time',
          toast_sys_no_delete:'System user cannot be deleted',
          toast_sub_copied:'Subscription link copied',
          toast_sub_copy_fail:'Failed to copy subscription link',
          toast_node_copied:'Node config copied',
          toast_node_copy_fail:'Failed to copy node config',
          toast_user_deleted:'User deleted successfully',
          toast_user_not_found:'User not found!',
          toast_conn_error:'Connection error',
          toast_tg_saved:'Telegram settings saved',
          toast_save_fail:'Save failed',
          toast_logs_cleared:'Logs cleared',
          toast_logs_load_fail:'Failed to load logs',
          toast_backup_restored:'Backup restored ({n} users)',
          toast_backup_fail:'Restore failed',
          toast_backup_download_fail:'Failed to download backup',
          toast_reset_vol_ok:'{type} reset successfully',
          toast_reset_vol:'Volume',
          toast_reset_time:'Time',
          bulk_confirm_title:'Bulk action',
          bulk_confirm_msg:'Are you sure you want to "{action}"?',
          bulk_delete_n:'Delete {n} services',
          bulk_activate_n:'Activate {n} services',
          bulk_deactivate_n:'Disable {n} services',
          bulk_reset_vol_n:'Reset volume for {n} services',
          bulk_reset_time_n:'Reset time for {n} services',
          bulk_reset_req_n:'Reset total requests for {n} services',
          bulk_enable_save_n:'Enable save for {n} services',
          reset_confirm_title:'Reset service',
          reset_confirm_msg:'Reset {type} for user "{name}"?',
          delete_user_title:'Delete user',
          delete_user_msg:'Delete user "{name}"?',
          restore_confirm_title:'Restore backup',
          restore_confirm_msg:'Restoring will replace all current users and settings. Continue?',
          clear_logs_confirm:'Delete all panel activity logs?',
          clear_logs_title:'Delete logs',
          logout_confirm:'Do you want to logout?',
          logout_title:'Logout',
          alert_select_port:'⚠️ Please select at least one connection port!',
          alert_error:'Error: {msg}',
          users_load_error:'Failed to fetch data from server',
          users_parse_error:'Failed to process user data',
          update_title:'Panel update',
          update_msg:'Downloading and installing new version...',
          update_available_title:'Update available',
          update_available_msg:'Version {remote} is available.\\nYour current panel version: {current}',
          update_later:'Later',
          update_complete:'Panel updated successfully',
          update_complete_reload:'Reloading panel...',
          update_failed:'Update failed',
          update_failed_msg:'Could not update panel.',
          update_cf_token_redirect:'CF_TOKEN is invalid. Redirecting to setup page...',
          panel_update_title:'Update Panel',
          panel_update_desc:'A new version of the server will be downloaded and your panel will be updated and new features will be added.',
          panel_update_current:'Current version',
          panel_update_remote:'Server version',
          panel_update_btn:'Update Panel',
          panel_update_confirm:'The latest version will be downloaded from the management server and deployed to your worker. Continue?',
          panel_update_available:'Version {remote} is available — your current version is {current}',
          panel_update_latest:'Your panel is up to date.',
          increase:'Increase',
          decrease:'Decrease',
          cf_token_required:'Enter Cloudflare API Token',
          reset_panel_fail:'Failed to reset panel',
          reset_panel_yes:'Yes, reset',
          about_kicker:'Open infrastructure dev team',
          about_hero_title:'Bypass filtering with your own panel',
          about_hero_desc:'NEXA is a group of developers building open-source tools for free internet access — on Cloudflare Workers infrastructure, no middleman, no config sales, fully under your control.',
          about_kicker2:'About Nexa',
          about_title:'Your own panel, no middleman, no cost',
          about_desc:'Instead of selling a service, NEXA provides a public tool. Anyone can deploy their personal connection management panel on their own Cloudflare account in minutes — fast, stable, and without trusting a middleman server.',
          about_f1_title:'Open source & transparent',
          about_f1_desc:'The panel code is fully visible; you can review everything that runs in the panel before using it.',
          about_f2_title:'Your own infrastructure',
          about_f2_desc:'The panel runs on your personal Cloudflare account; data and connections do not pass through any middleman server.',
          about_f3_title:'Quick setup',
          about_f3_desc:'In less than five minutes, without deep programming knowledge, your personal panel is ready and accessible.',
          about_f4_title:'Not for sale',
          about_f4_desc:"NEXA's goal is education and providing tools, not selling configs or internet subscriptions.",
          about_social:'Follow us on social media',
          about_social_desc:'Follow NEXA tutorials, updates and news on YouTube and Telegram.',
          tg_notify_title:'Telegram Notifications',
          tg_enable:'Enable Telegram notifications',
          tg_token:'Bot Token',
          tg_chat_id:'Chat / User ID',
          tg_chat_hint:'To get your chat ID, visit our bot and receive your numeric ID. Bot address: <a href="https://t.me/nexateam_bot" target="_blank" rel="noopener noreferrer">https://t.me/nexateam_bot</a>',
          tg_status_on:'On',
          tg_status_off:'Off',
          save:'Save',
          save_success:'Settings saved successfully',
          logs_desc:'All important panel events',
          refresh:'Refresh',
          clear_logs:'Clear all',
          loading:'Loading...',
          logs_empty:'No events yet.',
          col_time:'Time',
          col_action:'Action',
          col_details:'Details',
          backup_desc:'Download or restore users, all panel settings, activity logs and connection logs.',
          backup_download:'Download backup',
          backup_upload:'Upload backup',
          backup_includes:'Includes: users (all fields), worker, CDN, network, Telegram, blocked domains, CF API, activity logs and connection logs',
          backup_auto_title:'Daily Auto Backup',
          backup_auto_desc:'Every day at 00:00 (Tehran time) a full backup is sent to Telegram — requires bot token and chat ID in Activity Log section.',
          backup_tg_hint:'To send backups, first configure bot token and chat ID in the Activity Log section.',
          backup_cron_hint:'For exact 00:00 runs, add a Cloudflare Workers Cron Trigger: 30 20 * * *',
          backup_tg_send:'Send backup to Telegram (test)',
          backup_last_run:'Last auto backup',
          backup_last_never:'Not run yet',
          backup_tg_sent:'Backup sent to Telegram successfully',
          backup_tg_fail:'Failed to send backup to Telegram',
          backup_auto_saved:'Auto backup settings saved',
          reset_panel_title:'Reset All Settings',
          reset_panel_desc:'All users, proxy settings, Telegram notifications and logs will be removed. The panel will be like the first visit. Admin password is kept.',
          reset_panel_btn:'Reset All Settings',
          reset_panel_confirm:'Reset will delete all users (except main service), settings and logs. This cannot be undone. Continue?',
          reset_panel_success:'Panel reset successfully',
          pwd_info_title:'Change Admin Password',
          pwd_storage_note:'Password is stored in the ADMIN variable (Text type) in Cloudflare Workers.',
          pwd_current_label:'Current password',
          pwd_new_label:'New password',
          pwd_confirm_label:'Confirm new password',
          pwd_change_btn:'Change password',
          pwd_change_success:'Password changed successfully',
          cf_creds_title:'Cloudflare API Settings',
          cf_creds_note:'Enter only CF_TOKEN — Account ID is auto-detected from the token and saved to Worker secrets.',
          cf_token_label:'CF_TOKEN',
          cf_ac_id_label:'Account ID',
          cf_ac_id_auto_hint:'No manual entry needed',
          cf_creds_save:'Save Token',
          cf_creds_success:'Token saved successfully',
          cf_token_hint_set:'Token is configured — enter a new token to change it',
          kill_all_services_label:'Disconnect all services',
          kill_all_services_desc:'When enabled, all services will be suspended and disconnected',
          kill_all_services_on:'All services disconnected',
          kill_all_services_off:'Services re-enabled',
          proxy_save_base:'Proxy IP settings saved',
          proxy_change_labels:{proxy_ips:'Proxy IP addresses (CDN)'},
          proxy_ips_label:'Proxy IP addresses (CDN)',
          proxy_ips_hint:'Empty = default CDN pool',
          blocked_domains_title:'Domain blocking',
          blocked_domains_desc:'Listed domains cannot be accessed through the proxy. One domain per line.',
          blocked_domains_enable:'Enable domain blocking',
          blocked_domains_label:'Blocked domain list',
          blocked_domains_hint:'Example: example.com — subdomains are blocked too',
          blocked_domains_save:'Save blocking rules',
          blocked_domains_saved:'Domain blocking saved',
          wc_protocol_title:'Protocol & transport',
          wc_protocol_desc:'Protocol, transport, connection path and page URLs',
          wc_protocol_label:'Protocol',
          wc_transport_label:'Transport',
          wc_grpc_mode_label:'gRPC mode',
          wc_fingerprint_label:'TLS fingerprint',
          wc_tls_fragment_label:'TLS fragment',
          wc_transport_path_label:'Transport path',
          wc_transport_path_hint:'When a Proxy IP is set in the "CDN Proxy" section, this value is automatically set to fixip_<proxy-ip>.',
          wc_var_username:'Service username',
          wc_var_used:'Used volume so far',
          wc_var_total:'Total service volume (∞ = unlimited)',
          wc_var_dayremind:'Number of days remaining until expiry',
          wc_var_expiry:'Total validity in days (∞ = unlimited)',
          wc_var_port:'The port this specific config is built on',
          wc_var_proxyip:'Current Proxy IP address configured in "CDN Proxy" section',
          wc_var_flag:'Country flag set for this proxy (format #COUNTRYCODE after the IP)',
          adult_block_title:'Adult content blocking',
          adult_block_label:'Filter adult content (+18)',
          adult_block_save:'Save adult blocking',
          adult_block_saved:'Adult content blocking saved',
          adult_block_save_fail:'Failed to save settings',
          adult_block_saving:'Saving...',
          pwd_err_current_required:'Please enter your current password',
          pwd_err_minlength:'New password must be at least 4 characters',
          pwd_err_mismatch:'New password and confirmation do not match',
          pwd_err_generic:'Failed to change password',
          dash_qr_zoom_title:'Zoom QR',
          wc_skip_cert_label:'Skip TLS verification',
          wc_random_path_label:'Random path',
          wc_path_empty_hint:'Empty = default',
          wc_sub_page_path_label:'Subscription page path',
          wc_sub_page_path_hint:'e.g. sub — URL: /path/username',
          wc_logs_page_path_label:'Logs page path',
          wc_logs_page_path_hint:'e.g. logs — URL: /path/username',
          resist_title:'Resistance policy',
          resist_desc:'Clash/Sing-box routing rules — Iran/high censorship profile',
          resist_profile_label:'Profile',
          resist_profile_custom:'Custom',
          resist_profile_iran_high:'Iran / High censorship',
          resist_domestic_bypass:'Iran direct traffic',
          resist_block_quic:'Block QUIC',
          resist_ad_block:'Block ads',
          resist_malware_block:'Block malware',
          resist_phishing_block:'Block phishing',
          resist_bypass_sanctions:'Bypass sanctions',
          resist_doh:'Encrypted DNS (DoH)',
          resist_anti_sanction_dns:'Anti-sanction DNS',
          resist_save_btn:'Save resistance policy',
          wc_security_title:'Security',
          wc_security_desc:'ECH and central panel connection',
          wc_ech_enable_label:'Enable ECH',
          wc_ech_sni_label:'ECH SNI',
          wc_ech_dns_label:'ECH DoH',
          wc_central_api_label:'Central API (optional)',
          wc_sub_title:'Subscription',
          wc_sub_desc:'Subscription name, converter API and user status page',
          wc_sub_name_label:'Subscription name',
          wc_sub_update_label:'Update interval (hours)',
          wc_admin_page_path_label:'Admin panel path',
          wc_status_path_label:'Status page path',
          wc_status_path_hint:'e.g. servicestat or status — final URL: /path/username',
          wc_sub_converter_label:'Subscription converter API',
          wc_sub_config_label:'Routing rules URL (.ini)',
          wc_sub_emoji_label:'Emoji flags in node names',
          wc_naming_title:'Config naming',
          wc_naming_desc:'Subscription config name templates — first config (not for sale) is locked',
          wc_first_remark_label:'First config (locked)',
          wc_info_remark_label:'Service info config',
          wc_vars_hint:'Variables: {username} {dayremind} {used} {total} {expiry} {port} — dayremind shows remaining days',
          wc_node_remark_label:'Connection config names',
          wc_save_btn:'Save worker settings',
          coming_soon_title:'Under development',
          coming_soon_desc:'Coming soon...',
          guide_android_title:'Connection guide — Android',
          guide_android_1:'Download V2rayNG from the link below:<br><a href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" rel="noopener noreferrer" class="adm-guide-link">https://github.com/2dust/v2rayNG/releases/latest</a>',
          guide_android_2:'Open the app',
          guide_android_3:'Tap the + icon at top right',
          guide_android_4:'Select <strong>Import config from clipboard</strong><br><span class="text-xs opacity-70">(config link must be copied first)</span>',
          guide_android_5:'Config appears in the list — tap to select it',
          guide_android_6:'Tap the connect button at the bottom — you are now connected.',
          guide_ios_title:'Connection guide — iPhone (iOS)',
          guide_ios_1:'Download Streisand from the App Store:<br><a href="https://apps.apple.com/app/streisand/id6450534064" target="_blank" rel="noopener noreferrer" class="adm-guide-link">https://apps.apple.com/app/streisand/id6450534064</a>',
          guide_ios_2:'Open the app',
          guide_ios_3:'Tap + at top right',
          guide_ios_4:'Tap <strong>Import from Clipboard</strong><br><span class="text-xs opacity-70">(config link must be copied first)</span>',
          guide_ios_5:'Config added — tap Connect next to it',
          guide_ios_6:'Tap Allow in the popup',
          guide_desktop_title:'Connection guide — Windows / Mac',
          guide_windows:'Windows',
          guide_mac:'Mac',
          guide_win_1:'Download v2rayN:<br><a href="https://github.com/2dust/v2rayN/releases/latest" target="_blank" rel="noopener noreferrer" class="adm-guide-link">https://github.com/2dust/v2rayN/releases/latest</a>',
          guide_win_2:'Extract the zip and run v2rayN.exe',
          guide_win_3:'Right-click the app icon in the taskbar',
          guide_win_4:'Tap + and enter a name and the copied link',
          guide_win_5:'From the top menu, open subscription group and select the third option',
          guide_win_6:'To connect, set "Clear system proxy" at the bottom to the second option',
          guide_mac_1:'Download FoXray from the Mac App Store',
          guide_mac_2:'Tap + and select Import from clipboard',
          guide_mac_3:'Select the config and tap Connect',
          guide_support:'Cannot connect? <a href="https://t.me/nexateam_bot" target="_blank" rel="noopener noreferrer" class="adm-guide-support">Get help from support bot</a>'
          }
          };
        function getAdminLang() {
            return localStorage.getItem('nexa-admin-lang') || 'fa';
        }
        function adminT(key, vars) {
            const dict = ADMIN_I18N[getAdminLang()] || ADMIN_I18N.fa;
            let text = dict[key];
            if (text == null) return key;
            if (vars) {
                Object.keys(vars).forEach(function(k) {
                    text = String(text).replace(new RegExp('\\{' + k + '\\}', 'g'), vars[k]);
                });
            }
            return text;
        }
        function buildGuidePanelHtml(platform, dict) {
            let html = '';
            if (platform === 'desktop') {
                html = '<div class="adm-guide-section-title">' + dict.guide_desktop_title + '</div>' +
                    '<h4 class="text-sm font-bold mb-3" style="color: var(--admin-text)">' + dict.guide_windows + '</h4><div class="space-y-3 mb-6">';
                for (let w = 1; w <= 6; w++) {
                    if (dict['guide_win_' + w]) html += '<div class="adm-guide-step"><span class="adm-guide-step-num">' + w + '</span> ' + dict['guide_win_' + w] + '</div>';
                }
                html += '</div><h4 class="text-sm font-bold mb-3" style="color: var(--admin-text)">' + dict.guide_mac + '</h4><div class="space-y-3">';
                for (let m = 1; m <= 3; m++) {
                    if (dict['guide_mac_' + m]) html += '<div class="adm-guide-step"><span class="adm-guide-step-num">' + m + '</span> ' + dict['guide_mac_' + m] + '</div>';
                }
                html += '</div>';
            } else {
                html = '<div class="adm-guide-section-title">' + (dict['guide_' + platform + '_title'] || '') + '</div><div class="space-y-3">';
                let i = 1;
                while (dict['guide_' + platform + '_' + i]) {
                    html += '<div class="adm-guide-step"><span class="adm-guide-step-num">' + i + '</span> ' + dict['guide_' + platform + '_' + i] + '</div>';
                    i++;
                }
                html += '</div>';
            }
            html += '<p class="text-center text-sm pt-2" style="color: var(--admin-muted)">' + (dict.guide_support || '') + '</p>';
            return html;
        }
        function renderAdminGuide() {
            const lang = getAdminLang();
            const dict = ADMIN_I18N[lang] || ADMIN_I18N.fa;
            ['android', 'ios', 'desktop'].forEach(function(platform) {
                const panel = document.getElementById('adm-guide-panel-' + platform);
                if (panel) panel.innerHTML = buildGuidePanelHtml(platform, dict);
            });
        }
        const SECTION_HELP_LINKS = {
            dashboard: 'https://farzadqavidel.github.io/nexa-panel/#guide-dashboard',
            users: 'https://farzadqavidel.github.io/nexa-panel/#guide-users',
            'node-server': 'https://farzadqavidel.github.io/nexa-panel/#guide-node',
            'ip-scanner': 'https://farzadqavidel.github.io/nexa-panel/#guide-ipscan',
            'cdn-proxy': 'https://farzadqavidel.github.io/nexa-panel/#guide-cdn',
            logs: 'https://farzadqavidel.github.io/nexa-panel/#guide-logs',
            settings: 'https://farzadqavidel.github.io/nexa-panel/#guide-settings',
        };
        function openSectionHelp() {
            const activeNav = document.querySelector('.adm-nav-item.active[data-section]');
            const section = activeNav ? activeNav.dataset.section : 'dashboard';
            const link = SECTION_HELP_LINKS[section] || '#';
            const meta = ADMIN_SECTIONS[section];
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            const titleEl = document.getElementById('section-help-title');
            const linkEl = document.getElementById('section-help-link');
            if (titleEl && meta) titleEl.textContent = 'آموزش ' + (meta.title[lang] || meta.title.fa);
            if (linkEl) linkEl.href = link;
            const modal = document.getElementById('section-help-modal');
            const card = document.getElementById('section-help-modal-card');
            modal.classList.remove('opacity-0', 'pointer-events-none');
            modal.classList.add('opacity-100', 'pointer-events-auto');
            card.classList.remove('opacity-0', 'scale-95');
            card.classList.add('opacity-100', 'scale-100');
        }
        function closeSectionHelp() {
            const modal = document.getElementById('section-help-modal');
            const card = document.getElementById('section-help-modal-card');
            modal.classList.remove('opacity-100', 'pointer-events-auto');
            modal.classList.add('opacity-0', 'pointer-events-none');
            card.classList.remove('opacity-100', 'scale-100');
            card.classList.add('opacity-0', 'scale-95');
        }
        const ADMIN_SECTIONS = {
            dashboard: { title: { fa: 'داشبورد', en: 'Dashboard' }, desc: { fa: 'نمای کلی پنل', en: 'Panel overview' } },
            users: { title: { fa: 'مدیریت کاربران', en: 'User Management' }, desc: { fa: 'مدیریت کاربران , وضعیت کاربران', en: 'Manage, edit and bulk actions on users' } },
            guide: { title: { fa: 'آموزش اتصال', en: 'Connection Guide' }, desc: { fa: 'راهنمای اتصال برای اندروید، iOS و دسکتاپ', en: 'Connection guide for Android, iOS and desktop' } },
            'node-server': { title: { fa: 'سرور نود', en: 'Node Server' }, desc: { fa: 'سرور های نود اصلی', en: 'Main node Server' } },
            'ip-scanner': { title: { fa: 'اسکنر IP تمیز', en: 'Clean IP Scanner' }, desc: { fa: 'اسکن IP تمیز و مدیریت مخزن آی‌پی', en: 'Clean IP scan and pool management' } },
            'cdn-proxy': { title: { fa: 'پروکسی CDN', en: 'CDN Proxy' }, desc: { fa: 'تنظیمات پروکسی CDN کلودفلر', en: 'Cloudflare CDN proxy settings' } },
            logs: { title: { fa: 'لاگ فعالیت', en: 'Activity Log' }, desc: { fa: 'مشاهده لاگ ها', en: 'View Logs' } },
            settings: { title: { fa: 'تنظیمات پنل', en: 'Panel Settings' }, desc: { fa: 'تنظیمات ورکر، پروتکل، اشتراک و بکاپ', en: 'Worker, protocol, subscription and backup settings' } },
            'panel-control': { title: { fa: 'کنترل پنل', en: 'Panel Control' }, desc: { fa: 'ری‌استارت، خاموش کردن پنل و قطع سرویس‌ها', en: 'Restart, disable panel and kill switch' } },
            about: { title: { fa: 'درباره ما', en: 'About Us' }, desc: { fa: 'معرفی تیم NEXA و ماموریت پنل', en: 'NEXA team intro and panel mission' } }
        };
        let usersRefreshInterval = null;
        function ensureUsersRefreshInterval() {
            if (usersRefreshInterval) return;
            usersRefreshInterval = setInterval(function() { loadUsers(true); }, 60000);
        }
        let tgNotifyEnabled = false;
        let allServicesOffEnabled = false;
        let blockedDomainsEnabled = false;
        window.panelAllServicesOff = false;
        let tgSaveTimer = null;
        function applyAdminI18n(lang) {
            const dict = ADMIN_I18N[lang] || ADMIN_I18N.fa;
            document.querySelectorAll('[data-i18n]').forEach(function(el) {
                const key = el.getAttribute('data-i18n');
                if (dict[key]) el.textContent = dict[key];
            });
            document.querySelectorAll('[data-i18n-placeholder]').forEach(function(el) {
                const key = el.getAttribute('data-i18n-placeholder');
                if (dict[key]) el.placeholder = dict[key];
            });
            document.querySelectorAll('[data-i18n-title]').forEach(function(el) {
                const key = el.getAttribute('data-i18n-title');
                if (dict[key]) el.title = dict[key];
            });
            document.querySelectorAll('[data-i18n-aria-label]').forEach(function(el) {
                const key = el.getAttribute('data-i18n-aria-label');
                if (dict[key]) el.setAttribute('aria-label', dict[key]);
            });
            document.querySelectorAll('[data-i18n-html]').forEach(function(el) {
                const key = el.getAttribute('data-i18n-html');
                if (dict[key]) el.innerHTML = dict[key];
            });
        }
        function updateAdminPageHeader(section, lang) {
            lang = lang || localStorage.getItem('nexa-admin-lang') || 'fa';
            const meta = ADMIN_SECTIONS[section];
            if (!meta) return;
            const titleEl = document.getElementById('adm-page-title');
            const descEl = document.getElementById('adm-page-desc');
            if (titleEl) titleEl.textContent = meta.title[lang] || meta.title.fa;
            if (descEl) descEl.textContent = meta.desc[lang] || meta.desc.fa;
        }
        function setAdminLang(lang) {
            const prevLang = localStorage.getItem('nexa-admin-lang') || 'fa';
            localStorage.setItem('nexa-admin-lang', lang);
            if (lang !== prevLang) {
                location.reload();
                return;
            }
            const faBtn = document.getElementById('lang-fa');
            const enBtn = document.getElementById('lang-en');
            if (faBtn) faBtn.classList.toggle('active', lang === 'fa');
            if (enBtn) enBtn.classList.toggle('active', lang === 'en');
            document.documentElement.lang = lang;
            document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
            if (window.innerWidth < 1024) toggleAdminSidebar(false);
            applyAdminI18n(lang);
            renderAdminGuide();
            updateSidebarCollapseLabel();
            const activeNav = document.querySelector('.adm-nav-item.active[data-section]');
            updateAdminPageHeader(activeNav ? activeNav.dataset.section : 'dashboard', lang);
            updateTgNotifyUI();
            updateBulkToolbar();
            if (document.getElementById('section-settings')?.classList.contains('active') && typeof loadWorkerConfigForm === 'function') loadWorkerConfigForm();
            if (window.allUsers) filterAndRenderUsers();
            const refreshBtn = document.getElementById('dash-refresh-btn');
            if (refreshBtn && !refreshBtn.disabled) refreshBtn.textContent = adminT('refresh');
            const bulkSubmit = document.getElementById('bulk-edit-submit');
            if (bulkSubmit && !bulkSubmit.disabled) bulkSubmit.textContent = adminT('bulk_apply');
            const mapZoomBtn = document.getElementById('dash-map-zoom-btn');
            if (mapZoomBtn) mapZoomBtn.textContent = adminT('dash_zoom_map');
        }
        function switchAdminSection(name) {
            const helpBtn = document.querySelector('.adm-topbar-start .adm-theme-btn[title="آموزش این بخش"]');
            if (helpBtn) helpBtn.style.display = (name === 'about' || name === 'guide') ? 'none' : '';
            document.querySelectorAll('.adm-section').forEach(function(el) {
                el.classList.toggle('active', el.id === 'section-' + name);
            });
            document.querySelectorAll('.adm-nav-item[data-section]').forEach(function(el) {
                el.classList.toggle('active', el.dataset.section === name);
            });
            updateAdminPageHeader(name);
            if (name === 'logs') {
                loadTelegramNotify();
                loadAdminLogs();
            }
            if (name === 'dashboard') {
                loadDashboard();
            }
            if (name === 'node-server') {
                loadNodeServer();
            }
            if (name === 'ip-scanner') {
                loadScannerPoolPanel();
            }
            if (name === 'cdn-proxy') {
                loadCdnProxySettingsForm();
                updateCdnCfBanner();
            }
            if (name === 'users') {
                loadUsers();
                loadPanelProxySettings();
                ensureUsersRefreshInterval();
            }
            if (name === 'settings') {
                loadWorkerConfigForm();
                loadNetworkSettings();
                loadBlockedDomainsForm();
                loadContentPolicyForm();
                loadCfCredentialsForm();
                loadPanelProxySettings();
                loadAllServicesOff();
                loadBackupSettings();
                if (window.panelUpdateStatus) updatePanelUpdateUI(window.panelUpdateStatus);
            }
            if (name === 'panel-control') {
                loadPanelControlSection();
            }
            toggleAdminSidebar(false);
            if (location.hash !== '#' + name) history.replaceState(null, '', '#' + name);
        }
        function showAdminGuideTab(name) {
            ['android', 'ios', 'desktop'].forEach(function(id) {
                var panel = document.getElementById('adm-guide-panel-' + id);
                var tab = document.getElementById('adm-guide-tab-' + id);
                if (panel) panel.classList.toggle('hidden', id !== name);
                if (tab) tab.classList.toggle('active', id === name);
            });
        }
        function updateBlockedDomainsUI() {
            const toggle = document.getElementById('blocked-domains-toggle');
            if (!toggle) return;
            toggle.classList.toggle('on', blockedDomainsEnabled);
            toggle.setAttribute('aria-checked', blockedDomainsEnabled ? 'true' : 'false');
        }
        function toggleBlockedDomainsSwitch() {
            blockedDomainsEnabled = !blockedDomainsEnabled;
            updateBlockedDomainsUI();
        }
        async function loadBlockedDomainsForm() {
            try {
                const res = await fetch('/api/blocked-domains');
                if (!res.ok) return;
                const data = await res.json();
                blockedDomainsEnabled = !!data.enabled;
                updateBlockedDomainsUI();
                const input = document.getElementById('blocked-domains-input');
                if (input && Array.isArray(data.domains)) {
                    input.value = data.domains.join('\\n');
                }
            } catch (e) {}
        }
        let adultBlockEnabled = false;
        function updateContentPolicyUI() {
            const t2 = document.getElementById('adult-block-toggle');
            if (t2) { t2.classList.toggle('on', adultBlockEnabled); t2.setAttribute('aria-checked', adultBlockEnabled ? 'true' : 'false'); }
        }
        function toggleAdultBlockSwitch() { adultBlockEnabled = !adultBlockEnabled; updateContentPolicyUI(); }
        async function loadContentPolicyForm() {
            try {
                const res = await fetch('/api/content-policy');
                if (!res.ok) return;
                const data = await res.json();
                adultBlockEnabled = !!data.adultBlockEnabled;
                updateContentPolicyUI();
            } catch (e) {}
        }
        async function saveContentPolicy() {
            const btn = document.getElementById('save-content-policy-btn');
            btn.disabled = true;
            btn.innerText = adminT('adult_block_saving');
            try {
                const res = await fetch('/api/content-policy', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ adultBlockEnabled })
                });
                if (res.ok) showNexaToast(adminT('adult_block_saved'));
                else alert(adminT('adult_block_save_fail'));
            } catch (e) {
                alert(adminT('toast_conn_error'));
            } finally {
                btn.disabled = false;
                btn.innerText = adminT('adult_block_save');
            }
        }
        async function saveBlockedDomains() {
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            const dict = ADMIN_I18N[lang] || ADMIN_I18N.fa;
            const domainsRaw = (document.getElementById('blocked-domains-input') || {}).value.trim();
            const btn = document.getElementById('save-blocked-domains-btn');
            btn.disabled = true;
            btn.innerText = lang === 'en' ? 'Saving...' : 'در حال ذخیره...';
            try {
                const response = await fetch('/api/blocked-domains', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ enabled: blockedDomainsEnabled, domains: domainsRaw })
                });
                if (response.ok) {
                    showNexaToast(dict.blocked_domains_saved || 'مسدودسازی دامنه ذخیره شد');
                } else {
                    alert(lang === 'en' ? 'Failed to save settings' : 'خطا در ذخیره تنظیمات');
                }
            } catch (err) {
                alert(lang === 'en' ? 'Connection error' : 'خطا در برقراری ارتباط با سرور');
            } finally {
                btn.disabled = false;
                btn.innerText = dict.blocked_domains_save || 'ذخیره مسدودسازی';
            }
        }
        function updateAllServicesOffUI() {
            const toggle = document.getElementById('all-services-off-toggle');
            if (!toggle) return;
            toggle.classList.toggle('on', allServicesOffEnabled);
            toggle.setAttribute('aria-checked', allServicesOffEnabled ? 'true' : 'false');
        }
        function toggleAllServicesOffSwitch() {
            allServicesOffEnabled = !allServicesOffEnabled;
            updateAllServicesOffUI();
            saveAllServicesOff(false);
        }
        async function loadAllServicesOff() {
            try {
                const res = await fetch('/api/all-services-off');
                if (!res.ok) return;
                const data = await res.json();
                allServicesOffEnabled = !!data.enabled;
                window.panelAllServicesOff = allServicesOffEnabled;
                updateAllServicesOffUI();
                if (window.allUsers && typeof filterAndRenderUsers === 'function') {
                    filterAndRenderUsers();
                }
            } catch (e) {}
        }
       async function loadPanelControlSection() {
          await loadAllServicesOff();
          await loadPanelDisabledState();
      }
      let panelDisabledEnabled = false;
      function updatePanelDisabledUI() {
          const toggle = document.getElementById('panel-disabled-toggle');
          if (!toggle) return;
          toggle.classList.toggle('on', panelDisabledEnabled);
          toggle.setAttribute('aria-checked', panelDisabledEnabled ? 'true' : 'false');
      }
      async function loadPanelDisabledState() {
          try {
              const res = await fetch('/api/panel-disabled');
              if (!res.ok) return;
              const data = await res.json();
              panelDisabledEnabled = !!data.enabled;
              updatePanelDisabledUI();
          } catch (e) {}
      }
      async function togglePanelDisabledSwitch() {
          const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
          if (!panelDisabledEnabled) {
              const ok = await showNexaConfirm(
                  lang === 'en' ? 'Admin login will be blocked for everyone. To return, open the URL with ?unlock=1. Continue?' : 'صفحه ورود و پنل مدیریت برای همه غیرفعال می‌شود. برای بازگشت باید آدرس را با ?unlock=1 باز کنید. ادامه می‌دهید؟',
                  { title: lang === 'en' ? 'Disable panel' : 'خاموش کردن پنل', danger: true, confirmText: lang === 'en' ? 'Yes, disable' : 'بله، خاموش شود' }
              );
              if (!ok) return;
          }
          panelDisabledEnabled = !panelDisabledEnabled;
          updatePanelDisabledUI();
          try {
              const res = await fetch('/api/panel-disabled', {
                  method: 'POST', headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ enabled: panelDisabledEnabled })
              });
              const data = await res.json();
              if (!res.ok || !data.success) throw new Error(data.error || 'failed');
              showNexaToast(panelDisabledEnabled ? (lang === 'en' ? 'Panel disabled' : 'پنل مدیریت غیرفعال شد') : (lang === 'en' ? 'Panel enabled' : 'پنل مدیریت مجدداً فعال شد'));
          } catch (e) {
              panelDisabledEnabled = !panelDisabledEnabled;
              updatePanelDisabledUI();
              showNexaToast(lang === 'en' ? 'Failed to save' : 'خطا در ذخیره', 'error');
          }
      }
      async function restartPanelAction() {
          const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
          const ok = await showNexaConfirm(
              lang === 'en' ? 'This resets the uptime counter and clears temporary caches. Continue?' : 'شمارشگر آپتایم و کش‌های موقت پاک‌سازی می‌شود. ادامه می‌دهید؟',
              { title: lang === 'en' ? 'Restart panel' : 'ری‌استارت پنل', confirmText: lang === 'en' ? 'Yes, restart' : 'بله، ری‌استارت شود' }
          );
          if (!ok) return;
          const btn = document.getElementById('panel-restart-btn');
          if (btn) { btn.disabled = true; btn.textContent = lang === 'en' ? 'Restarting...' : 'در حال ری‌استارت...'; }
          try {
              const res = await fetch('/api/panel-restart', { method: 'POST' });
              const data = await res.json();
              if (!res.ok || !data.success) throw new Error(data.error || 'failed');
              showNexaToast(lang === 'en' ? 'Panel restarted' : 'پنل با موفقیت ری‌استارت شد');
          } catch (e) {
              showNexaToast(lang === 'en' ? 'Restart failed' : 'خطا در ری‌استارت', 'error');
          } finally {
              if (btn) { btn.disabled = false; btn.textContent = 'ری‌استارت پنل'; }
          }
      }
      window.togglePanelDisabledSwitch = togglePanelDisabledSwitch;
      window.restartPanelAction = restartPanelAction;
      window.loadPanelControlSection = loadPanelControlSection;
        async function saveAllServicesOff(silent) {
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            const dict = ADMIN_I18N[lang] || ADMIN_I18N.fa;
            try {
                const res = await fetch('/api/all-services-off', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ enabled: allServicesOffEnabled, quiet: !!silent })
                });
                const data = await res.json();
                if (res.ok && data.success) {
                    window.panelAllServicesOff = !!data.enabled;
                    if (!silent) {
                        showNexaToast(allServicesOffEnabled
                            ? (dict.kill_all_services_on || 'تمامی سرویس‌ها قطع شدند')
                            : (dict.kill_all_services_off || 'سرویس‌ها مجدداً فعال شدند'));
                    }
                    if (window.allUsers && typeof filterAndRenderUsers === 'function') {
                        filterAndRenderUsers();
                    }
                    if (typeof loadDashboard === 'function') loadDashboard(true);
                    if (!silent && typeof loadAdminLogs === 'function') loadAdminLogs();
                } else if (!silent) {
                    showNexaToast(data.error || (dict.toast_save_fail || 'خطا در ذخیره'), 'error');
                }
            } catch (e) {
                if (!silent) showNexaToast(dict.toast_conn_error || 'خطا در ارتباط', 'error');
            }
        }
        function updateTgNotifyUI() {
            const toggle = document.getElementById('tg-notify-toggle');
            const badge = document.getElementById('tg-notify-badge');
            if (!toggle || !badge) return;
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            const dict = ADMIN_I18N[lang] || ADMIN_I18N.fa;
            toggle.classList.toggle('on', tgNotifyEnabled);
            toggle.setAttribute('aria-checked', tgNotifyEnabled ? 'true' : 'false');
            const statusText = tgNotifyEnabled ? dict.tg_status_on : dict.tg_status_off;
            badge.innerHTML = '● <span>' + statusText + '</span>';
            badge.className = tgNotifyEnabled
                ? 'text-xs font-bold px-2.5 py-1 rounded-full bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800'
                : 'text-xs font-bold px-2.5 py-1 rounded-full bg-gray-100 text-gray-600 dark:bg-zinc-800 dark:text-zinc-400 border border-gray-200 dark:border-zinc-700';
        }
        function toggleTgNotifySwitch() {
            tgNotifyEnabled = !tgNotifyEnabled;
            updateTgNotifyUI();
            saveTelegramNotify(true);
        }
        function scheduleTelegramSave() {
            clearTimeout(tgSaveTimer);
            tgSaveTimer = setTimeout(function() { saveTelegramNotify(true); }, 700);
        }
        async function loadTelegramNotify() {
            try {
                const tokenEl = document.getElementById('tg-bot-token');
                const chatEl = document.getElementById('tg-chat-ids');
                if (document.activeElement === tokenEl || document.activeElement === chatEl) return;
                const res = await fetch('/api/telegram-notify');
                if (!res.ok) return;
                const data = await res.json();
                tgNotifyEnabled = !!data.enabled;
                if (tokenEl) tokenEl.value = data.bot_token || '';
                if (chatEl) chatEl.value = data.chat_ids || '';
                updateTgNotifyUI();
            } catch (e) {}
        }
        async function saveTelegramNotify(silent) {
            const btn = document.getElementById('save-tg-notify-btn');
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            if (btn && !silent) btn.disabled = true;
            try {
                const res = await fetch('/api/telegram-notify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        enabled: tgNotifyEnabled,
                        bot_token: (document.getElementById('tg-bot-token') || {}).value || '',
                        chat_ids: (document.getElementById('tg-chat-ids') || {}).value || '',
                        quiet: !!silent
                    })
                });
                const data = await res.json();
                if (res.ok && data.success) {
                    if (!silent) showNexaToast(lang === 'en' ? 'Telegram settings saved' : 'تنظیمات تلگرام ذخیره شد');
                    updateTgNotifyUI();
                } else if (!silent) {
                    showNexaToast(data.error || (lang === 'en' ? 'Save failed' : 'خطا در ذخیره'), 'error');
                }
            } catch (e) {
                if (!silent) showNexaToast(lang === 'en' ? 'Connection error' : 'خطا در ارتباط', 'error');
            } finally {
                if (btn && !silent) btn.disabled = false;
            }
        }
        function formatAdminLogTime(iso) {
            if (!iso) return '-';
            try {
                const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
                const locale = lang === 'en' ? 'en-US' : 'fa-IR';
                return new Date(iso).toLocaleString(locale, { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
            } catch (e) {
                return iso;
            }
        }
        function escapeAdminHtml(str) {
            return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }
        async function loadAdminLogs() {
            const loading = document.getElementById('admin-logs-loading');
            const empty = document.getElementById('admin-logs-empty');
            const table = document.getElementById('admin-logs-table');
            const tbody = document.getElementById('admin-logs-body');
            const countEl = document.getElementById('admin-log-count');
            if (!loading || !tbody) return;
            loading.classList.remove('hidden');
            if (empty) empty.classList.add('hidden');
            if (table) table.classList.add('hidden');
            try {
                const res = await fetch('/api/logs');
                if (!res.ok) throw new Error();
                const data = await res.json();
                const logs = data.logs || [];
                if (countEl) countEl.textContent = String(logs.length);
                loading.classList.add('hidden');
                if (!logs.length) {
                    if (empty) empty.classList.remove('hidden');
                    tbody.innerHTML = '';
                    return;
                }
                if (table) table.classList.remove('hidden');
                tbody.innerHTML = logs.map(function(log) {
                    return '<tr class="admin-row">' +
                        '<td class="px-4 py-3 whitespace-nowrap text-xs">' + formatAdminLogTime(log.created_at) + '</td>' +
                        '<td class="px-4 py-3 whitespace-nowrap font-bold">' + escapeAdminHtml(log.action) + '</td>' +
                        '<td class="px-4 py-3 text-xs">' + escapeAdminHtml(log.details) + '</td>' +
                        '<td class="px-4 py-3 whitespace-nowrap text-xs font-mono" dir="ltr">' + escapeAdminHtml(log.ip) + '</td>' +
                    '</tr>';
                }).join('');
            } catch (e) {
                const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
                loading.textContent = lang === 'en' ? 'Failed to load logs' : 'خطا در بارگذاری لاگ‌ها';
            }
        }
        async function clearAdminLogs() {
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            const ok = await showNexaConfirm(
                lang === 'en' ? 'Delete all panel activity logs?' : 'آیا از حذف همه لاگ‌های پنل مطمئن هستید؟',
                { title: lang === 'en' ? 'Delete logs' : 'حذف لاگ‌ها', danger: true, confirmText: lang === 'en' ? 'Yes, delete' : 'بله، حذف شوند' }
            );
            if (!ok) return;
            try {
                const res = await fetch('/api/logs', { method: 'DELETE' });
                if (res.ok) {
                    showNexaToast(lang === 'en' ? 'Logs cleared' : 'لاگ‌ها حذف شدند');
                    loadAdminLogs();
                }
            } catch (e) {}
        }
        function getSelectedUsernames() {
            return Array.from(window.selectedUsernames);
        }
        function updateBulkToolbar() {
            const count = window.selectedUsernames.size;
            const bar = document.getElementById('bulk-toolbar');
            if (bar) bar.classList.toggle('hidden', count === 0);
            const countEl = document.getElementById('bulk-selected-count');
            if (countEl) countEl.textContent = adminT('bulk_selected', { n: count });
            const subtitle = document.getElementById('bulk-edit-subtitle');
            if (subtitle) subtitle.textContent = adminT('bulk_selected', { n: count });
        }
        function syncUserSelectVisual(cb) {
            const row = cb.closest('tr.admin-row, .adm-user-card');
            if (row) row.classList.toggle('is-selected', cb.checked);
        }
        function onUserSelectChange(checkbox) {
            const username = decodeURIComponent(checkbox.dataset.username || '');
            if (!username) return;
            if (checkbox.checked) window.selectedUsernames.add(username);
            else window.selectedUsernames.delete(username);
            document.querySelectorAll('.user-select-cb[data-username="' + checkbox.dataset.username + '"]').forEach(function(cb) {
                cb.checked = checkbox.checked;
                syncUserSelectVisual(cb);
            });
            updateBulkToolbar();
        }
        function toggleSelectAllFiltered(checked) {
            document.querySelectorAll('.user-select-cb').forEach(function(cb) {
                cb.checked = checked;
                syncUserSelectVisual(cb);
                const username = decodeURIComponent(cb.dataset.username || '');
                if (!username) return;
                if (checked) window.selectedUsernames.add(username);
                else window.selectedUsernames.delete(username);
            });
            updateBulkToolbar();
        }
        function clearUserSelection() {
            window.selectedUsernames.clear();
            document.querySelectorAll('.user-select-cb').forEach(function(cb) {
                cb.checked = false;
                syncUserSelectVisual(cb);
            });
            const selectAll = document.getElementById('select-all-users');
            if (selectAll) selectAll.checked = false;
            updateBulkToolbar();
        }
        function toggleBulkEditModal(show) {
            const modal = document.getElementById('bulk-edit-modal');
            const card = document.getElementById('bulk-edit-modal-card');
            if (!modal || !card) return;
            if (show) {
                modal.classList.remove('opacity-0', 'pointer-events-none');
                modal.classList.add('opacity-100', 'pointer-events-auto');
                card.classList.remove('opacity-0', 'scale-95');
                card.classList.add('opacity-100', 'scale-100');
                updateBulkToolbar();
            } else {
                modal.classList.remove('opacity-100', 'pointer-events-auto');
                modal.classList.add('opacity-0', 'pointer-events-none');
                card.classList.remove('opacity-100', 'scale-100');
                card.classList.add('opacity-0', 'scale-95');
            }
        }
        function openBulkEditModal() {
            if (!getSelectedUsernames().length) {
                showNexaToast('ابتدا حداقل یک سرویس را انتخاب کنید', 'error');
                return;
            }
            toggleBulkEditModal(true);
        }
        async function runBulkAction(action) {
            const usernames = getSelectedUsernames();
            if (!usernames.length) {
                showNexaToast('ابتدا حداقل یک سرویس را انتخاب کنید', 'error');
                return;
            }
            const labels = {
                delete: 'حذف ' + usernames.length + ' سرویس',
                activate: 'فعال‌سازی ' + usernames.length + ' سرویس',
                deactivate: 'قطع ' + usernames.length + ' سرویس',
                reset_volume: 'ریست حجم ' + usernames.length + ' سرویس',
                reset_time: 'ریست زمان ' + usernames.length + ' سرویس',
                reset_requests: 'ریست ریکوئست کل ' + usernames.length + ' سرویس',
                enable_save: 'فعال‌سازی ذخیره برای ' + usernames.length + ' سرویس'
            };
            const dangerActions = ['delete', 'reset_volume', 'reset_time', 'reset_requests'];
            if (dangerActions.includes(action)) {
                const ok = await showNexaConfirm('آیا از «' + (labels[action] || action) + '» مطمئن هستید؟', { title: 'عملیات گروهی', danger: true, confirmText: 'بله، انجام شود' });
                if (!ok) return;
            }
            try {
                const res = await fetch('/api/users/bulk', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ usernames: usernames, action: action })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'عملیات ناموفق بود');
                showNexaToast('عملیات گروهی روی ' + (data.processed || 0) + ' سرویس انجام شد');
                clearUserSelection();
                await loadUsers(true);
            } catch (err) {
                showNexaToast(err.message || 'خطا در عملیات گروهی', 'error');
            }
        }
        async function submitBulkEdit(event) {
            event.preventDefault();
            const usernames = getSelectedUsernames();
            if (!usernames.length) {
                showNexaToast('هیچ سرویسی انتخاب نشده است', 'error');
                return;
            }
            const apply = {
                limit_gb: document.getElementById('bulk-apply-limit').checked,
                expiry_days: document.getElementById('bulk-apply-expiry').checked,
                max_requests: document.getElementById('bulk-apply-max-req').checked,
                max_requests_daily: document.getElementById('bulk-apply-max-req-daily').checked,
                port: document.getElementById('bulk-apply-ports').checked,
                ips: document.getElementById('bulk-apply-ips').checked,
                proxy_ip: document.getElementById('bulk-apply-proxy').checked,
                fingerprint: document.getElementById('bulk-apply-fp').checked
            };
            if (!Object.values(apply).some(Boolean)) {
                showNexaToast('حداقل یک فیلد را برای اعمال انتخاب کنید', 'error');
                return;
            }
            let port = '';
            if (apply.port) {
                const checkedPorts = Array.from(document.querySelectorAll('input[name="bulk-ports"]:checked')).map(function(cb) { return cb.value; });
                if (!checkedPorts.length) {
                    showNexaToast('حداقل یک پورت انتخاب کنید', 'error');
                    return;
                }
                port = checkedPorts.join(',');
            }
            const submitBtn = document.getElementById('bulk-edit-submit');
            submitBtn.disabled = true;
            submitBtn.textContent = 'در حال اعمال...';
            try {
                const res = await fetch('/api/users/bulk', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        usernames: usernames,
                        action: 'update',
                        apply: apply,
                        updates: {
                            limit_gb: document.getElementById('bulk-input-limit').value,
                            expiry_days: document.getElementById('bulk-input-expiry').value,
                            max_requests: document.getElementById('bulk-input-max-req').value,
                            max_requests_daily: document.getElementById('bulk-input-max-req-daily').value,
                            ips: document.getElementById('bulk-input-ips').value,
                            proxy_ip: document.getElementById('bulk-input-proxy-ip').value,
                            fingerprint: document.getElementById('bulk-fingerprint-select').value,
                            port: port
                        }
                    })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'عملیات ناموفق بود');
                showNexaToast('ویرایش گروهی روی ' + (data.processed || 0) + ' سرویس انجام شد');
                toggleBulkEditModal(false);
                clearUserSelection();
                await loadUsers(true);
            } catch (err) {
                showNexaToast(err.message || 'خطا در ویرایش گروهی', 'error');
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'اعمال روی انتخاب‌شده‌ها';
            }
        }
        function initNumSteppers() {
            document.querySelectorAll('.num-stepper').forEach(function(wrap) {
                if (wrap.dataset.stepperInit) return;
                const input = wrap.querySelector('.num-stepper-input');
                if (!input) return;
                wrap.dataset.stepperInit = '1';
                wrap.querySelectorAll('.num-stepper-btn').forEach(function(btn) {
                    btn.addEventListener('click', function() {
                        const dir = parseFloat(btn.dataset.step) || 1;
                        const min = input.min !== '' ? parseFloat(input.min) : null;
                        const max = input.max !== '' ? parseFloat(input.max) : null;
                        const stepAttr = input.getAttribute('step');
                        const stepVal = stepAttr && stepAttr !== 'any' ? parseFloat(stepAttr) : 1;
                        const delta = stepVal * dir;
                        let cur = input.value === '' ? null : parseFloat(input.value);
                        if (cur === null || isNaN(cur)) {
                            cur = dir > 0 ? (min !== null && !isNaN(min) ? min : 1) : 0;
                        } else {
                            cur = cur + delta;
                        }
                        if (min !== null && !isNaN(min) && cur < min) cur = min;
                        if (max !== null && !isNaN(max) && cur > max) cur = max;
                        if (dir < 0 && min !== null && cur <= min && input.placeholder) {
                            input.value = '';
                        } else {
                            input.value = Number.isInteger(stepVal) ? Math.round(cur) : parseFloat(cur.toFixed(4));
                        }
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                    });
                });
            });
        }
        function renderPortCheckboxes(opts) {
            opts = opts || {};
            const tlsContainer = document.getElementById(opts.tlsId || 'tls-ports-list');
            const nonTlsContainer = document.getElementById(opts.nonTlsId || 'nontls-ports-list');
            if (!tlsContainer || !nonTlsContainer) return;
            const inputName = opts.inputName || 'ports';
            const defaultTls = opts.defaultTls !== undefined ? opts.defaultTls : ['443'];
            const defaultNonTls = opts.defaultNonTls !== undefined ? opts.defaultNonTls : ['80'];
            tlsContainer.innerHTML = tlsPorts.map(function(port) {
                const isCheckedDefault = defaultTls.includes(port) ? 'checked' : '';
                return '<label class="relative cursor-pointer block">' +
                    '<input type="checkbox" name="' + inputName + '" value="' + port + '" ' + isCheckedDefault + ' class="peer sr-only">' +
                    '<div class="port-chip port-chip-tls">' +
                        '<span>' + port + '</span>' +
                        '<svg class="port-chip-check" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"></path></svg>' +
                    '</div>' +
                '</label>';
            }).join('');
            nonTlsContainer.innerHTML = nonTlsPorts.map(function(port) {
                const isCheckedDefault = defaultNonTls.includes(port) ? 'checked' : '';
                return '<label class="relative cursor-pointer block">' +
                    '<input type="checkbox" name="' + inputName + '" value="' + port + '" ' + isCheckedDefault + ' class="peer sr-only">' +
                    '<div class="port-chip port-chip-nontls">' +
                        '<span>' + port + '</span>' +
                        '<svg class="port-chip-check" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"></path></svg>' +
                    '</div>' +
                '</label>';
            }).join('');
        }
        function toggleSettingsModal(show) {
            if (show) switchAdminSection('settings');
        }
        function setSystemUserModalMode(isSystem) {
            const quota = document.getElementById('um-fields-quota');
            const notice = document.getElementById('um-sys-notice');
            if (quota) quota.classList.toggle('hidden', !!isSystem);
            if (notice) notice.classList.toggle('hidden', !isSystem);
            if (notice) notice.classList.toggle('hidden', !isSystem);
            if (isSystem) {
                document.getElementById('modal-title').innerText = 'مدیریت سرویس اصلی';
                document.getElementById('modal-subtitle').innerText = 'فقط پورت، آیپی تمیز و Proxy IP';
                document.getElementById('submit-btn').innerText = 'ذخیره تنظیمات';
            }
        }
        function toggleModal(show) {
            const modal = document.getElementById('user-modal');
            const headerIcon = modal.querySelector('.adm-um-header-icon svg');
            if (show) {
                modal.classList.add('open');
                document.body.style.overflow = 'hidden';
            } else {
                modal.classList.remove('open');
                document.body.style.overflow = '';
                isEditMode = false;
                editingUsername = '';
                setSystemUserModalMode(false);
                document.getElementById('modal-title').innerText = 'ایجاد کاربر جدید';
                document.getElementById('modal-subtitle').innerText = 'تنظیمات سرویس VPN را وارد کنید';
                document.getElementById('submit-btn').innerText = 'ایجاد کاربر';
                document.getElementById('input-name').disabled = false;
                document.getElementById('create-user-form').reset();
                if (headerIcon) headerIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z"></path>';
                const cb443 = document.querySelector('input[name="ports"][value="443"]');
                if (cb443) cb443.checked = true;
                const cb80 = document.querySelector('input[name="ports"][value="80"]');
                if (cb80) cb80.checked = true;
                const fpSelect = document.getElementById('fingerprint-select');
                if (fpSelect) fpSelect.value = 'random';
            }
        }
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                const modal = document.getElementById('user-modal');
                if (modal && modal.classList.contains('open')) toggleModal(false);
            }
        });
        function openCreateModal() {
            isEditMode = false;
            editingUsername = '';
            setSystemUserModalMode(false);
            document.getElementById('modal-title').innerText = 'ایجاد کاربر جدید';
            document.getElementById('modal-subtitle').innerText = 'تنظیمات سرویس VPN را وارد کنید';
            document.getElementById('submit-btn').innerText = 'ایجاد کاربر';
            document.getElementById('input-name').disabled = false;
            document.getElementById('create-user-form').reset();
            const headerIcon = document.querySelector('#user-modal .adm-um-header-icon svg');
            if (headerIcon) headerIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z"></path>';
            const cb443 = document.querySelector('input[name="ports"][value="443"]');
            if (cb443) cb443.checked = true;
            const cb80 = document.querySelector('input[name="ports"][value="80"]');
            if (cb80) cb80.checked = true;
            const fpSelect = document.getElementById('fingerprint-select');
            if (fpSelect) fpSelect.value = 'randomized';
            toggleModal(true);
        }
        try {
            const themeToggleBtn = document.getElementById('theme-toggle');
            if (localStorage.getItem('color-theme') === 'dark' || (!('color-theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                document.documentElement.classList.add('dark');
            } else {
                document.documentElement.classList.remove('dark');
            }
            if (themeToggleBtn) themeToggleBtn.addEventListener('click', function() {
                if (document.documentElement.classList.contains('dark')) {
                    document.documentElement.classList.remove('dark');
                    localStorage.setItem('color-theme', 'light');
                } else {
                    document.documentElement.classList.add('dark');
                    localStorage.setItem('color-theme', 'dark');
                }
            });
        } catch (e) {}
        async function loadUsers(silent = false) {
            const loadingState = document.getElementById('loading-state');
            const tableContainer = document.getElementById('users-table-container');
            const cardsContainer = document.getElementById('users-cards-container');
            const emptyState = document.getElementById('empty-state');
            if (!silent) {
                loadingState.classList.remove('hidden');
                tableContainer.classList.add('hidden');
                if (cardsContainer) cardsContainer.classList.add('hidden');
                emptyState.classList.add('hidden');
            }
            try {
                const res = await fetch('/api/users?t=' + Date.now());
                if (!res.ok) throw new Error();
                const data = await res.json();
                renderUsersUI(data);
            } catch (err) {
                if (!silent) {
                    loadingState.innerHTML = '<span class="text-red-500">خطا در دریافت اطلاعات از سرور</span>';
                }
            }
        }
        function renderUsersUI(data) {
            try {
                const users = data.users || [];
                window.allUsers = users;
                const serverTime = data.serverTime || Date.now();
                window.lastServerTime = serverTime;
                filterAndRenderUsers();
            } catch (err) {
                document.getElementById('loading-state').innerHTML = '<span class="text-red-500">خطا در پردازش اطلاعات کاربران</span>';
            }
        }
        function updateUsersStatsBar(users, serverTime) {
            let online = 0, inactive = 0, expired = 0;
            users.forEach(function(u) {
                if (u.is_online === 1) online++;
                let isExpired = false;
                if (u.limit_gb && u.used_gb >= u.limit_gb) isExpired = true;
                if (u.expiry_days && u.created_at) {
                    const created = new Date(u.created_at);
                    const expiryDate = new Date(created.getTime() + (u.expiry_days * 24 * 60 * 60 * 1000));
                    if (new Date(serverTime) > expiryDate) isExpired = true;
                }
                if (isExpired) expired++;
                if (u.is_active === 0) inactive++;
            });
            document.getElementById('stat-total').textContent = users.length;
            document.getElementById('stat-online').textContent = online;
            document.getElementById('stat-inactive').textContent = inactive;
            document.getElementById('stat-expired').textContent = expired;
        }
        function filterAndRenderUsers() {
            if (!window.allUsers) return;
            updateUsersStatsBar(window.allUsers, window.lastServerTime || Date.now());
            const searchQuery = (document.getElementById('search-input').value || '').toLowerCase().trim();
            const filterStatus = document.getElementById('filter-status').value;
            const sortVal = document.getElementById('sort-users').value;
            const serverTime = window.lastServerTime || Date.now();
            let filtered = [...window.allUsers];
            if (searchQuery) {
                filtered = filtered.filter(u => 
                    (u.username || '').toLowerCase().includes(searchQuery) || 
                    (u.uuid || '').toLowerCase().includes(searchQuery)
                );
            }
            if (filterStatus !== 'all') {
                filtered = filtered.filter(u => {
                    const isOnline = u.is_online === 1;
                    const isActive = u.is_active === 1;
                    let isExpired = false;
                    if (u.limit_gb && u.used_gb >= u.limit_gb) isExpired = true;
                    if (u.expiry_days && u.created_at) {
                        const created = new Date(u.created_at);
                        const expiryDate = new Date(created.getTime() + (u.expiry_days * 24 * 60 * 60 * 1000));
                        if (new Date(serverTime) > expiryDate) isExpired = true;
                    }
                    if (filterStatus === 'active') return isActive && !isExpired;
                    if (filterStatus === 'inactive') return !isActive;
                    if (filterStatus === 'online') return isOnline;
                    if (filterStatus === 'offline') return !isOnline;
                    if (filterStatus === 'expired') return isExpired || !isActive;
                    return true;
                });
            }
            filtered.sort((a, b) => {
                if (sortVal === 'newest') {
                    return b.id - a.id;
                }
                if (sortVal === 'name') {
                    return (a.username || '').localeCompare(b.username || '');
                }
                if (sortVal === 'usage-desc') {
                    return (b.used_gb || 0) - (a.used_gb || 0);
                }
                if (sortVal === 'usage-asc') {
                    return (a.used_gb || 0) - (b.used_gb || 0);
                }
                if (sortVal === 'expiry-asc') {
                    const getRemaining = (u) => {
                        if (!u.expiry_days) return Infinity;
                        if (!u.created_at) return Infinity;
                        const created = new Date(u.created_at);
                        const expiryDate = new Date(created.getTime() + (u.expiry_days * 24 * 60 * 60 * 1000));
                        return expiryDate - new Date(serverTime);
                    };
                    return getRemaining(a) - getRemaining(b);
                }
                return 0;
            });
            renderFilteredUsers(filtered, serverTime);
            const countBadge = document.getElementById('users-count-badge');
            if (countBadge) countBadge.textContent = filtered.length;
        }
        function renderFilteredUsers(users, serverTime) {
            const loadingState = document.getElementById('loading-state');
            const tableContainer = document.getElementById('users-table-container');
            const cardsContainer = document.getElementById('users-cards-container');
            const emptyState = document.getElementById('empty-state');
            const tbody = document.getElementById('users-tbody');
            if (users.length === 0) {
                loadingState.classList.add('hidden');
                emptyState.classList.remove('hidden');
                tableContainer.classList.add('hidden');
                if (cardsContainer) cardsContainer.classList.add('hidden');
                const emptyMsgs = emptyState.querySelectorAll('p');
                if (window.allUsers && window.allUsers.length > 0) {
                    if (emptyMsgs[0]) emptyMsgs[0].innerText = adminT('empty_no_results');
                    if (emptyMsgs[1]) emptyMsgs[1].innerText = adminT('empty_no_match');
                } else {
                    if (emptyMsgs[0]) emptyMsgs[0].innerText = adminT('empty_no_users');
                    if (emptyMsgs[1]) emptyMsgs[1].innerText = adminT('empty_create_hint');
                }
            } else {
                loadingState.classList.add('hidden');
                emptyState.classList.add('hidden');
                tableContainer.classList.remove('hidden');
                if (cardsContainer) cardsContainer.classList.remove('hidden');
                const rows = [];
                const cards = [];
                users.forEach(function(user) {
                    const createdDate = user.created_at ? new Date(user.created_at).toLocaleDateString('fa-IR') : '-';
                    let daysRemaining = 'نامحدود';
                    let daysPercent = 100;
                    if (user.expiry_days) {
                        if (user.created_at) {
                            const created = new Date(user.created_at);
                            const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
                            const diffDays = Math.ceil((expiryDate - new Date(serverTime)) / (1000 * 60 * 60 * 24));
                            daysRemaining = diffDays > 0 ? diffDays : 0;
                            daysPercent = Math.max(0, Math.min(100, (daysRemaining / user.expiry_days) * 100));
                        } else {
                            daysRemaining = user.expiry_days;
                        }
                    }
                    const usedGb = user.used_gb || 0;
                    const formattedUsed = usedGb < 1 ? (usedGb * 1024).toFixed(0) + ' MB' : usedGb.toFixed(2) + ' GB';
                    const volumeHtml = buildVolumeProgressHtml(user, usedGb, formattedUsed);
                    const expiryHtml = buildExpiryProgressHtml(user, daysRemaining, daysPercent);
                    const requestHtml = buildRequestProgressHtml(user);
                    const statusBtnClass = user.is_active === 0 ? 'act-toggle-off' : 'act-toggle-on';
                    const statusBtnTitle = user.is_active === 0 ? 'فعال کردن کاربر' : 'قطع کردن کاربر';
                    const statusBtnIcon = user.is_active === 0 
                        ? '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>'
                        : '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>';
                    const saveBtnClass = user.is_saved === 1 ? 'adm-ua-btn act-save active' : 'adm-ua-btn act-save';
                    const saveBtnTitle = user.is_saved === 1 ? 'ذخیره شده — حذف خودکار غیرفعال' : 'ذخیره (جلوگیری از حذف خودکار پس از انقضا)';
                    const isSelected = window.selectedUsernames.has(user.username) ? 'checked' : '';
                    const selectedClass = window.selectedUsernames.has(user.username) ? ' is-selected' : '';
                    const isSysUser = isSystemUserClient(user);
                    const systemBadge = isSysUser ? '<span class="adm-ub-badge info">سرویس اصلی</span>' : '';
                    const onlineBadge = user.is_online === 1 ? '<span class="adm-ub-badge online">آنلاین</span>' : '<span class="adm-ub-badge muted">آفلاین</span>';
                    const userInitial = (user.username || '?').charAt(0).toUpperCase();
                    const userAttr = adminUserDataAttrs(user.username);
                    const statusToggleBtn = '<button type="button" data-user-action="toggle-status"' + userAttr + ' title="' + statusBtnTitle + '" class="adm-ua-btn ' + statusBtnClass + '">' + statusBtnIcon + '</button>';
                    const sysActionBtns = isSysUser ? statusToggleBtn :
                        statusToggleBtn +
                        '<button type="button" data-user-action="reset-volume"' + userAttr + ' title="ریست حجم سرویس" class="adm-ua-btn act-reset"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg></button>' +
                        '<button type="button" data-user-action="reset-time"' + userAttr + ' title="ریست زمان سرویس" class="adm-ua-btn act-time"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></button>';
                    const saveBtnHtml = isSysUser ? '' : '<button type="button" data-user-action="save"' + userAttr + ' title="' + saveBtnTitle + '" class="' + saveBtnClass + '"><svg fill="' + (user.is_saved === 1 ? 'currentColor' : 'none') + '" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 5a2 2 0 012-2h10a2 2 0 012 2v16l-7-3.5L5 21V5z"></path></svg></button>';
                    const deleteBtnHtml = isSysUser ? '' : '<button type="button" data-user-action="delete"' + userAttr + ' title="حذف" class="adm-ua-btn act-delete"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg></button>';
                    const deleteBtnCardHtml = isSysUser ? '' : '<button type="button" data-user-action="delete"' + userAttr + ' title="حذف" class="adm-ua-btn act-delete"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg></button>';
                    const selectCbHtml = isSysUser ? '' : '<input type="checkbox" class="user-select-cb adm-select-cb" data-username="' + encodeURIComponent(user.username) + '" ' + isSelected + ' onchange="onUserSelectChange(this)">';
                    const subLinkHtml =
                        '<div class="adm-sub-group">' +
                            '<div class="adm-sub-row">' +
                                '<button type="button" data-user-action="copy-sub"' + userAttr + ' class="adm-ul-btn sub-main">' +
                                    '<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>کپی لینک ساب</button>' +
                                '<button type="button" data-user-action="sub-qr"' + userAttr + ' title="qrcode اشتراک" class="adm-ul-btn sub-main">qrcode اشتراک</button>' +
                            '</div>' +
                            '<div class="adm-sub-row">' +
                                '<button type="button" data-user-action="status"' + userAttr + ' class="adm-ul-btn blue">' +
                                    '<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>وضعیت سرویس</button>' +
                                '<button type="button" data-user-action="logs"' + userAttr + ' class="adm-ul-btn violet">' +
                                    '<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path></svg>لاگ اتصال</button>' +
                            '</div>' +
                        '</div>';
                    rows.push('<tr class="admin-row' + selectedClass + '">' +
                            '<td>' + selectCbHtml + '</td>' +
                            '<td>' +
                                '<div class="adm-user-identity">' +
                                    '<div class="adm-user-avatar">' + userInitial + '</div>' +
                                    '<div class="adm-user-identity-body">' +
                                        '<span class="adm-user-name">' + user.username + '</span>' +
                                        '<div class="adm-user-badges">' + systemBadge + getUserStatusBadge(user, serverTime) + onlineBadge + '</div>' +
                                        '<div class="adm-act-bar">' +
                                            sysActionBtns +
                                            '<button type="button" data-user-action="edit"' + userAttr + ' title="ویرایش" class="adm-ua-btn act-edit"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg></button>' +
                                            saveBtnHtml +
                                            deleteBtnHtml +
                                        '</div>' +
                                    '</div>' +
                                '</div>' +
                            '</td>' +
                            '<td>' + subLinkHtml + '</td>' +
                            '<td><span class="adm-proto-badge">VLESS</span></td>' +
                            '<td>' + 
                                '<div class="flex flex-wrap gap-1 max-w-[9rem]">' +
                                    String(user.port || "").split(",").map(function(p) {
                                        p = p.trim();
                                        if (!p) return "";
                                        var isTls = tlsPorts.includes(p);
                                        return '<span class="adm-port-tag ' + (isTls ? 'tls' : 'nontls') + '">' + p + '</span>';
                                    }).join("") +
                                '</div>' +
                            '</td>' +
                            '<td>' + volumeHtml + '</td>' +
                            '<td>' + expiryHtml + '</td>' +
                            '<td>' + requestHtml + '</td>' +
                            '<td class="adm-date-cell">' + createdDate + '</td>' +
                        '</tr>');
                    cards.push('<div class="adm-user-card' + selectedClass + '">' +
                        '<div class="adm-user-card-head">' +
                            '<div class="flex items-start gap-2 min-w-0">' +
                                (isSysUser ? '' : '<input type="checkbox" class="user-select-cb adm-select-cb mt-1" data-username="' + encodeURIComponent(user.username) + '" ' + isSelected + ' onchange="onUserSelectChange(this)">') +
                                '<div class="adm-user-avatar">' + userInitial + '</div>' +
                                '<div class="min-w-0">' +
                                    '<div class="adm-user-card-name">' + user.username + '</div>' +
                                    '<div class="adm-user-badges mt-1">' + systemBadge + getUserStatusBadge(user, serverTime) + onlineBadge + '</div>' +
                                '</div>' +
                            '</div>' +
                            '<span class="adm-proto-badge">VLESS</span>' +
                        '</div>' +
                        '<div class="adm-user-card-meta">' +
                            '<div class="adm-meta-col">' + volumeHtml + expiryHtml + '</div>' +
                            '<div class="adm-meta-col">' + requestHtml + '</div>' +
                        '</div>' +
                        '<div class="flex flex-wrap gap-1">' +
                            String(user.port || "").split(",").map(function(p) {
                                p = p.trim();
                                if (!p) return "";
                                var isTls = tlsPorts.includes(p);
                                return '<span class="adm-port-tag ' + (isTls ? 'tls' : 'nontls') + '">' + p + '</span>';
                            }).join("") +
                        '</div>' +
                        subLinkHtml +
                        '<div class="adm-user-card-actions">' +
                        '<div class="adm-act-bar">' +
                            '<button type="button" data-user-action="edit"' + userAttr + ' title="ویرایش" class="adm-ua-btn act-edit"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg></button>' +
                            statusToggleBtn +
                            (isSysUser ? '' :
                                '<button type="button" data-user-action="reset-volume"' + userAttr + ' title="ریست حجم" class="adm-ua-btn act-reset"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg></button>'
                            ) +
                            (isSysUser ? '' :
                                '<button type="button" data-user-action="reset-time"' + userAttr + ' title="ریست زمان" class="adm-ua-btn act-time"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></button>'
                            ) +
                            saveBtnHtml +
                            deleteBtnCardHtml +
                        '</div>' +
                    '</div>' +
                    '</div>');
                });
                tbody.innerHTML = rows.join('');
                if (cardsContainer) cardsContainer.innerHTML = cards.join('');
            }
        }
        async function toggleSaveUser(encodedUsername) {
            const username = decodeURIComponent(encodedUsername);
            const targetUser = (window.allUsers || []).find(function(u) { return u.username === username; });
            if (isSystemUserClient(targetUser)) {
                showNexaToast('سرویس اصلی همیشه ذخیره است', 'error');
                return;
            }
            try {
                const response = await fetch('/api/users/' + encodeURIComponent(username), {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ save_only: true })
                });
                if (response.ok) {
                    await loadUsers(true);
                } else {
                    const errData = await response.json();
                    alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
                }
            } catch (err) {
                alert('خطا در برقراری ارتباط با سرور');
            }
        }
        async function toggleUserStatus(encodedUsername) {
            const username = decodeURIComponent(encodedUsername);
            const targetUser = (window.allUsers || []).find(function(u) { return u.username === username; });
            const isSys = isSystemUserClient(targetUser);
            try {
                const response = await fetch('/api/users/' + encodeURIComponent(username), {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ toggle_only: true })
                });
                if (response.ok) {
                    await loadUsers(true);
                    if (isSys && typeof loadDashboard === 'function') loadDashboard(true);
                } else {
                    const errData = await response.json();
                    alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
                }
            } catch (err) {
                alert('خطا در برقراری ارتباط با سرور');
            }
        }
        async function resetUserService(encodedUsername, type) {
            const username = decodeURIComponent(encodedUsername);
            const targetUser = (window.allUsers || []).find(function(u) { return u.username === username; });
            if (isSystemUserClient(targetUser)) {
                showNexaToast('ریست حجم یا زمان سرویس اصلی مجاز نیست', 'error');
                return;
            }
            const label = type === 'time' ? 'زمان' : 'حجم';
            if (!await showNexaConfirm('آیا از ریست ' + label + ' سرویس کاربر «' + username + '» مطمئن هستید؟', { title: 'ریست سرویس', danger: true, confirmText: 'بله، ریست شود' })) return;
            try {
                const body = type === 'time' ? { reset_time: true } : { reset_volume: true };
                const response = await fetch('/api/users/' + encodeURIComponent(username), {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                if (response.ok) {
                    alert('✅ ریست ' + label + ' با موفقیت انجام شد');
                    await loadUsers(true);
                } else {
                    const errData = await response.json();
                    alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
                }
            } catch (err) {
                alert('خطا در برقراری ارتباط با سرور');
            }
        }
        async function handleFormSubmit(event) {
            event.preventDefault();
            const submitButton = document.getElementById('submit-btn');
            submitButton.disabled = true;
            submitButton.innerText = isEditMode ? 'در حال ذخیره تغییرات...' : 'در حال ایجاد...';
            const username = document.getElementById('input-name').value;
            const checkedPorts = Array.from(document.querySelectorAll('input[name="ports"]:checked')).map(cb => cb.value);
            if (checkedPorts.length === 0) {
                alert('⚠️ لطفا حداقل یک پورت را برای اتصال انتخاب کنید!');
                submitButton.disabled = false;
                submitButton.innerText = isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر';
                return;
            }
            const port = checkedPorts.join(',');
            const tls = checkedPorts.some(p => tlsPorts.includes(p)) ? 'on' : 'off';
            const ips = document.getElementById('input-ips').value;
            const proxyIp = document.getElementById('input-proxy-ip').value;
            const url = isEditMode ? '/api/users/' + encodeURIComponent(editingUsername) : '/api/users';
            const method = isEditMode ? 'PUT' : 'POST';
            const editingUser = isEditMode ? (window.allUsers || []).find(function(u) { return u.username === editingUsername; }) : null;
            const isSysEdit = isEditMode && isSystemUserClient(editingUser);
            const fingerprintValSys = document.getElementById('fingerprint-select').value;
            let payload;
            if (isSysEdit) {
                payload = { ips, tls, port, proxy_ip: proxyIp, fingerprint: fingerprintValSys };
            } else {
                const limit = document.getElementById('input-limit').value || null;
                const expiry = document.getElementById('input-expiry').value || null;
                const maxRequests = document.getElementById('input-max-requests').value || null;
                const maxRequestsDaily = document.getElementById('input-max-requests-daily').value || null;
                const fingerprint = document.getElementById('fingerprint-select').value;
                payload = { username, limit_gb: limit, expiry_days: expiry, tls, port, ips, proxy_ip: proxyIp, fingerprint, max_requests: maxRequests, max_requests_daily: maxRequestsDaily };
            }
            try {
                const response = await fetch(url, {
                    method: method,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                if (response.ok) {
                    toggleModal(false);
                    await loadUsers(true);
                    if (isSysEdit) loadDashboard(true);
                } else {
                    const errData = await response.json();
                    alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
                }
            } catch (err) {
                alert('خطا در برقراری ارتباط با سرور');
            } finally {
                submitButton.disabled = false;
                const editingUser = isEditMode ? (window.allUsers || []).find(function(u) { return u.username === editingUsername; }) : null;
                submitButton.innerText = (isEditMode && isSystemUserClient(editingUser)) ? 'ذخیره تنظیمات' : (isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر');
            }
        }
function closeUsageWarning() {
    const modal = document.getElementById('usage-warning-modal');
    const card = modal.querySelector('div');
    modal.classList.remove('opacity-100', 'pointer-events-auto');
    modal.classList.add('opacity-0', 'pointer-events-none');
    card.classList.remove('opacity-100', 'scale-100');
    card.classList.add('opacity-0', 'scale-95');
    const today = new Date().toISOString().split('T')[0];
    localStorage.setItem('nexa_usage_warned_date', today);
}
        function formatVolumeLabel(gb) {
            if (gb == null || gb === undefined) return 'نامحدود';
            if (gb < 1) return (gb * 1024).toFixed(0) + ' MB';
            const n = gb % 1 === 0 ? gb.toFixed(0) : gb.toFixed(2);
            return n + ' GB';
        }
        function buildServiceInfoRemark(user, now) {
            now = now || Date.now();
            const usedStr = fmtRemarkVolume(user.used_gb || 0);
            const totalStr = user.limit_gb != null ? fmtRemarkVolume(user.limit_gb) : '∞';
            let daysPart = '∞';
            if (user.expiry_days) {
                if (user.created_at) {
                    const created = new Date(user.created_at);
                    const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
                    const diffDays = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
                    daysPart = (diffDays > 0 ? diffDays : 0) + ' روز';
                } else {
                    daysPart = user.expiry_days + ' روز';
                }
            }
            return '[مصرف شده: ' + usedStr +']' + '['+ totalStr +' : کل ' +']'+ '[مانده :' + daysPart+']';
        }
        function fmtRemarkVolume(gb) {
            if (gb == null || gb === undefined) return '∞';
            if (gb < 1) return (gb * 1024).toFixed(0) + ' MB';
            const n = gb % 1 === 0 ? gb.toFixed(0) : gb.toFixed(2);
            return n + ' GB';
        }
        function isVolumeExpiredUser(user) {
            return user.limit_gb != null && user.used_gb >= user.limit_gb;
        }
        function buildFirstRemark() {
            return '❌ سرویس نکسا کاملا رایگان  است.❌ ';
        }
        function buildSecondRemark(user, now) {
            if (window.panelAllServicesOff) {
                return 'غیر فعال : قطع تمامی سرویس‌ها';
            }
            const volExp = isVolumeExpiredUser(user);
            const timeExp = isTimeExpiredUser(user, now);
            const reqExp = isRequestLimitExceededUser(user);
            if (reqExp || user.is_active === 0 || volExp || timeExp) {
                return 'غیر فعال : ' + getInactiveReasonUser(user, now);
            }
            const cfg = getPanelWorkerConfig();
            const template = cfg.infoRemarkTemplate || (workerConfigDefaults && workerConfigDefaults.infoRemarkTemplate) || '[مصرف شده: {used}] [{total} : کل ] [مانده : {dayremind}]';
            return applyRemarkTemplateClient(template, user, now);
        }
        function isTimeExpiredUser(user, now) {
            if (!user.expiry_days || !user.created_at) return false;
            const created = new Date(user.created_at);
            const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
            return (now || Date.now()) > expiryDate.getTime();
        }
        function getInactiveReasonUser(user, now) {
            if (isRequestLimitExceededUser(user)) return 'اتمام ریکوئست';
            const volExp = isVolumeExpiredUser(user);
            const timeExp = isTimeExpiredUser(user, now);
            if (volExp && timeExp) return 'پایان زمان و حجم سرویس';
            if (volExp) return 'پایان حجم سرویس';
            if (timeExp) return 'پایان زمان سرویس';
            if (user.is_active === 0) return 'قطع شدن دستی توسط ادمین';
            return 'غیرفعال';
        }
        function isRequestLimitExceededUser(user) {
            if (!user) return false;
            const usedTotal = user.used_requests_total != null ? user.used_requests_total : (user.used_requests || 0);
            const usedToday = user.used_requests_today != null ? user.used_requests_today : 0;
            if (user.max_requests && user.max_requests > 0 && usedTotal >= user.max_requests) return true;
            if (user.max_requests_daily && user.max_requests_daily > 0 && usedToday >= user.max_requests_daily) return true;
            return false;
        }
        function getUserStatusBadge(user, serverTime) {
            if (window.panelAllServicesOff) {
                return '<span class="adm-ub-badge danger">قطع کلی</span>';
            }
            const now = serverTime || Date.now();
            const volExp = isVolumeExpiredUser(user);
            const timeExp = isTimeExpiredUser(user, now);
            const reqExp = isRequestLimitExceededUser(user);
            if (reqExp) return '<span class="adm-ub-badge warn">ریکوئست تمام</span>';
            if (volExp && timeExp) return '<span class="adm-ub-badge danger">منقضی</span>';
            if (volExp) return '<span class="adm-ub-badge warn">حجم تمام</span>';
            if (timeExp) return '<span class="adm-ub-badge warn">زمان تمام</span>';
            if (user.is_active === 0) return '<span class="adm-ub-badge danger">قطع</span>';
            return '<span class="adm-ub-badge success">فعال</span>';
        }
        function buildVolumeProgressHtml(user, usedGb, formattedUsed) {
            if (user.limit_gb) {
                const limitPercent = Math.min((usedGb / user.limit_gb) * 100, 100);
                const fillClass = limitPercent >= 85 ? 'vol-high' : (limitPercent >= 55 ? 'vol-mid' : 'vol-low');
                const formattedLimit = user.limit_gb < 1 ? (user.limit_gb * 1024).toFixed(0) + ' MB' : user.limit_gb + ' GB';
                return '<div class="adm-up-wrap">' +
                    '<div class="adm-up-meta"><span>مصرف: ' + formattedUsed + '</span><span>کل: ' + formattedLimit + '</span></div>' +
                    '<div class="adm-up-track"><div class="adm-up-fill ' + fillClass + '" style="width:' + limitPercent + '%"></div></div>' +
                '</div>';
            }
            return '<div class="adm-up-wrap">' +
                '<div class="adm-up-meta"><span>مصرف: ' + formattedUsed + '</span><span>کل: نامحدود</span></div>' +
                '<div class="adm-up-track"><div class="adm-up-fill vol-unlimited" style="width:100%"></div></div>' +
            '</div>';
        }
        function buildExpiryProgressHtml(user, daysRemaining, daysPercent) {
            if (user.expiry_days) {
                const fillClass = daysPercent <= 20 ? 'exp-low' : (daysPercent <= 50 ? 'exp-mid' : 'exp-high');
                return '<div class="adm-up-wrap">' +
                    '<div class="adm-up-meta"><span>باقی‌مانده: ' + daysRemaining + ' روز</span><span>کل: ' + user.expiry_days + ' روز</span></div>' +
                    '<div class="adm-up-track"><div class="adm-up-fill ' + fillClass + '" style="width:' + daysPercent + '%"></div></div>' +
                '</div>';
            }
            return '<div class="adm-up-wrap">' +
                '<div class="adm-up-meta"><span>باقی‌مانده: نامحدود</span><span>کل: نامحدود</span></div>' +
                '<div class="adm-up-track"><div class="adm-up-fill exp-unlimited" style="width:100%"></div></div>' +
            '</div>';
        }
        function buildRequestProgressHtml(user) {
            const usedTotal = user.used_requests_total != null ? user.used_requests_total : (user.used_requests || 0);
            const usedToday = user.used_requests_today != null ? user.used_requests_today : 0;
            const totalHtml = user.max_requests
                ? buildRequestBarHtml('مصرف کل', formatReqCount(usedTotal), formatReqCount(user.max_requests), usedTotal, user.max_requests)
                : buildRequestBarHtml('مصرف کل', formatReqCount(usedTotal), 'نامحدود', 0, 0, true);
            const dailyHtml = user.max_requests_daily
                ? buildRequestBarHtml('مصرف روزانه', formatReqCount(usedToday), formatReqCount(user.max_requests_daily), usedToday, user.max_requests_daily)
                : buildRequestBarHtml('مصرف روزانه', formatReqCount(usedToday), 'نامحدود', 0, 0, true);
            return '<div class="space-y-2">' + totalHtml + dailyHtml + '</div>';
        }
        function buildRequestBarHtml(label, usedLabel, maxLabel, used, max, unlimited) {
            if (unlimited) {
                return '<div class="adm-up-wrap">' +
                    '<div class="adm-up-meta"><span>' + label + ': ' + usedLabel + '</span><span>کل: ' + maxLabel + '</span></div>' +
                    '<div class="adm-up-track"><div class="adm-up-fill vol-unlimited" style="width:100%"></div></div>' +
                '</div>';
            }
            const limitPercent = Math.min((used / max) * 100, 100);
            const fillClass = limitPercent >= 85 ? 'vol-high' : (limitPercent >= 55 ? 'vol-mid' : 'vol-low');
            return '<div class="adm-up-wrap">' +
                '<div class="adm-up-meta"><span>' + label + ': ' + usedLabel + '</span><span>کل: ' + maxLabel + '</span></div>' +
                '<div class="adm-up-track"><div class="adm-up-fill ' + fillClass + '" style="width:' + limitPercent + '%"></div></div>' +
            '</div>';
        }
        const backupSpinnerHtml = '<div class="p-3 rounded-xl" style="background: var(--admin-primary-soft); color: var(--admin-primary)"><svg class="w-8 h-8 animate-spin" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path></svg></div>';
        const backupDownloadIcon = '<svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path></svg>';
        const backupUploadIcon = '<svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M7.5 12L12 16.5m0 0L16.5 12M12 7.5v9"></path></svg>';
        const backupIconWrap = function(svg) { return '<div class="p-3 rounded-xl" style="background: var(--admin-primary-soft); color: var(--admin-primary)">' + svg + '</div>'; };
        const backupDownloadBtnHtml = backupIconWrap(backupDownloadIcon) + '<span class="text-sm font-bold" data-i18n="backup_download">دریافت بکاپ</span>';
        const backupUploadBtnHtml = backupIconWrap(backupUploadIcon) + '<span class="text-sm font-bold" data-i18n="backup_upload">بارگذاری بکاپ</span><input type="file" id="backup-file-input" accept=".json,application/json" class="hidden" onchange="restoreBackup(event)">';
        let backupAutoEnabled = false;
        function updateBackupAutoUI() {
            const toggle = document.getElementById('backup-auto-toggle');
            const hint = document.getElementById('backup-tg-hint');
            const sendBtn = document.getElementById('backup-tg-send-btn');
            if (toggle) {
                toggle.classList.toggle('on', backupAutoEnabled);
                toggle.setAttribute('aria-checked', backupAutoEnabled ? 'true' : 'false');
            }
            if (sendBtn) sendBtn.disabled = false;
            if (hint) hint.classList.toggle('hidden', window.backupTelegramReady);
        }
        function formatBackupLastRun(iso) {
            if (!iso) return '';
            try {
                const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
                const locale = lang === 'en' ? 'en-US' : 'fa-IR';
                return new Date(iso).toLocaleString(locale, { timeZone: 'Asia/Tehran' });
            } catch (e) { return iso; }
        }
        function updateBackupStatusUI(data) {
            const statusEl = document.getElementById('backup-auto-status');
            if (!statusEl) return;
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            const lastLabel = adminT('backup_last_run');
            const neverLabel = adminT('backup_last_never');
            const lastRun = data.last_run_at ? formatBackupLastRun(data.last_run_at) : neverLabel;
            let statusText = lastLabel + ': ' + lastRun;
            if (data.last_status && data.last_status !== 'success') {
                statusText += ' — ' + data.last_status;
            }
            statusEl.textContent = statusText;
            statusEl.classList.remove('hidden');
            window.backupTelegramReady = !!data.telegram_ready;
            updateBackupAutoUI();
        }
        async function loadBackupSettings() {
            try {
                const res = await fetch('/api/backup-settings');
                if (!res.ok) return;
                const data = await res.json();
                backupAutoEnabled = !!data.auto_enabled;
                updateBackupStatusUI(data);
            } catch (e) {}
        }
        function toggleBackupAutoSwitch() {
            if (!backupAutoEnabled && !window.backupTelegramReady) {
                showNexaToast(adminT('backup_tg_hint'), 'error');
                return;
            }
            backupAutoEnabled = !backupAutoEnabled;
            updateBackupAutoUI();
            saveBackupSettings(true);
        }
        async function saveBackupSettings(silent) {
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            try {
                const res = await fetch('/api/backup-settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ auto_enabled: backupAutoEnabled, quiet: !!silent })
                });
                const data = await res.json();
                if (res.ok && data.success) {
                    if (!silent) showNexaToast(adminT('backup_auto_saved'));
                    await loadBackupSettings();
                } else if (!silent) {
                    showNexaToast(data.error || adminT('toast_save_fail'), 'error');
                }
            } catch (e) {
                if (!silent) showNexaToast(lang === 'en' ? 'Connection error' : 'خطا در ارتباط', 'error');
            }
        }
        async function sendBackupToTelegram() {
            const btn = document.getElementById('backup-tg-send-btn');
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            if (btn) btn.disabled = true;
            try {
                const res = await fetch('/api/backup/send-telegram', { method: 'POST' });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || adminT('backup_tg_fail'));
                showNexaToast(adminT('backup_tg_sent'));
            } catch (err) {
                showNexaToast(err.message || adminT('backup_tg_fail'), 'error');
            } finally {
                if (btn) btn.disabled = false;
            }
        }
        async function downloadBackup() {
            const btn = document.getElementById('backup-download-btn');
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = backupSpinnerHtml + '<span class="text-sm font-bold" data-i18n="backup_download">دریافت بکاپ</span>';
            }
            try {
                const res = await fetch('/api/backup');
                if (!res.ok) throw new Error('خطا در دریافت بکاپ');
                const blob = await res.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'nexa-backup-' + new Date().toISOString().slice(0, 10) + '.json';
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(url);
            } catch (err) {
                alert('خطا: ' + err.message);
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = backupDownloadBtnHtml;
                    applyAdminI18n(localStorage.getItem('nexa-admin-lang') || 'fa');
                }
            }
        }
        async function restoreBackup(event) {
            const file = event.target.files[0];
            if (!file) return;
            const uploadBtn = document.getElementById('backup-upload-btn');
            if (!await showNexaConfirm('با بازیابی بکاپ، تمام کاربران و تنظیمات فعلی جایگزین می‌شوند. ادامه می‌دهید؟', { title: 'بازیابی بکاپ', danger: true, confirmText: 'بله، بازیابی شود' })) {
                event.target.value = '';
                return;
            }
            if (uploadBtn) {
                uploadBtn.innerHTML = backupSpinnerHtml + '<span class="text-sm font-bold" data-i18n="backup_upload">بارگذاری بکاپ</span><input type="file" id="backup-file-input" accept=".json,application/json" class="hidden" onchange="restoreBackup(event)">';
            }
            try {
                const text = await file.text();
                const data = JSON.parse(text);
                const res = await fetch('/api/restore', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                const result = await res.json();
                if (!res.ok) throw new Error(result.error || 'خطا در بازیابی');
                alert('✅ بکاپ با موفقیت بازیابی شد (' + result.users_count + ' کاربر)');
                location.reload();
            } catch (err) {
                alert('خطا: ' + err.message);
            } finally {
                if (uploadBtn) {
                    uploadBtn.innerHTML = backupUploadBtnHtml;
                    applyAdminI18n(localStorage.getItem('nexa-admin-lang') || 'fa');
                }
                event.target.value = '';
            }
        }
        function resolveConfigIps(host, userIpsRaw) {
            const parsed = String(userIpsRaw || '').split('\\n').map(function(ip) {
                const trimmed = ip.trim();
                const hashIdx = trimmed.indexOf('#');
                return hashIdx >= 0 ? trimmed.slice(0, hashIdx).trim() : trimmed;
            }).filter(function(ip) { return ip.length > 0; });
            if (!parsed.length) return [host];
            const ips = [host];
            parsed.forEach(function(ip) {
                if (!ips.some(function(existing) { return existing.toLowerCase() === ip.toLowerCase(); })) {
                    ips.push(ip);
                }
            });
            return ips;
        }
        function getVlessLink(username) {
            const user = window.allUsers.find(u => u.username === username);
            if (!user) return '';
            const host = window.location.hostname;
            const ips = resolveConfigIps(host, user.ips);
            const ports = String(user.port || '443').split(',').map(p => p.trim()).filter(p => p.length > 0);
            const fp = user.fingerprint || 'random';
            const links = [];
            const firstRemark = buildFirstRemark();
            let secondRemark = buildSecondRemark(user, Date.now());
            let inactive = secondRemark.startsWith('غیر فعال');
            if (window.panelAllServicesOff) {
                inactive = true;
                if (!secondRemark.startsWith('غیر فعال')) {
                    secondRemark = 'غیر فعال : قطع تمامی سرویس‌ها';
                }
            }
            const cfg = getPanelWorkerConfig();
            const tc = getClientTransportConfig(cfg);
            const pathEnc = encodeURIComponent(cfg.transportPath || '/in_config_foroshi_nist');
            const proto = cfg.protocolType === 'mixed' ? 'vless' : (cfg.protocolType || 'vless');
            const fakeLink = (remark) => proto + '://' + (user.uuid || '') + '@127.0.0.1:17?encryption=none&security=none&type=' + tc.typeParam + '&' + tc.hostField + '=' + host + '&' + tc.pathField + '=' + pathEnc + '#' + encodeURIComponent(remark);
            links.push(fakeLink(firstRemark));
            links.push(fakeLink(secondRemark));
            if (!inactive) {
                let nodeIndex = 0;
                ips.forEach((ip) => {
                    ports.forEach((portStr) => {
                        const nodeTemplate = cfg.nodeRemarkTemplate || '{username}';
                        const remark = applyRemarkTemplateClient(nodeTemplate, user, Date.now(), { port: portStr });
                        let nodeProto = cfg.protocolType || 'vless';
                        if (nodeProto === 'mixed') {
                            nodeProto = ['vless', 'trojan', 'ss'][nodeIndex % 3];
                            nodeIndex++;
                        }
                        links.push(buildClientNodeLink(cfg, user, ip, portStr, fp, remark, nodeProto, host));
                    });
                });
            }
            return links.join('\\n');
        }
        function getSubLink(username) {
            const cfg = getPanelWorkerConfig();
            const path = getWorkerPagePath(cfg, 'subPagePath', 'sub');
            return window.location.origin + '/' + path + '/' + encodeURIComponent(username);
        }
        function getStatusLink(username) {
            const cfg = getPanelWorkerConfig();
            const path = getWorkerPagePath(cfg, 'statusPagePath', 'servicestat');
            return window.location.origin + '/' + path + '/' + encodeURIComponent(username);
        }
        function getLogsLink(username) {
            const cfg = getPanelWorkerConfig();
            const path = getWorkerPagePath(cfg, 'logsPagePath', 'logs');
            return window.location.origin + '/' + path + '/' + encodeURIComponent(username);
        }
        function openStatusPage(encodedUsername) {
            const username = decodeURIComponent(encodedUsername);
            window.open(getStatusLink(username), '_blank');
        }
        function openLogsPage(encodedUsername) {
            const username = decodeURIComponent(encodedUsername);
            window.open(getLogsLink(username), '_blank');
        }
        function copySubLink(encodedUsername) {
            const username = decodeURIComponent(encodedUsername);
            navigator.clipboard.writeText(getSubLink(username)).then(() => {
                showNexaToast('لینک ساب با موفقیت کپی شد');
            }).catch(() => {
                showNexaToast('خطا در کپی کردن لینک ساب', 'error');
            });
        }
        function showSubQR(encodedUsername) {
            const username = decodeURIComponent(encodedUsername || '');
            if (!username) return;
            openSubLinkQrModal(username, adminT('btn_qr_sub') || 'qrcode اشتراک');
        }
        function editUser(encodedUsername) {
            const username = decodeURIComponent(encodedUsername);
            const user = window.allUsers.find(u => u.username === username);
            if (!user) {
                alert('کاربر یافت نشد!');
                return;
            }
            const isSys = isSystemUserClient(user);
            isEditMode = true;
            editingUsername = username;
            setSystemUserModalMode(isSys);
            if (!isSys) {
                document.getElementById('modal-title').innerText = 'ویرایش کاربر';
                document.getElementById('modal-subtitle').innerText = 'ویرایش تنظیمات «' + username + '»';
                document.getElementById('submit-btn').innerText = 'ذخیره تغییرات';
            }
            const headerIcon = document.querySelector('#user-modal .adm-um-header-icon svg');
            if (headerIcon) headerIcon.innerHTML = isSys
                ? '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"></path>'
                : '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>';
            const nameInput = document.getElementById('input-name');
            nameInput.value = username;
            nameInput.disabled = isSys;
            if (!isSys) {
                document.getElementById('input-limit').value = user.limit_gb || '';
                document.getElementById('input-expiry').value = user.expiry_days || '';
                document.getElementById('input-max-requests').value = user.max_requests || user.max_connections || '';
                document.getElementById('input-max-requests-daily').value = user.max_requests_daily || '';
            }
            document.getElementById('fingerprint-select').value = user.fingerprint || 'random';
            document.getElementById('input-ips').value = user.ips || '';
            document.getElementById('input-proxy-ip').value = user.proxy_ip || '';            const userPorts = String(user.port || '').split(',').map(p => p.trim());
            document.querySelectorAll('input[name="ports"]').forEach(cb => {
                cb.checked = userPorts.includes(cb.value);
            });
            toggleModal(true);
        }
        async function deleteUser(encodedUsername) {
            const username = decodeURIComponent(encodedUsername);
            const targetUser = (window.allUsers || []).find(function(u) { return u.username === username; });
            if (isSystemUserClient(targetUser)) {
                showNexaToast('این کاربر سیستمی است و قابل حذف نیست', 'error');
                return;
            }
            if (!await showNexaConfirm('آیا از حذف کاربر «' + username + '» مطمئن هستید؟', { title: 'حذف کاربر', danger: true, confirmText: 'بله، حذف شود' })) return;
            try {
                const response = await fetch('/api/users/' + encodeURIComponent(username), { method: 'DELETE' });
                if (response.ok) {
                    showNexaToast('کاربر با موفقیت حذف شد');
                    await loadUsers(true);
                } else {
                    const errData = await response.json();
                    showNexaToast('خطا: ' + (errData.error || 'عملیات ناموفق بود'), 'error');
                }
            } catch (err) {
                showNexaToast('خطا در برقراری ارتباط با سرور', 'error');
            }
        }
        function getFlagEmoji(countryCode) {
            if (!countryCode) return '🌐';
            const codePoints = countryCode.toUpperCase().split('').map(char => 127397 + char.charCodeAt(0));
            try {
                return String.fromCodePoint(...codePoints);
            } catch (e) {
                return '🌐';
            }
        }
        async function loadCfCredentialsForm() {
            try {
                const tokenEl = document.getElementById('cf-token-input');
                const accountEl = document.getElementById('cf-account-id-input');
                const hintEl = document.getElementById('cf-token-hint');
                if (document.activeElement === tokenEl) return;
                const res = await fetch('/api/cf-credentials');
                if (!res.ok) return;
                const data = await res.json();
                const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
                const dict = ADMIN_I18N[lang] || ADMIN_I18N.fa;
                if (accountEl) {
                    accountEl.value = data.cf_account_id || '';
                    accountEl.placeholder = data.cf_account_id
                        ? data.cf_account_id
                        : (dict.cf_ac_id_auto_hint || 'خودکار از توکن دریافت می‌شود');
                }
                if (tokenEl) tokenEl.value = '';
                if (hintEl) {
                    if (data.cf_token_set) {
                        hintEl.textContent = dict.cf_token_hint_set || 'توکن فعلی تنظیم شده — برای تغییر، توکن جدید وارد کنید';
                        hintEl.classList.remove('hidden');
                    } else {
                        hintEl.classList.add('hidden');
                        hintEl.textContent = '';
                    }
                }
            } catch (err) {}
        }
        async function saveCfCredentials() {
            const cfToken = (document.getElementById('cf-token-input') || {}).value || '';
            const errEl = document.getElementById('cf-creds-error');
            const btn = document.getElementById('cf-creds-save-btn');
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            const dict = ADMIN_I18N[lang] || ADMIN_I18N.fa;
            errEl.classList.add('hidden');
            errEl.textContent = '';
            if (!cfToken.trim()) {
                errEl.textContent = lang === 'en' ? 'Enter Cloudflare API Token' : 'توکن API کلودفلر را وارد کنید';
                errEl.classList.remove('hidden');
                return;
            }
            btn.disabled = true;
            btn.textContent = lang === 'en' ? 'Saving...' : 'در حال ذخیره...';
            try {
                const response = await fetch('/api/cf-credentials', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ cf_token: cfToken.trim() })
                });
                const data = await response.json();
                if (response.ok && data.success) {
                    showNexaToast(dict.cf_creds_success || 'توکن با موفقیت ذخیره شد');
                    await loadCfCredentialsForm();
                } else {
                    errEl.textContent = data.error || (lang === 'en' ? 'Save failed' : 'خطا در ذخیره');
                    errEl.classList.remove('hidden');
                }
            } catch (err) {
                errEl.textContent = lang === 'en' ? 'Connection error' : 'خطا در برقراری ارتباط با سرور';
                errEl.classList.remove('hidden');
            } finally {
                btn.disabled = false;
                btn.textContent = dict.cf_creds_save || 'ذخیره توکن';
            }
        }
        async function loadProxySettingsForm() {
            try {
                const statusRes = await fetch('/api/proxy-ip');
                if (statusRes.ok) {
                    const statusData = await statusRes.json();
                    const input = document.getElementById('proxy-ips-input');
                    if (input) {
                        if (statusData.proxy_ips && Array.isArray(statusData.proxy_ips)) {
                            input.value = statusData.proxy_ips.join('\\n');
                        } else if (statusData.proxy_ip) {
                            input.value = statusData.proxy_ip;
                        }
                    }
                }
            } catch (err) {}
        }
        let workerConfigDefaults = null;
        let workerConfigToggles = { skipCertVerify: false, randomPath: false, echEnabled: false, subEmoji: false };
        let networkSettingsState = {};
        let networkSettingsProfiles = {};
        let networkSettingsDefaults = {};
        const RESIST_TOGGLE_MAP = {
            enableDomesticBypass: 'resist-domestic-toggle',
            blockQUIC: 'resist-quic-toggle',
            enableAdBlock: 'resist-ad-toggle',
            enableMalwareBlock: 'resist-malware-toggle',
            enablePhishingBlock: 'resist-phishing-toggle',
            bypassSanctions: 'resist-sanctions-toggle',
            enableDoH: 'resist-doh-toggle',
            enableAntiSanctionDNS: 'resist-anti-sanction-toggle'
        };
        function setResistToggle(key, value) {
            const el = document.getElementById(RESIST_TOGGLE_MAP[key]);
            if (!el) return;
            el.classList.toggle('on', !!value);
            el.setAttribute('aria-checked', value ? 'true' : 'false');
        }
        function syncResistTogglesFromState() {
            Object.keys(RESIST_TOGGLE_MAP).forEach(function(key) {
                setResistToggle(key, !!networkSettingsState[key]);
            });
        }
        function toggleResistField(key) {
            networkSettingsState[key] = !networkSettingsState[key];
            setResistToggle(key, networkSettingsState[key]);
            const profileEl = document.getElementById('resist-profile');
            if (profileEl) profileEl.value = 'custom';
        }
        function applyResistanceProfile() {
            const profileEl = document.getElementById('resist-profile');
            if (!profileEl || profileEl.value === 'custom') return;
            const profile = networkSettingsProfiles[profileEl.value];
            if (!profile || !profile.settings) return;
            networkSettingsState = Object.assign({}, networkSettingsDefaults, profile.settings);
            syncResistTogglesFromState();
        }
        async function loadNetworkSettings() {
            try {
                const res = await fetch('/api/network-settings');
                if (!res.ok) return;
                const data = await res.json();
                networkSettingsDefaults = data.defaults || {};
                networkSettingsProfiles = data.profiles || {};
                networkSettingsState = Object.assign({}, networkSettingsDefaults, data.settings || {});
                syncResistTogglesFromState();
                const profileEl = document.getElementById('resist-profile');
                if (profileEl) {
                    let matched = 'custom';
                    for (const [id, profile] of Object.entries(networkSettingsProfiles)) {
                        if (!profile || !profile.settings) continue;
                        const keys = Object.keys(RESIST_TOGGLE_MAP);
                        const same = keys.every(function(k) { return !!networkSettingsState[k] === !!profile.settings[k]; });
                        if (same) { matched = id; break; }
                    }
                    profileEl.value = matched;
                }
            } catch (e) {}
        }
        async function saveNetworkSettings() {
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            const btn = document.getElementById('save-network-settings-btn');
            if (btn) { btn.disabled = true; btn.innerText = lang === 'en' ? 'Saving...' : 'در حال ذخیره...'; }
            try {
                const profileEl = document.getElementById('resist-profile');
                const profileId = profileEl ? profileEl.value : 'custom';
                const payload = Object.assign({}, networkSettingsState);
                if (profileId === 'iran_high' && networkSettingsProfiles.iran_high && networkSettingsProfiles.iran_high.settings) {
                    Object.assign(payload, networkSettingsProfiles.iran_high.settings);
                }
                const res = await fetch('/api/network-settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok) {
                    networkSettingsState = Object.assign({}, networkSettingsDefaults, data.settings || payload);
                    syncResistTogglesFromState();
                    showNexaToast(lang === 'en' ? 'Resistance policy saved' : 'سیاست مقاومت ذخیره شد');
                } else {
                    alert(data.error || (lang === 'en' ? 'Failed to save' : 'خطا در ذخیره'));
                }
            } catch (err) {
                alert(lang === 'en' ? 'Connection error' : 'خطا در برقراری ارتباط با سرور');
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.innerText = lang === 'en' ? 'Save resistance policy' : 'ذخیره سیاست مقاومت';
                }
            }
        }
        function cleanWorkerPagePath(value, fallback) {
            const seg = String(value || fallback || '').trim().toLowerCase().replace(new RegExp('^/+|/+$', 'g'), '').replace(/[^a-z0-9_-]/g, '').slice(0, 40);
            return seg || fallback;
        }
        function getWorkerPagePath(cfg, key, fallback) {
            const c = cfg || getPanelWorkerConfig();
            return cleanWorkerPagePath(c[key], fallback);
        }
        function resolveClientFingerprint(fp) {
            const val = String(fp || 'randomized').trim().toLowerCase();
            if (val && val !== 'random') return val;
            const fps = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge'];
            return fps[Math.floor(Math.random() * fps.length)];
        }
        function getClientTransportTypeParam(cfg) {
            const transport = cfg.transportProtocol || 'ws';
            if (transport === 'grpc') return cfg.gRPCmode === 'multi' ? 'grpc&mode=multi' : 'grpc&mode=gun';
            if (transport === 'xhttp') return 'xhttp&mode=stream-one';
            return 'ws';
        }
        function getClientTransportConfig(cfg) {
            const transport = cfg.transportProtocol || 'ws';
            const isGrpc = transport === 'grpc';
            return {
                typeParam: getClientTransportTypeParam(cfg),
                pathField: isGrpc ? 'serviceName' : 'path',
                hostField: isGrpc ? 'authority' : 'host'
            };
        }
        function getClientTlsFragmentParam(cfg) {
            if (cfg.tlsFragment === 'Shadowrocket') return '&fragment=' + encodeURIComponent('1,40-60,30-50,tlshello');
            if (cfg.tlsFragment === 'Happ') return '&fragment=' + encodeURIComponent('3,1,tlshello');
            return '';
        }
        function getClientEchParam(cfg) {
            if (!cfg.echEnabled) return '';
            const dns = cfg.echDns || 'https://dns.alidns.com/dns-query';
            const sni = cfg.echSni || '';
            return '&ech=' + encodeURIComponent((sni ? sni + '+' : '') + dns);
        }
        function buildClientNodeLink(cfg, user, ip, portStr, fp, remark, protoOverride, linkHost) {
            const host = linkHost || ip;
            const protocol = protoOverride || cfg.protocolType || 'vless';
            const resolvedFp = resolveClientFingerprint(fp);
            const pathVal = cfg.transportPath || '/in_config_foroshi_nist';
            const tc = getClientTransportConfig(cfg);
            const ech = getClientEchParam(cfg);
            const tlsPorts = ['443', '2053', '2083', '2087', '2096', '8443'];
            const noTlsPorts = ['80', '2052', '2082', '2086', '2095', '8080'];
            const isTlsPort = tlsPorts.includes(String(portStr));
            if (protocol === 'ss') {
                const enc = cfg.ssEncryption || 'aes-128-gcm';
                const ssPath = pathVal.replace(/([=,])/g, '\\\\$1');
                const plugin = 'ray-plugin;mode=websocket;host=' + host + ';path=' + ssPath + (isTlsPort ? ';tls' : '');
                return 'ss://' + btoa(enc + ':' + user.uuid) + '@' + ip + ':' + portStr + '?plugin=v2' + encodeURIComponent(plugin) + ech + (isTlsPort ? getClientTlsFragmentParam(cfg) : '') + '#' + encodeURIComponent(remark);
            }
            const tlsVal = isTlsPort ? 'tls' : 'none';
            const fragment = tlsVal === 'tls' ? getClientTlsFragmentParam(cfg) : '';
            const insecure = cfg.skipCertVerify ? '&insecure=1&allowInsecure=1' : '';
            if (!isTlsPort) {
                const mapped = noTlsPorts[tlsPorts.indexOf(Number(portStr))];
                const p = mapped != null ? String(mapped) : portStr;
                return protocol + '://' + user.uuid + '@' + ip + ':' + p + '?security=none&type=' + tc.typeParam + '&' + tc.hostField + '=' + host + '&' + tc.pathField + '=' + encodeURIComponent(pathVal) + '&encryption=none#' + encodeURIComponent(remark);
            }
            return protocol + '://' + user.uuid + '@' + ip + ':' + portStr + '?security=tls&type=' + tc.typeParam + ech + '&' + tc.hostField + '=' + host + '&fp=' + resolvedFp + '&sni=' + host + '&' + tc.pathField + '=' + encodeURIComponent(pathVal) + fragment + '&encryption=none' + insecure + '#' + encodeURIComponent(remark);
        }
        function setWorkerConfigField(id, value, defaultVal) {
            const el = document.getElementById(id);
            if (!el) return;
            const def = defaultVal != null ? String(defaultVal) : '';
            const val = value != null ? String(value) : '';
            if (val === def) {
                el.value = '';
                el.placeholder = def;
            } else {
                el.value = val;
                el.placeholder = def;
            }
        }
        function setWorkerToggle(id, key, value) {
            workerConfigToggles[key] = !!value;
            const el = document.getElementById(id);
            if (!el) return;
            el.classList.toggle('on', !!value);
            el.setAttribute('aria-checked', value ? 'true' : 'false');
        }
        function toggleWorkerSkipCert() { setWorkerToggle('wc-skip-cert-toggle', 'skipCertVerify', !workerConfigToggles.skipCertVerify); }
        function toggleWorkerRandomPath() { setWorkerToggle('wc-random-path-toggle', 'randomPath', !workerConfigToggles.randomPath); }
        function toggleWorkerEch() { setWorkerToggle('wc-ech-toggle', 'echEnabled', !workerConfigToggles.echEnabled); }
        function toggleWorkerSubEmoji() { setWorkerToggle('wc-sub-emoji-toggle', 'subEmoji', !workerConfigToggles.subEmoji); }
        function toggleWorkerGrpcFields() {
            const transport = (document.getElementById('wc-transport-protocol') || {}).value || 'ws';
            const section = document.getElementById('wc-grpc-mode-section');
            if (section) section.classList.toggle('hidden', transport !== 'grpc');
        }
        function getWorkerFieldValue(id, key) {
            const el = document.getElementById(id);
            if (!el) return workerConfigDefaults ? workerConfigDefaults[key] : '';
            const raw = String(el.value || '').trim();
            if (raw) return raw;
            return el.placeholder || (workerConfigDefaults ? workerConfigDefaults[key] : '');
        }
        function applyRemarkTemplateClient(template, user, now, extra) {
            now = now || Date.now();
            extra = extra || {};
            const usedStr = fmtRemarkVolume(user.used_gb || 0);
            const totalStr = user.limit_gb != null ? fmtRemarkVolume(user.limit_gb) : '∞';
            let dayremind = '∞';
            if (user.expiry_days) {
                if (user.created_at) {
                    const created = new Date(user.created_at);
                    const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
                    const diffDays = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
                    dayremind = (diffDays > 0 ? diffDays : 0) + ' روز';
                } else {
                    dayremind = user.expiry_days + ' روز';
                }
            }
            const vars = {
                username: user.username || '',
                dayremind: dayremind,
                used: usedStr,
                total: totalStr,
                expiry: user.expiry_days != null ? String(user.expiry_days) : '∞',
                port: extra.port != null ? String(extra.port) : ''
            };
            let result = String(template || '');
            Object.keys(vars).forEach(function(key) {
                result = result.split('{' + key + '}').join(vars[key]);
            });
            if (result.indexOf('dayremind') !== -1) result = result.replace(/dayremind/g, vars.dayremind);
            return result;
        }
        function getPanelWorkerConfig() {
            return window.panelWorkerConfig || workerConfigDefaults || {};
        }
        async function loadWorkerConfigForm() {
            try {
                const res = await fetch('/api/worker-config');
                if (!res.ok) return;
                const data = await res.json();
                workerConfigDefaults = data.defaults || {};
                window.panelWorkerConfig = data.settings || workerConfigDefaults;
                const cfg = window.panelWorkerConfig;
                const defs = workerConfigDefaults;
                const firstRemarkEl = document.getElementById('wc-first-remark');
                  if (firstRemarkEl) {
                      const _lang = localStorage.getItem('nexa-admin-lang') || 'fa';
                      firstRemarkEl.value = _lang === 'en'
                          ? '❌ This service is completely free ❌ '
                          : (data.lockedFirstRemark || buildFirstRemark());
                  }
                const protocolEl = document.getElementById('wc-protocol-type');
                if (protocolEl) protocolEl.value = cfg.protocolType || defs.protocolType || 'vless';
                const transportEl = document.getElementById('wc-transport-protocol');
                if (transportEl) transportEl.value = cfg.transportProtocol || defs.transportProtocol || 'ws';
                const grpcEl = document.getElementById('wc-grpc-mode');
                if (grpcEl) grpcEl.value = cfg.gRPCmode || defs.gRPCmode || 'gun';
                toggleWorkerGrpcFields();
                const fpEl = document.getElementById('wc-fingerprint');
                if (fpEl) fpEl.value = cfg.fingerprint || defs.fingerprint || 'random';
                const fragEl = document.getElementById('wc-tls-fragment');
                if (fragEl) fragEl.value = cfg.tlsFragment || defs.tlsFragment || '';
                setWorkerConfigField('wc-transport-path', cfg.transportPath, defs.transportPath);
                setWorkerConfigField('wc-ech-sni', cfg.echSni, defs.echSni);
                setWorkerConfigField('wc-ech-dns', cfg.echDns, defs.echDns);
                setWorkerConfigField('wc-central-api', cfg.centralApi, defs.centralApi);
                setWorkerConfigField('wc-sub-name', cfg.subName, defs.subName);
                setWorkerConfigField('wc-sub-update-hours', cfg.subUpdateHours, defs.subUpdateHours);
                setWorkerConfigField('wc-admin-page-path', cfg.adminPagePath, defs.adminPagePath);
                setWorkerConfigField('wc-status-page-path', cfg.statusPagePath, defs.statusPagePath);
                setWorkerConfigField('wc-sub-page-path', cfg.subPagePath, defs.subPagePath);
                setWorkerConfigField('wc-logs-page-path', cfg.logsPagePath, defs.logsPagePath);
                setWorkerConfigField('wc-sub-converter-api', cfg.subConverterApi, defs.subConverterApi);
                setWorkerConfigField('wc-sub-config-url', cfg.subConfigUrl, defs.subConfigUrl);
                setWorkerConfigField('wc-info-remark', cfg.infoRemarkTemplate, defs.infoRemarkTemplate);
                setWorkerConfigField('wc-node-remark', cfg.nodeRemarkTemplate, defs.nodeRemarkTemplate);
                setWorkerToggle('wc-skip-cert-toggle', 'skipCertVerify', !!cfg.skipCertVerify);
                setWorkerToggle('wc-random-path-toggle', 'randomPath', !!cfg.randomPath);
                setWorkerToggle('wc-ech-toggle', 'echEnabled', !!cfg.echEnabled);
                setWorkerToggle('wc-sub-emoji-toggle', 'subEmoji', !!cfg.subEmoji);
            } catch (e) {}
        }
        async function saveWorkerConfig() {
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            const btn = document.getElementById('save-worker-config-btn');
            if (btn) { btn.disabled = true; btn.innerText = lang === 'en' ? 'Saving...' : 'در حال ذخیره...'; }
            try {
                const payload = {
                    protocolType: getWorkerFieldValue('wc-protocol-type', 'protocolType'),
                    transportProtocol: getWorkerFieldValue('wc-transport-protocol', 'transportProtocol'),
                    gRPCmode: getWorkerFieldValue('wc-grpc-mode', 'gRPCmode'),
                    fingerprint: getWorkerFieldValue('wc-fingerprint', 'fingerprint'),
                    tlsFragment: getWorkerFieldValue('wc-tls-fragment', 'tlsFragment'),
                    transportPath: getWorkerFieldValue('wc-transport-path', 'transportPath'),
                    echSni: getWorkerFieldValue('wc-ech-sni', 'echSni'),
                    echDns: getWorkerFieldValue('wc-ech-dns', 'echDns'),
                    centralApi: getWorkerFieldValue('wc-central-api', 'centralApi'),
                    subName: getWorkerFieldValue('wc-sub-name', 'subName'),
                    subUpdateHours: Number(getWorkerFieldValue('wc-sub-update-hours', 'subUpdateHours')) || (workerConfigDefaults && workerConfigDefaults.subUpdateHours) || 3,
                    adminPagePath: getWorkerFieldValue('wc-admin-page-path', 'adminPagePath'),
                    statusPagePath: getWorkerFieldValue('wc-status-page-path', 'statusPagePath'),
                    subPagePath: getWorkerFieldValue('wc-sub-page-path', 'subPagePath'),
                    logsPagePath: getWorkerFieldValue('wc-logs-page-path', 'logsPagePath'),
                    subConverterApi: getWorkerFieldValue('wc-sub-converter-api', 'subConverterApi'),
                    subConfigUrl: getWorkerFieldValue('wc-sub-config-url', 'subConfigUrl'),
                    infoRemarkTemplate: getWorkerFieldValue('wc-info-remark', 'infoRemarkTemplate'),
                    nodeRemarkTemplate: getWorkerFieldValue('wc-node-remark', 'nodeRemarkTemplate'),
                    skipCertVerify: !!workerConfigToggles.skipCertVerify,
                    randomPath: !!workerConfigToggles.randomPath,
                    echEnabled: !!workerConfigToggles.echEnabled,
                    subEmoji: !!workerConfigToggles.subEmoji
                };
                const res = await fetch('/api/worker-config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok) {
                    window.panelWorkerConfig = data.settings || payload;
                    showNexaToast(lang === 'en' ? 'Worker settings saved' : 'تنظیمات ورکر ذخیره شد');
                    await loadWorkerConfigForm();
                    const newAdminPath = (data.settings && data.settings.adminPagePath) || 'admin';
                    const currentPathSeg = location.pathname.split('/').filter(Boolean).join('/');
                    const banner = document.getElementById('wc-admin-path-changed-banner');
                    if (banner && newAdminPath && newAdminPath !== currentPathSeg) {
                        const newUrl = location.origin + '/' + newAdminPath;
                        banner.classList.remove('hidden');
                        banner.textContent = (lang === 'en'
                            ? 'Admin panel address changed. New address: '
                            : 'آدرس پنل مدیریت تغییر کرد. آدرس جدید: ') + newUrl;
                        setTimeout(function() { window.location.href = newUrl; }, 2500);
                    } else if (banner) {
                        banner.classList.add('hidden');
                    }
                } else {
                    showNexaToast(data.error || (lang === 'en' ? 'Failed to save' : 'خطا در ذخیره'), 'error');
                }
            } catch (err) {
                alert(lang === 'en' ? 'Connection error' : 'خطا در برقراری ارتباط با سرور');
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.innerText = lang === 'en' ? 'Save worker settings' : 'ذخیره تنظیمات ';
                }
            }
        }
        async function changeAdminPassword() {
            const currentPassword = document.getElementById('pwd-current').value;
            const newPassword = document.getElementById('pwd-new').value;
            const confirmPassword = document.getElementById('pwd-confirm').value;
            const errEl = document.getElementById('pwd-change-error');
            const btn = document.getElementById('pwd-change-btn');
            errEl.classList.add('hidden');
            errEl.textContent = '';
            if (!currentPassword) {
                errEl.textContent = adminT('pwd_err_current_required');
                errEl.classList.remove('hidden');
                return;
            }
            if (!newPassword || newPassword.length < 4) {
                errEl.textContent = adminT('pwd_err_minlength');
                errEl.classList.remove('hidden');
                return;
            }
            if (newPassword !== confirmPassword) {
                errEl.textContent = adminT('pwd_err_mismatch');
                errEl.classList.remove('hidden');
                return;
            }
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            const dict = ADMIN_I18N[lang] || ADMIN_I18N.fa;
            btn.disabled = true;
            btn.textContent = lang === 'en' ? 'Saving...' : 'در حال ذخیره...';
            try {
                const response = await fetch('/api/change-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ currentPassword, newPassword, confirmPassword })
                });
                const data = await response.json();
                if (response.ok && data.success) {
                    document.getElementById('pwd-current').value = '';
                    document.getElementById('pwd-new').value = '';
                    document.getElementById('pwd-confirm').value = '';
                    showNexaToast(dict.pwd_change_success || 'رمز عبور با موفقیت تغییر کرد');
                } else {
                    errEl.textContent = data.error || adminT('pwd_err_generic');
                    errEl.classList.remove('hidden');
                }
            } catch (err) {
                errEl.textContent = adminT('toast_conn_error');
                errEl.classList.remove('hidden');
            } finally {
                btn.disabled = false;
                btn.textContent = dict.pwd_change_btn || 'تغییر رمز عبور';
            }
        }
        async function saveSettings() {
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            const dict = ADMIN_I18N[lang] || ADMIN_I18N.fa;
            const proxyIpsRaw = (document.getElementById('proxy-ips-input') || {}).value.trim();
            const btn = document.getElementById('save-settings-btn');
            btn.disabled = true;
            btn.innerText = lang === 'en' ? 'Saving...' : 'در حال ذخیره...';
            try {
                const payload = {
                    proxy_ips: proxyIpsRaw,
                    proxy_ip: proxyIpsRaw ? proxyIpsRaw.split('\\n')[0].trim() : ''
                };
                const response = await fetch('/api/proxy-ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await response.json();
                if (response.ok) {
                    const changeLabels = dict.proxy_change_labels || {};
                    let toastMsg = dict.proxy_save_base || 'تنظیمات Proxy IP ذخیره شد';
                    if (data.changes && data.changes.length) {
                        toastMsg += ' — ' + data.changes.map(k => changeLabels[k] || k).join('، ') + (lang === 'en' ? ' changed' : ' تغییر کرد');
                    } else {
                        toastMsg += lang === 'en' ? ' — no changes' : ' — بدون تغییر';
                    }
                    showNexaToast(toastMsg);
                    await loadPanelProxySettings();
                } else {
                    alert(lang === 'en' ? 'Failed to save settings' : 'خطا در ذخیره تنظیمات');
                }
            } catch (err) {
                alert(lang === 'en' ? 'Connection error' : 'خطا در برقراری ارتباط با سرور');
            } finally {
                btn.disabled = false;
                btn.innerText = dict.save || 'ذخیره تنظیمات';
            }
        }
        async function resetAllSettings() {
            const lang = localStorage.getItem('nexa-admin-lang') || 'fa';
            const dict = ADMIN_I18N[lang] || ADMIN_I18N.fa;
            if (!await showNexaConfirm(dict.reset_panel_confirm || 'با بازنشانی، تمام کاربران (به‌جز سرویس اصلی)، تنظیمات و لاگ‌ها حذف می‌شوند. این عمل قابل بازگشت نیست. ادامه می‌دهید؟', { title: dict.reset_panel_title || 'بازنشانی تمام تنظیمات', danger: true, confirmText: lang === 'en' ? 'Yes, reset' : 'بله، بازنشانی شود' })) return;
            const btn = document.getElementById('reset-panel-btn');
            const originalText = btn.textContent;
            btn.disabled = true;
            btn.textContent = lang === 'en' ? 'Resetting...' : 'در حال بازنشانی...';
            try {
                const res = await fetch('/api/reset-panel', { method: 'POST' });
                const result = await res.json();
                if (!res.ok) throw new Error(result.error || 'خطا در بازنشانی');
                showNexaToast(dict.reset_panel_success || 'پنل با موفقیت بازنشانی شد');
                await loadUsers(true);
                await loadProxySettingsForm();
                if (typeof loadBlockedDomainsForm === 'function') await loadBlockedDomainsForm();
                if (typeof loadAllServicesOff === 'function') await loadAllServicesOff();
                if (typeof loadDashboard === 'function') await loadDashboard(true);
                if (typeof loadTelegramNotify === 'function') await loadTelegramNotify();
                if (typeof loadAdminLogs === 'function') await loadAdminLogs();
            } catch (err) {
                showNexaToast(err.message || 'خطا در بازنشانی پنل', 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = originalText;
            }
        }
        async function logoutAdmin() {
            if (!await showNexaConfirm('آیا می‌خواهید از پنل خارج شوید؟', { title: 'خروج از پنل', confirmText: 'بله، خروج' })) return;
            try {
                await fetch('/api/logout', { method: 'POST' });
            } catch (err) {}
            window.location.reload();
        }
let cachedIpsData = {};
let ipScanBestResults = [];
let scannerPoolIps = [];
let cleanIpSourceMode = 'pool';
let cleanIpsUrl = '${REMOTE_CLEAN_IPS_URL}';
const IP_SERVER_OPERATOR_LABELS = {
    IR_CLOUD: 'آیپی ایران پشت کلود',
    MCI: 'همراه اول (MCI)',
    IRANCELL: 'ایرانسل',
    Rightel: 'رایتل / آپتل',
    Shatel: 'شاتل',
    ADSL: 'آسیاتک / ADSL',
    IR_DOMAINS: 'دامنه پشت کلودفلر'
};
const CF_SCAN_RANGES = [['104.16.',0,255],['104.17.',0,255],['104.18.',0,255],['104.19.',0,255],['104.20.',0,255],['104.21.',0,255],['104.22.',0,255],['104.24.',0,255],['104.25.',0,255],['104.26.',0,255],['104.27.',0,255],['162.159.',0,255],['172.64.',0,255],['172.66.',0,255],['172.67.',0,255],['188.114.',96,111],['141.101.',64,127]];
const CF_TLS_SCAN_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
function randCfScanIp() {
    const r = CF_SCAN_RANGES[Math.floor(Math.random() * CF_SCAN_RANGES.length)];
    const c = r[1] + Math.floor(Math.random() * (r[2] - r[1] + 1));
    return r[0] + c + '.' + Math.floor(Math.random() * 256);
}
function pingCfScanIp(ip, port, timeout) {
    return new Promise(function(res) {
        const t0 = performance.now();
        let done = false;
        const img = new Image();
        function fin(ok) {
            if (done) return;
            done = true;
            img.onerror = img.onload = null;
            res(ok ? Math.round(performance.now() - t0) : null);
        }
        const timer = setTimeout(function() { fin(false); }, timeout);
        img.onerror = function() { clearTimeout(timer); fin(true); };
        img.onload = function() { clearTimeout(timer); fin(true); };
        img.src = 'https://' + (port === 443 ? ip : ip + ':' + port) + '/cdn-cgi/trace?' + Math.random();
    });
}
function ipScanT(key, vars) {
    if (typeof adminT === 'function') return adminT(key, vars);
    return key;
}
function getIpScanSelectedPorts() {
    const ports = [];
    document.querySelectorAll('.ip-scan-port-cb:checked').forEach(function(cb) {
        ports.push(Number(cb.value));
    });
    return ports;
}
async function runCleanIpScanner() {
    const btn = document.getElementById('ip-scan-run-btn');
    const status = document.getElementById('ip-scan-status');
    const bar = document.getElementById('ip-scan-bar');
    const barFill = bar ? bar.querySelector('i') : null;
    const resultsPanel = document.getElementById('ip-scan-results-panel');
    const output = document.getElementById('ip-scan-output');
    const countEl = document.getElementById('ip-scan-results-count');
    if (!btn || !status || !bar || !barFill || !resultsPanel || !output) return;
    const ports = getIpScanSelectedPorts();
    if (!ports.length) {
        status.textContent = ipScanT('ip_scan_ports_required');
        return;
    }
    const totalTests = Math.min(400, Math.max(20, Number(document.getElementById('ip-scan-total')?.value) || 140));
    const timeout = 2000;
    const probes = 3;
    const conc = 12;
    btn.disabled = true;
    bar.style.display = 'block';
    barFill.style.width = '0%';
    resultsPanel.style.display = 'none';
    output.textContent = '';
    if (countEl) countEl.textContent = '';
    status.textContent = ipScanT('ip_scan_prep');
    const ipsNeeded = Math.ceil(totalTests / ports.length);
    const ips = [];
    const seen = {};
    try {
        const candRes = await fetch('/api/scanner-candidates');
        const candData = await candRes.json().catch(function() { return {}; });
        const candidates = Array.isArray(candData.ips) ? candData.ips : [];
        for (let ci = 0; ci < candidates.length && ips.length < ipsNeeded; ci++) {
            const ip = String(candidates[ci] || '').split(':')[0].trim();
            if (ip && !seen[ip]) { seen[ip] = 1; ips.push(ip); }
        }
    } catch (e) {}
    while (ips.length < ipsNeeded) {
        const ip = randCfScanIp();
        if (!seen[ip]) { seen[ip] = 1; ips.push(ip); }
    }
    const pairs = [];
    for (let a = 0; a < ips.length && pairs.length < totalTests; a++) {
        for (let pi = 0; pi < ports.length && pairs.length < totalTests; pi++) {
            pairs.push({ ip: ips[a], port: ports[pi] });
        }
    }
    const totalN = pairs.length;
    let tested = 0;
    const alive = [];
    async function worker() {
        while (pairs.length) {
            const pr = pairs.pop();
            const samples = [];
            for (let i = 0; i < probes; i++) {
                const ms = await pingCfScanIp(pr.ip, pr.port, timeout);
                if (ms != null) samples.push(ms);
            }
            tested++;
            if (samples.length) {
                const avg = Math.round(samples.reduce(function(a, b) { return a + b; }, 0) / samples.length);
                const jit = Math.round(Math.max.apply(null, samples) - Math.min.apply(null, samples));
                const loss = Math.round((1 - samples.length / probes) * 100);
                alive.push({ ip: pr.ip, port: pr.port, ms: avg, jit: jit, loss: loss, score: avg + jit * 0.5 + loss * 20 });
            }
            barFill.style.width = Math.max(3, Math.round(tested / totalN * 100)) + '%';
            status.textContent = ipScanT('ip_scan_testing') + tested + '/' + totalN + ' (' + alive.length + ipScanT('ip_scan_alive') + ')';
        }
    }
    const pool = [];
    for (let k = 0; k < conc; k++) pool.push(worker());
    await Promise.all(pool);
    alive.sort(function(a, b) { return a.score - b.score; });
    const byIp = {};
    alive.forEach(function(item) {
        if (!byIp[item.ip] || item.score < byIp[item.ip].score) byIp[item.ip] = item;
    });
    const uniqueSorted = Object.values(byIp).sort(function(a, b) { return a.score - b.score; });
    ipScanBestResults = uniqueSorted.map(function(item) { return item.ip; });
    barFill.style.width = '100%';
    setTimeout(function() { bar.style.display = 'none'; }, 500);
    btn.disabled = false;
    if (!ipScanBestResults.length) {
        status.textContent = ipScanT('ip_scan_none');
        return;
    }
    status.textContent = '✓ ' + ipScanBestResults.length + ipScanT('ip_scan_found');
    output.textContent = ipScanBestResults.join('\\n');
    if (countEl) countEl.textContent = ipScanBestResults.length + ' IP';
    resultsPanel.style.display = 'block';
    await autoSaveIpScanToPool();
}
async function autoSaveIpScanToPool() {
    if (!ipScanBestResults.length) return;
    try {
        const currentLines = readScannerPoolFromTextarea();
        const seen = new Set(currentLines);
        const appended = [];
        for (const ip of ipScanBestResults) {
            const val = String(ip || '').trim();
            if (!val || seen.has(val)) continue;
            seen.add(val);
            appended.push(val);
        }
        if (!appended.length) return;
        let text = currentLines.join('\\n');
        if (text) text += '\\n';
        text += appended.join('\\n');
        scannerPoolIps = text.split('\\n').map(function(s) { return s.trim(); }).filter(Boolean).slice(0, 50);
        renderScannerPoolList();
        const res = await fetch('/api/scanner-pool', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ips: scannerPoolIps.join('\\n'), merge: false })
        });
        const data = await res.json().catch(function() { return {}; });
        if (!res.ok || !data.success) throw new Error(data.error || 'save failed');
        scannerPoolIps = Array.isArray(data.ips) ? data.ips.slice() : scannerPoolIps;
        renderScannerPoolList();
        const addedCount = appended.length;
        const status = document.getElementById('ip-scan-status');
        if (status) status.textContent = '✓ ' + ipScanT('ip_scan_auto_saved') + ' (' + addedCount + ')';
        if (typeof showNexaToast === 'function') showNexaToast(ipScanT('ip_scan_auto_saved') + ' (' + addedCount + ')');
    } catch (e) {
        const status = document.getElementById('ip-scan-status');
        if (status) status.textContent = ipScanT('ip_scan_save_pool') + ': ' + (e.message || 'error');
    }
}
function renderCleanIpSourceView() {
    const smartView = document.getElementById('ip-source-smart-view');
    const poolView = document.getElementById('ip-source-pool-view');
    const tabSmart = document.getElementById('ip-source-tab-smart');
    const tabPool = document.getElementById('ip-source-tab-pool');
    const isPool = cleanIpSourceMode === 'pool';
    if (smartView) smartView.classList.toggle('hidden', isPool);
    if (poolView) poolView.classList.toggle('hidden', !isPool);
    if (tabSmart) tabSmart.classList.toggle('active', !isPool);
    if (tabPool) tabPool.classList.toggle('active', isPool);
    const link = document.getElementById('ip-smart-url-link');
    if (link) {
        link.textContent = cleanIpsUrl || '${REMOTE_CLEAN_IPS_URL}';
    }
}
async function setCleanIpSourceMode(mode) {
    const next = mode === 'pool' ? 'pool' : 'smart';
    cleanIpSourceMode = next;
    renderCleanIpSourceView();
    try {
        await fetch('/api/scanner-pool', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source_mode: next })
        });
    } catch (e) {}
}
async function loadScannerPoolPanel() {
    try {
        const res = await fetch('/api/scanner-pool');
        const data = await res.json().catch(function() { return {}; });
        scannerPoolIps = Array.isArray(data.ips) ? data.ips.slice() : [];
        cleanIpSourceMode = data.source_mode === 'pool' ? 'pool' : 'smart';
        cleanIpsUrl = data.clean_ips_url || '${REMOTE_CLEAN_IPS_URL}';
        renderScannerPoolList();
        renderCleanIpSourceView();
    } catch (e) {
        scannerPoolIps = [];
        renderScannerPoolList();
        renderCleanIpSourceView();
    }
}
function readScannerPoolFromTextarea() {
    const textarea = document.getElementById('ip-pool-textarea');
    if (!textarea) return scannerPoolIps.slice();
    return String(textarea.value || '').split(/\\r?\\n/).map(function(s) { return s.trim(); }).filter(Boolean);
}
function updateScannerPoolCount() {
    const countEl = document.getElementById('ip-pool-count');
    const lines = readScannerPoolFromTextarea();
    if (countEl) countEl.textContent = lines.length ? lines.length + ' IP' : '';
}
function renderScannerPoolList() {
    const textarea = document.getElementById('ip-pool-textarea');
    const countEl = document.getElementById('ip-pool-count');
    if (textarea && document.activeElement !== textarea) {
        textarea.value = scannerPoolIps.join('\\n');
    }
    if (countEl) countEl.textContent = scannerPoolIps.length ? scannerPoolIps.length + ' IP' : '';
}
async function saveScannerPool() {
    try {
        const lines = readScannerPoolFromTextarea();
        if (lines.length > 50) {
            alert(ipScanT('ip_scan_pool_max'));
            return;
        }
        const res = await fetch('/api/scanner-pool', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ips: lines.join('\\n'), merge: false, source_mode: 'pool' })
        });
        const data = await res.json().catch(function() { return {}; });
        if (!res.ok || !data.success) throw new Error(data.error || 'save failed');
        scannerPoolIps = Array.isArray(data.ips) ? data.ips.slice() : lines;
        cleanIpSourceMode = data.source_mode === 'pool' ? 'pool' : cleanIpSourceMode;
        renderScannerPoolList();
        renderCleanIpSourceView();
        if (typeof showNexaToast === 'function') showNexaToast(ipScanT('ip_scan_pool_saved') + ' (' + scannerPoolIps.length + ')');
    } catch (e) {
        alert(ipScanT('ip_scan_pool_save') + ': ' + (e.message || 'error'));
    }
}
async function clearScannerPool() {
    const lines = readScannerPoolFromTextarea();
    if (!lines.length) return;
    if (!confirm(ipScanT('ip_scan_pool_clear_confirm'))) return;
    try {
        const res = await fetch('/api/scanner-pool', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ips: '', merge: false })
        });
        const data = await res.json().catch(function() { return {}; });
        if (!res.ok || !data.success) throw new Error(data.error || 'clear failed');
        scannerPoolIps = [];
        renderScannerPoolList();
        if (typeof showNexaToast === 'function') showNexaToast(ipScanT('ip_scan_pool_cleared'));
    } catch (e) {
        alert(ipScanT('ip_scan_pool_clear') + ': ' + (e.message || 'error'));
    }
}
async function loadScannerPoolInfo() {
    await loadScannerPoolPanel();
}
function populateServerCleanIpSelect() {
    const select = document.getElementById('ip-server-operator');
    if (!select) return;
    const order = ['IR_DOMAINS', 'IR_CLOUD', 'MCI', 'IRANCELL', 'Rightel', 'Shatel', 'ADSL'];
    const prev = select.value;
    select.innerHTML = '<option value="all">' + ipScanT('ip_scan_server_all') + '</option>';
    const keys = [...new Set([...order, ...Object.keys(cachedIpsData)])];
    keys.forEach(function(op) {
        if (!cachedIpsData[op]?.length) return;
        const option = document.createElement('option');
        option.value = op;
        option.textContent = IP_SERVER_OPERATOR_LABELS[op] || op;
        select.appendChild(option);
    });
    if (prev && select.querySelector('option[value="' + prev + '"]')) select.value = prev;
}
function renderServerCleanIps() {
    const select = document.getElementById('ip-server-operator');
    const output = document.getElementById('ip-server-output');
    const countEl = document.getElementById('ip-server-count');
    if (!select || !output) return;
    const operator = select.value || 'all';
    let ips = [];
    if (operator === 'all') {
        Object.values(cachedIpsData).forEach(function(list) {
            if (Array.isArray(list)) ips = ips.concat(list);
        });
        ips = [...new Set(ips)];
    } else {
        ips = Array.isArray(cachedIpsData[operator]) ? cachedIpsData[operator].slice() : [];
    }
    output.textContent = ips.length ? ips.join('\\n') : ipScanT('ip_scan_server_empty');
    if (countEl) countEl.textContent = ips.length ? ips.length + ' IP' : '';
}
async function loadServerCleanIps(refresh) {
    const output = document.getElementById('ip-server-output');
    if (output) output.textContent = ipScanT('ip_scan_server_loading');
    try {
        const url = '/api/clean-ips' + (refresh ? '?refresh=1&_=' + Date.now() : '');
        const res = await fetch(url);
        if (!res.ok) throw new Error('fetch failed');
        cachedIpsData = await res.json();
        populateServerCleanIpSelect();
        renderServerCleanIps();
    } catch (e) {
        if (output) output.textContent = ipScanT('ip_scan_server_empty');
        const countEl = document.getElementById('ip-server-count');
        if (countEl) countEl.textContent = '';
    }
}
function copyServerCleanIps() {
    const output = document.getElementById('ip-server-output');
    if (!output || !output.textContent || output.textContent === ipScanT('ip_scan_server_empty') || output.textContent === ipScanT('ip_scan_server_loading')) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(output.textContent).then(function() {
            if (typeof showNexaToast === 'function') showNexaToast(ipScanT('ip_scan_copied'));
        }).catch(function() {});
    }
}
async function saveIpScanToPool() {
    return autoSaveIpScanToPool();
}
async function applyScannerPoolIps(targetId) {
    const fieldId = targetId || window.ipSelectorTargetId || 'input-ips';
    const field = document.getElementById(fieldId);
    if (!field) return;
    try {
        const res = await fetch('/api/scanner-pool');
        const data = await res.json().catch(function() { return {}; });
        if (!res.ok) throw new Error(data.error || 'fetch failed');
        const ips = Array.isArray(data.ips) ? data.ips : [];
        if (!ips.length) {
            alert(ipScanT('ip_scan_pool_empty'));
            return;
        }
        field.value = ips.join('\\n');
        field.dispatchEvent(new Event('input', { bubbles: true }));
        if (typeof showNexaToast === 'function') {
            showNexaToast(ipScanT('ip_scan_pool_applied') + ' (' + ips.length + ')');
        }
    } catch (e) {
        alert(ipScanT('um_scanner_pool') + ': ' + (e.message || 'error'));
    }
}
window.runCleanIpScanner = runCleanIpScanner;
window.autoSaveIpScanToPool = autoSaveIpScanToPool;
window.saveIpScanToPool = saveIpScanToPool;
window.setCleanIpSourceMode = setCleanIpSourceMode;
window.applyScannerPoolIps = applyScannerPoolIps;
window.loadScannerPoolInfo = loadScannerPoolInfo;
window.loadScannerPoolPanel = loadScannerPoolPanel;
window.updateScannerPoolCount = updateScannerPoolCount;
window.saveScannerPool = saveScannerPool;
window.clearScannerPool = clearScannerPool;
let cdnProxyPublicByCountry = {};
let cdnProxyPublicAll = [];
let cdnProxyPublicCountryCounts = {};
function cdnProxyT(key) {
    if (typeof adminT === 'function') return adminT(key);
    return key;
}
function cdnProxySetMsg(id, text, kind) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text || '';
    el.classList.remove('ok', 'bad', 'info');
    if (kind) el.classList.add(kind);
}
function cdnProxyApplyMode() {
    const modeEl = document.getElementById('cdn-proxy-mode');
    const mode = modeEl ? modeEl.value : 'proxyip';
    const secProxy = document.getElementById('cdn-sec-proxyip');
    const secChain = document.getElementById('cdn-sec-chain');
    const isProxyIp = mode === 'proxyip';
    if (secProxy) secProxy.classList.toggle('hidden', !isProxyIp);
    if (secChain) secChain.classList.toggle('hidden', isProxyIp);
}
async function loadCdnProxySettingsForm() {
    try {
        const res = await fetch('/api/proxy-ip');
        if (!res.ok) return;
        const data = await res.json();
        const modeEl = document.getElementById('cdn-proxy-mode');
        if (modeEl && data.mode) modeEl.value = data.mode;
        const proxyIpInput = document.getElementById('cdn-proxyip-input');
        if (proxyIpInput) {
            if (data.proxy_ips && data.proxy_ips.length) proxyIpInput.value = data.proxy_ips.join('\\n');
            else proxyIpInput.value = data.proxy_ip || 'auto';
        }
        const chainInput = document.getElementById('cdn-chain-input');
        if (chainInput) chainInput.value = data.chain_proxy || '';
        const rotateEvery = document.getElementById('cdn-rotate-every');
        if (rotateEvery) rotateEvery.value = data.socks5_rotate_every || '';
        const rotateCount = document.getElementById('cdn-rotate-count');
        if (rotateCount) rotateCount.value = data.socks5_rotate_count || 3;
        cdnProxyApplyMode();
    } catch (e) {}
}
async function saveCdnProxySettings() {
    const modeEl = document.getElementById('cdn-proxy-mode');
    const mode = modeEl ? modeEl.value : 'proxyip';
    const payload = { mode: mode };
    if (mode === 'proxyip') {
        const val = (document.getElementById('cdn-proxyip-input') || {}).value.trim() || 'auto';
        payload.proxy_ip = val;
    } else {
        payload.chain_proxy = (document.getElementById('cdn-chain-input') || {}).value.trim();
        payload.socks5_rotate_every = (document.getElementById('cdn-rotate-every') || {}).value || '';
        payload.socks5_rotate_count = Number((document.getElementById('cdn-rotate-count') || {}).value) || 3;
    }
    const btn = document.getElementById('save-cdn-proxy-btn');
    if (btn) btn.disabled = true;
    try {
        const res = await fetch('/api/proxy-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json().catch(function() { return {}; });
        if (!res.ok) throw new Error(data.error || 'save failed');
        cdnProxySetMsg('cdn-proxy-msg', cdnProxyT('cdn_proxy_saved'), 'ok');
        if (typeof showNexaToast === 'function') showNexaToast(cdnProxyT('cdn_proxy_saved'));
        await loadPanelProxySettings();

    } catch (e) {
        cdnProxySetMsg('cdn-proxy-msg', e.message || 'error', 'bad');
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function verifyCdnProxySettings() {
    const modeEl = document.getElementById('cdn-proxy-mode');
    const mode = modeEl ? modeEl.value : 'proxyip';
    if (mode === 'proxyip') {
        cdnProxySetMsg('cdn-proxy-msg', cdnProxyT('cdn_proxy_verify_proxyip'), 'info');
        return;
    }
    const val = (document.getElementById('cdn-chain-input') || {}).value.trim();
    if (!val) {
        cdnProxySetMsg('cdn-proxy-msg', cdnProxyT('cdn_proxy_enter_first'), 'bad');
        return;
    }
    const first = val.split(/[\\r\\n]+/).map(function(s) { return s.trim(); }).filter(Boolean)[0] || '';
    const btn = document.getElementById('cdn-proxy-verify-btn');
    if (btn) btn.disabled = true;
    try {
        const res = await fetch('/api/proxy-check?' + encodeURIComponent(mode) + '=' + encodeURIComponent(first));
        const data = await res.json().catch(function() { return {}; });
        if (data.success) cdnProxySetMsg('cdn-proxy-msg', data.message || cdnProxyT('cdn_proxy_verify_ok'), 'ok');
        else cdnProxySetMsg('cdn-proxy-msg', data.error || data.message || cdnProxyT('cdn_proxy_verify_fail'), 'bad');
    } catch (e) {
        cdnProxySetMsg('cdn-proxy-msg', cdnProxyT('cdn_proxy_verify_fail'), 'bad');
    } finally {
        if (btn) btn.disabled = false;
    }
}
function cdnProxyPublicListUrl(mode) {
    if (mode === 'proxyip') return 'https://cdn.jsdelivr.net/gh/IRNova/Tools@main/all.json';
    if (mode === 'http') return 'https://cdn.jsdelivr.net/gh/proxifly/proxifly@main/proxies/protocols/http/data.json';
    if (mode === 'https') return 'https://cdn.jsdelivr.net/gh/proxifly/proxifly@main/proxies/protocols/https/data.json';
    if (mode === 'socks5') return 'https://cdn.jsdelivr.net/gh/proxifly/proxifly@main/proxies/protocols/socks5/data.json';
    return '';
}
function cdnProxyFormatListStats(proxyCount, countryCount) {
    return cdnProxyT('cdn_proxy_list_stats')
        .replace('{proxies}', String(proxyCount))
        .replace('{countries}', String(countryCount));
}
function cdnProxyNormalizeProxyIpEntry(item) {
    if (!item || !item.ip) return null;
    const meta = item.meta || {};
    const country = meta.country || '';
    const city = meta.city || '';
    const value = String(item.ip).replace(/:\d+$/, '');
    let label = value;
    if (city && country) label = city + ' - (' + country + ') ' + value;
    else if (country) label = value + ' (' + country + ')';
    else if (city) label = city + ' - ' + value;
    return { label: label, value: value, country: country, city: city };
}
function cdnProxyNormalizePublicEntry(item, mode) {
    if (!item) return null;
    if (typeof item === 'string') return { label: item, value: item, country: '' };
    const host = item.ip || item.host || item.hostname || '';
    const port = item.port || (mode === 'https' ? 443 : mode === 'http' ? 80 : 1080);
    if (!host) return null;
    const value = host + ':' + port;
    const country = item.country || item.geo || (item.meta && item.meta.country) || '';
    return { label: value + (country ? ' (' + country + ')' : ''), value: value, country: country };
}
async function cdnProxyFetchPublicListJson(mode) {
    const url = cdnProxyPublicListUrl(mode);
    if (url) {
        try {
            const res = await fetch(url);
            if (res.ok) return res.json();
        } catch (e) {}
    }
    const apiRes = await fetch('/api/proxy-public-list?mode=' + encodeURIComponent(mode));
    if (!apiRes.ok) throw new Error('fetch failed');
    const apiJson = await apiRes.json().catch(function() { return {}; });
    if (!apiJson.success || !apiJson.data) throw new Error(apiJson.error || 'fetch failed');
    return apiJson.data;
}
function cdnProxyUpdateUseBtn() {
    const pickSel = document.getElementById('cdn-proxy-pick');
    const useBtn = document.getElementById('cdn-proxy-use-btn');
    if (!useBtn) return;
    useBtn.disabled = !(pickSel && pickSel.value);
}
function cdnProxyFlagEmoji(countryCode) {
    const code = String(countryCode || '').trim().toUpperCase();
    if (!code || code.length !== 2) return '🌐';
    try {
        const codePoints = code.split('').map(function(ch) { return 127397 + ch.charCodeAt(0); });
        return String.fromCodePoint.apply(String, codePoints);
    } catch (e) {
        return '🌐';
    }
}
function cdnProxyCountryName(countryCode) {
    const code = String(countryCode || '').trim().toUpperCase();
    if (!code) return '';
    if (code === 'OTHER') return (localStorage.getItem('nexa-admin-lang') || 'fa') === 'fa' ? 'سایر' : 'Other';
    try {
        const lang = (localStorage.getItem('nexa-admin-lang') || 'fa') === 'fa' ? 'fa' : 'en';
        const dn = new Intl.DisplayNames([lang], { type: 'region' });
        return dn.of(code) || code;
    } catch (e) {
        return code;
    }
}
function cdnProxyFillCountrySelect(countrySel, countsMap) {
    if (!countrySel) return;
    countrySel.innerHTML = '<option value="">-</option>';
    const keys = Object.keys(countsMap || {}).sort(function(a, b) {
        return cdnProxyCountryName(a).localeCompare(cdnProxyCountryName(b), localStorage.getItem('nexa-admin-lang') || 'fa');
    });
    keys.forEach(function(cc) {
        const opt = document.createElement('option');
        opt.value = cc;
        const name = cdnProxyCountryName(cc);
        const flag = cdnProxyFlagEmoji(cc);
        opt.textContent = name + ' ' + flag + ' (' + countsMap[cc] + ')';
        countrySel.appendChild(opt);
    });
}
function cdnProxyBuildCountryGroups(entries) {
    const byCountry = {};
    entries.forEach(function(entry) {
        const cc = String(entry.country || 'OTHER').trim() || 'OTHER';
        if (!byCountry[cc]) byCountry[cc] = [];
        byCountry[cc].push(entry);
    });
    return byCountry;
}
async function loadCdnProxyPublicList() {
    const modeEl = document.getElementById('cdn-proxy-mode');
    const mode = modeEl ? modeEl.value : 'proxyip';
    const btn = document.getElementById('cdn-proxy-list-btn');
    const countrySel = document.getElementById('cdn-proxy-country');
    cdnProxySetMsg('cdn-proxy-more-msg', cdnProxyT('cdn_proxy_fetching'), 'info');
    if (btn) btn.disabled = true;
    cdnProxyPublicByCountry = {};
    cdnProxyPublicAll = [];
    cdnProxyPublicCountryCounts = {};
    try {
        const json = await cdnProxyFetchPublicListJson(mode);
        let totalProxies = 0;
        let countryCount = 0;
        if (mode === 'proxyip') {
            const arr = Array.isArray(json.data) ? json.data : [];
            const seenIps = new Set();
            cdnProxyPublicAll = arr.map(function(item) { return cdnProxyNormalizeProxyIpEntry(item); }).filter(function(entry) {
                if (!entry) return false;
                if (seenIps.has(entry.value)) return false;
                seenIps.add(entry.value);
                return true;
            });
            cdnProxyPublicByCountry = cdnProxyBuildCountryGroups(cdnProxyPublicAll);
            cdnProxyPublicCountryCounts = (json.list && json.list.country) ? json.list.country : {};
            if (!Object.keys(cdnProxyPublicCountryCounts).length) {
                Object.keys(cdnProxyPublicByCountry).forEach(function(cc) {
                    cdnProxyPublicCountryCounts[cc] = cdnProxyPublicByCountry[cc].length;
                });
            }
            totalProxies = (json.list && json.list.ips) || cdnProxyPublicAll.length;
            countryCount = Object.keys(cdnProxyPublicCountryCounts).length;
            cdnProxyFillCountrySelect(countrySel, cdnProxyPublicCountryCounts);
        } else {
            const arr = Array.isArray(json) ? json : (Array.isArray(json.proxies) ? json.proxies : []);
            cdnProxyPublicAll = arr.map(function(item) { return cdnProxyNormalizePublicEntry(item, mode); }).filter(Boolean);
            cdnProxyPublicByCountry = cdnProxyBuildCountryGroups(cdnProxyPublicAll);
            cdnProxyPublicCountryCounts = {};
            Object.keys(cdnProxyPublicByCountry).forEach(function(cc) {
                cdnProxyPublicCountryCounts[cc] = cdnProxyPublicByCountry[cc].length;
            });
            totalProxies = cdnProxyPublicAll.length;
            countryCount = Object.keys(cdnProxyPublicCountryCounts).length;
            cdnProxyFillCountrySelect(countrySel, cdnProxyPublicCountryCounts);
        }
        cdnProxyCountryChange();
        cdnProxyUpdateUseBtn();
        cdnProxySetMsg('cdn-proxy-more-msg', '✓ ' + cdnProxyFormatListStats(totalProxies, countryCount), 'ok');
    } catch (e) {
        cdnProxySetMsg('cdn-proxy-more-msg', cdnProxyT('cdn_proxy_verify_fail'), 'bad');
    } finally {
        if (btn) btn.disabled = false;
    }
}
function cdnProxyCountryChange() {
    const countrySel = document.getElementById('cdn-proxy-country');
    const pickSel = document.getElementById('cdn-proxy-pick');
    if (!pickSel) return;
    const cc = countrySel ? countrySel.value : '';
    const list = cc && cdnProxyPublicByCountry[cc] ? cdnProxyPublicByCountry[cc] : cdnProxyPublicAll;
    pickSel.innerHTML = '<option value="">-</option>';
    list.slice(0, 500).forEach(function(entry) {
        const opt = document.createElement('option');
        opt.value = entry.value;
        opt.textContent = entry.label;
        pickSel.appendChild(opt);
    });
    cdnProxyUpdateUseBtn();
}
function useCdnProxySelection() {
    const pickSel = document.getElementById('cdn-proxy-pick');
    const val = pickSel ? pickSel.value : '';
    if (!val) return;
    const modeEl = document.getElementById('cdn-proxy-mode');
    const mode = modeEl ? modeEl.value : 'proxyip';
    if (mode === 'proxyip') {
        const input = document.getElementById('cdn-proxyip-input');
        if (input) input.value = val;
    } else {
        const input = document.getElementById('cdn-chain-input');
        if (input) {
            const lines = String(input.value || '').split(/[\\r\\n]+/).map(function(s) { return s.trim(); }).filter(Boolean);
            if (lines.indexOf(val) === -1) lines.unshift(val);
            input.value = lines.join('\\n');
        }
    }
    cdnProxySetMsg('cdn-proxy-more-msg', cdnProxyT('cdn_proxy_use_ok'), 'ok');
}
function dismissCdnCfBanner() {
    localStorage.setItem('nexa-cdn-cf-banner-dismissed', '1');
    const banner = document.getElementById('cdn-cf-token-banner');
    if (banner) banner.classList.add('hidden');
}
async function updateCdnCfBanner() {
    const banner = document.getElementById('cdn-cf-token-banner');
    if (!banner) return;
    if (localStorage.getItem('nexa-cdn-cf-banner-dismissed') === '1') {
        banner.classList.add('hidden');
        return;
    }
    try {
        const res = await fetch('/api/cf-credentials');
        if (!res.ok) return;
        const data = await res.json();
        banner.classList.toggle('hidden', !!(data.cf_token_set));
    } catch (e) {}
}
window.loadCdnProxySettingsForm = loadCdnProxySettingsForm;
window.cdnProxyApplyMode = cdnProxyApplyMode;
window.saveCdnProxySettings = saveCdnProxySettings;
window.verifyCdnProxySettings = verifyCdnProxySettings;
window.loadCdnProxyPublicList = loadCdnProxyPublicList;
window.cdnProxyCountryChange = cdnProxyCountryChange;
window.cdnProxyUpdateUseBtn = cdnProxyUpdateUseBtn;
window.useCdnProxySelection = useCdnProxySelection;
window.dismissCdnCfBanner = dismissCdnCfBanner;
window.updateCdnCfBanner = updateCdnCfBanner;
async function fetchIpsList() {
    try {
        const res = await fetch('/api/clean-ips');
        if (!res.ok) throw new Error('Failed to load IP list');
        cachedIpsData = await res.json();
        populateIpSelect();
    } catch (err) {
        alert('خطا در بارگذاری لیست IP.');
        toggleIpSelectorModal(false);
    }
}
function populateIpSelect() {
    const labels = {
        IR_CLOUD: 'آیپی ایران پشت کلود',
        MCI: 'همراه اول (MCI)',
        IRANCELL: 'ایرانسل',
        Rightel: 'رایتل / آپتل',
        Shatel: 'شاتل',
        ADSL: 'آسیاتک / ADSL',
        IR_DOMAINS: 'دامنه پشت کلودفلر'
    };
    const order = ['IR_DOMAINS', 'IR_CLOUD', 'MCI', 'IRANCELL', 'Rightel', 'Shatel', 'ADSL'];
    const select = document.getElementById('ip-operator-select');
    select.innerHTML = '<option value="all">همه</option>';
    const keys = [...new Set([...order, ...Object.keys(cachedIpsData)])];
    keys.forEach(op => {
        if (!cachedIpsData[op]?.length) return;
        const option = document.createElement('option');
        option.value = op;
        option.textContent = labels[op] || op;
        select.appendChild(option);
    });
}
function toggleIpSelectorModal(show) {
    const modal = document.getElementById('ip-selector-modal');
    const card = modal.querySelector('div');
    if (show) {
        modal.classList.remove('opacity-0', 'pointer-events-none');
        modal.classList.add('opacity-100', 'pointer-events-auto');
        card.classList.remove('opacity-0', 'scale-95');
        card.classList.add('opacity-100', 'scale-100');
    } else {
        modal.classList.remove('opacity-100', 'pointer-events-auto');
        modal.classList.add('opacity-0', 'pointer-events-none');
        card.classList.remove('opacity-100', 'scale-100');
        card.classList.add('opacity-0', 'scale-95');
    }
}
async function openIpSelectorModal(targetId) {
    window.ipSelectorTargetId = targetId || 'input-ips';
    toggleIpSelectorModal(true);
    document.getElementById('ip-loading-state').classList.remove('hidden');
    document.getElementById('ip-selection-form').classList.add('hidden');
    await fetchIpsList();
    document.getElementById('ip-loading-state').classList.add('hidden');
    document.getElementById('ip-selection-form').classList.remove('hidden');
}
function applySelectedIps() {
    const operator = document.getElementById('ip-operator-select').value;
    let count = parseInt(document.getElementById('ip-count-input').value, 10);
    if (isNaN(count) || count < 1) count = 10;
    let availableIps = [];
    if (operator === 'all') {
        Object.values(cachedIpsData).forEach(ips => {
            availableIps = availableIps.concat(ips);
        });
    } else {
        availableIps = cachedIpsData[operator] || [];
    }
    availableIps = [...new Set(availableIps)];
    let selectedIps = [];
    if (count >= availableIps.length) {
        selectedIps = availableIps;
    } else {
        const shuffled = availableIps.slice();
        for (let i = shuffled.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        }
        selectedIps = shuffled.slice(0, count);
    }
    selectedIps = selectedIps.map(function(entry) {
        const trimmed = String(entry || '').trim();
        const hashIdx = trimmed.indexOf('#');
        return hashIdx >= 0 ? trimmed.slice(0, hashIdx).trim() : trimmed;
    }).filter(Boolean);
    const targetField = document.getElementById(window.ipSelectorTargetId || 'input-ips');
    const existingLines = String(targetField.value || '').split('\\n').map(function(s) { return s.trim(); }).filter(Boolean);
    const mergedSet = new Set(existingLines);
    selectedIps.forEach(function(ip) { mergedSet.add(ip); });
    targetField.value = Array.from(mergedSet).join('\\n');
    toggleIpSelectorModal(false);
}
        let panelUpdateCheckRunning = false;
        let panelUpdateInProgress = false;
        window.panelKillxray = false;
        window.panelUpdateStatus = null;
        function showAnnounceBanner(text) {
            renderAnnounceBanner('adm-announce-banner', 'adm-announce-body', text);
        }
        function showUpdateOverlay(title, message, showSpinner, showActions) {
            const overlay = document.getElementById('adm-update-overlay');
            const titleEl = document.getElementById('adm-update-overlay-title');
            const msgEl = document.getElementById('adm-update-overlay-msg');
            const spinner = document.getElementById('adm-update-spinner');
            const actions = document.getElementById('adm-update-actions');
            if (!overlay) return;
            if (titleEl) titleEl.textContent = title || adminT('update_title');
            if (msgEl) msgEl.textContent = message || '';
            if (spinner) spinner.style.display = showSpinner === false ? 'none' : 'block';
            if (actions) actions.classList.toggle('show', !!showActions);
            overlay.classList.add('show');
            overlay.setAttribute('aria-hidden', 'false');
        }
        function hideUpdateOverlay() {
            const overlay = document.getElementById('adm-update-overlay');
            const actions = document.getElementById('adm-update-actions');
            if (!overlay) return;
            overlay.classList.remove('show');
            overlay.setAttribute('aria-hidden', 'true');
            if (actions) actions.classList.remove('show');
        }
        function updatePanelUpdateUI(data) {
            window.panelUpdateStatus = data || {};
            const remoteEl = document.getElementById('panel-update-remote-ver');
            const statusEl = document.getElementById('panel-update-status');
            const badge = document.getElementById('adm-nav-update-badge');
            if (!remoteEl) return;
            const remote = data.remoteVersion || '—';
            remoteEl.textContent = remote;
            if (badge) badge.style.display = data.updateAvailable ? 'inline-flex' : 'none';
            if (statusEl) {
                if (data.updateAvailable) {
                    statusEl.textContent = adminT('panel_update_available', { current: data.panelVersion || '', remote: data.remoteVersion || '' });
                    statusEl.style.color = 'var(--admin-primary)';
                } else if (data.error) {
                    statusEl.textContent = data.error;
                    statusEl.style.color = 'var(--admin-muted)';
                } else {
                    statusEl.textContent = adminT('panel_update_latest');
                    statusEl.style.color = 'var(--admin-muted)';
                }
            }
        }
        function showUpdateAvailablePrompt(panelVersion, remoteVersion) {
            const skipped = sessionStorage.getItem('nexa-update-prompt-skipped');
            if (skipped && skipped === String(remoteVersion || '')) return;
            showUpdateOverlay(
                adminT('update_available_title'),
                adminT('update_available_msg', { current: panelVersion || '', remote: remoteVersion || '' }),
                false,
                true
            );
        }
        function dismissUpdatePrompt() {
            const remote = window.panelUpdateStatus?.remoteVersion;
            if (remote) sessionStorage.setItem('nexa-update-prompt-skipped', String(remote));
            hideUpdateOverlay();
        }
        async function runPanelUpdate() {
            if (panelUpdateInProgress) return;
            panelUpdateInProgress = true;
            showUpdateOverlay(adminT('update_title'), adminT('update_msg'), true, false);
            try {
                const res = await fetch('/api/update-panel', { method: 'POST' });
                const result = await res.json();
                if (!res.ok) {
                    if (result.cf_token_invalid) {
                        showUpdateOverlay(adminT('update_failed'), adminT('update_cf_token_redirect'), true, false);
                        setTimeout(function() { window.location.href = '/setup?cf_token=1'; }, 1800);
                        return;
                    }
                    throw new Error(result.error || adminT('update_failed'));
                }
                sessionStorage.removeItem('nexa-update-prompt-skipped');
                showUpdateOverlay(adminT('update_complete'), adminT('update_complete_reload'), true, false);
                setTimeout(function() { window.location.reload(); }, 1800);
            } catch (err) {
                panelUpdateInProgress = false;
                showUpdateOverlay(
                    adminT('update_failed'),
                    err.message || adminT('update_failed_msg'),
                    false,
                    true
                );
            }
        }
        async function triggerPanelUpdate() {
            if (panelUpdateInProgress) return;
            if (window.innerWidth < 1024) toggleAdminSidebar(false);
            const ok = await showNexaConfirm(adminT('panel_update_confirm'), {
                title: adminT('panel_update_title'),
                confirmText: adminT('panel_update_btn')
            });
            if (!ok) return;
            await runPanelUpdate();
        }
        async function checkPanelUpdate() {
            if (panelUpdateCheckRunning || panelUpdateInProgress) return;
            panelUpdateCheckRunning = true;
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(function() { controller.abort(); }, 12000);
                let res;
                try {
                    res = await fetch('/api/panel-update-status?t=' + Date.now(), { signal: controller.signal });
                } finally {
                    clearTimeout(timeoutId);
                }
                if (!res.ok) return;
                const data = await res.json();
                allServicesOffEnabled = !!data.all_services_off;
                window.panelAllServicesOff = allServicesOffEnabled;
                updateAllServicesOffUI();
                showAnnounceBanner(data.announcement || '');
                updatePanelUpdateUI(data);
                if (data.updaterequired) {
                    await runPanelUpdate();
                    return;
                }
                if (data.updateAvailable) {
                    showUpdateAvailablePrompt(data.panelVersion, data.remoteVersion);
                }
                if (window.allUsers && typeof filterAndRenderUsers === 'function') {
                    filterAndRenderUsers();
                }
            } catch (e) {} finally {
                panelUpdateCheckRunning = false;
            }
        }
        window.loadDashboard = loadDashboard;
        window.loadNodeServer = loadNodeServer;
        window.runPanelUpdate = runPanelUpdate;
        window.triggerPanelUpdate = triggerPanelUpdate;
        window.dismissUpdatePrompt = dismissUpdatePrompt;
        window.showSubQR = showSubQR;
        window.copySubLink = copySubLink;
        window.openSubLinkQrModal = openSubLinkQrModal;
        window.openDashboardQrModal = openDashboardQrModal;
        window.switchAdminSection = switchAdminSection;
        window.toggleAdminSidebar = toggleAdminSidebar;
        window.toggleSidebarCollapse = toggleSidebarCollapse;
        window.logoutAdmin = logoutAdmin;
        window.setAdminLang = setAdminLang;
        window.toggleUserStatus = toggleUserStatus;
        window.toggleSaveUser = toggleSaveUser;
        window.resetUserService = resetUserService;
        window.deleteUser = deleteUser;
        window.editUser = editUser;
        window.openStatusPage = openStatusPage;
        window.openLogsPage = openLogsPage;
        window.openCreateModal = openCreateModal;
        window.toggleModal = toggleModal;
        window.handleFormSubmit = handleFormSubmit;
        window.filterAndRenderUsers = filterAndRenderUsers;
        window.openBulkEditModal = openBulkEditModal;
        window.toggleBulkEditModal = toggleBulkEditModal;
        window.runBulkAction = runBulkAction;
        window.clearUserSelection = clearUserSelection;
        window.toggleSelectAllFiltered = toggleSelectAllFiltered;
        window.onUserSelectChange = onUserSelectChange;
        window.showAdminGuideTab = showAdminGuideTab;
        window.openSystemUserEdit = openSystemUserEdit;
        window.copyDashboardSubLink = copyDashboardSubLink;
        window.setDashboardMapMode = setDashboardMapMode;
        window.openDashboardMapModal = openDashboardMapModal;
        window.closeDashboardMapModal = closeDashboardMapModal;
        window.closeUsageWarning = closeUsageWarning;
        window.copyNodeServerConfig = copyNodeServerConfig;
        initAdminClickDelegation();
        window.addEventListener('hashchange', function() {
            const hashSection = (location.hash || '').replace('#', '');
            if (hashSection === 'backup') switchAdminSection('settings');
            else if (hashSection && ADMIN_SECTIONS[hashSection]) switchAdminSection(hashSection);
        });
        document.addEventListener('DOMContentLoaded', function() {
        try {
            initAdminClickDelegation();
            initAdminSidebarClose();
            initSidebarCollapse();
            initNumSteppers();
            setAdminLang(localStorage.getItem('nexa-admin-lang') || 'fa');
        } catch (e) {}
        try {
        checkPanelUpdate();
        loadAllServicesOff();
        loadWorkerConfigForm();
        const hashSection = (location.hash || '').replace('#', '');
        if (hashSection === 'backup') {
            switchAdminSection('settings');
        } else if (hashSection && ADMIN_SECTIONS[hashSection]) {
            switchAdminSection(hashSection);
        } else {
            loadDashboard();
        }
        } catch (e) {}
        try {
            renderPortCheckboxes();
            renderPortCheckboxes({ tlsId: 'bulk-tls-ports-list', nonTlsId: 'bulk-nontls-ports-list', inputName: 'bulk-ports', defaultTls: [], defaultNonTls: [] });
        } catch (e) {}
});
    </script>
    <div id="adm-update-overlay" class="adm-update-overlay" aria-hidden="true">
        <div class="adm-update-overlay-card">
            <div class="adm-update-spinner" id="adm-update-spinner"></div>
            <div class="adm-update-overlay-title" id="adm-update-overlay-title">به‌روزرسانی پنل</div>
            <div class="adm-update-overlay-msg" id="adm-update-overlay-msg">در حال دریافت و نصب نسخه جدید...</div>
            <div id="adm-update-actions" class="adm-update-actions">
                <button type="button" id="adm-update-run-btn" class="adm-update-btn primary" onclick="runPanelUpdate()" data-i18n="panel_update_btn">به‌روزرسانی پنل</button>
                <button type="button" id="adm-update-later-btn" class="adm-update-btn secondary" onclick="dismissUpdatePrompt()" data-i18n="update_later">بعداً</button>
            </div>
        </div>
    </div>
    ${NEXA_TOAST_HTML}
    ${NEXA_TOAST_SCRIPT}
    ${NEXA_CONFIRM_HTML}
    ${NEXA_CONFIRM_SCRIPT}
</body>
</html>`,
  userNotFound: `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    ${NEXA_THEME_COLOR_USER}
    ${NEXA_FAVICON_TAGS}
    ${NEXA_THEME_COLOR_SYNC_SCRIPT}
    <title>کاربر یافت نشد - Nexa Team</title>
    ${NEXA_USER_THEME_SCRIPT}
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <script>
        tailwind.config = { darkMode: 'class', theme: { extend: { fontFamily: { sans: ['Vazirmatn', 'sans-serif'] } } } }
    </script>
    <style>
        body { font-family: 'Vazirmatn', sans-serif; transition: background 0.3s, color 0.3s; }
        ${NEXA_USER_THEME_VARS}
        ${NEXA_USER_THEME_COMMON}
        ${NEXA_USER_SHELL_CSS}
    </style>
</head>
<body class="user-shell-page">
    ${NEXA_USER_THEME_TOGGLE}
    <div class="st-shell">
        <div class="st-topbar">
            <div class="st-brand">
                <img src="${NEXA_LOGO_URL}" alt="Nexa Team" class="st-brand-logo">
                <div>
                    <div class="st-brand-title">Nexa Team</div>
                    <div class="st-brand-sub">Service Dashboard</div>
                </div>
            </div>
        </div>
        <div class="st-layout">
            <aside class="st-panel st-profile">
                <div class="st-page-title">سرویس یافت نشد</div>
                <div class="st-page-desc">لینکی که باز کرده‌اید معتبر نیست یا سرویس حذف شده است.</div>
                <div class="st-side-note">این سرویس فروشی نیست و به صورت رایگان می‌توانید استفاده کنید.</div>
                <a href="https://t.me/irnexa" target="_blank" class="telegram-link w-full justify-center">
                    <svg class="w-5 h-5 text-accent" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8c-.15 1.58-.8 5.42-1.13 7.19-.14.75-.42 1-.68 1.03-.58.05-1.02-.38-1.58-.75-.88-.58-1.38-.94-2.23-1.5-.99-.65-.35-1.01.22-1.59.15-.15 2.71-2.48 2.76-2.69a.2.2 0 00-.05-.18c-.06-.05-.14-.03-.21-.02-.09.02-1.49.94-4.22 2.79-.4.27-.76.41-1.08.4-.36-.01-1.04-.2-1.55-.37-.63-.2-1.12-.31-1.08-.66.02-.18.27-.36.74-.55 2.92-1.27 4.86-2.11 5.83-2.51 2.78-1.16 3.35-1.36 3.73-1.37.08 0 .27.02.39.12.1.08.13.19.14.27-.01.06.01.24 0 .24z"/></svg>
                    کانال تلگرام — irnexa@
                </a>
            </aside>
            <section class="st-panel st-content-wrap flex flex-col items-center justify-center text-center min-h-[16rem]">
                <div class="st-empty-icon">
                    <svg class="w-8 h-8 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                </div>
                <h2 class="text-lg font-black mb-2" style="color: var(--text-main)">کاربر مورد نظر وجود ندارد</h2>
                <p class="text-sm leading-relaxed max-w-sm" style="color: var(--text-muted)">سرویس مورد نظر یافت نشد یا حذف شده است. لطفاً لینک صحیح را از پنل یا بات دریافت کنید.</p>
            </section>
        </div>
    </div>
</body>
</html>`,
  status: `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    ${NEXA_THEME_COLOR_USER}
    ${NEXA_FAVICON_TAGS}
    ${NEXA_THEME_COLOR_SYNC_SCRIPT}
    <title>وضعیت سرویس</title>
    ${NEXA_USER_THEME_SCRIPT}
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <script>
        tailwind.config = { darkMode: 'class', theme: { extend: { fontFamily: { sans: ['Vazirmatn', 'sans-serif'] } } } }
    </script>
    <style>
        ${NEXA_SERVICE_PAGE_VARS}
        ${NEXA_SERVICE_PAGE_CSS}
        ${NEXA_TOAST_CSS}
    </style>
</head>
<body class="svc-page">
    <div class="svc-wrap">
        <header class="svc-header">
            <div class="svc-brand">
                <img src="${NEXA_LOGO_URL}" alt="Nexa Team" class="svc-brand-logo">
                <div>
                    <div class="svc-brand-title">Nexa Team</div>
                    <div class="svc-brand-sub">وضعیت سرویس</div>
                </div>
            </div>
            <div class="svc-header-actions">
                ${NEXA_SERVICE_THEME_TOGGLE}
            </div>
        </header>
        <div id="svc-announce-banner" class="svc-announce-banner hidden" role="status" aria-live="polite">
            <div class="svc-announce-inner">
                <span class="svc-announce-icon" aria-hidden="true">
                    <svg class="w-[1.05rem] h-[1.05rem] sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z"/></svg>
                </span>
                <div id="svc-announce-body" class="svc-announce-body"></div>
            </div>
        </div>
        <div class="svc-grid">
            <aside class="svc-card svc-sidebar">
                <div>
                    <div class="svc-label">نام سرویس</div>
                    <div id="display-username" class="svc-username">-</div>
                </div>
                <div id="status-card" class="svc-status">
                    <span id="status-icon" class="svc-status-icon">
                        <svg class="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                    </span>
                    <span id="status-text">در حال بارگذاری...</span>
                </div>
                <p class="svc-desc">این سرویس فروشی نیست و به صورت رایگان می‌توانید استفاده کنید. از این بخش می‌توانید وضعیت سرویس، میزان مصرف، زمان باقی‌مانده و لینک‌های اتصال را مدیریت کنید.</p>
                <a href="https://t.me/irnexa" target="_blank" class="svc-tg-link">
                    <svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8c-.15 1.58-.8 5.42-1.13 7.19-.14.75-.42 1-.68 1.03-.58.05-1.02-.38-1.58-.75-.88-.58-1.38-.94-2.23-1.5-.99-.65-.35-1.01.22-1.59.15-.15 2.71-2.48 2.76-2.69a.2.2 0 00-.05-.18c-.06-.05-.14-.03-.21-.02-.09.02-1.49.94-4.22 2.79-.4.27-.76.41-1.08.4-.36-.01-1.04-.2-1.55-.37-.63-.2-1.12-.31-1.08-.66.02-.18.27-.36.74-.55 2.92-1.27 4.86-2.11 5.83-2.51 2.78-1.16 3.35-1.36 3.73-1.37.08 0 .27.02.39.12.1.08.13.19.14.27-.01.06.01.24 0 .24z"/></svg>
                    کانال تلگرام irnexa@
                </a>
            </aside>
            <section class="space-y-4">
                <div class="svc-metrics">
                    <article class="svc-stat">
                        <div class="svc-stat-head">
                            <div class="svc-stat-title">
                                <span class="svc-stat-icon"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg></span>
                                حجم مصرفی
                            </div>
                            <div id="volume-pct" class="svc-stat-pct">۰٪</div>
                        </div>
                        <div class="svc-progress"><div id="volume-progress" class="svc-progress-bar" style="width: 0%"></div></div>
                        <div class="svc-stat-meta">
                            <div>مصرف شده: <strong id="used-vol">-</strong></div>
                            <div>حجم کل: <strong id="limit-vol">-</strong></div>
                        </div>
                    </article>
                    <article class="svc-stat accent">
                        <div class="svc-stat-head">
                            <div class="svc-stat-title">
                                <span class="svc-stat-icon"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></span>
                                زمان اشتراک
                            </div>
                            <div id="expiry-pct" class="svc-stat-pct">۰٪</div>
                        </div>
                        <div class="svc-progress"><div id="expiry-progress" class="svc-progress-bar" style="width: 0%"></div></div>
                        <div class="svc-stat-meta">
                            <div>باقی‌مانده: <strong id="days-remaining">-</strong></div>
                            <div>کل اعتبار: <strong id="total-days">-</strong></div>
                        </div>
                    </article>
                </div>
                <div class="svc-card svc-panel">
                    <div class="svc-section-title">
                        <span class="svc-stat-icon"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg></span>
                        دریافت لینک اشتراک
                    </div>
                    <div class="svc-actions">
                        <button type="button" onclick="copyVlessConfig()" class="svc-action vless">
                            <span class="svc-action-label"><svg class="w-4 h-4 svc-action-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>کپی کانفیگ VLESS</span>
                            <span class="svc-action-arrow">←</span>
                        </button>
                        <button type="button" onclick="copyTextSub()" class="svc-action sub">
                            <span class="svc-action-label"><svg class="w-4 h-4 svc-action-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path></svg>کپی لینک ساب</span>
                            <span class="svc-action-arrow">←</span>
                        </button>
                        <button type="button" onclick="showQR()" class="svc-action qr">
                            <span class="svc-action-label"><svg class="w-4 h-4 svc-action-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"></path></svg>QR لینک ساب</span>
                            <span class="svc-action-arrow">←</span>
                        </button>
                        <a href="/guide" class="svc-action guide">
                            <span class="svc-action-label"><svg class="w-4 h-4 svc-action-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"></path></svg>آموزش اتصال</span>
                            <span class="svc-action-arrow">←</span>
                        </a>
                    </div>
                </div>
            </section>
        </div>
    </div>
    <div id="qr-modal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out" onclick="if(event.target===this)window.toggleQRModal(false)">
        <div id="qr-modal-card" class="w-full max-w-sm svc-qr-modal rounded-2xl shadow-xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
            <h3 id="qr-modal-title" class="font-bold mb-4" style="color: var(--admin-text)">اسکن کد QR لینک ساب</h3>
            <div class="bg-white p-3 rounded-xl inline-block mb-4 border border-gray-100">
                <div id="qrcode-box" class="flex justify-center items-center w-48 h-48 mx-auto"></div>
            </div>
            <button type="button" onclick="window.toggleQRModal(false)" class="svc-qr-close">بستن</button>
        </div>
    </div>
    ${NEXA_QR_SCRIPT}
    ${NEXA_ANNOUNCE_LINKIFY_SCRIPT}
    <script>
        /* {{USER_DATA_PLACEHOLDER}} */
        function getSubLinkUrl() {
            const cfg = window.statusWorkerConfig || {};
            const path = String(cfg.subPagePath || 'sub').trim().toLowerCase().replace(new RegExp('^/+|/+$', 'g'), '').replace(/[^a-z0-9_-]/g, '').slice(0, 40) || 'sub';
            return window.location.protocol + '//' + getHost() + '/' + path + '/' + encodeURIComponent(window.statusUser.username);
        }
        function openSubscriptionQrModal(title) {
            window.toggleQRModal(true, getSubLinkUrl(), title || 'اسکن کد QR لینک ساب');
        }
        function getHost() {
            return window.location.host;
        }
        function formatVolumeLabel(gb) {
            if (gb == null || gb === undefined) return 'نامحدود';
            if (gb < 1) return (gb * 1024).toFixed(0) + ' MB';
            const n = gb % 1 === 0 ? gb.toFixed(0) : gb.toFixed(2);
            return n + ' GB';
        }
        function fmtRemarkVolume(gb) {
            if (gb == null || gb === undefined) return '∞';
            if (gb < 1) return (gb * 1024).toFixed(0) + ' MB';
            const n = gb % 1 === 0 ? gb.toFixed(0) : gb.toFixed(2);
            return n + ' GB';
        }
        function buildServiceInfoRemark(user) {
            const usedStr = fmtRemarkVolume(user.used_gb || 0);
            const totalStr = user.limit_gb != null ? fmtRemarkVolume(user.limit_gb) : '∞';
            let daysPart = '∞';
            if (user.expiry_days) {
                if (user.created_at) {
                    const created = new Date(user.created_at);
                    const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
                    const diffDays = Math.ceil((expiryDate - new Date()) / (1000 * 60 * 60 * 24));
                    daysPart = (diffDays > 0 ? diffDays : 0) + ' روز';
                } else {
                    daysPart = user.expiry_days + ' روز';
                }
            }
            return '[مصرف شده: ' + usedStr +']' + '['+ totalStr +' : کل ' +']'+ '[مانده :' + daysPart+']';
        }
        function applyRemarkTemplateClient(template, user, now, extra) {
            now = now || Date.now();
            extra = extra || {};
            const usedStr = fmtRemarkVolume(user.used_gb || 0);
            const totalStr = user.limit_gb != null ? fmtRemarkVolume(user.limit_gb) : '∞';
            let dayremind = '∞';
            if (user.expiry_days) {
                if (user.created_at) {
                    const created = new Date(user.created_at);
                    const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
                    const diffDays = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
                    dayremind = (diffDays > 0 ? diffDays : 0) + ' روز';
                } else {
                    dayremind = user.expiry_days + ' روز';
                }
            }
            const vars = {
                username: user.username || '',
                dayremind: dayremind,
                used: usedStr,
                total: totalStr,
                expiry: user.expiry_days != null ? String(user.expiry_days) : '∞',
                port: extra.port != null ? String(extra.port) : ''
            };
            let result = String(template || '');
            Object.keys(vars).forEach(function(key) {
                result = result.split('{' + key + '}').join(vars[key]);
            });
            if (result.indexOf('dayremind') !== -1) result = result.replace(/dayremind/g, vars.dayremind);
            return result;
        }
        function getInactiveReason(u) {
            if (u.request_limit_exceeded) return 'اتمام ریکوئست';
            const volExp = u.limit_gb && u.used_gb >= u.limit_gb;
            let timeExp = false;
            if (u.expiry_days && u.created_at) {
                const created = new Date(u.created_at);
                const expiryDate = new Date(created.getTime() + (u.expiry_days * 24 * 60 * 60 * 1000));
                timeExp = new Date() > expiryDate;
            }
            if (volExp && timeExp) return 'پایان زمان و حجم سرویس';
            if (volExp) return 'پایان حجم سرویس';
            if (timeExp) return 'پایان زمان سرویس';
            if (u.is_active === 0) return 'قطع شدن دستی توسط ادمین';
            return 'غیرفعال';
        }
        function buildFirstRemark() {
            return '❌ سرویس نکسا کاملا رایگان  است.❌ ';
        }
        function buildSecondRemark(u) {
            if (u.all_services_off) {
                return 'غیر فعال : قطع تمامی سرویس‌ها';
            }
            const volExp = u.limit_gb && u.used_gb >= u.limit_gb;
            let timeExp = false;
            if (u.expiry_days && u.created_at) {
                const created = new Date(u.created_at);
                const expiryDate = new Date(created.getTime() + (u.expiry_days * 24 * 60 * 60 * 1000));
                timeExp = new Date() > expiryDate;
            }
            if (u.request_limit_exceeded || u.is_active === 0 || volExp || timeExp) {
                return 'غیر فعال : ' + getInactiveReason(u);
            }
            const cfg = window.statusWorkerConfig || {};
            const template = cfg.infoRemarkTemplate || '[مصرف شده: {used}] [{total} : کل ] [مانده : {dayremind}]';
            return applyRemarkTemplateClient(template, u);
        }
        function getStatusWorkerConfig() {
            return window.statusWorkerConfig || {};
        }
        function resolveStatusFingerprint(fp) {
            const val = String(fp || 'random').trim().toLowerCase();
            if (val && val !== 'random') return val;
            const fps = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge'];
            return fps[Math.floor(Math.random() * fps.length)];
        }
        function getStatusTransportTypeParam(cfg) {
            const transport = cfg.transportProtocol || 'ws';
            if (transport === 'grpc') return cfg.gRPCmode === 'multi' ? 'grpc&mode=multi' : 'grpc&mode=gun';
            if (transport === 'xhttp') return 'xhttp&mode=stream-one';
            return 'ws';
        }
        function getStatusTransportConfig(cfg) {
            const transport = cfg.transportProtocol || 'ws';
            const isGrpc = transport === 'grpc';
            return { typeParam: getStatusTransportTypeParam(cfg), pathField: isGrpc ? 'serviceName' : 'path', hostField: isGrpc ? 'authority' : 'host' };
        }
        function getStatusTlsFragmentParam(cfg) {
            if (cfg.tlsFragment === 'Shadowrocket') return '&fragment=' + encodeURIComponent('1,40-60,30-50,tlshello');
            if (cfg.tlsFragment === 'Happ') return '&fragment=' + encodeURIComponent('3,1,tlshello');
            return '';
        }
        function getStatusEchParam(cfg) {
            if (!cfg.echEnabled) return '';
            const dns = cfg.echDns || 'https://dns.alidns.com/dns-query';
            const sni = cfg.echSni || '';
            return '&ech=' + encodeURIComponent((sni ? sni + '+' : '') + dns);
        }
        function buildStatusNodeLink(cfg, user, ip, portStr, fp, remark, protoOverride, linkHost) {
            const host = linkHost || ip;
            const protocol = protoOverride || cfg.protocolType || 'vless';
            const resolvedFp = resolveStatusFingerprint(fp);
            const pathVal = cfg.transportPath || '/in_config_foroshi_nist';
            const tc = getStatusTransportConfig(cfg);
            const ech = getStatusEchParam(cfg);
            const tlsPorts = ['443', '2053', '2083', '2087', '2096', '8443'];
            const noTlsPorts = ['80', '2052', '2082', '2086', '2095', '8080'];
            const isTlsPort = tlsPorts.includes(String(portStr));
            if (protocol === 'ss') {
                const enc = cfg.ssEncryption || 'aes-128-gcm';
                const ssPath = pathVal.replace(/([=,])/g, '\\\\$1');
                const plugin = 'ray-plugin;mode=websocket;host=' + host + ';path=' + ssPath + (isTlsPort ? ';tls' : '');
                return 'ss://' + btoa(enc + ':' + user.uuid) + '@' + ip + ':' + portStr + '?plugin=v2' + encodeURIComponent(plugin) + ech + (isTlsPort ? getStatusTlsFragmentParam(cfg) : '') + '#' + encodeURIComponent(remark);
            }
            const fragment = isTlsPort ? getStatusTlsFragmentParam(cfg) : '';
            const insecure = cfg.skipCertVerify ? '&insecure=1&allowInsecure=1' : '';
            if (!isTlsPort) {
                const mapped = noTlsPorts[tlsPorts.indexOf(Number(portStr))];
                const p = mapped != null ? String(mapped) : portStr;
                return protocol + '://' + user.uuid + '@' + ip + ':' + p + '?security=none&type=' + tc.typeParam + '&' + tc.hostField + '=' + host + '&' + tc.pathField + '=' + encodeURIComponent(pathVal) + '&encryption=none#' + encodeURIComponent(remark);
            }
            return protocol + '://' + user.uuid + '@' + ip + ':' + portStr + '?security=tls&type=' + tc.typeParam + ech + '&' + tc.hostField + '=' + host + '&fp=' + resolvedFp + '&sni=' + host + '&' + tc.pathField + '=' + encodeURIComponent(pathVal) + fragment + '&encryption=none' + insecure + '#' + encodeURIComponent(remark);
        }
        function isServiceInactive(u) {
            return buildSecondRemark(u).startsWith('غیر فعال');
        }
        function resolveConfigIps(host, userIpsRaw) {
            const parsed = String(userIpsRaw || '').split('\\n').map(function(ip) {
                const trimmed = ip.trim();
                const hashIdx = trimmed.indexOf('#');
                return hashIdx >= 0 ? trimmed.slice(0, hashIdx).trim() : trimmed;
            }).filter(function(ip) { return ip.length > 0; });
            if (!parsed.length) return [host];
            const ips = [host];
            parsed.forEach(function(ip) {
                if (!ips.some(function(existing) { return existing.toLowerCase() === ip.toLowerCase(); })) {
                    ips.push(ip);
                }
            });
            return ips;
        }
        function getDirectVlessLinks() {
            return getVlessLink();
        }
        function getVlessLink() {
            const u = window.statusUser;
            const host = getHost();
            var ips = resolveConfigIps(host, u.ips);
            var ports = String(u.port || '443').split(',').map(function(p) { return p.trim(); }).filter(function(p) { return p.length > 0; });
            var fp = u.fingerprint || 'random';
            var links = [];
            var firstRemark = buildFirstRemark();
            var secondRemark = buildSecondRemark(u);
            var inactive = isServiceInactive(u);
            var cfg = getStatusWorkerConfig();
            var tc = getStatusTransportConfig(cfg);
            var pathEnc = encodeURIComponent(cfg.transportPath || '/in_config_foroshi_nist');
            var proto = cfg.protocolType === 'mixed' ? 'vless' : (cfg.protocolType || 'vless');
            var fakeLink = function(remark) {
                return proto + '://' + (u.uuid || '') + '@127.0.0.1:17?encryption=none&security=none&type=' + tc.typeParam + '&' + tc.hostField + '=' + host + '&' + tc.pathField + '=' + pathEnc + '#' + encodeURIComponent(remark);
            };
            links.push(fakeLink(firstRemark));
            links.push(fakeLink(secondRemark));
            if (!inactive) {
                var nodeIndex = 0;
                ips.forEach(function(ip) {
                    ports.forEach(function(portStr) {
                        var nodeTemplate = cfg.nodeRemarkTemplate || '{username}';
                        var remark = applyRemarkTemplateClient(nodeTemplate, u, Date.now(), { port: portStr });
                        var nodeProto = cfg.protocolType || 'vless';
                        if (nodeProto === 'mixed') {
                            nodeProto = ['vless', 'trojan', 'ss'][nodeIndex % 3];
                            nodeIndex++;
                        }
                        links.push(buildStatusNodeLink(cfg, u, ip, portStr, fp, remark, nodeProto, host));
                    });
                });
            }
            return links.join('\\n');
        }
        function copyVlessConfig() {
            navigator.clipboard.writeText(getDirectVlessLinks()).then(() => showNexaToast('کانفیگ VLESS با موفقیت کپی شد')).catch(() => showNexaToast('خطا در کپی کردن کانفیگ', 'error'));
        }
        function copyTextSub() {
            const link = getSubLinkUrl();
            navigator.clipboard.writeText(link).then(() => showNexaToast('لینک ساب کپی شد')).catch(() => showNexaToast('خطا در کپی کردن لینک', 'error'));
        }
        function showQR() {
            window.toggleQRModal(true, getSubLinkUrl(), 'اسکن کد QR لینک ساب');
        }
        function setBarProgress(el, pct, color) {
            el.style.width = pct + '%';
            if (color) el.style.backgroundColor = color;
        }
        function themeColor(name) {
            return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
        }
        function setStatusState(isActive, text) {
            const statusCard = document.getElementById('status-card');
            const statusIcon = document.getElementById('status-icon');
            const statusText = document.getElementById('status-text');
            statusCard.className = 'svc-status ' + (isActive ? 'active' : 'inactive');
            statusIcon.className = 'svc-status-icon';
            statusIcon.innerHTML = isActive
                ? '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>'
                : '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>';
            statusText.innerText = text;
        }
        document.addEventListener('DOMContentLoaded', () => {
            const u = window.statusUser;
            if (!u) return;
            document.getElementById('display-username').innerText = u.username;
            renderAnnounceBanner('svc-announce-banner', 'svc-announce-body', u.announcement || '');
            const usedGb = u.used_gb || 0;
            const limitGb = u.limit_gb;
            const formattedUsed = usedGb < 1 ? (usedGb * 1024).toFixed(0) + ' MB' : usedGb.toFixed(2) + ' GB';
            document.getElementById('used-vol').innerText = formattedUsed;
            let isVolumeExpired = false;
            if (limitGb) {
                document.getElementById('limit-vol').innerText = limitGb + ' GB';
                const pct = Math.min((usedGb / limitGb) * 100, 100);
                document.getElementById('volume-pct').innerText = pct.toFixed(0) + '٪';
                const hue = 120 - (pct * 1.2);
                setBarProgress(document.getElementById('volume-progress'), pct, 'hsl(' + hue + ', 80%, 45%)');
                if (usedGb >= limitGb) isVolumeExpired = true;
            } else {
                document.getElementById('limit-vol').innerText = 'نامحدود';
                document.getElementById('volume-pct').innerText = '۰٪';
                setBarProgress(document.getElementById('volume-progress'), 100, themeColor('--admin-primary'));
            }
            let daysRemaining = 'نامحدود';
            let totalDays = 'نامحدود';
            let isTimeExpired = false;
            if (u.expiry_days) {
                totalDays = u.expiry_days + ' روز';
                if (u.created_at) {
                    const created = new Date(u.created_at);
                    const expiryDate = new Date(created.getTime() + (u.expiry_days * 24 * 60 * 60 * 1000));
                    const diffDays = Math.ceil((expiryDate - new Date()) / (1000 * 60 * 60 * 24));
                    daysRemaining = diffDays > 0 ? diffDays : 0;
                    const pct = Math.max(0, Math.min(100, (daysRemaining / u.expiry_days) * 100));
                    document.getElementById('expiry-pct').innerText = pct.toFixed(0) + '٪';
                    const hue = pct * 1.2;
                    setBarProgress(document.getElementById('expiry-progress'), pct, 'hsl(' + hue + ', 80%, 45%)');
                    if (new Date() > expiryDate) isTimeExpired = true;
                }
            } else {
                document.getElementById('expiry-pct').innerText = '۰٪';
                setBarProgress(document.getElementById('expiry-progress'), 100, themeColor('--admin-accent'));
            }
            document.getElementById('days-remaining').innerText = daysRemaining === 'نامحدود' ? 'نامحدود' : daysRemaining + ' روز';
            document.getElementById('total-days').innerText = totalDays;
            if (u.all_services_off) {
                setStatusState(false, 'وضعیت سرویس: غیرفعال — قطع تمامی سرویس‌ها');
            } else if (isVolumeExpired && isTimeExpired) {
                setStatusState(false, 'وضعیت سرویس: غیرفعال — پایان زمان و حجم سرویس');
            } else if (isVolumeExpired) {
                setStatusState(false, 'وضعیت سرویس: غیرفعال — پایان حجم سرویس');
            } else if (isTimeExpired) {
                setStatusState(false, 'وضعیت سرویس: غیرفعال — پایان زمان سرویس');
            } else if (u.request_limit_exceeded) {
                setStatusState(false, 'وضعیت سرویس: غیرفعال (اتمام ریکوئست)');
            } else if (u.is_active === 0) {
                setStatusState(false, 'وضعیت سرویس: غیرفعال — قطع شدن دستی توسط ادمین');
            } else {
                setStatusState(true, 'وضعیت سرویس: فعال');
            }
        });
    </script>
    ${NEXA_TOAST_HTML}
    ${NEXA_TOAST_SCRIPT}
</body>
</html>`,
  guide: `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    ${NEXA_THEME_COLOR_USER}
    ${NEXA_FAVICON_TAGS}
    ${NEXA_THEME_COLOR_SYNC_SCRIPT}
    <title>آموزش اتصال - Nexa Team</title>
    ${NEXA_USER_THEME_SCRIPT}
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <script>
        tailwind.config = { darkMode: 'class', theme: { extend: { fontFamily: { sans: ['Vazirmatn', 'sans-serif'] } } } }
    </script>
    <style>
        ${NEXA_SERVICE_PAGE_VARS}
        ${NEXA_SERVICE_PAGE_CSS}
    </style>
</head>
<body class="svc-page">
    <div class="svc-wrap">
        <header class="svc-header">
            <div class="svc-brand">
                <img src="${NEXA_LOGO_URL}" alt="Nexa Team" class="svc-brand-logo">
                <div>
                    <div class="svc-brand-title">Nexa Team</div>
                    <div class="svc-brand-sub">آموزش اتصال</div>
                </div>
            </div>
            <div class="svc-header-actions">
                <button type="button" onclick="history.back()" class="svc-back-btn">← بازگشت</button>
                ${NEXA_SERVICE_THEME_TOGGLE}
            </div>
        </header>
        <div class="svc-grid">
            <aside class="svc-card svc-sidebar">
                <div>
                    <div class="svc-label">راهنما</div>
                    <div class="svc-username" style="font-family: inherit">آموزش اتصال</div>
                </div>
                <p class="svc-desc">پلتفرم مورد نظر خود را انتخاب کنید و مراحل را گام‌به‌گام دنبال کنید.</p>
                <a href="https://t.me/irnexa" target="_blank" class="svc-tg-link">
                    <svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8c-.15 1.58-.8 5.42-1.13 7.19-.14.75-.42 1-.68 1.03-.58.05-1.02-.38-1.58-.75-.88-.58-1.38-.94-2.23-1.5-.99-.65-.35-1.01.22-1.59.15-.15 2.71-2.48 2.76-2.69a.2.2 0 00-.05-.18c-.06-.05-.14-.03-.21-.02-.09.02-1.49.94-4.22 2.79-.4.27-.76.41-1.08.4-.36-.01-1.04-.2-1.55-.37-.63-.2-1.12-.31-1.08-.66.02-.18.27-.36.74-.55 2.92-1.27 4.86-2.11 5.83-2.51 2.78-1.16 3.35-1.36 3.73-1.37.08 0 .27.02.39.12.1.08.13.19.14.27-.01.06.01.24 0 .24z"/></svg>
                    کانال تلگرام irnexa@
                </a>
            </aside>
            <section class="space-y-4">
                <div class="svc-tabs">
                    <button type="button" onclick="showTab('android')" id="tab-android" class="svc-tab active">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"></path></svg>
                        اندروید
                    </button>
                    <button type="button" onclick="showTab('ios')" id="tab-ios" class="svc-tab">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M7 21h10a2 2 0 002-2V5a2 2 0 00-2-2H7a2 2 0 00-2 2v14a2 2 0 002 2z"></path></svg>
                        آیفون
                    </button>
                    <button type="button" onclick="showTab('desktop')" id="tab-desktop" class="svc-tab">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
                        ویندوز / مک
                    </button>
                </div>
                <div id="panel-android" class="svc-card svc-panel">
                    <h2 class="svc-section-title">
                        <span class="svc-stat-icon"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"></path></svg></span>
                        راهنمای اتصال — اندروید
                    </h2>
                    <div class="space-y-3">
                        <div class="svc-step"><span class="svc-step-num">1</span> اپ V2rayNG را از لینک زیر دانلود کنید:<br><a href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" class="svc-guide-link">https://github.com/2dust/v2rayNG/releases/latest</a></div>
                        <div class="svc-step"><span class="svc-step-num">2</span> اپ را باز کنید</div>
                        <div class="svc-step"><span class="svc-step-num">3</span> روی آیکون <svg class="w-4 h-4 inline-block align-text-bottom" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg> در بالا راست بزنید</div>
                        <div class="svc-step"><span class="svc-step-num">4</span> گزینه <strong>Import config from clipboard</strong> را انتخاب کنید<br><span class="text-xs opacity-70">(لینک کانفیگ باید از قبل کپی شده باشد)</span></div>
                        <div class="svc-step"><span class="svc-step-num">5</span> کانفیگ در لیست ظاهر می‌شود — روی آن بزنید تا انتخاب شود</div>
                        <div class="svc-step"><span class="svc-step-num">6</span> دکمه <svg class="w-4 h-4 inline-block align-text-bottom" fill="currentColor" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"></path></svg> پایین صفحه را بزنید , اکنون با موفقیت متصل شدید .</div>
                        <div class="svc-step flex items-start gap-2">
                            <svg class="w-5 h-5 flex-shrink-0 mt-0.5" style="color: var(--admin-primary)" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                            <span><strong>نکته:</strong> برای مشاهده جزئیات سرویس و اپدیت کانفیگ‌ها در زمان قطعی، کافی است از <strong>۳ نقطه</strong> بالای صفحه گزینه آخر <strong>بروزرسانی اشتراک</strong> یا همان <strong>Update Subscription</strong> را بزنید.</span>
                        </div>
                        <p class="svc-footnote">
                            <svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                            نتوانستید متصل شوید؟ <a href="https://t.me/nexateam_bot" target="_blank" class="svc-support-link">از قسمت پشتیبانی در بات کمک بگیرید</a>
                        </p>
                    </div>
                </div>
                <div id="panel-ios" class="svc-card svc-panel hidden">
                    <h2 class="svc-section-title">
                        <span class="svc-stat-icon"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M7 21h10a2 2 0 002-2V5a2 2 0 00-2-2H7a2 2 0 00-2 2v14a2 2 0 002 2z"></path></svg></span>
                        راهنمای اتصال — آیفون (iOS)
                    </h2>
                    <div class="space-y-3">
                        <div class="svc-step"><span class="svc-step-num">1</span> اپ Streisand را از App Store دانلود کنید:<br><a href="https://apps.apple.com/app/streisand/id6450534064" target="_blank" class="svc-guide-link">https://apps.apple.com/app/streisand/id6450534064</a></div>
                        <div class="svc-step"><span class="svc-step-num">2</span> اپ را باز کنید</div>
                        <div class="svc-step"><span class="svc-step-num">3</span> روی <svg class="w-4 h-4 inline-block align-text-bottom" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg> در بالا راست بزنید</div>
                        <div class="svc-step"><span class="svc-step-num">4</span> گزینه <strong>Import from Clipboard</strong> را بزنید<br><span class="text-xs opacity-70">(لینک کانفیگ باید از قبل کپی شده باشد)</span></div>
                        <div class="svc-step"><span class="svc-step-num">5</span> کانفیگ اضافه شد — کنارش Connect را بزنید</div>
                        <div class="svc-step"><span class="svc-step-num">6</span> در پنجره‌ای که باز می‌شود Allow را بزنید</div>
                        <div class="svc-step flex items-start gap-2">
                            <svg class="w-5 h-5 flex-shrink-0 mt-0.5" style="color: var(--admin-primary)" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                            <span><strong>نکته:</strong> برای مشاهده جزئیات سرویس و اپدیت کانفیگ‌ها در زمان قطعی، کافی است از گزینه  <strong>بروزرسانی اشتراک</strong> یا همان <strong>Update Subscription</strong> را بزنید.</span>
                        </div>
                        <p class="svc-footnote">
                            <svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                            نتوانستید متصل شوید؟ <a href="https://t.me/nexateam_bot" target="_blank" class="svc-support-link">از قسمت پشتیبانی در بات کمک بگیرید</a>
                        </p>
                    </div>
                </div>
                <div id="panel-desktop" class="svc-card svc-panel hidden">
                    <h2 class="svc-section-title">
                        <span class="svc-stat-icon"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg></span>
                        راهنمای اتصال — ویندوز / مک
                    </h2>
                    <h3 class="svc-subsection-title">
                        <svg class="w-4 h-4" style="color: var(--admin-primary)" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
                        ویندوز
                    </h3>
                    <div class="space-y-3 mb-8">
                        <div class="svc-step"><span class="svc-step-num">1</span> نرم‌افزار v2rayN را دانلود کنید:<br><a href="https://github.com/2dust/v2rayN/releases/latest" target="_blank" class="svc-guide-link">https://github.com/2dust/v2rayN/releases/latest</a></div>
                        <div class="svc-step"><span class="svc-step-num">2</span> فایل zip را extract کنید و v2rayN.exe را اجرا کنید</div>
                        <div class="svc-step"><span class="svc-step-num">3</span> در تسک‌بار روی آیکون برنامه راست‌کلیک کنید</div>
                        <div class="svc-step"><span class="svc-step-num">4</span> گزینه <strong> + </strong> را بزنید و گزینه اول نام دلخواه و گزینه دوم لینک کپی شده را وارد کنید و روی گزینه تایید بزنید <br><span class="text-xs opacity-70">(لینک کانفیگ باید کپی شده باشد)</span></div>
                        <div class="svc-step"><span class="svc-step-num">5</span>از منوی بالا روی گروه اشتراک زده و گزینه سوم را بزنید .</div>
                        <div class="svc-step"><span class="svc-step-num">6</span>اکنون برای متصل شدن در پایین صفحه گزینه پاک کردن سیستم پروکسی رو روی گزینه دوم بزارید .</div>
                    </div>
                    <div class="svc-divider">━━━━━━━━━━━━━━━</div>
                    <h3 class="svc-subsection-title">
                        <svg class="w-4 h-4" style="color: var(--admin-accent)" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
                        مک
                    </h3>
                    <div class="space-y-3">
                        <div class="svc-step"><span class="svc-step-num">1</span> اپ FoXray را از Mac App Store دانلود کنید</div>
                        <div class="svc-step"><span class="svc-step-num">2</span> روی <svg class="w-4 h-4 inline-block align-text-bottom" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg> بزنید و Import from clipboard را انتخاب کنید</div>
                        <div class="svc-step"><span class="svc-step-num">3</span> کانفیگ را انتخاب و Connect بزنید</div>
                        <p class="svc-footnote">
                            <svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                            نتوانستید متصل شوید؟ <a href="https://t.me/nexateam_bot" target="_blank" class="svc-support-link">از قسمت پشتیبانی در بات کمک بگیرید</a>
                        </p>
                    </div>
                </div>
            </section>
        </div>
    </div>
    <script>
        function showTab(name) {
            ['android', 'ios', 'desktop'].forEach(function(id) {
                document.getElementById('panel-' + id).classList.toggle('hidden', id !== name);
                document.getElementById('tab-' + id).classList.toggle('active', id === name);
            });
        }
    </script>
</body>
</html>`,
  serviceLogs: `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    ${NEXA_THEME_COLOR_USER}
    ${NEXA_FAVICON_TAGS}
    ${NEXA_THEME_COLOR_SYNC_SCRIPT}
    <title>لاگ اتصال</title>
    ${NEXA_USER_THEME_SCRIPT}
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <script>
        tailwind.config = { darkMode: 'class', theme: { extend: { fontFamily: { sans: ['Vazirmatn', 'sans-serif'] } } } }
    </script>
    <style>
        ${NEXA_SERVICE_PAGE_VARS}
        ${NEXA_SERVICE_PAGE_CSS}
        ${NEXA_CONFIRM_CSS}
    </style>
</head>
<body class="svc-page">
    <div class="svc-wrap">
        <header class="svc-header">
            <div class="svc-brand">
                <img src="${NEXA_LOGO_URL}" alt="Nexa Team" class="svc-brand-logo">
                <div>
                    <div class="svc-brand-title">Nexa Team</div>
                    <div class="svc-brand-sub">لاگ اتصال</div>
                </div>
            </div>
            <div class="svc-header-actions">
                <a href="/admin" class="svc-back-btn">← بازگشت</a>
                ${NEXA_SERVICE_THEME_TOGGLE}
            </div>
        </header>
        <div class="svc-grid">
            <aside class="svc-card svc-sidebar">
                <div>
                    <div class="svc-label">نام سرویس</div>
                    <div id="display-username" class="svc-username">-</div>
                </div>
                <p class="svc-desc">تاریخچه اتصال و رویدادهای مرتبط با این سرویس در این بخش نمایش داده می‌شود.</p>
                <div class="flex items-center gap-2 flex-wrap">
                    <span id="log-count" class="svc-badge-count">۰ رویداد</span>
                    <button onclick="refreshLogs()" class="svc-btn-sm" title="بروزرسانی">بروزرسانی</button>
                    <button onclick="clearAllLogs()" class="svc-btn-sm danger" title="حذف همه">حذف همه</button>
                </div>
            </aside>
            <section class="svc-card svc-panel">
                <div class="svc-section-title">
                    <span class="svc-stat-icon"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg></span>
                    تاریخچه اتصال
                </div>
                <div id="logs-loading" class="svc-empty">در حال بارگذاری...</div>
                <div id="logs-empty" class="hidden svc-empty">هنوز اتصالی ثبت نشده است.</div>
                <div id="logs-list" class="hidden svc-log-list"></div>
            </section>
        </div>
    </div>
    <script>
        /* {{USERNAME_PLACEHOLDER}} */
        function formatLogTime(iso) {
            if (!iso) return '-';
            try {
                var d = new Date(iso);
                var date = d.toLocaleDateString('fa-IR', { year: 'numeric', month: '2-digit', day: '2-digit' });
                var time = d.toLocaleTimeString('fa-IR', { hour: '2-digit', minute: '2-digit' });
                return date + ' — ' + time;
            } catch (e) { return iso; }
        }
        function escapeHtml(str) {
            return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        }
        function eventTypeBadge(type) {
            var t = String(type || 'اتصال');
            var cls = 'default';
            var itemCls = '';
            if (t.indexOf('پینگ') >= 0) { cls = 'ping'; itemCls = 'type-ping'; }
            else if (t.indexOf('دریافت کانفیگ') >= 0) { cls = 'config'; itemCls = 'type-config'; }
            else if (t.indexOf('IP') >= 0) { cls = 'ip'; itemCls = 'type-ip'; }
            else if (t.indexOf('اتصال') >= 0) { cls = 'connect'; itemCls = 'type-connect'; }
            return { badge: '<span class="svc-log-badge ' + cls + '">' + escapeHtml(t) + '</span>', itemCls: itemCls };
        }
        function renderLogs(logs) {
            const loading = document.getElementById('logs-loading');
            const empty = document.getElementById('logs-empty');
            const list = document.getElementById('logs-list');
            const countEl = document.getElementById('log-count');
            loading.classList.add('hidden');
            countEl.textContent = logs.length + ' رویداد';
            if (!logs.length) {
                list.classList.add('hidden');
                empty.classList.remove('hidden');
                return;
            }
            empty.classList.add('hidden');
            list.classList.remove('hidden');
            list.innerHTML = logs.map(function(log) {
                var ev = eventTypeBadge(log.event_type);
                return '<div class="svc-log-item ' + ev.itemCls + '">' +
                    '<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">' +
                        '<div class="flex items-center gap-3 min-w-0">' +
                            '<span class="svc-stat-icon flex-shrink-0"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg></span>' +
                            '<div class="min-w-0">' +
                                '<div class="flex items-center gap-2 flex-wrap mb-1">' + ev.badge +
                                    '<span class="svc-log-ip">' + escapeHtml(log.ip || 'نامشخص') + '</span>' +
                                '</div>' +
                                (log.details ? '<div class="svc-log-details">' + escapeHtml(log.details) + '</div>' : '') +
                            '</div>' +
                        '</div>' +
                        '<span class="svc-log-time sm:text-left">' + escapeHtml(formatLogTime(log.created_at)) + '</span>' +
                    '</div>' +
                '</div>';
            }).join('');
        }
        function getServiceLogsPagePath() {
            const path = String(window.serviceLogsPagePath || 'logs').trim().toLowerCase().replace(new RegExp('^/+|/+$', 'g'), '').replace(/[^a-z0-9_-]/g, '').slice(0, 40);
            return path || 'logs';
        }
        function getServiceLogsLoginUrl() {
            return '/' + getServiceLogsPagePath() + '/' + encodeURIComponent(window.serviceLogUsername);
        }
        async function refreshLogs() {
            document.getElementById('logs-loading').classList.remove('hidden');
            document.getElementById('logs-list').classList.add('hidden');
            document.getElementById('logs-empty').classList.add('hidden');
            try {
                const res = await fetch('/api/connection-logs/' + encodeURIComponent(window.serviceLogUsername));
                if (res.status === 401) {
                    window.location.href = getServiceLogsLoginUrl();
                    return;
                }
                const data = await res.json();
                renderLogs(data.logs || []);
            } catch (e) {
                document.getElementById('logs-loading').textContent = 'خطا در بارگذاری لاگ‌ها';
            }
        }
        async function clearAllLogs() {
            if (!await showNexaConfirm('آیا از حذف همه لاگ‌های اتصال این سرویس مطمئن هستید؟', { title: 'حذف لاگ‌ها', danger: true, confirmText: 'بله، حذف شوند' })) return;
            try {
                const res = await fetch('/api/connection-logs/' + encodeURIComponent(window.serviceLogUsername), { method: 'DELETE' });
                if (res.status === 401) {
                    window.location.href = getServiceLogsLoginUrl();
                    return;
                }
                if (res.ok) renderLogs([]);
                else alert('خطا در حذف لاگ‌ها');
            } catch (e) {
                alert('خطا در برقراری ارتباط با سرور');
            }
        }
        document.addEventListener('DOMContentLoaded', function() {
            if (!window.serviceLogUsername) return;
            document.getElementById('display-username').textContent = window.serviceLogUsername;
            refreshLogs();
        });
    </script>
    ${NEXA_CONFIRM_HTML}
    ${NEXA_CONFIRM_SCRIPT}
</body>
</html>`,
  logs: `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    ${NEXA_THEME_COLOR_ADMIN}
    ${NEXA_FAVICON_TAGS}
    ${NEXA_THEME_COLOR_SYNC_SCRIPT}
    <title>لاگ فعالیت‌های پنل</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: { sans: ['Vazirmatn', 'sans-serif'] },
                    colors: { amoled: { bg: '#000000', card: '#080b0f', input: '#0d1117', border: '#1c2330' } }
                }
            }
        }
    </script>
    <style>
        body { font-family: 'Vazirmatn', sans-serif; }
        ${NEXA_CONFIRM_CSS}
    </style>
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen transition-colors duration-200">
    <header class="border-b border-gray-200 dark:border-amoled-border bg-white dark:bg-amoled-card px-4 py-4">
        <div class="max-w-6xl mx-auto flex flex-col md:flex-row justify-between items-center gap-4">
            <div class="flex items-center gap-3">
                <a href="/admin" class="p-2 rounded-lg bg-gray-100 dark:bg-amoled-input border border-gray-200 dark:border-amoled-border hover:bg-gray-200 dark:hover:bg-zinc-800 transition text-gray-600 dark:text-gray-300" title="بازگشت به پنل">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"></path></svg>
                </a>
                <h1 class="text-lg font-bold">لاگ فعالیت‌های پنل</h1>
            </div>
            <div class="flex items-center gap-3">
                <button id="theme-toggle" class="p-2 rounded-lg bg-gray-100 dark:bg-amoled-input border border-gray-200 dark:border-amoled-border hover:bg-gray-200 dark:hover:bg-zinc-800 transition">
                    <svg id="sun-icon" class="w-5 h-5 hidden dark:block text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m12.728 0l-.707-.707M6.343 6.343l-.707-.707M14 12a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
                    <svg id="moon-icon" class="w-5 h-5 block dark:hidden text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
                </button>
                <button onclick="refreshLogs()" class="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-bold transition">بروزرسانی</button>
                <button onclick="clearAllLogs()" class="p-2 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 hover:bg-red-100 dark:hover:bg-red-950/50 text-red-600 dark:text-red-400 transition" title="حذف همه لاگ‌ها">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                </button>
            </div>
        </div>
    </header>
    <main class="max-w-6xl mx-auto px-4 py-8">
        <div class="bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-sm overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-100 dark:border-amoled-border flex justify-between items-center">
                <p class="text-sm text-gray-500 dark:text-zinc-400">تمام رویدادهای مهم پنل (ورود ادمین، ساخت کاربر، بکاپ و ...)</p>
                <span id="log-count" class="text-xs font-bold text-violet-600 dark:text-violet-400 bg-violet-50 dark:bg-violet-950/30 px-3 py-1 rounded-full">۰ رویداد</span>
            </div>
            <div id="logs-loading" class="p-8 text-center text-gray-500 dark:text-zinc-400 text-sm">در حال بارگذاری...</div>
            <div id="logs-empty" class="hidden p-12 text-center text-gray-400 dark:text-zinc-500 text-sm">هنوز رویدادی ثبت نشده است.</div>
            <div class="overflow-x-auto">
                <table class="w-full text-sm hidden" id="logs-table">
                    <thead class="bg-gray-50 dark:bg-zinc-900/50 text-gray-600 dark:text-zinc-400">
                        <tr>
                            <th class="px-4 py-3 text-right font-bold whitespace-nowrap">زمان</th>
                            <th class="px-4 py-3 text-right font-bold whitespace-nowrap">عملیات</th>
                            <th class="px-4 py-3 text-right font-bold">جزئیات</th>
                            <th class="px-4 py-3 text-right font-bold whitespace-nowrap">IP</th>
                        </tr>
                    </thead>
                    <tbody id="logs-body" class="divide-y divide-gray-100 dark:divide-amoled-border"></tbody>
                </table>
            </div>
        </div>
    </main>
    <script>
        const themeToggle = document.getElementById('theme-toggle');
        if (localStorage.getItem('theme') === 'dark' || (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            document.documentElement.classList.add('dark');
        }
        themeToggle.addEventListener('click', () => {
            document.documentElement.classList.toggle('dark');
            localStorage.setItem('theme', document.documentElement.classList.contains('dark') ? 'dark' : 'light');
        });
        function formatLogTime(iso) {
            if (!iso) return '-';
            try {
                const d = new Date(iso);
                return d.toLocaleString('fa-IR', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
            } catch (e) {
                return iso;
            }
        }
        function escapeHtml(str) {
            return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }
        function renderLogs(logs) {
            const tbody = document.getElementById('logs-body');
            const table = document.getElementById('logs-table');
            const empty = document.getElementById('logs-empty');
            const loading = document.getElementById('logs-loading');
            const countEl = document.getElementById('log-count');
            loading.classList.add('hidden');
            countEl.textContent = logs.length + ' رویداد';
            if (!logs.length) {
                table.classList.add('hidden');
                empty.classList.remove('hidden');
                tbody.innerHTML = '';
                return;
            }
            empty.classList.add('hidden');
            table.classList.remove('hidden');
            tbody.innerHTML = logs.map(function(log) {
                return '<tr class="hover:bg-gray-50 dark:hover:bg-zinc-900/40 transition">' +
                    '<td class="px-4 py-3 whitespace-nowrap font-mono text-xs text-gray-500 dark:text-zinc-400" dir="ltr">' + escapeHtml(formatLogTime(log.created_at)) + '</td>' +
                    '<td class="px-4 py-3 whitespace-nowrap font-bold text-gray-900 dark:text-zinc-100">' + escapeHtml(log.action) + '</td>' +
                    '<td class="px-4 py-3 text-gray-600 dark:text-zinc-300">' + escapeHtml(log.details) + '</td>' +
                    '<td class="px-4 py-3 whitespace-nowrap font-mono text-xs text-violet-600 dark:text-violet-400" dir="ltr">' + escapeHtml(log.ip || '-') + '</td>' +
                '</tr>';
            }).join('');
        }
        async function refreshLogs() {
            document.getElementById('logs-loading').classList.remove('hidden');
            document.getElementById('logs-table').classList.add('hidden');
            document.getElementById('logs-empty').classList.add('hidden');
            try {
                const res = await fetch('/api/logs');
                if (res.status === 401) {
                    window.location.href = '/logs';
                    return;
                }
                const data = await res.json();
                renderLogs(data.logs || []);
            } catch (e) {
                document.getElementById('logs-loading').textContent = 'خطا در بارگذاری لاگ‌ها';
            }
        }
        async function clearAllLogs() {
            if (!await showNexaConfirm('آیا از حذف همه لاگ‌های پنل مطمئن هستید؟', { title: 'حذف لاگ‌ها', danger: true, confirmText: 'بله، حذف شوند' })) return;
            try {
                const res = await fetch('/api/logs', { method: 'DELETE' });
                if (res.status === 401) {
                    window.location.href = '/logs';
                    return;
                }
                if (res.ok) {
                    refreshLogs();
                } else {
                    alert('خطا در حذف لاگ‌ها');
                }
            } catch (e) {
                alert('خطا در برقراری ارتباط با سرور');
            }
        }
        refreshLogs();
    </script>
    ${NEXA_CONFIRM_HTML}
    ${NEXA_CONFIRM_SCRIPT}
</body>
</html>`
};