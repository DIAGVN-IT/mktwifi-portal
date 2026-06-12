import crypto from "crypto";
import express from "express";
import fetch from "node-fetch";

const app = express();
app.use(express.json({ limit: "4kb" }));

const parseRequiredPositiveInteger = (name, fallback) => {
  const raw = process.env[name];
  const value = raw === undefined || raw === "" ? String(fallback) : raw;
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`Invalid ${name}`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`Invalid ${name}`);
  }
  return parsed;
};

const parseOptionalPositiveInteger = (name) => {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return undefined;
  if (!/^[1-9][0-9]*$/.test(raw)) {
    throw new Error(`Invalid ${name}`);
  }
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`Invalid ${name}`);
  }
  return parsed;
};

const UNIFI_BASE = process.env.UNIFI_BASE;
const UNIFI_API_KEY = process.env.UNIFI_API_KEY;
const UNIFI_SITE = process.env.UNIFI_SITE || "default";
const POST_AUTH_DELAY_MS = Number.isFinite(Number(process.env.POST_AUTH_DELAY_MS)) ? Math.max(0, Number(process.env.POST_AUTH_DELAY_MS)) : 1500;
const UNIFI_REQUEST_TIMEOUT_MS = Number.isFinite(Number(process.env.UNIFI_REQUEST_TIMEOUT_MS)) ? Math.max(1, Math.floor(Number(process.env.UNIFI_REQUEST_TIMEOUT_MS))) : 5000;
const AUTHORIZE_DEADLINE_MS = Number.isFinite(Number(process.env.AUTHORIZE_DEADLINE_MS)) ? Math.max(1, Math.floor(Number(process.env.AUTHORIZE_DEADLINE_MS))) : 30000;
const CLIENT_WAIT_ATTEMPTS = parseRequiredPositiveInteger("CLIENT_WAIT_ATTEMPTS", 24);
const CLIENT_WAIT_INTERVAL_MS = parseRequiredPositiveInteger("CLIENT_WAIT_INTERVAL_MS", 250);
const SITE_CACHE_TTL_MS = parseRequiredPositiveInteger("SITE_CACHE_TTL_MS", 300000);

const AUTH_TIME_LIMIT_MINUTES = parseRequiredPositiveInteger("AUTH_TIME_LIMIT_MINUTES", 240);
const AUTH_DATA_USAGE_LIMIT_MBYTES = parseOptionalPositiveInteger("AUTH_DATA_USAGE_LIMIT_MBYTES");
const AUTH_RX_RATE_LIMIT_KBPS = parseOptionalPositiveInteger("AUTH_RX_RATE_LIMIT_KBPS");
const AUTH_TX_RATE_LIMIT_KBPS = parseOptionalPositiveInteger("AUTH_TX_RATE_LIMIT_KBPS");
const AUTH_RATE_LIMIT_WINDOW_MS = parseRequiredPositiveInteger("AUTH_RATE_LIMIT_WINDOW_MS", 60000);
const AUTH_RATE_LIMIT_MAX_PER_MAC = parseRequiredPositiveInteger("AUTH_RATE_LIMIT_MAX_PER_MAC", 10);
const AUTH_RATE_LIMIT_MAX_GLOBAL = parseRequiredPositiveInteger("AUTH_RATE_LIMIT_MAX_GLOBAL", 600);
const AUTH_RATE_LIMIT_MAX_MAC_KEYS = parseRequiredPositiveInteger("AUTH_RATE_LIMIT_MAX_MAC_KEYS", 5000);

if (!UNIFI_BASE) {
  throw new Error("Missing UNIFI_BASE");
}
if (!UNIFI_API_KEY) {
  throw new Error("Missing UNIFI_API_KEY");
}

class AppError extends Error {
  constructor(code, status = 500, fields = {}) {
    super(code);
    this.code = code;
    this.status = status;
    Object.assign(this, fields);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const isUuid = (v) =>
  typeof v === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);

const normMac = (v) => (typeof v === "string" ? v.trim().toLowerCase() : "");

const maskMac = (mac) => {
  const m = normMac(mac);
  const parts = m.split(":");
  if (parts.length !== 6) return m ? "invalid" : undefined;
  return `${parts[0]}:${parts[1]}:**:**:${parts[4]}:${parts[5]}`;
};

const nowMs = () => Date.now();

const createDeadline = (ms) => {
  const expiresAt = nowMs() + ms;
  return {
    expiresAt,
    remainingMs: () => Math.max(0, expiresAt - nowMs()),
    expired: () => nowMs() >= expiresAt
  };
};

const assertDeadline = (deadline) => {
  if (deadline && deadline.expired()) {
    throw new AppError("AUTHORIZE_TIMEOUT", 504);
  }
};

const sleepWithDeadline = async (ms, deadline) => {
  assertDeadline(deadline);
  const waitMs = deadline ? Math.min(ms, deadline.remainingMs()) : ms;
  if (waitMs > 0) await sleep(waitMs);
  assertDeadline(deadline);
};

const logJson = (level, event, fields = {}) => {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    event,
    ...fields
  };
  const line = JSON.stringify(entry);
  if (level === "error") console.error(line);
  else console.log(line);
};

const acceptedRequestId = (value) => {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 128) return null;
  if (!/^[A-Za-z0-9._:-]+$/.test(trimmed)) return null;
  return trimmed;
};

const requestIdFor = (req) => acceptedRequestId(req.get("X-Request-ID")) || crypto.randomUUID();

const publicStatusFor = (error) => {
  if (error instanceof AppError && Number.isFinite(error.status)) return error.status;
  if (error && error.code === "UPSTREAM_TIMEOUT") return 504;
  return 500;
};

const publicCodeFor = (error) => {
  if (error instanceof AppError && error.code) return error.code;
  if (error && error.code === "UPSTREAM_TIMEOUT") return "UPSTREAM_TIMEOUT";
  return "INTERNAL_ERROR";
};

const isObjectResponse = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

const validateSiteInput = (value) => {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string") throw new AppError("INVALID_SITE", 400);
  const trimmed = value.trim();
  if (!trimmed) return "";
  if (trimmed.length > 128 || !/^[A-Za-z0-9._~-]+$/.test(trimmed)) {
    throw new AppError("INVALID_SITE", 400);
  }
  return trimmed;
};

const authPolicyPayload = () => {
  const payload = { timeLimitMinutes: AUTH_TIME_LIMIT_MINUTES };
  if (AUTH_DATA_USAGE_LIMIT_MBYTES !== undefined) payload.dataUsageLimitMBytes = AUTH_DATA_USAGE_LIMIT_MBYTES;
  if (AUTH_RX_RATE_LIMIT_KBPS !== undefined) payload.rxRateLimitKbps = AUTH_RX_RATE_LIMIT_KBPS;
  if (AUTH_TX_RATE_LIMIT_KBPS !== undefined) payload.txRateLimitKbps = AUTH_TX_RATE_LIMIT_KBPS;
  return payload;
};

const macWindowCounts = new Map();
let globalWindow = { startedAt: nowMs(), count: 0 };

const retryAfterSeconds = (windowStartedAt) => Math.max(1, Math.ceil((windowStartedAt + AUTH_RATE_LIMIT_WINDOW_MS - nowMs()) / 1000));

const pruneMacWindows = (now) => {
  for (const [mac, state] of macWindowCounts.entries()) {
    if (now - state.startedAt >= AUTH_RATE_LIMIT_WINDOW_MS) {
      macWindowCounts.delete(mac);
    }
  }
};

const retryAfterSecondsForEarliestMacWindow = (now) => {
  let earliestExpiresAt = Infinity;
  for (const state of macWindowCounts.values()) {
    earliestExpiresAt = Math.min(earliestExpiresAt, state.startedAt + AUTH_RATE_LIMIT_WINDOW_MS);
  }
  if (!Number.isFinite(earliestExpiresAt)) return 1;
  return Math.max(1, Math.ceil((earliestExpiresAt - now) / 1000));
};

const checkAuthorizeRateLimit = (mac) => {
  const now = nowMs();
  if (now - globalWindow.startedAt >= AUTH_RATE_LIMIT_WINDOW_MS) {
    globalWindow = { startedAt: now, count: 0 };
  }
  globalWindow.count += 1;
  if (globalWindow.count > AUTH_RATE_LIMIT_MAX_GLOBAL) {
    return { limited: true, scope: "global", retryAfterSeconds: retryAfterSeconds(globalWindow.startedAt) };
  }

  if (!/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(mac)) return { limited: false };

  let macState = macWindowCounts.get(mac);
  if (macState && now - macState.startedAt >= AUTH_RATE_LIMIT_WINDOW_MS) {
    macWindowCounts.delete(mac);
    macState = null;
  }
  if (!macState) {
    if (macWindowCounts.size >= AUTH_RATE_LIMIT_MAX_MAC_KEYS) {
      pruneMacWindows(now);
    }
    if (macWindowCounts.size >= AUTH_RATE_LIMIT_MAX_MAC_KEYS) {
      return { limited: true, scope: "mac_keys", retryAfterSeconds: retryAfterSecondsForEarliestMacWindow(now) };
    }
    macState = { startedAt: now, count: 0 };
    macWindowCounts.set(mac, macState);
  }

  macState.count += 1;
  if (macState.count > AUTH_RATE_LIMIT_MAX_PER_MAC) {
    return { limited: true, scope: "mac", retryAfterSeconds: retryAfterSeconds(macState.startedAt) };
  }

  return { limited: false };
};

async function unifiRequest(path, { method = "GET", body = null, headers = {}, requestId, route, deadline } = {}) {
  assertDeadline(deadline);
  const url = `${UNIFI_BASE}${path}`;
  const h = {
    "X-API-KEY": UNIFI_API_KEY,
    Accept: "application/json",
    ...headers
  };

  const opts = { method, headers: h };
  if (body !== null) {
    opts.body = typeof body === "string" ? body : JSON.stringify(body);
    if (!h["Content-Type"]) {
      opts.headers["Content-Type"] = "application/json";
    }
  }

  const controller = new AbortController();
  opts.signal = controller.signal;
  const remainingMs = deadline ? deadline.remainingMs() : UNIFI_REQUEST_TIMEOUT_MS;
  const timeoutMs = Math.max(1, Math.min(UNIFI_REQUEST_TIMEOUT_MS, remainingMs || 1));
  const startedAt = nowMs();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const r = await fetch(url, opts);
    const ct = (r.headers.get("content-type") || "").toLowerCase();
    let text;

    try {
      text = await r.text();
    } catch (e) {
      if (e && e.name === "AbortError") {
        const expired = deadline && deadline.expired();
        const code = expired ? "AUTHORIZE_TIMEOUT" : "UPSTREAM_TIMEOUT";
        logJson("error", "unifi.request.timeout", {
          requestId,
          route,
          method,
          durationMs: nowMs() - startedAt,
          errorCode: code
        });
        throw new AppError(code, 504);
      }
      logJson("error", "unifi.request.error", {
        requestId,
        route,
        method,
        durationMs: nowMs() - startedAt,
        errorCode: "UPSTREAM_ERROR"
      });
      throw new AppError("UPSTREAM_ERROR", 502);
    }

    let json = null;

    if (ct.includes("application/json") && text) {
      try {
        json = JSON.parse(text);
      } catch {
        json = null;
      }
    }

    assertDeadline(deadline);

    if (!r.ok) {
      logJson("error", "unifi.request.error", {
        requestId,
        route,
        method,
        durationMs: nowMs() - startedAt,
        status: r.status,
        errorCode: "UPSTREAM_ERROR"
      });
      throw new AppError("UPSTREAM_ERROR", 502, { upstreamStatus: r.status });
    }

    return json ?? (text ? text : null);
  } catch (e) {
    if (e instanceof AppError) throw e;
    if (e && e.name === "AbortError") {
      const expired = deadline && deadline.expired();
      const code = expired ? "AUTHORIZE_TIMEOUT" : "UPSTREAM_TIMEOUT";
      logJson("error", "unifi.request.timeout", {
        requestId,
        route,
        method,
        durationMs: nowMs() - startedAt,
        errorCode: code
      });
      throw new AppError(code, 504);
    }
    logJson("error", "unifi.request.error", {
      requestId,
      route,
      method,
      durationMs: nowMs() - startedAt,
      errorCode: "UPSTREAM_ERROR"
    });
    throw new AppError("UPSTREAM_ERROR", 502);
  } finally {
    clearTimeout(timeout);
  }
}

async function getSites(context = {}) {
  const j = await unifiRequest("/proxy/network/integration/v1/sites", context);
  if (!isObjectResponse(j) || !Array.isArray(j.data)) {
    throw new AppError("UPSTREAM_ERROR", 502);
  }
  return j.data;
}

const siteResolutionCache = new Map();

const cacheSiteRef = (ref, siteId, expiresAt) => {
  if (typeof ref === "string" && ref && typeof siteId === "string" && siteId && !siteResolutionCache.has(ref)) {
    siteResolutionCache.set(ref, { siteId, expiresAt });
  }
};

const refreshSiteResolutionCache = (sites, expiresAt) => {
  siteResolutionCache.clear();
  for (const s of sites) {
    if (!s || typeof s.id !== "string" || !s.id) continue;
    cacheSiteRef(s.id, s.id, expiresAt);
    cacheSiteRef(s.internalReference, s.id, expiresAt);
    cacheSiteRef(s.name, s.id, expiresAt);
  }
};

async function resolveSiteId(siteRef, context = {}) {
  const ref = siteRef || UNIFI_SITE;
  if (isUuid(ref)) return { siteId: ref, cacheHit: false, source: "uuid" };

  const cached = siteResolutionCache.get(ref);
  if (cached) {
    if (cached.expiresAt > nowMs()) {
      return { siteId: cached.siteId, cacheHit: true, source: "cache" };
    }
    siteResolutionCache.delete(ref);
  }

  const sites = await getSites(context);
  const expiresAt = nowMs() + SITE_CACHE_TTL_MS;
  refreshSiteResolutionCache(sites, expiresAt);
  const hit = sites.find(
    (s) =>
      s &&
      typeof s.id === "string" &&
      s.id &&
      (s.id === ref ||
        (typeof s.internalReference === "string" && s.internalReference === ref) ||
        (typeof s.name === "string" && s.name === ref))
  );

  if (!hit || !hit.id) {
    throw new AppError("SITE_NOT_FOUND", 404);
  }
  return { siteId: hit.id, cacheHit: false, source: "upstream" };
}

async function findClientByMac(siteId, mac, context = {}) {
  const m = normMac(mac);
  const j = await unifiRequest(`/proxy/network/integration/v1/sites/${siteId}/clients?filter=macAddress.eq('${m}')`, context);
  if (!isObjectResponse(j) || !Array.isArray(j.data)) {
    throw new AppError("UPSTREAM_ERROR", 502);
  }
  return j.data.length ? j.data[0] : null;
}

const clientLookupMetrics = (startedAt, attempts) => ({
  attempts,
  durationMs: nowMs() - startedAt
});

const attachClientLookupMetrics = (error, metrics) => {
  if (error && typeof error === "object") {
    error.clientLookupMetrics = metrics;
  }
  throw error;
};

async function waitForClientId(siteId, mac, { deadline, requestId, route } = {}) {
  const startedAt = nowMs();
  let lookupAttempts = 0;
  try {
    for (let i = 0; i < CLIENT_WAIT_ATTEMPTS; i += 1) {
      assertDeadline(deadline);
      lookupAttempts += 1;
      const c = await findClientByMac(siteId, mac, { requestId, route, deadline });
      if (c && c.id) return { clientId: c.id, ...clientLookupMetrics(startedAt, lookupAttempts) };
      if (i < CLIENT_WAIT_ATTEMPTS - 1) await sleepWithDeadline(CLIENT_WAIT_INTERVAL_MS, deadline);
    }
    return { clientId: null, ...clientLookupMetrics(startedAt, lookupAttempts) };
  } catch (e) {
    attachClientLookupMetrics(e, clientLookupMetrics(startedAt, lookupAttempts));
  }
}

const strictMacRe = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;
async function authorizeClient(siteId, clientId, opts, context = {}) {
  const payload = { action: "AUTHORIZE_GUEST_ACCESS", ...opts };

  return await unifiRequest(`/proxy/network/integration/v1/sites/${siteId}/clients/${clientId}/actions`, {
    ...context,
    method: "POST",
    body: payload
  });
}

async function findClientAcrossSites(mac, { deadline, requestId, route } = {}) {
  const startedAt = nowMs();
  let lookupAttempts = 0;
  try {
    const sites = await getSites({ requestId, route, deadline });
    for (let attempt = 0; attempt < CLIENT_WAIT_ATTEMPTS; attempt += 1) {
      assertDeadline(deadline);
      for (const s of sites) {
        assertDeadline(deadline);
        if (!s || !s.id) continue;
        lookupAttempts += 1;
        try {
          const c = await findClientByMac(s.id, mac, { requestId, route, deadline });
          if (c && c.id) {
            return { siteId: s.id, clientId: c.id, ...clientLookupMetrics(startedAt, lookupAttempts) };
          }
        } catch (e) {
          logJson("error", "fallback.site_lookup_error", {
            requestId,
            route,
            siteId: s.id,
            maskedMac: maskMac(mac),
            errorCode: publicCodeFor(e),
            status: publicStatusFor(e)
          });
          assertDeadline(deadline);
        }
      }
      if (attempt < CLIENT_WAIT_ATTEMPTS - 1) await sleepWithDeadline(CLIENT_WAIT_INTERVAL_MS, deadline);
    }
    return { siteId: null, clientId: null, ...clientLookupMetrics(startedAt, lookupAttempts) };
  } catch (e) {
    attachClientLookupMetrics(e, clientLookupMetrics(startedAt, lookupAttempts));
  }
}

const readinessHandler = async (req, res) => {
  const requestId = requestIdFor(req);
  res.set("X-Request-ID", requestId);
  const startedAt = nowMs();
  const route = req.path;
  try {
    await getSites({ requestId, route });
    logJson("info", "health.ready.success", {
      requestId,
      route,
      method: req.method,
      durationMs: nowMs() - startedAt,
      status: 200
    });
    res.json({ ok: true });
  } catch (e) {
    const status = publicStatusFor(e);
    const errorCode = publicCodeFor(e) === "AUTHORIZE_TIMEOUT" ? "UPSTREAM_TIMEOUT" : publicCodeFor(e);
    logJson("error", "health.ready.error", {
      requestId,
      route,
      method: req.method,
      durationMs: nowMs() - startedAt,
      status,
      errorCode
    });
    res.status(status).json({ ok: false, error: errorCode });
  }
};

app.get("/api/health/live", (_req, res) => {
  res.json({ ok: true });
});

app.get("/api/health/ready", readinessHandler);

app.get("/api/health", readinessHandler);

app.post("/api/authorize", async (req, res) => {
  const requestId = requestIdFor(req);
  res.set("X-Request-ID", requestId);
  const startedAt = nowMs();
  const deadline = createDeadline(AUTHORIZE_DEADLINE_MS);
  const route = req.path;
  const mac = normMac(req.body && req.body.mac);
  let siteRef = "";
  let siteId = null;
  let clientId = null;
  let siteCacheHit = null;
  let siteResolveSource = null;
  let siteResolveDurationMs = null;
  let clientLookupAttempts = null;
  let clientLookupDurationMs = null;
  let authorizeActionDurationMs = null;
  const assignLookupMetrics = (lookup) => {
    clientLookupAttempts = lookup.attempts;
    clientLookupDurationMs = lookup.durationMs;
  };

  logJson("info", "authorize.start", {
    requestId,
    route,
    method: req.method,
    maskedMac: maskMac(mac)
  });

  const rateLimit = checkAuthorizeRateLimit(mac);
  if (rateLimit.limited) {
    const validMac = strictMacRe.test(mac);
    res.set("Retry-After", String(rateLimit.retryAfterSeconds));
    logJson("info", "authorize.rate_limited", {
      requestId,
      route,
      method: req.method,
      maskedMac: validMac ? maskMac(mac) : undefined,
      durationMs: nowMs() - startedAt,
      status: 429,
      errorCode: "RATE_LIMITED",
      rateLimitScope: rateLimit.scope,
      retryAfterSeconds: rateLimit.retryAfterSeconds
    });
    return res.status(429).json({ ok: false, error: "RATE_LIMITED" });
  }

  try {
    siteRef = validateSiteInput(req.body && req.body.site);

    if (!mac || !strictMacRe.test(mac)) {
      logJson("info", "authorize.error", {
        requestId,
        route,
        method: req.method,
        maskedMac: maskMac(mac),
        durationMs: nowMs() - startedAt,
        status: 400,
        errorCode: "INVALID_MAC"
      });
      return res.status(400).json({ ok: false, error: "INVALID_MAC" });
    }

    if (siteRef) {
      const siteResolveStartedAt = nowMs();
      let siteResolution;
      try {
        siteResolution = await resolveSiteId(siteRef, { requestId, route, deadline });
      } finally {
        siteResolveDurationMs = nowMs() - siteResolveStartedAt;
      }
      siteId = siteResolution.siteId;
      siteCacheHit = siteResolution.cacheHit;
      siteResolveSource = siteResolution.source;

      const lookup = await waitForClientId(siteId, mac, { deadline, requestId, route });
      clientId = lookup.clientId;
      assignLookupMetrics(lookup);
    } else {
      const lookup = await findClientAcrossSites(mac, { deadline, requestId, route });
      siteId = lookup.siteId;
      clientId = lookup.clientId;
      assignLookupMetrics(lookup);
    }

    if (!siteId || !clientId) {
      logJson("info", "authorize.client_not_found", {
        requestId,
        route,
        method: req.method,
        siteRef,
        siteId,
        maskedMac: maskMac(mac),
        durationMs: nowMs() - startedAt,
        status: 404,
        errorCode: "CLIENT_NOT_FOUND",
        siteCacheHit,
        siteResolveSource,
        siteResolveDurationMs,
        clientLookupAttempts,
        clientLookupDurationMs
      });
      return res.status(404).json({ ok: false, error: "CLIENT_NOT_FOUND" });
    }

    const authorizeOnce = async (id) => {
      const authorizeActionStartedAt = nowMs();
      try {
        await authorizeClient(siteId, id, authPolicyPayload(), { requestId, route, deadline });
      } finally {
        authorizeActionDurationMs = nowMs() - authorizeActionStartedAt;
      }
    };

    await authorizeOnce(clientId);

    if (POST_AUTH_DELAY_MS > 0) await sleepWithDeadline(POST_AUTH_DELAY_MS, deadline);

    logJson("info", "authorize.success", {
      requestId,
      route,
      method: req.method,
      siteRef,
      siteId,
      maskedMac: maskMac(mac),
      durationMs: nowMs() - startedAt,
      status: 200,
      siteCacheHit,
      siteResolveSource,
      siteResolveDurationMs,
      clientLookupAttempts,
      clientLookupDurationMs,
      authorizeActionDurationMs
    });
    res.json({ ok: true });
  } catch (e) {
    if (e && typeof e === "object" && e.clientLookupMetrics) {
      clientLookupAttempts = clientLookupAttempts ?? e.clientLookupMetrics.attempts;
      clientLookupDurationMs = clientLookupDurationMs ?? e.clientLookupMetrics.durationMs;
    }
    const expired = deadline.expired() || publicCodeFor(e) === "AUTHORIZE_TIMEOUT";
    const status = expired ? 504 : publicStatusFor(e);
    const errorCode = expired ? "AUTHORIZE_TIMEOUT" : publicCodeFor(e);
    logJson("error", expired ? "authorize.timeout" : "authorize.error", {
      requestId,
      route,
      method: req.method,
      siteRef,
      maskedMac: maskMac(mac),
      durationMs: nowMs() - startedAt,
      status,
      errorCode,
      siteCacheHit,
      siteResolveSource,
      siteResolveDurationMs,
      clientLookupAttempts,
      clientLookupDurationMs,
      authorizeActionDurationMs
    });
    res.status(status).json({ ok: false, error: errorCode });
  }
});

app.use((err, _req, res, next) => {
  if (!err) return next();
  if (err.type === "entity.too.large") {
    return res.status(413).json({ ok: false, error: "PAYLOAD_TOO_LARGE" });
  }
  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    return res.status(400).json({ ok: false, error: "INVALID_JSON" });
  }
  return next(err);
});

app.listen(3000, "0.0.0.0");
