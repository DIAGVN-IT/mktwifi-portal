import express from "express";
import fetch from "node-fetch";

const app = express();
app.use(express.json());

const UNIFI_BASE = process.env.UNIFI_BASE;
const UNIFI_API_KEY = process.env.UNIFI_API_KEY;
const UNIFI_SITE = process.env.UNIFI_SITE || "default";
const POST_AUTH_DELAY_MS = Number.isFinite(Number(process.env.POST_AUTH_DELAY_MS)) ? Math.max(0, Number(process.env.POST_AUTH_DELAY_MS)) : 1500;
const CLIENT_WAIT_ATTEMPTS = Number.isFinite(Number(process.env.CLIENT_WAIT_ATTEMPTS)) ? Math.max(1, Math.floor(Number(process.env.CLIENT_WAIT_ATTEMPTS))) : 45;
const CLIENT_WAIT_INTERVAL_MS = Number.isFinite(Number(process.env.CLIENT_WAIT_INTERVAL_MS)) ? Math.max(100, Math.floor(Number(process.env.CLIENT_WAIT_INTERVAL_MS))) : 1000;

if (!UNIFI_BASE) {
  throw new Error("Missing UNIFI_BASE");
}
if (!UNIFI_API_KEY) {
  throw new Error("Missing UNIFI_API_KEY");
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const isUuid = (v) =>
  typeof v === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);

const normMac = (v) => (typeof v === "string" ? v.trim().toLowerCase() : "");

async function unifiRequest(path, { method = "GET", body = null, headers = {} } = {}) {
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

  const r = await fetch(url, opts);
  const ct = (r.headers.get("content-type") || "").toLowerCase();
  const text = await r.text();
  let json = null;

  if (ct.includes("application/json") && text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
  }

  if (!r.ok) {
    const msg = (json && (json.message || json.statusName || json.code)) || text || `HTTP ${r.status}`;
    const err = new Error(msg);
    err.status = r.status;
    err.body = json || text;
    throw err;
  }

  return json ?? (text ? text : null);
}

async function getSites() {
  const j = await unifiRequest("/proxy/network/integration/v1/sites");
  return j && j.data ? j.data : [];
}

async function resolveSiteId(siteRef) {
  const ref = siteRef || UNIFI_SITE;
  if (isUuid(ref)) return ref;

  const sites = await getSites();
  const hit = sites.find(
    (s) =>
      (typeof s.internalReference === "string" && s.internalReference === ref) ||
      (typeof s.name === "string" && s.name === ref)
  );

  if (!hit || !hit.id) {
    throw new Error("Site not found");
  }
  return hit.id;
}

async function findClientByMac(siteId, mac) {
  const m = normMac(mac);
  const j = await unifiRequest(`/proxy/network/integration/v1/sites/${siteId}/clients?filter=macAddress.eq('${m}')`);
  const list = j && j.data ? j.data : [];
  return list.length ? list[0] : null;
}

async function waitForClientId(siteId, mac, { attempts = CLIENT_WAIT_ATTEMPTS, intervalMs = CLIENT_WAIT_INTERVAL_MS } = {}) {
  for (let i = 0; i < attempts; i += 1) {
    const c = await findClientByMac(siteId, mac);
    if (c && c.id) return c.id;
    await sleep(intervalMs);
  }
  return null;
}

async function authorizeClient(siteId, clientId, opts) {
  const payload = { action: "AUTHORIZE_GUEST_ACCESS" };

  if (opts && Number.isFinite(opts.timeLimitMinutes)) payload.timeLimitMinutes = opts.timeLimitMinutes;
  if (opts && Number.isFinite(opts.dataUsageLimitMBytes)) payload.dataUsageLimitMBytes = opts.dataUsageLimitMBytes;
  if (opts && Number.isFinite(opts.rxRateLimitKbps)) payload.rxRateLimitKbps = opts.rxRateLimitKbps;
  if (opts && Number.isFinite(opts.txRateLimitKbps)) payload.txRateLimitKbps = opts.txRateLimitKbps;

  return await unifiRequest(`/proxy/network/integration/v1/sites/${siteId}/clients/${clientId}/actions`, {
    method: "POST",
    body: payload
  });
}

async function findClientAcrossSites(mac) {
  const sites = await getSites();
  for (const s of sites) {
    if (!s || !s.id) continue;
    try {
      const id = await waitForClientId(s.id, mac);
      if (id) return { siteId: s.id, clientId: id };
    } catch (_) {}
  }
  return null;
}

app.get("/api/health", async (_req, res) => {
  try {
    const sites = await getSites();
    res.json({ ok: true, sites: sites.map((x) => ({ id: x.id, internalReference: x.internalReference, name: x.name })) });
  } catch (e) {
    const status = e && e.status ? e.status : 500;
    res.status(status).json({ ok: false, error: e.message || "ERROR", detail: e.body || null });
  }
});

app.post("/api/authorize", async (req, res) => {
  try {
    const mac = normMac(req.body && req.body.mac);
    const siteRef = req.body && req.body.site;
    const minutesRaw = req.body && req.body.minutes;

    if (!mac || !/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(mac)) {
      return res.status(400).json({ ok: false, error: "INVALID_MAC" });
    }

    const minutes = Number.isFinite(Number(minutesRaw)) ? Math.max(1, Math.floor(Number(minutesRaw))) : 720;

    let siteId = null;
    let clientId = null;

    if (siteRef) {
      siteId = await resolveSiteId(siteRef);
      clientId = await waitForClientId(siteId, mac);
    } else {
      const r = await findClientAcrossSites(mac);
      if (r) {
        siteId = r.siteId;
        clientId = r.clientId;
      }
    }

    if (!siteId || !clientId) {
      return res.status(404).json({ ok: false, error: "CLIENT_NOT_FOUND" });
    }

    const granted = await authorizeClient(siteId, clientId, {
      timeLimitMinutes: minutes,
      dataUsageLimitMBytes: req.body && Number.isFinite(Number(req.body.dataUsageLimitMBytes)) ? Number(req.body.dataUsageLimitMBytes) : undefined,
      rxRateLimitKbps: req.body && Number.isFinite(Number(req.body.rxRateLimitKbps)) ? Number(req.body.rxRateLimitKbps) : undefined,
      txRateLimitKbps: req.body && Number.isFinite(Number(req.body.txRateLimitKbps)) ? Number(req.body.txRateLimitKbps) : undefined
    });

    if (POST_AUTH_DELAY_MS > 0) await sleep(POST_AUTH_DELAY_MS);

    res.json({ ok: true, siteId, clientId, result: granted, postAuthDelayMs: POST_AUTH_DELAY_MS });
  } catch (e) {
    const status = e && e.status ? e.status : 500;
    res.status(status).json({ ok: false, error: e.message || "ERROR", detail: e.body || null });
  }
});

app.listen(3000, "0.0.0.0");
