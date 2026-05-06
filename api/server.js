import express from "express";
import fetch from "node-fetch";
import fs from "fs";


const app = express();
app.use(express.json());

const UNIFI_BASE = process.env.UNIFI_BASE;
const UNIFI_API_KEY = process.env.UNIFI_API_KEY;
const UNIFI_SITE = process.env.UNIFI_SITE || "default";
const POST_AUTH_DELAY_MS = Number.isFinite(Number(process.env.POST_AUTH_DELAY_MS)) ? Math.max(0, Number(process.env.POST_AUTH_DELAY_MS)) : 1500;
const BRANCH_MAP_PATH = process.env.BRANCH_MAP_PATH || "/app/branch-map.json";

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

function safeInt(v, fallback) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.floor(n) : fallback;
}

function normText(v) {
  return typeof v === "string" ? v.trim() : "";
}

function readBranchMap() {
  try {
    const raw = fs.readFileSync(BRANCH_MAP_PATH, "utf8");
    const parsed = JSON.parse(raw);
    const def = parsed && parsed.default && typeof parsed.default === "object" ? parsed.default : {};
    const branches = Array.isArray(parsed && parsed.branches) ? parsed.branches : [];
    return { default: def, branches };
  } catch (e) {
    return {
      default: {
        key: "default",
        name: "Default",
        bannerUrl: "/bg.jpg",
        redirectUrl: "http://diag.vn/",
        minutes: 720
      },
      branches: []
    };
  }
}

function findFirstString(obj, keys) {
  if (!obj || typeof obj !== "object") return "";
  for (const key of keys) {
    const v = obj[key];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return "";
}

function extractApInfo(client, apFromQuery) {
  const directMac = normMac(apFromQuery) || normMac(findFirstString(client, [
    "apMacAddress",
    "accessPointMacAddress",
    "accessPointMac",
    "uplinkMacAddress",
    "uplinkDeviceMacAddress",
    "connectedDeviceMacAddress"
  ]));

  const directName = normText(findFirstString(client, [
    "accessPointName",
    "apName",
    "uplinkDeviceName",
    "connectedDeviceName"
  ]));

  const nestedObjects = [
    client && client.accessPoint,
    client && client.uplink,
    client && client.uplinkDevice,
    client && client.connectedDevice,
    client && client.device
  ];

  let nestedMac = "";
  let nestedName = "";

  for (const item of nestedObjects) {
    if (!item || typeof item !== "object") continue;
    if (!nestedMac) nestedMac = normMac(findFirstString(item, ["macAddress", "mac", "id"]));
    if (!nestedName) nestedName = normText(findFirstString(item, ["name", "displayName"]));
  }

  return {
    apMac: directMac || nestedMac,
    apName: directName || nestedName
  };
}

function normalizeBranch(branch) {
  const minutes = safeInt(branch && branch.minutes, 720);
  return {
    key: normText(branch && branch.key) || "default",
    name: normText(branch && branch.name) || normText(branch && branch.key) || "Default",
    bannerUrl: normText(branch && branch.bannerUrl) || "/bg.jpg",
    redirectUrl: normText(branch && branch.redirectUrl) || "http://diag.vn/",
    minutes: Math.max(1, minutes)
  };
}

function matchBranch(apInfo) {
  const branchMap = readBranchMap();
  const apMac = normMac(apInfo && apInfo.apMac);
  const apName = normText(apInfo && apInfo.apName).toLowerCase();

  for (const branch of branchMap.branches) {
    const apMacs = Array.isArray(branch.apMacs) ? branch.apMacs.map(normMac).filter(Boolean) : [];
    const apNames = Array.isArray(branch.apNames) ? branch.apNames.map((x) => normText(x).toLowerCase()).filter(Boolean) : [];

    if (apMac && apMacs.includes(apMac)) return normalizeBranch(branch);
    if (apName && apNames.includes(apName)) return normalizeBranch(branch);
  }

  return normalizeBranch(branchMap.default);
}

async function getClientForContext(siteRef, mac) {
  const m = normMac(mac);
  if (!m || !/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(m)) {
    return { siteId: null, client: null };
  }

  if (siteRef) {
    const siteId = await resolveSiteId(siteRef);
    const client = await findClientByMac(siteId, m);
    return { siteId, client };
  }

  const sites = await getSites();
  for (const s of sites) {
    if (!s || !s.id) continue;
    try {
      const client = await findClientByMac(s.id, m);
      if (client) return { siteId: s.id, client };
    } catch (_) {}
  }

  return { siteId: null, client: null };
}

async function buildPortalContext({ siteRef, mac, ap }) {
  const clientLookup = await getClientForContext(siteRef, mac);
  const apInfo = extractApInfo(clientLookup.client, ap);
  const branch = matchBranch(apInfo);

  return {
    ok: true,
    siteId: clientLookup.siteId,
    clientFound: !!clientLookup.client,
    clientId: clientLookup.client && clientLookup.client.id ? clientLookup.client.id : null,
    apMac: apInfo.apMac || normMac(ap),
    apName: apInfo.apName || "",
    branch
  };
}


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

async function waitForClientId(siteId, mac, { attempts = 24, intervalMs = 250 } = {}) {
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


app.get("/api/portal-context", async (req, res) => {
  try {
    const mac = normMac(req.query && req.query.mac);
    const ap = normMac(req.query && req.query.ap);
    const siteRef = req.query && req.query.site ? String(req.query.site) : "";

    const ctx = await buildPortalContext({ siteRef, mac, ap });
    res.json(ctx);
  } catch (e) {
    const fallback = normalizeBranch(readBranchMap().default);
    const status = e && e.status ? e.status : 200;
    res.status(status).json({ ok: false, error: e.message || "ERROR", branch: fallback });
  }
});

app.get("/api/debug-client", async (req, res) => {
  try {
    const mac = normMac(req.query && req.query.mac);
    const ap = normMac(req.query && req.query.ap);
    const siteRef = req.query && req.query.site ? String(req.query.site) : "";

    if (!mac || !/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(mac)) {
      return res.status(400).json({ ok: false, error: "INVALID_MAC" });
    }

    const clientLookup = await getClientForContext(siteRef, mac);
    const apInfo = extractApInfo(clientLookup.client, ap);
    const branch = matchBranch(apInfo);

    res.json({
      ok: true,
      siteId: clientLookup.siteId,
      apFromQuery: ap,
      extractedAp: apInfo,
      matchedBranch: branch,
      client: clientLookup.client
    });
  } catch (e) {
    const status = e && e.status ? e.status : 500;
    res.status(status).json({ ok: false, error: e.message || "ERROR", detail: e.body || null });
  }
});

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
    const ap = req.body && req.body.ap;

    if (!mac || !/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(mac)) {
      return res.status(400).json({ ok: false, error: "INVALID_MAC" });
    }

    const portalContext = await buildPortalContext({ siteRef, mac, ap });
    const branchMinutes = portalContext && portalContext.branch && Number.isFinite(Number(portalContext.branch.minutes)) ? Number(portalContext.branch.minutes) : 720;
    const minutes = Number.isFinite(Number(minutesRaw)) ? Math.max(1, Math.floor(Number(minutesRaw))) : Math.max(1, Math.floor(branchMinutes));

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

    res.json({ ok: true, siteId, clientId, branch: portalContext.branch, result: granted, postAuthDelayMs: POST_AUTH_DELAY_MS });
  } catch (e) {
    const status = e && e.status ? e.status : 500;
    res.status(status).json({ ok: false, error: e.message || "ERROR", detail: e.body || null });
  }
});

app.listen(3000, "0.0.0.0");
