// LOLDrivers + HijackLibs threat intelligence — fetched server-side and cached.
// Used by the detection engine to match collected artifacts (Amcache driver/DLL
// entries) against known-vulnerable/malicious drivers and DLL-hijacking targets.
//
// Data sources (server reaches them; the browser is blocked by CORS/CSP):
//   - https://www.loldrivers.io/api/drivers.json   (~30 MB, thousands of samples)
//   - https://hijacklibs.net/api/hijacklibs.json   (~1 MB)
const https = require('https');
const logger = require('../config/logger').default;

const TTL_MS = 24 * 60 * 60 * 1000; // refresh datasets at most once a day

function httpsGetJson(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'Heimdall-DFIR' } }, (res) => {
      const sc = res.statusCode || 0;
      if (sc >= 300 && sc < 400 && res.headers.location) {
        res.resume();
        return httpsGetJson(res.headers.location).then(resolve, reject);
      }
      if (sc !== 200) { res.resume(); return reject(new Error('HTTP ' + sc)); }
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { data += c; });
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch (e) { reject(e); } });
    }).on('error', reject);
  });
}

const hex = (s) => String(s || '').replace(/[^a-fA-F0-9]/g, '').toLowerCase();
// Amcache DriverId / FileId is sometimes prefixed (e.g. "0000" + SHA1). Keep the
// trailing 40 (SHA1) / 64 (SHA256) hex chars.
function normHash(s) {
  const h = hex(s);
  if (h.length > 64) return h.slice(-64);
  if (h.length === 44) return h.slice(-40); // 0000 + sha1
  return h;
}

let driverCache = { at: 0, index: null, building: null };

async function buildDriverIndex() {
  const drivers = await httpsGetJson('https://www.loldrivers.io/api/drivers.json');
  const sha = new Set();          // sha256 + sha1 + md5 (all lowercased hex)
  const names = new Map();        // filename -> { category, mitre }
  for (const d of (Array.isArray(drivers) ? drivers : [])) {
    const meta = { category: d.Category || 'vulnerable driver', mitre: d.MitreID || null };
    for (const t of (d.Tags || [])) { const n = String(t).toLowerCase(); if (n.endsWith('.sys')) names.set(n, meta); }
    for (const s of (d.KnownVulnerableSamples || [])) {
      for (const f of [s.SHA256, s.SHA1, s.MD5]) { const h = hex(f); if (h.length >= 32) sha.add(h); }
      const fn = String(s.Filename || '').toLowerCase();
      if (fn.endsWith('.sys')) names.set(fn, meta);
    }
  }
  logger.info(`[loldrivers] index built: ${sha.size} hashes, ${names.size} filenames`);
  return { sha, names };
}

async function getDriverIndex() {
  if (driverCache.index && Date.now() - driverCache.at < TTL_MS) return driverCache.index;
  if (driverCache.building) return driverCache.building;
  driverCache.building = buildDriverIndex()
    .then((idx) => { driverCache = { at: Date.now(), index: idx, building: null }; return idx; })
    .catch((e) => { driverCache.building = null; logger.error('[loldrivers] fetch failed:', e.message); throw e; });
  return driverCache.building;
}

let hijackCache = { at: 0, index: null, building: null };

async function buildHijackIndex() {
  const libs = await httpsGetJson('https://hijacklibs.net/api/hijacklibs.json');
  const byName = new Map(); // dllname -> { expected:[lowercased loc substrings], vendor }
  for (const l of (Array.isArray(libs) ? libs : [])) {
    const name = String(l.Name || '').toLowerCase();
    if (!name.endsWith('.dll')) continue;
    const expected = (l.ExpectedLocations || []).map((p) => String(p).toLowerCase()
      .replace(/%programfiles%/g, 'program files').replace(/%systemroot%/g, 'windows')
      .replace(/%windir%/g, 'windows').replace(/%system32%/g, 'system32').replace(/\\/g, '\\'));
    byName.set(name, { expected, vendor: l.Vendor || null });
  }
  logger.info(`[hijacklibs] index built: ${byName.size} DLLs`);
  return byName;
}

async function getHijackIndex() {
  if (hijackCache.index && Date.now() - hijackCache.at < TTL_MS) return hijackCache.index;
  if (hijackCache.building) return hijackCache.building;
  hijackCache.building = buildHijackIndex()
    .then((idx) => { hijackCache = { at: Date.now(), index: idx, building: null }; return idx; })
    .catch((e) => { hijackCache.building = null; logger.error('[hijacklibs] fetch failed:', e.message); throw e; });
  return hijackCache.building;
}

// Sysmon EID 6 (Driver Loaded) carries the path in ImageLoaded and hashes as a
// pipe-delimited string like "SHA1=<hex>|MD5=<hex>|SHA256=<hex>,IMPHASH=<hex>".
// Pull the SHA1 (falls back to SHA256/MD5) so runtime driver loads can be
// matched the same way as Amcache inventory rows.
function extractEvtxHash(hashes) {
  const s = String(hashes || '');
  const m = s.match(/SHA1=([a-fA-F0-9]+)/) || s.match(/SHA256=([a-fA-F0-9]+)/) || s.match(/MD5=([a-fA-F0-9]+)/);
  return m ? m[1] : '';
}

// Match Amcache driver rows (or Sysmon EID 6 runtime driver-load rows) against
// LOLDrivers. Hash match = high confidence; filename-only match = medium (a
// legitimate driver can share a name).
function matchDrivers(rows, index) {
  const out = [];
  for (const r of rows) {
    const raw = r.raw || {};
    const id = normHash(raw.DriverId || raw.FileId || raw.SHA1 || raw.sha1 || extractEvtxHash(raw.Hashes));
    const imageLoaded = String(raw.ImageLoaded || '').toLowerCase();
    const imageName = imageLoaded ? imageLoaded.split(/[\\/]/).pop() : '';
    const name = String(raw.DriverName || raw.Name || '').toLowerCase() || imageName;
    let hit = null;
    if (id && index.sha.has(id)) hit = { confidence: 'high', reason: 'hash' };
    else if (name && index.names.has(name)) hit = { confidence: 'medium', reason: 'nom' };
    if (!hit) continue;
    const meta = index.names.get(name) || {};
    out.push({
      timestamp: r.timestamp, artifact_type: r.artifact_type, host_name: r.host_name,
      description: `${raw.DriverName || raw.ImageLoaded || name} — ${hit.reason === 'hash' ? 'hash LOLDrivers' : 'nom LOLDrivers'}${meta.category ? ' (' + meta.category + ')' : ''}`,
      source: raw.KeyName || raw.DriverName || raw.ImageLoaded || name,
      severity: hit.reason === 'hash' ? 'CRITIQUE' : 'ÉLEVÉ',
      confidence: hit.confidence, mitre: meta.mitre || 'T1068',
      raw: { ...raw, _match: hit.reason },
    });
  }
  return out;
}

// Match Amcache/MFT DLL rows against HijackLibs: a known-hijackable DLL name found
// in a path that is NOT one of its expected locations.
function matchHijack(rows, index) {
  const out = [];
  for (const r of rows) {
    const raw = r.raw || {};
    const path = String(raw.path || raw.FullPath || raw.KeyName || r.source || r.description || '').toLowerCase();
    const m = path.match(/([a-z0-9_.-]+\.dll)/);
    if (!m) continue;
    const name = m[1];
    const entry = index.get(name);
    if (!entry) continue;
    const expected = entry.expected.length
      ? entry.expected.some((loc) => loc && path.includes(loc.split('\\').pop()))
      : /\\(system32|syswow64|winsxs)\\|\\program files/.test(path);
    if (expected) continue; // in a legitimate location → not a hijack
    out.push({
      timestamp: r.timestamp, artifact_type: r.artifact_type, host_name: r.host_name,
      description: `${name} hors emplacement attendu${entry.vendor ? ' (' + entry.vendor + ')' : ''}`,
      source: path, severity: 'ÉLEVÉ', confidence: 'medium', mitre: 'T1574.001',
      raw,
    });
  }
  return out;
}

module.exports = { getDriverIndex, getHijackIndex, matchDrivers, matchHijack };
