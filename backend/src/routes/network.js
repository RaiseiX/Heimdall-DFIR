const express = require('express');
const multer = require('multer');
const { pool } = require('../config/database');
const { authenticate, requireRole } = require('../middleware/auth');
const { parse: parseCsv } = require('csv-parse/sync');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

function isInternalIP(ip) {
  const s = (ip || '').replace(/^::ffff:/i, '').replace(/:\d+$/, '');
  // ── IPv6 special ──────────────────────────────────────────────────────
  if (s === '::1')                        return true; // loopback
  if (/^fe[89ab][0-9a-f]:/i.test(s))     return true; // link-local fe80::/10
  if (/^f[cd][0-9a-f]{2}:/i.test(s))     return true; // ULA fc00::/7
  // ── IPv4 private + special ────────────────────────────────────────────
  return (
    /^10\./.test(s)                                                      || // RFC1918 /8
    /^172\.(1[6-9]|2\d|3[01])\./.test(s)                                || // RFC1918 /12
    /^192\.168\./.test(s)                                                || // RFC1918 /16
    /^127\./.test(s)                                                     || // loopback /8
    /^169\.254\./.test(s)                                                || // APIPA link-local /16
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(s)                 || // CGN RFC6598 /10
    /^(22[4-9]|23\d)\./.test(s)                                         || // multicast /4
    /^0\.0\.0\.0$/.test(s)                                              || // unspecified
    /^255\.255\.255\.255$/.test(s)                                          // broadcast
  );
}

// Extract IP from "NAME (IP)" format like "LAB (127.0.0.1)" or "ROWENA (192.168.1.4)"
function extractParenIP(id) {
  const m = String(id || '').match(/\((\d+\.\d+\.\d+\.\d+)\)/);
  return m ? m[1] : null;
}

const PRIVATE_TLD = /\.(lab|local|lan|corp|internal|intranet|home|localdomain|test|priv)$/i;

const logger = require('../config/logger').default;
const geoip  = require('geoip-lite');
const router = express.Router();

const { caseAccessParam } = require('../middleware/caseAccess');
router.use(authenticate);
router.param('caseId', caseAccessParam);

// ── OS fingerprint from port evidence ────────────────────────────────────────
function computeOsHint(ports) {
  const p = new Set((ports || []).map(Number));
  const win = (p.has(445)?60:0) + (p.has(135)?40:0) + (p.has(3389)?40:0) +
              (p.has(88)?30:0)  + ((p.has(5985)||p.has(5986))?50:0) +
              (p.has(139)?25:0) + ((p.has(137)||p.has(138))?15:0);
  const lin = (p.has(22)?50:0) + (p.has(111)?40:0) + (p.has(2049)?40:0) + (p.has(631)?25:0);
  const net = ((p.has(161)||p.has(162))?60:0) + (p.has(179)?75:0) +
              ((p.has(520)||p.has(521))?50:0) + ((p.has(1812)||p.has(1813))?45:0);
  const max = Math.max(win, lin, net);
  if (max < 40) return null;
  if (net === max && net >= 60) return 'network_device';
  if (win === max && win >= 60) return 'windows';
  if (lin === max && lin >= 50) return 'linux';
  return null;
}

// ── Enrich nodeMap with ports, degrees, os_hint, geo (mutates in place) ──────
function enrichNodes(nodeMap, edges) {
  for (const e of edges) {
    const src = nodeMap.get(e.source);
    const tgt = nodeMap.get(e.target);
    if (src) {
      if (!src._ports)       src._ports       = new Set();
      if (!src._out_targets) src._out_targets  = new Set();
      src._out_targets.add(e.target);
      (e.ports || []).forEach(p => src._ports.add(Number(p)));
    }
    if (tgt) {
      if (!tgt._ports)       tgt._ports       = new Set();
      if (!tgt._in_sources)  tgt._in_sources  = new Set();
      tgt._in_sources.add(e.source);
      (e.ports || []).forEach(p => tgt._ports.add(Number(p)));
    }
  }
  nodeMap.forEach((n, id) => {
    const ports  = Array.from(n._ports    || []);
    const inDeg  = (n._in_sources  || new Set()).size;
    const outDeg = (n._out_targets || new Set()).size;
    const total  = inDeg + outDeg;
    n.ports        = ports;
    n.in_degree    = inDeg;
    n.out_degree   = outDeg;
    n.server_score = total > 0 ? Math.round(inDeg / total * 100) / 100 : null;
    n.os_hint      = computeOsHint(ports);
    if (n.type === 'external') {
      const raw = String(id).replace(/^::ffff:/i, '').replace(/:\d+$/, '');
      const geo = geoip.lookup(raw);
      if (geo) n.geo = { country: geo.country, region: geo.region || null, city: geo.city || null };
    }
    delete n._ports; delete n._in_sources; delete n._out_targets;
  });
}

// network_annotations: one row per case, stores zone rects and node type overrides
pool.query(`
  CREATE TABLE IF NOT EXISTS network_annotations (
    case_id    UUID PRIMARY KEY REFERENCES cases(id) ON DELETE CASCADE,
    data       JSONB NOT NULL DEFAULT '{"zones":[],"node_overrides":{}}',
    updated_at TIMESTAMPTZ DEFAULT NOW()
  )
`).catch(err => logger.error('[network_annotations] table init failed:', err));

router.get('/:caseId', authenticate, async (req, res) => {
  try {
    const { suspicious } = req.query;
    let query = 'SELECT * FROM network_connections WHERE case_id = $1';
    const params = [req.params.caseId];

    if (suspicious === 'true') {
      query += ' AND is_suspicious = true';
    }

    query += ' ORDER BY first_seen ASC';
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/:caseId', authenticate, async (req, res) => {
  try {
    const { src_ip, src_port, dst_ip, dst_port, protocol, bytes_sent, bytes_received, packet_count, first_seen, last_seen, geo_src, geo_dst, is_suspicious, notes } = req.body;
    const result = await pool.query(
      `INSERT INTO network_connections (case_id, src_ip, src_port, dst_ip, dst_port, protocol, bytes_sent, bytes_received, packet_count, first_seen, last_seen, geo_src, geo_dst, is_suspicious, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,
      [req.params.caseId, src_ip, src_port, dst_ip, dst_port, protocol, bytes_sent, bytes_received, packet_count, first_seen, last_seen, geo_src || {}, geo_dst || {}, is_suspicious, notes]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/:caseId/stats', authenticate, async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT
        COUNT(*) as total_connections,
        COUNT(*) FILTER (WHERE is_suspicious) as suspicious_connections,
        COUNT(DISTINCT src_ip) as unique_src_ips,
        COUNT(DISTINCT dst_ip) as unique_dst_ips,
        SUM(bytes_sent) as total_bytes_sent,
        SUM(bytes_received) as total_bytes_received,
        SUM(packet_count) as total_packets
      FROM network_connections WHERE case_id = $1
    `, [req.params.caseId]);
    res.json(stats.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/:caseId/graph', authenticate, requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const { caseId } = req.params;
    const { evidence_id } = req.query;

    const ctEvidenceFilter = evidence_id
      ? `AND result_id IN (SELECT id FROM parser_results WHERE evidence_id = $2)`
      : '';
    const ctParams = evidence_id ? [caseId, evidence_id] : [caseId];

    const [r1, r2, r3, r4] = await Promise.all([

      evidence_id
        ? Promise.resolve({ rows: [] })
        : pool.query(`
        SELECT src_ip, dst_ip, dst_port::text AS dst_port, protocol,
               COUNT(*) AS connection_count,
               SUM(COALESCE(bytes_sent,0) + COALESCE(bytes_received,0)) AS total_bytes,
               bool_or(is_suspicious) AS is_suspicious,
               MIN(first_seen) AS first_seen,
               MAX(last_seen)  AS last_seen
        FROM network_connections
        WHERE case_id = $1 AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
          AND src_ip <> '' AND dst_ip <> ''
        GROUP BY src_ip, dst_ip, dst_port, protocol
        ORDER BY connection_count DESC
        LIMIT 300
      `, [caseId]),

      pool.query(`
        SELECT src_ip, dst_ip, dst_port, protocol,
               COUNT(*) AS connection_count, 0::bigint AS total_bytes, false AS is_suspicious,
               MIN(ts) AS first_seen, MAX(ts) AS last_seen
        FROM (
          SELECT
            COALESCE(NULLIF(TRIM(raw->>'Computer'), ''), 'local') AS src_ip,
            COALESCE(
              NULLIF(TRIM(raw->>'RemoteHost'),      ''),
              NULLIF(TRIM(raw->>'RemoteAddress'),   ''),
              NULLIF(TRIM(raw->>'DstIP'),           ''),
              NULLIF(TRIM(raw->>'dst_ip'),          ''),
              NULLIF(TRIM(raw->>'DestinationIp'),   ''),
              NULLIF(TRIM(raw->>'id.resp_h'),       ''),
              NULLIF(TRIM(raw->>'dst_host'),        '')
            ) AS dst_ip,
            COALESCE(
              NULLIF(TRIM(raw->>'RemotePort'),      ''),
              NULLIF(TRIM(raw->>'DstPort'),         ''),
              NULLIF(TRIM(raw->>'dst_port'),        ''),
              NULLIF(TRIM(raw->>'DestinationPort'), '')
            ) AS dst_port,
            COALESCE(
              NULLIF(TRIM(raw->>'Protocol'),  ''),
              NULLIF(TRIM(raw->>'proto'),     ''),
              NULLIF(TRIM(raw->>'Transport'), '')
            ) AS protocol,
            timestamp AS ts
          FROM collection_timeline
          WHERE case_id = $1
            ${ctEvidenceFilter}
            AND (
              raw->>'RemoteHost'    IS NOT NULL OR
              raw->>'RemoteAddress' IS NOT NULL OR
              raw->>'DstIP'         IS NOT NULL OR
              raw->>'dst_ip'        IS NOT NULL OR
              raw->>'DestinationIp' IS NOT NULL OR
              raw->>'id.resp_h'     IS NOT NULL OR
              raw->>'dst_host'      IS NOT NULL
            )
        ) AS t
        WHERE dst_ip IS NOT NULL AND dst_ip <> '' AND dst_ip <> '-'
          AND dst_ip NOT IN ('0.0.0.0', '::', '255.255.255.255')
        GROUP BY src_ip, dst_ip, dst_port, protocol
        ORDER BY connection_count DESC
        LIMIT 300
      `, ctParams),

      pool.query(`
        SELECT value, ioc_type::text AS ioc_type, is_malicious, severity
        FROM iocs
        WHERE case_id = $1 AND ioc_type IN ('ip', 'domain', 'url')
        ORDER BY severity DESC NULLS LAST, is_malicious DESC NULLS LAST
        LIMIT 200
      `, [caseId]),

      pool.query(`
        SELECT
          COALESCE(NULLIF(TRIM(host_name), ''), 'local') AS src_host,
          raw->>'URL' AS dst_url,
          COUNT(*) AS visit_count
        FROM collection_timeline
        WHERE case_id = $1
          ${ctEvidenceFilter}
          AND artifact_type = 'sqle'
          AND raw->>'URL' IS NOT NULL AND raw->>'URL' <> ''
          AND raw->>'URL' LIKE 'http%'
        GROUP BY host_name, raw->>'URL'
        ORDER BY visit_count DESC
        LIMIT 100
      `, ctParams),
    ]);

    // Well-known port → protocol label
    const PORT_LABEL = {
      '21':'FTP','22':'SSH','23':'TELNET','25':'SMTP','53':'DNS','67':'DHCP',
      '80':'HTTP','88':'KERBEROS','110':'POP3','135':'RPC','139':'NETBIOS',
      '143':'IMAP','389':'LDAP','443':'HTTPS','445':'SMB','465':'SMTPS',
      '514':'SYSLOG','587':'SMTP','636':'LDAPS','993':'IMAPS','995':'POP3S',
      '1433':'MSSQL','1723':'PPTP','3306':'MYSQL','3389':'RDP','5985':'WINRM',
      '5986':'WINRMS','6379':'REDIS','8080':'HTTP-ALT','8443':'HTTPS-ALT',
      '27017':'MONGODB','5432':'POSTGRES',
    };

    const edgeMap = new Map();
    const mergeEdge = (src, dst, port, proto, count, bytes, suspicious, firstSeen, lastSeen) => {
      if (!src || !dst || src === dst) return;
      const key = `${src}||${dst}||${port || ''}||${proto || ''}`;
      if (edgeMap.has(key)) {
        const e = edgeMap.get(key);
        e.connection_count += parseInt(count) || 1;
        e.total_bytes += parseInt(bytes) || 0;
        if (suspicious) e.has_suspicious = true;
        if (firstSeen && (!e.first_seen || firstSeen < e.first_seen)) e.first_seen = firstSeen;
        if (lastSeen  && (!e.last_seen  || lastSeen  > e.last_seen))  e.last_seen  = lastSeen;
      } else {
        const portLabel = port ? (PORT_LABEL[String(port)] || String(port)) : null;
        const protoLabel = proto ? String(proto).toUpperCase() : null;
        const label = portLabel || protoLabel || null;
        edgeMap.set(key, {
          source: src, target: dst,
          connection_count: parseInt(count) || 1,
          total_bytes: parseInt(bytes) || 0,
          ports: port ? [String(port)] : [],
          protocols: proto ? [String(proto).toUpperCase()] : [],
          has_suspicious: Boolean(suspicious),
          first_seen: firstSeen || null,
          last_seen:  lastSeen  || null,
          label,
        });
      }
    };

    for (const r of r1.rows) mergeEdge(r.src_ip, r.dst_ip, r.dst_port, r.protocol, r.connection_count, r.total_bytes, r.is_suspicious, r.first_seen, r.last_seen);
    for (const r of r2.rows) mergeEdge(r.src_ip, r.dst_ip, r.dst_port, r.protocol, r.connection_count, r.total_bytes, false, r.first_seen, r.last_seen);
    for (const r of r4.rows) {
      if (r.dst_url && r.src_host) {
        const proto = r.dst_url.startsWith('https') ? 'HTTPS' : 'HTTP';
        mergeEdge(r.src_host, r.dst_url, null, proto, r.visit_count, 0, false);
      }
    }

    const edges = Array.from(edgeMap.values());

    const classifyType = (id) => {
      if (/^https?:\/\//.test(id)) return 'url';
      if (id === 'local') return 'internal';
      // IPv6-mapped (::ffff:) or pure IPv6 or plain IPv4
      if (/^::ffff:/i.test(id) || /^\d+\.\d+\.\d+\.\d+$/.test(id) || /^[0-9a-f:]+$/i.test(id)) {
        return isInternalIP(id) ? 'internal' : 'external';
      }
      // "IP:port" format (e.g. 127.0.0.1:0, 192.168.1.4:445)
      if (/^\d+\.\d+\.\d+\.\d+:\d+$/.test(id)) return isInternalIP(id) ? 'internal' : 'external';
      // "NAME (IP)" format (e.g. LAB (127.0.0.1), ROWENA (192.168.1.4))
      const pip = extractParenIP(id);
      if (pip) return isInternalIP(pip) ? 'internal' : 'external';
      // Private TLDs (.lab, .local, .lan, etc.) → internal hostname
      if (PRIVATE_TLD.test(id)) return 'internal';
      return id.includes('.') ? 'domain' : 'internal';
    };

    const nodeMap = new Map();
    const upsertNode = (id, type, suspicious, bytes) => {
      if (!nodeMap.has(id)) {
        nodeMap.set(id, { id, type, is_suspicious: Boolean(suspicious), connection_count: 0, total_bytes: 0 });
      }
      const n = nodeMap.get(id);
      n.connection_count++;
      n.total_bytes += parseInt(bytes) || 0;
      if (suspicious) n.is_suspicious = true;
    };

    for (const e of edges) {
      upsertNode(e.source, classifyType(e.source), e.has_suspicious, 0);
      upsertNode(e.target, classifyType(e.target), e.has_suspicious, e.total_bytes);
    }

    for (const ioc of r3.rows) {
      const type = ioc.ioc_type === 'url' ? 'url'
        : ioc.ioc_type === 'domain' ? 'domain'
        : classifyType(ioc.value);
      if (!nodeMap.has(ioc.value)) {
        nodeMap.set(ioc.value, { id: ioc.value, type, is_suspicious: Boolean(ioc.is_malicious), connection_count: 0, total_bytes: 0 });
      } else if (ioc.is_malicious) {
        nodeMap.get(ioc.value).is_suspicious = true;
      }
    }

    enrichNodes(nodeMap, edges);
    res.json({
      nodes: Array.from(nodeMap.values()),
      edges,
      total_records: edges.length,
    });
  } catch (err) {
    logger.error('[network/graph]', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/:caseId/import-csv', authenticate, upload.single('file'), async (req, res) => {
  try {
    const { caseId } = req.params;

    let csvText;
    if (req.file) {
      csvText = req.file.buffer.toString('utf-8');
    } else if (typeof req.body === 'string' && req.body.trim()) {
      csvText = req.body;
    } else {
      return res.status(400).json({ error: 'Aucun fichier CSV fourni' });
    }

    if (csvText.charCodeAt(0) === 0xFEFF) csvText = csvText.slice(1);

    const rows = parseCsv(csvText, {
      columns: true,
      skip_empty_lines: true,
      trim: true,
      relax_quotes: true,
      relax_column_count: true,
    });

    if (!rows.length) return res.status(400).json({ error: 'CSV vide ou non parseable' });

    const ALIASES = {
      src_ip:         ['src_ip', 'source_ip', 'src', 'source', 'id.orig_h', 'srcip', 'sourceip'],
      dst_ip:         ['dst_ip', 'dest_ip', 'destination_ip', 'dst', 'dest', 'id.resp_h', 'dstip', 'destip'],
      src_port:       ['src_port', 'source_port', 'sport', 'id.orig_p', 'srcport'],
      dst_port:       ['dst_port', 'dest_port', 'dport', 'id.resp_p', 'dstport'],
      protocol:       ['protocol', 'proto', 'transport', 'network_protocol'],
      bytes_sent:     ['bytes_sent', 'orig_bytes', 'bytes_out', 'sent_bytes', 'tx_bytes'],
      bytes_received: ['bytes_received', 'resp_bytes', 'bytes_in', 'recv_bytes', 'rx_bytes'],
      packet_count:   ['packet_count', 'packets', 'orig_pkts', 'pkts'],
      first_seen:     ['first_seen', 'ts', 'timestamp', 'start_time', 'start'],
      last_seen:      ['last_seen', 'end_time', 'end', 'last_time'],
      is_suspicious:  ['is_suspicious', 'suspicious', 'alert', 'malicious'],
      notes:          ['notes', 'note', 'comment', 'label', 'conn_state'],
    };

    const headers = Object.keys(rows[0]).map(h => h.toLowerCase());
    const colMap = {};
    for (const [field, aliases] of Object.entries(ALIASES)) {
      for (const alias of aliases) {
        const found = Object.keys(rows[0]).find(h => h.toLowerCase() === alias);
        if (found) { colMap[field] = found; break; }
      }
    }

    if (!colMap.src_ip && !colMap.dst_ip) {
      return res.status(422).json({ error: 'Colonnes src_ip/dst_ip introuvables dans le CSV', headers: Object.keys(rows[0]) });
    }

    const get = (row, field) => (colMap[field] ? (row[colMap[field]] ?? null) : null);

    const values = { caseId: [], src_ip: [], src_port: [], dst_ip: [], dst_port: [], protocol: [],
                     bytes_sent: [], bytes_received: [], packet_count: [], first_seen: [], last_seen: [],
                     is_suspicious: [], notes: [] };

    for (const row of rows) {
      const srcIp = get(row, 'src_ip');
      const dstIp = get(row, 'dst_ip');
      if (!srcIp || !dstIp) continue;

      const parsePort = v => { const n = parseInt(v, 10); return (Number.isFinite(n) && n > 0) ? n : null; };
      const parseBool = v => v && ['true', '1', 'yes', 'oui', 'alert'].includes(String(v).toLowerCase());
      const parseTs   = v => { if (!v || v === '-') return null; const d = new Date(v); return isNaN(d) ? null : d.toISOString(); };

      values.caseId.push(caseId);
      values.src_ip.push(srcIp || null);
      values.src_port.push(parsePort(get(row, 'src_port')));
      values.dst_ip.push(dstIp || null);
      values.dst_port.push(parsePort(get(row, 'dst_port')));
      values.protocol.push(get(row, 'protocol') || null);
      values.bytes_sent.push(parseInt(get(row, 'bytes_sent'), 10) || null);
      values.bytes_received.push(parseInt(get(row, 'bytes_received'), 10) || null);
      values.packet_count.push(parseInt(get(row, 'packet_count'), 10) || null);
      values.first_seen.push(parseTs(get(row, 'first_seen')));
      values.last_seen.push(parseTs(get(row, 'last_seen')));
      values.is_suspicious.push(parseBool(get(row, 'is_suspicious')));
      values.notes.push(get(row, 'notes') || null);
    }

    if (!values.caseId.length) return res.status(422).json({ error: 'Aucune ligne valide dans le CSV' });

    await pool.query(`
      INSERT INTO network_connections
        (case_id, src_ip, src_port, dst_ip, dst_port, protocol, bytes_sent, bytes_received,
         packet_count, first_seen, last_seen, is_suspicious, notes)
      SELECT * FROM UNNEST(
        $1::uuid[], $2::text[], $3::int[], $4::text[], $5::int[], $6::text[],
        $7::bigint[], $8::bigint[], $9::int[], $10::timestamptz[], $11::timestamptz[],
        $12::boolean[], $13::text[]
      )
    `, [
      values.caseId, values.src_ip, values.src_port, values.dst_ip, values.dst_port,
      values.protocol, values.bytes_sent, values.bytes_received, values.packet_count,
      values.first_seen, values.last_seen, values.is_suspicious, values.notes,
    ]);

    res.json({ imported: values.caseId.length, total_rows: rows.length });
  } catch (err) {
    logger.error('[network/import-csv]', err);
    res.status(500).json({ error: 'Erreur import CSV', detail: err.message });
  }
});

// ── Network graph builder ──────────────────────────────────────────────────
// fromTs / toTs are optional ISO strings to scope the timeline window.
async function buildNetworkGraph(caseId, evidenceIdList, pool, fromTs, toTs) {
  const hasFilter = evidenceIdList.length > 0;

  // Build evidence filter fragment
  const ctEvidenceFilter = hasFilter
    ? `AND result_id IN (SELECT id FROM parser_results WHERE evidence_id = ANY($2::uuid[]))`
    : '';

  // Build base params, then append optional time range at the end so param
  // numbers stay predictable regardless of which combination is active.
  const ctBase = hasFilter ? [caseId, evidenceIdList] : [caseId];
  const ctParams = [...ctBase];
  let timeFilter = '';
  if (fromTs) { ctParams.push(fromTs); timeFilter += ` AND timestamp >= $${ctParams.length}::timestamptz`; }
  if (toTs)   { ctParams.push(toTs);   timeFilter += ` AND timestamp <= $${ctParams.length}::timestamptz`; }

  const ncParams = [caseId];
  let ncTimeFilter = '';
  if (fromTs) { ncParams.push(fromTs); ncTimeFilter += ` AND first_seen >= $${ncParams.length}::timestamptz`; }
  if (toTs)   { ncParams.push(toTs);   ncTimeFilter += ` AND last_seen  <= $${ncParams.length}::timestamptz`; }

  const LIMIT = 500; // raised from 300

  const [r1, r2, r3, r4, r5] = await Promise.all([

    // ── Source 1: network_connections table (PCAP / CSV imports) ──
    // network_connections has no evidence_id column, so always query by case_id.
    // A collection-scoped view still shows all TCP flows for the case.
    pool.query(`
      SELECT src_ip, dst_ip, dst_port::text AS dst_port, protocol,
             COUNT(*) AS connection_count,
             SUM(COALESCE(bytes_sent,0) + COALESCE(bytes_received,0)) AS total_bytes,
             bool_or(is_suspicious) AS is_suspicious
      FROM network_connections
      WHERE case_id = $1 AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
        AND src_ip <> '' AND dst_ip <> ''
        ${ncTimeFilter}
      GROUP BY src_ip, dst_ip, dst_port, protocol
      ORDER BY connection_count DESC LIMIT ${LIMIT}
    `, ncParams),

    // ── Source 2: collection_timeline raw JSON ──
    // Priority field order is intentional:
    //   src: SourceIp (Sysmon EID 3) > src_ip column > SourceAddress (WFP 5156) > Computer hostname
    //   dst: DestinationHostname (resolved name, best for display) > DestinationIp > legacy aliases
    //   process: Image field from Sysmon — which process made this connection
    pool.query(`
      SELECT src_ip, dst_ip, dst_port, protocol, process_name,
             COUNT(*) AS connection_count, 0::bigint AS total_bytes, false AS is_suspicious
      FROM (
        SELECT
          COALESCE(
            NULLIF(TRIM(raw->>'SourceIp'),       ''),
            NULLIF(TRIM(raw->>'src_ip'),         ''),
            NULLIF(TRIM(src_ip::text),           ''),
            NULLIF(TRIM(raw->>'SourceAddress'),  ''),
            NULLIF(TRIM(host_name),              ''),
            NULLIF(TRIM(raw->>'Computer'),       ''),
            'local'
          ) AS src_ip,
          COALESCE(
            NULLIF(TRIM(raw->>'DestinationHostname'), ''),
            NULLIF(TRIM(raw->>'DestinationIp'),       ''),
            NULLIF(TRIM(dst_ip::text),                ''),
            NULLIF(TRIM(raw->>'RemoteHost'),          ''),
            NULLIF(TRIM(raw->>'RemoteAddress'),       ''),
            NULLIF(TRIM(raw->>'DstIP'),               ''),
            NULLIF(TRIM(raw->>'dst_ip'),              ''),
            NULLIF(TRIM(raw->>'DestAddress'),         ''),
            NULLIF(TRIM(raw->>'id.resp_h'),           ''),
            NULLIF(TRIM(raw->>'dst_host'),            '')
          ) AS dst_ip,
          COALESCE(
            NULLIF(TRIM(raw->>'DestinationPort'), ''),
            NULLIF(TRIM(raw->>'RemotePort'),      ''),
            NULLIF(TRIM(raw->>'DstPort'),         ''),
            NULLIF(TRIM(raw->>'dst_port'),        ''),
            NULLIF(TRIM(raw->>'DestinationPort'), '')
          ) AS dst_port,
          COALESCE(
            NULLIF(TRIM(raw->>'Protocol'),  ''),
            NULLIF(TRIM(raw->>'proto'),     ''),
            NULLIF(TRIM(raw->>'Transport'), '')
          ) AS protocol,
          -- Extract the initiating process (Sysmon EID 3 "Image" field)
          NULLIF(TRIM(raw->>'Image'), '') AS process_name
        FROM collection_timeline
        WHERE case_id = $1
          ${ctEvidenceFilter}
          ${timeFilter}
          AND (
            raw->>'SourceIp'          IS NOT NULL OR
            raw->>'DestinationIp'     IS NOT NULL OR
            raw->>'DestinationHostname' IS NOT NULL OR
            raw->>'RemoteHost'        IS NOT NULL OR
            raw->>'RemoteAddress'     IS NOT NULL OR
            raw->>'DstIP'             IS NOT NULL OR
            raw->>'dst_ip'            IS NOT NULL OR
            raw->>'id.resp_h'         IS NOT NULL OR
            raw->>'dst_host'          IS NOT NULL OR
            dst_ip                    IS NOT NULL
          )
      ) AS t
      WHERE dst_ip IS NOT NULL AND dst_ip <> '' AND dst_ip <> '-'
        AND dst_ip NOT IN ('0.0.0.0', '::', '255.255.255.255', 'localhost')
        AND src_ip <> dst_ip
      GROUP BY src_ip, dst_ip, dst_port, protocol, process_name
      ORDER BY connection_count DESC LIMIT ${LIMIT}
    `, ctParams),

    // ── Source 3: IOCs ──
    pool.query(`
      SELECT value, ioc_type::text AS ioc_type, is_malicious, severity
      FROM iocs
      WHERE case_id = $1 AND ioc_type IN ('ip', 'domain', 'url')
      ORDER BY severity DESC NULLS LAST, is_malicious DESC NULLS LAST
      LIMIT 200
    `, [caseId]),

    // ── Source 4: evidence sources that have network data ──
    pool.query(`
      SELECT DISTINCT e.id, e.name, e.original_filename
      FROM evidence e
      JOIN parser_results pr ON pr.evidence_id = e.id
      JOIN collection_timeline ct ON ct.result_id = pr.id
      WHERE ct.case_id = $1
        AND (
          ct.raw->>'SourceIp'      IS NOT NULL OR
          ct.raw->>'DestinationIp' IS NOT NULL OR
          ct.raw->>'RemoteAddress' IS NOT NULL OR
          ct.dst_ip                IS NOT NULL
        )
      LIMIT 50
    `, [caseId]),

    // ── Source 5: browser history (SQLite via sqle parser) ──
    pool.query(`
      SELECT
        COALESCE(NULLIF(TRIM(host_name), ''), 'local') AS src_host,
        raw->>'URL' AS dst_url,
        COUNT(*) AS visit_count
      FROM collection_timeline
      WHERE case_id = $1
        ${ctEvidenceFilter}
        ${timeFilter}
        AND artifact_type = 'sqle'
        AND raw->>'URL' IS NOT NULL AND raw->>'URL' <> ''
        AND raw->>'URL' LIKE 'http%'
      GROUP BY host_name, raw->>'URL'
      ORDER BY visit_count DESC
      LIMIT 100
    `, ctParams),
  ]);

  // ── Merge edges from all sources ──
  const edgeMap = new Map();
  const mergeEdge = (src, dst, port, proto, count, bytes, suspicious, processName) => {
    if (!src || !dst || src === dst) return;
    const key = `${src}||${dst}||${port || ''}||${proto || ''}`;
    if (edgeMap.has(key)) {
      const e = edgeMap.get(key);
      e.connection_count += parseInt(count) || 1;
      e.total_bytes      += parseInt(bytes)  || 0;
      if (suspicious) e.has_suspicious = true;
      // Accumulate unique process names (max 5 to keep payload small)
      if (processName && e.processes.length < 5 && !e.processes.includes(processName)) {
        e.processes.push(processName);
      }
    } else {
      edgeMap.set(key, {
        source: src, target: dst,
        connection_count: parseInt(count) || 1,
        total_bytes:      parseInt(bytes)  || 0,
        ports:     port        ? [String(port)]  : [],
        protocols: proto       ? [String(proto)] : [],
        processes: processName ? [processName]   : [],
        has_suspicious: Boolean(suspicious),
      });
    }
  };

  for (const r of r1.rows) mergeEdge(r.src_ip, r.dst_ip, r.dst_port, r.protocol, r.connection_count, r.total_bytes, r.is_suspicious, null);
  for (const r of r2.rows) mergeEdge(r.src_ip, r.dst_ip, r.dst_port, r.protocol, r.connection_count, r.total_bytes, false, r.process_name);
  for (const r of r5.rows) {
    if (r.dst_url && r.src_host) {
      const proto = r.dst_url.startsWith('https') ? 'HTTPS' : 'HTTP';
      mergeEdge(r.src_host, r.dst_url, null, proto, r.visit_count, 0, false, null);
    }
  }

  const edges = Array.from(edgeMap.values());

  // ── Build nodes ──
  const classifyType = (id) => {
    if (/^https?:\/\//.test(id)) return 'url';
    if (id === 'local') return 'internal';
    // IPv6-mapped, pure IPv4, pure IPv6
    if (/^::ffff:/i.test(id) || /^\d+\.\d+\.\d+\.\d+$/.test(id) || /^[0-9a-f:]+$/i.test(id))
      return isInternalIP(id) ? 'internal' : 'external';
    // IP:port (e.g. 127.0.0.1:0)
    if (/^\d+\.\d+\.\d+\.\d+:\d+$/.test(id)) return isInternalIP(id) ? 'internal' : 'external';
    // NAME (IP) (e.g. LAB (127.0.0.1))
    const pip = extractParenIP(id);
    if (pip) return isInternalIP(pip) ? 'internal' : 'external';
    // Private TLDs
    if (PRIVATE_TLD.test(id)) return 'internal';
    return id.includes('.') ? 'domain' : 'internal';
  };

  const nodeMap = new Map();
  const upsertNode = (id, type, suspicious, bytes) => {
    if (!nodeMap.has(id)) {
      const node = { id, type, is_suspicious: Boolean(suspicious), connection_count: 0, total_bytes: 0 };
      // Compute DGA score inline for domain nodes
      if (type === 'domain') {
        const name = id.split('.').slice(0, -1).join('.') || id;
        node.dga_score = computeDgaScore(name);
        // Auto-flag high-confidence DGA domains
        if (node.dga_score >= 70) node.is_suspicious = true;
      }
      nodeMap.set(id, node);
    }
    const n = nodeMap.get(id);
    n.connection_count++;
    n.total_bytes += parseInt(bytes) || 0;
    if (suspicious) n.is_suspicious = true;
  };

  for (const e of edges) {
    upsertNode(e.source, classifyType(e.source), e.has_suspicious, 0);
    upsertNode(e.target, classifyType(e.target), e.has_suspicious, e.total_bytes);
  }

  for (const ioc of r3.rows) {
    const type = ioc.ioc_type === 'url' ? 'url'
      : ioc.ioc_type === 'domain' ? 'domain'
      : classifyType(ioc.value);
    if (!nodeMap.has(ioc.value)) {
      nodeMap.set(ioc.value, { id: ioc.value, type, is_suspicious: Boolean(ioc.is_malicious), connection_count: 0, total_bytes: 0 });
    } else if (ioc.is_malicious) {
      nodeMap.get(ioc.value).is_suspicious = true;
    }
  }

  enrichNodes(nodeMap, edges);

  // Warn the caller when the LIMIT was hit (data may be incomplete)
  const truncated = r2.rows.length >= LIMIT || r1.rows.length >= LIMIT;

  return {
    nodes:            Array.from(nodeMap.values()),
    edges,
    evidence_sources: r4.rows.map(r => ({ id: r.id, name: r.name || r.original_filename || r.id })),
    truncated,
    limit:            LIMIT,
  };
}

async function buildAttackPath(caseId, pool) {
  const MITRE_TAG_RE = /attack\.(t\d{4}(?:\.\d{3})?)/gi;

  const [r1, r2, r3] = await Promise.all([
    pool.query(`
      SELECT technique_id, tactic, technique_name, confidence, notes, created_at
      FROM case_mitre_techniques WHERE case_id = $1 ORDER BY created_at ASC
    `, [caseId]),

    pool.query(`
      SELECT id, event_timestamp, title, description, mitre_technique, mitre_tactic, color, artifact_ref
      FROM timeline_bookmarks
      WHERE case_id = $1 AND mitre_technique IS NOT NULL
      ORDER BY event_timestamp ASC
    `, [caseId]),

    pool.query(`
      SELECT id, hunted_at AS created_at, rule_name, matched_events
      FROM sigma_hunt_results WHERE case_id = $1 ORDER BY hunted_at ASC
    `, [caseId]),
  ]);

  const nodes = [];

  for (const r of r1.rows) {
    nodes.push({
      id: `technique-${r.technique_id}`,
      type: 'technique',
      tactic: r.tactic || '',
      technique_id: r.technique_id,
      technique_name: r.technique_name || r.technique_id,
      title: r.technique_name || r.technique_id,
      timestamp: r.created_at,
      confidence: r.confidence || 'medium',
      source: 'technique',
      notes: r.notes,
    });
  }

  for (const r of r2.rows) {
    nodes.push({
      id: `bookmark-${r.id}`,
      type: 'bookmark',
      tactic: r.mitre_tactic || '',
      technique_id: r.mitre_technique,
      technique_name: r.mitre_technique,
      title: r.title || r.description || r.mitre_technique,
      timestamp: r.event_timestamp,
      confidence: 'confirmed',
      source: 'bookmark',
      artifact_ref: r.artifact_ref,
    });
  }

  for (const r of r3.rows) {
    const events = Array.isArray(r.matched_events) ? r.matched_events : [];
    const techSet = new Set();
    for (const ev of events) {
      const tags = Array.isArray(ev.Tags) ? ev.Tags : (Array.isArray(ev.tags) ? ev.tags : []);
      for (const tag of tags) {
        MITRE_TAG_RE.lastIndex = 0;
        let m;
        while ((m = MITRE_TAG_RE.exec(String(tag))) !== null) {
          techSet.add(m[1].toUpperCase());
        }
      }
    }
    for (const techId of techSet) {
      nodes.push({
        id: `detection-${r.id}-${techId}`,
        type: 'detection',
        tactic: '',
        technique_id: techId,
        technique_name: techId,
        title: r.rule_name || techId,
        timestamp: r.created_at,
        confidence: 'high',
        source: 'detection',
        rule_name: r.rule_name,
      });
    }
  }

  const TACTIC_ORDER = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
    'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
    'Exfiltration', 'Impact',
  ];
  const tacticIdx = Object.fromEntries(TACTIC_ORDER.map((t, i) => [t, i]));

  const sorted = [...nodes].sort((a, b) =>
    new Date(a.timestamp || 0).getTime() - new Date(b.timestamp || 0).getTime()
  );

  const edges = [];
  for (let i = 0; i < sorted.length - 1; i++) {
    const a = sorted[i], b = sorted[i + 1];
    const ai = tacticIdx[a.tactic] ?? -1;
    const bi = tacticIdx[b.tactic] ?? -1;
    if (a.tactic && b.tactic && a.tactic === b.tactic) {
      edges.push({ source: a.id, target: b.id, temporal: true });
    } else if (ai >= 0 && bi >= 0 && bi > ai) {
      edges.push({ source: a.id, target: b.id, temporal: true });
    }
  }

  return {
    nodes,
    edges,
    phases_covered: [...new Set(nodes.map(n => n.tactic).filter(Boolean))],
  };
}

router.get('/:caseId/graph-data', authenticate, requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const { caseId } = req.params;
    const { view = 'all', evidence_ids, from_ts, to_ts } = req.query;
    const evidenceIdList = evidence_ids ? evidence_ids.split(',').filter(Boolean) : [];

    const result = {};
    if (view === 'network' || view === 'all') {
      result.network = await buildNetworkGraph(caseId, evidenceIdList, pool, from_ts || null, to_ts || null);
    }
    if (view === 'attack' || view === 'all') {
      result.attack = await buildAttackPath(caseId, pool);
    }
    res.json(result);
  } catch (err) {
    logger.error('[network/graph-data]', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/:caseId/graph-data/events', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const { node_id, limit = 100 } = req.query;
    if (!node_id) return res.status(400).json({ error: 'node_id requis' });

    // Strip cluster/domain prefix for matching
    const matchId = node_id.replace(/^(cluster:|domain:)/, '');

    const result = await pool.query(`
      SELECT
        ct.timestamp,
        ct.artifact_type,
        ct.description,
        ct.source,
        ct.host_name,
        ct.user_name,
        ct.event_id,
        ct.mitre_technique_id,
        ct.mitre_tactic,
        -- Network fields
        NULLIF(TRIM(ct.raw->>'Image'),             '') AS process_name,
        COALESCE(ct.raw->>'DestinationPort', ct.raw->>'RemotePort', ct.raw->>'DstPort') AS dst_port,
        COALESCE(ct.raw->>'Protocol', ct.raw->>'proto', ct.raw->>'Transport')           AS protocol,
        -- URL for browser history (sqle)
        ct.raw->>'URL'   AS url,
        -- Remote host info
        COALESCE(
          ct.raw->>'RemoteHost', ct.raw->>'RemoteAddress',
          ct.raw->>'DestinationHostname', ct.raw->>'dst_host'
        ) AS remote_host,
        -- Source/dest IPs
        ct.src_ip::text AS src_ip,
        ct.dst_ip::text AS dst_ip
      FROM collection_timeline ct
      WHERE ct.case_id = $1
        AND ct.artifact_type IN ('sqle', 'evtx', 'hayabusa', 'srum')
        AND (
          -- Exact IP / hostname matches
          ct.raw->>'SourceIp'            = $2 OR
          ct.raw->>'DestinationIp'       = $2 OR
          ct.raw->>'DestinationHostname' = $2 OR
          ct.raw->>'RemoteHost'          = $2 OR
          ct.raw->>'RemoteAddress'       = $2 OR
          ct.raw->>'DstIP'               = $2 OR
          ct.raw->>'dst_ip'              = $2 OR
          ct.raw->>'id.resp_h'           = $2 OR
          ct.raw->>'Computer'            = $2 OR
          ct.host_name                   = $2 OR
          ct.src_ip::text                = $2 OR
          ct.dst_ip::text                = $2 OR
          -- Domain-based match: sqle browser history URLs containing the hostname
          (ct.artifact_type = 'sqle'
           AND ct.raw->>'URL' IS NOT NULL
           AND ct.raw->>'URL' ILIKE '%' || $2 || '%')
        )
      ORDER BY ct.timestamp DESC
      LIMIT $3
    `, [caseId, matchId, parseInt(limit) || 100]);

    res.json({ events: result.rows, total: result.rowCount });
  } catch (err) {
    logger.error('[network/graph-data/events]', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

function shannonEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((sum, count) => {
    const p = count / len;
    return sum + p * Math.log2(p);
  }, 0);
}

function consonantRatio(str) {
  const consonants = (str.match(/[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]/g) || []).length;
  return str.length > 0 ? consonants / str.length : 0;
}

function vowelRatio(str) {
  const vowels = (str.match(/[aeiouAEIOU]/g) || []).length;
  return str.length > 0 ? vowels / str.length : 0;
}

function hasRepeatingPattern(str) {

  for (let len = 2; len <= 4; len++) {
    for (let i = 0; i <= str.length - len * 3; i++) {
      const sub = str.slice(i, i + len);
      let count = 0;
      let pos = 0;
      while ((pos = str.indexOf(sub, pos)) !== -1) { count++; pos += len; }
      if (count >= 3) return true;
    }
  }
  return false;
}

function computeDgaScore(name) {
  const ent = shannonEntropy(name);
  const cRatio = consonantRatio(name);
  const digits = (name.match(/\d/g) || []).length;
  const len = name.length;

  let score = 0;
  if (ent > 3.5) score += 40;
  if (cRatio > 0.65) score += 25;
  if (len > 20) score += 20;
  else if (len > 12) score += 15;
  if (digits > 2) score += 10;
  if (hasRepeatingPattern(name)) score += 10;

  return Math.min(score, 100);
}

// ── Beaconing detection ────────────────────────────────────────────────────
// Groups network events by (src, dst, port), computes the coefficient of
// variation (CV = stddev / avg) of inter-connection intervals.
// CV < 0.35 with ≥ 5 events signals suspiciously regular behaviour (C2 beacon).
// beacon_score = (1 - CV) * 100  →  100 = perfectly regular, 65 = CV=0.35 threshold.
router.get('/:caseId/beacons', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const { from_ts, to_ts } = req.query;

    const params = [caseId];
    let timeFilter = '';
    if (from_ts) { params.push(from_ts); timeFilter += ` AND timestamp >= $${params.length}::timestamptz`; }
    if (to_ts)   { params.push(to_ts);   timeFilter += ` AND timestamp <= $${params.length}::timestamptz`; }

    const result = await pool.query(`
      WITH raw_events AS (
        SELECT
          COALESCE(
            NULLIF(TRIM(raw->>'SourceIp'),      ''),
            NULLIF(TRIM(src_ip::text),          ''),
            NULLIF(TRIM(host_name),             ''),
            'unknown'
          ) AS src,
          COALESCE(
            NULLIF(TRIM(raw->>'DestinationHostname'), ''),
            NULLIF(TRIM(raw->>'DestinationIp'),       ''),
            NULLIF(TRIM(dst_ip::text),                ''),
            NULLIF(TRIM(raw->>'RemoteAddress'),       ''),
            NULLIF(TRIM(raw->>'RemoteHost'),          '')
          ) AS dst,
          COALESCE(
            NULLIF(raw->>'DestinationPort', ''),
            NULLIF(raw->>'RemotePort',      ''),
            NULLIF(raw->>'dst_port',        '')
          ) AS port,
          timestamp,
          NULLIF(TRIM(raw->>'Image'), '') AS process_name
        FROM collection_timeline
        WHERE case_id = $1
          ${timeFilter}
          AND timestamp IS NOT NULL
          AND (
            raw->>'DestinationIp'      IS NOT NULL OR
            raw->>'DestinationHostname' IS NOT NULL OR
            raw->>'RemoteAddress'      IS NOT NULL OR
            dst_ip                     IS NOT NULL
          )
      ),
      with_gaps AS (
        SELECT src, dst, port, timestamp, process_name,
          EXTRACT(EPOCH FROM (
            timestamp - LAG(timestamp) OVER (
              PARTITION BY src, dst, port ORDER BY timestamp
            )
          )) AS gap_sec
        FROM raw_events
        WHERE src IS NOT NULL AND dst IS NOT NULL
          AND src != dst AND src != 'unknown'
      )
      SELECT
        src, dst, port,
        COUNT(*)                                                    AS event_count,
        MIN(timestamp)                                              AS first_seen,
        MAX(timestamp)                                              AS last_seen,
        array_agg(DISTINCT process_name)
          FILTER (WHERE process_name IS NOT NULL)                   AS processes,
        ROUND(AVG(gap_sec)::numeric, 1)                            AS interval_avg_sec,
        ROUND(STDDEV(gap_sec)::numeric, 1)                         AS interval_stddev_sec,
        ROUND(
          CASE WHEN AVG(gap_sec) > 0
            THEN (STDDEV(gap_sec) / AVG(gap_sec))
            ELSE 1
          END::numeric, 3
        )                                                           AS cv,
        ROUND(
          GREATEST(0,
            (1 - CASE WHEN AVG(gap_sec) > 0
              THEN LEAST(STDDEV(gap_sec) / AVG(gap_sec), 1)
              ELSE 1
            END)
          ) * 100
        )::int                                                      AS beacon_score
      FROM with_gaps
      GROUP BY src, dst, port
      HAVING COUNT(*) >= 5
        AND AVG(gap_sec) > 0
        AND STDDEV(gap_sec) / NULLIF(AVG(gap_sec), 0) < 0.35
      ORDER BY beacon_score DESC, event_count DESC
      LIMIT 50
    `, params);

    res.json({
      beacons:  result.rows,
      total:    result.rows.length,
    });
  } catch (err) {
    logger.error('[network/beacons]', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/:caseId/dga-analysis', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const result = await pool.query(
      `SELECT value FROM iocs WHERE case_id = $1 AND ioc_type = 'domain'`,
      [caseId]
    );

    const domains = result.rows.map(row => {
      const full = row.value.toLowerCase().trim();

      const parts = full.split('.');
      const name = parts.length > 1 ? parts.slice(0, -1).join('.') : full;

      const entropy = parseFloat(shannonEntropy(name).toFixed(3));
      const cRatio = parseFloat(consonantRatio(name).toFixed(3));
      const vRatio = parseFloat(vowelRatio(name).toFixed(3));
      const digits = (name.match(/\d/g) || []).length;
      const dga_score = computeDgaScore(name);

      return {
        domain: full,
        entropy,
        consonant_ratio: cRatio,
        vowel_ratio: vRatio,
        length: full.length,
        digit_count: digits,
        dga_score,
        is_suspicious: dga_score >= 60,
      };
    });

    domains.sort((a, b) => b.dga_score - a.dga_score);

    res.json({
      domains,
      total: domains.length,
      suspicious_count: domains.filter(d => d.is_suspicious).length,
    });
  } catch (err) {
    logger.error('[network/dga-analysis]', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── Canvas annotations (zones + node type overrides) ───────────────────────
router.get('/:caseId/annotations', authenticate, requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const { caseId } = req.params;
    const result = await pool.query(
      'SELECT data FROM network_annotations WHERE case_id = $1',
      [caseId]
    );
    res.json(result.rows[0]?.data ?? { zones: [], node_overrides: {} });
  } catch (err) {
    logger.error('[network/annotations GET]', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.put('/:caseId/annotations', authenticate, requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const { caseId } = req.params;
    const data = req.body;
    if (!Array.isArray(data?.zones) || typeof data?.node_overrides !== 'object' || data.node_overrides === null) {
      return res.status(400).json({ error: 'Invalid annotations shape' });
    }
    await pool.query(
      `INSERT INTO network_annotations (case_id, data, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (case_id) DO UPDATE SET data = $2, updated_at = NOW()`,
      [caseId, JSON.stringify(data)]
    );
    const io = req.app.locals.io;
    if (io) {
      io.to(caseId).emit('network:schema_edited', {
        username:  req.user?.username || 'Anonyme',
        userId:    req.user?.id,
        timestamp: Date.now(),
      });
    }
    res.json({ ok: true });
  } catch (err) {
    logger.error('[network/annotations PUT]', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── Global-map annotations (zones/overrides/manual nodes for the case-level view) ─
// Uses JSONB || merge so per-evidence annotations (zones / node_overrides) are never overwritten.
router.put('/:caseId/annotations/global', authenticate, requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const { caseId } = req.params;
    const { zones = [], node_overrides = {}, manual_nodes = [], subnet_rules = [] } = req.body;
    if (!Array.isArray(zones) || typeof node_overrides !== 'object' || !Array.isArray(manual_nodes) || !Array.isArray(subnet_rules)) {
      return res.status(400).json({ error: 'Invalid global annotations shape' });
    }
    const patch = JSON.stringify({ global_zones: zones, global_node_overrides: node_overrides, global_manual_nodes: manual_nodes, global_subnet_rules: subnet_rules });
    await pool.query(
      `INSERT INTO network_annotations (case_id, data, updated_at)
       VALUES ($1, $2::jsonb || '{"zones":[],"node_overrides":{}}'::jsonb, NOW())
       ON CONFLICT (case_id) DO UPDATE
         SET data = network_annotations.data || $2::jsonb,
             updated_at = NOW()`,
      [caseId, patch]
    );
    res.json({ ok: true });
  } catch (err) {
    logger.error('[network/annotations/global PUT]', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

function mergeGlobalGraph(results, evidences) {
  if (results.length !== evidences.length) {
    throw new Error(`mergeGlobalGraph: results/evidences length mismatch (${results.length} vs ${evidences.length})`);
  }
  const nodeMap = new Map();
  const edgeMap = new Map();
  const evidenceSources = evidences.map(ev => ({
    id: ev.id,
    name: ev.name || ev.original_filename || ev.id,
  }));

  results.forEach((result, idx) => {
    const evidenceId = evidences[idx].id;
    const { nodes = [], edges = [] } = result;

    for (const node of nodes) {
      if (!nodeMap.has(node.id)) {
        nodeMap.set(node.id, {
          ...node,
          processes:    node.processes ? [...node.processes] : undefined,
          evidence_ids: [],
          connection_count: 0,
          total_bytes: 0,
        });
      }
      const n = nodeMap.get(node.id);
      if (!n.evidence_ids.includes(evidenceId)) n.evidence_ids.push(evidenceId);
      n.connection_count += node.connection_count || 0;
      n.total_bytes      += node.total_bytes      || 0;
      if (node.is_suspicious) n.is_suspicious = true;
      if ((node.dga_score || 0) > (n.dga_score || 0)) n.dga_score = node.dga_score;
    }

    for (const edge of edges) {
      const key = `${edge.source}||${edge.target}||${(edge.ports || [])[0] || ''}||${(edge.protocols || [])[0] || ''}`;
      if (!edgeMap.has(key)) {
        edgeMap.set(key, {
          ...edge,
          ports:        edge.ports     ? [...edge.ports]     : [],
          protocols:    edge.protocols ? [...edge.protocols] : [],
          processes:    edge.processes ? [...edge.processes] : [],
          evidence_ids: [],
          connection_count: 0,
          total_bytes: 0,
        });
      }
      const e = edgeMap.get(key);
      if (!e.evidence_ids.includes(evidenceId)) e.evidence_ids.push(evidenceId);
      e.connection_count += edge.connection_count || 0;
      e.total_bytes      += edge.total_bytes      || 0;
      if (edge.has_suspicious) e.has_suspicious = true;
    }
  });

  return {
    nodes:            Array.from(nodeMap.values()),
    edges:            Array.from(edgeMap.values()),
    evidence_sources: evidenceSources,
    truncated:        results.some(r => r.truncated),
  };
}

router.get('/:caseId/global-graph', authenticate, requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const { caseId } = req.params;

    const evidencesResult = await pool.query(
      `SELECT id, name, original_filename FROM evidence WHERE case_id = $1 ORDER BY created_at ASC`,
      [caseId]
    );
    const evidences = evidencesResult.rows;

    if (!evidences.length) {
      return res.json({ nodes: [], edges: [], evidence_sources: [], truncated: false });
    }

    const results = await Promise.all(
      evidences.map(ev => buildNetworkGraph(caseId, [ev.id], pool, null, null))
    );

    const graph = mergeGlobalGraph(results, evidences);
    res.json(graph);
  } catch (err) {
    logger.error('[network/global-graph]', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── Phase 2: network behavioural analytics over network_connections ──────────
// Exfiltration (volume), scan/sweep, lateral-movement ports, rare external
// connections, and pivot hosts. Returns findings + per-node flags for the map.
// IP "internal" test uses string prefixes (avoids ::inet cast errors on hostnames).
const INTERNAL_SQL = (col) =>
  `(${col} LIKE '10.%' OR ${col} LIKE '192.168.%' OR ${col} ~ '^172\\.(1[6-9]|2[0-9]|3[01])\\.' OR ${col} LIKE '169.254.%' OR ${col} LIKE 'fe80:%' OR ${col} LIKE 'fc%' OR ${col} LIKE 'fd%')`;

router.get('/:caseId/analytics', authenticate, async (req, res) => {
  const cid = req.params.caseId;
  try {
    const findings = [];
    const nodeFlags = {}; // ip -> { exfil, scanner, lateral, pivot, rare }
    const flag = (ip, k) => { if (!ip) return; (nodeFlags[ip] = nodeFlags[ip] || {})[k] = true; };

    // 1. Exfiltration — large outbound volume to an external destination.
    const exfil = (await pool.query(
      `SELECT src_ip, dst_ip, SUM(bytes_sent) AS sent, SUM(bytes_received) AS recv
         FROM network_connections WHERE case_id=$1 AND NOT ${INTERNAL_SQL('dst_ip')}
         GROUP BY src_ip, dst_ip HAVING SUM(bytes_sent) > 52428800
         ORDER BY sent DESC LIMIT 30`, [cid])).rows;
    exfil.forEach(r => { flag(r.src_ip, 'exfil'); findings.push({ type: 'exfil', severity: 'ÉLEVÉ', mitre: 'T1048', src: r.src_ip, dst: r.dst_ip, label: `Exfiltration possible — ${(r.sent / 1048576).toFixed(0)} Mo sortants vers ${r.dst_ip}` }); });

    // 2. Scan / sweep — one source reaching many distinct hosts or ports.
    const scan = (await pool.query(
      `SELECT src_ip, COUNT(DISTINCT dst_ip) AS hosts, COUNT(DISTINCT dst_port) AS ports
         FROM network_connections WHERE case_id=$1
         GROUP BY src_ip HAVING COUNT(DISTINCT dst_ip) >= 25 OR COUNT(DISTINCT dst_port) >= 25
         ORDER BY hosts DESC LIMIT 30`, [cid])).rows;
    scan.forEach(r => { flag(r.src_ip, 'scanner'); findings.push({ type: 'scan', severity: 'ÉLEVÉ', mitre: 'T1046', src: r.src_ip, label: `Scan/sweep — ${r.hosts} hôtes, ${r.ports} ports depuis ${r.src_ip}` }); });

    // 3. Lateral movement — internal→internal on admin ports.
    const lateral = (await pool.query(
      `SELECT src_ip, dst_ip, dst_port, COUNT(*) AS n
         FROM network_connections WHERE case_id=$1
           AND dst_port IN (3389,445,5985,5986,22,135,139,5900)
           AND ${INTERNAL_SQL('src_ip')} AND ${INTERNAL_SQL('dst_ip')}
         GROUP BY src_ip, dst_ip, dst_port ORDER BY n DESC LIMIT 40`, [cid])).rows;
    const PORTNAME = { 3389: 'RDP', 445: 'SMB', 5985: 'WinRM', 5986: 'WinRM', 22: 'SSH', 135: 'RPC', 139: 'NetBIOS', 5900: 'VNC' };
    lateral.forEach(r => { flag(r.src_ip, 'lateral'); flag(r.dst_ip, 'lateral'); findings.push({ type: 'lateral', severity: 'ÉLEVÉ', mitre: 'T1021', src: r.src_ip, dst: r.dst_ip, label: `Mouvement latéral — ${PORTNAME[r.dst_port] || r.dst_port} ${r.src_ip} → ${r.dst_ip}` }); });

    // 4. Pivot host — internal node with high in AND out internal degree.
    const pivot = (await pool.query(
      `WITH deg AS (
         SELECT src_ip AS ip, COUNT(DISTINCT dst_ip) AS out_d, 0 AS in_d FROM network_connections WHERE case_id=$1 AND ${INTERNAL_SQL('src_ip')} GROUP BY src_ip
         UNION ALL
         SELECT dst_ip AS ip, 0, COUNT(DISTINCT src_ip) FROM network_connections WHERE case_id=$1 AND ${INTERNAL_SQL('dst_ip')} GROUP BY dst_ip )
       SELECT ip, SUM(out_d) AS o, SUM(in_d) AS i FROM deg GROUP BY ip HAVING SUM(out_d) >= 5 AND SUM(in_d) >= 5 ORDER BY (SUM(out_d)+SUM(in_d)) DESC LIMIT 20`, [cid])).rows;
    pivot.forEach(r => { flag(r.ip, 'pivot'); findings.push({ type: 'pivot', severity: 'MOYEN', mitre: 'T1570', src: r.ip, label: `Relais de pivot — ${r.ip} (${r.i} entrants / ${r.o} sortants)` }); });

    // 5. Rare external connection — a single connection to an external host on a high port.
    const rare = (await pool.query(
      `SELECT src_ip, dst_ip, dst_port FROM network_connections
        WHERE case_id=$1 AND NOT ${INTERNAL_SQL('dst_ip')} AND dst_port > 1024 AND dst_port NOT IN (8080,8443,3128)
        GROUP BY src_ip, dst_ip, dst_port HAVING COUNT(*) = 1 ORDER BY dst_port DESC LIMIT 25`, [cid])).rows;
    rare.forEach(r => { flag(r.dst_ip, 'rare'); findings.push({ type: 'rare', severity: 'FAIBLE', mitre: 'T1571', src: r.src_ip, dst: r.dst_ip, label: `Connexion externe rare — ${r.src_ip} → ${r.dst_ip}:${r.dst_port}` }); });

    // 6. Threat Intel — node matches a known-bad indicator (TAXII / feed correlation).
    const ti = (await pool.query(
      `SELECT DISTINCT ioc_value, indicator_name, source_name FROM threat_correlations WHERE case_id=$1 LIMIT 50`, [cid])).rows;
    ti.forEach(r => { flag(r.ioc_value, 'knownBad'); findings.unshift({ type: 'threat-intel', severity: 'CRITIQUE', mitre: 'T1071', src: r.ioc_value, dst: r.ioc_value, label: `Known-bad (${r.source_name || 'feed'}) — ${r.ioc_value}${r.indicator_name ? ' · ' + r.indicator_name : ''}` }); });

    // GeoIP summary of external destinations.
    const geo = (await pool.query(
      `SELECT geo_dst->>'country' AS country, COUNT(DISTINCT dst_ip) AS hosts
         FROM network_connections WHERE case_id=$1 AND COALESCE(geo_dst->>'country','') <> ''
         GROUP BY country ORDER BY hosts DESC LIMIT 10`, [cid])).rows;

    // Auto zone classification (internal vs external, + cloud by geo org).
    const zones = (await pool.query(
      `SELECT
         COUNT(DISTINCT ip) FILTER (WHERE internal)                       AS internal,
         COUNT(DISTINCT ip) FILTER (WHERE NOT internal AND NOT cloud)     AS external,
         COUNT(DISTINCT ip) FILTER (WHERE cloud)                          AS cloud
       FROM (
         SELECT src_ip AS ip, ${INTERNAL_SQL('src_ip')} AS internal, FALSE AS cloud FROM network_connections WHERE case_id=$1
         UNION
         SELECT dst_ip, ${INTERNAL_SQL('dst_ip')},
                COALESCE(geo_dst->>'org','') ~* '(amazon|aws|azure|microsoft|google|cloud|digitalocean|ovh|hetzner|linode)'
           FROM network_connections WHERE case_id=$1
       ) u`, [cid])).rows[0] || {};

    res.json({
      findings, nodeFlags,
      counts: { exfil: exfil.length, scan: scan.length, lateral: lateral.length, pivot: pivot.length, rare: rare.length, knownBad: ti.length },
      geo, zones,
    });
  } catch (err) {
    logger.error('[network analytics]', err.message);
    res.status(500).json({ error: 'Erreur analytics réseau : ' + err.message });
  }
});

module.exports = router;
module.exports.mergeGlobalGraph = mergeGlobalGraph;
