const express = require('express');
const multer = require('multer');
const { pool } = require('../config/database');
const { authenticate, requireRole } = require('../middleware/auth');
const { parse: parseCsv } = require('csv-parse/sync');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

function isInternalIP(ip) {
  return /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1$)/.test(ip || '');
}

const logger = require('../config/logger').default;
const router = express.Router();

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
               bool_or(is_suspicious) AS is_suspicious
        FROM network_connections
        WHERE case_id = $1 AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
          AND src_ip <> '' AND dst_ip <> ''
        GROUP BY src_ip, dst_ip, dst_port, protocol
        ORDER BY connection_count DESC
        LIMIT 300
      `, [caseId]),

      pool.query(`
        SELECT src_ip, dst_ip, dst_port, protocol,
               COUNT(*) AS connection_count, 0::bigint AS total_bytes, false AS is_suspicious
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
            ) AS protocol
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

    const edgeMap = new Map();
    const mergeEdge = (src, dst, port, proto, count, bytes, suspicious) => {
      if (!src || !dst || src === dst) return;
      const key = `${src}||${dst}||${port || ''}||${proto || ''}`;
      if (edgeMap.has(key)) {
        const e = edgeMap.get(key);
        e.connection_count += parseInt(count) || 1;
        e.total_bytes += parseInt(bytes) || 0;
        if (suspicious) e.has_suspicious = true;
      } else {
        edgeMap.set(key, {
          source: src, target: dst,
          connection_count: parseInt(count) || 1,
          total_bytes: parseInt(bytes) || 0,
          ports: port ? [String(port)] : [],
          protocols: proto ? [String(proto)] : [],
          has_suspicious: Boolean(suspicious),
        });
      }
    };

    for (const r of r1.rows) mergeEdge(r.src_ip, r.dst_ip, r.dst_port, r.protocol, r.connection_count, r.total_bytes, r.is_suspicious);
    for (const r of r2.rows) mergeEdge(r.src_ip, r.dst_ip, r.dst_port, r.protocol, r.connection_count, r.total_bytes, false);
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
      if (/^\d+\.\d+\.\d+\.\d+$/.test(id) || /^[0-9a-f:]+$/i.test(id)) {
        return isInternalIP(id) ? 'internal' : 'external';
      }
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

async function buildNetworkGraph(caseId, evidenceIdList, pool) {
  const hasFilter = evidenceIdList.length > 0;
  const ctEvidenceFilter = hasFilter
    ? `AND result_id IN (SELECT id FROM parser_results WHERE evidence_id = ANY($2::uuid[]))`
    : '';
  const ctParams = hasFilter ? [caseId, evidenceIdList] : [caseId];

  const [r1, r2, r3, r4, r5] = await Promise.all([

    hasFilter
      ? Promise.resolve({ rows: [] })
      : pool.query(`
        SELECT src_ip, dst_ip, dst_port::text AS dst_port, protocol,
               COUNT(*) AS connection_count,
               SUM(COALESCE(bytes_sent,0) + COALESCE(bytes_received,0)) AS total_bytes,
               bool_or(is_suspicious) AS is_suspicious
        FROM network_connections
        WHERE case_id = $1 AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
          AND src_ip <> '' AND dst_ip <> ''
        GROUP BY src_ip, dst_ip, dst_port, protocol
        ORDER BY connection_count DESC LIMIT 300
      `, [caseId]),

    pool.query(`
      SELECT src_ip, dst_ip, dst_port, protocol,
             COUNT(*) AS connection_count, 0::bigint AS total_bytes, false AS is_suspicious
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
          ) AS protocol
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
      ORDER BY connection_count DESC LIMIT 300
    `, ctParams),

    pool.query(`
      SELECT value, ioc_type::text AS ioc_type, is_malicious, severity
      FROM iocs
      WHERE case_id = $1 AND ioc_type IN ('ip', 'domain', 'url')
      ORDER BY severity DESC NULLS LAST, is_malicious DESC NULLS LAST
      LIMIT 200
    `, [caseId]),

    pool.query(`
      SELECT DISTINCT e.id, e.name, e.original_filename
      FROM evidence e
      JOIN parser_results pr ON pr.evidence_id = e.id
      JOIN collection_timeline ct ON ct.result_id = pr.id
      WHERE ct.case_id = $1
        AND (
          ct.raw->>'RemoteHost' IS NOT NULL OR ct.raw->>'RemoteAddress' IS NOT NULL OR
          ct.raw->>'DstIP' IS NOT NULL OR ct.raw->>'dst_ip' IS NOT NULL OR
          ct.raw->>'DestinationIp' IS NOT NULL OR ct.raw->>'id.resp_h' IS NOT NULL OR
          ct.raw->>'dst_host' IS NOT NULL
        )
      LIMIT 50
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

  const edgeMap = new Map();
  const mergeEdge = (src, dst, port, proto, count, bytes, suspicious) => {
    if (!src || !dst || src === dst) return;
    const key = `${src}||${dst}||${port || ''}||${proto || ''}`;
    if (edgeMap.has(key)) {
      const e = edgeMap.get(key);
      e.connection_count += parseInt(count) || 1;
      e.total_bytes += parseInt(bytes) || 0;
      if (suspicious) e.has_suspicious = true;
    } else {
      edgeMap.set(key, {
        source: src, target: dst,
        connection_count: parseInt(count) || 1,
        total_bytes: parseInt(bytes) || 0,
        ports: port ? [String(port)] : [],
        protocols: proto ? [String(proto)] : [],
        has_suspicious: Boolean(suspicious),
      });
    }
  };

  for (const r of r1.rows) mergeEdge(r.src_ip, r.dst_ip, r.dst_port, r.protocol, r.connection_count, r.total_bytes, r.is_suspicious);
  for (const r of r2.rows) mergeEdge(r.src_ip, r.dst_ip, r.dst_port, r.protocol, r.connection_count, r.total_bytes, false);
  for (const r of r5.rows) {
    if (r.dst_url && r.src_host) {
      const proto = r.dst_url.startsWith('https') ? 'HTTPS' : 'HTTP';
      mergeEdge(r.src_host, r.dst_url, null, proto, r.visit_count, 0, false);
    }
  }

  const edges = Array.from(edgeMap.values());

  const classifyType = (id) => {
    if (/^https?:\/\//.test(id)) return 'url';
    if (id === 'local') return 'internal';
    if (/^\d+\.\d+\.\d+\.\d+$/.test(id) || /^[0-9a-f:]+$/i.test(id)) {
      return isInternalIP(id) ? 'internal' : 'external';
    }
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

  return {
    nodes: Array.from(nodeMap.values()),
    edges,
    evidence_sources: r4.rows.map(r => ({ id: r.id, name: r.name || r.original_filename || r.id })),
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
    const { view = 'all', evidence_ids } = req.query;
    const evidenceIdList = evidence_ids ? evidence_ids.split(',').filter(Boolean) : [];

    const result = {};
    if (view === 'network' || view === 'all') {
      result.network = await buildNetworkGraph(caseId, evidenceIdList, pool);
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
    const { node_id, limit = 50 } = req.query;
    if (!node_id) return res.status(400).json({ error: 'node_id requis' });

    const result = await pool.query(`
      SELECT ct.timestamp, ct.artifact_type, ct.description, ct.source,
             ct.evidence_id, e.name as evidence_name
      FROM collection_timeline ct
      LEFT JOIN evidence e ON ct.evidence_id = e.id
      WHERE ct.case_id = $1
        AND (
          ct.raw->>'RemoteHost' = $2 OR ct.raw->>'RemoteAddress' = $2 OR
          ct.raw->>'DstIP' = $2 OR ct.raw->>'dst_ip' = $2 OR
          ct.raw->>'DestinationIp' = $2 OR ct.raw->>'id.resp_h' = $2 OR
          ct.raw->>'Computer' = $2 OR ct.host_name = $2
        )
      ORDER BY ct.timestamp DESC LIMIT $3
    `, [caseId, node_id, parseInt(limit) || 50]);

    res.json(result.rows);
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

module.exports = router;
