
import { Pool } from 'pg';
import * as http from 'http';

const OLLAMA_URL  = process.env.OLLAMA_URL;
const AI_MODEL    = process.env.AI_MODEL            || 'qwen3:14b';
const MAX_HISTORY = parseInt(process.env.AI_MAX_HISTORY_MESSAGES || '30', 10);
const TEMPERATURE = parseFloat(process.env.AI_TEMPERATURE || '0.1');

export interface ChatMessage {
  id: number;
  role: 'user' | 'assistant';
  content: string;
  created_at: string;
  model?: string;
}

interface CaseContext {
  caseId:              number;
  caseName:            string;
  caseDescription:     string;
  caseStatus:          string;
  investigatorContext: string | null;
  iocs:                Array<{ value: string; type: string; verdict: string }>;
  notes:               Array<{ content: string; author: string; created_at: string }>;
  evidences:           Array<{ filename: string; type: string; status: string }>;
  alerts:              Array<{ rule_title: string; level: string; timestamp: string; mitre_id: string }>;
  timelineArtifacts:   Array<{
    artifact_type:      string;
    description:        string;
    timestamp:          string;
    host_name:          string;
    user_name:          string;
    mitre_technique_id: string;
    level:              string;
  }>;
}

export async function getConversationHistory(
  pool: Pool,
  caseId: number,
  limit = MAX_HISTORY
): Promise<ChatMessage[]> {
  const r = await pool.query<ChatMessage>(
    `SELECT id, role, content, created_at, model
     FROM ai_conversations
     WHERE case_id = $1
     ORDER BY created_at ASC
     LIMIT $2`,
    [caseId, Math.min(limit, 200)]
  );
  return r.rows;
}

export async function saveMessage(
  pool: Pool,
  caseId: number,
  userId: number,
  role: 'user' | 'assistant',
  content: string,
  model?: string
): Promise<void> {
  await pool.query(
    `INSERT INTO ai_conversations (case_id, user_id, role, content, model)
     VALUES ($1, $2, $3, $4, $5)`,
    [caseId, userId, role, content, model || null]
  );
}

export async function clearConversationHistory(pool: Pool, caseId: number): Promise<void> {
  await pool.query('DELETE FROM ai_conversations WHERE case_id = $1', [caseId]);
}

export async function getInvestigatorContext(
  pool: Pool,
  caseId: number
): Promise<{ freeText: string | null; updatedBy: string | null; updatedAt: string | null }> {
  const r = await pool.query(
    `SELECT ic.free_text, u.username AS updated_by, ic.updated_at
     FROM ai_investigator_context ic
     LEFT JOIN users u ON u.id = ic.updated_by
     WHERE ic.case_id = $1`,
    [caseId]
  );
  if (!r.rows.length) return { freeText: null, updatedBy: null, updatedAt: null };
  const row = r.rows[0];
  return {
    freeText:  row.free_text,
    updatedBy: row.updated_by,
    updatedAt: row.updated_at,
  };
}

export async function saveInvestigatorContext(
  pool: Pool,
  caseId: number,
  userId: number,
  freeText: string
): Promise<void> {
  await pool.query(
    `INSERT INTO ai_investigator_context (case_id, free_text, updated_by, updated_at)
     VALUES ($1, $2, $3, NOW())
     ON CONFLICT (case_id)
     DO UPDATE SET
       free_text  = EXCLUDED.free_text,
       updated_by = EXCLUDED.updated_by,
       updated_at = NOW()`,
    [caseId, freeText, userId]
  );
}

export async function clearInvestigatorContext(pool: Pool, caseId: number): Promise<void> {
  await pool.query('DELETE FROM ai_investigator_context WHERE case_id = $1', [caseId]);
}

export async function buildCaseContext(pool: Pool, caseId: number): Promise<CaseContext> {

  const caseRes = await pool.query(
    'SELECT id, title, description, status FROM cases WHERE id = $1',
    [caseId]
  );
  const c = caseRes.rows[0] || { id: caseId, title: 'Inconnu', description: '', status: 'unknown' };

  const { freeText: investigatorContext } = await getInvestigatorContext(pool, caseId);

  const alertsRes = await pool.query(
    `SELECT raw->>'rule_title' AS rule_title, raw->>'level' AS level, timestamp, mitre_technique_id AS mitre_id
     FROM collection_timeline
     WHERE case_id = $1
       AND artifact_type = 'hayabusa'
       AND raw->>'level' IN ('critical', 'high', 'medium')
     ORDER BY
       CASE raw->>'level' WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END,
       timestamp DESC
     LIMIT 30`,
    [caseId]
  );

  const iocsRes = await pool.query(
    `SELECT value, ioc_type AS type,
       CASE WHEN is_malicious THEN 'malveillant'
            WHEN vt_verdict IS NOT NULL THEN vt_verdict
            ELSE 'inconnu' END AS verdict
     FROM iocs
     WHERE case_id = $1
     ORDER BY severity DESC, is_malicious DESC
     LIMIT 30`,
    [caseId]
  );

  const artifactsRes = await pool.query(
    `SELECT artifact_type, description, timestamp,
            COALESCE(host_name, '') AS host_name,
            COALESCE(user_name, '') AS user_name,
            COALESCE(mitre_technique_id, '') AS mitre_technique_id,
            COALESCE(raw->>'level', '') AS level
     FROM collection_timeline
     WHERE case_id = $1
     ORDER BY
       CASE raw->>'level' WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
       timestamp DESC
     LIMIT 20`,
    [caseId]
  );

  const evidenceRes = await pool.query(
    `SELECT original_filename AS filename, evidence_type AS type,
       COALESCE(scan_status, 'pending') AS status
     FROM evidence
     WHERE case_id = $1
     ORDER BY created_at DESC
     LIMIT 20`,
    [caseId]
  );

  const notesRes = await pool.query(
    `SELECT an.note AS content, u.username AS author, an.created_at
     FROM artifact_notes an
     LEFT JOIN users u ON u.id = an.author_id
     WHERE an.case_id = $1
     ORDER BY an.created_at DESC
     LIMIT 10`,
    [caseId]
  );

  return {
    caseId:              c.id,
    caseName:            c.title,
    caseDescription:     c.description || '',
    caseStatus:          c.status,
    investigatorContext: investigatorContext,
    iocs:                iocsRes.rows,
    notes:               notesRes.rows,
    evidences:           evidenceRes.rows,
    alerts:              alertsRes.rows,
    timelineArtifacts:   artifactsRes.rows,
  };
}

export function buildSystemPrompt(ctx: CaseContext): string {
  const fmt = (arr: unknown[], fn: (x: any) => string) =>
    arr.length ? arr.map(fn).join('\n') : '  (aucune donnée)';

  return `Tu es un analyste DFIR senior intégré dans Heimdall DFIR.
Tu analyses UNIQUEMENT le cas suivant.
Ne fais JAMAIS référence à d'autres cas ou d'autres investigations.

=== CAS EN COURS ===
ID     : ${ctx.caseId}
Nom    : ${ctx.caseName}
Statut : ${ctx.caseStatus}
Description : ${ctx.caseDescription || '(aucune description)'}

=== CONTEXTE DE L'INVESTIGATION (fourni par l'analyste) ===
${ctx.investigatorContext || 'Aucun contexte renseigné par l\'analyste.'}

⚠ Ce contexte est la priorité. Il oriente toute ton analyse.
  Utilise-le pour interpréter les artifacts et formuler tes hypothèses.

=== ALERTES HAYABUSA/SIGMA (${ctx.alerts.length}) ===
${fmt(ctx.alerts, a => `  [${a.level?.toUpperCase()}] ${a.rule_title} | ${a.timestamp} | MITRE: ${a.mitre_id || '-'}`)}

=== IOCs (${ctx.iocs.length}) ===
${fmt(ctx.iocs, i => `  [${i.type}] ${i.value} — ${i.verdict}`)}

=== ARTIFACTS SUPER TIMELINE (top ${ctx.timelineArtifacts.length} critiques) ===
${fmt(ctx.timelineArtifacts, a => `  [${a.level || '?'}] ${a.artifact_type} | ${a.timestamp} | ${a.host_name || '?'} | ${a.user_name || '?'} | ${a.description?.slice(0, 120) || ''}`)}

=== PIÈCES À CONVICTION (${ctx.evidences.length}) ===
${fmt(ctx.evidences, e => `  ${e.filename} [${e.type}] — ClamAV: ${e.status}`)}

=== NOTES D'INVESTIGATION (${ctx.notes.length}) ===
${fmt(ctx.notes, n => `  [${n.author}] ${n.content?.slice(0, 200) || ''}`)}

=== INSTRUCTIONS ===
- Réponds en français
- Structure : Observation → Hypothèse → MITRE ATT&CK → Recommandations
- Cite les artifacts et IOCs spécifiques de ce cas
- Si données insuffisantes, dis-le clairement
- Ne mentionne jamais d'autres cas`;
}

export async function chat(
  pool: Pool,
  caseId: number,
  userId: number,
  message: string,
  model = AI_MODEL
): Promise<string> {
  if (!OLLAMA_URL) throw new Error('OLLAMA_URL not configured');

  const ctx    = await buildCaseContext(pool, caseId);
  const system = buildSystemPrompt(ctx);

  await saveMessage(pool, caseId, userId, 'user', message, model);

  const body = JSON.stringify({
    model,
    system,
    prompt: message,
    stream: false,
    options: { temperature: TEMPERATURE },
  });

  const response = await new Promise<string>((resolve, reject) => {
    const url = new URL('/api/generate', OLLAMA_URL);
    const req = http.request(
      {
        hostname: url.hostname,
        port: parseInt(url.port) || 11434,
        path: url.pathname,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      },
      (res) => {
        let data = '';
        res.on('data', (c: string) => { data += c; });
        res.on('end', () => {
          try {
            const j = JSON.parse(data);
            resolve(j.response || '');
          } catch {
            reject(new Error('Invalid JSON from Ollama'));
          }
        });
        res.on('error', reject);
      }
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });

  await saveMessage(pool, caseId, userId, 'assistant', response, model);
  return response;
}

export async function chatStream(
  pool: Pool,
  caseId: number,
  userId: number,
  message: string,
  res: import('express').Response,
  model = AI_MODEL
): Promise<void> {
  if (!OLLAMA_URL) {
    res.status(503).json({ error: 'OLLAMA_URL not configured' });
    return;
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  const emit = (data: object) => res.write(`data: ${JSON.stringify(data)}\n\n`);
  const think = (
    icon: string,
    label: string,
    status: 'loading' | 'done' | 'generating',
    extra?: object
  ) => emit({ thinking: { icon, label, status, ...extra } });

  think('📁', 'Métadonnées du cas', 'loading');
  const caseRes = await pool.query(
    'SELECT id, title, description, status FROM cases WHERE id = $1',
    [caseId]
  );
  const c = caseRes.rows[0] || { id: caseId, title: 'Inconnu', description: '', status: 'unknown' };
  think('📁', 'Métadonnées du cas', 'done', { detail: c.title });

  think('📝', 'Contexte investigateur', 'loading');
  const { freeText: investigatorContext } = await getInvestigatorContext(pool, caseId);
  think('📝', 'Contexte investigateur', 'done', {
    detail: investigatorContext ? 'Actif' : 'Aucun',
  });

  think('⚡', 'Alertes Hayabusa / Sigma', 'loading');
  const alertsRes = await pool.query(
    `SELECT raw->>'rule_title' AS rule_title, raw->>'level' AS level, timestamp, mitre_technique_id AS mitre_id
     FROM collection_timeline
     WHERE case_id = $1
       AND artifact_type = 'hayabusa'
       AND raw->>'level' IN ('critical', 'high', 'medium')
     ORDER BY
       CASE raw->>'level' WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END,
       timestamp DESC
     LIMIT 30`,
    [caseId]
  );
  const critCount = alertsRes.rows.filter((a: any) => a.level === 'critical').length;
  const highCount = alertsRes.rows.filter((a: any) => a.level === 'high').length;
  think('⚡', 'Alertes Hayabusa / Sigma', 'done', {
    count: alertsRes.rows.length,
    detail: `${critCount} critiques · ${highCount} high`,
  });

  think('🔴', 'IOCs', 'loading');
  const iocsRes = await pool.query(
    `SELECT value, ioc_type AS type,
       CASE WHEN is_malicious THEN 'malveillant'
            WHEN vt_verdict IS NOT NULL THEN vt_verdict
            ELSE 'inconnu' END AS verdict
     FROM iocs
     WHERE case_id = $1
     ORDER BY severity DESC, is_malicious DESC
     LIMIT 30`,
    [caseId]
  );
  const maliciousCount = iocsRes.rows.filter((i: any) => i.verdict === 'malveillant').length;
  think('🔴', 'IOCs', 'done', {
    count: iocsRes.rows.length,
    detail: maliciousCount > 0 ? `${maliciousCount} malveillants` : 'aucun malveillant',
  });

  think('📅', 'Super Timeline', 'loading');
  const artifactsRes = await pool.query(
    `SELECT artifact_type, description, timestamp,
            COALESCE(host_name, '') AS host_name,
            COALESCE(user_name, '') AS user_name,
            COALESCE(mitre_technique_id, '') AS mitre_technique_id,
            COALESCE(raw->>'level', '') AS level
     FROM collection_timeline
     WHERE case_id = $1
     ORDER BY
       CASE raw->>'level' WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
       timestamp DESC
     LIMIT 20`,
    [caseId]
  );
  const typeGroups: Record<string, number> = {};
  for (const a of artifactsRes.rows) {
    typeGroups[a.artifact_type] = (typeGroups[a.artifact_type] || 0) + 1;
  }
  const typesSummary = Object.entries(typeGroups)
    .map(([t, n]) => `${t}(${n})`)
    .join(' · ') || 'aucun';
  think('📅', 'Super Timeline', 'done', {
    count: artifactsRes.rows.length,
    detail: typesSummary,
  });

  think('🗂️', 'Pièces à conviction', 'loading');
  const evidenceRes = await pool.query(
    `SELECT original_filename AS filename, evidence_type AS type,
       COALESCE(scan_status, 'pending') AS status
     FROM evidence
     WHERE case_id = $1
     ORDER BY created_at DESC
     LIMIT 20`,
    [caseId]
  );
  const evTypes: Record<string, number> = {};
  for (const e of evidenceRes.rows) {
    evTypes[e.type || 'inconnu'] = (evTypes[e.type || 'inconnu'] || 0) + 1;
  }
  think('🗂️', 'Pièces à conviction', 'done', {
    count: evidenceRes.rows.length,
    detail: Object.entries(evTypes).map(([t, n]) => `${t}(${n})`).join(' · ') || 'aucune',
  });

  think('🗒️', "Notes d'investigation", 'loading');
  const notesRes = await pool.query(
    `SELECT an.note AS content, u.username AS author, an.created_at
     FROM artifact_notes an
     LEFT JOIN users u ON u.id = an.author_id
     WHERE an.case_id = $1
     ORDER BY an.created_at DESC
     LIMIT 10`,
    [caseId]
  );
  think('🗒️', "Notes d'investigation", 'done', { count: notesRes.rows.length });

  const ctx: CaseContext = {
    caseId:            c.id,
    caseName:          c.title,
    caseDescription:   c.description || '',
    caseStatus:        c.status,
    investigatorContext,
    iocs:              iocsRes.rows,
    notes:             notesRes.rows,
    evidences:         evidenceRes.rows,
    alerts:            alertsRes.rows,
    timelineArtifacts: artifactsRes.rows,
  };

  const system = buildSystemPrompt(ctx);

  think('🤖', "Génération de l'analyse", 'generating');

  await saveMessage(pool, caseId, userId, 'user', message, model);

  const body = JSON.stringify({
    model,
    system,
    prompt: message,
    stream: true,
    options: { temperature: TEMPERATURE },
  });

  return new Promise((resolve, reject) => {
    const url = new URL('/api/generate', OLLAMA_URL);
    const req = http.request(
      {
        hostname: url.hostname,
        port: parseInt(url.port) || 11434,
        path: url.pathname,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      },
      (ollamaRes) => {
        let fullResponse = '';

        ollamaRes.on('data', (chunk: Buffer) => {
          const lines = chunk.toString().split('\n').filter(Boolean);
          for (const line of lines) {
            try {
              const j = JSON.parse(line);
              if (j.response) {
                fullResponse += j.response;
                emit({ response: j.response });
              }
              if (j.done) {
                emit({ done: true, hasContext: Boolean(ctx.investigatorContext) });
                res.write('data: [DONE]\n\n');
              }
            } catch (_e) {}
          }
        });

        ollamaRes.on('end', async () => {
          if (fullResponse) {
            await saveMessage(pool, caseId, userId, 'assistant', fullResponse, model).catch(() => {});
          }
          res.end();
          resolve();
        });

        ollamaRes.on('error', reject);
      }
    );

    req.on('error', (err) => {
      if (!res.headersSent) res.status(502).json({ error: `Ollama unreachable: ${err.message}` });
      reject(err);
    });
    req.write(body);
    req.end();
  });
}

export function isAvailable(): boolean {
  return Boolean(OLLAMA_URL);
}
