
import { Pool } from 'pg';
import * as aiRouter from './aiRouter';
import type { ThinkingMode } from './aiRouter';

const OLLAMA_URL  = process.env.OLLAMA_URL;
const AI_MODEL    = process.env.AI_MODEL            || 'qwen2.5:3b';
const MAX_HISTORY = parseInt(process.env.AI_MAX_HISTORY_MESSAGES || '30', 10);
const TEMPERATURE = parseFloat(process.env.AI_TEMPERATURE || '0.1');
// Max conversation turns included in the messages array sent to Ollama.
// Keeps context window usage predictable across model sizes.
const HISTORY_FOR_CONTEXT = 10;

export interface ChatMessage {
  id: number;
  role: 'user' | 'assistant';
  content: string;
  created_at: string;
  model?: string;
}

interface CaseContext {
  caseId:              string;
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
  // Question-relevant items retrieved by keyword (RAG-lite) — present only when a query is given.
  relevant?: {
    artifacts: Array<{ artifact_type: string; description: string; timestamp: string; host_name: string; user_name: string; mitre_technique_id: string; level: string }>;
    iocs:      Array<{ value: string; type: string; verdict: string }>;
    notes:     Array<{ content: string; author: string }>;
  } | null;
}

// ── RAG-lite: pull case items that match the user's question by keyword ────────

const RAG_STOPWORDS = new Set([
  'les','des','une','que','qui','quoi','dans','pour','avec','est','sur','par','quel','quelle','quels','quelles',
  'comment','pourquoi','est-ce','y','t-il','il','elle','ils','elles','sont','ce','cette','ces','cas','the','and',
  'que','est','son','ses','leur','plus','moins','tout','tous','toute','toutes','fait','faire','peux','peut','dois',
  'donne','montre','liste','analyse','explique','dis','moi','nous','vous','aux','des','une','est','était','être',
]);

function ragKeywords(query?: string): string[] {
  if (!query) return [];
  const words = (query.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').match(/[a-z0-9._:/\\-]{3,}/g) || []);
  return [...new Set(words)].filter((w) => !RAG_STOPWORDS.has(w)).slice(0, 8);
}

async function retrieveRelevant(pool: Pool, caseId: string, query?: string): Promise<CaseContext['relevant']> {
  const kw = ragKeywords(query);
  if (!kw.length) return null;
  const pats = kw.map((k) => `%${k}%`);
  const [arts, iocs, notes] = await Promise.all([
    pool.query(
      `SELECT artifact_type, description, timestamp,
              COALESCE(host_name,'') AS host_name, COALESCE(user_name,'') AS user_name,
              COALESCE(mitre_technique_id,'') AS mitre_technique_id, COALESCE(raw->>'level','') AS level
       FROM collection_timeline
       WHERE case_id=$1 AND (description ILIKE ANY($2) OR host_name ILIKE ANY($2) OR user_name ILIKE ANY($2)
                              OR artifact_type ILIKE ANY($2) OR mitre_technique_id ILIKE ANY($2))
       ORDER BY CASE raw->>'level' WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, timestamp DESC
       LIMIT 18`, [caseId, pats]).catch(() => ({ rows: [] })),
    pool.query(
      `SELECT value, ioc_type AS type,
              CASE WHEN is_malicious THEN 'malveillant' ELSE 'inconnu' END AS verdict
       FROM iocs WHERE case_id=$1 AND value ILIKE ANY($2) ORDER BY severity DESC LIMIT 12`, [caseId, pats]).catch(() => ({ rows: [] })),
    pool.query(
      `SELECT an.note AS content, u.username AS author
       FROM artifact_notes an LEFT JOIN users u ON u.id=an.author_id
       WHERE an.case_id=$1 AND an.note ILIKE ANY($2) ORDER BY an.created_at DESC LIMIT 8`, [caseId, pats]).catch(() => ({ rows: [] })),
  ]);
  if (!arts.rows.length && !iocs.rows.length && !notes.rows.length) return null;
  return { artifacts: arts.rows as any, iocs: iocs.rows as any, notes: notes.rows as any };
}

// Resolve the model to use: explicit request → operator's active model (Opérations
// tab, if installed) → best auto-selected installed model.
export async function resolveModel(pool: Pool, requested?: string): Promise<string> {
  if (requested) return requested;
  try {
    const r = await pool.query("SELECT value FROM system_settings WHERE key='ai'");
    const configured: string | undefined = r.rows[0]?.value?.active_model;
    if (configured) {
      const status = await aiRouter.probe();
      if (status.models.some((m) => m.name === configured)) return configured;
    }
  } catch (_e) { /* fall through to auto-select */ }
  return aiRouter.selectModel('fast');
}

export async function getConversationHistory(
  pool: Pool,
  caseId: string,
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
  caseId: string,
  userId: string,
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

export async function clearConversationHistory(pool: Pool, caseId: string): Promise<void> {
  await pool.query('DELETE FROM ai_conversations WHERE case_id = $1', [caseId]);
}

export async function getInvestigatorContext(
  pool: Pool,
  caseId: string
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
  caseId: string,
  userId: string,
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

export async function clearInvestigatorContext(pool: Pool, caseId: string): Promise<void> {
  await pool.query('DELETE FROM ai_investigator_context WHERE case_id = $1', [caseId]);
}

export async function buildCaseContext(pool: Pool, caseId: string, query?: string): Promise<CaseContext> {

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
    relevant:            await retrieveRelevant(pool, caseId, query),
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
${ctx.relevant ? `
=== ÉLÉMENTS PERTINENTS À LA QUESTION (recherche ciblée) ===
Ces éléments correspondent directement aux mots-clés de la question — PRIVILÉGIE-les pour répondre précisément et cite-les.
${ctx.relevant.artifacts.length ? 'Artefacts :\n' + ctx.relevant.artifacts.map((a) => `  [${a.level || '?'}] ${a.artifact_type} | ${a.timestamp} | ${a.host_name || '?'} | ${a.user_name || '?'} | ${(a.description || '').slice(0, 150)}`).join('\n') : ''}${ctx.relevant.iocs.length ? '\nIOCs :\n' + ctx.relevant.iocs.map((i) => `  [${i.type}] ${i.value} — ${i.verdict}`).join('\n') : ''}${ctx.relevant.notes.length ? '\nNotes :\n' + ctx.relevant.notes.map((n) => `  [${n.author}] ${(n.content || '').slice(0, 160)}`).join('\n') : ''}
` : ''}
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

// ── Forensics Agent Definitions ───────────────────────────────────────────────
// Inspired by domain-specific agent temperature tuning (My_AI / gonicolas12).
// Each agent appends a focused directive to the shared system prompt and runs
// at its own temperature — low for precise triage, higher for prose generation.

export type AgentType = 'triage' | 'analysis' | 'narrative' | 'agentic';

const AGENT_CONFIG: Partial<Record<AgentType, { temperature: number; directive: string }>> = {
  triage: {
    temperature: 0.1,
    directive: `
=== MODE AGENT : TRIAGE RAPIDE ===
Objectif : Classification et décision d'escalade en moins de 5 lignes.
Format de réponse OBLIGATOIRE :
  VERDICT    : CRITIQUE | ÉLEVÉ | MOYEN | FAIBLE | BÉNIN
  CONFIANCE  : X %
  TECHNIQUE  : T<XXXX.XXX> ou N/A
  ACTION     : une seule phrase d'action immédiate
Ne développe pas — le triage est pour la rapidité, pas l'exhaustivité.`,
  },
  analysis: {
    temperature: 0.3,
    directive: `
=== MODE AGENT : ANALYSE APPROFONDIE ===
Structure ta réponse en 4 sections :
  1. OBSERVATION — ce que les artifacts montrent factuellement
  2. HYPOTHÈSE — scénario d'attaque le plus probable
  3. MITRE ATT&CK — techniques identifiées avec IDs précis
  4. RECOMMANDATIONS — prochaines étapes d'investigation`,
  },
  narrative: {
    temperature: 0.5,
    directive: `
=== MODE AGENT : RÉDACTION RAPPORT ===
Rédige en prose professionnelle destinée à la direction ou au juridique.
Structure : Résumé exécutif (2 phrases) → Chronologie narrative → Impact → Recommandations.
Évite le jargon technique — chaque terme technique doit être explicité.
Chaque affirmation doit être ancrée sur un artifact ou IOC du cas.`,
  },
};

function applyAgentConfig(
  system: string,
  agentType: AgentType = 'analysis'
): { system: string; temperature: number } {
  const cfg = AGENT_CONFIG[agentType] ?? AGENT_CONFIG.analysis!;
  return {
    system:      system + cfg.directive,
    temperature: cfg.temperature,
  };
}

export async function chat(
  pool: Pool,
  caseId: string,
  userId: string,
  message: string,
  model         = '',
  thinkingMode: ThinkingMode = 'no_think',
  agentType:    AgentType    = 'analysis'
): Promise<string> {
  if (!OLLAMA_URL) throw new Error('OLLAMA_URL not configured');

  const useModel = await resolveModel(pool, model);
  const ctx    = await buildCaseContext(pool, caseId, message);
  const { system, temperature } = applyAgentConfig(buildSystemPrompt(ctx), agentType);

  // Fetch history BEFORE saving the new user message to avoid duplicating it.
  const history = await getConversationHistory(pool, caseId, HISTORY_FOR_CONTEXT);

  await saveMessage(pool, caseId, userId, 'user', message, useModel);

  const messages: aiRouter.OllamaMessage[] = [
    { role: 'system',    content: system },
    ...history.map((m) => ({ role: m.role, content: m.content })),
    { role: 'user',      content: message },
  ];

  const response = await aiRouter.chat({ model: useModel, messages, thinkingMode, temperature });

  await saveMessage(pool, caseId, userId, 'assistant', response, useModel);
  return response;
}

export async function chatStream(
  pool: Pool,
  caseId: string,
  userId: string,
  message: string,
  res: import('express').Response,
  model         = '',
  thinkingMode: ThinkingMode = 'no_think',
  agentType:    AgentType    = 'analysis'
): Promise<void> {
  if (!OLLAMA_URL) {
    res.status(503).json({ error: 'OLLAMA_URL not configured' });
    return;
  }

  const useModel = await resolveModel(pool, model);

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

  think('🔎', 'Recherche ciblée (question)', 'loading');
  const relevant = await retrieveRelevant(pool, caseId, message);
  think('🔎', 'Recherche ciblée (question)', 'done', {
    detail: relevant ? `${relevant.artifacts.length + relevant.iocs.length + relevant.notes.length} élément(s) pertinent(s)` : 'aucun',
  });

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
    relevant,
  };

  const agentCfg = applyAgentConfig(buildSystemPrompt(ctx), agentType);
  let system = agentCfg.system;
  const temperature = agentCfg.temperature;

  // Agentic mode (opt-in): let the model call read-only case tools (counts, distributions,
  // targeted searches) and fold the exact results into the prompt before answering.
  if (agentType === 'agentic') {
    think('🔧', 'Outils du cas', 'loading');
    try {
      const aiAgent = require('./aiAgent');
      const toolOut = await aiAgent.runTools(pool, caseId, message, useModel,
        (name: string, _args: any, resStr: string) => think('🔧', `Outil : ${name}`, 'done', { detail: String(resStr).slice(0, 80) }));
      if (toolOut) system += `\n\n=== RÉSULTATS D'OUTILS (calculés sur le cas — chiffres exacts) ===\n${toolOut}\n\nUtilise ces résultats chiffrés tels quels dans ta réponse ; ne les recalcule pas.`;
      think('🔧', 'Outils du cas', 'done', { detail: toolOut ? 'résultats intégrés' : 'aucun outil pertinent' });
    } catch (_e) {
      think('🔧', 'Outils du cas', 'done', { detail: 'indisponible' });
    }
  }

  think('🤖', "Génération de l'analyse", 'generating');

  // Fetch history BEFORE saving the new user message to avoid duplicating it.
  const history = await getConversationHistory(pool, caseId, HISTORY_FOR_CONTEXT);

  await saveMessage(pool, caseId, userId, 'user', message, useModel);

  const messages: aiRouter.OllamaMessage[] = [
    { role: 'system', content: system },
    ...history.map((m) => ({ role: m.role, content: m.content })),
    { role: 'user',   content: message },
  ];

  // SSE keepalive — prevents Traefik/nginx from closing the connection during
  // slow inference (models can take > 30 s before the first token).
  const keepAlive = setInterval(() => {
    try { res.write(': ping\n\n'); } catch (_e) {}
  }, 5_000);

  try {
    await aiRouter.streamChat({
      model: useModel,
      messages,
      thinkingMode,
      temperature,
      onToken: (t) => emit({ response: t }),
      onReasoningToken: (t) => emit({ reasoningToken: t }),
      onDone: async (full) => {
        emit({ done: true, hasContext: Boolean(ctx.investigatorContext) });
        res.write('data: [DONE]\n\n');
        if (full) {
          await saveMessage(pool, caseId, userId, 'assistant', full, useModel).catch(() => {});
        }
      },
      onError: (err) => {
        if (!res.headersSent) {
          res.status(502).json({ error: `Ollama unreachable: ${err.message}` });
        }
      },
    });
  } finally {
    clearInterval(keepAlive);
    res.end();
  }
}

export function isAvailable(): boolean {
  return Boolean(OLLAMA_URL);
}
