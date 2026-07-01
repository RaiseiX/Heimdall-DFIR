// Stateless post-parse auto-triage.
// After artifact parsing completes, samples the top suspicious events,
// runs the LLM triage agent, parses the structured verdict, and pushes
// a finding into the persistent alert inbox.
// Does NOT save to conversation history — uses aiRouter directly.
import * as aiRouter from './aiRouter';
import { buildCaseContext, buildSystemPrompt, resolveModel } from './aiService';
import { Pool } from 'pg';

const AGENT_TRIAGE_DIRECTIVE = `
=== MODE AGENT : TRIAGE RAPIDE ===
Objectif : Classification et décision d'escalade en moins de 5 lignes.
Format de réponse OBLIGATOIRE (respecte ces étiquettes exactement) :
  VERDICT    : CRITIQUE | ÉLEVÉ | MOYEN | FAIBLE | BÉNIN
  CONFIANCE  : X %
  TECHNIQUE  : T<XXXX.XXX> ou N/A
  ACTION     : une seule phrase d'action immédiate
Ne développe pas — le triage est pour la rapidité, pas l'exhaustivité.`;

const VERDICT_TO_SEV: Record<string, string> = {
  CRITIQUE: 'critical',
  ÉLEVÉ:    'high',
  ELEVE:    'high',
  MOYEN:    'medium',
  FAIBLE:   'low',
  BÉNIN:    'info',
  BENIN:    'info',
};

function parseVerdict(text: string): {
  severity: string;
  confidence: number;
  technique: string | null;
  action: string;
} {
  const line = (label: string) =>
    text.match(new RegExp(`${label}\\s*:\\s*(.+)`, 'i'))?.[1]?.trim() ?? '';

  const rawVerdict   = line('VERDICT').toUpperCase().replace(/[ÉÈÊË]/g, 'E');
  const rawConf      = line('CONFIANCE').replace('%', '').trim();
  const rawTechnique = line('TECHNIQUE');
  const rawAction    = line('ACTION');

  const severity   = VERDICT_TO_SEV[rawVerdict] ?? 'medium';
  const confidence = Math.min(100, Math.max(0, parseInt(rawConf, 10) || 50));
  const technique  = /T\d{4}/i.test(rawTechnique) ? rawTechnique : null;
  const action     = rawAction || 'Investiguer les événements suspects.';

  return { severity, confidence, technique, action };
}

export interface AutoTriageOptions {
  pool:          Pool;
  caseId:        number;
  resultId:      string;
  artifactTypes: string[];
  totalRecords:  number;
  userId:        number;
  io?:           any;
}

export async function autoTriageArtifact(opts: AutoTriageOptions): Promise<void> {
  const { pool, caseId, resultId, artifactTypes, totalRecords, userId, io } = opts;

  // Skip if no AI backend or trivially small parse.
  const { isAvailable } = await import('./aiService');
  if (!isAvailable()) return;
  if (totalRecords < 5) return;

  // Avoid duplicating an alert if the same parse result is re-triaged.
  const { createAlert } = require('./triageService');
  const dedupKey = `auto:${resultId}`;

  try {
    // Pull top suspicious events for this specific parse result.
    const eventsRes = await pool.query<{
      artifact_type: string; description: string; timestamp: string;
      host_name: string; user_name: string; mitre_technique_id: string; level: string;
    }>(
      `SELECT artifact_type,
              description,
              timestamp,
              COALESCE(host_name, '')          AS host_name,
              COALESCE(user_name, '')          AS user_name,
              COALESCE(mitre_technique_id, '') AS mitre_technique_id,
              COALESCE(raw->>'level', '')      AS level
         FROM collection_timeline
        WHERE result_id = $1
          AND (
            raw->>'level' IN ('critical', 'high', 'medium')
            OR mitre_technique_id IS NOT NULL
          )
        ORDER BY
          CASE raw->>'level' WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
          timestamp DESC
        LIMIT 25`,
      [resultId],
    );

    // If zero suspicious events, fall back to sampling any events.
    const sampleRes = eventsRes.rows.length > 0 ? eventsRes : await pool.query(
      `SELECT artifact_type, description, timestamp,
              COALESCE(host_name, '') AS host_name, COALESCE(user_name, '') AS user_name,
              COALESCE(mitre_technique_id, '') AS mitre_technique_id, '' AS level
         FROM collection_timeline WHERE result_id = $1 ORDER BY timestamp DESC LIMIT 20`,
      [resultId],
    );

    const eventSummary = sampleRes.rows.map(r =>
      `[${r.artifact_type}] ${r.timestamp?.slice(0, 16) ?? ''} ${r.description?.slice(0, 120) ?? ''}` +
      (r.host_name ? ` | host:${r.host_name}` : '') +
      (r.mitre_technique_id ? ` | ${r.mitre_technique_id}` : ''),
    ).join('\n');

    // Build case context + system prompt (no query — triage uses everything).
    const ctx    = await buildCaseContext(pool, caseId);
    const system = buildSystemPrompt(ctx) + AGENT_TRIAGE_DIRECTIVE;
    const model  = await resolveModel(pool);

    const prompt =
      `Artefacts analysés : ${artifactTypes.join(', ')} — ${totalRecords.toLocaleString('fr-FR')} événements indexés.\n` +
      `Top événements suspects :\n${eventSummary || 'Aucun événement suspect détecté.'}\n\n` +
      `Effectue le triage de cette session de parsing.`;

    const response = await aiRouter.chat({
      model,
      messages: [
        { role: 'system', content: system },
        { role: 'user',   content: prompt },
      ],
      thinkingMode: 'no_think',
      temperature:  0.1,
    });

    const { severity, confidence, technique, action } = parseVerdict(response);

    // Only create an alert if the verdict is not pure noise (bénin + high confidence).
    if (severity === 'info' && confidence >= 85) return;

    const title = `[Auto-triage] ${artifactTypes.join('+')} — ${totalRecords.toLocaleString('fr-FR')} evt`;
    const description =
      `IA : ${response.trim().slice(0, 800)}\n\nAction : ${action}`;

    const alert = await createAlert({
      title,
      description,
      source:       'auto_triage',
      severity,
      dedup_key:    dedupKey,
      case_id:      caseId,
      entity_type:  'artifact',
      entity_value: artifactTypes.join(','),
      metadata:     { confidence, technique, result_id: resultId, total_records: totalRecords },
      created_by:   userId,
    });

    // Notify the analyst who triggered parsing.
    if (io && alert) {
      io.to(`user:${userId}`).emit('notification:job_done', {
        type:     'triage',
        caseId,
        status:   severity === 'critical' || severity === 'high' ? 'warning' : 'done',
        message:  `Auto-triage : ${severity.toUpperCase()} — ${action.slice(0, 100)}`,
        alertId:  alert.id,
      });
    }
  } catch (err: any) {
    // Non-fatal — auto-triage failure must never break the parse flow.
    const logger = require('../config/logger').default;
    logger.warn('[auto-triage] failed (non-fatal):', err.message);
  }
}
