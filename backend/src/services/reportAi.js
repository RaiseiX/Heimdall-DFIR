'use strict';

// Report AI narrative — shared by the live "draft" endpoint (so the analyst can
// review/edit the text in a code editor before it's baked into the PDF) and the
// one-shot generation path. Uses the same working LLM backend as the chat/copilot
// (aiRouter + OLLAMA_URL), not the legacy AI_ENABLED/AI_BACKEND_URL path.

const aiRouter = require('./aiRouter');

const FIELDS = ['executive_summary', 'key_findings', 'ioc_analysis', 'mitre_analysis', 'timeline_narrative', 'recommendations'];

function isAvailable() {
  return Boolean(process.env.OLLAMA_URL);
}

// Build the factual context handed to the model from already-fetched rows.
// Analyst-provided material (note, bookmark/pin observations, artifact notes) is
// surfaced first — it is the most authoritative signal for the report.
function buildContext(caseData, rows = {}) {
  const iocs = rows.iocs || [];
  const bookmarks = rows.bookmarks || [];
  const pins = rows.pins || [];
  const notes = rows.notes || [];
  return {
    // ── Identité du dossier ──
    case_number: caseData.case_number,
    title: caseData.title,
    status: caseData.status,
    priority: caseData.priority,
    investigator: caseData.investigator_name || null,
    opened_at: caseData.opened_at,
    case_description: caseData.description || null,

    // ── Contexte & conclusions fournis par l'analyste (À PRIVILÉGIER) ──
    analyst_context: rows.analystNote ? String(rows.analystNote).slice(0, 2000) : null,
    analyst_observations: (() => {
      const idToTitle = new Map(bookmarks.filter(b => b && b.id).map(b => [b.id, b.title]));
      return bookmarks
        .filter(b => b && (b.title || b.description))
        .slice(0, 15)
        .map(b => ({
          observation: b.title || null,
          note: b.description || null,
          significance: b.significance || null,
          confidence: b.confidence || null,
          mitre: b.mitre_technique || b.mitre_tactic || null,
          leads_to: (b.links_to && idToTitle.get(b.links_to)) || null,
        }));
    })(),
    pinned_events: pins
      .filter(p => p && (p.title || p.description))
      .slice(0, 12)
      .map(p => ({ event: p.title || null, analyst_note: p.description || null })),
    artifact_notes: notes.map(n => (n && (n.note || n.content)) || null).filter(Boolean).slice(0, 15),

    // ── Données techniques (preuves objectives) ──
    evidence_count: (rows.evidence || []).length,
    ioc_count: iocs.length,
    malicious_iocs: iocs.filter(i => i.is_malicious).map(i => i.value).slice(0, 15),
    mitre_techniques: (rows.mitre || []).map(t => `${t.technique_id} (${t.tactic})`).slice(0, 25),
    critical_detections: (rows.hayabusa || []).slice(0, 12).map(h => `[${h.level}] ${h.rule_title || h.description}`),
    sigma_hits: (rows.sigma || []).slice(0, 10).map(s => `${s.rule_name} (${s.severity})`),
    yara_matches: (rows.yara || []).map(y => y.rule_name).slice(0, 8),
    triage_top: (rows.triage || []).slice(0, 6).map(t => `${t.hostname}: ${t.risk_level} (${t.score}/100)`),
  };
}

async function generateNarrative(caseCtx, model) {
  const sys = [
    "Tu es un analyste DFIR senior (Digital Forensics & Incident Response), expert dans la rédaction de rapports d'investigation forensique de niveau professionnel, destinés à la direction, aux équipes techniques et, le cas échéant, à une procédure judiciaire.",
    "",
    "Méthodologie impérative :",
    "- Fonde TOUTE ton analyse UNIQUEMENT sur les données fournies. N'invente jamais un fait, un IOC, une date, un hôte ou une technique qui ne figure pas dans les données.",
    "- Accorde la priorité absolue au CONTEXTE et aux OBSERVATIONS DE L'ANALYSTE (champs analyst_context, analyst_observations, pinned_events, artifact_notes) : ce sont les conclusions humaines de l'enquête, plus fiables que les détections brutes. Reprends-les et structure-les.",
    "- Corrobore les observations de l'analyste avec les preuves techniques (détections, IOCs, ATT&CK, triage).",
    "- Distingue clairement ce qui est CONFIRMÉ de ce qui est PROBABLE ou HYPOTHÉTIQUE.",
    "- Sois factuel, précis, sobre et professionnel — pas de sensationnalisme.",
    "- Les recommandations doivent être concrètes, actionnables et priorisées (confinement, éradication, remédiation, durcissement).",
    "- Si une donnée manque, reste prudent plutôt que d'extrapoler.",
    "",
    "Tu réponds UNIQUEMENT par un objet JSON valide, en français, sans markdown ni texte avant ou après.",
  ].join('\n');

  const userMsg = `Rédige l'analyse de ce rapport d'investigation forensique.\n\nIMPORTANT : appuie-toi en priorité sur « analyst_context », « analyst_observations », « pinned_events » et « artifact_notes » (les conclusions de l'analyste), puis corrobore avec les données techniques.\n\nDONNÉES DE L'INVESTIGATION :\n${JSON.stringify(caseCtx, null, 2)}\n\nRéponds avec EXACTEMENT cet objet JSON (français, factuel, fondé sur les données — n'invente rien) :\n{\n  "executive_summary": "3-5 phrases : nature de l'incident, vecteur, impact, statut — pour la direction",\n  "key_findings": "3-4 phrases : découvertes principales, en intégrant les observations de l'analyste",\n  "ioc_analysis": "2-3 phrases : analyse des IOCs et de leur signification",\n  "mitre_analysis": "2-3 phrases : TTPs observées et reconstruction de la chaîne d'attaque (ATT&CK)",\n  "timeline_narrative": "2-3 phrases : déroulé chronologique de l'attaque",\n  "recommendations": "4-5 recommandations concrètes et priorisées (confinement, éradication, remédiation, durcissement), séparées par des retours à la ligne"\n}`;

  // Use a model that is actually installed (the hardcoded default 404'd when the
  // user had a different model pulled). selectModel('fast') prefers a small model
  // and gracefully falls back to whatever is available.
  let useModel = model;
  if (!useModel) {
    try { useModel = await aiRouter.selectModel('fast'); } catch (_e) { /* fall through */ }
  }
  useModel = useModel || process.env.AI_MODEL || 'qwen2.5:7b';

  const raw = await aiRouter.chat({
    model: useModel,
    messages: [{ role: 'system', content: sys }, { role: 'user', content: userMsg }],
    thinkingMode: 'no_think',
    temperature: 0.3,
    format: 'json',   // constrain Ollama to emit valid JSON
  });

  const text0 = String(raw || '').trim();
  if (!text0) throw new Error(`le modèle « ${useModel} » n'a renvoyé aucune réponse (modèle absent/non chargé ?)`);
  // Isolate the JSON object from any stray prose / code fences.
  let txt = text0.replace(/```(?:json)?/gi, '').trim();
  const a = txt.indexOf('{'), b = txt.lastIndexOf('}');
  if (a < 0 || b <= a) throw new Error('réponse du modèle non exploitable (aucun JSON détecté)');
  txt = txt.slice(a, b + 1);
  let parsed;
  try { parsed = JSON.parse(txt); }
  catch (_e) { throw new Error('le JSON renvoyé par le modèle est invalide'); }
  // Keep only known fields, coerce to strings.
  const out = {};
  for (const f of FIELDS) if (parsed[f] != null && String(parsed[f]).trim()) out[f] = String(parsed[f]).trim();
  if (!Object.keys(out).length) throw new Error('le modèle n\'a renvoyé aucun champ exploitable');
  return out;
}

// Sanitize an analyst-edited narrative coming from the request body.
function sanitizeNarrative(input) {
  if (!input || typeof input !== 'object') return null;
  const out = {};
  let any = false;
  for (const f of FIELDS) {
    if (input[f] != null && String(input[f]).trim()) { out[f] = String(input[f]).slice(0, 4000); any = true; }
  }
  return any ? out : null;
}

module.exports = { FIELDS, isAvailable, buildContext, generateNarrative, sanitizeNarrative };
