'use strict';

// Agentic case tools — read-only, case-scoped queries the LLM can call on demand
// to COMPUTE/AGGREGATE facts that a static context snapshot can't provide
// (exact counts, distributions, targeted searches). Opt-in (agentType='agentic')
// because each tool round adds one inference.

const aiRouter = require('./aiRouter');

const TOOLS = [
  {
    name: 'count_events',
    description: "Compte les événements de la timeline du cas selon des filtres optionnels (hôte, EventID Windows, type d'artefact). Utilise-le pour les questions 'combien de…'.",
    parameters: {
      type: 'object',
      properties: {
        host:          { type: 'string',  description: "nom d'hôte, ex: WS01" },
        event_id:      { type: 'string',  description: 'EventID Windows, ex: 4625' },
        artifact_type: { type: 'string',  description: 'type: evtx, hayabusa, mft, prefetch, amcache, registry…' },
      },
      required: [],
    },
    run: async (pool, caseId, a = {}) => {
      const conds = ['case_id=$1']; const p = [caseId];
      if (a.host)          { p.push(`%${a.host}%`);                    conds.push(`host_name ILIKE $${p.length}`); }
      if (a.event_id)      { p.push(String(a.event_id));              conds.push(`event_id = $${p.length}`); }
      if (a.artifact_type) { p.push(String(a.artifact_type).toLowerCase()); conds.push(`artifact_type = $${p.length}`); }
      const r = await pool.query(`SELECT count(*)::int n FROM collection_timeline WHERE ${conds.join(' AND ')}`, p);
      return `${r.rows[0].n} événement(s)`;
    },
  },
  {
    name: 'top_hosts',
    description: 'Liste les hôtes les plus actifs du cas (par nombre d\'événements).',
    parameters: { type: 'object', properties: { limit: { type: 'integer', description: 'max hôtes (défaut 8)' } }, required: [] },
    run: async (pool, caseId, a = {}) => {
      const lim = Math.min(Math.max(parseInt(a.limit) || 8, 1), 20);
      const r = await pool.query(
        `SELECT host_name, count(*)::int n FROM collection_timeline
         WHERE case_id=$1 AND host_name IS NOT NULL AND host_name<>'' GROUP BY host_name ORDER BY n DESC LIMIT ${lim}`, [caseId]);
      return r.rows.length ? r.rows.map((x) => `${x.host_name}: ${x.n}`).join(' · ') : 'aucun hôte nommé';
    },
  },
  {
    name: 'event_id_distribution',
    description: 'Distribution des EventID Windows les plus fréquents (optionnellement pour un hôte).',
    parameters: { type: 'object', properties: { host: { type: 'string' }, limit: { type: 'integer' } }, required: [] },
    run: async (pool, caseId, a = {}) => {
      const lim = Math.min(Math.max(parseInt(a.limit) || 10, 1), 25);
      const p = [caseId]; let hostc = '';
      if (a.host) { p.push(`%${a.host}%`); hostc = ` AND host_name ILIKE $2`; }
      const r = await pool.query(
        `SELECT event_id, count(*)::int n FROM collection_timeline
         WHERE case_id=$1 AND event_id IS NOT NULL${hostc}
         GROUP BY event_id ORDER BY n DESC LIMIT ${lim}`, p);
      return r.rows.length ? r.rows.map((x) => `EID ${x.event_id}: ${x.n}`).join(' · ') : 'aucun EventID';
    },
  },
  {
    name: 'search_timeline',
    description: 'Recherche des artefacts de la timeline contenant un mot-clé (description, hôte, utilisateur).',
    parameters: { type: 'object', properties: { keyword: { type: 'string' }, limit: { type: 'integer' } }, required: ['keyword'] },
    run: async (pool, caseId, a = {}) => {
      if (!a.keyword) return 'mot-clé requis';
      const lim = Math.min(Math.max(parseInt(a.limit) || 10, 1), 20);
      const r = await pool.query(
        `SELECT artifact_type, host_name, user_name, left(description,120) AS d, timestamp
         FROM collection_timeline WHERE case_id=$1 AND (description ILIKE $2 OR host_name ILIKE $2 OR user_name ILIKE $2)
         ORDER BY timestamp DESC LIMIT ${lim}`, [caseId, `%${a.keyword}%`]);
      return r.rows.length
        ? r.rows.map((x) => `[${x.artifact_type}] ${x.timestamp} ${x.host_name || ''} ${x.user_name || ''} — ${x.d || ''}`).join('\n')
        : 'aucun résultat';
    },
  },
  {
    name: 'list_malicious_iocs',
    description: 'Liste les IOCs marqués malveillants dans le cas.',
    parameters: { type: 'object', properties: {}, required: [] },
    run: async (pool, caseId) => {
      const r = await pool.query(
        `SELECT ioc_type, value FROM iocs WHERE case_id=$1 AND is_malicious=true ORDER BY severity DESC LIMIT 30`, [caseId]);
      return r.rows.length ? r.rows.map((x) => `[${x.ioc_type}] ${x.value}`).join('\n') : 'aucun IOC malveillant';
    },
  },
];

function toolSpecs() {
  return TOOLS.map((t) => ({ type: 'function', function: { name: t.name, description: t.description, parameters: t.parameters } }));
}

// One tool round: ask the model what to call, execute, return a concatenated results string (or null).
async function runTools(pool, caseId, userMessage, model, onTool) {
  let decision;
  try {
    decision = await aiRouter.chatWithTools({
      model,
      messages: [
        { role: 'system', content: "Tu es un assistant DFIR. Si la question nécessite de COMPTER, AGRÉGER ou CHERCHER des données précises du cas, APPELLE le ou les outils appropriés. Si une réponse générale suffit, n'appelle AUCUN outil." },
        { role: 'user', content: userMessage },
      ],
      tools: toolSpecs(),
    });
  } catch (_e) { return null; }

  const calls = (decision && decision.toolCalls) || [];
  if (!calls.length) return null;

  const lines = [];
  for (const c of calls.slice(0, 4)) {
    const def = TOOLS.find((t) => t.name === c.name);
    let result;
    try { result = def ? await def.run(pool, caseId, c.args || {}) : 'outil inconnu'; }
    catch (e) { result = `erreur: ${e.message}`; }
    if (onTool) onTool(c.name, c.args, result);
    lines.push(`• ${c.name}(${JSON.stringify(c.args || {})}) →\n${result}`);
  }
  return lines.join('\n\n');
}

module.exports = { TOOLS, toolSpecs, runTools };
