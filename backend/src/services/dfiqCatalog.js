// Pure DFIQ catalog loader: normalize a vendored snapshot then idempotently
// upsert into the catalog tables (upsert by dfiq_id; never touch is_custom rows).
'use strict';

function normalizeCatalog(catalog) {
  const scenarios = [], questions = [], approaches = [];
  for (const s of catalog?.scenarios || []) {
    if (!s.title) throw new Error(`DFIQ scenario missing title: ${JSON.stringify(s).slice(0, 80)}`);
    if (!s.dfiq_id) throw new Error(`DFIQ scenario missing dfiq_id: ${JSON.stringify(s).slice(0, 80)}`);
    scenarios.push({ dfiq_id: s.dfiq_id, title: s.title, description: s.description || null,
      tags: s.tags || [], raw: s });
    let qi = 0;
    for (const q of s.questions || []) {
      if (!q.text) throw new Error(`DFIQ question missing text in ${s.dfiq_id || s.title}`);
      if (!q.dfiq_id) throw new Error(`DFIQ question missing dfiq_id in ${s.dfiq_id || s.title}`);
      const qKey = { scenario_dfiq_id: s.dfiq_id, dfiq_id: q.dfiq_id };
      questions.push({ ...qKey, facet_dfiq_id: q.facet_dfiq_id || null, facet_name: q.facet_name || null,
        text: q.text, position: qi++, raw: q });
      let ai = 0;
      for (const a of q.approaches || []) {
        approaches.push({ question_dfiq_id: q.dfiq_id, scenario_dfiq_id: s.dfiq_id, name: a.name || 'Approach',
          description: a.description || null, data_sources: a.data_sources || [], refs: a.refs || [],
          position: ai++, raw: a });
      }
    }
  }
  return { scenarios, questions, approaches };
}

async function loadCatalog(pool, catalog) {
  const n = normalizeCatalog(catalog);
  const scenarioIdByDfiq = {}, questionIdByDfiq = {};
  for (const s of n.scenarios) {
    const r = await pool.query(
      `INSERT INTO dfiq_scenarios (dfiq_id, title, description, tags, is_custom, source, raw)
       VALUES ($1,$2,$3,$4,FALSE,'dfiq',$5)
       ON CONFLICT (dfiq_id) DO UPDATE SET title=$2, description=$3, tags=$4, raw=$5, updated_at=NOW()
         WHERE dfiq_scenarios.is_custom = FALSE
       RETURNING id, dfiq_id`, [s.dfiq_id, s.title, s.description, s.tags, JSON.stringify(s.raw)]);
    // ON CONFLICT with WHERE may skip (custom); re-select to get the id either way
    const id = r.rows[0]?.id || (await pool.query('SELECT id FROM dfiq_scenarios WHERE dfiq_id=$1', [s.dfiq_id])).rows[0].id;
    scenarioIdByDfiq[s.dfiq_id] = id;
  }
  for (const q of n.questions) {
    const sid = scenarioIdByDfiq[q.scenario_dfiq_id];
    const r = await pool.query(
      `INSERT INTO dfiq_questions (scenario_id, dfiq_id, facet_dfiq_id, facet_name, text, position, is_custom, raw)
       VALUES ($1,$2,$3,$4,$5,$6,FALSE,$7)
       ON CONFLICT (scenario_id, dfiq_id) DO UPDATE SET facet_dfiq_id=$3, facet_name=$4, text=$5, position=$6, raw=$7
         WHERE dfiq_questions.is_custom = FALSE
       RETURNING id, dfiq_id`, [sid, q.dfiq_id, q.facet_dfiq_id, q.facet_name, q.text, q.position, JSON.stringify(q.raw)]);
    // ON CONFLICT with WHERE may skip (custom); re-select to get the id either way
    const qid = r.rows[0]?.id || (await pool.query('SELECT id FROM dfiq_questions WHERE scenario_id=$1 AND dfiq_id=$2', [sid, q.dfiq_id])).rows[0].id;
    questionIdByDfiq[`${q.scenario_dfiq_id}::${q.dfiq_id}`] = qid;
  }
  // approaches: replace-all per question (read-mostly, no natural key) — delete then insert for seeded questions
  for (const q of n.questions) {
    const qid = questionIdByDfiq[`${q.scenario_dfiq_id}::${q.dfiq_id}`];
    await pool.query('DELETE FROM dfiq_approaches WHERE question_id=$1', [qid]);
  }
  for (const a of n.approaches) {
    const qid = questionIdByDfiq[`${a.scenario_dfiq_id}::${a.question_dfiq_id}`];
    if (!qid) continue;
    await pool.query(
      `INSERT INTO dfiq_approaches (question_id, name, description, data_sources, refs, position, raw)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [qid, a.name, a.description, a.data_sources, a.refs, a.position, JSON.stringify(a.raw)]);
  }
  return { scenarios: n.scenarios.length, questions: n.questions.length, approaches: n.approaches.length };
}

module.exports = { normalizeCatalog, loadCatalog };
