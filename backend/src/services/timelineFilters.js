const { pushTextFilter, pushSearchFilter } = require('../utils/textFilter');
const { pushProviderFilter } = require('./timelineProviderFilter');
const { pushHashFilter } = require('./timelineHashFilter');
const { hitsOnlyPredicate } = require('./huntDetections');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function shiftHuntPredicate(where, nextParamIndex) {
  return String(where).replace(/\$(\d+)/g, (_m, n) => `$${parseInt(n, 10) + nextParamIndex - 1}`);
}

function listesDe(q) {
  const rawTags = q.tags || q.tag;
  return {
    toolList: (!q.tool_op && q.tool)
      ? String(q.tool).split(',').map(s => s.trim()).filter(Boolean) : null,
    extList: (!q.ext_op && q.ext)
      ? String(q.ext).split(',').map(s => s.trim().toLowerCase()).filter(Boolean) : null,
    eventIdList: q.event_id
      ? String(q.event_id).split(',').map(s => parseInt(s, 10)).filter(Number.isFinite) : null,
    tagList: rawTags
      ? String(rawTags).split(',').map(s => s.trim()).filter(t => t && /^[\w:.\-]{1,64}$/.test(t)) : null,
  };
}

function aDesFiltresAvances(q) {
  const l = listesDe(q);
  const detection = Boolean(q.detections || q.detection_severity || q.detection_category);
  return Boolean(l.toolList || l.extList || l.eventIdList || l.tagList || detection || q.hunt_id);
}

async function validerEvidenceIds(pool, caseId, q) {
  if (q.evidence_id || !q.evidence_ids) return { ok: true, ids: null };

  const ids = String(q.evidence_ids).split(',').map(s => s.trim()).filter(Boolean);
  const invalides = ids.filter(id => !UUID_RE.test(id));
  if (invalides.length > 0) {
    return { ok: false, status: 400, error: `Paramètres evidence_ids invalides: ${invalides.slice(0, 3).join(', ')}` };
  }
  if (ids.length === 0) return { ok: true, ids: null };

  const check = await pool.query(
    `SELECT id FROM evidence WHERE id = ANY($1::uuid[]) AND case_id = $2`,
    [ids, caseId],
  );
  if (check.rows.length !== ids.length) {
    return { ok: false, status: 403, error: 'Accès refusé : une ou plusieurs collectes n\'appartiennent pas à ce cas' };
  }
  return { ok: true, ids };
}

function pushTimelineFilters(q, ctx) {
  const { conditions, params } = ctx;
  const hostCol = ctx.hostCol || 'host_name';
  let pi = ctx.pi;

  const searchOp = q.search_op || 'contains';
  const hostOp   = q.host_name_op || 'contains';
  const userOp   = q.user_name_op || 'contains';
  const { toolList, extList, eventIdList, tagList } = listesDe(q);

  if (q.artifact_types) {
    conditions.push(`artifact_type = ANY($${pi++})`);
    params.push(String(q.artifact_types).split(','));
  }
  if (q.search || searchOp === 'empty' || searchOp === 'not_empty')
    pi = pushSearchFilter(q.search || '', searchOp, pi, conditions, params);

  if (q.start_time) { conditions.push(`timestamp >= $${pi++}`); params.push(q.start_time); }
  if (q.end_time)   { conditions.push(`timestamp <= $${pi++}`); params.push(q.end_time);   }

  if (q.host_name || hostOp === 'empty' || hostOp === 'not_empty')
    pi = pushTextFilter(hostCol, q.host_name || '', hostOp, pi, conditions, params);
  if (q.user_name || userOp === 'empty' || userOp === 'not_empty')
    pi = pushTextFilter('user_name', q.user_name || '', userOp, pi, conditions, params);

  if (q.result_id)   { conditions.push(`result_id = $${pi++}`);   params.push(q.result_id);   }
  if (q.evidence_id) { conditions.push(`evidence_id = $${pi++}`); params.push(q.evidence_id); }
  if (ctx.validatedEvidenceIds) {
    conditions.push(`evidence_id = ANY($${pi++}::uuid[])`);
    params.push(ctx.validatedEvidenceIds);
  }

  if (q.tool_op && (q.tool || q.tool_op === 'empty' || q.tool_op === 'not_empty'))
    pi = pushTextFilter('tool', q.tool || '', q.tool_op, pi, conditions, params);

  if (q.artifact_name_op && (q.artifact_name || q.artifact_name_op === 'empty' || q.artifact_name_op === 'not_empty'))
    pi = pushTextFilter('artifact_name', q.artifact_name || '', q.artifact_name_op, pi, conditions, params);

  if (toolList && toolList.length) {
    conditions.push(`tool = ANY($${pi++}::text[])`);
    params.push(toolList);
  }

  if (q.provider || q.provider_op === 'empty' || q.provider_op === 'not_empty')
    pi = pushProviderFilter(q.provider || '', q.provider_op || 'equals', pi, conditions, params);

  if (q.sha1 || q.sha1_op === 'empty' || q.sha1_op === 'not_empty')
    pi = pushHashFilter(q.sha1 || '', q.sha1_op || 'equals', pi, conditions, params);

  if (q.ext_op && (q.ext || q.ext_op === 'empty' || q.ext_op === 'not_empty'))
    pi = pushTextFilter('ext', q.ext || '', q.ext_op, pi, conditions, params);
  if (extList && extList.length) {
    conditions.push(`lower(ext) = ANY($${pi++}::text[])`);
    params.push(extList);
  }

  if (eventIdList && eventIdList.length) {
    conditions.push(`event_id = ANY($${pi++}::int[])`);
    params.push(eventIdList);
  }
  if (tagList && tagList.length) {
    conditions.push(`tags && $${pi++}::text[]`);
    params.push(tagList);
  }

  const hitsOnly = q.detections === 'hits_only' || q.detections === 'hits'
                || q.detections === '1' || q.detections === 'true';
  if (hitsOnly) conditions.push(hitsOnlyPredicate());

  if (q.detection_severity && /^(greyware|low|medium|high|critical)(,(greyware|low|medium|high|critical))*$/.test(String(q.detection_severity))) {
    const sevList = String(q.detection_severity).split(',');
    conditions.push('(' + sevList.map((_, i) => `detections @> $${pi + i}::jsonb`).join(' OR ') + ')');
    for (const s of sevList) params.push(JSON.stringify([{ severity: s }]));
    pi += sevList.length;
  }
  if (q.detection_category && /^[\w_]{1,32}(,[\w_]{1,32})*$/.test(String(q.detection_category))) {
    const catList = String(q.detection_category).split(',');
    conditions.push('(' + catList.map((_, i) => `detections @> $${pi + i}::jsonb`).join(' OR ') + ')');
    for (const c of catList) params.push(JSON.stringify([{ category: c }]));
    pi += catList.length;
  }

  if (ctx.huntPredicate) {
    conditions.push(`(${shiftHuntPredicate(ctx.huntPredicate.where, pi)})`);
    params.push(...ctx.huntPredicate.params);
    pi += ctx.huntPredicate.params.length;
  }

  return pi;
}

module.exports = {
  pushTimelineFilters,
  listesDe,
  aDesFiltresAvances,
  validerEvidenceIds,
  shiftHuntPredicate,
  UUID_RE,
};
