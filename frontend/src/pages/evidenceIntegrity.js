const ETATS_JOB_EN_COURS = new Set(['active', 'waiting', 'delayed', 'prioritized']);

const PAR_STATUT = {
  ok: { cle: 'ok', ton: 'ok' },
  skipped: { cle: 'stockage-objet', ton: 'neutral' },
  source_not_preserved: { cle: 'original-perdu', ton: 'warn' },
  missing: { cle: 'absent', ton: 'warn' },
  no_stored_file: { cle: 'absent', ton: 'warn' },
};

const IMPOSSIBLE = { cle: 'impossible', ton: 'warn' };

export function etatIntegrite(check, enCours) {
  if (enCours) return { cle: 'en-cours', ton: 'neutral', date: null };
  if (!check) return { cle: 'non-controle', ton: 'neutral', date: null };

  const date = check.checked_at ?? null;

  if (check.status === 'mismatch') return { cle: 'ecart', ton: 'alert', date };
  if (check.last_mismatch_at) return { cle: 'ecart', ton: 'alert', date: check.last_mismatch_at };
  if (check.status === 'ok' && check.stale) return { cle: 'perime', ton: 'warn', date };

  return { ...(PAR_STATUT[check.status] || IMPOSSIBLE), date };
}

export function enCoursPour(ev, integrite) {
  if (!ev || !integrite?.job?.enCours) return false;
  if (integrite.traitees?.has(ev.id)) return false;
  return integrite.cible == null || integrite.cible === ev.id;
}

export function progressionJob(job) {
  if (!job) return { enCours: false, done: 0, total: 0 };
  const p = job.progress;
  const objet = p && typeof p === 'object';
  return {
    enCours: ETATS_JOB_EN_COURS.has(job.state),
    done: objet && Number.isFinite(p.done) ? p.done : 0,
    total: objet && Number.isFinite(p.total) ? p.total : 0,
  };
}
