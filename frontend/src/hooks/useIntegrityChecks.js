import { useState, useEffect, useCallback, useRef } from 'react';
import { integrityAPI } from '../utils/api';
import { progressionJob } from '../pages/evidenceIntegrity';

const JOB_ARRETE = { enCours: false, done: 0, total: 0 };

export function useIntegrityChecks(socket, caseId) {
  const [checks, setChecks] = useState({});
  const [job, setJob] = useState(JOB_ARRETE);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [traitees, setTraitees] = useState(() => new Set());
  const [cible, setCible] = useState(null);
  const cibleRef = useRef(null);
  const caseRef = useRef(caseId);
  caseRef.current = caseId;

  const charger = useCallback(async (silencieux) => {
    if (!caseId) return;
    if (!silencieux) setLoading(true);
    try {
      const res = await integrityAPI.list(caseId);
      if (caseRef.current !== caseId) return;
      setChecks(res?.data?.checks || {});
      setJob(progressionJob(res?.data?.job));
      setError(null);
    } catch {
      if (caseRef.current === caseId) setError('chargement');
    } finally {
      if (caseRef.current === caseId) setLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    setChecks({});
    setJob(JOB_ARRETE);
    setError(null);
    charger(false);
  }, [charger]);

  useEffect(() => {
    if (!socket || !caseId) return undefined;

    const surProgres = (p) => {
      if (!p || p.caseId !== caseId) return;
      setJob({ enCours: true, done: Number(p.done) || 0, total: Number(p.total) || 0 });
      if (p.evidenceId) {
        setTraitees((prev) => new Set(prev).add(p.evidenceId));
        setChecks((prev) => ({
          ...prev,
          [p.evidenceId]: {
            ...prev[p.evidenceId],
            status: p.status,
            checked_at: new Date().toISOString(),
            stale: false,
          },
        }));
      }
    };
    const surFin = (p) => {
      if (!p || p.caseId !== caseId) return;
      setJob((prev) => ({ ...prev, enCours: false }));
      setTraitees(new Set());
      charger(true);
    };
    const surEchec = (p) => {
      if (!p || p.caseId !== caseId) return;
      setJob((prev) => ({ ...prev, enCours: false }));
      setError('echec');
    };

    socket.on('integrity:progress', surProgres);
    socket.on('integrity:done', surFin);
    socket.on('integrity:failed', surEchec);
    return () => {
      socket.off('integrity:progress', surProgres);
      socket.off('integrity:done', surFin);
      socket.off('integrity:failed', surEchec);
    };
  }, [socket, caseId, charger]);

  const lancer = useCallback(async (evidenceId) => {
    setError(null);
    setTraitees(new Set());
    cibleRef.current = evidenceId ?? null;
    setCible(cibleRef.current);
    try {
      await integrityAPI.start(caseId, evidenceId);
      setJob({ enCours: true, done: 0, total: 0 });
    } catch (err) {
      const statut = err?.response?.status;
      if (statut === 409) {
        setJob((prev) => ({ ...prev, enCours: true }));
      } else {
        setError(statut === 503 ? 'indisponible' : statut === 429 ? 'limite' : 'echec');
      }
    }
  }, [caseId]);

  const relancer = useCallback(() => lancer(cibleRef.current ?? undefined), [lancer]);

  return { checks, job, loading, error, traitees, cible, lancer, relancer, recharger: () => charger(false) };
}
