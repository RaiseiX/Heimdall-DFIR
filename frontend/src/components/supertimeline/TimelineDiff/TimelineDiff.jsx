import { useEffect, useState } from 'react';
import { useTimelineDiffStore } from '../store/useTimelineDiffStore';
import { evidenceAPI } from '../../../utils/api';

const row = (r) => (
  <div key={`${r.diff_side}-${r.id}`} style={{ display: 'flex', gap: 8, padding: '4px 10px', fontSize: 10.5,
    borderBottom: '1px solid var(--fl-card)', color: 'var(--fl-on-dark)' }}>
    <span style={{ color: 'var(--fl-muted)', whiteSpace: 'nowrap' }}>{new Date(r.timestamp).toISOString().replace('T', ' ').slice(0, 19)}</span>
    <span style={{ color: 'var(--fl-dim)', flexShrink: 0 }}>[{r.artifact_type}]</span>
    <span style={{ color: 'var(--fl-dim)', flexShrink: 0 }}>{r.host_name || '—'}</span>
    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.description || r.source || '—'}</span>
  </div>
);

export default function TimelineDiff({ caseId }) {
  const { sideA, sideB, counts, added, removed, loading, setSide, runDiff } = useTimelineDiffStore();
  const [evidences, setEvidences] = useState([]);

  // reset sides + results when the case changes (panel stays mounted across case nav)
  useEffect(() => { useTimelineDiffStore.setState({ caseId, sideA: {}, sideB: {}, counts: null, added: [], removed: [] }); }, [caseId]);
  useEffect(() => { evidenceAPI.list(caseId).then(r => setEvidences(r.data || [])).catch(() => setEvidences([])); }, [caseId]);

  const picker = (which, side) => (
    <select value={side.evidenceId || ''} onChange={e => setSide(which, { evidenceId: e.target.value || null })}
      style={{ fontFamily: 'inherit', fontSize: 11, background: 'var(--fl-card)', color: 'var(--fl-on-dark)',
        border: '1px solid var(--fl-raised)', borderRadius: 4, padding: '3px 6px' }}>
      <option value="">Côté {which} — choisir une collecte…</option>
      {evidences.map(ev => <option key={ev.id} value={ev.id}>{ev.name || ev.original_filename || ev.id}</option>)}
    </select>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, padding: 12, fontFamily: 'var(--f-mono, monospace)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        {picker('A', sideA)} <span style={{ color: 'var(--fl-dim)' }}>vs</span> {picker('B', sideB)}
        <button onClick={runDiff} style={{ padding: '3px 12px', borderRadius: 4, cursor: 'pointer',
          background: 'var(--fl-card)', border: '1px solid var(--fl-raised)', color: 'var(--fl-accent)', fontFamily: 'inherit', fontSize: 11 }}>Comparer</button>
      </div>
      {loading && <div style={{ color: 'var(--fl-muted)', fontSize: 11 }}>Comparaison…</div>}
      {counts && (
        <div style={{ display: 'flex', gap: 16, fontSize: 11 }}>
          <span style={{ color: 'var(--fl-ok)' }}>+{counts.added} ajoutés</span>
          <span style={{ color: 'var(--fl-danger)' }}>−{counts.removed} retirés</span>
          <span style={{ color: 'var(--fl-muted)' }}>{counts.unchanged} inchangés</span>
        </div>
      )}
      {counts && (
        <div style={{ display: 'flex', gap: 12 }}>
          <div style={{ flex: 1, borderTop: '2px solid var(--fl-ok)' }}>
            <div style={{ fontSize: 10, color: 'var(--fl-ok)', padding: '4px 10px' }}>AJOUTÉS (dans B)</div>
            {added.map(row)}
            {!added.length && <div style={{ padding: 10, color: 'var(--fl-muted)', fontSize: 11 }}>Aucun.</div>}
          </div>
          <div style={{ flex: 1, borderTop: '2px solid var(--fl-danger)' }}>
            <div style={{ fontSize: 10, color: 'var(--fl-danger)', padding: '4px 10px' }}>RETIRÉS (dans A)</div>
            {removed.map(row)}
            {!removed.length && <div style={{ padding: 10, color: 'var(--fl-muted)', fontSize: 11 }}>Aucun.</div>}
          </div>
        </div>
      )}
    </div>
  );
}
