import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import WorkflowTracker from './WorkflowTracker';
import KanbanBoard from './KanbanBoard/KanbanBoard';
import FindingsPanel from './FindingsPanel';
import KillChainView from './KillChainView';
import DfiqPanel from './DfiqPanel/DfiqPanel';

const band = {
  border: '1px solid var(--fl-sep)', borderRadius: 12, background: 'var(--fl-card-bg, var(--fl-bg))',
  padding: '16px 18px',
};

function ToggleButton({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      style={{
        background: active ? 'var(--fl-accent)' : 'transparent',
        color: active ? '#050c18' : 'var(--fl-subtle)',
        border: 'none', borderRadius: 5, cursor: 'pointer',
        padding: '3px 10px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
        fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em',
      }}
    >
      {children}
    </button>
  );
}

/**
 * Investigation workspace — single home for the analyst flow:
 * ① workflow (DFIR phases + tasks) OR Kanban board (status columns)
 * → ② findings (structured forensic notes) → ③ kill chain (built live from findings).
 * All of it feeds the PDF report.
 */
export default function InvestigationWorkspace({ caseId }) {
  const { t } = useTranslation();
  // Bump to make the kill chain re-read findings whenever the analyst edits one.
  const [refreshKey, setRefreshKey] = useState(0);
  const [view, setView] = useState('phases'); // 'phases' | 'kanban'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 1100, margin: '0 auto' }}>
      <section style={band}>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 4, marginBottom: 10 }}>
          <div style={{ display: 'inline-flex', gap: 2, padding: 2, borderRadius: 7, border: '1px solid var(--fl-sep)', background: 'var(--fl-bg)' }}>
            <ToggleButton active={view === 'phases'} onClick={() => setView('phases')}>{t('investigation.view_phases')}</ToggleButton>
            <ToggleButton active={view === 'kanban'} onClick={() => setView('kanban')}>{t('investigation.view_kanban')}</ToggleButton>
          </div>
        </div>
        {view === 'phases'
          ? <WorkflowTracker caseId={caseId} />
          : <KanbanBoard caseId={caseId} />}
      </section>
      <section style={band}><FindingsPanel caseId={caseId} onChange={() => setRefreshKey(k => k + 1)} /></section>
      <section style={band}><DfiqPanel caseId={caseId} /></section>
      <section style={band}><KillChainView caseId={caseId} refreshKey={refreshKey} /></section>
    </div>
  );
}
