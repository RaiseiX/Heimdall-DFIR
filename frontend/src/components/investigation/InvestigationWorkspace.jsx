import { useState } from 'react';
import WorkflowTracker from './WorkflowTracker';
import FindingsPanel from './FindingsPanel';
import KillChainView from './KillChainView';

const band = {
  border: '1px solid var(--fl-sep)', borderRadius: 12, background: 'var(--fl-card-bg, var(--fl-bg))',
  padding: '16px 18px',
};

/**
 * Investigation workspace — single home for the analyst flow:
 * ① workflow (DFIR phases + tasks) → ② findings (structured forensic notes)
 * → ③ kill chain (built live from findings). All of it feeds the PDF report.
 */
export default function InvestigationWorkspace({ caseId }) {
  // Bump to make the kill chain re-read findings whenever the analyst edits one.
  const [refreshKey, setRefreshKey] = useState(0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 1100, margin: '0 auto' }}>
      <section style={band}><WorkflowTracker caseId={caseId} /></section>
      <section style={band}><FindingsPanel caseId={caseId} onChange={() => setRefreshKey(k => k + 1)} /></section>
      <section style={band}><KillChainView caseId={caseId} refreshKey={refreshKey} /></section>
    </div>
  );
}
