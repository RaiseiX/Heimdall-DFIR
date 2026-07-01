// frontend/src/pages/SuperTimelinePage.jsx
import { useEffect, useState, useRef } from 'react';
import { useParams, useSearchParams, useOutletContext } from 'react-router-dom';
import { useTimelineStore } from '../components/supertimeline/store/useTimelineStore';
import { timelineRulesAPI } from '../utils/api';
import { sortRules } from '../utils/colorRulesEngine';
import CommandBar  from '../components/supertimeline/CommandBar/CommandBar';
import EventGrid   from '../components/supertimeline/EventGrid/EventGrid';
import StatusBar   from '../components/supertimeline/StatusBar/StatusBar';
import DetailPanel from '../components/supertimeline/DetailPanel/DetailPanel';
import TipsTab     from '../components/supertimeline/ExplorerPanel/TipsTab';

export default function SuperTimelinePage() {
  const { id: routeId, caseId: routeCaseId_, collectionId: routeEvidenceId } = useParams();
  const [searchParams] = useSearchParams();
  const shellCtx = useOutletContext() || {};
  const routeCaseId = shellCtx.caseId || routeId || routeCaseId_;
  const { setCaseId, setFilter, setColorRules, loadTimeline } = useTimelineStore();

  useEffect(() => {
    const caseId = routeCaseId || searchParams.get('caseId');
    if (!caseId) return;

    setCaseId(caseId, routeEvidenceId || null);

    const initSearch   = searchParams.get('search');
    const initResultId = searchParams.get('resultId');
    if (initSearch)   setFilter('search', initSearch);
    if (initResultId) setFilter('resultId', initResultId);

    // Load color rules first (fast DB query), then kick off timeline so first render has correct row colors
    timelineRulesAPI.list(caseId)
      .then(r => {
        const rules = r.data?.rules || r.data || [];
        setColorRules(sortRules(Array.isArray(rules) ? rules : []));
      })
      .catch(() => setColorRules([]))
      .finally(() => loadTimeline());
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [routeCaseId, routeEvidenceId]);

  return (
    <div style={{ height: '100%', background: 'var(--fl-bg)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <HeaderStrip />
      <CommandBar />
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <EventGrid />
        <DetailPanel />
      </div>
      <StatusBar />
    </div>
  );
}

function HeaderStrip() {
  const { total, caseId } = useTimelineStore();
  const [tipsOpen, setTipsOpen] = useState(false);
  const panelRef = useRef(null);

  useEffect(() => {
    if (!tipsOpen) return;
    function handler(e) {
      if (panelRef.current && !panelRef.current.contains(e.target)) setTipsOpen(false);
    }
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [tipsOpen]);

  const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
  return (
    <div style={{ height: 46, background: 'var(--fl-bg)', borderBottom: '1px solid var(--fl-border)',
      display: 'flex', alignItems: 'center', padding: '0 18px', gap: 12, flexShrink: 0 }}>
      <span style={{ fontSize: 15, fontWeight: 600, fontFamily: 'var(--f-display, var(--f-ui))', letterSpacing: '-0.01em', color: 'var(--fl-text)' }}>Super Timeline</span>
      {caseId && total > 0 && (
        <span style={{ fontSize: 11.5, fontFamily: MONO, color: 'var(--fl-muted)', fontFeatureSettings: '"tnum"' }}>
          {total.toLocaleString('en-US')} events
        </span>
      )}
      <div style={{ flex: 1 }} />
      <div ref={panelRef} style={{ position: 'relative' }}>
        <button
          onClick={() => setTipsOpen(v => !v)}
          title="Help - search & filters"
          style={{
            width: 24, height: 24, borderRadius: 6, border: `1px solid ${tipsOpen ? 'color-mix(in srgb, var(--fl-accent) 30%, transparent)' : 'var(--fl-border)'}`,
            background: tipsOpen ? 'var(--fl-card)' : 'transparent',
            color: tipsOpen ? 'var(--fl-accent)' : 'var(--fl-muted)',
            cursor: 'pointer', fontFamily: MONO, fontSize: 12, fontWeight: 700,
            display: 'flex', alignItems: 'center', justifyContent: 'center', lineHeight: 1,
          }}
          onMouseEnter={e => { if (!tipsOpen) e.currentTarget.style.color = 'var(--fl-dim)'; }}
          onMouseLeave={e => { if (!tipsOpen) e.currentTarget.style.color = 'var(--fl-muted)'; }}
        >?</button>
        {tipsOpen && (
          <div style={{
            position: 'absolute', top: '100%', right: 0, marginTop: 6, zIndex: 2000,
            width: 280, maxHeight: 'calc(100vh - 80px)',
            background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 8,
            boxShadow: 'var(--fl-shadow-lg)',
            display: 'flex', flexDirection: 'column', overflow: 'hidden',
          }}>
            <div style={{ padding: '9px 12px 7px', borderBottom: '1px solid var(--fl-border2)',
              fontSize: 9, color: 'var(--fl-muted)', textTransform: 'uppercase',
              letterSpacing: '0.1em', fontWeight: 600, fontFamily: MONO, flexShrink: 0 }}>
              Help - search &amp; filters
            </div>
            <TipsTab />
          </div>
        )}
      </div>
    </div>
  );
}
