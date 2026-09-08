import { useEffect, useState, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { controlStyle, controlHover } from '../components/ui/controlIdiom';
import { useParams, useSearchParams, useOutletContext } from 'react-router-dom';
import { useTimelineStore } from '../components/supertimeline/store/useTimelineStore';
import { splitCounts } from '../components/supertimeline/utils/timelineUtils';
import { timelineRulesAPI } from '../utils/api';
import { sortRules } from '../utils/colorRulesEngine';
import CommandBar  from '../components/supertimeline/CommandBar/CommandBar';
import EventGrid   from '../components/supertimeline/EventGrid/EventGrid';
import StatusBar   from '../components/supertimeline/StatusBar/StatusBar';
import DetailPanel from '../components/supertimeline/DetailPanel/DetailPanel';
import ContextPanel from '../components/supertimeline/ContextPanel/ContextPanel';
import TipsTab     from '../components/supertimeline/ExplorerPanel/TipsTab';
import TimelineDiff from '../components/supertimeline/TimelineDiff/TimelineDiff';

const SEGMENT_ROW = { display: 'flex', alignItems: 'center', gap: 16 };

export default function SuperTimelinePage() {
  const { id: routeId, caseId: routeCaseId_, collectionId: routeEvidenceId } = useParams();
  const [searchParams] = useSearchParams();
  const shellCtx = useOutletContext() || {};
  const routeCaseId = shellCtx.caseId || routeId || routeCaseId_;
  const { setCaseId, setFilter, setColorRules, loadTimeline } = useTimelineStore();
  const [showDiff, setShowDiff] = useState(false);

  useEffect(() => {
    const caseId = routeCaseId || searchParams.get('caseId');
    if (!caseId) return;

    setCaseId(caseId, routeEvidenceId || null);

    const initSearch   = searchParams.get('search');
    const initResultId = searchParams.get('resultId');
    const initHuntId   = searchParams.get('huntId');
    if (initSearch)   setFilter('search', initSearch);
    if (initResultId) setFilter('resultId', initResultId);
    if (initHuntId)   setFilter('huntId', initHuntId);

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
      <HeaderStrip showDiff={showDiff} setShowDiff={setShowDiff} />
      <CommandBar />
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <EventGrid />
        <DetailPanel />
        <ContextPanel />
      </div>
      {showDiff && <TimelineDiff caseId={routeCaseId} />}
      <StatusBar />
    </div>
  );
}

const fmtCount = (n, locale) => Number(n || 0).toLocaleString(locale || undefined);

function HeaderStrip({ showDiff, setShowDiff }) {
  const { t, i18n } = useTranslation();
  const { total, undated, caseId, nature, setNature } = useTimelineStore();
  const { dated } = splitCounts(total, undated);
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
          <span style={{ color: 'var(--fl-dim)' }}>{fmtCount(dated, i18n.language)}</span>{' '}
          {t('timeline.header.events', { count: dated })}
          {undated > 0 && (
            <>
              <span style={{ color: 'var(--fl-subtle)', margin: '0 6px' }}>·</span>
              {fmtCount(undated, i18n.language)}{' '}
              {t('timeline.header.inventory', { count: undated })}
            </>
          )}
        </span>
      )}
      {caseId && undated > 0 && (
        <div style={SEGMENT_ROW} role="group" aria-label={t('timeline.nature_label')}>
          {['all', 'dated', 'undated'].map(key => {
            const on = (nature || 'all') === key;
            return (
              <button key={key} onClick={() => setNature(key)} aria-pressed={on}
                style={controlStyle(on)} {...controlHover(on)}>
                {t(`timeline.nature_${key}`)}
              </button>
            );
          })}
        </div>
      )}
      <div style={{ flex: 1 }} />
      <button
        onClick={() => setShowDiff(v => !v)}
        title="Comparer deux collectes"
        aria-pressed={showDiff}
        style={controlStyle(showDiff)} {...controlHover(showDiff)}
      >Diff</button>
      <div ref={panelRef} style={{ position: 'relative' }}>
        <button
          onClick={() => setTipsOpen(v => !v)}
          title="Help - search & filters"
          aria-pressed={tipsOpen}
          style={controlStyle(tipsOpen)} {...controlHover(tipsOpen)}
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
