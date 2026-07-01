import { useState, useEffect } from 'react';
import { Outlet, useParams, useNavigate } from 'react-router-dom';
import { casesAPI } from '../utils/api';
import { Spinner } from '../components/ui';
import { PriorityPill } from '../components/ui/StatusPill';
import AssigneesControl from '../components/cases/AssigneesControl';
import Icon from '../components/ui/Icon';
import { useTranslation } from 'react-i18next';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
const UI   = 'var(--f-ui, "Inter", sans-serif)';

export default function CaseShell({ user }) {
  const { t } = useTranslation();
  const { id } = useParams();
  const navigate = useNavigate();
  const [caseData, setCaseData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    casesAPI.get(id)
      .then(r => setCaseData(r.data))
      .catch(e => setError(e.response?.data?.error || e.message))
      .finally(() => setLoading(false));
  }, [id]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>

      {/* Persistent case command-strip — breadcrumb + state, stable across tab changes */}
      <div style={{
        position: 'sticky', top: 0, zIndex: 110,
        display: 'flex', alignItems: 'center', gap: 10,
        height: 40, padding: '0 16px',
        background: 'var(--fl-bg)',
        borderBottom: '1px solid var(--fl-border)',
        flexShrink: 0,
      }}>
        <button
          onClick={() => navigate('/cases')}
          title={t('case.back_to_list')}
          style={{
            display: 'flex', alignItems: 'center', gap: 5,
            fontFamily: MONO, fontSize: 11, color: 'var(--fl-muted)',
            background: 'none', border: 'none', cursor: 'pointer', padding: 0, flexShrink: 0,
          }}
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-dim)'; }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}>
          <Icon name="case" size={13} />
          {t('case.back_to_list')}
        </button>

        <Icon name="ChevronRight" size={12} style={{ color: 'var(--fl-subtle)', flexShrink: 0 }} />

        {loading ? (
          <Spinner size={12} />
        ) : error ? (
          <span style={{ fontFamily: MONO, fontSize: 11, color: 'var(--fl-danger)' }}>
            {t('casedetail.not_found')}
          </span>
        ) : caseData ? (
          <>
            <span style={{ fontFamily: MONO, fontSize: 11, color: 'var(--fl-text)', fontWeight: 700, flexShrink: 0 }}>
              {caseData.case_number}
            </span>
            <span style={{ color: 'var(--fl-subtle)', fontSize: 13, flexShrink: 0 }}>·</span>
            <span style={{
              fontFamily: UI, fontSize: 12, color: 'var(--fl-dim)',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              flex: 1, minWidth: 0,
            }}>
              {caseData.title}
            </span>
            {/* Status now lives once, as a clickable chip in the CaseDetailPage cockpit strip — not duplicated here. */}
            {caseData.priority && <PriorityPill priority={caseData.priority} />}
            <AssigneesControl caseId={id} user={user} />
          </>
        ) : <span style={{ flex: 1 }} />}
      </div>

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        <Outlet context={{
          caseId:       id,
          caseTitle:    caseData?.title    || '',
          caseNumber:   caseData?.case_number || '',
          caseStatus:   caseData?.status   || '',
          casePriority: caseData?.priority || '',
          user,
        }} />
      </div>
    </div>
  );
}
