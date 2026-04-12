import { useState, useEffect } from 'react';
import { Outlet, useParams, useNavigate, useLocation } from 'react-router-dom';
import { casesAPI } from '../utils/api';
import { Spinner } from '../components/ui';
import { ChevronLeft } from 'lucide-react';

const PRIORITY_COLOR = {
  critical: 'var(--fl-danger)',
  high:     'var(--fl-warn)',
  medium:   'var(--fl-gold)',
  low:      'var(--fl-ok)',
};
const STATUS_LABEL = {
  active:  'En cours',
  pending: 'En attente',
  closed:  'Clôturé',
};

export default function CaseShell({ user }) {
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

  const pc = PRIORITY_COLOR[caseData?.priority] || 'var(--fl-accent)';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>

      <div style={{
        position: 'sticky', top: 0, zIndex: 110,
        display: 'flex', alignItems: 'center', gap: 8,
        height: 38, padding: '0 14px',
        background: 'var(--fl-bg, var(--fl-bg))',
        borderBottom: `1px solid ${pc}30`,
        flexShrink: 0,
      }}>

        <button
          onClick={() => navigate('/cases')}
          style={{
            display: 'flex', alignItems: 'center', gap: 3,
            fontFamily: 'monospace', fontSize: 11,
            color: 'var(--fl-muted, #7d8590)',
            background: 'none', border: 'none', cursor: 'pointer', padding: 0,
            flexShrink: 0,
          }}>
          <ChevronLeft size={12} />
          Cas
        </button>

        <span style={{ color: 'var(--fl-border, var(--fl-border))', fontSize: 13, flexShrink: 0 }}>/</span>

        {loading ? (
          <Spinner size={12} />
        ) : error ? (
          <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-danger, #da3633)' }}>
            Cas introuvable
          </span>
        ) : caseData ? (
          <>
            <span style={{ fontFamily: 'monospace', fontSize: 11, color: pc, fontWeight: 700, flexShrink: 0 }}>
              {caseData.case_number}
            </span>
            <span style={{ color: 'var(--fl-border, var(--fl-border))', fontSize: 13, flexShrink: 0 }}>·</span>
            <span style={{
              fontFamily: 'monospace', fontSize: 11,
              color: 'var(--fl-text-muted, #8aa0bc)',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              flex: 1, minWidth: 0,
            }}>
              {caseData.title}
            </span>
          </>
        ) : <span style={{ flex: 1 }} />}

        {caseData && (
          <span style={{
            fontFamily: 'monospace', fontSize: 10, fontWeight: 600,
            padding: '1px 7px', borderRadius: 4,
            background: `${pc}18`, color: pc,
            border: `1px solid ${pc}40`,
            flexShrink: 0,
          }}>
            {STATUS_LABEL[caseData.status] || caseData.status}
          </span>
        )}
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
