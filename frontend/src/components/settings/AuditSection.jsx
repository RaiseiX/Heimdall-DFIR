import { useState, useEffect } from 'react';
import { ChevronLeft, ChevronRight, ShieldCheck } from 'lucide-react';
import { usersAPI } from '../../utils/api';
import { MONO, SectionHead, Btn, Table, tdStyle, Skeletons, Empty } from './shared';
import { useTranslation } from 'react-i18next';

const PAGE = 25;

function IntegrityChip({ label, value, color }) {
  if (!value) return null;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10.5, fontFamily: MONO, padding: '2px 8px', borderRadius: 4,
      background: `color-mix(in srgb, ${color} 9%, transparent)`, color, border: `1px solid color-mix(in srgb, ${color} 19%, transparent)` }}>
      <span style={{ width: 7, height: 7, borderRadius: 2, background: color }} />{value} {label}
    </span>
  );
}

export default function AuditSection() {
  const { t } = useTranslation();
  const [rows, setRows]       = useState([]);
  const [total, setTotal]     = useState(0);
  const [page, setPage]       = useState(0);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [integrity, setIntegrity] = useState(null);

  const verify = async () => {
    setVerifying(true); setIntegrity(null);
    try { const r = await usersAPI.verifyAudit(); setIntegrity(r.data); }
    catch (e) { setIntegrity({ error: e.response?.data?.error || t('settings.audit.verify_failed') }); }
    finally { setVerifying(false); }
  };

  useEffect(() => {
    let alive = true;
    setLoading(true);
    usersAPI.audit({ limit: PAGE, offset: page * PAGE })
      .then(r => { if (!alive) return; setRows(r.data?.rows || r.data?.logs || (Array.isArray(r.data) ? r.data : [])); setTotal(r.data?.total ?? 0); })
      .catch(() => { if (alive) setRows([]); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [page]);

  const pages = Math.max(1, Math.ceil(total / PAGE));

  return (
    <>
      <SectionHead title={t('settings.audit.title')} desc={t('settings.audit.desc')} />

      {/* Integrity verification */}
      <div style={{ marginTop: 14, padding: 14, borderRadius: 8, border: '1px solid var(--fl-border)', background: 'var(--fl-panel)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <Btn variant="primary" onClick={verify} disabled={verifying}>
            <ShieldCheck size={13} /> {verifying ? t('settings.audit.verifying') : t('settings.audit.verify_integrity')}
          </Btn>
          <span style={{ fontSize: 11.5, fontFamily: MONO, color: 'var(--fl-muted)' }}>
            {t('settings.audit.verify_hint')}
          </span>
        </div>
        {integrity && !integrity.error && (
          <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, fontFamily: MONO, color: 'var(--fl-dim)' }}>{t('settings.audit.checked_count', { count: integrity.checked })}</span>
            <IntegrityChip label={t('settings.audit.integrity_valid')} value={integrity.verified} color="var(--fl-ok)" />
            <IntegrityChip label={t('settings.audit.integrity_tampered')} value={integrity.tampered} color="var(--fl-danger)" />
            <IntegrityChip label={t('settings.audit.integrity_missing')} value={integrity.missing} color="var(--fl-warn)" />
            <IntegrityChip label={t('settings.audit.integrity_legacy')} value={integrity.legacy_unverifiable} color="var(--fl-subtle)" />
          </div>
        )}
        {integrity && integrity.tampered > 0 && (
          <div style={{ marginTop: 8, fontSize: 11, fontFamily: MONO, color: 'var(--fl-danger)' }}>
            {t('settings.audit.tampered_detected')}{integrity.tampered_ids?.length ? ` - IDs: ${integrity.tampered_ids.slice(0, 5).join(', ')}${integrity.tampered_ids.length > 5 ? '…' : ''}` : ''}
          </div>
        )}
        {integrity?.error && <div style={{ marginTop: 8, fontSize: 11, fontFamily: MONO, color: 'var(--fl-danger)' }}>✗ {integrity.error}</div>}
      </div>

      {loading ? <Skeletons n={6} h={38} /> : rows.length === 0 ? <Empty text={t('settings.audit.none')} /> : (
        <>
          <Table cols={[[t('settings.audit.date'), 150], [t('settings.audit.actor'), 140], [t('settings.audit.action'), null], [t('settings.audit.entity'), 110], ['IP', 110]]}>
            {rows.map((r, i) => (
              <tr key={r.id || i}>
                <td style={{ ...tdStyle, fontFamily: MONO, fontSize: 10.5, color: 'var(--fl-dim)', whiteSpace: 'nowrap' }}>{r.created_at ? new Date(r.created_at).toLocaleString() : '—'}</td>
                <td style={{ ...tdStyle, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 140 }}>{r.full_name || r.username || t('settings.breadcrumb.system')}</td>
                <td style={{ ...tdStyle, fontFamily: MONO, fontSize: 11, color: 'var(--fl-accent)' }}>{(r.action || '').replace(/_/g, ' ')}</td>
                <td style={{ ...tdStyle, fontFamily: MONO, fontSize: 11, color: 'var(--fl-muted)' }}>{(r.entity_type || '—').replace(/_/g, ' ')}</td>
                <td style={{ ...tdStyle, fontFamily: MONO, fontSize: 10.5, color: 'var(--fl-subtle)', whiteSpace: 'nowrap' }}>{r.ip_address || '—'}</td>
              </tr>
            ))}
          </Table>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 12 }}>
            <Btn onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}><ChevronLeft size={12} /></Btn>
            <span style={{ fontSize: 11, fontFamily: MONO, color: 'var(--fl-muted)' }}>{page + 1} / {pages} · {t('settings.audit.entries_count', { count: total })}</span>
            <Btn onClick={() => setPage(p => Math.min(pages - 1, p + 1))} disabled={page >= pages - 1}><ChevronRight size={12} /></Btn>
          </div>
        </>
      )}
    </>
  );
}
