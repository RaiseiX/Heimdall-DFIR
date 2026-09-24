import { useState, useEffect, useCallback } from 'react';
import { LogOut, MonitorSmartphone } from 'lucide-react';
import { usersAPI } from '../../utils/api';
import { MONO, SectionHead, Btn, Table, tdStyle, Skeletons, Empty, Msg } from './shared';
import { useTranslation } from 'react-i18next';

export default function SessionsSection() {
  const { t } = useTranslation();
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading]   = useState(true);
  const [msg, setMsg]           = useState('');
  const [confirm, setConfirm]   = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    usersAPI.sessions().then(r => setSessions(r.data?.sessions || [])).catch(() => setSessions([])).finally(() => setLoading(false));
  }, []);
  useEffect(() => { load(); }, [load]);

  const revokeAll = async () => {
    try {
      const r = await usersAPI.revokeAllSessions();
      setMsg(t('settings.sessions.revoked_msg', { count: r.data?.revoked ?? 0 }));
      setConfirm(false); load();
    } catch { setMsg(t('settings.messages.failed')); }
  };

  return (
    <>
      <SectionHead title={t('settings.sessions.title')} desc={t('settings.sessions.desc')} />

      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 14 }}>
        {confirm
          ? <Btn variant="danger" onClick={revokeAll}>{t('settings.sessions.confirm_global_logout')}</Btn>
          : <Btn variant="danger" onClick={() => setConfirm(true)}><LogOut size={13} /> {t('settings.sessions.logout_everywhere')}</Btn>}
        {confirm && <Btn onClick={() => setConfirm(false)}>{t('common.cancel')}</Btn>}
        <Msg msg={msg} />
      </div>

      {loading ? <Skeletons n={2} /> : sessions.length === 0 ? <Empty text={t('settings.sessions.none_active')} /> : (
        <Table cols={[[t('settings.sessions.session'), null], [t('settings.sessions.opened_at'), 170], [t('settings.sessions.expires_at'), 170]]}>
          {sessions.map((s, i) => (
            <tr key={s.id}>
              <td style={tdStyle}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                  <MonitorSmartphone size={13} style={{ color: 'var(--fl-accent)' }} />
                  {t('settings.sessions.session_label', { index: i + 1 })}{i === 0 && <span style={{ fontSize: 9.5, fontFamily: MONO, padding: '1px 6px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-ok) 9%, transparent)', color: 'var(--fl-ok)', border: '1px solid color-mix(in srgb, var(--fl-ok) 19%, transparent)' }}>{t('settings.sessions.most_recent')}</span>}
                </span>
              </td>
              <td style={{ ...tdStyle, fontFamily: MONO, fontSize: 10.5, color: 'var(--fl-muted)' }}>{new Date(s.created_at).toLocaleString()}</td>
              <td style={{ ...tdStyle, fontFamily: MONO, fontSize: 10.5, color: 'var(--fl-muted)' }}>{new Date(s.expires_at).toLocaleString()}</td>
            </tr>
          ))}
        </Table>
      )}
    </>
  );
}
