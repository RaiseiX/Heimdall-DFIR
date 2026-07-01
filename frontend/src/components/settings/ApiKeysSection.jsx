import { useState, useEffect, useCallback } from 'react';
import { Plus, Trash2, Copy, KeyRound } from 'lucide-react';
import { usersAPI } from '../../utils/api';
import { MONO, SectionHead, Btn, Input, Table, tdStyle, Skeletons, Empty, Msg } from './shared';
import { useTranslation } from 'react-i18next';

export default function ApiKeysSection() {
  const { t } = useTranslation();
  const [tokens, setTokens]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [name, setName]       = useState('');
  const [fresh, setFresh]     = useState(null);   // raw token shown once
  const [msg, setMsg]         = useState('');
  const [confirmDel, setConfirmDel] = useState(null);

  const load = useCallback(() => {
    setLoading(true);
    usersAPI.tokens().then(r => setTokens(r.data?.tokens || [])).catch(() => setTokens([])).finally(() => setLoading(false));
  }, []);
  useEffect(() => { load(); }, [load]);

  const flash = (m) => { setMsg(m); setTimeout(() => setMsg(''), 3000); };

  const create = async () => {
    if (!name.trim()) { flash(t('settings.api_keys.name_required')); return; }
    try {
      const r = await usersAPI.createToken(name.trim());
      setFresh(r.data?.token || null);
      setName(''); load();
    } catch (e) { flash(`✗ ${e.response?.data?.error || t('common.error')}`); }
  };
  const revoke = async (id) => {
    try { await usersAPI.revokeToken(id); setConfirmDel(null); load(); flash(t('settings.api_keys.revoked')); }
    catch { flash(t('settings.messages.failed')); }
  };

  return (
    <>
      <SectionHead title={t('settings.api_keys.title')} desc={t('settings.api_keys.desc')} />

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 14, flexWrap: 'wrap' }}>
        <Input placeholder={t('settings.api_keys.name_ph')} value={name} onChange={e => setName(e.target.value)} width={240} />
        <Btn variant="primary" onClick={create}><Plus size={13} /> {t('settings.api_keys.generate')}</Btn>
        <Msg msg={msg} />
      </div>

      {fresh && (
        <div style={{ marginTop: 12, padding: 14, borderRadius: 8, border: '1px solid color-mix(in srgb, var(--fl-ok) 25%, transparent)', background: 'color-mix(in srgb, var(--fl-ok) 5%, transparent)' }}>
          <div style={{ fontSize: 11, fontFamily: MONO, color: 'var(--fl-ok)', marginBottom: 8 }}>{t('settings.api_keys.created_notice')}</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <code style={{ flex: 1, fontSize: 11, fontFamily: MONO, color: 'var(--fl-text)', wordBreak: 'break-all', padding: '8px 10px', borderRadius: 6, background: 'var(--fl-bg)', border: '1px solid var(--fl-border)' }}>{fresh}</code>
            <Btn variant="ok" onClick={() => { navigator.clipboard?.writeText(fresh); }}><Copy size={12} /> {t('settings.api_keys.copy')}</Btn>
            <Btn onClick={() => setFresh(null)}>{t('common.close')}</Btn>
          </div>
        </div>
      )}

      {loading ? <Skeletons n={2} /> : tokens.length === 0 ? <Empty text={t('settings.api_keys.none_active')} /> : (
        <Table cols={[[t('settings.api_keys.name'), null], [t('settings.api_keys.created_at'), 160], [t('settings.api_keys.last_used'), 160], ['', 90]]}>
          {tokens.map(tk => (
            <tr key={tk.id}>
              <td style={tdStyle}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                  <KeyRound size={12} style={{ color: 'var(--fl-accent)' }} />{tk.name}
                </span>
              </td>
              <td style={{ ...tdStyle, fontFamily: MONO, fontSize: 10.5, color: 'var(--fl-muted)' }}>{new Date(tk.created_at).toLocaleString()}</td>
              <td style={{ ...tdStyle, fontFamily: MONO, fontSize: 10.5, color: 'var(--fl-muted)' }}>{tk.last_used ? new Date(tk.last_used).toLocaleString() : t('common.never')}</td>
              <td style={tdStyle}>
                {confirmDel === tk.id
                  ? <Btn variant="danger" onClick={() => revoke(tk.id)}>OK?</Btn>
                  : <button onClick={() => setConfirmDel(tk.id)} title={t('settings.api_keys.revoke')}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-subtle)' }}><Trash2 size={13} /></button>}
              </td>
            </tr>
          ))}
        </Table>
      )}
    </>
  );
}
