import { useState, useEffect } from 'react';
import { ShieldAlert } from 'lucide-react';
import { settingsAPI } from '../../utils/api';
import { MONO, UI, SectionHead, Row, Input, Btn, Msg } from './shared';
import { useTranslation } from 'react-i18next';

const FIELDS = [
  { key: 'passwordMinLength', min: 8,  max: 128 },
  { key: 'lockoutThreshold', min: 0,  max: 100 },
  { key: 'lockoutWindowMin', min: 1,  max: 1440 },
  { key: 'sessionDurationH', min: 1,  max: 2160 },
  { key: 'inactivityTimeoutMin', min: 0,  max: 1440 },
];

export default function SecuritySection() {
  const { t } = useTranslation();
  const [cfg, setCfg]       = useState(null);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg]       = useState('');

  useEffect(() => { settingsAPI.getSecurity().then(r => setCfg(r.data)).catch(() => setCfg({})); }, []);

  const set = (k, v) => setCfg(c => ({ ...c, [k]: v === '' ? '' : parseInt(v, 10) }));

  const save = async () => {
    setSaving(true); setMsg('');
    try { const r = await settingsAPI.setSecurity(cfg); setCfg(r.data); setMsg(t('settings.security.policy_saved')); }
    catch (e) { setMsg(`✗ ${e.response?.data?.error || t('common.error')}`); }
    finally { setSaving(false); }
  };

  if (!cfg) return <><SectionHead title={t('settings.security.title')} /><div className="fl-skeleton" style={{ height: 200, borderRadius: 8, marginTop: 16, background: 'var(--fl-card)' }} /></>;

  return (
    <>
      <SectionHead title={t('settings.security.title')} desc={t('settings.security.desc')} />

      <div style={{ marginTop: 12, padding: '8px 12px', borderRadius: 6, background: 'color-mix(in srgb, var(--fl-ok) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-ok) 18%, transparent)', display: 'flex', alignItems: 'center', gap: 8 }}>
        <ShieldAlert size={13} style={{ color: 'var(--fl-ok)', flexShrink: 0 }} />
        <span style={{ fontSize: 11.5, fontFamily: UI, color: 'var(--fl-dim)' }}>
          {t('settings.security.apply_hint')}
        </span>
      </div>

      <div style={{ marginTop: 8 }}>
        {FIELDS.map((f, i) => (
          <Row key={f.key} label={t(`settings.security.fields.${f.key}.label`)} desc={t(`settings.security.fields.${f.key}.desc`)} last={i === FIELDS.length - 1}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Input type="number" min={f.min} max={f.max} value={cfg[f.key] ?? ''} onChange={e => set(f.key, e.target.value)} width={80} style={{ textAlign: 'right', fontSize: 13 }} />
              <span style={{ fontSize: 12, color: 'var(--fl-muted)', fontFamily: MONO, minWidth: 70 }}>{t(`settings.security.fields.${f.key}.unit`)}</span>
            </div>
          </Row>
        ))}
      </div>

      <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
        <Btn variant="primary" onClick={save} disabled={saving}>{saving ? t('settings.messages.saving') : t('settings.security.save_policy')}</Btn>
        <Msg msg={msg} />
      </div>
    </>
  );
}
