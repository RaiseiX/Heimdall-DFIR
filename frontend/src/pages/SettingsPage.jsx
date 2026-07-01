import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ChevronRight, ShieldCheck, Check, X as XIcon, ExternalLink } from 'lucide-react';
import { usePreferences } from '../utils/preferences';
import { useTheme } from '../utils/theme';
import { isAdmin, currentUser } from '../utils/auth';
import { settingsAPI } from '../utils/api';
import { MONO, UI, Row, Toggle, SegToggle, SectionHead, Btn, Input, Msg } from '../components/settings/shared';
import TeamSection from '../components/settings/TeamSection';
import AuditSection from '../components/settings/AuditSection';
import RetentionSection from '../components/settings/RetentionSection';
import ApiKeysSection from '../components/settings/ApiKeysSection';
import SessionsSection from '../components/settings/SessionsSection';
import IntegrationsSection from '../components/settings/IntegrationsSection';
import SecuritySection from '../components/settings/SecuritySection';
import { useTranslation } from 'react-i18next';

const CHAT_COLORS = ['var(--fl-accent)', 'var(--fl-ok)', 'var(--fl-warn)', 'var(--fl-danger)', 'var(--fl-purple)', 'var(--fl-pink)', 'var(--fl-gold)'];

// ── Section catalogue (admin-gated groups flagged) ───────────────────────────
const buildGroups = (t) => [
  { id: 'account', label: t('settings.groups.account'), admin: false, items: [
    { id: 'profile',       label: t('settings.nav.profile') },
    { id: 'notifications', label: t('settings.nav.notifications') },
    { id: 'apikeys',       label: t('settings.nav.apikeys') },
    { id: 'sessions',      label: t('settings.nav.sessions') },
  ]},
  { id: 'workspace', label: t('settings.groups.workspace'), admin: true, items: [
    { id: 'team',  label: t('settings.nav.team') },
    { id: 'roles', label: t('settings.nav.roles') },
    { id: 'audit', label: t('settings.nav.audit') },
  ]},
  { id: 'platform', label: t('settings.groups.platform'), admin: true, items: [
    { id: 'security',     label: t('settings.nav.security') },
    { id: 'retention',    label: t('settings.nav.retention') },
    { id: 'integrations', label: t('settings.nav.integrations') },
    { id: 'sla',          label: t('settings.nav.sla') },
  ]},
  { id: 'appearance', label: t('settings.groups.appearance'), admin: false, items: [
    { id: 'theme',     label: t('settings.nav.theme') },
    { id: 'density',   label: t('settings.nav.density') },
    { id: 'shortcuts', label: t('settings.nav.shortcuts') },
  ]},
];

// ── SLA (system_settings via settingsAPI) ────────────────────────────────────
function SlaSection() {
  const { t } = useTranslation();
  const [sla, setSla]   = useState({ urgentH: 24, warningH: 72, upcomingH: 168 });
  const [saving, setSaving] = useState(false);
  const [msg, setMsg]   = useState('');
  useEffect(() => { settingsAPI.getDashboard().then(r => { if (r.data?.sla) setSla(r.data.sla); }).catch(() => {}); }, []);
  const ordered = Number(sla.urgentH) > 0 && Number(sla.warningH) > Number(sla.urgentH) && Number(sla.upcomingH) > Number(sla.warningH);
  const save = async () => {
    setSaving(true); setMsg('');
    try { const r = await settingsAPI.setDashboard({ sla }); if (r.data?.sla) setSla(r.data.sla); setMsg(t('settings.messages.saved')); }
    catch { setMsg(t('settings.messages.failed')); } finally { setSaving(false); }
  };
  const FIELDS = [['urgentH', t('settings.sla.urgent'), 'var(--fl-danger)'], ['warningH', t('settings.sla.warning'), 'var(--fl-warn)'], ['upcomingH', t('settings.sla.upcoming'), 'var(--fl-purple)']];
  return (
    <>
      <SectionHead title={t('settings.sla.title')} desc={t('settings.sla.desc')} />
      <div style={{ marginTop: 8 }}>
        {FIELDS.map(([k, label, color]) => (
          <Row key={k} label={<span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}><span style={{ width: 8, height: 8, borderRadius: 2, background: color }} />{label}</span>}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Input type="number" min="1" value={sla[k]} onChange={e => setSla(s => ({ ...s, [k]: parseInt(e.target.value, 10) || '' }))} width={80} style={{ textAlign: 'right', fontSize: 13, paddingRight: 22 }} />
              <span style={{ fontSize: 12, color: 'var(--fl-muted)', fontFamily: MONO }}>{t('settings.sla.hours')}</span>
            </div>
          </Row>
        ))}
      </div>
      {!ordered && <p style={{ fontSize: 11.5, color: 'var(--fl-warn)', marginTop: 10 }}>{t('settings.sla.order_hint')}</p>}
      <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
        <Btn variant="primary" onClick={save} disabled={!ordered || saving}>{saving ? t('settings.messages.saving') : t('settings.sla.save')}</Btn>
        <Msg msg={msg} />
      </div>
    </>
  );
}

// ── Roles capability matrix (informational) ──────────────────────────────────
// [capability, analyst, team_lead, admin]
const ROLE_COLS = [
  { key: 'analyst',   label: 'analyst' },
  { key: 'team_lead', label: 'team lead' },
  { key: 'admin',     label: 'admin' },
];

function RolesSection() {
  const { t } = useTranslation();
  const capabilities = [
    [t('settings.roles.capabilities.view_cases'), true,  true,  true],
    [t('settings.roles.capabilities.edit_cases'), true,  true,  true],
    [t('settings.roles.capabilities.run_scans'), true,  true,  true],
    [t('settings.roles.capabilities.create_rules'), true,  true,  true],
    [t('settings.roles.capabilities.view_all_cases'), false, true, true],
    [t('settings.roles.capabilities.assign_analysts'), false, true,  true],
    [t('settings.roles.capabilities.import_rules'), false, false, true],
    [t('settings.roles.capabilities.manage_feeds'), false, false, true],
    [t('settings.roles.capabilities.manage_accounts'), false, false, true],
    [t('settings.roles.capabilities.view_audit'), false, false, true],
    [t('settings.roles.capabilities.configure_platform'), false, false, true],
    [t('settings.roles.capabilities.gdpr_purge'), false, false, true],
  ];
  return (
    <>
      <SectionHead title={t('settings.roles.title')} desc={t('settings.roles.desc')} />
      <div style={{ border: '1px solid var(--fl-border)', borderRadius: 8, overflow: 'hidden', marginTop: 16 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ background: 'var(--fl-bg)', borderBottom: '1px solid var(--fl-border)' }}>
              <th style={{ textAlign: 'left', padding: '7px 10px', fontSize: 9.5, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)' }}>{t('settings.roles.capability')}</th>
              {ROLE_COLS.map(r => (
                <th key={r.key} style={{ width: 90, textAlign: 'center', padding: '7px 10px', fontSize: 9.5, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.1em', color: r.key === 'admin' ? 'var(--fl-accent)' : r.key === 'team_lead' ? 'var(--fl-purple)' : 'var(--fl-muted)' }}>{r.label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {capabilities.map(([cap, analyst, teamLead, admin], i) => (
              <tr key={cap}>
                <td style={{ padding: '0 10px', height: 36, borderBottom: i < capabilities.length - 1 ? '1px solid var(--fl-border2)' : 'none', fontSize: 12, fontFamily: UI, color: 'var(--fl-text)' }}>{cap}</td>
                {[analyst, teamLead, admin].map((ok, j) => (
                  <td key={j} style={{ textAlign: 'center', borderBottom: i < capabilities.length - 1 ? '1px solid var(--fl-border2)' : 'none' }}>
                    {ok ? <Check size={13} style={{ color: 'var(--fl-ok)' }} /> : <XIcon size={13} style={{ color: 'var(--fl-subtle)' }} />}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

// ── Keyboard shortcuts reference ─────────────────────────────────────────────
function ShortcutsSection() {
  const { t } = useTranslation();
  const shortcuts = [
    ['⌘ / Ctrl + K', t('settings.shortcuts.command_palette')],
    [t('settings.shortcuts.escape_key'), t('settings.shortcuts.close_active')],
    ['⌘ / Ctrl + C', t('settings.shortcuts.copy_selection')],
    ['↑ / ↓', t('settings.shortcuts.navigate_rows')],
    [t('settings.shortcuts.enter_key'), t('settings.shortcuts.open_selected')],
  ];
  return (
    <>
      <SectionHead title={t('settings.shortcuts.title')} desc={t('settings.shortcuts.desc')} />
      <div style={{ marginTop: 16, display: 'flex', flexDirection: 'column' }}>
        {shortcuts.map(([keys, desc], i) => (
          <div key={keys} style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '12px 0', borderBottom: i < shortcuts.length - 1 ? '1px solid var(--fl-border2)' : 'none' }}>
            <kbd style={{ minWidth: 110, padding: '4px 10px', borderRadius: 6, background: 'var(--fl-card)', border: '1px solid var(--fl-border)', fontFamily: MONO, fontSize: 11, color: 'var(--fl-accent)', textAlign: 'center' }}>{keys}</kbd>
            <span style={{ fontSize: 12.5, fontFamily: UI, color: 'var(--fl-dim)' }}>{desc}</span>
          </div>
        ))}
      </div>
    </>
  );
}

export default function SettingsPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { prefs, updatePref } = usePreferences();
  const { mode, toggle } = useTheme();
  const admin = isAdmin();
  const user = currentUser();
  const [active, setActive] = useState('profile');

  const groups = buildGroups(t).filter(g => !g.admin || admin);

  function renderSection() {
    switch (active) {
      case 'profile':
        return (
          <>
            <SectionHead title={t('settings.profile.title')} desc={t('settings.profile.desc')} />
            <Row label={t('settings.profile.display_name')} desc={t('settings.profile.display_name_desc')}>
              <Input value={prefs.display_name || ''} onChange={e => updatePref('display_name', e.target.value || null)} placeholder={user.full_name || user.username || ''} width={240} />
            </Row>
            <Row label={t('settings.profile.language')} desc={t('settings.profile.language_desc')}>
              <SegToggle value={prefs.language || 'fr'} onChange={v => updatePref('language', v)} options={[{ value: 'fr', label: t('profile.lang_fr') }, { value: 'en', label: t('profile.lang_en') }]} />
            </Row>
            <Row label={t('settings.profile.role')} desc={t('settings.profile.role_desc')}>
              <span style={{ padding: '7px 10px', borderRadius: 6, background: 'var(--fl-card)', border: '1px solid var(--fl-border)', color: 'var(--fl-muted)', fontFamily: MONO, fontSize: 12, display: 'inline-block', minWidth: 240, textAlign: 'left' }}>{user.role || '—'}</span>
            </Row>
            <Row label={t('settings.profile.timezone')} desc={t('settings.profile.timezone_desc')}>
              <SegToggle value={prefs.timezone || 'utc'} onChange={v => updatePref('timezone', v)} options={[{ value: 'local', label: 'Local' }, { value: 'utc', label: 'UTC' }]} />
            </Row>
            <Row label={t('settings.profile.chat_color')} desc={t('settings.profile.chat_color_desc')} last>
              <div style={{ display: 'flex', gap: 6 }}>
                {CHAT_COLORS.map(c => (
                  <button key={c} onClick={() => updatePref('chat_color', c)} title={c}
                    style={{ width: 22, height: 22, borderRadius: '50%', background: c, cursor: 'pointer', border: 'none',
                      outline: (prefs.chat_color || 'var(--fl-accent)') === c ? `2px solid ${c}` : '2px solid transparent', outlineOffset: 2 }} />
                ))}
              </div>
            </Row>
          </>
        );
      case 'notifications':
        return (
          <>
            <SectionHead title={t('settings.notifications.title')} desc={t('settings.notifications.desc')} />
            <Row label={t('settings.notifications.desktop')} desc={t('settings.notifications.desktop_desc')}>
              <Toggle on={prefs.notif_desktop !== false} onClick={() => updatePref('notif_desktop', prefs.notif_desktop === false)} />
            </Row>
            <Row label={t('settings.notifications.critical')} desc={t('settings.notifications.critical_desc')}>
              <Toggle on={prefs.notif_critical !== false} onClick={() => updatePref('notif_critical', prefs.notif_critical === false)} />
            </Row>
            <Row label={t('settings.notifications.mentions')} desc={t('settings.notifications.mentions_desc')}>
              <Toggle on={prefs.notif_mentions !== false} onClick={() => updatePref('notif_mentions', prefs.notif_mentions === false)} />
            </Row>
            <Row label={t('settings.notifications.oncall')} desc={t('settings.notifications.oncall_desc')} last>
              <Toggle on={!!prefs.notif_oncall} onClick={() => updatePref('notif_oncall', !prefs.notif_oncall)} />
            </Row>
          </>
        );
      case 'apikeys':      return <ApiKeysSection />;
      case 'sessions':     return <SessionsSection />;
      case 'team':         return <TeamSection />;
      case 'roles':        return <RolesSection />;
      case 'audit':        return <AuditSection />;
      case 'security':     return <SecuritySection />;
      case 'retention':    return <RetentionSection />;
      case 'integrations': return <IntegrationsSection />;
      case 'sla':          return <SlaSection />;
      case 'theme':
        return (
          <>
            <SectionHead title={t('settings.appearance.theme_title')} desc={t('settings.appearance.theme_desc')} />
            <Row label={t('settings.appearance.mode')} desc={t('settings.appearance.mode_desc')} last>
              <SegToggle value={mode} onChange={v => { if (v !== mode) toggle(); }} options={[{ value: 'dark', label: t('profile.theme_dark') }, { value: 'light', label: t('profile.theme_light') }]} />
            </Row>
          </>
        );
      case 'density':
        return (
          <>
            <SectionHead title={t('settings.appearance.density_title')} desc={t('profile.density_hint')} />
            <Row label={t('profile.density')} last>
              <SegToggle value={prefs.table_density || 'standard'} onChange={v => updatePref('table_density', v)}
                options={[{ value: 'compact', label: t('profile.density_compact') }, { value: 'standard', label: t('profile.density_std') }, { value: 'comfortable', label: t('profile.density_comf') }]} />
            </Row>
          </>
        );
      case 'shortcuts': return <ShortcutsSection />;
      default: return null;
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--fl-bg)' }}>
      {/* Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '14px 22px', borderBottom: '1px solid var(--fl-border)', flexShrink: 0 }}>
        <span style={{ fontSize: 11, fontFamily: MONO, color: 'var(--fl-muted)' }}>{t('settings.breadcrumb.system')}</span>
        <ChevronRight size={12} style={{ color: 'var(--fl-subtle)' }} />
        <span style={{ fontSize: 11, fontFamily: MONO, color: 'var(--fl-text)', fontWeight: 600 }}>{t('nav.settings')}</span>
      </div>

      <div style={{ flex: 1, display: 'flex', minHeight: 0 }}>
        {/* Sub-nav */}
        <div style={{ width: 230, flexShrink: 0, borderRight: '1px solid var(--fl-border)', overflowY: 'auto', padding: '16px 12px' }}>
          {groups.map(g => (
            <div key={g.id} style={{ marginBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 9.5, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.12em', color: 'var(--fl-subtle)', padding: '0 8px 6px' }}>
                {g.label}{g.admin && <ShieldCheck size={10} style={{ color: 'var(--fl-purple)' }} title="Admin" />}
              </div>
              {g.items.map(it => {
                const on = active === it.id && !it.to;
                return (
                  <button key={it.id} onClick={() => it.to ? navigate(it.to) : setActive(it.id)}
                    style={{ width: '100%', textAlign: 'left', padding: '6px 8px', borderRadius: 6, border: 'none', cursor: 'pointer', marginBottom: 1,
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6,
                      background: on ? 'color-mix(in srgb, var(--fl-accent) 10%, transparent)' : 'transparent',
                      color: on ? 'var(--fl-accent)' : 'var(--fl-dim)', fontFamily: UI, fontSize: 12.5 }}
                    onMouseEnter={e => { if (!on) e.currentTarget.style.background = 'var(--fl-surface-hover)'; }}
                    onMouseLeave={e => { if (!on) e.currentTarget.style.background = 'transparent'; }}>
                    {it.label}
                    {it.to && <ExternalLink size={11} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} />}
                  </button>
                );
              })}
            </div>
          ))}
        </div>

        {/* Content */}
        <div key={active} style={{ flex: 1, overflowY: 'auto', padding: '28px 40px', animation: 'fl-fade 120ms ease' }}>
          <div style={{ maxWidth: 760 }}>
            {renderSection()}
          </div>
        </div>
      </div>
    </div>
  );
}
