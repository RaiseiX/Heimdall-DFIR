
import { useState } from 'react';
import { X, User, Globe, Clock, Palette, AlignJustify, Sun, Moon } from 'lucide-react';
import { usePreferences } from '../../utils/preferences';
import { useTheme } from '../../utils/theme';
import { useTranslation } from 'react-i18next';
import i18n from '../../i18n/index.js';

const CHAT_COLORS = [
  'var(--fl-accent)', 'var(--fl-ok)', 'var(--fl-warn)', 'var(--fl-danger)',
  'var(--fl-purple)', 'var(--fl-pink)', '#06b6d4', 'var(--fl-gold)',
  '#f43f5e', '#22c55e',
];

function Section({ icon: Icon, title, children }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10,
        paddingBottom: 6, borderBottom: '1px solid var(--fl-border)' }}>
        <Icon size={12} style={{ color: 'var(--fl-accent)' }} />
        <span style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700,
          textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-dim)' }}>
          {title}
        </span>
      </div>
      {children}
    </div>
  );
}

function ToggleGroup({ options, value, onChange }) {
  return (
    <div style={{ display: 'flex', background: 'var(--fl-bg)', border: '1px solid var(--fl-border)',
      borderRadius: 6, overflow: 'hidden' }}>
      {options.map((opt, i) => (
        <button key={opt.value}
          onClick={() => onChange(opt.value)}
          style={{
            flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
            gap: 5, padding: '5px 10px',
            fontSize: 11, fontFamily: 'monospace', border: 'none', cursor: 'pointer',
            borderRight: i < options.length - 1 ? '1px solid var(--fl-border)' : 'none',
            background: value === opt.value ? 'rgba(77,130,192,0.15)' : 'transparent',
            color: value === opt.value ? 'var(--fl-accent)' : 'var(--fl-dim)',
            transition: 'all 0.15s',
          }}>
          {opt.icon && <opt.icon size={11} />}
          {opt.label}
        </button>
      ))}
    </div>
  );
}

export default function UserProfileModal({ user, onClose }) {
  const { prefs, updatePref } = usePreferences();
  const T = useTheme();
  const { t } = useTranslation();

  const [draft, setDraft] = useState(() => ({ ...prefs }));
  const updateDraft = (key, value) => setDraft(prev => ({ ...prev, [key]: value }));

  const initials = (() => {
    const name = draft.display_name || user?.full_name || user?.username || '?';
    return name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase();
  })();

  const handleSave = () => {
    Object.keys(draft).forEach(key => {
      if (draft[key] !== prefs[key]) updatePref(key, draft[key]);
    });
    if (draft.language !== prefs.language) i18n.changeLanguage(draft.language);
    if (draft.theme !== prefs.theme && T.mode !== draft.theme) T.toggle();
    onClose();
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9100,
      background: 'rgba(0,0,0,0.6)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onMouseDown={e => { if (e.target === e.currentTarget) onClose(); }}>

      <div style={{
        background: 'var(--fl-panel)', border: '1px solid var(--fl-border)',
        borderRadius: 12, width: 460, maxWidth: '95vw', maxHeight: '90vh',
        display: 'flex', flexDirection: 'column',
        boxShadow: '0 24px 64px rgba(0,0,0,0.7)',
      }}>
        
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '14px 18px', borderBottom: '1px solid var(--fl-border)', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            
            <div style={{
              width: 36, height: 36, borderRadius: '50%',
              background: draft.chat_color,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontFamily: 'monospace', fontWeight: 700, fontSize: 13, color: '#fff',
              flexShrink: 0,
            }}>
              {initials}
            </div>
            <div>
              <div style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 700,
                color: 'var(--fl-text)' }}>
                {t('profile.title')}
              </div>
              <div style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-muted)' }}>
                {user?.username} · {user?.role?.toUpperCase()}
              </div>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer',
            color: 'var(--fl-muted)', padding: 4, borderRadius: 4 }}>
            <X size={14} />
          </button>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: '18px 18px 10px' }}>

          <Section icon={User} title={t('profile.display_name')}>
            <input
              value={draft.display_name || ''}
              onChange={e => updateDraft('display_name', e.target.value || null)}
              placeholder={t('profile.display_name_ph')}
              style={{
                width: '100%', padding: '7px 10px', borderRadius: 6,
                fontSize: 12, fontFamily: 'monospace',
                background: 'var(--fl-bg)', color: 'var(--fl-text)',
                border: '1px solid var(--fl-border)', outline: 'none',
              }}
            />
          </Section>

          <Section icon={Globe} title={t('profile.language')}>
            <ToggleGroup
              value={draft.language}
              onChange={lang => updateDraft('language', lang)}
              options={[
                { value: 'fr', label: '🇫🇷 ' + t('profile.lang_fr') },
                { value: 'en', label: '🇬🇧 ' + t('profile.lang_en') },
              ]}
            />
          </Section>

          <Section icon={Clock} title={t('profile.timezone')}>
            <ToggleGroup
              value={draft.timezone}
              onChange={v => updateDraft('timezone', v)}
              options={[
                { value: 'utc',   label: '🌐 ' + t('profile.tz_utc') },
                { value: 'local', label: '🕐 ' + t('profile.tz_local') },
              ]}
            />
            <div style={{ marginTop: 6, fontSize: 10, fontFamily: 'monospace',
              color: 'var(--fl-muted)', lineHeight: 1.5 }}>
              {draft.timezone === 'utc'
                ? t('profile.tz_utc_desc')
                : t('profile.tz_local_desc')}
            </div>
          </Section>

          <Section icon={Sun} title={t('profile.theme')}>
            <ToggleGroup
              value={draft.theme}
              onChange={theme => updateDraft('theme', theme)}
              options={[
                { value: 'dark',  label: t('profile.theme_dark'),  icon: Moon },
                { value: 'light', label: t('profile.theme_light'), icon: Sun  },
              ]}
            />
          </Section>

          <Section icon={Palette} title={t('profile.chat_color')}>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {CHAT_COLORS.map(c => (
                <button
                  key={c}
                  onClick={() => updateDraft('chat_color', c)}
                  title={c}
                  style={{
                    width: 28, height: 28, borderRadius: '50%',
                    background: c, border: 'none', cursor: 'pointer',
                    outline: draft.chat_color === c ? `3px solid ${c}` : '3px solid transparent',
                    outlineOffset: 2,
                    transition: 'outline 0.1s',
                  }}
                />
              ))}
            </div>
          </Section>

          <Section icon={AlignJustify} title={t('profile.density')}>
            <ToggleGroup
              value={draft.table_density}
              onChange={v => updateDraft('table_density', v)}
              options={[
                { value: 'compact',      label: t('profile.density_compact') },
                { value: 'standard',     label: t('profile.density_std') },
                { value: 'comfortable',  label: t('profile.density_comf') },
              ]}
            />
            <p style={{ margin: '6px 0 0', fontSize: '11px', color: 'var(--fl-text-muted)', lineHeight: 1.5 }}>
              {t('profile.density_hint')}
            </p>
          </Section>

        </div>

        <div style={{
          padding: '10px 18px', borderTop: '1px solid var(--fl-border)',
          display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 8,
          flexShrink: 0,
        }}>
          <button onClick={onClose}
            style={{
              padding: '5px 14px', borderRadius: 6, fontSize: 11, fontFamily: 'monospace',
              background: 'transparent', color: 'var(--fl-dim)',
              border: '1px solid var(--fl-border)', cursor: 'pointer',
            }}>
            {t('common.cancel')}
          </button>
          <button onClick={handleSave}
            style={{
              padding: '5px 14px', borderRadius: 6, fontSize: 11, fontFamily: 'monospace',
              background: 'var(--fl-accent)', color: '#fff', border: 'none', cursor: 'pointer',
            }}>
            {t('common.save')}
          </button>
        </div>
      </div>
    </div>
  );
}
