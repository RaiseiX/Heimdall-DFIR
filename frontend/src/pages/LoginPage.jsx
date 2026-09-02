import { useState, useEffect } from 'react';
import { Eye, EyeOff, AlertCircle, User, Lock, Loader2, ArrowBigUp, WifiOff, ShieldAlert } from 'lucide-react';
import HeimdallLogo from '../components/ui/HeimdallLogo';
import { useTranslation } from 'react-i18next';
import { authAPI } from '../utils/api';
import { getLoginContent } from '../i18n/loginContent';
import { resolveLoginError } from './loginErrors';

export default function LoginPage({ onLogin }) {
  const { t, i18n } = useTranslation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [capsOn, setCapsOn] = useState(false);
  const [qi, setQi] = useState(0);

  useEffect(() => {
    const n = getLoginContent(i18n.language).quotes.length;
    setQi(Math.floor(Math.random() * n));
  }, [i18n.language]);

  const lang = (i18n.language || 'fr').slice(0, 2);
  const content = getLoginContent(lang);
  const setLang = (lng) => i18n.changeLanguage(lng);
  const quote = content.quotes[qi % content.quotes.length];
  const onPwKey = (e) => { if (e.getModifierState) setCapsOn(e.getModifierState('CapsLock')); };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const { data } = await authAPI.login({ username, password });
      onLogin(data.user, data.token, data.refreshToken);
    } catch (err) {
      const { key, vars, tone, net } = resolveLoginError(err);
      setError({ message: t(key, vars), tone, net });
    } finally {
      setLoading(false);
    }
  };

  const betaPill = (
    <span style={{
      fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, fontWeight: 700, letterSpacing: '0.1em',
      padding: '2px 7px', borderRadius: 999, color: 'var(--fl-warn)',
      background: 'color-mix(in srgb, var(--fl-warn) 14%, transparent)',
      border: '1px solid color-mix(in srgb, var(--fl-warn) 32%, transparent)',
    }}>{content.badge}</span>
  );

  return (
    <div className="login-root">

      <div className="login-bgimg" />
      <div style={{ position: 'absolute', inset: 0, zIndex: 1, background: 'linear-gradient(90deg, rgba(8,10,15,0.92) 10%, rgba(8,10,15,0.55) 48%, rgba(8,10,15,0.35) 100%)' }} />

      <div role="group" aria-label="Langue" style={{
        position: 'absolute', top: 20, right: 24, zIndex: 6,
        display: 'flex', gap: 2, padding: 3,
        background: 'rgba(14,17,24,0.6)', backdropFilter: 'blur(10px)', border: '1px solid rgba(255,255,255,0.10)', borderRadius: 8,
      }}>
        {['fr', 'en'].map(lng => {
          const active = lang === lng;
          return (
            <button key={lng} type="button" onClick={() => setLang(lng)} aria-pressed={active}
              style={{
                padding: '4px 10px', borderRadius: 6, cursor: 'pointer', border: 'none',
                fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, fontWeight: 600, letterSpacing: '0.04em',
                background: active ? 'color-mix(in srgb, var(--fl-accent) 22%, transparent)' : 'transparent',
                color: active ? 'var(--fl-accent)' : 'rgba(229,232,240,0.5)', transition: 'all 0.12s',
              }}
              onMouseEnter={e => { if (!active) e.currentTarget.style.color = 'rgba(229,232,240,0.8)'; }}
              onMouseLeave={e => { if (!active) e.currentTarget.style.color = 'rgba(229,232,240,0.5)'; }}>
              {lng.toUpperCase()}
            </button>
          );
        })}
      </div>

      <div className="login-content">

       <div className="login-main">

        <div className="login-herotext">
          <div className="login-rise" style={{ display: 'flex', alignItems: 'center', gap: 18, flexWrap: 'wrap' }} >
            <HeimdallLogo size={84} id="login-hero" />
            <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 22, letterSpacing: '0.06em', color: 'rgba(229,232,240,0.78)' }}>
              HEIMDALL <span style={{ color: '#ffffff', fontWeight: 700 }}>DFIR</span>
              <span style={{ color: 'rgba(229,232,240,0.4)', fontSize: 15 }}> · PLATFORM</span>
            </div>
            {betaPill}
            <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 'var(--fs-sm)', letterSpacing: '0.06em', color: 'rgba(229,232,240,0.4)' }}>
              v{__APP_VERSION__}
            </span>
          </div>

          <div className="login-rise" style={{ animationDelay: '0.12s' }}>
            <div style={{
              display: 'inline-flex', alignItems: 'center', gap: 7, marginBottom: 22,
              padding: '4px 11px', borderRadius: 999,
              border: '1px solid color-mix(in srgb, var(--fl-accent) 40%, transparent)',
              background: 'color-mix(in srgb, var(--fl-accent) 12%, transparent)',
              fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 'var(--fs-sm)',
              letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--fl-accent)',
            }}>
              <span style={{ width: 6, height: 6, borderRadius: 2, background: 'var(--fl-accent)' }} />
              {content.eyebrow}
            </div>
            <h1 className="login-hero-title login-rise" style={{ animationDelay: '0.12s' }}>
              {content.headline1}<br />
              <span className="second">{content.headline2}</span>
            </h1>
            <p style={{ marginTop: 20, maxWidth: 440, fontSize: 'var(--fs-title)', lineHeight: 1.6, color: 'rgba(229,232,240,0.72)', fontFamily: 'var(--f-ui, "Inter", sans-serif)' }}>
              {content.hero_copy}
            </p>
          </div>

          <div className="login-rise" style={{ animationDelay: '0.3s', maxWidth: 470 }}>
            <div key={`${qi}-${lang}`} className="login-rise" style={{ borderLeft: '2px solid color-mix(in srgb, var(--fl-accent) 50%, transparent)', paddingLeft: 16 }}>
              <p style={{ margin: 0, fontStyle: 'italic', fontSize: 'var(--fs-title)', lineHeight: 1.55, color: 'rgba(229,232,240,0.82)', fontFamily: 'var(--f-display, "Space Grotesk", "Inter", sans-serif)' }}>
                {lang === 'en' ? `"${quote.q}"` : `« ${quote.q} »`}
              </p>
              <div style={{ marginTop: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 'var(--fs-sm)', letterSpacing: '0.04em', color: 'var(--fl-accent)' }}>
                {quote.a}
              </div>
            </div>
          </div>
        </div>

        <div className="login-card login-rise" style={{ animationDelay: '0.1s' }}>

          <div className="login-card-brand">
            <HeimdallLogo size={26} id="login" />
            <span className="login-card-brandname">Heimdall <b>DFIR</b></span>
            {betaPill}
          </div>

          <span className="login-card-eyebrow">{t('login.eyebrow')}</span>
          <h2 className="login-card-title">{t('login.title')}</h2>

          {error && (() => {
            const c = error.tone === 'warn' ? 'var(--fl-warn)' : 'var(--fl-danger)';
            const ErrIcon = error.net ? WifiOff : error.tone === 'warn' ? ShieldAlert : AlertCircle;
            return (
              <div id="login-error" role="alert" aria-live="assertive" key={error.message}
                className="login-shake login-error" style={{ '--tone': c }}>
                <ErrIcon size={15} />
                <span>{error.message}</span>
              </div>
            );
          })()}

          <form onSubmit={handleSubmit} className="login-form">
            <div className="login-field">
              <label htmlFor="login-username">{t('login.username')}</label>
              <div className="login-inputwrap">
                <User size={15} className="login-inputicon" />
                <input id="login-username" type="text" value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="login-input" placeholder={t('login.username')}
                  required autoFocus autoComplete="username"
                  aria-invalid={!!error} aria-describedby={error ? 'login-error' : undefined} />
              </div>
            </div>

            <div className="login-field">
              <label htmlFor="login-password">{t('login.password')}</label>
              <div className="login-inputwrap">
                <Lock size={15} className="login-inputicon" />
                <input id="login-password" type={showPw ? 'text' : 'password'} value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={onPwKey} onKeyUp={onPwKey}
                  className="login-input login-input--pw" placeholder="••••••••"
                  required autoComplete="current-password"
                  aria-invalid={!!error} aria-describedby={error ? 'login-error' : undefined} />
                <button type="button" onClick={() => setShowPw(!showPw)}
                  className="login-eye"
                  aria-label={showPw ? t('login.hide_password') : t('login.show_password')}>
                  {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
              {capsOn && (
                <div role="status" className="login-caps">
                  <ArrowBigUp size={13} />{t('login.caps_lock')}
                </div>
              )}
            </div>

            <button type="submit" disabled={loading} className="login-submit">
              {loading
                ? <><Loader2 size={16} className="spin" /> {t('login.submit')}…</>
                : t('login.submit')}
            </button>
          </form>
        </div>
       </div>
      </div>
    </div>
  );
}
