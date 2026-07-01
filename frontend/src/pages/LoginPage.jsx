import { useState, useRef, useEffect } from 'react';
import { Eye, EyeOff, AlertCircle, User, Lock, ArrowRight, Loader2, ArrowBigUp, WifiOff, ShieldAlert } from 'lucide-react';
import HeimdallLogo from '../components/ui/HeimdallLogo';
import { useTranslation } from 'react-i18next';
import { authAPI } from '../utils/api';
import { getLoginContent } from '../i18n/loginContent';

export default function LoginPage({ onLogin }) {
  const { t, i18n } = useTranslation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState(null); // { message, tone: 'danger'|'warn', net?: bool }
  const [loading, setLoading] = useState(false);
  const [capsOn, setCapsOn] = useState(false);
  const [utc, setUtc] = useState('');
  const [tagi, setTagi] = useState(0);
  const [qi, setQi] = useState(0);

  // Rotating tagline under the card title.
  useEffect(() => {
    const id = setInterval(() => setTagi(i => (i + 1) % getLoginContent(i18n.language).taglines.length), 4200);
    return () => clearInterval(id);
  }, [i18n.language]);

  // Rotating forensic quote in the hero — changes every 10 s.
  useEffect(() => {
    const id = setInterval(() => setQi(i => (i + 1) % getLoginContent(i18n.language).quotes.length), 10000);
    return () => clearInterval(id);
  }, [i18n.language]);

  const lang = (i18n.language || 'fr').slice(0, 2);
  const content = getLoginContent(lang);
  const setLang = (lng) => i18n.changeLanguage(lng);
  const quote = content.quotes[qi % content.quotes.length];
  // CapsLock detection — getModifierState reflects the live key state on any keypress.
  const onPwKey = (e) => { if (e.getModifierState) setCapsOn(e.getModifierState('CapsLock')); };

  // Live UTC clock (forensic identity — everything is timestamped in UTC).
  useEffect(() => {
    const fmt = () => new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    setUtc(fmt());
    const id = setInterval(() => setUtc(fmt()), 1000);
    return () => clearInterval(id);
  }, []);

  // Gold embers rising over the Bifrost beam (canvas particles).
  const embersRef = useRef(null);
  useEffect(() => {
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;
    const cv = embersRef.current; if (!cv) return;
    const ctx = cv.getContext('2d'); let raf, W, H;
    const resize = () => { const r = cv.parentElement.getBoundingClientRect(); W = cv.width = r.width; H = cv.height = r.height; };
    resize();
    const rnd = (a, b) => a + Math.random() * (b - a);
    const spawn = () => ({ x: rnd(W * 0.5, W), y: rnd(H * 0.65, H * 1.05), vx: rnd(-0.12, 0.12), vy: -rnd(0.15, 0.5), r: rnd(0.6, 1.9), life: rnd(0.4, 1), a: Math.random() });
    const ps = Array.from({ length: 26 }, spawn);
    const loop = () => {
      ctx.clearRect(0, 0, W, H);
      for (const p of ps) {
        p.x += p.vx; p.y += p.vy; p.a += 0.005;
        if (p.y < H * 0.12 || p.a > 1) Object.assign(p, spawn(), { a: 0 });
        const op = Math.sin(Math.min(p.a, 1) * Math.PI) * 0.7 * p.life;
        ctx.beginPath();
        ctx.fillStyle = `rgba(226,182,92,${op})`;
        ctx.arc(p.x, p.y, p.r, 0, 6.283);
        ctx.fill();
      }
      raf = requestAnimationFrame(loop);
    };
    loop();
    window.addEventListener('resize', resize);
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', resize); };
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const { data } = await authAPI.login({ username, password });
      onLogin(data.user, data.token, data.refreshToken);
    } catch (err) {
      // Distinguish bad credentials from a locked/disabled account or an unreachable server.
      if (!err.response) {
        setError({ message: t('login.error_network'), tone: 'danger', net: true });
      } else {
        const status = err.response.status;
        const backendMsg = err.response.data?.error;
        if (status === 429)      setError({ message: backendMsg || t('login.error_locked'), tone: 'warn' });
        else if (status === 403) setError({ message: backendMsg || t('login.error_disabled'), tone: 'warn' });
        else if (status === 401) setError({ message: t('login.error_credentials'), tone: 'danger' });
        else if (status >= 500)  setError({ message: t('login.error_server'), tone: 'danger' });
        else                     setError({ message: backendMsg || t('login.error'), tone: 'danger' });
      }
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

      {/* Full-bleed cinematic background (Ken Burns) + beam glow + embers + scrim + grain */}
      <div className="login-bgwrap"><div className="login-bgimg" /></div>
      <div className="login-beamglow" />
      <canvas className="login-embers" ref={embersRef} />
      <div style={{ position: 'absolute', inset: 0, zIndex: 1, background: 'linear-gradient(90deg, rgba(8,10,15,0.92) 10%, rgba(8,10,15,0.55) 48%, rgba(8,10,15,0.35) 100%)' }} />
      <div className="login-grain" />

      {/* Language selector */}
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

        {/* ── Left: editorial brand text (over the full-bleed bg) ── */}
        <div className="login-herotext">
          {/* Brand — pinned at the top of the column */}
          <div className="login-rise" style={{ display: 'flex', alignItems: 'center', gap: 18, flexWrap: 'wrap' }} >
            <span className="login-logo-glow"><HeimdallLogo size={84} id="login-hero" /></span>
            <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 22, letterSpacing: '0.06em', color: 'rgba(229,232,240,0.78)' }}>
              HEIMDALL <span style={{ color: '#ffffff', fontWeight: 700 }}>DFIR</span>
              <span style={{ color: 'rgba(229,232,240,0.4)', fontSize: 15 }}> · PLATFORM</span>
            </div>
            {betaPill}
            <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10.5, letterSpacing: '0.06em', color: 'rgba(229,232,240,0.4)' }}>
              v{__APP_VERSION__}
            </span>
          </div>

          {/* Headline + copy — centred in the column */}
          <div className="login-rise" style={{ animationDelay: '0.12s' }}>
            <div style={{
              display: 'inline-flex', alignItems: 'center', gap: 7, marginBottom: 22,
              padding: '4px 11px', borderRadius: 999,
              border: '1px solid color-mix(in srgb, var(--fl-accent) 40%, transparent)',
              background: 'color-mix(in srgb, var(--fl-accent) 12%, transparent)',
              fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10.5,
              letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--fl-accent)',
            }}>
              <span style={{ width: 6, height: 6, borderRadius: 2, background: 'var(--fl-accent)' }} />
              {content.eyebrow}
            </div>
            <h1 style={{
              margin: 0, fontFamily: 'var(--f-display, "Space Grotesk", "Inter", sans-serif)',
              fontSize: 'clamp(34px, 3.8vw, 54px)', fontWeight: 600, lineHeight: 1.03, letterSpacing: '-0.025em',
            }}>
              <span style={{
                background: 'linear-gradient(105deg, #ffffff 30%, color-mix(in srgb, var(--fl-accent) 70%, #ffffff))',
                WebkitBackgroundClip: 'text', backgroundClip: 'text', color: 'transparent',
              }}>{content.hero_primary}</span><br />
              <span style={{ color: 'rgba(229,232,240,0.55)' }}>{content.hero_secondary}</span>
            </h1>
            <p style={{ marginTop: 20, maxWidth: 440, fontSize: 14.5, lineHeight: 1.6, color: 'rgba(229,232,240,0.72)', fontFamily: 'var(--f-ui, "Inter", sans-serif)' }}>
              {content.hero_copy}
            </p>
          </div>

          {/* Rotating forensic quote — pinned at the bottom of the column */}
          <div className="login-rise" style={{ animationDelay: '0.3s', maxWidth: 470 }}>
            <div key={`${qi}-${lang}`} className="login-rise" style={{ borderLeft: '2px solid color-mix(in srgb, var(--fl-accent) 50%, transparent)', paddingLeft: 16 }}>
              <p style={{ margin: 0, fontStyle: 'italic', fontSize: 14.5, lineHeight: 1.55, color: 'rgba(229,232,240,0.82)', fontFamily: 'var(--f-display, "Space Grotesk", "Inter", sans-serif)' }}>
                {lang === 'en' ? `"${quote.q}"` : `« ${quote.q} »`}
              </p>
              <div style={{ marginTop: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10.5, letterSpacing: '0.04em', color: 'var(--fl-accent)' }}>
                {quote.a}
              </div>
            </div>
          </div>
        </div>

        {/* ── Right: floating glass form card ── */}
        <div className="login-card login-rise" style={{ animationDelay: '0.1s', alignSelf: 'center' }}>

          {/* Brand inside the card — only when the left hero is hidden (narrow screens),
              otherwise it duplicates the hero brand. */}
          <div className="login-card-brand" style={{ alignItems: 'center', gap: 10, marginBottom: 24, flexWrap: 'wrap' }}>
            <HeimdallLogo size={26} id="login" />
            <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11.5, letterSpacing: '0.04em', color: 'rgba(229,232,240,0.72)' }}>
              Heimdall <span style={{ color: '#ffffff', fontWeight: 600 }}>DFIR</span>
            </div>
            {betaPill}
          </div>

          <h2 style={{ margin: 0, fontFamily: 'var(--f-display, "Space Grotesk", "Inter", sans-serif)', fontSize: 23, fontWeight: 600, letterSpacing: '-0.015em', color: '#ffffff', lineHeight: 1.15 }}>
            {t('login.title')}
          </h2>
          <p style={{ marginTop: 6, marginBottom: 24, fontSize: 13, color: 'rgba(229,232,240,0.66)', lineHeight: 1.5, minHeight: 19, fontFamily: 'var(--f-ui, "Inter", sans-serif)' }}>
            <span key={tagi} className="login-rise" style={{ display: 'inline-block' }}>{content.taglines[tagi % content.taglines.length]}</span>
          </p>

          {error && (() => {
            const c = error.tone === 'warn' ? 'var(--fl-warn)' : 'var(--fl-danger)';
            const ErrIcon = error.net ? WifiOff : error.tone === 'warn' ? ShieldAlert : AlertCircle;
            return (
              <div id="login-error" role="alert" aria-live="assertive" key={error.message} className="login-shake" style={{
                display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: 18, padding: '10px 12px', borderRadius: 8,
                background: `color-mix(in srgb, ${c} 12%, transparent)`, border: `1px solid color-mix(in srgb, ${c} 32%, transparent)`,
                color: c, fontSize: 12.5, lineHeight: 1.5,
              }}>
                <ErrIcon size={15} style={{ flexShrink: 0, marginTop: 1 }} />
                <span>{error.message}</span>
              </div>
            );
          })()}

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.12em', color: 'rgba(229,232,240,0.5)' }}>
                {t('login.username')}
              </label>
              <div style={{ position: 'relative' }}>
                <User size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'rgba(229,232,240,0.42)', pointerEvents: 'none' }} />
                <input type="text" value={username} onChange={(e) => setUsername(e.target.value)}
                  className="login-input" style={{ paddingLeft: 38 }} placeholder={t('login.username')}
                  required autoFocus autoComplete="username" aria-invalid={!!error} aria-describedby={error ? 'login-error' : undefined} />
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.12em', color: 'rgba(229,232,240,0.5)' }}>
                {t('login.password')}
              </label>
              <div style={{ position: 'relative' }}>
                <Lock size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'rgba(229,232,240,0.42)', pointerEvents: 'none' }} />
                <input type={showPw ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={onPwKey} onKeyUp={onPwKey}
                  className="login-input" style={{ paddingLeft: 38, paddingRight: 44 }} placeholder="••••••••"
                  required autoComplete="current-password" aria-invalid={!!error} aria-describedby={error ? 'login-error' : undefined} />
                <button type="button" onClick={() => setShowPw(!showPw)}
                  title={showPw ? t('login.hide_password') : t('login.show_password')}
                  aria-label={showPw ? t('login.hide_password') : t('login.show_password')}
                  style={{ position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)', background: 'transparent', border: 'none', cursor: 'pointer', color: 'rgba(229,232,240,0.45)', padding: 6, borderRadius: 5, display: 'flex', alignItems: 'center' }}
                  onMouseEnter={e => { e.currentTarget.style.color = 'rgba(229,232,240,0.8)'; }}
                  onMouseLeave={e => { e.currentTarget.style.color = 'rgba(229,232,240,0.45)'; }}>
                  {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
              {capsOn && (
                <div role="status" style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 1, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10.5, color: 'var(--fl-warn)' }}>
                  <ArrowBigUp size={13} style={{ flexShrink: 0 }} />
                  {t('login.caps_lock')}
                </div>
              )}
            </div>

            <button type="submit" disabled={loading}
              style={{
                position: 'relative', overflow: 'hidden', marginTop: 4, width: '100%', height: 46, borderRadius: 10,
                cursor: loading ? 'wait' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                fontFamily: 'var(--f-ui, "Inter", sans-serif)', fontSize: 14, fontWeight: 600, color: '#fff', border: '1px solid var(--fl-accent)',
                background: 'linear-gradient(180deg, color-mix(in srgb, var(--fl-accent) 92%, white), var(--fl-accent))',
                boxShadow: '0 8px 22px color-mix(in srgb, var(--fl-accent) 35%, transparent)',
                opacity: loading ? 0.75 : 1, transition: 'transform 0.12s ease, box-shadow 0.12s ease',
              }}
              onMouseEnter={e => { if (!loading) { e.currentTarget.style.transform = 'translateY(-1px)'; e.currentTarget.style.boxShadow = '0 10px 28px color-mix(in srgb, var(--fl-accent) 45%, transparent)'; } }}
              onMouseLeave={e => { e.currentTarget.style.transform = 'none'; e.currentTarget.style.boxShadow = '0 8px 22px color-mix(in srgb, var(--fl-accent) 35%, transparent)'; }}>
              {!loading && <span className="login-sheen" />}
              {loading
                ? <><Loader2 size={16} style={{ animation: 'login-spin 0.7s linear infinite' }} /> {t('login.submit')}…</>
                : <>{t('login.submit')} <ArrowRight size={16} /></>}
            </button>
          </form>
        </div>
       </div>

        {/* Ground line — live UTC clock (forensic identity: all timestamps in UTC) */}
        <div className="login-footer">
          <div className="login-utc"><i />{utc}</div>
        </div>
      </div>
    </div>
  );
}
