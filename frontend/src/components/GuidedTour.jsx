import { useState, useEffect, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import i18n from '../i18n/index.js';
import {
  Sparkles, LayoutDashboard, FolderOpen, Terminal, Crosshair, Library,
  CalendarDays, SlidersHorizontal, Activity, CheckCircle2, ArrowRight, ArrowLeft, X,
} from 'lucide-react';

// Each step optionally navigates to a page and spotlights a sidebar item.
// Steps whose anchor doesn't exist in the DOM (e.g. admin-only items for an
// analyst) are filtered out automatically at mount.
function getTourSteps(t) {
  const steps = i18n.getResourceBundle(i18n.language || 'en', 'translation')?.tour?.steps
    || i18n.getResourceBundle('en', 'translation')?.tour?.steps
    || {};
  return [
    { key: 'welcome',   icon: Sparkles,         title: steps.welcome?.title || '',
      desc: steps.welcome?.desc || '' },
    { key: 'dashboard', path: '/', anchor: '[data-tour="/"]', icon: LayoutDashboard, title: steps.dashboard?.title || '',
      desc: steps.dashboard?.desc || '' },
    { key: 'cases',     path: '/cases', anchor: '[data-tour="/cases"]', icon: FolderOpen, title: steps.cases?.title || '',
      desc: steps.cases?.desc || '' },
    { key: 'collection', path: '/collection-agent', anchor: '[data-tour="/collection-agent"]', icon: Terminal, title: steps.collection?.title || '',
      desc: steps.collection?.desc || '' },
    { key: 'iocs',      path: '/iocs', anchor: '[data-tour="/iocs"]', icon: Crosshair, title: steps.iocs?.title || '',
      desc: steps.iocs?.desc || '' },
    { key: 'doc',       path: '/documentation', anchor: '[data-tour="/documentation"]', icon: Library, title: steps.documentation?.title || '',
      desc: steps.documentation?.desc || '' },
    { key: 'calendar',  path: '/calendar', anchor: '[data-tour="/calendar"]', icon: CalendarDays, title: steps.calendar?.title || '',
      desc: steps.calendar?.desc || '' },
    { key: 'settings',  path: '/settings', anchor: '[data-tour="/settings"]', icon: SlidersHorizontal, title: steps.settings?.title || '',
      desc: steps.settings?.desc || '' },
    { key: 'admin',     path: '/admin', anchor: '[data-tour="/admin"]', icon: Activity, title: steps.admin?.title || '',
      desc: steps.admin?.desc || '' },
    { key: 'done',      icon: CheckCircle2,      title: steps.done?.title || '',
      desc: steps.done?.desc || '' },
  ];
}

const CARD_W = 390;

export default function GuidedTour({ onClose }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  // Keep only steps without an anchor, or whose anchor element is present.
  const steps = useMemo(
    () => getTourSteps(t).filter(s => !s.anchor || document.querySelector(s.anchor)),
    [t],
  );
  const [idx, setIdx] = useState(0);
  const [rect, setRect] = useState(null);
  const step = steps[idx] || steps[0];
  const pct = ((idx + 1) / steps.length) * 100;
  const last = idx === steps.length - 1;

  const measure = useCallback(() => {
    const s = steps[idx];
    if (!s?.anchor) { setRect(null); return; }
    const el = document.querySelector(s.anchor);
    setRect(el ? el.getBoundingClientRect() : null);
  }, [steps, idx]);

  // On step change: navigate to the page, then measure the anchor once it renders.
  useEffect(() => {
    const s = steps[idx];
    if (s?.path) navigate(s.path);
    const t = setTimeout(measure, 130);
    return () => clearTimeout(t);
  }, [idx]); // eslint-disable-line react-hooks/exhaustive-deps

  // Keep the spotlight aligned on resize/scroll.
  useEffect(() => {
    window.addEventListener('resize', measure);
    window.addEventListener('scroll', measure, true);
    return () => {
      window.removeEventListener('resize', measure);
      window.removeEventListener('scroll', measure, true);
    };
  }, [measure]);

  // Keyboard: ←/→ navigate, Esc closes.
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
      else if (e.key === 'ArrowRight' && !last) setIdx(i => i + 1);
      else if (e.key === 'ArrowLeft' && idx > 0) setIdx(i => i - 1);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [idx, last, onClose]);

  // Card position: beside the spotlight, else centred.
  let cardPos;
  if (rect) {
    let left = rect.right + 20;
    if (left + CARD_W > window.innerWidth - 16) left = Math.max(16, rect.left - CARD_W - 20);
    const top = Math.max(16, Math.min(rect.top - 10, window.innerHeight - 340));
    cardPos = { left, top };
  } else {
    cardPos = { left: '50%', top: '50%', transform: 'translate(-50%, -50%)' };
  }

  const Icon = step.icon;

  return (
    <>
      {/* Click-blocker so the user follows the tour */}
      <div style={{ position: 'fixed', inset: 0, zIndex: 9997 }} onClick={(e) => e.stopPropagation()} />

      {/* Dimming: spotlight cut-out if anchored, full dim otherwise */}
      {rect ? (
        <div style={{
          position: 'fixed', zIndex: 9998, pointerEvents: 'none',
          left: rect.left - 8, top: rect.top - 6,
          width: rect.width + 16, height: rect.height + 12,
          borderRadius: 12,
          boxShadow: '0 0 0 9999px rgba(3,5,10,0.74)',
          border: '1.5px solid color-mix(in srgb, var(--fl-accent) 65%, transparent)',
          transition: 'left 0.32s cubic-bezier(.4,0,.2,1), top 0.32s cubic-bezier(.4,0,.2,1), width 0.32s, height 0.32s',
        }} />
      ) : (
        <div style={{ position: 'fixed', inset: 0, zIndex: 9998, pointerEvents: 'none', background: 'rgba(3,5,10,0.74)', backdropFilter: 'blur(5px)' }} />
      )}

      {/* Coachmark card */}
      <div
        className="login-rise"
        style={{
          position: 'fixed', zIndex: 9999, width: CARD_W, ...cardPos,
          background: 'var(--fl-panel)', border: '1px solid var(--fl-border)',
          borderRadius: 14, overflow: 'hidden', boxShadow: 'var(--fl-shadow-lg)',
          transition: 'left 0.32s cubic-bezier(.4,0,.2,1), top 0.32s cubic-bezier(.4,0,.2,1)',
        }}
      >
        {/* Progress */}
        <div style={{ height: 3, background: 'var(--fl-border)' }}>
          <div style={{ height: '100%', width: `${pct}%`, background: 'linear-gradient(90deg, var(--fl-accent), var(--fl-purple))', transition: 'width 0.3s ease' }} />
        </div>

        <div style={{ padding: '20px 22px 18px' }}>
          {/* Close */}
          <button onClick={onClose} aria-label={t('common.close')} style={{
            position: 'absolute', top: 12, right: 12, background: 'none', border: 'none',
            cursor: 'pointer', color: 'var(--fl-muted)', padding: 4, borderRadius: 6, display: 'flex',
          }}
            onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-dim)'; }}
            onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}>
            <X size={15} />
          </button>

          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14 }}>
            <div style={{
              width: 40, height: 40, borderRadius: 10, flexShrink: 0,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              background: 'color-mix(in srgb, var(--fl-accent) 12%, transparent)',
              border: '1px solid color-mix(in srgb, var(--fl-accent) 28%, transparent)',
            }}>
              <Icon size={19} style={{ color: 'var(--fl-accent)' }} />
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, letterSpacing: '0.12em', textTransform: 'uppercase', color: 'var(--fl-muted)' }}>
                {t('tour.step_count', { current: idx + 1, total: steps.length })}
              </div>
              <div style={{ fontFamily: 'var(--f-display, "Space Grotesk", "Inter", sans-serif)', fontSize: 17, fontWeight: 600, color: 'var(--fl-text)', letterSpacing: '-0.01em' }}>
                {step.title}
              </div>
            </div>
          </div>

          <p style={{ margin: '0 0 20px', fontSize: 13, lineHeight: 1.6, color: 'var(--fl-dim)', fontFamily: 'var(--f-ui, "Inter", sans-serif)' }}>
            {step.desc}
          </p>

          {/* Controls */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <button onClick={onClose} style={{ fontSize: 11, color: 'var(--fl-muted)', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
              {t('tour.skip')}
            </button>
            <div style={{ display: 'flex', gap: 8 }}>
              {idx > 0 && (
                <button onClick={() => setIdx(i => i - 1)} style={{
                  display: 'flex', alignItems: 'center', gap: 5, padding: '7px 12px', borderRadius: 8, fontSize: 12.5, fontWeight: 500, cursor: 'pointer',
                  border: '1px solid var(--fl-border)', color: 'var(--fl-dim)', background: 'transparent', fontFamily: 'var(--f-ui, "Inter", sans-serif)',
                }}>
                  <ArrowLeft size={14} /> {t('common.previous_page')}
                </button>
              )}
              {last ? (
                <button onClick={onClose} style={{
                  display: 'flex', alignItems: 'center', gap: 6, padding: '7px 16px', borderRadius: 8, fontSize: 12.5, fontWeight: 600, cursor: 'pointer',
                  border: '1px solid var(--fl-ok)', color: '#fff', fontFamily: 'var(--f-ui, "Inter", sans-serif)',
                  background: 'linear-gradient(180deg, color-mix(in srgb, var(--fl-ok) 90%, white), var(--fl-ok))',
                }}>
                  <CheckCircle2 size={15} /> {t('tour.done')}
                </button>
              ) : (
                <button onClick={() => setIdx(i => i + 1)} style={{
                  display: 'flex', alignItems: 'center', gap: 6, padding: '7px 16px', borderRadius: 8, fontSize: 12.5, fontWeight: 600, cursor: 'pointer',
                  border: '1px solid var(--fl-accent)', color: '#fff', fontFamily: 'var(--f-ui, "Inter", sans-serif)',
                  background: 'linear-gradient(180deg, color-mix(in srgb, var(--fl-accent) 90%, white), var(--fl-accent))',
                }}>
                  {t('tour.next')} <ArrowRight size={15} />
                </button>
              )}
            </div>
          </div>

          {/* Dots */}
          <div style={{ display: 'flex', justifyContent: 'center', gap: 6, marginTop: 16 }}>
            {steps.map((_, i) => (
              <button key={i} onClick={() => setIdx(i)} aria-label={t('tour.dot_label', { step: i + 1 })} style={{
                width: i === idx ? 18 : 6, height: 6, borderRadius: 3, padding: 0, border: 'none',
                background: i === idx ? 'var(--fl-accent)' : 'var(--fl-border)', cursor: 'pointer', transition: 'all 0.2s',
              }} />
            ))}
          </div>
        </div>
      </div>
    </>
  );
}
