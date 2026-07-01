import { useState, useCallback, useRef, useEffect } from 'react';
import {
  Shield, Terminal, Cpu, AlertTriangle, Search, BookMarked, X, Server, Network,
  Wrench, ClipboardList, Home, ArrowRight, ListTree, CornerDownRight,
} from 'lucide-react';
import WindowsArtifactsDoc, { DOC_INDEX as IDX_artifacts }     from './documentation/WindowsArtifactsDoc';
import EventIdsDoc,        { DOC_INDEX as IDX_event }           from './documentation/EventIdsDoc';
import MemoryForensicsDoc, { DOC_INDEX as IDX_memory }         from './documentation/MemoryForensicsDoc';
import AttackPatternsDoc,  { DOC_INDEX as IDX_attacks }        from './documentation/AttackPatternsDoc';
import LinuxArtifactsDoc,  { DOC_INDEX as IDX_linux }          from './documentation/LinuxArtifactsDoc';
import NetworkForensicsDoc,{ DOC_INDEX as IDX_network }        from './documentation/NetworkForensicsDoc';
import ToolsCheatsheetsDoc,{ DOC_INDEX as IDX_tools }          from './documentation/ToolsCheatsheetsDoc';
import DFIRMethodologyDoc, { DOC_INDEX as IDX_methodo }        from './documentation/DFIRMethodologyDoc';
import { useTranslation } from 'react-i18next';

const SECTIONS = [
  { id: 'artifacts',          icon: Shield,        n: '15' },
  { id: 'linux-artifacts',    icon: Server,        n: '12' },
  { id: 'event-ids',          icon: Terminal,      n: '40+' },
  { id: 'memory',             icon: Cpu,           n: 'Vol3' },
  { id: 'attacks',            icon: AlertTriangle, n: '35' },
  { id: 'network-forensics',  icon: Network,       n: 'NET' },
  { id: 'tools-cheatsheets',  icon: Wrench,        n: 'CLI' },
  { id: 'dfir-methodology',   icon: ClipboardList, n: '7' },
];

const DOC_COMPONENTS = {
  artifacts: WindowsArtifactsDoc, 'linux-artifacts': LinuxArtifactsDoc, 'event-ids': EventIdsDoc,
  memory: MemoryForensicsDoc, attacks: AttackPatternsDoc, 'network-forensics': NetworkForensicsDoc,
  'tools-cheatsheets': ToolsCheatsheetsDoc, 'dfir-methodology': DFIRMethodologyDoc,
};
const SECTION_BY_ID = Object.fromEntries(SECTIONS.map(s => [s.id, s]));

// Combined cross-section search index.
const GLOBAL_INDEX = [
  ...IDX_artifacts.map(x => ({ ...x, section: 'artifacts' })),
  ...IDX_linux.map(x => ({ ...x, section: 'linux-artifacts' })),
  ...IDX_event.map(x => ({ ...x, section: 'event-ids' })),
  ...IDX_memory.map(x => ({ ...x, section: 'memory' })),
  ...IDX_attacks.map(x => ({ ...x, section: 'attacks' })),
  ...IDX_network.map(x => ({ ...x, section: 'network-forensics' })),
  ...IDX_tools.map(x => ({ ...x, section: 'tools-cheatsheets' })),
  ...IDX_methodo.map(x => ({ ...x, section: 'dfir-methodology' })),
];

// ── Home / overview ─────────────────────────────────────────────────────
function DocHome({ onOpen }) {
  const { t } = useTranslation();
  return (
    <div style={{ padding: '40px 44px', maxWidth: 1000, margin: '0 auto' }}>
      <div style={{ display: 'inline-flex', alignItems: 'center', gap: 7, padding: '4px 11px', borderRadius: 999, border: '1px solid color-mix(in srgb, var(--fl-accent) 28%, transparent)', background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10.5, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--fl-accent)' }}>
        <span style={{ width: 6, height: 6, borderRadius: 2, background: 'var(--fl-accent)' }} /> {t('docs.eyebrow')}
      </div>
      <h1 style={{ margin: '14px 0 0', fontFamily: 'var(--f-display, "Space Grotesk", "Inter", sans-serif)', fontSize: 32, fontWeight: 600, letterSpacing: '-0.025em', color: 'var(--fl-text)' }}>
        {t('docs.title')}
      </h1>
      <p style={{ marginTop: 8, fontSize: 14.5, lineHeight: 1.6, color: 'var(--fl-dim)', maxWidth: 620, fontFamily: 'var(--f-ui, "Inter", sans-serif)' }}>
        {t('docs.subtitle')} <strong style={{ color: 'var(--fl-dim)' }}>⌘K</strong>.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 14, marginTop: 30 }}>
        {SECTIONS.map(s => {
          const Icon = s.icon;
          return (
            <button key={s.id} onClick={() => onOpen(s.id)}
              style={{ textAlign: 'left', padding: '16px 18px', borderRadius: 12, cursor: 'pointer', background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', transition: 'border-color 0.14s, transform 0.14s' }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'color-mix(in srgb, var(--fl-accent) 35%, transparent)'; e.currentTarget.style.transform = 'translateY(-2px)'; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--fl-border)'; e.currentTarget.style.transform = 'none'; }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                <div style={{ width: 34, height: 34, borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'color-mix(in srgb, var(--fl-accent) 10%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 24%, transparent)' }}>
                  <Icon size={16} style={{ color: 'var(--fl-accent)' }} />
                </div>
                <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-muted)' }}>{s.n}</span>
              </div>
              <div style={{ fontFamily: 'var(--f-display, "Space Grotesk", "Inter", sans-serif)', fontSize: 15, fontWeight: 600, color: 'var(--fl-text)', marginBottom: 4 }}>{t(`docs.sections.${s.id}.label`)}</div>
              <p style={{ fontSize: 12, lineHeight: 1.5, color: 'var(--fl-muted)', margin: 0, fontFamily: 'var(--f-ui, "Inter", sans-serif)' }}>{t(`docs.sections.${s.id}.desc`)}</p>
              <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 5, fontSize: 11.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-accent)' }}>{t('docs.open')} <ArrowRight size={13} /></div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ── Global search results (across all sections) ─────────────────────────
function GlobalResults({ query, onPick }) {
  const { t } = useTranslation();
  const q = query.trim().toLowerCase();
  const matches = GLOBAL_INDEX.filter(x => x.title.toLowerCase().includes(q) || (x.sub || '').toLowerCase().includes(q));
  const groups = {};
  matches.forEach(m => { (groups[m.section] = groups[m.section] || []).push(m); });
  const order = SECTIONS.map(s => s.id).filter(id => groups[id]);

  return (
    <div style={{ padding: '34px 40px', maxWidth: 900, margin: '0 auto' }}>
      <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12, color: 'var(--fl-dim)', marginBottom: 22 }}>
        {t('docs.results_for', { count: matches.length, query })}
      </div>

      {matches.length === 0 && (
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--fl-muted)' }}>
          <Search size={28} style={{ opacity: 0.35, marginBottom: 10 }} />
          <p style={{ fontSize: 13, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{t('docs.no_results')}</p>
        </div>
      )}

      {order.map(secId => {
        const sec = SECTION_BY_ID[secId];
        const Icon = sec.icon;
        return (
          <div key={secId} style={{ marginBottom: 26 }}>
            <button onClick={() => onPick(secId)} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
              <Icon size={14} style={{ color: 'var(--fl-accent)' }} />
              <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-accent)' }}>{t(`docs.sections.${sec.id}.label`)}</span>
              <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-muted)' }}>{groups[secId].length}</span>
            </button>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {groups[secId].slice(0, 8).map((m, i) => (
                <button key={i} onClick={() => onPick(secId)}
                  style={{ display: 'flex', alignItems: 'center', gap: 9, textAlign: 'left', padding: '8px 12px', borderRadius: 8, cursor: 'pointer', background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', transition: 'border-color 0.12s' }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = 'color-mix(in srgb, var(--fl-accent) 30%, transparent)'; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--fl-border)'; }}>
                  <CornerDownRight size={12} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} />
                  <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12.5, color: 'var(--fl-text)' }}>{m.title}</span>
                  {m.sub && <span style={{ fontSize: 11, color: 'var(--fl-muted)', fontFamily: 'var(--f-ui, "Inter", sans-serif)' }}>· {m.sub}</span>}
                </button>
              ))}
              {groups[secId].length > 8 && (
                <button onClick={() => onPick(secId)} style={{ alignSelf: 'flex-start', marginTop: 2, background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-accent)' }}>
                  {t('docs.more_results', { count: groups[secId].length - 8 })}
                </button>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Right "On this page" TOC — scroll-spy over <h2> headings ─────────────
function DocTOC({ mainRef, dep }) {
  const { t } = useTranslation();
  const [items, setItems] = useState([]);
  const [active, setActive] = useState(0);

  useEffect(() => {
    const t = setTimeout(() => {
      const root = mainRef.current;
      if (!root) { setItems([]); return; }
      const hs = Array.from(root.querySelectorAll('h2'));
      hs.forEach((h, i) => { if (!h.id) h.id = `doc-h-${i}`; });
      setItems(hs.map((h) => ({ id: h.id, text: (h.textContent || '').trim() })).filter(x => x.text));
    }, 220);
    return () => clearTimeout(t);
  }, [dep, mainRef]);

  useEffect(() => {
    const root = mainRef.current;
    if (!root || !items.length) return;
    const onScroll = () => {
      let cur = 0;
      items.forEach((it, i) => { const el = document.getElementById(it.id); if (el && el.getBoundingClientRect().top < 180) cur = i; });
      setActive(cur);
    };
    root.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    return () => root.removeEventListener('scroll', onScroll);
  }, [items, mainRef]);

  if (items.length < 2) return null;

  return (
    <aside style={{ width: 224, flexShrink: 0, borderLeft: '1px solid var(--fl-border)', padding: '22px 18px', overflowY: 'auto' }}>
      <div style={{ position: 'sticky', top: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)' }}>
          <ListTree size={12} /> {t('docs.on_this_page')}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {items.map((it, i) => (
            <button key={it.id} onClick={() => document.getElementById(it.id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
              style={{
                textAlign: 'left', padding: '5px 10px', borderRadius: 6, cursor: 'pointer', border: 'none',
                borderLeft: `2px solid ${i === active ? 'var(--fl-accent)' : 'transparent'}`,
                background: i === active ? 'color-mix(in srgb, var(--fl-accent) 8%, transparent)' : 'transparent',
                fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, lineHeight: 1.4,
                color: i === active ? 'var(--fl-accent)' : 'var(--fl-muted)',
                whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', transition: 'all 0.12s',
              }}
              onMouseEnter={e => { if (i !== active) e.currentTarget.style.color = 'var(--fl-dim)'; }}
              onMouseLeave={e => { if (i !== active) e.currentTarget.style.color = 'var(--fl-muted)'; }}
              title={it.text}>
              {it.text}
            </button>
          ))}
        </div>
      </div>
    </aside>
  );
}

export default function DocumentationPage() {
  const { t, i18n } = useTranslation();
  const [activeSection, setActiveSection] = useState('home');
  const [query, setQuery] = useState('');
  const [searchMode, setSearchMode] = useState(false);
  const mainRef = useRef(null);
  const searchRef = useRef(null);

  const openSection = useCallback((id) => { setActiveSection(id); setQuery(''); setSearchMode(false); if (mainRef.current) mainRef.current.scrollTop = 0; }, []);
  const clearSearch = useCallback(() => { setQuery(''); setSearchMode(false); }, []);
  const onSearchChange = useCallback((v) => { setQuery(v); setSearchMode(v.trim().length >= 2); }, []);
  // Pick a global result → open its section, keep the query as the in-section filter.
  const pickResult = useCallback((secId) => { setActiveSection(secId); setSearchMode(false); if (mainRef.current) mainRef.current.scrollTop = 0; }, []);

  useEffect(() => {
    const onKey = (e) => { if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); searchRef.current?.focus(); } };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const ActiveDoc = DOC_COMPONENTS[activeSection];
  const navItems = [{ id: 'home', label: t('docs.home'), icon: Home, desc: t('docs.home_desc') }, ...SECTIONS.map(s => ({ ...s, label: t(`docs.sections.${s.id}.label`), desc: t(`docs.sections.${s.id}.desc`) }))];
  const showingDoc = !searchMode && activeSection !== 'home' && ActiveDoc;
  const showEnglishFallback = i18n.language?.startsWith('en') && showingDoc;

  return (
    <div style={{ display: 'flex', height: '100%', overflow: 'hidden', background: 'var(--fl-bg)' }}>

      {/* ── Left: section nav ── */}
      <aside style={{ width: 264, flexShrink: 0, display: 'flex', flexDirection: 'column', background: 'var(--fl-panel)', borderRight: '1px solid var(--fl-border)', overflow: 'hidden' }}>
        <div style={{ padding: '16px 16px 14px', borderBottom: '1px solid var(--fl-border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
            <BookMarked size={15} style={{ color: 'var(--fl-accent)' }} />
            <span style={{ fontFamily: 'var(--f-display, "Space Grotesk", "Inter", sans-serif)', fontWeight: 600, fontSize: 14, letterSpacing: '-0.01em', color: 'var(--fl-text)' }}>{t('docs.nav_title')}</span>
          </div>
          <p style={{ fontSize: 11.5, color: 'var(--fl-muted)', fontFamily: 'var(--f-ui, "Inter", sans-serif)' }}>{t('docs.nav_desc')}</p>
        </div>

        {/* Global search */}
        <div style={{ padding: '12px', borderBottom: '1px solid var(--fl-border)' }}>
          <div style={{ position: 'relative' }}>
            <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--fl-muted)', pointerEvents: 'none' }} />
            <input ref={searchRef} type="text" placeholder={t('docs.search_ph')} value={query} onChange={e => onSearchChange(e.target.value)}
              className="fl-input" style={{ width: '100%', height: 36, paddingLeft: 30, paddingRight: 48, fontSize: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }} />
            {query ? (
              <button onClick={clearSearch} style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', display: 'flex', padding: 3 }}>
                <X size={12} />
              </button>
            ) : (
              <kbd style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9.5, color: 'var(--fl-muted)', background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', borderRadius: 4, padding: '1px 5px' }}>⌘K</kbd>
            )}
          </div>
        </div>

        <nav style={{ flex: 1, padding: 8, display: 'flex', flexDirection: 'column', gap: 3, overflowY: 'auto' }}>
          {navItems.map(s => {
            const active = !searchMode && activeSection === s.id;
            const Icon = s.icon;
            return (
              <button key={s.id} onClick={() => openSection(s.id)}
                style={{
                  width: '100%', textAlign: 'left', padding: '9px 11px', borderRadius: 9, cursor: 'pointer',
                  background: active ? 'color-mix(in srgb, var(--fl-accent) 10%, transparent)' : 'transparent',
                  border: `1px solid ${active ? 'color-mix(in srgb, var(--fl-accent) 26%, transparent)' : 'transparent'}`,
                  transition: 'background 0.12s, border-color 0.12s',
                }}
                onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'var(--fl-card)'; }}
                onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent'; }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                  <Icon size={14} style={{ color: active ? 'var(--fl-accent)' : 'var(--fl-muted)', flexShrink: 0 }} />
                  <span style={{ fontFamily: 'var(--f-ui, "Inter", sans-serif)', fontSize: 12.5, fontWeight: active ? 600 : 500, color: active ? 'var(--fl-text)' : 'var(--fl-dim)' }}>{s.label}</span>
                </div>
                {s.desc && <p style={{ fontSize: 10.5, color: 'var(--fl-muted)', marginLeft: 23, marginTop: 2, lineHeight: 1.4, fontFamily: 'var(--f-ui, "Inter", sans-serif)' }}>{s.desc}</p>}
              </button>
            );
          })}
        </nav>

        <div style={{ padding: '11px 16px', borderTop: '1px solid var(--fl-border)' }}>
          <p style={{ fontSize: 10, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', letterSpacing: '0.02em' }}>{t('docs.footer_hint')}</p>
        </div>
      </aside>

      {/* ── Center: content ── */}
      <main ref={mainRef} style={{ flex: 1, overflowY: 'auto', background: 'var(--fl-bg)' }}>
        {searchMode
          ? <GlobalResults query={query} onPick={pickResult} />
          : activeSection === 'home'
            ? <DocHome onOpen={openSection} />
            : showEnglishFallback ? <EnglishDocFallback section={activeSection} /> : ActiveDoc ? <ActiveDoc search={query} /> : null}
      </main>

      {/* ── Right: on-this-page TOC (only when reading a doc) ── */}
      {showingDoc && <DocTOC mainRef={mainRef} dep={`${activeSection}|${query}`} />}
    </div>
  );
}

function EnglishDocFallback({ section }) {
  const { t } = useTranslation();
  return (
    <div style={{ padding: '40px 44px', maxWidth: 860 }}>
      <div style={{ display: 'inline-flex', alignItems: 'center', gap: 7, padding: '4px 11px', borderRadius: 999, border: '1px solid color-mix(in srgb, var(--fl-accent) 28%, transparent)', background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10.5, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--fl-accent)' }}>
        {t('docs.english_reference')}
      </div>
      <h1 style={{ margin: '16px 0 0', fontSize: 26, fontWeight: 600, color: 'var(--fl-text)' }}>{t(`docs.sections.${section}.label`)}</h1>
      <p style={{ marginTop: 8, fontSize: 14, lineHeight: 1.6, color: 'var(--fl-dim)' }}>{t(`docs.sections.${section}.desc`)}</p>
      <div style={{ marginTop: 24, padding: 18, borderRadius: 10, background: 'var(--fl-panel)', border: '1px solid var(--fl-border)' }}>
        <p style={{ margin: 0, fontSize: 13, lineHeight: 1.6, color: 'var(--fl-muted)' }}>{t('docs.english_fallback_body')}</p>
      </div>
    </div>
  );
}
