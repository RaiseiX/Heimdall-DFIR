
import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search, LayoutDashboard, FolderOpen, Crosshair, Shield,
  Globe, MonitorCheck, Terminal, CalendarDays, Settings,
  ChevronRight, Network, Clock, Activity,
} from 'lucide-react';
import { casesAPI } from '../../utils/api';

const RE_IP   = /^(\d{1,3}\.){3}\d{1,3}$/;
const RE_HASH = /^[0-9a-fA-F]{32,}$/;
const RE_DOMAIN = /^[a-zA-Z0-9.-]{4,}\.[a-zA-Z]{2,}$/;

const NAV_ITEMS = [
  { label: 'Dashboard',       path: '/',                icon: LayoutDashboard },
  { label: 'Cas',             path: '/cases',           icon: FolderOpen },
  { label: 'IOCs',            path: '/iocs',            icon: Crosshair },
  { label: 'Hayabusa',        path: '/hayabusa',        icon: Activity },
  { label: 'Threat Hunting',  path: '/threat-hunt',     icon: Shield },
  { label: 'Threat Intel',    path: '/threat-intel',    icon: Globe },
  { label: 'Sysmon Configs',  path: '/sysmon',          icon: MonitorCheck },
  { label: 'Agent Collecte',  path: '/collection-agent',icon: Terminal },
  { label: 'Calendrier',      path: '/calendar',        icon: CalendarDays },
  { label: 'Administration',  path: '/admin',           icon: Settings },
];

function ResultItem({ item, active, onSelect }) {
  const Icon = item.icon || ChevronRight;
  return (
    <div
      onMouseDown={e => { e.preventDefault(); onSelect(item); }}
      style={{
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '8px 14px', cursor: 'pointer', borderRadius: 6,
        background: active ? 'rgba(77,130,192,0.14)' : 'transparent',
        margin: '0 4px',
        transition: 'background 0.1s',
      }}
    >
      <Icon size={14} style={{ color: active ? 'var(--fl-accent)' : 'var(--fl-dim)', flexShrink: 0 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontFamily: 'monospace', fontSize: 12, color: active ? 'var(--fl-text)' : 'var(--fl-dim)',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {item.label}
        </div>
        {item.sub && (
          <div style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-muted)',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {item.sub}
          </div>
        )}
      </div>
      {item.category === 'nav' && (
        <span style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-border)', flexShrink: 0 }}>nav</span>
      )}
      {item.category === 'case' && (
        <span style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-border)', flexShrink: 0 }}>cas</span>
      )}
      {item.category === 'ioc' && (
        <span style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-gold)', flexShrink: 0 }}>IOC</span>
      )}
    </div>
  );
}

function SectionHeader({ label }) {
  return (
    <div style={{
      padding: '6px 14px 2px', fontSize: 9, fontFamily: 'monospace',
      color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.08em',
    }}>
      {label}
    </div>
  );
}

export default function CommandPalette({ open, onClose }) {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [cases, setCases] = useState([]);
  const [activeIdx, setActiveIdx] = useState(0);
  const inputRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    setQuery('');
    setActiveIdx(0);
    setTimeout(() => inputRef.current?.focus(), 30);
    casesAPI.list({ limit: 30 }).then(r => setCases(r.data?.cases || [])).catch(() => {});
  }, [open]);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    const sections = [];

    if (RE_IP.test(query.trim()) || RE_HASH.test(query.trim()) || RE_DOMAIN.test(query.trim())) {
      sections.push({
        key: 'ioc',
        label: 'Actions IOC',
        items: [
          { label: `Rechercher "${query.trim()}" dans les IOCs`, path: `/iocs?q=${encodeURIComponent(query.trim())}`, icon: Crosshair, category: 'ioc' },
          { label: `Chercher dans la Super Timeline`, path: `/super-timeline?q=${encodeURIComponent(query.trim())}`, icon: Clock, category: 'ioc' },
          { label: `Carte réseau — filtrer par "${query.trim()}"`, path: `/iocs?q=${encodeURIComponent(query.trim())}&view=network`, icon: Network, category: 'ioc' },
        ],
      });
    }

    const navFiltered = q
      ? NAV_ITEMS.filter(n => n.label.toLowerCase().includes(q))
      : NAV_ITEMS;
    if (navFiltered.length) {
      sections.push({
        key: 'nav',
        label: 'Navigation',
        items: navFiltered.slice(0, 6).map(n => ({ ...n, category: 'nav' })),
      });
    }

    const caseFiltered = q
      ? cases.filter(c =>
          c.title?.toLowerCase().includes(q) ||
          c.case_number?.toLowerCase().includes(q) ||
          c.description?.toLowerCase().includes(q)
        )
      : cases.slice(0, 5);
    if (caseFiltered.length) {
      sections.push({
        key: 'cases',
        label: 'Cas',
        items: caseFiltered.slice(0, 5).map(c => ({
          label: c.title || c.case_number,
          sub: c.case_number,
          path: `/cases/${c.id}`,
          icon: FolderOpen,
          category: 'case',
        })),
      });
    }

    return sections;
  }, [query, cases]);

  const flatItems = useMemo(() => results.flatMap(s => s.items), [results]);

  const handleSelect = useCallback((item) => {
    if (item.path) navigate(item.path);
    onClose();
  }, [navigate, onClose]);

  const handleKeyDown = useCallback((e) => {
    if (e.key === 'Escape') { onClose(); return; }
    if (e.key === 'ArrowDown') { e.preventDefault(); setActiveIdx(i => Math.min(i + 1, flatItems.length - 1)); }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setActiveIdx(i => Math.max(i - 1, 0)); }
    if (e.key === 'Enter' && flatItems[activeIdx]) { handleSelect(flatItems[activeIdx]); }
  }, [flatItems, activeIdx, handleSelect, onClose]);

  useEffect(() => setActiveIdx(0), [query]);

  if (!open) return null;

  let globalIdx = 0;

  return (
    <div
      style={{ position: 'fixed', inset: 0, zIndex: 9999, display: 'flex', alignItems: 'flex-start', justifyContent: 'center', paddingTop: '12vh' }}
      onMouseDown={e => { if (e.target === e.currentTarget) onClose(); }}
    >
      
      <div style={{ position: 'absolute', inset: 0, background: 'rgba(0,0,0,0.6)' }} />

      <div
        role="dialog"
        aria-modal="true"
        aria-label="Barre de commande"
        style={{
          position: 'relative', zIndex: 1,
          width: '100%', maxWidth: 560,
          background: 'var(--fl-panel)',
          border: '1px solid var(--fl-border)',
          borderRadius: 12,
          boxShadow: '0 24px 64px rgba(0,0,0,0.7)',
          overflow: 'hidden',
        }}
      >
        
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', borderBottom: '1px solid var(--fl-panel)' }}>
          <Search size={16} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Naviguer, rechercher une IP / hash / cas…"
            style={{
              flex: 1, background: 'none', border: 'none', outline: 'none',
              fontFamily: 'monospace', fontSize: 13, color: 'var(--fl-text)',
            }}
          />
          <kbd style={{ fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-muted)',
            background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', borderRadius: 4, padding: '2px 5px' }}>
            ESC
          </kbd>
        </div>

        <div style={{ maxHeight: 380, overflowY: 'auto', padding: '6px 0 8px' }}>
          {flatItems.length === 0 ? (
            <div style={{ padding: '20px 14px', fontFamily: 'monospace', fontSize: 12, color: 'var(--fl-muted)', textAlign: 'center' }}>
              Aucun résultat
            </div>
          ) : (
            results.map(section => (
              <div key={section.key}>
                <SectionHeader label={section.label} />
                {section.items.map(item => {
                  const idx = globalIdx++;
                  return (
                    <ResultItem
                      key={`${section.key}-${item.label}`}
                      item={item}
                      active={idx === activeIdx}
                      onSelect={handleSelect}
                    />
                  );
                })}
              </div>
            ))
          )}
        </div>

        <div style={{ display: 'flex', gap: 14, padding: '6px 14px', borderTop: '1px solid var(--fl-panel)',
          background: 'var(--fl-bg)', fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-border)' }}>
          <span><kbd style={{ marginRight: 4 }}>↑↓</kbd>naviguer</span>
          <span><kbd style={{ marginRight: 4 }}>↵</kbd>ouvrir</span>
          <span><kbd style={{ marginRight: 4 }}>ESC</kbd>fermer</span>
        </div>
      </div>
    </div>
  );
}
