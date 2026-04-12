import { useState, useEffect, useCallback, useMemo } from 'react';
import { collectionAPI } from '../../utils/api';
import TimelineHeatmap from '../timeline/TimelineHeatmap';
import { Button, FilterChip, SearchInput, PanelShell } from '../ui';
import {
  Monitor, RefreshCw, Terminal, Network,
  Shield, History, Clock, ChevronDown, ChevronRight,
  AlertTriangle, UserCheck, Loader2, BarChart2,
} from 'lucide-react';

const ALL_CATSCALE_TYPES = [
  'catscale_auth',
  'catscale_logon',
  'catscale_process',
  'catscale_network',
  'catscale_history',
  'catscale_persistence',
  'catscale_fstimeline',
];

const TYPE_META = {
  catscale_auth:        { label: 'Auth',        color: '#f43f5e', icon: Shield,    },
  catscale_logon:       { label: 'Logons',      color: '#22c55e', icon: UserCheck, },
  catscale_process:     { label: 'Processus',   color: 'var(--fl-purple)', icon: Terminal,  },
  catscale_network:     { label: 'Réseau',      color: 'var(--fl-accent)', icon: Network,   },
  catscale_history:     { label: 'Historique',  color: 'var(--fl-warn)', icon: History,   },
  catscale_persistence: { label: 'Persistance', color: 'var(--fl-gold)', icon: Clock,     },
  catscale_fstimeline:  { label: 'FS Timeline', color: '#06b6d4', icon: Clock,     },
};

const SUSPICIOUS_RE = [
  /ssh.*(failed|invalid|error)/i,
  /sudo:/i,
  /\broot\b/i,
  /mimikatz|sekurlsa|ntdsutil|procdump/i,
  /(wget|curl|bash|nc|ncat|nmap|python|perl|ruby)\s+/i,
  /chmod\s+[+]?[0-7]*x/i,
  /crontab|@reboot/i,
  /\/(tmp|dev\/shm|var\/tmp)\//i,
  /base64|xxd|hexdump/i,
  /passwd|shadow|sudoers/i,
  /useradd|adduser|usermod/i,
];

function isSuspicious(desc) {
  return SUSPICIOUS_RE.some(re => re.test(desc));
}

function fmt(ts) {
  if (!ts) return '—';
  return ts.replace('T', ' ').replace('Z', '').substring(0, 19);
}

function TypeBadge({ type }) {
  const m = TYPE_META[type] || { label: type, color: 'var(--fl-dim)' };
  return (
    <span style={{
      fontSize: 10, fontFamily: 'monospace', padding: '1px 6px',
      borderRadius: 'var(--fl-radius-sm)',
      background: `color-mix(in srgb, ${m.color} 12%, transparent)`,
      color: m.color,
      border: `1px solid color-mix(in srgb, ${m.color} 30%, transparent)`,
      whiteSpace: 'nowrap',
    }}>
      {m.label}
    </span>
  );
}

function EventRow({ ev }) {
  const [open, setOpen] = useState(false);
  const suspicious = isSuspicious(ev.description);

  return (
    <div style={{
      borderBottom: '1px solid var(--fl-sep)',
      background: suspicious ? 'color-mix(in srgb, var(--fl-danger) 6%, transparent)' : 'transparent',
    }}>
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'grid',
          gridTemplateColumns: '160px 100px 1fr 16px',
          gap: 8,
          padding: '4px 10px',
          alignItems: 'center',
          cursor: 'pointer',
          fontSize: 12,
          fontFamily: 'monospace',
        }}
        onMouseEnter={e => e.currentTarget.style.background = 'var(--fl-hover-bg)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
      >
        <span style={{ color: 'var(--fl-dim)', fontSize: 11 }}>{fmt(ev.timestamp)}</span>
        <TypeBadge type={ev.artifact_type} />
        <span style={{ color: suspicious ? '#fca5a5' : 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {suspicious && <AlertTriangle size={11} style={{ color: 'var(--fl-danger)', marginRight: 4, display: 'inline', verticalAlign: 'middle' }} />}
          {ev.description}
        </span>
        {open
          ? <ChevronDown size={12} style={{ color: 'var(--fl-dim)' }} />
          : <ChevronRight size={12} style={{ color: 'var(--fl-muted)' }} />
        }
      </div>

      {open && (
        <div style={{ padding: '4px 10px 8px 10px', borderTop: '1px solid var(--fl-sep)' }}>
          <pre style={{
            margin: 0, fontSize: 11, fontFamily: 'monospace',
            background: 'var(--fl-bg)', color: 'var(--fl-dim)',
            padding: 8, borderRadius: 'var(--fl-radius-sm)',
            overflow: 'auto', maxHeight: 200,
          }}>
            {JSON.stringify(ev.raw, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

export default function CatScaleTimelineTab({ caseId, onTotalChange }) {
  const [events,         setEvents]         = useState([]);
  const [loading,        setLoading]        = useState(false);
  const [search,         setSearch]         = useState('');
  const [typeFilter,     setTypeFilter]     = useState('all');
  const [showSuspicious, setShowSuspicious] = useState(false);
  const [counts,         setCounts]         = useState({});
  const [showHeatmap,    setShowHeatmap]    = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await collectionAPI.timeline(caseId, {
        artifact_types: ALL_CATSCALE_TYPES.join(','),
        limit: 5000,
        sort_col: 'timestamp',
        sort_dir: 'asc',
      });
      const rows = data.records || [];
      setEvents(rows);
      const c = {};
      for (const r of rows) c[r.artifact_type] = (c[r.artifact_type] || 0) + 1;
      setCounts(c);
      onTotalChange?.(rows.length);
    } catch (e) {
      console.error('[CatScale] load error:', e);
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  useEffect(() => { load(); }, [load]);

  const sysInfo = useMemo(() => {
    const ev = events.find(e => e.raw?.host || e.raw?.hostname);
    return {
      hostname: ev?.raw?.host || ev?.raw?.hostname || ev?.host_name || '—',
      os: events.find(e => e.raw?.os)?.raw?.os || '',
    };
  }, [events]);

  const filtered = useMemo(() => {
    let rows = events;
    if (typeFilter !== 'all') rows = rows.filter(r => r.artifact_type === typeFilter);
    if (showSuspicious) rows = rows.filter(r => isSuspicious(r.description));
    if (search.trim()) {
      const q = search.toLowerCase();
      rows = rows.filter(r => r.description?.toLowerCase().includes(q));
    }
    return rows;
  }, [events, typeFilter, search, showSuspicious]);

  const suspiciousCount = useMemo(
    () => events.filter(e => isSuspicious(e.description)).length,
    [events]
  );

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 60, color: 'var(--fl-dim)' }}>
        <Loader2 size={20} style={{ animation: 'spin 1s linear infinite', marginRight: 8 }} />
        Chargement des artefacts CatScale…
      </div>
    );
  }

  if (!loading && events.length === 0) {
    return (
      <div className="fl-empty">
        <Monitor size={40} className="fl-empty-icon" />
        <div className="fl-empty-title">Aucun artefact CatScale dans ce cas</div>
        <div className="fl-empty-sub">Importez une collecte CatScale (.tar.gz) via l'onglet Preuves</div>
      </div>
    );
  }

  return (
    <div style={{ fontFamily: 'monospace', display: 'flex', flexDirection: 'column', gap: 10 }}>
      <PanelShell
        icon={Monitor}
        title={sysInfo.hostname}
        subtitle={sysInfo.os || undefined}
        noPadding
        bodyStyle={{ padding: 0 }}
        actions={
          <>
            {suspiciousCount > 0 && (
              <span className="fl-badge" style={{
                background: 'color-mix(in srgb, var(--fl-danger) 12%, transparent)',
                color: 'var(--fl-danger)',
                border: '1px solid color-mix(in srgb, var(--fl-danger) 30%, transparent)',
              }}>
                <AlertTriangle size={10} />
                {suspiciousCount} suspect{suspiciousCount > 1 ? 's' : ''}
              </span>
            )}
            <Button
              variant="ghost"
              size="xs"
              icon={BarChart2}
              onClick={() => setShowHeatmap(v => !v)}
              title="Heatmap d'activité"
              style={showHeatmap ? { color: 'var(--fl-accent)' } : undefined}
            >
              Heatmap
            </Button>
            <Button variant="ghost" size="xs" icon={RefreshCw} onClick={load} title="Rafraîchir" />
          </>
        }
      />

      {showHeatmap && (
        <div className="fl-card" style={{ overflow: 'hidden' }}>
          <TimelineHeatmap caseId={caseId} availTypes={ALL_CATSCALE_TYPES} />
        </div>
      )}

      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
        <FilterChip
          active={typeFilter === 'all'}
          onClick={() => setTypeFilter('all')}
          count={events.length}
        >
          Tous
        </FilterChip>

        {ALL_CATSCALE_TYPES.map(type => {
          const m = TYPE_META[type];
          const cnt = counts[type] || 0;
          if (!cnt) return null;
          return (
            <FilterChip
              key={type}
              active={typeFilter === type}
              color={m.color}
              icon={m.icon}
              count={cnt}
              onClick={() => setTypeFilter(typeFilter === type ? 'all' : type)}
            >
              {m.label}
            </FilterChip>
          );
        })}

        <FilterChip
          active={showSuspicious}
          color="var(--fl-danger)"
          icon={AlertTriangle}
          onClick={() => setShowSuspicious(v => !v)}
          style={{ marginLeft: 'auto' }}
        >
          Suspects seulement
        </FilterChip>
      </div>

      <SearchInput
        value={search}
        onChange={setSearch}
        onClear={() => setSearch('')}
        placeholder="Filtrer les événements…"
      />

      <div style={{ fontSize: 11, color: 'var(--fl-muted)', paddingLeft: 2 }}>
        {filtered.length.toLocaleString()} événement{filtered.length > 1 ? 's' : ''}
        {filtered.length !== events.length && ` (sur ${events.length.toLocaleString()})`}
      </div>

      <div className="fl-card" style={{ overflow: 'auto', maxHeight: 'calc(100vh - 380px)', minHeight: 200 }}>
        <div style={{
          display: 'grid', gridTemplateColumns: '160px 100px 1fr 16px',
          gap: 8, padding: '4px 10px',
          background: 'var(--fl-bg)', borderBottom: '1px solid var(--fl-sep)',
          fontSize: 10, color: 'var(--fl-muted)', fontWeight: 700,
          position: 'sticky', top: 0, zIndex: 1,
        }}>
          <span>HORODATAGE</span>
          <span>TYPE</span>
          <span>ÉVÉNEMENT</span>
          <span />
        </div>

        {filtered.length === 0 ? (
          <div style={{ padding: '30px 24px', textAlign: 'center', color: 'var(--fl-muted)', fontSize: 12 }}>
            Aucun événement correspondant
          </div>
        ) : (
          filtered.map((ev, i) => <EventRow key={`${ev.id || i}`} ev={ev} />)
        )}
      </div>
    </div>
  );
}
