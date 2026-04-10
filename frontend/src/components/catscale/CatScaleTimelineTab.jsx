import { useState, useEffect, useCallback, useMemo } from 'react';
import { collectionAPI } from '../../utils/api';
import {
  Monitor, RefreshCw, Search, X, Terminal, Network,
  Shield, History, Clock, ChevronDown, ChevronRight,
  AlertTriangle, UserCheck, Loader2,
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
  catscale_auth:        { label: 'Auth',        color: '#f43f5e', icon: Shield,    bg: '#f43f5e18' },
  catscale_logon:       { label: 'Logons',      color: '#22c55e', icon: UserCheck, bg: '#22c55e18' },
  catscale_process:     { label: 'Processus',   color: '#8b72d6', icon: Terminal,  bg: '#8b72d618' },
  catscale_network:     { label: 'Réseau',      color: '#4d82c0', icon: Network,   bg: '#4d82c018' },
  catscale_history:     { label: 'Historique',  color: '#d97c20', icon: History,   bg: '#d97c2018' },
  catscale_persistence: { label: 'Persistance', color: '#c89d1d', icon: Clock,     bg: '#c89d1d18' },
  catscale_fstimeline:  { label: 'FS Timeline', color: '#06b6d4', icon: Clock,     bg: '#06b6d418' },
};

const SUSPICIOUS_RE = [
  /ssh.*(failed|invalid|error)/i,
  /sudo:/i,
  /\broot\b/i,
  /mimikatz|sekurlsa|ntdsutil|procdump/i,
  /(wget|curl|bash|nc|ncat|nmap|python|perl|ruby)\s+/i,
  /chmod\s+[+]?[0-7]*x/i,
  /crontab|@reboot/i,
  /\/(tmp|dev\/shm|var\/tmp)\
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
  const m = TYPE_META[type] || { label: type, color: '#7d8590', bg: '#7d859018' };
  return (
    <span style={{
      fontSize: 10, fontFamily: 'monospace', padding: '1px 6px', borderRadius: 3,
      background: m.bg, color: m.color, border: `1px solid ${m.color}40`,
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
      borderBottom: '1px solid #1a2035',
      background: suspicious ? '#7c1d1d18' : 'transparent',
    }}>
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'grid',
          gridTemplateColumns: '160px 100px 1fr 16px',
          gap: 8,
          padding: '4px 8px',
          alignItems: 'center',
          cursor: 'pointer',
          fontSize: 12,
          fontFamily: 'monospace',
        }}
        onMouseEnter={e => e.currentTarget.style.background = '#1a2035'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
      >
        <span style={{ color: '#7d8590', fontSize: 11 }}>{fmt(ev.timestamp)}</span>
        <TypeBadge type={ev.artifact_type} />
        <span style={{ color: suspicious ? '#fca5a5' : '#e6edf3', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {suspicious && <AlertTriangle size={11} style={{ color: '#f43f5e', marginRight: 4, display: 'inline', verticalAlign: 'middle' }} />}
          {ev.description}
        </span>
        {open
          ? <ChevronDown size={12} style={{ color: '#7d8590' }} />
          : <ChevronRight size={12} style={{ color: '#484f58' }} />
        }
      </div>

      {open && (
        <div style={{ padding: '4px 8px 8px 8px', borderTop: '1px solid #1a2035' }}>
          <pre style={{
            margin: 0, fontSize: 11, fontFamily: 'monospace',
            background: '#0d1117', color: '#7d8590',
            padding: 8, borderRadius: 4,
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
  const [events,  setEvents]  = useState([]);
  const [loading, setLoading] = useState(false);
  const [search,  setSearch]  = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [showSuspicious, setShowSuspicious] = useState(false);
  const [counts, setCounts] = useState({});

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
      for (const r of rows) {
        c[r.artifact_type] = (c[r.artifact_type] || 0) + 1;
      }
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
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 60, color: '#7d8590' }}>
        <Loader2 size={20} style={{ animation: 'spin 1s linear infinite', marginRight: 8 }} />
        Chargement des artefacts CatScale…
      </div>
    );
  }

  if (!loading && events.length === 0) {
    return (
      <div style={{ textAlign: 'center', padding: 60, color: '#7d8590' }}>
        <Monitor size={48} style={{ marginBottom: 12, opacity: 0.3 }} />
        <div>Aucun artefact CatScale dans ce cas</div>
        <div style={{ fontSize: 12, marginTop: 4 }}>
          Importez une collecte CatScale (.tar.gz) via l'onglet Preuves
        </div>
      </div>
    );
  }

  return (
    <div style={{ fontFamily: 'monospace' }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 16,
        background: '#161b22', borderRadius: 8, padding: '10px 16px',
        marginBottom: 12, border: '1px solid #30363d',
      }}>
        <Monitor size={18} style={{ color: '#4d82c0' }} />
        <div>
          <span style={{ color: '#e6edf3', fontWeight: 700, fontSize: 13 }}>
            {sysInfo.hostname}
          </span>
          {sysInfo.os && (
            <span style={{ color: '#7d8590', fontSize: 12, marginLeft: 10 }}>
              {sysInfo.os}
            </span>
          )}
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          {suspiciousCount > 0 && (
            <span style={{
              fontSize: 11, padding: '2px 8px', borderRadius: 4,
              background: '#7c1d1d40', color: '#f43f5e', border: '1px solid #f43f5e30',
            }}>
              ⚠ {suspiciousCount} suspect{suspiciousCount > 1 ? 's' : ''}
            </span>
          )}
          <button onClick={load} style={{
            background: 'none', border: '1px solid #30363d', borderRadius: 4,
            color: '#7d8590', cursor: 'pointer', padding: '2px 8px', fontSize: 11,
          }}>
            <RefreshCw size={11} style={{ verticalAlign: 'middle' }} />
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
        <button
          onClick={() => setTypeFilter('all')}
          style={{
            padding: '3px 10px', borderRadius: 4, fontSize: 11,
            background: typeFilter === 'all' ? '#1c2333' : 'transparent',
            border: `1px solid ${typeFilter === 'all' ? '#4d82c0' : '#30363d'}`,
            color: typeFilter === 'all' ? '#4d82c0' : '#7d8590',
            cursor: 'pointer',
          }}
        >
          Tous ({events.length})
        </button>

        {ALL_CATSCALE_TYPES.map(type => {
          const m = TYPE_META[type];
          const cnt = counts[type] || 0;
          if (!cnt) return null;
          const active = typeFilter === type;
          return (
            <button
              key={type}
              onClick={() => setTypeFilter(active ? 'all' : type)}
              style={{
                padding: '3px 10px', borderRadius: 4, fontSize: 11,
                background: active ? m.bg : 'transparent',
                border: `1px solid ${active ? m.color : '#30363d'}`,
                color: active ? m.color : '#7d8590',
                cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: 4,
              }}
            >
              {m.label} ({cnt})
            </button>
          );
        })}

        <button
          onClick={() => setShowSuspicious(v => !v)}
          style={{
            marginLeft: 'auto', padding: '3px 10px', borderRadius: 4, fontSize: 11,
            background: showSuspicious ? '#7c1d1d40' : 'transparent',
            border: `1px solid ${showSuspicious ? '#f43f5e' : '#30363d'}`,
            color: showSuspicious ? '#f43f5e' : '#7d8590',
            cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: 4,
          }}
        >
          <AlertTriangle size={11} />
          Suspects seulement
        </button>
      </div>

      <div style={{ position: 'relative', marginBottom: 10 }}>
        <Search size={13} style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', color: '#7d8590' }} />
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filtrer les événements…"
          style={{
            width: '100%', boxSizing: 'border-box',
            background: '#161b22', border: '1px solid #30363d', borderRadius: 4,
            color: '#e6edf3', fontSize: 12, fontFamily: 'monospace',
            padding: '5px 30px 5px 26px', outline: 'none',
          }}
        />
        {search && (
          <X size={13} onClick={() => setSearch('')} style={{
            position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)',
            color: '#7d8590', cursor: 'pointer',
          }} />
        )}
      </div>

      <div style={{ fontSize: 11, color: '#484f58', marginBottom: 6, paddingLeft: 2 }}>
        {filtered.length.toLocaleString()} événement{filtered.length > 1 ? 's' : ''}
        {filtered.length !== events.length && ` (sur ${events.length.toLocaleString()})`}
      </div>

      <div style={{
        background: '#161b22', borderRadius: 8, border: '1px solid #30363d',
        overflow: 'auto', maxHeight: 'calc(100vh - 380px)', minHeight: 200,
      }}>
        <div style={{
          display: 'grid', gridTemplateColumns: '160px 100px 1fr 16px',
          gap: 8, padding: '4px 8px',
          background: '#0d1117', borderBottom: '1px solid #1a2035',
          fontSize: 10, color: '#484f58', fontFamily: 'monospace', fontWeight: 700,
          position: 'sticky', top: 0, zIndex: 1,
        }}>
          <span>HORODATAGE</span>
          <span>TYPE</span>
          <span>ÉVÉNEMENT</span>
          <span />
        </div>

        {filtered.length === 0 ? (
          <div style={{ padding: 30, textAlign: 'center', color: '#484f58', fontSize: 12 }}>
            Aucun événement correspondant
          </div>
        ) : (
          filtered.map((ev, i) => <EventRow key={`${ev.id || i}`} ev={ev} />)
        )}
      </div>
    </div>
  );
}
