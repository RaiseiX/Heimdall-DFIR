import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, ChevronDown, ChevronRight } from 'lucide-react';
import { bookmarksAPI } from '../../utils/api';

const PHASES = [
  { id: 'Reconnaissance',       short: 'RECON',    color: '#7d8590' },
  { id: 'Resource Development', short: 'RESOURCE', color: '#7d8590' },
  { id: 'Initial Access',       short: 'INIT',     color: '#d97c20' },
  { id: 'Execution',            short: 'EXEC',     color: '#da3633' },
  { id: 'Persistence',          short: 'PERSIST',  color: '#c96898' },
  { id: 'Privilege Escalation', short: 'PRIVESC',  color: '#8b72d6' },
  { id: 'Defense Evasion',      short: 'EVADE',    color: '#4d82c0' },
  { id: 'Credential Access',    short: 'CREDS',    color: '#da3633' },
  { id: 'Discovery',            short: 'DISC',     color: '#c89d1d' },
  { id: 'Lateral Movement',     short: 'LATERAL',  color: '#d97c20' },
  { id: 'Collection',           short: 'COLLECT',  color: '#3fb950' },
  { id: 'Command and Control',  short: 'C2',       color: '#da3633' },
  { id: 'Exfiltration',         short: 'EXFIL',    color: '#f43f5e' },
  { id: 'Impact',               short: 'IMPACT',   color: '#da3633' },
];

function BookmarkCard({ b, color }) {
  return (
    <div style={{
      borderRadius: 5, border: `1px solid ${b.color || color}30`,
      borderLeft: `2px solid ${b.color || color}`,
      background: '#0a1625', padding: '5px 8px',
      display: 'flex', flexDirection: 'column', gap: 2,
    }}>
      <span style={{ fontSize: 10, fontWeight: 600, color: '#c8d8ec', lineHeight: 1.3 }}>{b.title}</span>
      {b.mitre_technique && (
        <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#3d5070' }}>{b.mitre_technique}</span>
      )}
      {b.event_timestamp && (
        <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#2a3a50' }}>
          {new Date(b.event_timestamp).toLocaleString('fr-FR')}
        </span>
      )}
    </div>
  );
}

function PhaseColumn({ phase, bookmarks, compact }) {
  const [open, setOpen] = useState(true);
  const active = bookmarks.length > 0;

  if (compact) {

    return (
      <div
        title={phase.id}
        style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3,
          padding: '6px 4px', borderRadius: 6, cursor: active ? 'pointer' : 'default',
          background: active ? `${phase.color}15` : '#07101f',
          border: `1px solid ${active ? phase.color + '40' : '#1a2035'}`,
          minWidth: 52, position: 'relative',
        }}
      >
        <span style={{
          fontSize: 8, fontFamily: 'monospace', fontWeight: 700, letterSpacing: '0.05em',
          color: active ? phase.color : '#2a3a50', textAlign: 'center',
        }}>
          {phase.short}
        </span>
        {active && (
          <span style={{
            fontSize: 11, fontWeight: 700, color: phase.color,
          }}>
            {bookmarks.length}
          </span>
        )}
        {!active && (
          <span style={{ fontSize: 11, color: '#1a2035' }}>—</span>
        )}
      </div>
    );
  }

  return (
    <div style={{
      display: 'flex', flexDirection: 'column',
      border: `1px solid ${active ? phase.color + '35' : '#1a2035'}`,
      borderTop: `2px solid ${active ? phase.color : '#1a2035'}`,
      borderRadius: '0 0 6px 6px',
      background: active ? `${phase.color}08` : '#07101f',
      minWidth: 160, maxWidth: 200, flex: '0 0 160px',
    }}>
      
      <button
        onClick={() => active && setOpen(v => !v)}
        style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '6px 8px', background: 'none', border: 'none', cursor: active ? 'pointer' : 'default',
          borderBottom: active && open ? `1px solid ${phase.color}20` : 'none',
          gap: 4,
        }}
      >
        <span style={{
          fontSize: 9, fontFamily: 'monospace', fontWeight: 700, letterSpacing: '0.08em',
          color: active ? phase.color : '#2a3a50', textTransform: 'uppercase',
        }}>
          {phase.short}
        </span>
        {active && (
          <span style={{
            fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
            background: `${phase.color}25`, color: phase.color,
            padding: '1px 5px', borderRadius: 10,
          }}>
            {bookmarks.length}
          </span>
        )}
        {active && (open ? <ChevronDown size={9} style={{ color: phase.color }} /> : <ChevronRight size={9} style={{ color: phase.color }} />)}
      </button>

      <div style={{ padding: '2px 8px 4px', fontSize: 9, color: active ? '#7d8590' : '#1e2a3a' }}>
        {phase.id}
      </div>

      {active && open && (
        <div style={{ padding: '6px 6px', display: 'flex', flexDirection: 'column', gap: 5 }}>
          {bookmarks.map(b => (
            <BookmarkCard key={b.id} b={b} color={phase.color} />
          ))}
        </div>
      )}
    </div>
  );
}

export default function AttackChain({ caseId }) {
  const [bookmarks, setBookmarks] = useState([]);
  const [loading, setLoading]     = useState(false);
  const [view, setView]           = useState('full');

  const load = useCallback(() => {
    if (!caseId) return;
    setLoading(true);
    bookmarksAPI.list(caseId)
      .then(res => setBookmarks(res.data))
      .catch(() => setBookmarks([]))
      .finally(() => setLoading(false));
  }, [caseId]);

  useEffect(() => { load(); }, [load]);

  const byTactic = {};
  for (const b of bookmarks) {
    const key = b.mitre_tactic || '__none__';
    if (!byTactic[key]) byTactic[key] = [];
    byTactic[key].push(b);
  }

  const activePhasesCount = PHASES.filter(p => (byTactic[p.id] || []).length > 0).length;
  const untaggedCount = (byTactic['__none__'] || []).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 700, color: '#8aa0bc', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Chaîne d'Attaque MITRE ATT&CK
          </span>
          {activePhasesCount > 0 && (
            <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#7d8590' }}>
              · {activePhasesCount} phase{activePhasesCount > 1 ? 's' : ''} · {bookmarks.length} bookmark{bookmarks.length > 1 ? 's' : ''}
            </span>
          )}
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <button
            onClick={() => setView(v => v === 'full' ? 'compact' : 'full')}
            style={{
              padding: '3px 8px', borderRadius: 4, background: 'none',
              border: '1px solid #1a2035', color: '#3d5070', fontSize: 10,
              fontFamily: 'monospace', cursor: 'pointer',
            }}
          >
            {view === 'full' ? 'Vue compacte' : 'Vue complète'}
          </button>
          <button onClick={load} style={{ background: 'none', border: '1px solid #1a2035', borderRadius: 4, cursor: 'pointer', padding: '3px 7px', color: '#3d5070' }}>
            <RefreshCw size={11} />
          </button>
        </div>
      </div>

      {loading && (
        <div style={{ textAlign: 'center', color: '#3d5070', fontFamily: 'monospace', fontSize: 11, padding: 12 }}>
          Chargement…
        </div>
      )}

      {!loading && bookmarks.length === 0 && (
        <div style={{
          textAlign: 'center', color: '#2a3a50', fontFamily: 'monospace', fontSize: 11,
          padding: '28px 16px', border: '1px dashed #1a2035', borderRadius: 8,
        }}>
          Aucun bookmark — créez des bookmarks avec la tactique MITRE pour construire la chaîne d'attaque.
        </div>
      )}

      {!loading && bookmarks.length > 0 && (
        <>
          {view === 'compact' ? (

            <div style={{
              display: 'flex', gap: 4, overflowX: 'auto', paddingBottom: 4,
              alignItems: 'stretch',
            }}>
              {PHASES.map((phase, i) => (
                <div key={phase.id} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <PhaseColumn phase={phase} bookmarks={byTactic[phase.id] || []} compact />
                  {i < PHASES.length - 1 && (
                    <span style={{ fontSize: 14, color: '#1a2035', flexShrink: 0 }}>→</span>
                  )}
                </div>
              ))}
            </div>
          ) : (

            <div style={{ overflowX: 'auto', paddingBottom: 8 }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start', minWidth: 'max-content' }}>
                {PHASES.map((phase, i) => {
                  const pBkms = byTactic[phase.id] || [];
                  if (pBkms.length === 0 && !byTactic['__none__']) return null;

                  return (
                    <div key={phase.id} style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                      <PhaseColumn phase={phase} bookmarks={pBkms} compact={false} />
                      {i < PHASES.length - 1 && pBkms.length > 0 && (
                        <div style={{
                          alignSelf: 'center', fontSize: 18, color: '#1a2035', marginTop: -20, flexShrink: 0,
                        }}>
                          →
                        </div>
                      )}
                    </div>
                  );
                })}

                {untaggedCount > 0 && (
                  <div style={{
                    borderRadius: 6, border: '1px solid #2a3045', background: '#07101f',
                    minWidth: 160, padding: '8px 10px',
                  }}>
                    <div style={{ fontSize: 9, fontFamily: 'monospace', fontWeight: 700, color: '#3d5070', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                      Non classifié
                    </div>
                    {(byTactic['__none__'] || []).map(b => (
                      <BookmarkCard key={b.id} b={b} color="#7d8590" />
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </>
      )}

      {bookmarks.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 4 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#3d5070', textTransform: 'uppercase' }}>
              Couverture kill chain
            </span>
            <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#7d8590' }}>
              {activePhasesCount}/{PHASES.length} phases
            </span>
          </div>
          <div style={{ height: 4, background: '#0d1117', borderRadius: 2, overflow: 'hidden' }}>
            <div style={{
              height: '100%', borderRadius: 2,
              width: `${(activePhasesCount / PHASES.length) * 100}%`,
              background: 'linear-gradient(90deg, #4d82c0, #da3633)',
              transition: 'width 0.4s',
            }} />
          </div>
        </div>
      )}
    </div>
  );
}
