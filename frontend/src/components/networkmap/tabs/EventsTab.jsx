// frontend/src/components/networkmap/tabs/EventsTab.jsx
import { useEffect, useState } from 'react';
import { networkAPI } from '../../../utils/api';
import { useTranslation } from 'react-i18next';

const ARTIFACT_COLOR = {
  evtx:     'var(--fl-artifact-evtx)',     hayabusa: 'var(--fl-danger)',          sqle:    'var(--fl-artifact-sqle)',
  srum:     'var(--fl-artifact-srum)',     amcache:  'var(--fl-artifact-amcache)', prefetch:'var(--fl-artifact-prefetch)',
  registry: 'var(--fl-artifact-registry)', mft:      'var(--fl-artifact-mft)',     lnk:     'var(--fl-artifact-lnk)',
};

const ARTIFACT_LABEL = {
  sqle: 'Browser', evtx: 'EVTX', hayabusa: 'Sigma', srum: 'SRUM',
  amcache: 'Amcache', prefetch: 'Prefetch', registry: 'Registry', mft: 'MFT',
};

function fmtTs(ts, locale) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString(locale, {
      day: '2-digit', month: '2-digit', year: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  } catch { return String(ts).slice(0, 19).replace('T', ' '); }
}

// Extract readable search query from Bing/Google search URLs
function extractSearchQuery(url) {
  if (!url) return null;
  try {
    const u = new URL(url);
    const q = u.searchParams.get('q') || u.searchParams.get('query') || u.searchParams.get('search_query');
    return q ? decodeURIComponent(q).slice(0, 120) : null;
  } catch { return null; }
}

// Shorten a URL for display: keep scheme + host + first 60 chars of path
function shortUrl(url) {
  if (!url) return '';
  try {
    const u = new URL(url);
    const path = u.pathname.length > 40 ? u.pathname.slice(0, 38) + '…' : u.pathname;
    return `${u.hostname}${path}`;
  } catch { return url.slice(0, 70); }
}

export default function EventsTab({ caseId, nodeId }) {
  const { t, i18n } = useTranslation();
  const [events, setEvents] = useState([]);
  const [total, setTotal]   = useState(0);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState(null);

  useEffect(() => {
    if (!caseId || !nodeId) return;
    setLoading(true);
    setExpanded(null);
    networkAPI.nodeEvents(caseId, nodeId, { limit: 100 })
      .then(r => {
        const data = r.data;
        setEvents(Array.isArray(data) ? data : (data?.events || []));
        setTotal(data?.total || (Array.isArray(data) ? data.length : 0));
      })
      .catch(() => setEvents([]))
      .finally(() => setLoading(false));
  }, [caseId, nodeId]);

  if (loading) return (
    <div style={{ padding: 12, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10 }}>
      {t('common.loading')}
    </div>
  );
  if (!events.length) return (
    <div style={{ padding: 12, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10 }}>
      {t('networkMap.no_node_events')}
    </div>
  );

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '6px 10px' }}>
      <div style={{ fontSize: 7, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
        textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>
        {total > events.length ? t('networkMap.events_total', { count: events.length, total }) : t('networkMap.events_count', { count: events.length })}
      </div>

      {events.map((ev, i) => {
        const type     = ev.artifact_type || '';
        const color    = ARTIFACT_COLOR[type] || 'var(--fl-muted)';
        const typeLabel = ARTIFACT_LABEL[type] || type;
        const isOpen   = expanded === i;

        // Build the best possible "title" for this event
        const searchQ  = ev.artifact_type === 'sqle' ? extractSearchQuery(ev.url) : null;
        const title    = searchQ
          ? `🔍 ${searchQ}`
          : ev.description?.slice(0, 100) || t('networkMap.event_fallback', { id: ev.event_id || '?' });

        // Build subtitle: process or remote host or URL
        const subtitle = ev.process_name
          ? ev.process_name.split(/[/\\]/).pop()
          : ev.remote_host
            ? ev.remote_host
            : ev.url && !searchQ
              ? shortUrl(ev.url)
              : null;

        return (
          <div key={i} style={{ marginBottom: 2 }}>
            {/* Event row */}
            <div
              onClick={() => setExpanded(isOpen ? null : i)}
              style={{
                padding: '5px 6px', borderRadius: isOpen ? '3px 3px 0 0' : 3,
                background: isOpen ? '#131722' : '#0a0f18',
                cursor: 'pointer', borderLeft: `2px solid ${color}`,
              }}
              onMouseEnter={e => { e.currentTarget.style.background = '#0e1118'; }}
              onMouseLeave={e => { e.currentTarget.style.background = isOpen ? '#131722' : '#0a0f18'; }}
            >
              <div style={{ display: 'flex', gap: 5, alignItems: 'flex-start', marginBottom: subtitle ? 2 : 0 }}>
                {/* Artifact type badge */}
                <span style={{ fontSize: 7, padding: '1px 4px', borderRadius: 2,
                  background: `color-mix(in srgb, ${color} 9%, transparent)`, color, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                  flexShrink: 0, border: `1px solid color-mix(in srgb, ${color} 19%, transparent)` }}>
                  {typeLabel}
                </span>
                {/* Event ID for EVTX */}
                {ev.event_id && (
                  <span style={{ fontSize: 7, color: color, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flexShrink: 0 }}>
                    {ev.event_id}
                  </span>
                )}
                {/* Title — wraps so long URLs stay fully readable without expanding */}
                <span style={{ fontSize: 9, color: '#a0b8d0', flex: 1, minWidth: 0,
                  whiteSpace: 'normal', wordBreak: 'break-all', lineHeight: 1.4,
                  fontFamily: ev.artifact_type === 'sqle' ? 'sans-serif' : 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                  {title}
                </span>
                {/* Timestamp */}
                <span style={{ fontSize: 7, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                  flexShrink: 0, whiteSpace: 'nowrap' }}>
                  {fmtTs(ev.timestamp, i18n.language)}
                </span>
              </div>
              {/* Subtitle */}
              {subtitle && (
                <div style={{ fontSize: 7, color: '#3a5878', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                  paddingLeft: 2, whiteSpace: 'normal', wordBreak: 'break-all', lineHeight: 1.4 }}>
                  {subtitle}
                </div>
              )}
            </div>

            {/* Expanded detail */}
            {isOpen && (
              <div style={{ background: '#0a0c11', border: '1px solid #131722',
                borderTop: 'none', borderRadius: '0 0 3px 3px', padding: '8px 10px' }}>

                {/* Full URL */}
                {ev.url && (
                  <div style={{ marginBottom: 6 }}>
                    <div style={{ fontSize: 7, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                      textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 2 }}>URL</div>
                    <div style={{ fontSize: 8, color: 'var(--fl-purple)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                      wordBreak: 'break-all', lineHeight: 1.5 }}>
                      {ev.url}
                    </div>
                  </div>
                )}

                {/* Key fields grid */}
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginBottom: 6 }}>
                  {[
                    [t('networkMap.fields.date'),      fmtTs(ev.timestamp, i18n.language)],
                    [t('networkMap.fields.type'),      typeLabel],
                    [t('networkMap.fields.host'),      ev.host_name],
                    [t('networkMap.fields.user'),      ev.user_name],
                    [t('networkMap.fields.process'),   ev.process_name?.split(/[/\\]/).pop()],
                    [t('networkMap.fields.protocol'),  ev.protocol],
                    [t('networkMap.fields.port'),      ev.dst_port],
                    [t('networkMap.fields.remote'),    ev.remote_host],
                    [t('networkMap.fields.mitre'),     ev.mitre_technique_id],
                    [t('networkMap.fields.tactic'),    ev.mitre_tactic],
                  ].filter(([, v]) => v).map(([label, val]) => (
                    <div key={label}>
                      <div style={{ fontSize: 7, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                        textTransform: 'uppercase', letterSpacing: '0.07em' }}>{label}</div>
                      <div style={{ fontSize: 9, color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                        fontWeight: 700, maxWidth: 160, overflow: 'hidden',
                        textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{val}</div>
                    </div>
                  ))}
                </div>

                {/* Full description */}
                {ev.description && ev.description !== ev.url && (
                  <div>
                    <div style={{ fontSize: 7, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                      textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 2 }}>
                      {t('networkMap.fields.description')}
                    </div>
                    <div style={{ fontSize: 8, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                      wordBreak: 'break-word', lineHeight: 1.5 }}>
                      {ev.description.slice(0, 400)}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
