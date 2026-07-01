import { useEffect, useState } from 'react';
import { Maximize2, Minimize2, X } from 'lucide-react';
import { useTimelineStore } from '../store/useTimelineStore';
import { artifactColor } from '../../../constants/artifactColors';
import { fmtTs } from '../../../utils/formatters';
import {
  fmtDesc, CONFIDENCE_MAP, FORENSIC_TAGS,
  topDetectionSeverity, DETECTION_SEV_COLOR,
  computeRef,
} from '../utils/timelineUtils';
import DetailsTab from './tabs/DetailsTab';
import RawTab     from './tabs/RawTab';
import MitreTab   from './tabs/MitreTab';
import NotesTab   from './tabs/NotesTab';
import AiTab      from './tabs/AiTab';
import TagsTab    from './tabs/TagsTab';
import SchemaTab  from './tabs/SchemaTab';

const FORENSIC_TAG_MAP = Object.fromEntries(FORENSIC_TAGS.map(t => [t.key, t]));

const TABS = [
  { key: 'details', label: 'Details' },
  { key: 'mitre',   label: 'MITRE'   },
  { key: 'tags',    label: 'Tags'    },
  { key: 'notes',   label: 'Notes'   },
  { key: 'raw',     label: 'Raw'     },
  { key: 'schema',  label: 'Schema'  },
  { key: 'ai',      label: 'AI ✦', accent: 'var(--fl-ok)' },
];

export default function DetailPanel() {
  const {
    selectedRowId, detailOpen, records, tagData,
    detailTab, setDetailTab, closeDetail, setSelectedRow,
    bookmarks, toggleBookmark,
  } = useTimelineStore();
  const [expanded, setExpanded] = useState(false);

  const record = records.find(r => r.id === selectedRowId) || null;
  const acol   = record ? artifactColor(record.artifact_type) : 'var(--fl-accent)';
  const td     = record ? (tagData.get(record.id) || {}) : {};
  const lvl    = td.level ? CONFIDENCE_MAP[td.level] : null;
  const detSev = record ? topDetectionSeverity(record.detections) : null;
  const isBookmarked = record ? bookmarks.some(b => b.ref === computeRef(record)) : false;

  useEffect(() => {
    function onKey(e) {
      const tag = (e.target?.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || e.target?.isContentEditable) return;
      if (e.key === 'd' || e.key === 'D') { if (detailOpen) closeDetail(); }
    }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [detailOpen, closeDetail]);

  if (!detailOpen || !record) return null;

  const desc      = fmtDesc(record) || record.description || '—';
  const mitreTags = record.mitre_technique_id
    ? record.mitre_technique_id.split(',').map(s => s.trim()).filter(Boolean)
    : [];

  return (
    <div style={{ width: expanded ? 700 : 360, flexShrink: 0, background: 'var(--fl-bg)',
      borderLeft: '1px solid var(--fl-border)', display: 'flex', flexDirection: 'column', overflow: 'hidden',
      transition: 'width 0.15s ease' }}>

      {/* Artifact color bar — full width top border */}
      <div style={{ height: 3, background: acol, flexShrink: 0 }} />

      {/* Forensic identity header */}
      <div style={{ padding: '8px 12px 0', borderBottom: '1px solid var(--fl-card)', flexShrink: 0 }}>

        {/* Line 1: artifact badge + timestamp + host + navigation */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
          <span style={{ padding: '1px 6px', borderRadius: 3, fontSize: 9, fontWeight: 700,
            fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: `color-mix(in srgb, ${acol} 9%, transparent)`, color: acol, border: `1px solid color-mix(in srgb, ${acol} 19%, transparent)`,
            flexShrink: 0 }}>
            {record.artifact_type}
          </span>
          <span style={{ fontSize: 10, color: 'var(--fl-accent)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flex: 1,
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {fmtTs(record.timestamp)}
          </span>
          {record.host_name && (
            <span style={{ fontSize: 9, color: '#4a6080', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flexShrink: 0 }}>
              {record.host_name}
            </span>
          )}
          <div style={{ display: 'flex', gap: 2, flexShrink: 0 }}>
            <button
              onClick={() => { const idx = records.indexOf(record); if (idx > 0) setSelectedRow(records[idx - 1].id); }}
              title="Previous (↑)"
              style={{ width: 20, height: 18, borderRadius: 3, background: 'transparent',
                border: '1px solid var(--fl-border)', color: 'var(--fl-muted)', cursor: 'pointer', fontSize: 10,
                display: 'flex', alignItems: 'center', justifyContent: 'center' }}>↑</button>
            <button
              onClick={() => { const idx = records.indexOf(record); if (idx < records.length - 1) setSelectedRow(records[idx + 1].id); }}
              title="Next (↓)"
              style={{ width: 20, height: 18, borderRadius: 3, background: 'transparent',
                border: '1px solid var(--fl-border)', color: 'var(--fl-muted)', cursor: 'pointer', fontSize: 10,
                display: 'flex', alignItems: 'center', justifyContent: 'center' }}>↓</button>
            <button
              onClick={() => record && toggleBookmark(record)}
              title={isBookmarked ? 'Remove bookmark' : 'Bookmark this event'}
              style={{
                width: 20, height: 18, borderRadius: 3, background: 'transparent',
                border: `1px solid ${isBookmarked ? 'color-mix(in srgb, var(--fl-gold) 25%, transparent)' : 'var(--fl-border)'}`,
                color: isBookmarked ? 'var(--fl-gold)' : 'var(--fl-muted)', cursor: 'pointer', fontSize: 12,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}
              onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-gold)'; }}
              onMouseLeave={e => { e.currentTarget.style.color = isBookmarked ? 'var(--fl-gold)' : 'var(--fl-muted)'; }}
            >
              {isBookmarked ? '★' : '☆'}
            </button>
            <button onClick={() => setExpanded(v => !v)} title={expanded ? 'Collapse' : 'Expand'}
              style={{ width: 20, height: 18, borderRadius: 3, background: 'transparent',
                border: '1px solid var(--fl-border)', color: 'var(--fl-muted)', cursor: 'pointer',
                display: 'flex', alignItems: 'center', justifyContent: 'center' }}
              onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-accent)'; e.currentTarget.style.borderColor = 'color-mix(in srgb, var(--fl-accent) 25%, transparent)'; }}
              onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; e.currentTarget.style.borderColor = 'var(--fl-border)'; }}>
              {expanded ? <Minimize2 size={10} /> : <Maximize2 size={10} />}
            </button>
            <button onClick={closeDetail} title="Close (D / Esc)"
              style={{ width: 20, height: 18, borderRadius: 3, background: 'transparent',
                border: '1px solid var(--fl-border)', color: 'var(--fl-muted)', cursor: 'pointer', fontSize: 12,
                display: 'flex', alignItems: 'center', justifyContent: 'center' }}><X size={10} /></button>
          </div>
        </div>

        {/* Line 2: description */}
        <div style={{ fontSize: 11, color: '#c0d4f0', marginBottom: 5, lineHeight: 1.4,
          display: '-webkit-box', WebkitLineClamp: 3, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
          {desc}
        </div>

        {/* Line 3: confidence + forensic tags + MITRE IDs */}
        {(lvl || detSev || td.tags?.length > 0 || mitreTags.length > 0) && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 6 }}>
            {lvl && (
              <span style={{ padding: '1px 6px', borderRadius: 3, fontSize: 9, fontWeight: 700,
                fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: lvl.bg, color: lvl.color,
                border: `1px solid color-mix(in srgb, ${lvl.color} 25%, transparent)` }}>
                {lvl.label}
              </span>
            )}
            {detSev && !lvl && (
              <span style={{ padding: '1px 6px', borderRadius: 3, fontSize: 9, fontWeight: 700,
                fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: `color-mix(in srgb, ${DETECTION_SEV_COLOR[detSev]} 9%, transparent)`,
                color: DETECTION_SEV_COLOR[detSev], border: `1px solid color-mix(in srgb, ${DETECTION_SEV_COLOR[detSev]} 25%, transparent)` }}>
                {detSev}
              </span>
            )}
            {td.tags?.map(key => {
              const ft = FORENSIC_TAG_MAP[key];
              return ft ? (
                <span key={key} style={{ padding: '0 5px', borderRadius: 8, fontSize: 9,
                  fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 600, background: `color-mix(in srgb, ${ft.color} 13%, transparent)`,
                  color: ft.color, border: `1px solid color-mix(in srgb, ${ft.color} 19%, transparent)` }}>
                  {ft.label}
                </span>
              ) : null;
            })}
            {mitreTags.slice(0, 3).map(t => (
              <span key={t} style={{ padding: '0 5px', borderRadius: 3, fontSize: 9,
                fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'var(--fl-card)', color: 'var(--fl-accent)',
                border: '1px solid color-mix(in srgb, var(--fl-accent) 19%, transparent)' }}>
                {t}
              </span>
            ))}
          </div>
        )}

        {/* Tab nav */}
        <div style={{ display: 'flex', gap: 0, flexWrap: 'nowrap', overflowX: 'auto' }}>
          {TABS.map(tab => {
            const active = detailTab === tab.key;
            const color  = tab.accent || acol;
            return (
              <button key={tab.key} onClick={() => setDetailTab(tab.key)} style={{
                padding: '3px 8px', borderRadius: '4px 4px 0 0', fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                background: active ? 'var(--fl-panel)' : 'transparent',
                border: `1px solid ${active ? 'var(--fl-border)' : 'transparent'}`,
                borderBottom: active ? '1px solid var(--fl-panel)' : '1px solid transparent',
                marginBottom: active ? -1 : 0,
                color: active ? color : 'var(--fl-muted)', cursor: 'pointer',
                fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase',
                whiteSpace: 'nowrap', flexShrink: 0,
              }}>{tab.label}</button>
            );
          })}
        </div>
      </div>

      {/* Tab body */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: 'var(--fl-panel)' }}>
        {detailTab === 'details' && <DetailsTab record={record} />}
        {detailTab === 'mitre'   && <MitreTab   record={record} />}
        {detailTab === 'tags'    && <TagsTab    record={record} />}
        {detailTab === 'notes'   && <NotesTab   record={record} />}
        {detailTab === 'raw'     && <RawTab     record={record} />}
        {detailTab === 'schema'  && <SchemaTab  record={record} />}
        {detailTab === 'ai'      && <AiTab      record={record} />}
      </div>
    </div>
  );
}
