import { memo } from 'react';
import { fmtTs } from '../../../utils/formatters';
import { artifactColor } from '../../../constants/artifactColors';
import { evaluateColorRules } from '../../../utils/colorRulesEngine';
import {
  fmtDesc, fmtSrc, CONFIDENCE_MAP, FORENSIC_TAGS,
  topDetectionSeverity, DETECTION_SEV_COLOR,
} from '../utils/timelineUtils';

const FORENSIC_TAG_MAP = Object.fromEntries(FORENSIC_TAGS.map(t => [t.key, t]));

function Highlight({ text, term }) {
  const str = String(text ?? '');
  if (!term) return <>{str}</>;
  const idx = str.toLowerCase().indexOf(term.toLowerCase());
  if (idx === -1) return <>{str}</>;
  return (
    <>
      {str.slice(0, idx)}
      <mark style={{ background: 'color-mix(in srgb, var(--fl-warn) 15%, transparent)', color: 'var(--fl-warn)', borderRadius: 2, padding: '0 1px' }}>
        {str.slice(idx, idx + term.length)}
      </mark>
      {str.slice(idx + term.length)}
    </>
  );
}

// Color = signal: the left tick is coloured ONLY for flagged rows (detection,
// hayabusa level, colour rule, selection). Plain rows get no coloured strip —
// the artifact type is already shown by the badge in the ARTIFACT column.
function accentColor({ detSev, lvl, colorMatch, isSelected }) {
  if (detSev)     return DETECTION_SEV_COLOR[detSev] || 'var(--fl-danger)';
  if (lvl)        return lvl.color;
  if (colorMatch) return colorMatch.color;
  if (isSelected) return 'var(--fl-accent)';
  return 'transparent';
}

function rowBg({ isSelected, lvl, colorMatch, hayLevel }) {
  const HAY = {
    critical: 'rgba(220,38,38,0.06)',
    high:     'rgba(234,88,12,0.05)',
    medium:   'rgba(245,158,11,0.04)',
  };
  if (isSelected) return '#0e1a2e';
  if (lvl)        return lvl.bg;
  if (colorMatch) return `color-mix(in srgb, ${colorMatch.color} 7%, transparent)`;
  return HAY[hayLevel] ?? 'transparent';
}

export const EventRow = memo(function EventRow({
  record: r, gridTemplate, visibleCols,
  isSelected, hasNote,
  tagEntry, colorRules, searchTerm,
  onClick, onCellContextMenu,
  pinnedCols, pinnedOffsets, scrollLeftRef,
}) {
  const acol       = artifactColor(r.artifact_type);
  const td         = tagEntry || {};
  const lvl        = td.level ? CONFIDENCE_MAP[td.level] : null;
  const hayLevel   = !lvl && r.artifact_type === 'hayabusa' ? (r.raw?.level || null) : null;
  const colorMatch = colorRules?.length ? evaluateColorRules(r, colorRules) : null;
  const detSev     = topDetectionSeverity(r.detections);
  const accent     = accentColor({ detSev, lvl, colorMatch, isSelected, acol });
  const bg         = rowBg({ isSelected, lvl, colorMatch, hayLevel });

  return (
    <div
      className={`tl-row${isSelected ? ' tl-row--sel' : ''}`}
      style={{ gridTemplateColumns: gridTemplate, background: bg }}
      onClick={onClick}
    >
      {/* Accent bar — 4px left stripe */}
      <div className="tl-accent" style={{ background: accent }} />

      {visibleCols.map(col => {
        const val = col.meta?.dynamic ? r.raw?.[col.meta.rawKey] : r[col.key];
        let content;

        if (col.key === 'timestamp') {
          const ts  = fmtTs(r.timestamp);
          const sep = ts.indexOf(' ');
          const d   = sep > 0 ? ts.slice(0, sep) : ts;
          const t   = sep > 0 ? ts.slice(sep + 1) : '';
          content = (
            <span style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <span style={{ color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, whiteSpace: 'nowrap', lineHeight: '14px' }}>{d}</span>
              {t && <span style={{ color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 8,  whiteSpace: 'nowrap', lineHeight: '13px' }}>{t}</span>}
            </span>
          );

        } else if (col.key === 'timestamp_kind') {
          const kind = r.timestamp_kind || '';
          content = kind
            ? <span style={{ color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, whiteSpace: 'nowrap', padding: '1px 5px', borderRadius: 3, background: 'var(--fl-panel)', border: '1px solid var(--fl-border)' }}>{kind}</span>
            : <span style={{ color: 'var(--fl-border)' }}>—</span>;

        } else if (col.key === 'artifact_type') {
          content = <span style={{ padding: '1px 6px', borderRadius: 3, fontSize: 9, fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: `color-mix(in srgb, ${acol} 9%, transparent)`, color: acol, border: `1px solid color-mix(in srgb, ${acol} 19%, transparent)`, whiteSpace: 'nowrap' }}>{r.artifact_type}</span>;

        } else if (col.key === 'tool') {
          content = val
            ? <span title={String(val)} style={{ color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, whiteSpace: 'nowrap', padding: '1px 5px', borderRadius: 3, background: 'var(--fl-panel)', border: '1px solid var(--fl-border)' }}>{String(val)}</span>
            : <span style={{ color: 'var(--fl-border)' }}>—</span>;

        } else if (col.key === 'description') {
          const desc = fmtDesc(r) || '—';
          content = (
            <span title={desc} style={{ color: 'var(--fl-text)', fontSize: 11 }}>
              {searchTerm ? <Highlight text={desc} term={searchTerm} /> : desc}
              {td.tags?.length > 0 && td.tags.map(key => {
                const ft = FORENSIC_TAG_MAP[key];
                return ft ? <span key={key} style={{ marginLeft: 5, padding: '0 5px', borderRadius: 8, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 600, background: `color-mix(in srgb, ${ft.color} 13%, transparent)`, color: ft.color, border: `1px solid color-mix(in srgb, ${ft.color} 19%, transparent)`, verticalAlign: 'middle' }}>{ft.label}</span> : null;
              })}
              {hasNote && <span style={{ marginLeft: 5, display: 'inline-block', width: 6, height: 6, borderRadius: 2, background: 'var(--fl-accent)', verticalAlign: 'middle' }} />}
            </span>
          );

        } else if (col.key === '_source') {
          const src = fmtSrc(r);
          content = src
            ? <span title={src} style={{ color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10 }}>{src}</span>
            : <span style={{ color: 'var(--fl-border)' }}>—</span>;

        } else if (col.key === 'user_name') {
          content = val
            ? <span title={String(val)} style={{ color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10 }}>{String(val)}</span>
            : <span style={{ color: 'var(--fl-border)' }}>—</span>;

        } else if (col.key === 'host_name') {
          const hn = val ? String(val) : '';
          const display = (hn.startsWith('/app/') || hn.startsWith('/tmp/')) ? '' : hn;
          content = display
            ? <span title={display} style={{ color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10 }}>{display}</span>
            : <span style={{ color: 'var(--fl-border)' }}>—</span>;

        } else if (col.key === '_verdict') {
          const chip = lvl
            ? { label: lvl.label, bg: lvl.bg, color: lvl.color, border: `1px solid color-mix(in srgb, ${lvl.color} 25%, transparent)` }
            : detSev
              ? { label: detSev, bg: `color-mix(in srgb, ${DETECTION_SEV_COLOR[detSev]} 9%, transparent)`, color: DETECTION_SEV_COLOR[detSev], border: `1px solid color-mix(in srgb, ${DETECTION_SEV_COLOR[detSev]} 25%, transparent)` }
              : null;
          content = chip
            ? <span style={{ padding: '1px 6px', borderRadius: 3, fontSize: 9, fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: chip.bg, color: chip.color, border: chip.border, whiteSpace: 'nowrap' }}>{chip.label}</span>
            : null;

        } else if (col.meta?.dynamic) {
          content = val != null
            ? <span style={{ color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10 }}>{String(val).slice(0, 80)}</span>
            : <span style={{ color: 'var(--fl-border)' }}>—</span>;

        } else {
          content = val
            ? <span style={{ color: '#6677aa', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{String(val).slice(0, 60)}</span>
            : <span style={{ color: 'var(--fl-border)' }}>—</span>;
        }

        return (
          <div
            key={col.key}
            className="tl-cell"
            {...(pinnedOffsets?.has(col.key) ? { 'data-sticky-left': '' } : {})}
            onContextMenu={e => { e.preventDefault(); onCellContextMenu(e, col, r); }}
            style={pinnedOffsets?.has(col.key) ? {
              position: 'relative',
              transform: `translateX(${scrollLeftRef?.current ?? 0}px)`,
              zIndex: 2,
              background: (bg && bg !== 'transparent') ? bg : 'var(--fl-bg)',
              boxShadow: '3px 0 6px rgba(0,0,0,0.18)',
              borderRight: '1px solid var(--fl-border)',
            } : undefined}
          >
            {content}
          </div>
        );
      })}
    </div>
  );
}, (prev, next) =>
  prev.record        === next.record       &&
  prev.gridTemplate  === next.gridTemplate &&
  prev.isSelected    === next.isSelected   &&
  prev.hasNote       === next.hasNote      &&
  prev.tagEntry      === next.tagEntry     &&
  prev.colorRules    === next.colorRules   &&
  prev.searchTerm    === next.searchTerm   &&
  prev.visibleCols   === next.visibleCols  &&
  prev.pinnedCols    === next.pinnedCols   &&
  prev.pinnedOffsets === next.pinnedOffsets &&
  prev.scrollLeftRef === next.scrollLeftRef
);
