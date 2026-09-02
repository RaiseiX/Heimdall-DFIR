import { useState, useEffect, useRef, useMemo } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { useTimelineStore } from '../store/useTimelineStore';
import { buildFacet } from '../utils/timelineUtils';

const SELECT_ONLY = new Set(['artifact_type']);

const OPS = [
  { value: 'contains',     label: 'contains'    },
  { value: 'not_contains', label: 'not contains' },
  { value: 'equals',       label: 'equals'       },
  { value: 'not_equals',   label: 'not equals'   },
  { value: 'starts_with',  label: 'starts with'  },
  { value: 'ends_with',    label: 'ends with'    },
  { value: 'regex',        label: 'regex'        },
  { value: 'empty',        label: 'is empty'     },
  { value: 'not_empty',    label: 'is not empty' },
];

function getStoreField(colKey) {
  const MAP = {
    host_name: 'hostFilter',
    user_name: 'userFilter',
    tool:      'toolFilter',
    event_id:  'eventIdFilter',
    ext:       'extFilter',
  };
  return MAP[colKey] || null;
}

export function isColFilterActive(colKey, storeState) {
  const field = getStoreField(colKey);
  if (field) {
    const opField = field + 'Op';
    return !!storeState[field]
      || storeState[opField] === 'empty'
      || storeState[opField] === 'not_empty';
  }
  if (colKey === 'artifact_type') return storeState.artifactTypes.length > 0;
  return !!storeState.search
    || storeState.searchOp === 'empty'
    || storeState.searchOp === 'not_empty';
}

export default function FilterPopover({ col, onClose, anchorEl }) {
  const { t, i18n } = useTranslation();
  const store = useTimelineStore();
  const ref   = useRef(null);

  const selectOnly = SELECT_ONLY.has(col.key);
  const facet = useMemo(() => buildFacet(col.key, store), [col.key, store]);
  const selectedValues = col.key === 'artifact_type' ? store.artifactTypes : [];

  function pickValue(value) {
    const s = useTimelineStore.getState();
    if (col.key === 'artifact_type') { s.toggleArtifactType(value); return; }
    const field = getStoreField(col.key);
    if (field) {
      s.setFilter(field + 'Op', 'equals');
      s.setFilter(field, value);
    } else {
      s.setFilter('searchOp', 'equals');
      s.setFilter('search', value);
    }
    s.applyFilters();
    onClose();
  }

  const storeField   = getStoreField(col.key);
  const storeOpField = storeField ? storeField + 'Op' : 'searchOp';
  const initialValue = storeField ? (store[storeField] || '') : (store.search || '');

  const [op,    setOp]    = useState(store[storeOpField] || 'contains');
  const [value, setValue] = useState(initialValue);

  const [pos, setPos] = useState({ top: -9999, left: -9999 });
  useEffect(() => {
    if (anchorEl?.current) {
      const rect = anchorEl.current.getBoundingClientRect();
      const popoverW = 220;
      const left = Math.max(4, Math.min(
        rect.left + rect.width / 2 - popoverW / 2,
        window.innerWidth - popoverW - 4,
      ));
      setPos({ top: rect.bottom + 2, left });
    }
  }, [anchorEl]);

  useEffect(() => {
    function handler(e) {
      if (ref.current && !ref.current.contains(e.target)
          && !(anchorEl?.current?.contains(e.target))) onClose();
    }
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [onClose, anchorEl]);

  function handleValueChange(e) {
    const raw = e.target.value;
    if (raw.startsWith('-') && raw.length > 1) {
      setOp('not_contains');
      setValue(raw.slice(1));
    } else {
      setValue(raw);
    }
  }

  function apply() {
    const s = useTimelineStore.getState();
    if (storeField) {
      s.setFilter(storeField + 'Op', op);
      s.setFilter(storeField, noValue ? '' : value);
    } else {
      s.setFilter('search',   noValue ? '' : value);
      s.setFilter('searchOp', op);
    }
    s.applyFilters();
    onClose();
  }

  function clear() {
    const s = useTimelineStore.getState();
    if (storeField) {
      s.setFilter(storeField + 'Op', 'contains');
      s.setFilter(storeField, '');
    } else {
      s.setFilter('searchOp', 'contains');
      s.setFilter('search', '');
    }
    s.applyFilters();
    onClose();
  }

  const noValue = op === 'empty' || op === 'not_empty';

  return createPortal(
    <div
      ref={ref}
      onMouseDown={e => e.stopPropagation()}
      style={{
        position: 'fixed', top: pos.top, left: pos.left, zIndex: 9999,
        background: 'var(--fl-bg)', border: '1px solid var(--fl-raised)', borderRadius: 6,
        padding: 10, width: 248, boxShadow: '0 8px 28px rgba(0,0,0,0.7)',
        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, display: 'flex', flexDirection: 'column', gap: 7,
      }}
    >
      <div style={{ fontSize: 8, color: 'var(--fl-muted)', textTransform: 'uppercase',
        letterSpacing: '0.08em', fontWeight: 700 }}>
        {t('timeline.filter_title', { column: col.label })}
      </div>

      {facet.values.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          <div style={{ fontSize: 8, color: 'var(--fl-muted)', display: 'flex', justifyContent: 'space-between', gap: 6, paddingBottom: 2 }}>
            <span>{t('timeline.filter_values')}</span>
            <span>{t(facet.scope === 'collection' ? 'timeline.filter_scope_collection' : 'timeline.filter_scope_page')}</span>
          </div>
          <div style={{ maxHeight: 168, overflowY: 'auto', display: 'flex', flexDirection: 'column' }}>
            {facet.values.map(v => {
              const on = selectedValues.includes(v.value);
              return (
                <button key={v.value} onClick={() => pickValue(v.value)}
                  title={v.value}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 7, width: '100%',
                    background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left',
                    padding: '3px 2px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10,
                    color: on ? 'var(--fl-accent)' : 'var(--fl-dim)',
                  }}>
                  <span style={{ width: 9, height: 9, borderRadius: 2, flexShrink: 0,
                    border: `1px solid ${on ? 'var(--fl-accent)' : 'var(--fl-raised)'}`,
                    background: on ? 'var(--fl-accent)' : 'transparent' }} />
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.value}</span>
                  <span style={{ marginLeft: 'auto', color: 'var(--fl-muted)', fontSize: 9, flexShrink: 0 }}>
                    {v.count === null
                      ? t('timeline.filter_no_count')
                      : v.count.toLocaleString(i18n.language)}
                  </span>
                </button>
              );
            })}
          </div>
          {facet.hidden > 0 && (
            <div style={{ fontSize: 9, color: 'var(--fl-muted)', paddingTop: 3 }}>
              {t('timeline.filter_hidden', { count: facet.hidden })}
            </div>
          )}
        </div>
      )}

      {selectOnly ? (
        <div style={{ fontSize: 9, color: 'var(--fl-muted)', lineHeight: 1.5 }}>
          {t('timeline.filter_select_only')}
        </div>
      ) : (<>
      <select
        value={op}
        onChange={e => setOp(e.target.value)}
        style={{
          background: 'var(--fl-panel)', color: 'var(--fl-dim)', border: '1px solid var(--fl-raised)',
          borderRadius: 4, padding: '4px 6px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, outline: 'none',
        }}
      >
        {OPS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
      <input
        autoFocus
        disabled={noValue}
        value={noValue ? '' : value}
        onChange={handleValueChange}
        onKeyDown={e => { if (e.key === 'Enter') apply(); if (e.key === 'Escape') onClose(); }}
        placeholder={noValue ? '—' : '-foo = not contains foo'}
        style={{
          background: noValue ? 'var(--fl-bg)' : 'var(--fl-panel)',
          color: noValue ? 'var(--fl-raised)' : 'var(--fl-dim)',
          border: '1px solid var(--fl-raised)', borderRadius: 4,
          padding: '5px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, outline: 'none',
        }}
      />
      <div style={{ display: 'flex', gap: 6 }}>
        <button
          onClick={apply}
          style={{
            flex: 1, padding: '4px', borderRadius: 4, background: 'var(--fl-card)',
            border: '1px solid color-mix(in srgb, var(--fl-accent) 25%, transparent)', color: 'var(--fl-accent)', cursor: 'pointer',
            fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
          }}
        >{t('timeline.filter_apply')}</button>
        <button
          onClick={clear}
          style={{
            padding: '4px 8px', borderRadius: 4, background: 'transparent',
            border: '1px solid var(--fl-raised)', color: 'var(--fl-muted)', cursor: 'pointer',
            fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
          }}
        >{t('timeline.filter_clear')}</button>
      </div>
      </>)}
    </div>,
    document.body,
  );
}
