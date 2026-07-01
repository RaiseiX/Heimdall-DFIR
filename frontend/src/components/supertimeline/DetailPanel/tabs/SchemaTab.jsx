import { useState, useMemo } from 'react';
import { useTimelineStore } from '../../store/useTimelineStore';
import { ARTIFACT_FIELD_PRIORITY, buildDynamicCols } from '../../utils/timelineUtils';

export default function SchemaTab({ record }) {
  const { artifactTypes, records, caseId } = useTimelineStore();
  const [search, setSearch] = useState('');

  const isSingleArtifact = artifactTypes.length === 1;
  const artifactType     = isSingleArtifact ? artifactTypes[0] : record?.artifact_type;

  const activeDynamicKeys = useMemo(() => {
    if (!isSingleArtifact) return new Set();
    return new Set(buildDynamicCols(records, artifactType, caseId).map(c => c.meta.rawKey));
  }, [isSingleArtifact, records, artifactType, caseId]);

  const rawFields = useMemo(() => {
    if (!record?.raw) return [];
    const priority = ARTIFACT_FIELD_PRIORITY[record.artifact_type] || [];
    const prioritySet = new Set(priority);
    const allKeys = Object.keys(record.raw);
    return [
      ...priority.filter(k => allKeys.includes(k)),
      ...allKeys.filter(k => !prioritySet.has(k)).sort(),
    ].map(k => ({ key: k, value: record.raw[k] }));
  }, [record]);

  const filtered = search
    ? rawFields.filter(f =>
        f.key.toLowerCase().includes(search.toLowerCase()) ||
        String(f.value ?? '').toLowerCase().includes(search.toLowerCase())
      )
    : rawFields;

  function addColumn(rawKey) {
    if (!artifactType || !caseId) return;
    const storageKey = `supertl.dynamicCols.${artifactType}.${caseId}`;
    try {
      const existing = JSON.parse(localStorage.getItem(storageKey) || '[]');
      if (!existing.includes(rawKey)) {
        localStorage.setItem(storageKey, JSON.stringify([...existing, rawKey]));
        useTimelineStore.getState().bumpDynamicCols();
      }
    } catch { /**/ }
  }

  if (!record?.raw || Object.keys(record.raw).length === 0) {
    return (
      <div style={{ padding: 20, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, textAlign: 'center' }}>
        No raw fields available for this event.
      </div>
    );
  }

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Search */}
      <div style={{ padding: '8px 12px', borderBottom: '1px solid var(--fl-card)', flexShrink: 0 }}>
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter fields…"
          style={{ width: '100%', background: 'var(--fl-panel)', border: '1px solid var(--fl-raised)', borderRadius: 5,
            padding: '4px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-dim)', outline: 'none',
            boxSizing: 'border-box' }}
        />
        {!isSingleArtifact && (
          <div style={{ marginTop: 5, fontSize: 9, color: 'var(--fl-muted)', fontStyle: 'italic' }}>
            Select a single artifact type to enable Add Column.
          </div>
        )}
      </div>

      {/* Field list */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {filtered.map(({ key, value }) => {
          const isActive   = activeDynamicKeys.has(key);
          const displayVal = value == null ? '—'
            : typeof value === 'object' ? JSON.stringify(value)
            : String(value);
          return (
            <div key={key} style={{ padding: '5px 12px', borderBottom: '1px solid #090d14',
              display: 'flex', alignItems: 'flex-start', gap: 8 }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 9, color: 'var(--fl-muted)', textTransform: 'uppercase',
                  letterSpacing: '0.1em', marginBottom: 2, display: 'flex', alignItems: 'center', gap: 4 }}>
                  {key}
                  {isActive && (
                    <span style={{ fontSize: 8, padding: '0 4px', borderRadius: 2,
                      background: 'var(--fl-card)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 25%, transparent)' }}>⊞ visible</span>
                  )}
                </div>
                <div
                  onClick={() => { try { navigator.clipboard.writeText(displayVal); } catch { /**/ } }}
                  title="Click to copy"
                  style={{ fontSize: 10, color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'copy',
                    wordBreak: 'break-all', lineHeight: 1.4, maxHeight: 60, overflow: 'hidden' }}>
                  {displayVal.length > 200 ? `${displayVal.slice(0, 200)}…` : displayVal}
                </div>
              </div>
              {isSingleArtifact && !isActive && (
                <button onClick={() => addColumn(key)} title="Add as column in timeline"
                  style={{ flexShrink: 0, fontSize: 9, padding: '2px 6px', borderRadius: 3, cursor: 'pointer',
                    background: 'var(--fl-card)', border: '1px solid color-mix(in srgb, var(--fl-accent) 25%, transparent)', color: 'var(--fl-accent)',
                    fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', marginTop: 2 }}>
                  + col
                </button>
              )}
            </div>
          );
        })}
        {filtered.length === 0 && (
          <div style={{ padding: 20, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, textAlign: 'center' }}>
            {search ? `No fields match "${search}"` : 'No fields to display.'}
          </div>
        )}
      </div>

      {/* Footer */}
      <div style={{ padding: '4px 12px', borderTop: '1px solid var(--fl-card)', flexShrink: 0,
        fontSize: 8, color: 'var(--fl-raised)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
        {rawFields.length} fields · {filtered.length} shown
      </div>
    </div>
  );
}
