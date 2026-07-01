// frontend/src/components/networkmap/Toolbar.jsx
import { useState } from 'react';
import { Search } from 'lucide-react';
import { NODE_TYPES } from '../../constants/nodeTypes';
import { useTranslation } from 'react-i18next';

const FILTER_TYPES = ['server','workstation','laptop','domain_controller','external_ip','domain','firewall','proxy','router','switch','ioc'];

export default function Toolbar({ graphData, filters, onFilterChange, onSearch, onViewChange, view }) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const stats = graphData || {};

  const iocCount     = (stats.nodes || []).filter(n => n.is_suspicious).length;
  const beaconCount  = (stats.nodes || []).filter(n => (n.beacon_score || 0) > 70).length;
  const dgaCount     = (stats.nodes || []).filter(n => (n.dga_score || 0) > 60).length;

  return (
    <div style={{ background: 'var(--fl-bg)', borderBottom: '1px solid var(--fl-raised)', padding: '5px 12px', flexShrink: 0, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', minHeight: 36 }}>
      {/* View toggle */}
      <div style={{ display: 'flex', gap: 2, flexShrink: 0 }}>
        {[['network', t('networkMap.views.network')], ['attack', t('networkMap.views.attack')], ['lateral', t('networkMap.views.lateral')]].map(([v, label]) => (
          <button key={v} onClick={() => onViewChange(v)} style={{
            padding: '2px 9px', borderRadius: 4, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer',
            background: view === v ? 'color-mix(in srgb, var(--fl-purple) 8%, transparent)' : 'transparent',
            color:      view === v ? 'var(--fl-purple)'   : 'var(--fl-muted)',
            border:     `1px solid ${view === v ? 'color-mix(in srgb, var(--fl-purple) 25%, transparent)' : 'var(--fl-raised)'}`,
          }}>{label}</button>
        ))}
      </div>

      <div style={{ width: 1, height: 18, background: 'var(--fl-raised)', flexShrink: 0 }} />

      {/* Search */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 5, background: 'var(--fl-panel)', border: '1px solid var(--fl-subtle)', borderRadius: 4, padding: '0 8px', height: 24, minWidth: 180 }}>
        <Search size={11} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} />
        <input
          value={search}
          onChange={e => { setSearch(e.target.value); onSearch(e.target.value); }}
          placeholder={t('networkMap.search_node_ph')}
          style={{ background: 'none', border: 'none', outline: 'none', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-dim)', width: '100%' }}
        />
      </div>

      {/* Type filter chips */}
      <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
        {FILTER_TYPES.filter(t => NODE_TYPES[t]).slice(0, 6).map(typeId => {
          const type   = NODE_TYPES[typeId];
          const active = !((filters?.hiddenTypes) || new Set()).has(typeId);
          return (
            <button key={typeId} onClick={() => onFilterChange('toggleType', typeId)} style={{
              padding: '1px 7px', borderRadius: 8, fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer',
              background: active ? `color-mix(in srgb, ${type.color} 13%, transparent)` : 'transparent',
              color:      active ? type.color        : `color-mix(in srgb, ${type.color} 27%, transparent)`,
              border:     `1px solid ${active ? type.color + '60' : type.color + '20'}`,
              textDecoration: active ? 'none' : 'line-through',
              opacity: active ? 1 : 0.5,
            }}>● {type.label}</button>
          );
        })}
      </div>

      <div style={{ flex: 1 }} />

      {/* Intelligence badges */}
      {iocCount > 0    && <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-danger) 6%, transparent)', color: 'var(--fl-danger)', border: '1px solid color-mix(in srgb, var(--fl-danger) 19%, transparent)', flexShrink: 0 }}>⚠ {iocCount} IOC</span>}
      {beaconCount > 0 && <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-warn) 6%, transparent)', color: 'var(--fl-warn)', border: '1px solid color-mix(in srgb, var(--fl-warn) 19%, transparent)', flexShrink: 0 }}>◎ {beaconCount > 1 ? t('networkMap.beacons_pl', { count: beaconCount }) : t('networkMap.beacons', { count: beaconCount })}</span>}
      {dgaCount > 0    && <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-accent) 6%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 19%, transparent)', flexShrink: 0 }}>⁉ {dgaCount} DGA</span>}
    </div>
  );
}
