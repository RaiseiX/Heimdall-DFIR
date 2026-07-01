// frontend/src/components/globalnetworkmap/GlobalMapStats.jsx
import { useTranslation } from 'react-i18next';

export default function GlobalMapStats({ stats, loading }) {
  const { t } = useTranslation();
  const { nodeCount, edgeCount, evidenceCount, correlatedCount, truncated } = stats || {};

  const chip = (label, value, color, dimColor) => (
    <span key={label} style={{
      background: 'rgba(10,15,26,0.9)',
      border: `1px solid ${color}`,
      borderRadius: 4,
      padding: '2px 10px',
      fontSize: 11,
      color: dimColor || color,
      fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
      whiteSpace: 'nowrap',
    }}>
      {loading ? '—' : label}
    </span>
  );

  return (
    <div style={{
      position: 'absolute', top: 12, left: 12,
      display: 'flex', gap: 6, zIndex: 10, flexWrap: 'wrap',
    }}>
      {chip(t('networkMap.nodes', { count: nodeCount || 0 }), nodeCount, '#1e293b', 'var(--fl-purple)')}
      {chip(t('networkMap.edges', { count: edgeCount || 0 }), edgeCount, '#1e293b', 'var(--fl-purple)')}
      {chip(t('networkMap.evidences', { count: evidenceCount || 0 }), evidenceCount, '#1e293b', 'var(--fl-accent)')}
      {!loading && correlatedCount > 0 && chip(t('networkMap.correlated', { count: correlatedCount }), correlatedCount, 'rgba(218,54,51,0.4)', 'var(--fl-danger)')}
      {!loading && truncated && (
        <span style={{
          background: 'rgba(200,157,29,0.12)',
          border: '1px solid rgba(200,157,29,0.35)',
          borderRadius: 4,
          padding: '2px 10px',
          fontSize: 11,
          color: 'var(--fl-gold)',
          fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
        }}>
          {t('networkMap.graph_truncated')}
        </span>
      )}
    </div>
  );
}
