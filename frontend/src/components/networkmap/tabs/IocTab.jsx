// frontend/src/components/networkmap/tabs/IocTab.jsx
import { useTranslation } from 'react-i18next';

export default function IocTab({ nodeData }) {
  const { t } = useTranslation();
  if (!nodeData) return null;
  const raw = nodeData._raw || {};
  const hasIoc     = nodeData.is_suspicious || raw.ioc_matches?.length > 0;
  const hasBeacon  = (nodeData.beacon_score || 0) > 0;
  const hasDga     = (nodeData.dga_score || 0) > 0;

  if (!hasIoc && !hasBeacon && !hasDga) return (
    <div style={{ padding: 12, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10 }}>{t('networkMap.no_threat_intel')}</div>
  );

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '8px 10px', display: 'flex', flexDirection: 'column', gap: 8 }}>
      {hasBeacon && (
        <div style={{ padding: '6px 8px', borderRadius: 4, background: '#0a0f18', border: '1px solid color-mix(in srgb, var(--fl-warn) 19%, transparent)' }}>
          <div style={{ fontSize: 8, color: 'var(--fl-warn)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, marginBottom: 4 }}>{t('networkMap.c2_beacon_detected')}</div>
          <div style={{ fontSize: 9, color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{t('networkMap.fields.score')}: {nodeData.beacon_score}%</div>
          {raw.beacon_interval_avg && <div style={{ fontSize: 8, color: '#556070', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{t('networkMap.fields.interval_avg')}: {Math.round(raw.beacon_interval_avg)}s</div>}
          {raw.beacon_cv !== undefined && <div style={{ fontSize: 8, color: '#556070', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>CV: {raw.beacon_cv?.toFixed(3)}</div>}
        </div>
      )}
      {hasDga && (
        <div style={{ padding: '6px 8px', borderRadius: 4, background: '#0a0f18', border: '1px solid color-mix(in srgb, var(--fl-accent) 19%, transparent)' }}>
          <div style={{ fontSize: 8, color: 'var(--fl-accent)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, marginBottom: 4 }}>{t('networkMap.dga_domain')}</div>
          <div style={{ fontSize: 9, color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{t('networkMap.fields.score')}: {nodeData.dga_score}/100</div>
          {raw.dga_entropy && <div style={{ fontSize: 8, color: '#556070', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{t('networkMap.fields.entropy')}: {raw.dga_entropy?.toFixed(2)}</div>}
        </div>
      )}
      {(raw.ioc_matches || []).map((ioc, i) => (
        <div key={i} style={{ padding: '6px 8px', borderRadius: 4, background: '#0a0f18', border: '1px solid color-mix(in srgb, var(--fl-danger) 19%, transparent)' }}>
          <div style={{ fontSize: 8, color: 'var(--fl-danger)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700 }}>{t('networkMap.ioc_match')}</div>
          <div style={{ fontSize: 9, color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{ioc.type}: {ioc.value}</div>
          {ioc.feed && <div style={{ fontSize: 8, color: '#556070', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{t('networkMap.fields.feed')}: {ioc.feed}</div>}
          {ioc.severity && <div style={{ fontSize: 8, color: '#556070', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{t('networkMap.fields.severity')}: {ioc.severity}</div>}
        </div>
      ))}
    </div>
  );
}
