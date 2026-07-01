// frontend/src/components/networkmap/tabs/LateralTab.jsx
import { useTranslation } from 'react-i18next';

const LATERAL_EID_KEYS = {
  4624: 'networkMap.eid_logon', 4648: 'networkMap.eid_explicit_creds', 4768: 'networkMap.eid_kerberos_tgt',
  4769: 'networkMap.eid_kerberos_st', 4776: 'networkMap.eid_ntlm_auth', 3: 'networkMap.eid_sysmon_network',
};

export default function LateralTab({ nodeData, allEdges }) {
  const { t } = useTranslation();
  if (!nodeData) return null;
  const nodeId = nodeData.id;

  const lateralEdges = (allEdges || []).filter(e => {
    const src = e.data?.source;
    const tgt = e.data?.target;
    if (!src || !tgt) return false;
    const eids = e.data?.event_ids || [];
    const isLateral = eids.some(id => [4624, 4648, 4768, 4769, 4776].includes(Number(id)));
    return isLateral && (src === nodeId || tgt === nodeId);
  });

  if (!lateralEdges.length) return (
    <div style={{ padding: 12, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10 }}>{t('networkMap.no_lateral')}</div>
  );

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '6px 10px' }}>
      <div style={{ fontSize: 7, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>
        {t(lateralEdges.length !== 1 ? 'networkMap.lateral_paths_pl' : 'networkMap.lateral_paths', { count: lateralEdges.length })}
      </div>
      {lateralEdges.map((e, i) => {
        const src = e.data?.source;
        const tgt = e.data?.target;
        const dir = src === nodeId ? 'out' : 'in';
        const peer = dir === 'out' ? tgt : src;
        const eids = (e.data?.event_ids || []).map(Number);
        return (
          <div key={i} style={{ padding: '5px 6px', marginBottom: 3, borderRadius: 2, background: '#0a0f18', borderLeft: `2px solid ${dir === 'out' ? 'var(--fl-warn)' : 'var(--fl-purple)'}` }}>
            <div style={{ display: 'flex', gap: 5, alignItems: 'center', marginBottom: 2 }}>
              <span style={{ fontSize: 9, color: dir === 'out' ? 'var(--fl-warn)' : 'var(--fl-purple)' }}>{dir === 'out' ? '→' : '←'}</span>
              <span style={{ fontSize: 8, color: '#a0b8d0', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flex: 1 }}>{peer}</span>
              <span style={{ fontSize: 7, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{e.data?.connection_count || 1}x</span>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
              {eids.map(eid => (
                <span key={eid} style={{ fontSize: 6.5, padding: '1px 4px', borderRadius: 2, background: '#1a1f2c', color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                  {LATERAL_EID_KEYS[eid] ? t(LATERAL_EID_KEYS[eid]) : t('networkMap.eid', { eid })}
                </span>
              ))}
              {(e.data?.usernames || []).map((u, j) => (
                <span key={j} style={{ fontSize: 6.5, padding: '1px 4px', borderRadius: 2, background: '#1a1030', color: 'var(--fl-accent)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{u}</span>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
