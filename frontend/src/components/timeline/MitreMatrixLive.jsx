
import { useMemo } from 'react';

const TACTICS = [
  { id: 'TA0001', short: 'Recon',       label: 'Reconnaissance' },
  { id: 'TA0002', short: 'Resource',    label: 'Resource Development' },
  { id: 'TA0003', short: 'Init Access', label: 'Initial Access' },
  { id: 'TA0004', short: 'Exec',        label: 'Execution' },
  { id: 'TA0005', short: 'Persist',     label: 'Persistence' },
  { id: 'TA0006', short: 'Priv Esc',    label: 'Privilege Escalation' },
  { id: 'TA0007', short: 'Def Evade',   label: 'Defense Evasion' },
  { id: 'TA0008', short: 'Cred Acc',    label: 'Credential Access' },
  { id: 'TA0009', short: 'Discovery',   label: 'Discovery' },
  { id: 'TA0010', short: 'Lat Move',    label: 'Lateral Movement' },
  { id: 'TA0011', short: 'Collection',  label: 'Collection' },
  { id: 'TA0012', short: 'C2',          label: 'Command and Control' },
  { id: 'TA0040', short: 'Exfil',       label: 'Exfiltration' },
  { id: 'TA0041', short: 'Impact',      label: 'Impact' },
];

const TECH_TO_TACTIC = {
  'T1059': 'TA0004', 'T1059.001': 'TA0004', 'T1059.003': 'TA0004',
  'T1053': 'TA0005', 'T1053.005': 'TA0005',
  'T1078': 'TA0003', 'T1078.003': 'TA0006',
  'T1112': 'TA0005',
  'T1547': 'TA0005', 'T1547.001': 'TA0005',
  'T1055': 'TA0005', 'T1055.001': 'TA0004', 'T1055.012': 'TA0007',
  'T1003': 'TA0008', 'T1003.001': 'TA0008',
  'T1110': 'TA0008',
  'T1021': 'TA0010', 'T1021.001': 'TA0010', 'T1021.002': 'TA0010', 'T1021.006': 'TA0010',
  'T1569': 'TA0004', 'T1569.002': 'TA0004',
  'T1218': 'TA0007', 'T1218.011': 'TA0007',
  'T1140': 'TA0007',
  'T1027': 'TA0007',
  'T1070': 'TA0007', 'T1070.001': 'TA0007', 'T1070.004': 'TA0007',
  'T1036': 'TA0007',
  'T1562': 'TA0007', 'T1562.001': 'TA0007',
  'T1543': 'TA0005', 'T1543.003': 'TA0005',
  'T1012': 'TA0009',
  'T1082': 'TA0009',
  'T1083': 'TA0009',
  'T1069': 'TA0009',
  'T1057': 'TA0009',
  'T1046': 'TA0007',
  'T1049': 'TA0009',
  'T1016': 'TA0009',
  'T1041': 'TA0040',
  'T1071': 'TA0012',
  'T1566': 'TA0003', 'T1566.001': 'TA0003', 'T1566.002': 'TA0003',
  'T1190': 'TA0003',
  'T1133': 'TA0003',
  'T1486': 'TA0041',
  'T1490': 'TA0041',
  'T1105': 'TA0011',
  'T1560': 'TA0011',
};

function getTacticForTech(techId) {
  if (!techId) return null;
  const base = techId.split('.')[0];
  return TECH_TO_TACTIC[techId] || TECH_TO_TACTIC[base] || null;
}

export default function MitreMatrixLive({ records }) {

  const { byTactic, totalHits, techCounts } = useMemo(() => {
    const byTactic = new Map(TACTICS.map(t => [t.id, new Map()]));
    const techCounts = new Map();
    let totalHits = 0;
    for (const r of (records || [])) {
      const tech = r.mitre_technique;
      if (!tech) continue;
      const tactic = getTacticForTech(tech);
      if (!tactic) continue;
      const prev = techCounts.get(tech) || 0;
      techCounts.set(tech, prev + 1);
      if (byTactic.has(tactic)) byTactic.get(tactic).set(tech, (byTactic.get(tactic).get(tech) || 0) + 1);
      totalHits++;
    }
    return { byTactic, totalHits, techCounts };
  }, [records]);

  const activeTactics = TACTICS.filter(t => byTactic.get(t.id)?.size > 0);

  if (totalHits === 0) {
    return (
      <div style={{ padding: '20px 16px', fontFamily: 'monospace', color: '#2a5a8a', fontSize: 11 }}>
        Aucune technique MITRE ATT&CK dans les enregistrements actuels.
        <br />
        <span style={{ fontSize: 10, color: 'var(--fl-accent)' }}>
          Parsez des logs Hayabusa ou Sigma pour enrichir le champ mitre_technique.
        </span>
      </div>
    );
  }

  const maxCount = Math.max(...[...techCounts.values()]);

  return (
    <div style={{ padding: '12px 16px', overflow: 'auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
        <span style={{ fontFamily: 'monospace', fontSize: 9, color: '#3a6a9a', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
          MITRE ATT&CK Matrix — Live
        </span>
        <span style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-accent)', fontWeight: 700 }}>
          {totalHits} hit{totalHits > 1 ? 's' : ''} · {activeTactics.length} tactic{activeTactics.length > 1 ? 's' : ''} · {techCounts.size} technique{techCounts.size > 1 ? 's' : ''}
        </span>
      </div>

      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {TACTICS.map(tac => {
          const techMap = byTactic.get(tac.id);
          const active = techMap?.size > 0;
          return (
            <div key={tac.id} style={{
              minWidth: 100, borderRadius: 5,
              border: `1px solid ${active ? 'var(--fl-accent)' : 'var(--fl-bg)'}`,
              background: active ? '#06111f' : 'var(--fl-bg)',
              overflow: 'hidden',
            }}>
              
              <div style={{
                padding: '4px 7px',
                background: active ? 'linear-gradient(90deg, #0a1e35, var(--fl-bg))' : 'transparent',
                borderBottom: `1px solid ${active ? 'var(--fl-accent)' : 'var(--fl-bg)'}`,
              }}>
                <span style={{
                  fontFamily: 'monospace', fontSize: 8, fontWeight: 700,
                  textTransform: 'uppercase', letterSpacing: '0.08em',
                  color: active ? 'var(--fl-accent)' : 'var(--fl-accent)',
                }}>
                  {tac.short}
                </span>
                {active && (
                  <span style={{ marginLeft: 4, fontSize: 8, fontFamily: 'monospace', color: '#7abfff' }}>
                    ({techMap.size})
                  </span>
                )}
              </div>

              {active && [...techMap.entries()].map(([tech, count]) => {
                const intensity = Math.max(0.15, count / maxCount);
                return (
                  <div key={tech} style={{
                    padding: '3px 7px',
                    background: `rgba(77,130,192,${intensity * 0.25})`,
                    borderBottom: '1px solid var(--fl-bg)',
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 4,
                  }}
                    title={`${tech} — ${count} événement${count > 1 ? 's' : ''}`}
                  >
                    <span style={{ fontFamily: 'monospace', fontSize: 9, color: '#7abfff', fontWeight: 600 }}>
                      {tech}
                    </span>
                    <span style={{
                      fontFamily: 'monospace', fontSize: 8, fontWeight: 700,
                      padding: '0 4px', borderRadius: 3,
                      background: `rgba(77,130,192,${intensity * 0.4})`,
                      color: 'var(--fl-accent)',
                    }}>
                      {count}
                    </span>
                  </div>
                );
              })}

              {!active && (
                <div style={{ padding: '4px 7px', fontSize: 8, color: 'var(--fl-muted)', fontFamily: 'monospace' }}>—</div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
