import { useMemo } from 'react';
import AiAnalystPanel from '../../../timeline/AiAnalystPanel';
import { useTimelineStore } from '../../store/useTimelineStore';
import { fmtDesc, fmtSrc } from '../../utils/timelineUtils';
import { fmtTs } from '../../../../utils/formatters';

export default function AiTab({ record: r }) {
  const { caseId } = useTimelineStore();

  const eventContext = useMemo(() => {
    if (!r) return null;
    return {
      timestamp:     fmtTs(r.timestamp),
      artifact_type: r.artifact_type,
      description:   fmtDesc(r),
      source:        fmtSrc(r),
      host_name:     r.host_name,
      user_name:     r.user_name,
      process_name:  r.process_name,
      event_id:      r.event_id,
      detections:    r.detections,
      mitre:         r.mitre_technique_id,
      raw:           r.raw,
    };
  }, [r]);

  if (!r || !caseId) return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }}>
      Select an event to use the AI analyst.
    </div>
  );

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <AiAnalystPanel caseId={caseId} records={[r]} totalEvents={1} />
    </div>
  );
}
