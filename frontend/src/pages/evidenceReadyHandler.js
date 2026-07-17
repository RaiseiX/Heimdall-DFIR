// Pure reaction to a socket `evidence:ready` event. Kept out of the component so it is unit-testable.
export function makeEvidenceReadyHandler({ activeCaseId, refetchEvidence, refetchParsers, toast, t }) {
  return (data) => {
    if (!data || String(data.caseId) !== String(activeCaseId)) return;
    refetchEvidence();
    refetchParsers();
    const count = data.rollup && typeof data.rollup === 'object'
      ? Object.values(data.rollup).reduce((a, b) => a + (Number(b) || 0), 0)
      : 0;
    toast.success(t('casedetail.evidence_ready', { count }), 6000);
  };
}
