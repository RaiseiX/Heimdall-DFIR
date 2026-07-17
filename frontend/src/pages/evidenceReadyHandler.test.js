import { describe, test, expect, vi } from 'vitest';
import { makeEvidenceReadyHandler } from './evidenceReadyHandler';

describe('makeEvidenceReadyHandler', () => {
  test('active-case event refetches evidence + parsers and toasts', () => {
    const refetchEvidence = vi.fn(), refetchParsers = vi.fn(), success = vi.fn();
    const h = makeEvidenceReadyHandler({ activeCaseId: '42', refetchEvidence, refetchParsers, toast: { success }, t: () => 'ok' });
    h({ evidenceId: 'e1', caseId: '42', rollup: { done: 2, error: 1 } });
    expect(refetchEvidence).toHaveBeenCalledTimes(1);
    expect(refetchParsers).toHaveBeenCalledTimes(1);
    expect(success).toHaveBeenCalledTimes(1);
  });
  test('event for a different case is ignored', () => {
    const refetchEvidence = vi.fn(), success = vi.fn();
    const h = makeEvidenceReadyHandler({ activeCaseId: '42', refetchEvidence, refetchParsers: vi.fn(), toast: { success }, t: () => 'ok' });
    h({ evidenceId: 'e2', caseId: '999' });
    expect(refetchEvidence).not.toHaveBeenCalled();
    expect(success).not.toHaveBeenCalled();
  });
  test('tolerates missing rollup', () => {
    const success = vi.fn();
    const h = makeEvidenceReadyHandler({ activeCaseId: '42', refetchEvidence: vi.fn(), refetchParsers: vi.fn(), toast: { success }, t: () => 'ok' });
    expect(() => h({ evidenceId: 'e3', caseId: '42' })).not.toThrow();
    expect(success).toHaveBeenCalledTimes(1);
  });
});
