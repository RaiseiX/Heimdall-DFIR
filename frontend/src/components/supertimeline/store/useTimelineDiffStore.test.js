import { it, expect, beforeEach, vi } from 'vitest';
vi.mock('../../../utils/api', () => ({
  collectionAPI: { timelineDiff: vi.fn() },
}));
import { collectionAPI } from '../../../utils/api';
import { useTimelineDiffStore } from './useTimelineDiffStore';

beforeEach(() => {
  vi.clearAllMocks();
  useTimelineDiffStore.setState({ caseId: 'c-1', sideA: {}, sideB: {}, counts: null, added: [], removed: [], loading: false });
});

it('setSide patches one side', () => {
  useTimelineDiffStore.getState().setSide('A', { evidenceId: 'ev-1' });
  expect(useTimelineDiffStore.getState().sideA).toEqual({ evidenceId: 'ev-1' });
});

it('runDiff populates counts + rows from the response', async () => {
  collectionAPI.timelineDiff.mockResolvedValueOnce({ data: { counts: { added: 2, removed: 1, unchanged: 3 }, added: [{ id: 1 }, { id: 2 }], removed: [{ id: 9 }] } });
  useTimelineDiffStore.setState({ sideA: { evidenceId: 'a' }, sideB: { evidenceId: 'b' } });
  await useTimelineDiffStore.getState().runDiff();
  expect(collectionAPI.timelineDiff).toHaveBeenCalledWith('c-1', { evidenceId: 'a' }, { evidenceId: 'b' }, { limit: 500 });
  expect(useTimelineDiffStore.getState().counts.added).toBe(2);
  expect(useTimelineDiffStore.getState().added).toHaveLength(2);
});

it('runDiff falls back to empty on API failure', async () => {
  collectionAPI.timelineDiff.mockRejectedValueOnce(new Error('boom'));
  useTimelineDiffStore.setState({ sideA: { evidenceId: 'a' }, sideB: { evidenceId: 'b' }, added: [{ id: 1 }] });
  await useTimelineDiffStore.getState().runDiff();
  expect(useTimelineDiffStore.getState().added).toEqual([]);
  expect(useTimelineDiffStore.getState().counts).toBe(null);
});

it('reset clears results', () => {
  useTimelineDiffStore.setState({ counts: { added: 1 }, added: [{ id: 1 }] });
  useTimelineDiffStore.getState().reset();
  expect(useTimelineDiffStore.getState().counts).toBe(null);
  expect(useTimelineDiffStore.getState().added).toEqual([]);
});
