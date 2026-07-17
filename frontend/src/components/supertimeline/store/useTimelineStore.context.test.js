import { it, expect, beforeEach, vi } from 'vitest';

vi.mock('../../../utils/api', () => ({
  collectionAPI:   { timeline: vi.fn().mockResolvedValue({ data: { records: [] } }), timelineContext: vi.fn() },
  artifactsAPI:    { refsWithNotes: vi.fn().mockResolvedValue({ data: { refs: [] } }) },
  bookmarksAPI:    { list: vi.fn().mockResolvedValue({ data: [] }) },
  savedSearchesAPI:{ list: vi.fn().mockResolvedValue({ data: [] }), create: vi.fn(), update: vi.fn(), remove: vi.fn() },
}));

import { collectionAPI } from '../../../utils/api';
import { useTimelineStore } from './useTimelineStore';

beforeEach(() => {
  vi.clearAllMocks();
  useTimelineStore.setState({ caseId: 'c-1', contextRows: [], contextAnchorId: null, contextN: 25, contextAllHosts: false, contextOpen: false });
});

it('loadContext populates contextRows + host', async () => {
  collectionAPI.timelineContext.mockResolvedValueOnce({ data: { rows: [{ id: 1 }, { id: 2, is_anchor: true }], host_name: 'DC01' } });
  useTimelineStore.setState({ contextAnchorId: 2 });
  await useTimelineStore.getState().loadContext();
  expect(useTimelineStore.getState().contextRows).toHaveLength(2);
  expect(useTimelineStore.getState().contextHostName).toBe('DC01');
});

it('openContext ignores non-real anchors (id <= 0)', () => {
  useTimelineStore.getState().openContext(-5);
  expect(collectionAPI.timelineContext).not.toHaveBeenCalled();
  expect(useTimelineStore.getState().contextOpen).toBe(false);
});

it('setContextN reloads with the new n', async () => {
  collectionAPI.timelineContext.mockResolvedValue({ data: { rows: [], host_name: null } });
  useTimelineStore.setState({ contextAnchorId: 2 });
  useTimelineStore.getState().setContextN(50);
  expect(useTimelineStore.getState().contextN).toBe(50);
  await Promise.resolve(); await Promise.resolve();
  expect(collectionAPI.timelineContext).toHaveBeenCalledWith('c-1', 2, { n: 50, allHosts: false });
});

it('toggleContextAllHosts flips + reloads', async () => {
  collectionAPI.timelineContext.mockResolvedValue({ data: { rows: [], host_name: null } });
  useTimelineStore.setState({ contextAnchorId: 2 });
  useTimelineStore.getState().toggleContextAllHosts();
  expect(useTimelineStore.getState().contextAllHosts).toBe(true);
  await Promise.resolve(); await Promise.resolve();
  expect(collectionAPI.timelineContext).toHaveBeenCalledWith('c-1', 2, { n: 25, allHosts: true });
});

it('loadContext falls back to empty on API failure', async () => {
  collectionAPI.timelineContext.mockRejectedValueOnce(new Error('boom'));
  useTimelineStore.setState({ contextAnchorId: 2, contextRows: [{ id: 9 }] });
  await useTimelineStore.getState().loadContext();
  expect(useTimelineStore.getState().contextRows).toEqual([]);
});
