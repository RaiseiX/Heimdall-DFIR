import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('../../../utils/api', () => ({
  collectionAPI:   { timeline: vi.fn().mockResolvedValue({ data: { records: [] } }) },
  artifactsAPI:    { refsWithNotes: vi.fn().mockResolvedValue({ data: { refs: [] } }) },
  bookmarksAPI:    { list: vi.fn().mockResolvedValue({ data: [] }) },
  savedSearchesAPI: {
    list:   vi.fn().mockResolvedValue({ data: [] }),
    create: vi.fn(),
    update: vi.fn(),
    remove: vi.fn(),
  },
}));

import { savedSearchesAPI } from '../../../utils/api';
import { useTimelineStore } from './useTimelineStore';

beforeEach(() => {
  vi.clearAllMocks();
  useTimelineStore.setState({ caseId: 'c-1', savedSearches: [], loadTimeline: vi.fn() });
});

describe('captureCurrentQuery', () => {
  it('returns only whitelisted keys', () => {
    useTimelineStore.setState({
      search: 'psexec', hostFilter: 'DC01',
      evidenceId: 'ev-1', resultId: 'r1', page: 5, pageSize: 500,
    });
    const q = useTimelineStore.getState().captureCurrentQuery();
    expect(q.search).toBe('psexec');
    expect(q.hostFilter).toBe('DC01');
    expect(q).toHaveProperty('multiSort');
    expect(q).toHaveProperty('groupByFields');
    expect(q).not.toHaveProperty('evidenceId');
    expect(q).not.toHaveProperty('resultId');
    expect(q).not.toHaveProperty('page');
    expect(q).not.toHaveProperty('pageSize');
    expect(Object.keys(q)).toHaveLength(20);
  });
});

describe('applySavedSearch', () => {
  it('resets residual filters, overlays the blob, derives sort, loads once', () => {
    useTimelineStore.setState({ hostFilter: 'GHOST', userFilter: 'admin' });
    const loadSpy = useTimelineStore.getState().loadTimeline;
    useTimelineStore.getState().applySavedSearch({
      search: 'psexec',
      multiSort: [{ col: 'artifact_type', dir: 'asc' }],
    });
    const s = useTimelineStore.getState();
    expect(s.search).toBe('psexec');
    expect(s.hostFilter).toBe('');   // residual cleared by reset
    expect(s.userFilter).toBe('');   // residual cleared by reset
    expect(s.sortCol).toBe('artifact_type'); // derived from multiSort[0]
    expect(s.sortDir).toBe('asc');
    expect(loadSpy).toHaveBeenCalledTimes(1);
  });
});

describe('CRUD optimism + rollback', () => {
  it('saveCurrentSearch appends the created row', async () => {
    savedSearchesAPI.create.mockResolvedValueOnce({ data: { id: 's1', name: 'X', scope: 'personal' } });
    await useTimelineStore.getState().saveCurrentSearch('X', 'personal');
    expect(useTimelineStore.getState().savedSearches).toHaveLength(1);
    expect(useTimelineStore.getState().savedSearches[0].id).toBe('s1');
  });

  it('updateSavedSearch rolls back on API failure', async () => {
    savedSearchesAPI.update.mockRejectedValueOnce(new Error('boom'));
    useTimelineStore.setState({ savedSearches: [{ id: 's1', name: 'X', scope: 'personal' }] });
    await expect(useTimelineStore.getState().updateSavedSearch('s1', { scope: 'case' })).rejects.toThrow();
    expect(useTimelineStore.getState().savedSearches[0].scope).toBe('personal'); // rolled back
  });

  it('deleteSavedSearch rolls back on API failure', async () => {
    savedSearchesAPI.remove.mockRejectedValueOnce(new Error('boom'));
    useTimelineStore.setState({ savedSearches: [{ id: 's1', name: 'X' }] });
    await expect(useTimelineStore.getState().deleteSavedSearch('s1')).rejects.toThrow();
    expect(useTimelineStore.getState().savedSearches).toHaveLength(1); // rolled back
  });
});
