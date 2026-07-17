import { it, expect, beforeEach, vi } from 'vitest';
vi.mock('../../../utils/api', () => ({
  dfiqAPI: {
    scenarios: vi.fn().mockResolvedValue({ data: [{ id: 's1', title: 'A', question_count: 2 }] }),
    caseInstances: vi.fn().mockResolvedValue({ data: [] }),
    attach: vi.fn().mockResolvedValue({ data: { id: 'inst1' } }),
    answers: vi.fn().mockResolvedValue({ data: [{ question_id: 'q1', status: 'todo', evidence: [] }] }),
    setAnswer: vi.fn().mockResolvedValue({ data: { status: 'answered' } }),
    addEvidence: vi.fn().mockResolvedValue({ data: { success: true } }),
  },
}));
import { dfiqAPI } from '../../../utils/api';
import { useDfiqStore } from './useDfiqStore';

beforeEach(() => { vi.clearAllMocks(); useDfiqStore.setState({ catalog: [], answers: [], caseInstances: [] }); });

it('loadCatalog populates catalog', async () => {
  await useDfiqStore.getState().loadCatalog();
  expect(useDfiqStore.getState().catalog).toHaveLength(1);
});
it('setAnswer sends status+note then reloads answers', async () => {
  await useDfiqStore.getState().setAnswer('c1', 'inst1', 'q1', { status: 'answered', note: 'x' });
  expect(dfiqAPI.setAnswer).toHaveBeenCalledWith('c1', 'inst1', 'q1', { status: 'answered', note: 'x' });
  expect(dfiqAPI.answers).toHaveBeenCalledWith('c1', 'inst1');
});
it('attach then reloads case instances', async () => {
  await useDfiqStore.getState().attach('c1', 's1');
  expect(dfiqAPI.attach).toHaveBeenCalledWith('c1', 's1');
  expect(dfiqAPI.caseInstances).toHaveBeenCalledWith('c1');
});
