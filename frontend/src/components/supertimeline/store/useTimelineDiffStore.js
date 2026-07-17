import { create } from 'zustand';
import { collectionAPI } from '../../../utils/api';

export const useTimelineDiffStore = create((set, get) => ({
  caseId: null, sideA: {}, sideB: {}, counts: null, added: [], removed: [], loading: false,

  setSide(which, patch) {
    set(which === 'A' ? { sideA: { ...get().sideA, ...patch } } : { sideB: { ...get().sideB, ...patch } });
  },
  async runDiff() {
    const { caseId, sideA, sideB } = get();
    const has = (s) => Boolean(s.evidenceId) || Boolean(s.hostName);
    if (!caseId || !has(sideA) || !has(sideB)) return;
    set({ loading: true });
    try {
      const res = await collectionAPI.timelineDiff(caseId, sideA, sideB, { limit: 500 });
      const d = res.data || {};
      set({ counts: d.counts || null, added: d.added || [], removed: d.removed || [], loading: false });
    } catch {
      set({ counts: null, added: [], removed: [], loading: false });
    }
  },
  reset() { set({ counts: null, added: [], removed: [] }); },
}));
