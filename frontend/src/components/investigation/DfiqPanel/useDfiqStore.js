// frontend/src/components/investigation/DfiqPanel/useDfiqStore.js
import { create } from 'zustand';
import { dfiqAPI } from '../../../utils/api';

export const useDfiqStore = create((set, get) => ({
  catalog: [], scenario: null, caseInstances: [], answers: [], loading: false,

  async loadCatalog() {
    set({ loading: true });
    try { const r = await dfiqAPI.scenarios(); set({ catalog: r.data || [], loading: false }); }
    catch { set({ catalog: [], loading: false }); }
  },
  async loadScenario(id) {
    try { const r = await dfiqAPI.scenario(id); set({ scenario: r.data }); } catch { set({ scenario: null }); }
  },
  async loadCaseInstances(caseId) {
    try { const r = await dfiqAPI.caseInstances(caseId); set({ caseInstances: r.data || [] }); } catch { set({ caseInstances: [] }); }
  },
  async attach(caseId, scenarioId) {
    await dfiqAPI.attach(caseId, scenarioId).catch(() => {});
    await get().loadCaseInstances(caseId);
  },
  async detach(caseId, instanceId) {
    await dfiqAPI.detach(caseId, instanceId).catch(() => {});
    await get().loadCaseInstances(caseId);
  },
  async loadAnswers(caseId, instanceId) {
    try { const r = await dfiqAPI.answers(caseId, instanceId); set({ answers: r.data || [] }); } catch { set({ answers: [] }); }
  },
  async setAnswer(caseId, instanceId, questionId, data) {
    await dfiqAPI.setAnswer(caseId, instanceId, questionId, data).catch(() => {});
    await get().loadAnswers(caseId, instanceId);
  },
  async addEvidence(caseId, instanceId, questionId, bookmarkId) {
    await dfiqAPI.addEvidence(caseId, instanceId, questionId, bookmarkId).catch(() => {});
    await get().loadAnswers(caseId, instanceId);
  },
  async removeEvidence(caseId, instanceId, questionId, bookmarkId) {
    await dfiqAPI.removeEvidence(caseId, instanceId, questionId, bookmarkId).catch(() => {});
    await get().loadAnswers(caseId, instanceId);
  },
}));
