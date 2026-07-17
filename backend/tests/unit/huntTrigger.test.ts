import { maybeTriggerHunt } from '../../src/workers/huntTrigger';

it('enqueues a hunt only when finalize emitted', async () => {
  const calls: any[] = [];
  const trig = async (_p: any, caseId: string, userId: string, t: string, ev: string) => { calls.push({ caseId, userId, t, ev }); return { started: true }; };
  await maybeTriggerHunt(true,  { pool: {} as any, caseId: 'c', userId: 'u', evidenceId: 'e', triggerHunt: trig });
  await maybeTriggerHunt(false, { pool: {} as any, caseId: 'c', userId: 'u', evidenceId: 'e', triggerHunt: trig });
  expect(calls).toEqual([{ caseId: 'c', userId: 'u', t: 'auto', ev: 'e' }]);
});
