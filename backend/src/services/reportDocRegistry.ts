import * as Y from 'yjs';
import { Pool } from 'pg';
import { loadDraft, saveDraft } from './reportDraftStore';
import { createDocRegistry } from './yDocRegistry';

export const SECTIONS = [
  'executive_summary', 'key_findings', 'ioc_analysis',
  'mitre_analysis', 'timeline_narrative', 'recommendations',
];

export const NOTE_ANALYSTE = 'analyst_note';

const registre = createDocRegistry({
  async load(pool: Pool, caseId: string) {
    const doc = new Y.Doc();
    const persisted = await loadDraft(pool, caseId);
    if (persisted) Y.applyUpdate(doc, new Uint8Array(persisted), 'db');
    return doc;
  },
  async save(pool: Pool, caseId: string, doc: Y.Doc) {
    const snap: Record<string, string> = {};
    for (const k of [...SECTIONS, NOTE_ANALYSTE]) snap[k] = doc.getText(k).toString();
    await saveDraft(pool, caseId, Buffer.from(Y.encodeStateAsUpdate(doc)), snap);
  },
}, { label: 'reportDraft' });

export const getDoc = registre.getDoc;
export const acquireDoc = registre.acquireDoc;
export const releaseDoc = registre.releaseDoc;
export const addSubscriber = registre.addSubscriber;
export const encodeState = registre.encodeState;
export const applyRemoteUpdate = registre.applyRemoteUpdate;
export const flush = registre.flush;
export const subscriberCount = registre.subscriberCount;
