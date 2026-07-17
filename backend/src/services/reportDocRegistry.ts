import * as Y from 'yjs';
import { Pool } from 'pg';
import { loadDraft, saveDraft } from './reportDraftStore';
import logger from '../config/logger';

export const SECTIONS = [
  'executive_summary', 'key_findings', 'ioc_analysis',
  'mitre_analysis', 'timeline_narrative', 'recommendations',
];
const SAVE_DEBOUNCE_MS = 2000;

interface Entry { doc: Y.Doc; subscribers: number; saveTimer: NodeJS.Timeout | null; }
const registry = new Map<string, Entry>();
const inflight = new Map<string, Promise<Entry>>();

async function ensureEntry(pool: Pool, caseId: string): Promise<Entry> {
  const existing = registry.get(caseId);
  if (existing) return existing;
  let p = inflight.get(caseId);
  if (!p) {
    p = (async () => {
      const doc = new Y.Doc();
      const persisted = await loadDraft(pool, caseId);
      if (persisted) Y.applyUpdate(doc, new Uint8Array(persisted), 'db');
      const entry: Entry = { doc, subscribers: 0, saveTimer: null };
      registry.set(caseId, entry);
      inflight.delete(caseId);
      return entry;
    })();
    inflight.set(caseId, p);
  }
  return p;
}

export async function getDoc(pool: Pool, caseId: string): Promise<Y.Doc> {
  return (await ensureEntry(pool, caseId)).doc;
}

// Atomic get-or-create + subscribe: increments the subscriber count synchronously
// after the entry is guaranteed in the registry, so there is no evict gap.
export async function acquireDoc(pool: Pool, caseId: string): Promise<Y.Doc> {
  const entry = await ensureEntry(pool, caseId);
  entry.subscribers += 1;
  return entry.doc;
}

export function addSubscriber(caseId: string): void {
  const e = registry.get(caseId);
  if (e) e.subscribers += 1;
}

export function encodeState(doc: Y.Doc): Buffer {
  return Buffer.from(Y.encodeStateAsUpdate(doc));
}

export function applyRemoteUpdate(pool: Pool, caseId: string, update: Uint8Array): void {
  const e = registry.get(caseId);
  if (!e) return;
  Y.applyUpdate(e.doc, update, 'remote');
  scheduleSave(pool, caseId);
}

function scheduleSave(pool: Pool, caseId: string): void {
  const e = registry.get(caseId);
  if (!e) return;
  if (e.saveTimer) clearTimeout(e.saveTimer);
  e.saveTimer = setTimeout(() => { flush(pool, caseId).catch(() => {}); }, SAVE_DEBOUNCE_MS);
  e.saveTimer.unref?.();
}

export async function flush(pool: Pool, caseId: string): Promise<void> {
  const e = registry.get(caseId);
  if (!e) return;
  if (e.saveTimer) { clearTimeout(e.saveTimer); e.saveTimer = null; }
  const buf = encodeState(e.doc);
  const snap: Record<string, string> = {};
  for (const k of SECTIONS) snap[k] = e.doc.getText(k).toString();
  await saveDraft(pool, caseId, buf, snap).catch((e) =>
    logger.warn('[reportDraft] persist failed', { caseId, err: e?.message }));
}

export function subscriberCount(caseId: string): number {
  return registry.get(caseId)?.subscribers ?? 0;
}

export async function releaseDoc(pool: Pool, caseId: string): Promise<void> {
  const e = registry.get(caseId);
  if (!e) return;
  e.subscribers = Math.max(0, e.subscribers - 1);
  if (e.subscribers === 0) {
    await flush(pool, caseId);
    registry.delete(caseId);
  }
}
