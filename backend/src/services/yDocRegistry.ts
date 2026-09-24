import * as Y from 'yjs';
import { Pool } from 'pg';
import logger from '../config/logger';

export interface DocMeta { auteur: string | null; distant: boolean; }

export interface DocStore {
  load(pool: Pool, id: string): Promise<Y.Doc>;
  save(pool: Pool, id: string, doc: Y.Doc, meta: DocMeta): Promise<void>;
}

interface Entry {
  doc: Y.Doc;
  subscribers: number;
  saveTimer: NodeJS.Timeout | null;
  dirty: boolean;
  meta: DocMeta;
}

export interface DocRegistry {
  getDoc(pool: Pool, id: string): Promise<Y.Doc>;
  acquireDoc(pool: Pool, id: string): Promise<Y.Doc>;
  releaseDoc(pool: Pool, id: string): Promise<void>;
  addSubscriber(id: string): void;
  encodeState(doc: Y.Doc): Buffer;
  applyRemoteUpdate(pool: Pool, id: string, update: Uint8Array, auteur?: string | null): void;
  edit(pool: Pool, id: string, auteur: string | null, change: (doc: Y.Doc) => void): Promise<Uint8Array>;
  flush(pool: Pool, id: string): Promise<void>;
  isLive(id: string): boolean;
  subscriberCount(id: string): number;
}

export function createDocRegistry(store: DocStore, { label, debounceMs = 2000 }: { label: string; debounceMs?: number }): DocRegistry {
  const registry = new Map<string, Entry>();
  const inflight = new Map<string, Promise<Entry>>();

  async function ensureEntry(pool: Pool, id: string): Promise<Entry> {
    const existing = registry.get(id);
    if (existing) return existing;
    let pending = inflight.get(id);
    if (!pending) {
      pending = (async () => {
        try {
          const doc = await store.load(pool, id);
          const entry: Entry = { doc, subscribers: 0, saveTimer: null, dirty: false, meta: { auteur: null, distant: false } };
          registry.set(id, entry);
          return entry;
        } finally {
          inflight.delete(id);
        }
      })();
      inflight.set(id, pending);
    }
    return pending;
  }

  async function flush(pool: Pool, id: string): Promise<void> {
    const entry = registry.get(id);
    if (!entry) return;
    if (entry.saveTimer) { clearTimeout(entry.saveTimer); entry.saveTimer = null; }
    if (!entry.dirty) return;
    entry.dirty = false;
    const meta = { ...entry.meta };
    entry.meta.distant = false;
    try {
      await store.save(pool, id, entry.doc, meta);
    } catch (err) {
      entry.dirty = true;
      entry.meta.distant = entry.meta.distant || meta.distant;
      throw err;
    }
  }

  function scheduleSave(pool: Pool, id: string): void {
    const entry = registry.get(id);
    if (!entry) return;
    if (entry.saveTimer) clearTimeout(entry.saveTimer);
    entry.saveTimer = setTimeout(() => {
      flush(pool, id).then(() => {
        const current = registry.get(id);
        if (current && current.subscribers === 0 && !current.dirty && !current.saveTimer) registry.delete(id);
      }).catch((err) => {
        logger.warn(`[${label}] persist failed`, { id, err: err?.message });
        scheduleSave(pool, id);
      });
    }, debounceMs);
    entry.saveTimer.unref?.();
  }

  function markDirty(pool: Pool, entry: Entry, id: string, auteur: string | null | undefined): void {
    entry.dirty = true;
    if (auteur) entry.meta.auteur = auteur;
    scheduleSave(pool, id);
  }

  return {
    async getDoc(pool, id) {
      return (await ensureEntry(pool, id)).doc;
    },
    async acquireDoc(pool, id) {
      const entry = await ensureEntry(pool, id);
      entry.subscribers += 1;
      return entry.doc;
    },
    async releaseDoc(pool, id) {
      const entry = registry.get(id);
      if (!entry) return;
      entry.subscribers = Math.max(0, entry.subscribers - 1);
      if (entry.subscribers > 0) return;
      try {
        await flush(pool, id);
      } catch (err: any) {
        logger.warn(`[${label}] persist on release failed, kept in memory`, { id, err: err?.message });
        scheduleSave(pool, id);
        return;
      }
      if (entry.subscribers === 0 && !entry.dirty) registry.delete(id);
    },
    addSubscriber(id) {
      const entry = registry.get(id);
      if (entry) entry.subscribers += 1;
    },
    encodeState(doc) {
      return Buffer.from(Y.encodeStateAsUpdate(doc));
    },
    applyRemoteUpdate(pool, id, update, auteur = null) {
      const entry = registry.get(id);
      if (!entry) return;
      Y.applyUpdate(entry.doc, update, 'remote');
      entry.meta.distant = true;
      markDirty(pool, entry, id, auteur);
    },
    async edit(pool, id, auteur, change) {
      const entry = await ensureEntry(pool, id);
      entry.subscribers += 1;
      try {
        const before = Y.encodeStateVector(entry.doc);
        let modifie = false;
        const surModification = () => { modifie = true; };
        entry.doc.on('update', surModification);
        try {
          entry.doc.transact(() => change(entry.doc), 'server');
        } finally {
          entry.doc.off('update', surModification);
        }
        if (!modifie) return new Uint8Array(0);
        const update = Y.encodeStateAsUpdate(entry.doc, before);
        markDirty(pool, entry, id, auteur);
        await flush(pool, id);
        return update;
      } finally {
        entry.subscribers = Math.max(0, entry.subscribers - 1);
        if (entry.subscribers === 0 && !entry.dirty && !entry.saveTimer) registry.delete(id);
      }
    },
    flush,
    isLive(id) {
      return registry.has(id);
    },
    subscriberCount(id) {
      return registry.get(id)?.subscribers ?? 0;
    },
  };
}
