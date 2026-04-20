// Evidence Bridge — pinned forensic rows shared between Super Timeline and Workbench.
// Keyed by caseId so switching cases swaps the visible set automatically.
// Client-only (localStorage). Server sync is a later phase.

import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { workbenchPinsAPI } from '../utils/api';

const MAX_PINS_PER_CASE = 500;

// Fire-and-forget server sync — errors are logged but don't block the UI.
// localStorage stays authoritative client-side so the app keeps working offline;
// on next `hydrateFromServer` the server merges in (server wins on conflict).
const syncCreate = (caseId, pin) => {
  workbenchPinsAPI.create(caseId, pin).catch(err => {
    if (err?.response?.status !== 409) console.warn('[bridge] sync create failed:', err?.message);
  });
};
const syncUpdate = (caseId, pinId, patch) => {
  workbenchPinsAPI.update(caseId, pinId, patch).catch(err => console.warn('[bridge] sync update failed:', err?.message));
};
const syncRemove = (caseId, pinId) => {
  workbenchPinsAPI.remove(caseId, pinId).catch(err => console.warn('[bridge] sync remove failed:', err?.message));
};
const syncClear = (caseId) => {
  workbenchPinsAPI.clear(caseId).catch(err => console.warn('[bridge] sync clear failed:', err?.message));
};

function normalize(row, caseId, userId) {
  const pin_id = (globalThis.crypto?.randomUUID?.() ?? `pin_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`);
  return {
    pin_id,
    pinned_at:     new Date().toISOString(),
    pinned_by:     userId || null,
    case_id:       String(caseId),
    collection_timeline_id: row.id ?? null,
    dedupe_hash:   row.dedupe_hash ?? null,
    timestamp:     row.timestamp ?? null,
    artifact_type: row.artifact_type ?? null,
    tool:          row.tool ?? null,
    source:        row.source ?? null,
    description:   (row.description ?? '').slice(0, 400),
    event_id:      row.event_id ?? null,
    host_name:     row.host_name ?? null,
    user_name:     row.user_name ?? null,
    mitre_technique_id: row.mitre_technique_id ?? null,
    tags:          Array.isArray(row.tags) ? [...row.tags] : [],
    note:          '',
    color:         null,
    status:        'triage',  // triage | confirmed | reported
  };
}

export const useEvidenceBridge = create(persist(
  (set, get) => ({
    pinned: {},

    pin: (caseId, row, userId) => {
      const cid = String(caseId);
      const list = get().pinned[cid] || [];
      if (list.length >= MAX_PINS_PER_CASE) return { ok: false, reason: 'max_pins' };
      if (row?.id != null && list.some(p => p.collection_timeline_id === row.id)) {
        return { ok: false, reason: 'already_pinned' };
      }
      const entry = normalize(row, cid, userId);
      set(s => ({ pinned: { ...s.pinned, [cid]: [...list, entry] } }));
      syncCreate(cid, entry);
      return { ok: true, pin_id: entry.pin_id };
    },

    pinMany: (caseId, rows, userId) => {
      const cid = String(caseId);
      const list = get().pinned[cid] || [];
      const have = new Set(list.map(p => p.collection_timeline_id).filter(v => v != null));
      const budget = MAX_PINS_PER_CASE - list.length;
      const fresh = rows
        .filter(r => r && (r.id == null || !have.has(r.id)))
        .slice(0, Math.max(0, budget))
        .map(r => normalize(r, cid, userId));
      set(s => ({ pinned: { ...s.pinned, [cid]: [...list, ...fresh] } }));
      fresh.forEach(p => syncCreate(cid, p));
      return { ok: true, added: fresh.length, dropped: rows.length - fresh.length };
    },

    unpin: (caseId, pinId) => {
      const cid = String(caseId);
      set(s => {
        const list = s.pinned[cid] || [];
        return { pinned: { ...s.pinned, [cid]: list.filter(p => p.pin_id !== pinId) } };
      });
      syncRemove(cid, pinId);
    },

    updatePin: (caseId, pinId, patch) => {
      const cid = String(caseId);
      set(s => {
        const list = s.pinned[cid] || [];
        return { pinned: { ...s.pinned, [cid]: list.map(p => p.pin_id === pinId ? { ...p, ...patch } : p) } };
      });
      const allowed = ['note', 'status', 'tags', 'color'];
      const serverPatch = {};
      for (const k of allowed) if (Object.prototype.hasOwnProperty.call(patch, k)) serverPatch[k] = patch[k];
      if (Object.keys(serverPatch).length) syncUpdate(cid, pinId, serverPatch);
    },

    clear: (caseId) => {
      const cid = String(caseId);
      set(s => ({ pinned: { ...s.pinned, [cid]: [] } }));
      syncClear(cid);
    },

    // Apply server-pushed events (from socket.io) WITHOUT re-emitting REST sync.
    applyServerPin: (caseId, pin) => set(s => {
      const cid = String(caseId);
      const list = s.pinned[cid] || [];
      if (list.some(p => p.pin_id === pin.pin_id)) return s;
      const normalized = { ...pin, tags: Array.isArray(pin.tags) ? pin.tags : [], note: pin.note ?? '', status: pin.status || 'triage' };
      return { pinned: { ...s.pinned, [cid]: [...list, normalized] } };
    }),
    applyServerUpdate: (caseId, pin) => set(s => {
      const cid = String(caseId);
      const list = s.pinned[cid] || [];
      return { pinned: { ...s.pinned, [cid]: list.map(p => p.pin_id === pin.pin_id ? { ...p, ...pin } : p) } };
    }),
    applyServerRemove: (caseId, pinId) => set(s => {
      const cid = String(caseId);
      const list = s.pinned[cid] || [];
      return { pinned: { ...s.pinned, [cid]: list.filter(p => p.pin_id !== pinId) } };
    }),
    applyServerClear: (caseId) => set(s => ({ pinned: { ...s.pinned, [String(caseId)]: [] } })),

    // Pull server state on case switch, merge into local cache (server wins on conflict).
    hydrateFromServer: async (caseId) => {
      const cid = String(caseId);
      try {
        const res = await workbenchPinsAPI.list(cid);
        const serverPins = (res?.data?.pins || res?.pins || []).map(p => ({
          ...p,
          tags: Array.isArray(p.tags) ? p.tags : [],
          note: p.note ?? '',
          status: p.status || 'triage',
        }));
        set(s => ({ pinned: { ...s.pinned, [cid]: serverPins } }));
        return { ok: true, count: serverPins.length };
      } catch (err) {
        return { ok: false, error: err?.message };
      }
    },

    isPinned: (caseId, rowId) => {
      if (rowId == null) return false;
      const list = get().pinned[String(caseId)] || [];
      return list.some(p => p.collection_timeline_id === rowId);
    },

    count: (caseId) => (get().pinned[String(caseId)] || []).length,
    list:  (caseId) => (get().pinned[String(caseId)] || []),
  }),
  {
    name: 'heimdall.evidenceBridge.v1',
    partialize: (s) => ({ pinned: s.pinned }),
  },
));

export const PIN_MAX_PER_CASE = MAX_PINS_PER_CASE;
