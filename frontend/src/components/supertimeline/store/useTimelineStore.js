// frontend/src/components/supertimeline/store/useTimelineStore.js
import { create } from 'zustand';
import { collectionAPI, artifactsAPI, bookmarksAPI, savedSearchesAPI } from '../../../utils/api';
import { computeRef } from '../utils/timelineUtils';

const DEBOUNCE_MS = 150;
let _debounceTimer = null;
let _loadSeq = 0; // B8: stale request guard

const DEFAULT_GROUPS = [
  { key: 'artifact_type', label: 'Artifact Type' },
  { key: 'host_name',     label: 'Host' },
];

// The exact subset of filter state persisted in a saved search (server whitelists too).
const QUERY_KEYS = [
  'search', 'searchOp', 'startTime', 'endTime', 'artifactTypes',
  'hostFilter', 'hostFilterOp', 'userFilter', 'userFilterOp',
  'toolFilter', 'toolFilterOp', 'extFilter', 'extFilterOp',
  'eventIdFilter', 'tagFilter', 'hitsOnly', 'detSeverity', 'dedupe',
  'multiSort', 'groupByFields',
];

// Fresh default filter state (new array instances each call — never share mutable refs).
const filterDefaults = () => ({
  search: '', searchOp: 'contains', startTime: '', endTime: '',
  artifactTypes: [],
  hostFilter: '', hostFilterOp: 'contains',
  userFilter: '', userFilterOp: 'contains',
  toolFilter: '', toolFilterOp: 'contains',
  extFilter:  '', extFilterOp:  'contains',
  eventIdFilter: '', tagFilter: '',
  evidenceIds: [], resultId: '',
  hitsOnly: false, detSeverity: '', dedupe: false,
  sortCol: 'timestamp', sortDir: 'desc',
  multiSort: [{ col: 'timestamp', dir: 'desc' }],
  groupByFields: [], page: 1,
  appendMode: false,
});

// B2: encode confidence level as a _conf: tag prefix so it persists in the DB tags array
function encodeTagsWithLevel(tags, level) {
  const clean = (tags || []).filter(t => !t.startsWith('_conf:'));
  if (level) clean.push(`_conf:${level}`);
  return clean;
}
function decodeTagsAndLevel(rawTags) {
  const tags = [];
  let level = null;
  for (const t of (rawTags || [])) {
    if (t.startsWith('_conf:')) level = t.slice(6);
    else tags.push(t);
  }
  return { tags, level };
}

function buildQueryParams(s) {
  const p = { page: s.page, limit: s.pageSize, sort_dir: s.sortDir, sort_col: s.sortCol };
  if (s.multiSort.length > 1) p.sort_multi = s.multiSort.map(x => `${x.col}:${x.dir}`).join(',');
  if (s.search || s.searchOp === 'empty' || s.searchOp === 'not_empty')
    { p.search = s.search; p.search_op = s.searchOp; }
  if (s.artifactTypes.length)  p.artifact_types = s.artifactTypes.join(',');
  if (s.startTime)             p.start_time = new Date(s.startTime).toISOString();
  if (s.endTime)               p.end_time   = new Date(s.endTime).toISOString();
  if (s.hostFilter || s.hostFilterOp === 'empty' || s.hostFilterOp === 'not_empty')
    { p.host_name = s.hostFilter; p.host_name_op = s.hostFilterOp; }
  if (s.userFilter || s.userFilterOp === 'empty' || s.userFilterOp === 'not_empty')
    { p.user_name = s.userFilter; p.user_name_op = s.userFilterOp; }
  if (s.toolFilter || s.toolFilterOp === 'empty' || s.toolFilterOp === 'not_empty')
    { p.tool = s.toolFilter; p.tool_op = s.toolFilterOp; }
  if (s.eventIdFilter)         p.event_id   = s.eventIdFilter;
  if (s.extFilter || s.extFilterOp === 'empty' || s.extFilterOp === 'not_empty')
    { p.ext = s.extFilter; p.ext_op = s.extFilterOp; }
  if (s.tagFilter)             p.tag        = s.tagFilter;
  if (s.evidenceIds.length)    p.evidence_ids = s.evidenceIds.join(',');
  if (s.evidenceId)            p.evidence_id  = s.evidenceId;
  if (s.resultId)              p.result_id    = s.resultId;
  if (s.hitsOnly)              p.detections   = 'hits_only';
  if (s.detSeverity)           p.detection_severity = s.detSeverity;
  if (s.dedupe)                p.dedupe       = 'collapse';
  return p;
}

export const useTimelineStore = create((set, get) => ({
  // ── Filter state ──
  search: '', searchOp: 'contains',
  startTime: '', endTime: '',
  artifactTypes: [],
  hostFilter: '', hostFilterOp: 'contains',
  userFilter: '', userFilterOp: 'contains',
  toolFilter: '', toolFilterOp: 'contains',
  extFilter:  '', extFilterOp:  'contains',
  eventIdFilter: '', tagFilter: '',
  evidenceIds: [], evidenceId: null, resultId: '',
  hitsOnly: false, detSeverity: '', dedupe: false,

  // ── Sort ──
  sortCol: 'timestamp', sortDir: 'desc',
  multiSort: [{ col: 'timestamp', dir: 'desc' }],

  // ── Pagination / data ──
  page: 1, pageSize: (() => { try { return parseInt(localStorage.getItem('supertl.pageSize'), 10) || 500; } catch { return 500; } })(),
  total: 0, totalPages: 0,
  records: [], loading: false,
  appendMode: false,
  dynamicColsRev: 0,
  availTypes: [], typeCounts: {},
  hostsAvail: [], usersAvail: [],
  caseId: null,

  // ── Timeline context view state ──
  contextOpen: false, contextAnchorId: null, contextRows: [], contextHostName: null,
  contextAllHosts: false, contextN: 25, contextLoading: false,

  // ── UI state ──
  selectedRowId: null,
  tagData: new Map(),       // Map<row.id, { level: string|null, tags: string[] }>
  notedRefs: new Set(),     // C6: artifact_ref strings that have analyst notes
  bookmarks: [],
  savedSearches: [],
  detailTab: 'details',
  explorerOpen: (() => { try { return localStorage.getItem('supertl.explorerOpen') !== 'false'; } catch { return true; } })(),
  detailOpen: false,
  groupByFields: [],  // No group-by by default — events visible immediately (Timeline Explorer style)
  colorRules: [],

  // ── Actions ──
  setCaseId(caseId, evidenceId = null) {
    set({ caseId, evidenceId, page: 1, records: [], total: 0,
          selectedRowId: null, detailOpen: false, availTypes: [], typeCounts: {},
          tagData: new Map(), notedRefs: new Set(), bookmarks: [], savedSearches: [] });
    artifactsAPI.refsWithNotes(caseId)
      .then(res => set({ notedRefs: new Set(res.data?.refs || []) }))
      .catch(() => set({ notedRefs: new Set() }));
    bookmarksAPI.list(caseId)
      .then(res => {
        const raw = res.data || [];
        set({ bookmarks: raw.map(b => ({ ...b, ref: b.artifact_ref ?? b.ref })) });
      })
      .catch(() => set({ bookmarks: [] }));
    savedSearchesAPI.list(caseId)
      .then(res => set({ savedSearches: res.data || [] }))
      .catch(() => set({ savedSearches: [] }));
  },

  setColorRules(rules) { set({ colorRules: rules }); },

  setFilter(key, value) { set({ [key]: value, page: 1 }); },

  applyFilters() {
    set({ page: 1 });
    get().loadTimeline();
  },

  applyFiltersDebounced() {
    clearTimeout(_debounceTimer);
    _debounceTimer = setTimeout(() => get().applyFilters(), DEBOUNCE_MS);
  },

  clearFilters() {
    set(filterDefaults());
    get().loadTimeline();
  },

  async loadTimeline() {
    const s = get();
    if (!s.caseId) return;
    const seq = ++_loadSeq; // B8: stamp this request
    set({ loading: true });
    try {
      const res = await collectionAPI.timeline(s.caseId, buildQueryParams(s));
      if (seq !== _loadSeq) { set({ appendMode: false }); return; } // B8: discard stale response
      if (!res?.data) return;
      const recs = res.data.records || [];
      // Legacy records (fallback parser_results) have no id field — synthesize negative IDs.
      // Negative IDs never exist in the DB, so setTag will not call the API for them.
      if (recs.length > 0 && recs[0].id == null) {
        const base = get().appendMode ? get().records.length : 0;
        recs.forEach((r, i) => { if (r.id == null) r.id = -(base + i + 1); });
      }
      const newTagData = new Map(get().tagData);
      recs.forEach(r => {
        if (r.id == null) return;
        // B2: decode _conf: prefix from server tags to restore confidence level
        const { tags, level } = decodeTagsAndLevel(r.tags);
        const existing = newTagData.get(r.id);
        newTagData.set(r.id, {
          level: existing?.level ?? level,
          tags,
        });
      });
      set({
        records:     get().appendMode ? [...get().records, ...recs] : recs,
        appendMode:  false,
        total:       res.data.total         || 0,
        totalPages:  res.data.total_pages   || 0,
        // Only update the master list when no type filter is active — otherwise filtered
        // responses would remove pills for excluded types from the UI
        availTypes:  s.artifactTypes.length === 0
          ? (res.data.artifact_types_available || get().availTypes)
          : get().availTypes,
        typeCounts:  { ...get().typeCounts, ...(res.data.artifact_types_counts || {}) },
        hostsAvail:  res.data.hosts_available?.length  ? res.data.hosts_available  : get().hostsAvail,
        usersAvail:  res.data.users_available?.length  ? res.data.users_available  : get().usersAvail,
        tagData:     newTagData,
      });
    } catch { if (seq === _loadSeq) set({ records: [], total: 0, appendMode: false }); }
    finally  { if (seq === _loadSeq) set({ loading: false }); }
  },

  setSort(col, shiftKey = false) {
    const s = get();
    const SERVER_SORTABLE = new Set(['timestamp', 'artifact_type', 'description', 'source']);
    if (!SERVER_SORTABLE.has(col)) return;
    if (shiftKey && s.multiSort.length > 0) {
      const idx = s.multiSort.findIndex(x => x.col === col);
      const newMs = idx !== -1
        ? s.multiSort.map((x, i) => i === idx ? { col: x.col, dir: x.dir === 'desc' ? 'asc' : 'desc' } : x)
        : [...s.multiSort, { col, dir: 'desc' }].slice(0, 3);
      set({ multiSort: newMs, sortCol: newMs[0].col, sortDir: newMs[0].dir, page: 1 });
    } else {
      const newDir = (s.sortCol === col && s.sortDir === 'desc') ? 'asc' : 'desc';
      set({ sortCol: col, sortDir: newDir, multiSort: [{ col, dir: newDir }], page: 1 });
    }
    get().loadTimeline();
  },

  setPage(p) { set({ page: p }); get().loadTimeline(); },
  setPageSize(n) {
    try { localStorage.setItem('supertl.pageSize', String(n)); } catch {}
    set({ pageSize: n, page: 1 });
    get().loadTimeline();
  },

  loadMore() {
    const s = get();
    if (s.page >= s.totalPages || s.loading) return;
    set({ appendMode: true });
    get().setPage(s.page + 1);
  },

  bumpDynamicCols() { set(s => ({ dynamicColsRev: s.dynamicColsRev + 1 })); },

  setSelectedRow(id) {
    set({ selectedRowId: id, detailOpen: id != null });
  },

  async setTag(rowId, data) {
    const s = get();
    const rec  = s.records.find(r => r.id === rowId);
    const prev = s.tagData.get(rowId);
    const newTagData = new Map(s.tagData);
    newTagData.set(rowId, data);
    set({ tagData: newTagData });
    if (rec?.id != null && rec.id > 0 && s.caseId) {
      // B2: include level as _conf: prefix so it survives DB round-trip
      const tagsToSend = encodeTagsWithLevel(data.tags, data.level);
      try {
        const resp = await collectionAPI.updateTimelineTags(s.caseId, rec.id, tagsToSend);
        const persisted = resp?.data?.tags;
        if (Array.isArray(persisted)) {
          const { tags: decodedTags, level: decodedLevel } = decodeTagsAndLevel(persisted);
          const updated = new Map(get().tagData);
          updated.set(rowId, { tags: decodedTags, level: data.level ?? decodedLevel });
          set({ tagData: updated });
        }
      } catch {
        const rollback = new Map(get().tagData);
        rollback.set(rowId, prev || { level: null, tags: [] });
        set({ tagData: rollback });
      }
    }
  },

  toggleArtifactType(type) {
    const s = get();
    let next;
    if (s.artifactTypes.length === 1 && s.artifactTypes[0] === '__NONE__') {
      // "Nothing displayed" mode -> inclusion: add this type
      next = [type];
    } else if (s.artifactTypes.length === 0) {
      // Everything displayed -> exclusion: remove this type
      next = s.availTypes.filter(t => t !== type);
    } else if (s.artifactTypes.includes(type)) {
      // Included type -> remove it; if nothing remains -> fall back to __NONE__
      next = s.artifactTypes.filter(t => t !== type);
      if (next.length === 0) next = ['__NONE__'];
    } else {
      // Missing type -> add it
      next = [...s.artifactTypes, type];
    }
    // If all types are explicitly included -> reset to [] (= "All")
    const allBack = s.availTypes.length > 0 &&
                    s.availTypes.every(t => next.includes(t));
    set({ artifactTypes: allBack ? [] : next, page: 1 });
    get().loadTimeline();
  },

  soloArtifactType(type) {
    set({ artifactTypes: [type], page: 1 });
    get().loadTimeline();
  },

  clearArtifactTypes() {
    set({ artifactTypes: ['__NONE__'], page: 1 });
    get().loadTimeline();
  },

  setNotedRef(ref, hasNotes) {
    const next = new Set(get().notedRefs);
    hasNotes ? next.add(ref) : next.delete(ref);
    set({ notedRefs: next });
  },

  async loadBookmarks() {
    const { caseId } = get();
    if (!caseId) return;
    try {
      const res = await bookmarksAPI.list(caseId);
      const raw = res.data || [];
      set({ bookmarks: raw.map(b => ({ ...b, ref: b.artifact_ref ?? b.ref })) });
    } catch { set({ bookmarks: [] }); }
  },

  async toggleBookmark(record) {
    const { caseId, bookmarks } = get();
    if (!caseId) return;
    const ref      = computeRef(record);
    const existing = bookmarks.find(b => b.ref === ref);
    if (existing) {
      await bookmarksAPI.remove(caseId, existing.id);
    } else {
      await bookmarksAPI.create(caseId, {
        artifact_ref:    ref,
        title:           (record.description || '').slice(0, 80) || '—',
        event_timestamp: record.timestamp,
      });
    }
    get().loadBookmarks();
  },

  setDetailTab(tab) { set({ detailTab: tab }); },
  toggleExplorer() {
    const next = !get().explorerOpen;
    try { localStorage.setItem('supertl.explorerOpen', String(next)); } catch {}
    set({ explorerOpen: next });
  },
  closeDetail()     { set({ detailOpen: false, selectedRowId: null }); },
  openDetail(id)    { set({ selectedRowId: id, detailOpen: true }); },

  openContext(anchorId) {
    if (!(anchorId > 0)) return;               // real DB rows only
    set({ contextOpen: true, contextAnchorId: anchorId });
    get().loadContext();
  },
  async loadContext() {
    const { caseId, contextAnchorId, contextN, contextAllHosts } = get();
    if (!caseId || !(contextAnchorId > 0)) return;
    set({ contextLoading: true });
    try {
      const res = await collectionAPI.timelineContext(caseId, contextAnchorId, { n: contextN, allHosts: contextAllHosts });
      set({ contextRows: res.data?.rows || [], contextHostName: res.data?.host_name ?? null, contextLoading: false });
    } catch {
      set({ contextRows: [], contextLoading: false });
    }
  },
  setContextN(n)          { set({ contextN: n }); get().loadContext(); },
  toggleContextAllHosts() { set({ contextAllHosts: !get().contextAllHosts }); get().loadContext(); },
  reAnchorContext(id)     { if (id > 0) { set({ contextAnchorId: id }); get().loadContext(); } },
  closeContext()          { set({ contextOpen: false, contextRows: [], contextAnchorId: null }); },
  addGroupByField(f) {
    const s = get();
    if (!s.groupByFields.find(x => x.key === f.key)) set({ groupByFields: [...s.groupByFields, f] });
  },
  removeGroupByField(key) {
    set(s => ({ groupByFields: s.groupByFields.filter(f => f.key !== key) }));
  },
  setGroupByFields(fields) { set({ groupByFields: fields }); },

  async loadSavedSearches() {
    const { caseId } = get();
    if (!caseId) return;
    try {
      const res = await savedSearchesAPI.list(caseId);
      set({ savedSearches: res.data || [] });
    } catch { set({ savedSearches: [] }); }
  },

  captureCurrentQuery() {
    const s = get();
    const q = {};
    for (const k of QUERY_KEYS) q[k] = s[k];
    return q;
  },

  applySavedSearch(query) {
    const overlay = {};
    for (const k of QUERY_KEYS) if (query?.[k] !== undefined) overlay[k] = query[k];
    // multiSort drives sort_col/sort_dir in buildQueryParams — keep the scalars in sync.
    const ms = Array.isArray(overlay.multiSort) && overlay.multiSort.length ? overlay.multiSort[0] : null;
    const derivedSort = ms ? { sortCol: ms.col, sortDir: ms.dir } : {};
    set({ ...filterDefaults(), ...overlay, ...derivedSort, page: 1 });
    get().loadTimeline();
  },

  async saveCurrentSearch(name, scope = 'personal') {
    const { caseId } = get();
    if (!caseId) return null;
    const query = get().captureCurrentQuery();
    const res = await savedSearchesAPI.create(caseId, { name, scope, query });
    set({ savedSearches: [...get().savedSearches, res.data] });
    return res.data;
  },

  async updateSavedSearch(id, patch) {
    const { caseId, savedSearches } = get();
    const prev = savedSearches;
    set({ savedSearches: savedSearches.map(s => (s.id === id ? { ...s, ...patch } : s)) }); // optimistic
    try {
      const res = await savedSearchesAPI.update(caseId, id, patch);
      set({ savedSearches: get().savedSearches.map(s => (s.id === id ? res.data : s)) });
    } catch (e) {
      set({ savedSearches: prev }); // rollback
      throw e;
    }
  },

  promoteSavedSearch(id) { return get().updateSavedSearch(id, { scope: 'case' }); },

  async deleteSavedSearch(id) {
    const { caseId, savedSearches } = get();
    const prev = savedSearches;
    set({ savedSearches: savedSearches.filter(s => s.id !== id) }); // optimistic
    try {
      await savedSearchesAPI.remove(caseId, id);
    } catch (e) {
      set({ savedSearches: prev }); // rollback
      throw e;
    }
  },
}));
