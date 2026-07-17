import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' }
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('heimdall_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

let _refreshing = null;

const _forceLogout = () => {
  localStorage.removeItem('heimdall_token');
  localStorage.removeItem('heimdall_refresh_token');
  localStorage.removeItem('heimdall_user');
  if (!window.location.pathname.startsWith('/login')) {
    window.location.href = '/login';
  }
};

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const orig = error.config;
    // Skip interceptor for auth/refresh calls to prevent recursive refresh loops
    if (orig?.url?.includes('/auth/refresh') || orig?.url?.includes('/auth/logout')) {
      if (error.response?.status === 401) _forceLogout();
      return Promise.reject(error);
    }
    if (error.response?.status === 401 && !orig._retry) {
      orig._retry = true;
      const refreshToken = localStorage.getItem('heimdall_refresh_token');
      if (refreshToken) {
        try {
          if (!_refreshing) {
            _refreshing = api.post('/auth/refresh', { refreshToken }).finally(() => { _refreshing = null; });
          }
          const { data } = await _refreshing;
          localStorage.setItem('heimdall_token', data.token);
          if (data.refreshToken) localStorage.setItem('heimdall_refresh_token', data.refreshToken);
          orig.headers.Authorization = `Bearer ${data.token}`;
          return api(orig);
        } catch {
          _forceLogout();
          return Promise.reject(error);
        }
      }
      _forceLogout();
    }
    return Promise.reject(error);
  }
);

export default api;

export const authAPI = {
  login:   (data)         => api.post('/auth/login', data),
  me:      ()             => api.get('/auth/me'),
  register:(data)         => api.post('/auth/register', data),
  refresh: (refreshToken) => api.post('/auth/refresh', { refreshToken }),
  logout:  (refreshToken) => api.post('/auth/logout', { refreshToken }),
};

export const adminAPI = {
  health:           ()           => api.get('/admin/health'),
  listBackups:      ()           => api.get('/admin/backups'),
  triggerBackup:    ()           => api.post('/admin/backups/trigger'),
  downloadBackup:   (filename)   => `/api/admin/backups/${encodeURIComponent(filename)}`,
  getSchedule:      ()           => api.get('/admin/backups/schedule'),
  setSchedule:      (cron)       => api.post('/admin/backups/schedule', { cron }),
  deleteSchedule:   ()           => api.delete('/admin/backups/schedule'),
  dockerContainers: ()           => api.get('/admin/docker/containers'),
  jobs:             (params)     => api.get('/admin/jobs', { params }),
  accessLogs:       (params)     => api.get('/admin/access-logs', { params }),
  serverLogs:       (params)     => api.get('/admin/logs', { params }),
};

export const casesAPI = {
  list: (params) => api.get('/cases', { params }),
  get: (id) => api.get(`/cases/${id}`),
  create: (data) => api.post('/cases', data),
  update: (id, data) => api.put(`/cases/${id}`, data),
  stats: () => api.get('/cases/stats/dashboard'),
  assignableUsers: () => api.get('/cases/assignable-users'),
  assignees: (id) => api.get(`/cases/${id}/assignees`),
  assignUser: (id, userId) => api.post(`/cases/${id}/assignees`, { user_id: userId }),
  unassignUser: (id, userId) => api.delete(`/cases/${id}/assignees/${userId}`),
  audit: (id, params) => api.get(`/cases/${id}/audit`, { params }),
  hardDelete: (id) => api.delete(`/cases/${id}/hard-delete`),
  runTriage: (id) => api.post(`/cases/${id}/triage`),
  getTriage: (id) => api.get(`/cases/${id}/triage`),
  lateralMovement: (id) => api.get(`/cases/${id}/lateral-movement`),
  deadlines:   () => api.get('/cases/deadlines'),
  leaderboard: () => api.get('/cases/leaderboard'),
  exportAnonymized: (id) => api.get(`/cases/${id}/export/anonymized`, { responseType: 'blob' }),
  riskScore: (id) => api.get(`/cases/${id}/risk-score`),
  timeStats: (id) => api.get(`/cases/${id}/time`),
};

export const attributionAPI = {
  getCaseAttribution: (caseId) => api.get(`/attribution/${caseId}`),
};

export const detectionsAPI = {
  timestomping:    (id, params) => api.get(`/cases/${id}/detections/timestomping`,    { params }),
  doubleExt:       (id)         => api.get(`/cases/${id}/detections/double-ext`),
  beaconing:       (id, params) => api.get(`/cases/${id}/detections/beaconing`,       { params }),
  persistence:     (id)         => api.get(`/cases/${id}/detections/persistence`),
  sysmonBehavior:  (id)         => api.get(`/cases/${id}/detections/sysmon-behavior`),
  antiForensic:    (id)         => api.get(`/cases/${id}/detections/anti-forensic`),
  executionAnomaly:(id)         => api.get(`/cases/${id}/detections/execution-anomaly`),
  attackTechniques:(id)         => api.get(`/cases/${id}/detections/attack-techniques`),
  vulnDrivers:     (id)         => api.get(`/cases/${id}/detections/vuln-drivers`, { timeout: 120_000 }),
  exceptions:      (id)         => api.get(`/cases/${id}/detections/exceptions`),
  addException:    (id, data)   => api.post(`/cases/${id}/detections/exceptions`, data),
  deleteException: (id, exId)   => api.delete(`/cases/${id}/detections/exceptions/${exId}`),
};

export const evidenceAPI = {
  list: (caseId) => api.get(`/evidence/${caseId}`),
  upload: (caseId, formData, onUploadProgress) => api.post(`/evidence/${caseId}/upload`, formData, { headers: { 'Content-Type': 'multipart/form-data' }, onUploadProgress }),
  highlight: (id) => api.put(`/evidence/${id}/highlight`),
  delete: (id) => api.delete(`/evidence/${id}`),
  hex: (id, offset, length) => api.get(`/evidence/${id}/hex`, { params: { offset, length } }),
  strings: (id, minLength) => api.get(`/evidence/${id}/strings`, { params: { min_length: minLength } }),
  comments: (id) => api.get(`/evidence/${id}/comments`),
  addComment: (id, content) => api.post(`/evidence/${id}/comments`, { content }),
  integrityCheck: (id) => api.get(`/evidence/${id}/integrity`),
};

export const timelineAPI = {
  list: (caseId, params) => api.get(`/timeline/${caseId}`, { params }),
  create: (caseId, data) => api.post(`/timeline/${caseId}`, data),
};

export const iocsAPI = {
  list: (caseId, params) => api.get(`/iocs/${caseId}`, { params }),
  create: (caseId, data) => api.post(`/iocs/${caseId}`, data),
  searchGlobal: (q, type) => api.get('/iocs/search/global', { params: { q, type } }),
  enrich: (id) => api.post(`/iocs/${id}/enrich`),
  enrichCase: (caseId) => api.post(`/iocs/enrich-case/${caseId}`),
  exportStix: (caseId) => api.get(`/iocs/export-stix/${caseId}`, { responseType: 'blob' }),
  crossCase: (value) => api.get('/iocs/cross-case', { params: { value } }),
  crossCases: (value) => api.get(`/iocs/${encodeURIComponent(value)}/cross-cases`),
  topShared: () => api.get('/iocs/top-shared'),
  confirmIOC: (id, data) => api.post(`/iocs/${id}/confirm`, data),
  remove: (id) => api.delete(`/iocs/${id}`),
  internalIntel: (params) => api.get('/iocs/internal-intel', { params }),
  importStix: (caseId, bundles) => api.post(`/iocs/${caseId}/import-stix`, { bundles }),

  quickEnrich: (value, type) => api.get('/iocs/quick-enrich', { params: { value, type } }),
};

export const networkAPI = {
  list: (caseId, params) => api.get(`/network/${caseId}`, { params }),
  create: (caseId, data) => api.post(`/network/${caseId}`, data),
  stats: (caseId) => api.get(`/network/${caseId}/stats`),
  graph: (caseId, evidenceId) => api.get(`/network/${caseId}/graph`, evidenceId ? { params: { evidence_id: evidenceId } } : {}),
  graphData: (caseId, params) => api.get(`/network/${caseId}/graph-data`, { params }),
  nodeEvents: (caseId, nodeId, params) => api.get(`/network/${caseId}/graph-data/events`, { params: { node_id: nodeId, ...params } }),
  importCsv: (caseId, file) => {
    const form = new FormData();
    form.append('file', file);
    return api.post(`/network/${caseId}/import-csv`, form, { headers: { 'Content-Type': 'multipart/form-data' } });
  },
  dgaAnalysis:     (caseId)        => api.get(`/network/${caseId}/dga-analysis`),
  beacons:         (caseId, params) => api.get(`/network/${caseId}/beacons`, { params }),
  analytics:       (caseId)         => api.get(`/network/${caseId}/analytics`),
  getAnnotations:        (caseId)       => api.get(`/network/${caseId}/annotations`),
  saveAnnotations:       (caseId, data) => api.put(`/network/${caseId}/annotations`, data),
  saveGlobalAnnotations: (caseId, data) => api.put(`/network/${caseId}/annotations/global`, data),
  globalGraph:           (caseId)       => api.get(`/network/${caseId}/global-graph`),
};

export const parsersAPI = {
  available: () => api.get('/parsers/available'),
  run: (data) => api.post('/parsers/run', data),
  results: (caseId) => api.get(`/parsers/results/${caseId}`),
  resultData: (resultId, params) => api.get(`/parsers/result/${resultId}/data`, { params }),
  resultTypes: (resultId) => api.get(`/parsers/result/${resultId}/types`),
  deleteResult: (resultId) => api.delete(`/parsers/results/${resultId}`),
  exportResultCsv: (resultId) => api.get(`/parsers/result/${resultId}/export/csv`, { responseType: 'blob' }),
  // Honest per-status rollup (all 11 ingestion_files states) for one evidence.
  status: (caseId, evidenceId) => api.get(`/parsers/status/${caseId}/${evidenceId}`),
};

export const reportsAPI = {
  // opts: { templateId } | { sections: string[], notes: string, ... }. A bare string is treated as templateId (back-compat).
  generate: (caseId, opts = {}) => api.post(`/reports/${caseId}/generate`, typeof opts === 'string' ? { templateId: opts } : (opts || {})),
  aiDraft: (caseId, opts = {}) => api.post(`/reports/${caseId}/ai-draft`, opts || {}),
  list: (caseId) => api.get(`/reports/${caseId}`),
  download: (id) => api.get(`/reports/download/${id}`, { responseType: 'blob' }),

  listTemplates: () => api.get('/reports/templates'),
  createTemplate: (data) => api.post('/reports/templates', data),
  updateTemplate: (id, data) => api.put(`/reports/templates/${id}`, data),
  deleteTemplate: (id) => api.delete(`/reports/templates/${id}`),
  bookmarkNarrative: (caseId) => api.post(`/reports/${caseId}/bookmark-narrative`),
};

export const notebookAPI = {
  get:  (caseId)          => api.get(`/notebook/${caseId}`),
  save: (caseId, content) => api.put(`/notebook/${caseId}`, { content }),
};

export const usersAPI = {
  list: () => api.get('/users'),
  me: () => api.get('/users/me'),
  update: (id, data) => api.put(`/users/${id}`, data),
  delete: (id) => api.delete(`/users/${id}`),
  changePassword: (id, password) => api.put(`/users/${id}/password`, { password }),
  audit: (params) => api.get('/users/audit', { params }),
  updatePreferences: (prefs) => api.patch('/users/me/preferences', prefs),
  tokens:      ()     => api.get('/users/me/tokens'),
  createToken: (name) => api.post('/users/me/tokens', { name }),
  revokeToken: (id)   => api.delete(`/users/me/tokens/${id}`),
  sessions:    ()     => api.get('/users/me/sessions'),
  revokeAllSessions: () => api.post('/users/me/sessions/revoke-all'),
  verifyAudit: () => api.get('/users/audit/verify'),
};

export const collectionAPI = {
  import: (caseId, formData, onUploadProgress) => api.post(`/collection/${caseId}/import`, formData, { headers: { 'Content-Type': 'multipart/form-data' }, onUploadProgress }),
  parse: (caseId, data) => api.post(`/collection/${caseId}/parse`, data),
  parseProgress: (caseId) => api.get(`/collection/${caseId}/parse-progress`),
  timelineHistogram: (caseId, buckets = 48) => api.get(`/collection/${caseId}/timeline-histogram`, { params: { buckets } }),
  rdpCacheList: (caseId) => api.get(`/collection/${caseId}/rdp-cache`),
  rdpCacheImage: (caseId, name) => api.get(`/collection/${caseId}/rdp-cache/${name}`, { responseType: 'blob' }),
  timeline: (caseId, params) => api.get(`/collection/${caseId}/timeline`, { params }),
  detectionsSummary: (caseId) => api.get(`/collection/${caseId}/detections/summary`),
  record: (caseId, index) => api.get(`/collection/${caseId}/record/${index}`),
  runHayabusa: (caseId)         => api.post(`/collection/${caseId}/hayabusa`),
  getHayabusa: (caseId, params) => api.get(`/collection/${caseId}/hayabusa`, { params }),
  deleteData:  (caseId) => api.delete(`/collection/${caseId}/data`),
  exportCsv: (caseId, params) => api.get(`/collection/${caseId}/export/csv`, { params, responseType: 'blob' }),

  exportCsvStream: (caseId, params) => api.get(`/collection/${caseId}/export-csv-stream`, { params, responseType: 'blob' }),

  openPitSession:  (caseId, keepAlive = '5m') => api.post(`/collection/${caseId}/timeline/session`, { keep_alive: keepAlive }),
  closePitSession: (caseId, pitId)            => api.delete(`/collection/${caseId}/timeline/session`, { data: { pit_id: pitId } }),
  evidenceIds: (caseId) => api.get(`/collection/${caseId}/evidence-ids`),

  rawFields: (caseId, artifactType) => api.get(`/collection/${caseId}/timeline/raw-fields`, { params: { artifact_type: artifactType } }),

  heatmap: (caseId, params) => api.get(`/collection/${caseId}/heatmap`, { params }),

  deadTime: (caseId, params) => api.get(`/collection/${caseId}/dead-time`, { params }),

  verdicts:       (caseId)                     => api.get(`/collection/${caseId}/verdicts`),
  setVerdict:     (caseId, data)               => api.post(`/collection/${caseId}/verdicts`, data),
  deleteVerdict:  (caseId, eventRef)           => api.delete(`/collection/${caseId}/verdicts/${encodeURIComponent(eventRef)}`),

  timelineRowRaw: (caseId, id)                 => api.get(`/collection/${caseId}/timeline-row/${id}/raw`),
  timelineMappings: (caseId)                   => api.get(`/collection/${caseId}/timeline/mappings`),
  timelineGroups: (caseId, by, params = {})    => api.get(`/collection/${caseId}/timeline/groups`, { params: { by: Array.isArray(by) ? by.join(',') : by, ...params } }),
  timelineContext: (caseId, anchorId, { n = 25, allHosts = false } = {}) =>
    api.get(`/collection/${caseId}/timeline/context`, { params: { anchor_id: anchorId, n, all_hosts: allHosts } }),
  timelineDiff: (caseId, sideA, sideB, { limit = 500 } = {}) =>
    api.get(`/collection/${caseId}/timeline/diff`, { params: {
      a_evidence: sideA.evidenceId || undefined, a_host: sideA.hostName || undefined,
      b_evidence: sideB.evidenceId || undefined, b_host: sideB.hostName || undefined, limit } }),
  updateTimelineTags: (caseId, id, tags)       => api.patch(`/collection/${caseId}/timeline/${id}/tags`, { tags }),
  bulkUpdateTimelineTags: (caseId, updates)    => api.post(`/collection/${caseId}/timeline/tags/bulk`, { updates }),
  importCsv: (caseId, formData, onUploadProgress) =>
    api.post(`/collection/${caseId}/import-csv`, formData, { headers: { 'Content-Type': 'multipart/form-data' }, onUploadProgress }),
};

export const columnPrefsAPI = {
  list:   (artifactType, caseId) => api.get('/column-prefs', { params: { artifact_type: artifactType, case_id: caseId } }),
  upsert: (artifactType, data)   => api.put(`/column-prefs/${artifactType}`, data),
  remove: (artifactType, scope, caseId) => api.delete(`/column-prefs/${artifactType}`, { params: { scope, case_id: caseId } }),
};

export const timelineRulesAPI = {
  list:    (caseId) => api.get('/timeline-rules', { params: { case_id: caseId } }),
  create:  (data)   => api.post('/timeline-rules', data),
  update:  (id, data) => api.put(`/timeline-rules/${id}`, data),
  remove:  (id)     => api.delete(`/timeline-rules/${id}`),
  reorder: (updates) => api.patch('/timeline-rules/reorder', { updates }),
};

export const searchAPI = {
  search: (q, type) => api.get('/search', { params: { q, type } }),
};

export const mitreAPI = {
  list:   (caseId)        => api.get(`/mitre/${caseId}`),
  add:    (caseId, data)  => api.post(`/mitre/${caseId}`, data),
  update: (caseId, id, data) => api.patch(`/mitre/${caseId}/${id}`, data),
  remove: (caseId, id)    => api.delete(`/mitre/${caseId}/${id}`),
};

export const artifactsAPI = {
  refsWithNotes: (caseId)                    => api.get(`/artifacts/${caseId}/refs-with-notes`),
  getNotes:      (caseId, ref)               => api.get(`/artifacts/${caseId}/${ref}/notes`),
  createNote:    (caseId, ref, note)         => api.post(`/artifacts/${caseId}/${ref}/notes`, { note }),
  updateNote:    (caseId, ref, noteId, note) => api.put(`/artifacts/${caseId}/${ref}/notes/${noteId}`, { note }),
  deleteNote:    (caseId, ref, noteId)       => api.delete(`/artifacts/${caseId}/${ref}/notes/${noteId}`),
};

export const threatHuntingAPI = {

  yaraRules:       ()              => api.get('/threat-hunting/yara/rules'),
  createYaraRule:  (data)          => api.post('/threat-hunting/yara/rules', data),
  updateYaraRule:  (id, data)      => api.put(`/threat-hunting/yara/rules/${id}`, data),
  deleteYaraRule:  (id)            => api.delete(`/threat-hunting/yara/rules/${id}`),

  scanEvidence:    (evidenceId)    => api.post(`/threat-hunting/yara/scan/${evidenceId}`),
  scanCase:        (caseId)        => api.post(`/threat-hunting/yara/scan-case/${caseId}`),
  yaraResultsCase: (caseId)        => api.get(`/threat-hunting/yara/results/${caseId}`),
  yaraResultsEvidence: (evidenceId) => api.get(`/threat-hunting/yara/results/evidence/${evidenceId}`),

  sigmaRules:      ()              => api.get('/threat-hunting/sigma/rules'),
  createSigmaRule: (data)          => api.post('/threat-hunting/sigma/rules', data),
  updateSigmaRule: (id, data)      => api.put(`/threat-hunting/sigma/rules/${id}`, data),
  deleteSigmaRule: (id)            => api.delete(`/threat-hunting/sigma/rules/${id}`),

  sigmaHunt:       (caseId, ruleId) => api.post(`/threat-hunting/sigma/hunt/${caseId}`, { ruleId }),
  sigmaScanCase:   (caseId)         => api.post(`/threat-hunting/sigma/scan-case/${caseId}`, {}, { timeout: 600_000 }),
  sigmaHunts:      (caseId)         => api.get(`/threat-hunting/sigma/hunts/${caseId}`),

  githubRepos:     (type)                        => api.get(`/threat-hunting/github/repos?type=${type}`),
  githubTree:      (owner, repo, branch, type)   => api.get(`/threat-hunting/github/tree?owner=${encodeURIComponent(owner)}&repo=${encodeURIComponent(repo)}&branch=${encodeURIComponent(branch)}&type=${type}`),
  githubImport:    (data)                        => api.post('/threat-hunting/github/import', data),
  githubImportZip: (data)                        => api.post('/threat-hunting/github/import-zip', data, { timeout: 600_000 }),
  sysmonImport:    (key)                         => api.post(`/threat-hunting/sysmon/configs/${key}/import`, {}, { timeout: 30_000 }),
  sysmonLibrary:   ()                            => api.get('/threat-hunting/sysmon/library'),
  sysmonLibraryContent: (key)                    => api.get(`/threat-hunting/sysmon/library/${key}/content`, { responseType: 'blob' }),
  sysmonLibraryDelete:  (key)                    => api.delete(`/threat-hunting/sysmon/library/${key}`),
  runAll:          (caseId)                      => api.post(`/threat-hunting/run-all/${caseId}`),
  runAllStatus:    (caseId)                      => api.get(`/threat-hunting/run-all/${caseId}/status`),
};

export const sysmonAPI = {
  list: () => api.get('/sysmon/configs'),
  download: (id) => api.get(`/sysmon/configs/${id}/download`, { responseType: 'blob' }),
  markDeployed: (id, notes) => api.post(`/sysmon/configs/${id}/mark-deployed`, { notes }),
};

export const bookmarksAPI = {
  list:   (caseId)           => api.get(`/cases/${caseId}/bookmarks`),
  create: (caseId, data)     => api.post(`/cases/${caseId}/bookmarks`, data),
  update: (caseId, id, data) => api.put(`/cases/${caseId}/bookmarks/${id}`, data),
  remove: (caseId, id)       => api.delete(`/cases/${caseId}/bookmarks/${id}`),
};

export const savedSearchesAPI = {
  list:   (caseId)           => api.get(`/cases/${caseId}/saved-searches`),
  create: (caseId, data)     => api.post(`/cases/${caseId}/saved-searches`, data),
  update: (caseId, id, data) => api.put(`/cases/${caseId}/saved-searches/${id}`, data),
  remove: (caseId, id)       => api.delete(`/cases/${caseId}/saved-searches/${id}`),
};

export const investigationAPI = {
  get:        (caseId)            => api.get(`/cases/${caseId}/investigation`),
  seed:       (caseId)            => api.post(`/cases/${caseId}/investigation/seed`),
  addStep:    (caseId, data)      => api.post(`/cases/${caseId}/investigation/steps`, data),
  updateStep: (caseId, id, data)  => api.put(`/cases/${caseId}/investigation/steps/${id}`, data),
  removeStep: (caseId, id)        => api.delete(`/cases/${caseId}/investigation/steps/${id}`),
  navigator:  (caseId)            => api.get(`/cases/${caseId}/investigation/navigator`),
};

export const threatIntelAPI = {
  feeds:        ()               => api.get('/threat-intel/feeds'),
  addFeed:      (data)           => api.post('/threat-intel/feeds', data),
  deleteFeed:   (id)             => api.delete(`/threat-intel/feeds/${id}`),
  fetchFeed:    (id)             => api.post(`/threat-intel/feeds/${id}/fetch`),
  indicators:   (params)         => api.get('/threat-intel/indicators', { params }),
  stats:        ()               => api.get('/threat-intel/stats'),
  correlate:    (caseId)         => api.post(`/threat-intel/correlate/${caseId}`),
  correlations: (caseId)         => api.get(`/threat-intel/correlations/${caseId}`),
};

export const mispAPI = {
  instances:      ()      => api.get('/misp/instances'),
  addInstance:    (data)  => api.post('/misp/instances', data),
  deleteInstance: (id)    => api.delete(`/misp/instances/${id}`),
  testInstance:   (id)    => api.post(`/misp/instances/${id}/test`),
  syncInstance:   (id)    => api.post(`/misp/instances/${id}/sync`),
};

export const playbooksAPI = {

  list:          ()                          => api.get('/playbooks'),
  get:           (id)                        => api.get(`/playbooks/${id}`),
  myOpenSteps:   ()                          => api.get('/playbooks/my-open-steps'),

  caseInstances: (caseId)                    => api.get(`/playbooks/cases/${caseId}`),
  instanceSteps: (caseId, instanceId)        => api.get(`/playbooks/cases/${caseId}/${instanceId}/steps`),
  start:         (caseId, playbookId)        => api.post(`/playbooks/cases/${caseId}/start`, { playbook_id: playbookId }),
  updateStep:    (caseId, instanceId, stepId, data) => api.put(`/playbooks/cases/${caseId}/${instanceId}/steps/${stepId}`, data),
};

export const dfiqAPI = {
  scenarios:      ()                       => api.get('/dfiq/scenarios'),
  scenario:       (id)                     => api.get(`/dfiq/scenarios/${id}`),
  createScenario: (data)                   => api.post('/dfiq/scenarios', data),
  updateScenario: (id, data)               => api.put(`/dfiq/scenarios/${id}`, data),
  deleteScenario: (id)                     => api.delete(`/dfiq/scenarios/${id}`),
  addQuestion:    (id, data)               => api.post(`/dfiq/scenarios/${id}/questions`, data),
  caseInstances:  (caseId)                 => api.get(`/cases/${caseId}/dfiq`),
  attach:         (caseId, scenarioId)     => api.post(`/cases/${caseId}/dfiq/attach`, { scenario_id: scenarioId }),
  detach:         (caseId, instanceId)     => api.delete(`/cases/${caseId}/dfiq/${instanceId}`),
  answers:        (caseId, instanceId)     => api.get(`/cases/${caseId}/dfiq/${instanceId}/answers`),
  setAnswer:      (caseId, instanceId, qId, data) => api.put(`/cases/${caseId}/dfiq/${instanceId}/answers/${qId}`, data),
  addEvidence:    (caseId, instanceId, qId, bookmarkId) => api.post(`/cases/${caseId}/dfiq/${instanceId}/answers/${qId}/evidence`, { bookmark_id: bookmarkId }),
  removeEvidence: (caseId, instanceId, qId, bookmarkId) => api.delete(`/cases/${caseId}/dfiq/${instanceId}/answers/${qId}/evidence/${bookmarkId}`),
};

export const legalHoldAPI = {
  enable:   (caseId, reason) => api.post(`/cases/${caseId}/legal-hold`, { reason }),
  disable:  (caseId)         => api.delete(`/cases/${caseId}/legal-hold`),
  manifest: (caseId)         => api.get(`/cases/${caseId}/legal-hold/manifest`, { responseType: 'blob' }),
};

export const pcapAPI = {
  upload: (caseId, file, onProgress) => {
    const fd = new FormData();
    fd.append('pcap', file);
    return api.post(`/collection/${caseId}/pcap`, fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress: onProgress,
    });
  },
};

export const pinsAPI = {
  list:    (caseId)        => api.get(`/timeline-pins/${caseId}`),
  add:     (caseId, data)  => api.post(`/timeline-pins/${caseId}`, data),
  remove:  (caseId, pinId) => api.delete(`/timeline-pins/${caseId}/${pinId}`),
  promote: (caseId, pinId) => api.patch(`/timeline-pins/${caseId}/${pinId}/promote`),
};

export const feedbackAPI = {
  submit: (data)         => api.post('/feedback', data),
  mine:   ()             => api.get('/feedback/mine'),
  list:   (params)       => api.get('/feedback', { params }),
  update: (id, data)     => api.patch(`/feedback/${id}`, data),
};

export const aiCopilotAPI = {
  health:         ()                => api.get('/ai/health'),
  models:         ()                => api.get('/ai/models'),
  history:        (caseId)          => api.get(`/cases/${caseId}/ai/history`),
  clearHistory:   (caseId)          => api.delete(`/cases/${caseId}/ai/history`),
  chat:           (caseId, data)    => api.post(`/cases/${caseId}/ai/chat`, data),
  getContext:     (caseId)          => api.get(`/cases/${caseId}/ai/context`),
  saveContext:    (caseId, freeText) => api.put(`/cases/${caseId}/ai/context`, { freeText }),
  clearContext:   (caseId)          => api.delete(`/cases/${caseId}/ai/context`),
};

export const soarAPI = {
  alerts:  (caseId, params) => api.get(`/cases/${caseId}/soar/alerts`, { params }),
  ack:     (caseId, alertId, acknowledged = true) => api.put(`/cases/${caseId}/soar/alerts/${alertId}/ack`, { acknowledged }),
  ackAll:  (caseId)         => api.put(`/cases/${caseId}/soar/alerts/ack-all`),
  run:     (caseId)         => api.post(`/cases/${caseId}/soar/run`),
};

export const settingsAPI = {
  getDashboard: ()     => api.get('/settings/dashboard'),
  setDashboard: (data) => api.put('/settings/dashboard', data),
  getIntegrations: ()     => api.get('/settings/integrations'),
  setIntegrations: (data) => api.put('/settings/integrations', data),
  getSecurity:       ()     => api.get('/settings/security'),
  setSecurity:       (data) => api.put('/settings/security', data),
  getSecurityClient: ()     => api.get('/settings/security/client'),
  getRetention:      ()       => api.get('/settings/retention'),
  setRetention:      (data)   => api.put('/settings/retention', data),
  previewRetention:  (days)   => api.get('/settings/retention/preview', { params: days ? { days } : {} }),
  runRetention:      ()       => api.post('/settings/retention/run'),
  setCaseExempt:     (caseId, exempt) => api.patch(`/settings/retention/exempt/${caseId}`, { exempt }),
};

export const triageAPI = {
  queue: () => api.get('/triage'),
  // Persistent alert inbox
  alerts:       (params)   => api.get('/triage/alerts', { params }),
  alertStats:   ()         => api.get('/triage/alerts/stats'),
  createAlert:  (data)     => api.post('/triage/alerts', data),
  updateAlert:  (id, data) => api.patch(`/triage/alerts/${id}`, data),
  dismissAlert: (id, data) => api.post(`/triage/alerts/${id}/dismiss`, data),
  deleteAlert:  (id)       => api.delete(`/triage/alerts/${id}`),
};
