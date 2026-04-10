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

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const orig = error.config;
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

        }
      }
      localStorage.removeItem('heimdall_token');
      localStorage.removeItem('heimdall_refresh_token');
      localStorage.removeItem('heimdall_user');
      window.location.href = '/login';
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
};

export const casesAPI = {
  list: (params) => api.get('/cases', { params }),
  get: (id) => api.get(`/cases/${id}`),
  create: (data) => api.post('/cases', data),
  update: (id, data) => api.put(`/cases/${id}`, data),
  stats: () => api.get('/cases/stats/dashboard'),
  audit: (id, params) => api.get(`/cases/${id}/audit`, { params }),
  hardDelete: (id) => api.delete(`/cases/${id}/hard-delete`),
  runTriage: (id) => api.post(`/cases/${id}/triage`),
  getTriage: (id) => api.get(`/cases/${id}/triage`),
  lateralMovement: (id) => api.get(`/cases/${id}/lateral-movement`),
  deadlines:   () => api.get('/cases/deadlines'),
  leaderboard: () => api.get('/cases/leaderboard'),
  exportAnonymized: (id) => api.get(`/cases/${id}/export/anonymized`, { responseType: 'blob' }),
  riskScore: (id) => api.get(`/cases/${id}/risk-score`),
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
  dgaAnalysis: (caseId) => api.get(`/network/${caseId}/dga-analysis`),
};

export const parsersAPI = {
  available: () => api.get('/parsers/available'),
  run: (data) => api.post('/parsers/run', data),
  results: (caseId) => api.get(`/parsers/results/${caseId}`),
  resultData: (resultId, params) => api.get(`/parsers/result/${resultId}/data`, { params }),
  resultTypes: (resultId) => api.get(`/parsers/result/${resultId}/types`),
  deleteResult: (resultId) => api.delete(`/parsers/results/${resultId}`),
  exportResultCsv: (resultId) => api.get(`/parsers/result/${resultId}/export/csv`, { responseType: 'blob' }),
};

export const reportsAPI = {
  generate: (caseId, templateId = null) => api.post(`/reports/${caseId}/generate`, { templateId }),
  list: (caseId) => api.get(`/reports/${caseId}`),
  download: (id) => api.get(`/reports/download/${id}`, { responseType: 'blob' }),

  listTemplates: () => api.get('/reports/templates'),
  createTemplate: (data) => api.post('/reports/templates', data),
  updateTemplate: (id, data) => api.put(`/reports/templates/${id}`, data),
  deleteTemplate: (id) => api.delete(`/reports/templates/${id}`),
};

export const usersAPI = {
  list: () => api.get('/users'),
  me: () => api.get('/users/me'),
  update: (id, data) => api.put(`/users/${id}`, data),
  delete: (id) => api.delete(`/users/${id}`),
  changePassword: (id, password) => api.put(`/users/${id}/password`, { password }),
  audit: (params) => api.get('/users/audit', { params }),
  updatePreferences: (prefs) => api.patch('/users/me/preferences', prefs),
};

export const collectionAPI = {
  import: (caseId, formData, onUploadProgress) => api.post(`/collection/${caseId}/import`, formData, { headers: { 'Content-Type': 'multipart/form-data' }, onUploadProgress }),
  parse: (caseId, data) => api.post(`/collection/${caseId}/parse`, data),
  timeline: (caseId, params) => api.get(`/collection/${caseId}/timeline`, { params }),
  record: (caseId, index) => api.get(`/collection/${caseId}/record/${index}`),
  runHayabusa: (caseId) => api.post(`/collection/${caseId}/hayabusa`),
  getHayabusa: (caseId) => api.get(`/collection/${caseId}/hayabusa`),
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

export const playbooksAPI = {

  list:          ()                          => api.get('/playbooks'),
  get:           (id)                        => api.get(`/playbooks/${id}`),

  caseInstances: (caseId)                    => api.get(`/playbooks/cases/${caseId}`),
  instanceSteps: (caseId, instanceId)        => api.get(`/playbooks/cases/${caseId}/${instanceId}/steps`),
  start:         (caseId, playbookId)        => api.post(`/playbooks/cases/${caseId}/start`, { playbook_id: playbookId }),
  updateStep:    (caseId, instanceId, stepId, data) => api.put(`/playbooks/cases/${caseId}/${instanceId}/steps/${stepId}`, data),
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
