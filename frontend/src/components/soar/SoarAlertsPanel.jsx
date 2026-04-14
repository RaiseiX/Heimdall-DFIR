
import { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert, ShieldCheck, RefreshCw, CheckCheck,
  ChevronDown, ChevronRight, Zap, Eye, EyeOff,
} from 'lucide-react';
import { soarAPI } from '../../utils/api';
import { useDateFormat } from '../../hooks/useDateFormat';

const SEV_STYLES = {
  critical: 'bg-red-900/60 text-red-300 border border-red-700',
  high:     'bg-orange-900/60 text-orange-300 border border-orange-700',
  medium:   'bg-yellow-900/60 text-yellow-300 border border-yellow-700',
  low:      'bg-blue-900/60 text-blue-300 border border-blue-700',
  info:     'bg-gray-700 text-gray-300 border border-gray-600',
};

const TYPE_LABELS = {
  yara:         'YARA',
  sigma:        'Sigma',
  threat_intel: 'Threat Intel',
  triage:       'Triage',
};

const TYPE_COLORS = {
  yara:         'bg-purple-800 text-purple-200',
  sigma:        'bg-blue-800 text-blue-200',
  threat_intel: 'bg-red-800 text-red-200',
  triage:       'bg-orange-800 text-orange-200',
};

function fmt(dt) {
  if (!dt) return '—';
  return new Date(dt).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC';
}

function AlertRow({ alert, onAck, onUnack, fmtDateTime }) {
  const [open, setOpen] = useState(false);

  return (
    <div className={`rounded-lg mb-2 ${alert.acknowledged ? 'opacity-50' : ''}`}>
      
      <div
        className="flex items-center gap-3 p-3 cursor-pointer hover:bg-gray-700/50 rounded-lg"
        onClick={() => setOpen(o => !o)}
      >
        
        <span className={`text-xs font-bold px-2 py-0.5 rounded-full uppercase ${SEV_STYLES[alert.severity] || SEV_STYLES.info}`}>
          {alert.severity}
        </span>

        <span className={`text-xs px-2 py-0.5 rounded font-mono ${TYPE_COLORS[alert.type] || 'bg-gray-700 text-gray-300'}`}>
          {TYPE_LABELS[alert.type] || alert.type}
        </span>

        <span className="flex-1 text-sm text-white font-medium truncate">{alert.title}</span>

        <span className="text-xs text-gray-500 shrink-0">{fmtDateTime(alert.created_at)}</span>

        <button
          className={`ml-2 p-1 rounded hover:bg-gray-600 shrink-0 ${alert.acknowledged ? 'text-green-400' : 'text-gray-500'}`}
          title={alert.acknowledged ? 'Annuler acquittement' : 'Acquitter'}
          onClick={e => { e.stopPropagation(); alert.acknowledged ? onUnack(alert.id) : onAck(alert.id); }}
        >
          <ShieldCheck size={14} />
        </button>

        {open ? <ChevronDown size={14} className="text-gray-400 shrink-0" /> : <ChevronRight size={14} className="text-gray-400 shrink-0" />}
      </div>

      {open && (
        <div className="px-4 pb-3 text-sm text-gray-300 border-t border-gray-700 mt-1 pt-2 space-y-2">
          <p>{alert.description}</p>
          {alert.acknowledged && (
            <p className="text-xs text-green-400">
              Acquitté par {alert.acknowledged_by_name || 'inconnu'} le {fmtDateTime(alert.acknowledged_at)}
            </p>
          )}
          {alert.details && Object.keys(alert.details).length > 0 && (
            <pre className="text-xs bg-gray-900 rounded p-2 overflow-auto max-h-40 text-gray-400">
              {JSON.stringify(alert.details, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

export default function SoarAlertsPanel({ caseId, socket, onBadgeUpdate }) {
  const { fmtDateTime } = useDateFormat();
  const [alerts, setAlerts]       = useState([]);
  const [summary, setSummary]     = useState(null);
  const [loading, setLoading]     = useState(false);
  const [running, setRunning]     = useState(false);
  const [showAcked, setShowAcked] = useState(false);
  const [filter, setFilter]       = useState({ type: '', severity: '' });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = {};
      if (filter.type)     params.type     = filter.type;
      if (filter.severity) params.severity = filter.severity;
      if (!showAcked)      params.ack      = 'false';
      const { data } = await soarAPI.alerts(caseId, params);
      setAlerts(data.alerts || []);
      setSummary(data.summary || null);
      onBadgeUpdate?.(parseInt(data.summary?.total_unack || '0', 10));
    } catch (_e) {}
    finally { setLoading(false); }
  }, [caseId, filter, showAcked]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!socket) return;
    const handler = (result) => {
      if (result.case_id === caseId) load();
    };
    socket.on('soar:complete', handler);
    return () => socket.off('soar:complete', handler);
  }, [socket, caseId, load]);

  const handleRun = async () => {
    setRunning(true);
    try { await soarAPI.run(caseId); }
    catch (_e) {}
    finally { setRunning(false); }
  };

  const handleAck    = async (id) => { await soarAPI.ack(caseId, id, true);  load(); };
  const handleUnack  = async (id) => { await soarAPI.ack(caseId, id, false); load(); };
  const handleAckAll = async ()   => { await soarAPI.ackAll(caseId); load(); };

  const kpis = [
    { label: 'Critique', count: summary?.critical || 0, color: 'text-red-400' },
    { label: 'Élevé',    count: summary?.high     || 0, color: 'text-orange-400' },
    { label: 'Moyen',    count: summary?.medium   || 0, color: 'text-yellow-400' },
  ];

  return (
    <div className="space-y-4">
      
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldAlert size={20} className="text-red-400" />
          <h2 className="text-lg font-semibold text-white">Alertes SOAR</h2>
          {summary?.total_unack > 0 && (
            <span className="bg-red-600 text-white text-xs font-bold px-2 py-0.5 rounded-full">
              {summary.total_unack}
            </span>
          )}
        </div>

        <div className="flex gap-2">
          <button
            onClick={handleRun}
            disabled={running}
            className="flex items-center gap-1 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm rounded-lg"
          >
            <Zap size={14} />
            {running ? 'Analyse…' : 'Lancer SOAR'}
          </button>
          <button
            onClick={load}
            disabled={loading}
            className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg"
            title="Rafraîchir"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-3">
        {kpis.map(k => (
          <div key={k.label} className="bg-gray-800 rounded-lg p-3 text-center">
            <div className={`text-2xl font-bold ${k.color}`}>{k.count}</div>
            <div className="text-xs text-gray-400 mt-0.5">{k.label}</div>
          </div>
        ))}
      </div>

      <div className="flex gap-2 flex-wrap">
        <select
          value={filter.type}
          onChange={e => setFilter(f => ({ ...f, type: e.target.value }))}
          className="bg-gray-700 text-gray-300 text-sm rounded-lg px-2 py-1 border border-gray-600"
        >
          <option value="">Tous les types</option>
          {Object.entries(TYPE_LABELS).map(([v, l]) => (
            <option key={v} value={v}>{l}</option>
          ))}
        </select>

        <select
          value={filter.severity}
          onChange={e => setFilter(f => ({ ...f, severity: e.target.value }))}
          className="bg-gray-700 text-gray-300 text-sm rounded-lg px-2 py-1 border border-gray-600"
        >
          <option value="">Toutes sévérités</option>
          {['critical','high','medium','low','info'].map(s => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>

        <button
          onClick={() => setShowAcked(v => !v)}
          className={`flex items-center gap-1 px-3 py-1 text-sm rounded-lg border ${
            showAcked
              ? 'border-green-600 text-green-400 bg-green-900/30'
              : 'border-gray-600 text-gray-400'
          }`}
        >
          {showAcked ? <Eye size={13} /> : <EyeOff size={13} />}
          {showAcked ? 'Masquer acquittés' : 'Voir acquittés'}
        </button>

        {alerts.length > 0 && !showAcked && (
          <button
            onClick={handleAckAll}
            className="flex items-center gap-1 px-3 py-1 text-sm rounded-lg border border-gray-600 text-gray-400 hover:text-white hover:border-gray-400"
          >
            <CheckCheck size={13} />
            Tout acquitter
          </button>
        )}
      </div>

      {loading && <p className="text-gray-500 text-sm">Chargement…</p>}

      {!loading && alerts.length === 0 && (
        <div className="text-center py-10 text-gray-500">
          <ShieldCheck size={40} className="mx-auto mb-2 text-green-600 opacity-50" />
          <p>Aucune alerte active</p>
          <p className="text-xs mt-1">Lancez une analyse SOAR pour scanner le cas</p>
        </div>
      )}

      <div>
        {alerts.map(a => (
          <AlertRow
            key={a.id}
            alert={a}
            onAck={handleAck}
            onUnack={handleUnack}
            fmtDateTime={fmtDateTime}
          />
        ))}
      </div>
    </div>
  );
}
