
import React, {
  useState,
  useEffect,
  useRef,
  useCallback,
  useMemo,
} from 'react';
import { FixedSizeList as VirtualList } from 'react-window';
import {
  Play,
  Square,
  Terminal,
  CheckCircle,
  XCircle,
  Loader,
  Download,
  Copy,
  Filter,
  Wifi,
  WifiOff,
  ChevronDown,
} from 'lucide-react';
import { useSocket, useSocketEvent } from '../../hooks/useSocket';
import type {
  ParserStatus,
  ParserStatusEvent,
  ParserLogEvent,
  LogEntry,
  AvailableTools,
  Evidence,
} from '../../types/forensic';

interface ParserConsoleProps {
  caseId: string;

  defaultEvidenceId?: string;

  onSuccess?: (resultId: string, recordCount: number) => void;
}

const LOG_ITEM_HEIGHT = 20;
const MAX_VISIBLE_LOGS = 5000;

const StatusBadge: React.FC<{ status: ParserStatus | null; isConnected: boolean }> = ({
  status,
  isConnected,
}) => {
  if (!isConnected)
    return (
      <span className="flex items-center gap-1 text-xs text-slate-500">
        <WifiOff className="w-3 h-3" /> Déconnecté
      </span>
    );

  switch (status) {
    case 'INIT':
      return (
        <span className="flex items-center gap-1 text-xs text-blue-400">
          <Loader className="w-3 h-3 animate-spin" /> Initialisation
        </span>
      );
    case 'RUNNING':
      return (
        <span className="flex items-center gap-1 text-xs text-cyan-400">
          <Loader className="w-3 h-3 animate-spin" /> En cours
        </span>
      );
    case 'SUCCESS':
      return (
        <span className="flex items-center gap-1 text-xs text-green-400">
          <CheckCircle className="w-3 h-3" /> Succès
        </span>
      );
    case 'FAILED':
      return (
        <span className="flex items-center gap-1 text-xs text-red-400">
          <XCircle className="w-3 h-3" /> Échec
        </span>
      );
    default:
      return (
        <span className="flex items-center gap-1 text-xs text-slate-400">
          <Wifi className="w-3 h-3 text-green-400" /> Prêt
        </span>
      );
  }
};

interface RowProps {
  index: number;
  style: React.CSSProperties;
  data: LogEntry[];
}

const LogRow: React.FC<RowProps> = ({ index, style, data }) => {
  const entry = data[index];
  const isStderr = entry.stream === 'stderr';
  return (
    <div
      style={style}
      className={[
        'px-3 font-mono text-xs leading-5 whitespace-pre-wrap break-all select-text',
        isStderr ? 'text-red-400' : 'text-green-300',
      ].join(' ')}
    >
      <span className="text-slate-600 mr-2 select-none">{String(index + 1).padStart(5, ' ')}</span>
      {entry.line}
    </div>
  );
};

const ParserConsole: React.FC<ParserConsoleProps> = ({ caseId, defaultEvidenceId, onSuccess }) => {

  const { socket, isConnected, socketId } = useSocket();

  const [availableTools, setAvailableTools] = useState<AvailableTools>({});
  const [evidenceList, setEvidenceList] = useState<Evidence[]>([]);
  const [selectedParser, setSelectedParser] = useState('');
  const [selectedEvidence, setSelectedEvidence] = useState(defaultEvidenceId || '');

  const [status, setStatus] = useState<ParserStatus | null>(null);
  const [statusMessage, setStatusMessage] = useState('');
  const [resultId, setResultId] = useState<string | null>(null);
  const [recordCount, setRecordCount] = useState<number | null>(null);
  const [isRunning, setIsRunning] = useState(false);

  const [logs, setLogs] = useState<LogEntry[]>([]);
  const logIdRef = useRef(0);
  const runControllerRef = useRef<AbortController | null>(null);
  const [filter, setFilter] = useState('');
  const [autoScroll, setAutoScroll] = useState(true);
  const listRef = useRef<VirtualList>(null);
  const listOuterRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const controller = new AbortController();
    const { signal } = controller;
    const token = localStorage.getItem('heimdall_token');
    const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};

    fetch('/api/parsers/available', { headers, signal })
      .then((r) => r.ok ? r.json() : Promise.reject(r.status))
      .then((data) => { if (data && typeof data === 'object' && !Array.isArray(data)) setAvailableTools(data); })
      .catch((e) => { if (e.name !== 'AbortError') console.error(e); });

    fetch(`/api/evidence/${caseId}`, { headers, signal })
      .then((r) => r.ok ? r.json() : Promise.reject(r.status))
      .then((data: unknown) => {
        if (!Array.isArray(data)) return;
        setEvidenceList(data as Evidence[]);
        if (!defaultEvidenceId && (data as Evidence[]).length > 0) {
          setSelectedEvidence((data as Evidence[])[0].id);
        }
      })
      .catch((e) => { if (e.name !== 'AbortError') console.error(e); });

    return () => controller.abort();
  }, [caseId, defaultEvidenceId]);

  useEffect(() => () => { runControllerRef.current?.abort(); }, []);

  const appendLog = useCallback((stream: 'stdout' | 'stderr', line: string) => {
    setLogs((prev) => {
      const next: LogEntry[] = [
        ...(prev.length >= MAX_VISIBLE_LOGS ? prev.slice(-MAX_VISIBLE_LOGS + 1) : prev),
        { id: logIdRef.current++, stream, line, ts: Date.now() },
      ];
      return next;
    });
  }, []);

  useSocketEvent<ParserStatusEvent>(socket, 'parser:status', useCallback((data) => {
    setStatus(data.status);
    setStatusMessage(data.message || '');
    if (data.status === 'SUCCESS' || data.status === 'FAILED') {
      setIsRunning(false);
      if (data.resultId) setResultId(data.resultId);
      if (data.recordCount !== undefined) setRecordCount(data.recordCount);
      if (data.status === 'SUCCESS' && data.resultId && onSuccess) {
        onSuccess(data.resultId, data.recordCount ?? 0);
      }
    }
    if (data.message) appendLog('stdout', `[STATUS] ${data.message}`);
  }, [appendLog, onSuccess]));

  useSocketEvent<ParserLogEvent>(socket, 'parser:log', useCallback((data) => {
    appendLog(data.stream, data.line);
  }, [appendLog]));

  useSocketEvent<{ message: string }>(socket, 'parser:error', useCallback((data) => {
    appendLog('stderr', `[ERROR] ${data.message}`);
    setIsRunning(false);
    setStatus('FAILED');
  }, [appendLog]));

  useEffect(() => {
    if (autoScroll && listRef.current && logs.length > 0) {
      listRef.current.scrollToItem(logs.length - 1, 'end');
    }
  }, [logs, autoScroll]);

  const handleScroll = useCallback(
    ({ scrollOffset }: { scrollOffset: number; scrollUpdateWasRequested: boolean }) => {
      const outer = listOuterRef.current;
      if (!outer) return;
      const maxScroll = outer.scrollHeight - outer.clientHeight;
      setAutoScroll(scrollOffset >= maxScroll - LOG_ITEM_HEIGHT);
    },
    []
  );

  const displayedLogs = useMemo(() => {
    if (!filter.trim()) return logs;
    const lf = filter.toLowerCase();
    return logs.filter((l) => l.line.toLowerCase().includes(lf));
  }, [logs, filter]);

  const handleRun = useCallback(async () => {
    if (!selectedParser || !selectedEvidence || !socketId) return;

    setLogs([]);
    logIdRef.current = 0;
    setStatus(null);
    setStatusMessage('');
    setResultId(null);
    setRecordCount(null);
    setIsRunning(true);

    runControllerRef.current?.abort();
    const controller = new AbortController();
    runControllerRef.current = controller;

    try {
      const token = localStorage.getItem('heimdall_token');
      const res = await fetch('/api/parsers/run', {
        method: 'POST',
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          parser: selectedParser,
          evidenceId: selectedEvidence,
          caseId,
          socketId,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        appendLog('stderr', `[HTTP ERROR] ${err.error || res.statusText}`);
        setIsRunning(false);
        setStatus('FAILED');
      }
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') return;
      const msg = err instanceof Error ? err.message : String(err);
      appendLog('stderr', `[NETWORK ERROR] ${msg}`);
      setIsRunning(false);
      setStatus('FAILED');
    }
  }, [selectedParser, selectedEvidence, socketId, caseId, appendLog]);

  const handleCopy = useCallback(() => {
    const text = logs.map((l) => `[${l.stream.toUpperCase()}] ${l.line}`).join('\n');
    navigator.clipboard.writeText(text).catch(console.error);
  }, [logs]);

  const handleDownload = useCallback(() => {
    const text = logs.map((l) => `[${l.stream.toUpperCase()}] ${l.line}`).join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `heimdall-parser-log-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }, [logs]);

  return (
    <div className="flex flex-col h-full bg-slate-900 rounded-lg border border-slate-700 overflow-hidden">

      <div className="flex items-center justify-between px-4 py-2 bg-slate-800 border-b border-slate-700">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span className="text-sm font-medium text-slate-200">Parser Console</span>
        </div>
        <StatusBadge status={status} isConnected={isConnected} />
      </div>

      <div className="flex flex-wrap items-end gap-3 p-3 bg-slate-850 border-b border-slate-700">
        
        <div className="flex-1 min-w-36">
          <label className="block text-xs text-slate-400 mb-1">Parseur</label>
          <select
            value={selectedParser}
            onChange={(e) => setSelectedParser(e.target.value)}
            disabled={isRunning}
            className="w-full bg-slate-800 border border-slate-600 rounded px-2 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
          >
            <option value="">— Choisir —</option>
            {Object.entries(availableTools).map(([key, tool]) => (
              <option key={key} value={key} disabled={!tool.available}>
                {tool.name} {!tool.available ? '(non installé)' : ''}
              </option>
            ))}
          </select>
        </div>

        <div className="flex-1 min-w-48">
          <label className="block text-xs text-slate-400 mb-1">Preuve</label>
          <select
            value={selectedEvidence}
            onChange={(e) => setSelectedEvidence(e.target.value)}
            disabled={isRunning}
            className="w-full bg-slate-800 border border-slate-600 rounded px-2 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
          >
            <option value="">— Choisir —</option>
            {evidenceList.map((ev) => (
              <option key={ev.id} value={ev.id}>
                {ev.name}
              </option>
            ))}
          </select>
        </div>

        <button
          onClick={handleRun}
          disabled={isRunning || !selectedParser || !selectedEvidence || !isConnected}
          className={[
            'flex items-center gap-2 px-4 py-1.5 rounded text-sm font-medium transition-colors',
            isRunning || !selectedParser || !selectedEvidence || !isConnected
              ? 'bg-slate-700 text-slate-500 cursor-not-allowed'
              : 'bg-cyan-600 hover:bg-cyan-500 text-white',
          ].join(' ')}
        >
          {isRunning ? (
            <>
              <Loader className="w-4 h-4 animate-spin" />
              En cours…
            </>
          ) : (
            <>
              <Play className="w-4 h-4" />
              Exécuter
            </>
          )}
        </button>
      </div>

      {statusMessage && (
        <div className={[
          'px-4 py-1.5 text-xs border-b',
          status === 'FAILED'
            ? 'bg-red-950/40 border-red-800 text-red-300'
            : status === 'SUCCESS'
            ? 'bg-green-950/40 border-green-800 text-green-300'
            : 'bg-blue-950/40 border-blue-800 text-blue-300',
        ].join(' ')}>
          {statusMessage}
          {recordCount !== null && (
            <span className="ml-2 font-medium">
              — {recordCount.toLocaleString()} événements importés
            </span>
          )}
        </div>
      )}

      <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 border-b border-slate-700">
        <Filter className="w-3 h-3 text-slate-500 flex-shrink-0" />
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filtrer les logs…"
          className="flex-1 bg-transparent text-xs text-slate-300 placeholder-slate-600 outline-none"
        />
        <span className="text-xs text-slate-500">
          {displayedLogs.length}/{logs.length}
        </span>
        <button
          onClick={() => setAutoScroll((v) => !v)}
          title={autoScroll ? 'Défilement auto activé' : 'Défilement auto désactivé'}
          className={`p-1 rounded ${autoScroll ? 'text-cyan-400' : 'text-slate-500'}`}
        >
          <ChevronDown className="w-3 h-3" />
        </button>
        <button onClick={handleCopy} title="Copier" className="p-1 rounded text-slate-500 hover:text-slate-300">
          <Copy className="w-3 h-3" />
        </button>
        <button onClick={handleDownload} title="Télécharger" className="p-1 rounded text-slate-500 hover:text-slate-300">
          <Download className="w-3 h-3" />
        </button>
      </div>

      <div className="flex-1 min-h-0">
        {displayedLogs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-slate-600 text-sm gap-2">
            <Terminal className="w-8 h-8" />
            <p>En attente d'exécution…</p>
            <p className="text-xs text-slate-700">Sélectionnez un parseur et une preuve, puis cliquez sur Exécuter</p>
          </div>
        ) : (
          <VirtualList
            ref={listRef}
            outerRef={listOuterRef}
            height={600}
            width="100%"
            itemCount={displayedLogs.length}
            itemSize={LOG_ITEM_HEIGHT}
            itemData={displayedLogs}
            onScroll={handleScroll}
            className="bg-slate-950"
            style={{ overflowX: 'hidden' }}
          >
            {LogRow}
          </VirtualList>
        )}
      </div>

      
      <div className="flex items-center justify-between px-3 py-1 bg-slate-800 border-t border-slate-700 text-xs text-slate-500">
        <span>
          Socket: <span className={isConnected ? 'text-green-400' : 'text-red-400'}>
            {isConnected ? socketId?.slice(0, 8) + '…' : 'Déconnecté'}
          </span>
        </span>
        {resultId && (
          <span>
            Résultat: <span className="text-slate-300 font-mono">{resultId.slice(0, 8)}</span>
          </span>
        )}
        <span>{logs.length.toLocaleString()} lignes</span>
      </div>
    </div>
  );
};

export default ParserConsole;
