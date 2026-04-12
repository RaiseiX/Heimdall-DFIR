
import React, { useState, useCallback, useRef } from 'react';
import { useDropzone } from 'react-dropzone';
import {
  Upload,
  CheckCircle,
  XCircle,
  AlertTriangle,
  FileText,
  Loader,
  RefreshCw,
  Shield,
} from 'lucide-react';
import { uploadFile, formatBytes, formatSpeed } from '../../services/uploadService';
import type { UploadState, CompleteUploadResult } from '../../types/forensic';

interface ChunkedUploaderProps {
  caseId: string;
  onComplete?: (result: CompleteUploadResult) => void;
  onError?: (message: string) => void;

  accept?: Record<string, string[]>;

  maxSize?: number;
}

const defaultState = (): UploadState => ({
  phase: 'idle',
  uploadId: null,
  file: null,
  totalChunks: 0,
  chunkSize: 50 * 1024 * 1024,
  chunks: [],
  progress: 0,
  speed: 0,
  errorMessage: null,
  result: null,
});

const PhaseIcon: React.FC<{ phase: UploadState['phase'] }> = ({ phase }) => {
  switch (phase) {
    case 'complete':   return <CheckCircle className="w-5 h-5 text-green-400" />;
    case 'error':      return <XCircle className="w-5 h-5 text-red-400" />;
    case 'uploading':
    case 'assembling':
    case 'hashing':
    case 'initializing': return <Loader className="w-5 h-5 text-cyan-400 animate-spin" />;
    default:           return <Upload className="w-5 h-5 text-slate-400" />;
  }
};

const phaseBadge: Record<UploadState['phase'], string> = {
  idle:         'bg-slate-700 text-slate-300',
  initializing: 'bg-blue-900 text-blue-300',
  uploading:    'bg-cyan-900 text-cyan-300',
  assembling:   'bg-violet-900 text-violet-300',
  hashing:      'bg-amber-900 text-amber-300',
  complete:     'bg-green-900 text-green-300',
  error:        'bg-red-900 text-red-300',
};

const phaseLabel: Record<UploadState['phase'], string> = {
  idle:         'Prêt',
  initializing: 'Initialisation',
  uploading:    'Envoi en cours',
  assembling:   'Assemblage',
  hashing:      'Calcul des hashes',
  complete:     'Terminé',
  error:        'Erreur',
};

const ChunkedUploader: React.FC<ChunkedUploaderProps> = ({
  caseId,
  onComplete,
  onError,
  accept,
  maxSize = 0,
}) => {
  const [uploadState, setUploadState] = useState<UploadState>(defaultState);
  const [phaseMessage, setPhaseMessage] = useState('');
  const [evidenceType, setEvidenceType] = useState('other');
  const [notes, setNotes] = useState('');
  const abortRef = useRef(false);

  const handleStateUpdate = useCallback((state: Readonly<UploadState>) => {
    setUploadState({ ...state });
  }, []);

  const handlePhaseChange = useCallback(
    (phase: UploadState['phase'], message = '') => {
      setPhaseMessage(message);
    },
    []
  );

  const handleComplete = useCallback(
    (result: CompleteUploadResult) => {
      onComplete?.(result);
    },
    [onComplete]
  );

  const handleError = useCallback(
    (message: string) => {
      onError?.(message);
    },
    [onError]
  );

  const onDrop = useCallback(
    (accepted: File[]) => {
      if (accepted.length === 0) return;
      const file = accepted[0];

      if (maxSize > 0 && file.size > maxSize) {
        setUploadState((s) => ({
          ...s,
          phase: 'error',
          errorMessage: `Fichier trop volumineux (max ${formatBytes(maxSize)})`,
        }));
        return;
      }

      abortRef.current = false;
      setUploadState(defaultState());
      setPhaseMessage('');

      uploadFile(
        file,
        { caseId, evidenceType, notes },
        {
          onProgress: handleStateUpdate,
          onPhaseChange: handlePhaseChange,
          onComplete: handleComplete,
          onError: handleError,
        }
      );
    },
    [caseId, evidenceType, notes, maxSize, handleStateUpdate, handlePhaseChange, handleComplete, handleError]
  );

  const { getRootProps, getInputProps, isDragActive, isDragReject } = useDropzone({
    onDrop,
    multiple: false,
    accept,
    disabled: uploadState.phase !== 'idle' && uploadState.phase !== 'complete' && uploadState.phase !== 'error',
  });

  const isActive = ['initializing', 'uploading', 'assembling', 'hashing'].includes(uploadState.phase);

  const resetUpload = useCallback(() => {
    setUploadState(defaultState());
    setPhaseMessage('');
  }, []);

  const chunkColor = (status: string) => {
    switch (status) {
      case 'done':      return 'bg-green-500';
      case 'uploading': return 'bg-cyan-400 animate-pulse';
      case 'error':     return 'bg-red-500';
      default:          return 'bg-slate-600';
    }
  };

  return (
    <div className="space-y-4">
      
      {uploadState.phase === 'idle' && (
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Type de preuve</label>
            <select
              value={evidenceType}
              onChange={(e) => setEvidenceType(e.target.value)}
              className="w-full bg-slate-800 border border-slate-600 rounded px-2 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              {['disk','memory','log','network','binary','registry','prefetch','browser','collection','config','text','other'].map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Notes (optionnel)</label>
            <input
              type="text"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Description rapide…"
              className="w-full bg-slate-800 border border-slate-600 rounded px-2 py-1.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>
      )}

      <div
        {...getRootProps()}
        className={[
          'border-2 border-dashed rounded-lg p-8 text-center transition-colors cursor-pointer',
          isDragActive && !isDragReject ? 'border-cyan-400 bg-cyan-950/30' : '',
          isDragReject ? 'border-red-400 bg-red-950/30' : '',
          !isDragActive && !isDragReject ? 'border-slate-600 hover:border-slate-400' : '',
          isActive ? 'pointer-events-none opacity-60' : '',
        ].join(' ')}
      >
        <input {...getInputProps()} />

        {uploadState.phase === 'idle' && (
          <div className="space-y-2">
            <Upload className="w-10 h-10 text-slate-400 mx-auto" />
            <p className="text-slate-300 text-sm">
              {isDragActive
                ? isDragReject
                  ? 'Fichier non supporté'
                  : 'Déposez ici…'
                : 'Glissez un fichier ou cliquez pour parcourir'}
            </p>
            <p className="text-slate-500 text-xs">
              Taille illimitée — upload par blocs de 50 Mo
            </p>
          </div>
        )}

        {uploadState.file && uploadState.phase !== 'idle' && (
          <div className="flex items-center justify-center gap-3">
            <FileText className="w-6 h-6 text-slate-400 flex-shrink-0" />
            <div className="text-left">
              <p className="text-slate-200 text-sm font-medium truncate max-w-xs">
                {uploadState.file.name}
              </p>
              <p className="text-slate-400 text-xs">{formatBytes(uploadState.file.size)}</p>
            </div>
          </div>
        )}
      </div>

      {uploadState.phase !== 'idle' && (
        <div className="space-y-3">
          
          <div className="flex items-center gap-2">
            <PhaseIcon phase={uploadState.phase} />
            <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${phaseBadge[uploadState.phase]}`}>
              {phaseLabel[uploadState.phase]}
            </span>
            {phaseMessage && (
              <span className="text-slate-400 text-xs truncate">{phaseMessage}</span>
            )}
          </div>

          <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
            <div
              className={[
                'h-full transition-all duration-300 rounded-full',
                uploadState.phase === 'complete' ? 'bg-green-500' :
                uploadState.phase === 'error' ? 'bg-red-500' : 'bg-cyan-500',
              ].join(' ')}
              style={{ width: `${uploadState.progress}%` }}
            />
          </div>

          <div className="flex justify-between text-xs text-slate-400">
            <span>{uploadState.progress}%</span>
            <span>
              {uploadState.chunks.filter((c) => c.status === 'done').length}
              {' / '}
              {uploadState.totalChunks} chunks
            </span>
            {uploadState.speed > 0 && <span>{formatSpeed(uploadState.speed)}</span>}
          </div>

          {uploadState.totalChunks > 1 && (
            <div className="flex flex-wrap gap-1">
              {uploadState.chunks.map((chunk) => (
                <div
                  key={chunk.index}
                  title={`Chunk ${chunk.index}: ${chunk.status}${chunk.retries > 0 ? ` (${chunk.retries} retries)` : ''}`}
                  className={`w-3 h-3 rounded-sm ${chunkColor(chunk.status)}`}
                />
              ))}
            </div>
          )}

          {uploadState.phase === 'error' && uploadState.errorMessage && (
            <div className="flex items-start gap-2 bg-red-950/40 border border-red-800 rounded-md p-3">
              <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-red-300 text-xs">{uploadState.errorMessage}</p>
            </div>
          )}

          {uploadState.phase === 'complete' && uploadState.result && (
            <div className="bg-green-950/30 border border-green-800 rounded-md p-4 space-y-2">
              <div className="flex items-center gap-2 text-green-400">
                <CheckCircle className="w-4 h-4" />
                <span className="text-sm font-medium">Upload réussi</span>
              </div>
              <div className="space-y-1 font-mono text-xs text-slate-300">
                <div className="flex gap-2">
                  <Shield className="w-3 h-3 text-slate-500 mt-0.5 flex-shrink-0" />
                  <span className="text-slate-500">MD5:</span>
                  <span className="break-all">{uploadState.result.hash_md5}</span>
                </div>
                <div className="flex gap-2">
                  <Shield className="w-3 h-3 text-slate-500 mt-0.5 flex-shrink-0" />
                  <span className="text-slate-500">SHA256:</span>
                  <span className="break-all">{uploadState.result.hash_sha256}</span>
                </div>
                <div className="text-slate-500">
                  Taille: {formatBytes(uploadState.result.fileSize)}
                </div>
              </div>
            </div>
          )}

          {(uploadState.phase === 'complete' || uploadState.phase === 'error') && (
            <button
              onClick={resetUpload}
              className="flex items-center gap-2 text-xs text-slate-400 hover:text-slate-200 transition-colors"
            >
              <RefreshCw className="w-3 h-3" />
              Nouvel upload
            </button>
          )}
        </div>
      )}
    </div>
  );
};

export default ChunkedUploader;
