// backend/src/services/ingestion/classifier.ts
import { SignalHit, detectMagic, detectPath, detectSniff } from './signals';
import { PARSER_VERSIONS } from './parserVersions';

export type EvidenceTypeContext = 'windows' | 'linux' | 'macos' | 'network' | 'memory' | 'other';
export type ClassificationInput = { relativePath: string; header: Buffer; evidenceType: EvidenceTypeContext };
export type ClassificationResult = {
  detectedType: string; parser: string | null; parserVersion: string | null;
  confidence: number; reasons: string[];
};

export const QUARANTINE_THRESHOLD = 50;

// The UI/`completeSchema` evidenceType vocabulary (backend/src/routes/upload.ts
// completeSchema; mirrored in frontend/src/components/upload/ChunkedUploader.tsx)
// is artifact-oriented: 'disk' | 'memory' | 'log' | 'network' | 'binary' |
// 'registry' | 'prefetch' | 'browser' | 'collection' | 'config' | 'text' | 'other'.
// It does NOT match EvidenceTypeContext's OS-oriented vocabulary above, so it
// must be translated before being used as the classifier's prior. Only values
// that unambiguously imply an OS/context are mapped; everything else (a 'disk'
// image can hold any OS, a 'log'/'collection'/'browser'/etc. upload likewise)
// maps to 'other', which makes classify() skip the prior entirely (see the
// `input.evidenceType !== 'other'` guard below) — no damping, no false
// quarantine for ambiguous uploads.
const UI_EVIDENCE_TYPE_TO_CONTEXT: Partial<Record<string, EvidenceTypeContext>> = {
  memory: 'memory',
  network: 'network',
  registry: 'windows',
  prefetch: 'windows',
};

export function toEvidenceTypeContext(raw: string): EvidenceTypeContext {
  return UI_EVIDENCE_TYPE_TO_CONTEXT[raw] ?? 'other';
}

// Which evidence-type context each artifact "belongs" to (for the prior).
const FAMILY: Record<string, EvidenceTypeContext> = {
  mft: 'windows', evtx: 'windows', prefetch: 'windows', webcache: 'windows', esedb: 'windows',
  bash: 'linux', syslog: 'linux', pcap: 'network', sqlite: 'other', csv: 'other', json: 'other',
};

export function classify(input: ClassificationInput): ClassificationResult {
  const hits: SignalHit[] = [];
  try {
    const m = detectMagic(input.header); if (m) hits.push(m);
    const p = detectPath(input.relativePath); if (p) hits.push(p);
    const s = detectSniff(input.header); if (s) hits.push(s);
  } catch {
    // Defensive: any detector blowing up must not fail ingestion.
  }

  if (hits.length === 0) {
    return { detectedType: 'unknown', parser: null, parserVersion: null, confidence: 0, reasons: ['no signal matched'] };
  }

  // Winner = highest-weight signal.
  hits.sort((a, b) => b.weight - a.weight);
  const winner = hits[0];
  const reasons = hits.map(h => `${h.source}: ${h.reason}`);

  let confidence = winner.weight;
  // Agreement boost: a second signal points at the same type.
  if (hits.some(h => h !== winner && h.detectedType === winner.detectedType)) {
    confidence = Math.min(100, confidence + 10);
    reasons.push('corroborated by a second signal');
  }
  // Evidence-type prior: matches the declared context → boost; mismatch → damp.
  const family = FAMILY[winner.detectedType];
  if (family && input.evidenceType !== 'other') {
    if (family === input.evidenceType) { confidence = Math.min(100, confidence + 5); reasons.push('matches evidence-type context'); }
    else { confidence = Math.max(0, confidence - 15); reasons.push('conflicts with evidence-type context'); }
  }

  if (confidence < QUARANTINE_THRESHOLD) {
    return { detectedType: 'unknown', parser: null, parserVersion: null, confidence, reasons };
  }
  return {
    detectedType: winner.detectedType, parser: winner.parser,
    parserVersion: PARSER_VERSIONS[winner.parser] ?? '0', confidence, reasons,
  };
}
