// backend/tests/unit/ingestion/classifier.test.ts
import { classify, QUARANTINE_THRESHOLD, toEvidenceTypeContext } from '../../../src/services/ingestion/classifier';

const win = (relativePath: string, header = Buffer.alloc(0)) =>
  classify({ relativePath, header, evidenceType: 'windows' as const });

describe('classify', () => {
  it('trusts magic bytes over a misleading name', () => {
    const r = win('export_final.bin', Buffer.from('FILE0\x00'));
    expect(r.detectedType).toBe('mft');
    expect(r.confidence).toBeGreaterThanOrEqual(QUARANTINE_THRESHOLD);
  });

  it('falls back to path when there is no magic', () => {
    const r = win('C/Windows/winevt/Logs/System.evtx');
    expect(r.detectedType).toBe('evtx');
  });

  it('quarantines low-confidence unknown files', () => {
    const r = win('notes/random.dat', Buffer.from('\x00\x01\x02\x03'));
    expect(r.detectedType).toBe('unknown');
    expect(r.parser).toBeNull();
  });

  it('never throws on a corrupt/empty buffer', () => {
    expect(() => win('x', Buffer.alloc(0))).not.toThrow();
  });

  // FIX D regression test: the UI's artifact-oriented evidenceType ('disk')
  // is ambiguous w.r.t. OS, and must NOT be used as-is as the classifier's
  // OS-oriented prior context — doing so previously damped confidence for a
  // real Windows MFT on the most common DFIR upload type (a disk image) and
  // wrongly quarantined it. toEvidenceTypeContext('disk') must map to
  // 'other', which classify() treats as "skip the prior" (see the
  // `input.evidenceType !== 'other'` guard in classifier.ts).
  it('does not quarantine a Windows MFT (path-only detection) on an ambiguous "disk" upload', () => {
    const r = classify({
      relativePath: 'C/$MFT',
      header: Buffer.alloc(0), // no magic bytes — path-only detection (weight 60)
      evidenceType: toEvidenceTypeContext('disk'),
    });
    expect(r.detectedType).toBe('mft');
    expect(r.parser).toBe('mft');
    expect(r.confidence).toBeGreaterThanOrEqual(QUARANTINE_THRESHOLD);
  });
});

describe('toEvidenceTypeContext', () => {
  it('maps unambiguous UI evidence types to their OS/context', () => {
    expect(toEvidenceTypeContext('memory')).toBe('memory');
    expect(toEvidenceTypeContext('network')).toBe('network');
    expect(toEvidenceTypeContext('registry')).toBe('windows');
    expect(toEvidenceTypeContext('prefetch')).toBe('windows');
  });

  it('maps every ambiguous UI evidence type to other', () => {
    for (const raw of ['disk', 'log', 'binary', 'browser', 'collection', 'config', 'text', 'other']) {
      expect(toEvidenceTypeContext(raw)).toBe('other');
    }
  });

  it('maps an unknown/garbage value to other (safe default)', () => {
    expect(toEvidenceTypeContext('bogus')).toBe('other');
  });
});
