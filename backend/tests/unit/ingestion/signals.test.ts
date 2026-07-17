// backend/tests/unit/ingestion/signals.test.ts
import { detectMagic, detectPath, detectSniff } from '../../../src/services/ingestion/signals';

describe('detectMagic', () => {
  it('recognizes an MFT even when renamed', () => {
    const hit = detectMagic(Buffer.from('FILE0\x00\x00\x00', 'binary'));
    expect(hit).toMatchObject({ source: 'magic', detectedType: 'mft', parser: 'mft' });
  });
  it('recognizes an EVTX header', () => {
    expect(detectMagic(Buffer.from('ElfFile\x00'))!.detectedType).toBe('evtx');
  });
  it('returns null on unknown bytes', () => {
    expect(detectMagic(Buffer.from('random-noise'))).toBeNull();
  });
});

describe('detectPath', () => {
  it('matches evtx by extension', () => {
    expect(detectPath('C/Windows/winevt/Logs/System.evtx')!.detectedType).toBe('evtx');
  });
});

describe('detectSniff', () => {
  it('flags a CSV header line', () => {
    expect(detectSniff(Buffer.from('ts,host,event\n1,a,b\n'))!.detectedType).toBe('csv');
  });
});
