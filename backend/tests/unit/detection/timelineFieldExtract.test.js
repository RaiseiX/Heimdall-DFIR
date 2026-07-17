const { CRITICAL_FIELDS, buildSlimRaw } = require('../../../src/services/timelineFieldExtract');
const { extractEvtxFields } = require('../../../src/services/timelineFieldExtract');

// Build an ordered object with N synthetic columns col0..colN-1
function orderedRow(n, overrides = {}) {
  const o = {};
  for (let i = 0; i < n; i++) o[`col${i}`] = `v${i}`;
  return { ...o, ...overrides };
}

describe('buildSlimRaw — current behavior (characterization)', () => {
  test('keeps the first 15 columns', () => {
    const raw = buildSlimRaw(orderedRow(20), 'mft');
    expect(Object.keys(raw)).toContain('col0');
    expect(Object.keys(raw)).toContain('col14');
    expect(raw.col0).toBe('v0');
  });

  test('drops a column beyond 15 that is not in CRITICAL_FIELDS', () => {
    const raw = buildSlimRaw(orderedRow(20), 'mft');
    expect(raw).not.toHaveProperty('col15');
    expect(raw).not.toHaveProperty('col19');
  });

  test('keeps a column beyond 15 that IS in CRITICAL_FIELDS', () => {
    // FileName is in the allowlist; place it at position 18
    const row = orderedRow(18);
    row['FileName'] = 'evil.exe'; // 19th key, beyond 15
    const raw = buildSlimRaw(row, 'mft');
    expect(raw.FileName).toBe('evil.exe');
  });

  test('evtx network event (EventID 3) still extracts DstIP/DstPort/dst_host', () => {
    const clean = {
      EventId: '3',
      PayloadData1: 'SourceIp: 10.0.0.5',
      PayloadData2: 'DestinationIp: 93.184.216.34 DestinationPort: 443',
      PayloadData3: 'DestinationHostname: evil.example.com',
      PayloadData4: '',
    };
    const raw = buildSlimRaw(clean, 'evtx');
    expect(raw.DstIP).toBe('93.184.216.34');
    expect(raw.DstPort).toBe('443');
    expect(raw.dst_host).toBe('evil.example.com');
  });

  test('CRITICAL_FIELDS is a Set containing the known baseline fields', () => {
    expect(CRITICAL_FIELDS.has('ExtraFieldInfo')).toBe(true);
    expect(CRITICAL_FIELDS.has('EventID')).toBe(true);
    expect(CRITICAL_FIELDS.has('PayloadData1')).toBe(true);
  });
});

describe('buildSlimRaw — Class A (forensic fields survive slimming)', () => {
  // MFTECmd row where the $FN/$SI timestamps appear well beyond column 15
  function mftRow() {
    const row = {};
    // first 15 columns (typical MFTECmd head, positions 0-14)
    ['EntryNumber','SequenceNumber','InUse','ParentEntryNumber','ParentSequenceNumber',
     'InUse2','ParentPath','FileName','Extension','FileSize','ReferenceCount',
     'ReparseTarget','IsDirectory','HasAds','IsAds'].forEach((k,i)=>{ row[k] = `v${i}`; });
    // beyond column 15 — the timestomping-relevant fields
    row['SI<FN']            = 'true';
    row['Created0x10']      = '2021-06-01 10:00:00.0000000';
    row['Created0x30']      = '2023-06-01 10:00:00.0000000';
    row['LastModified0x10'] = '2021-06-01 10:00:00.0000000';
    row['LastModified0x30'] = '2023-06-01 10:00:00.0000000';
    row['LastAccess0x10']   = '2021-06-01 10:00:00.0000000';
    return row;
  }

  test('MFT timestomping timestamps survive the slim', () => {
    const raw = buildSlimRaw(mftRow(), 'mft');
    expect(raw.Created0x10).toBe('2021-06-01 10:00:00.0000000');
    expect(raw.Created0x30).toBe('2023-06-01 10:00:00.0000000');
    expect(raw.LastModified0x10).toBeDefined();
    expect(raw.LastModified0x30).toBeDefined();
    expect(raw.LastAccess0x10).toBeDefined();
    expect(raw['SI<FN']).toBe('true');
  });

  test('vuln-drivers amcache fields survive the slim', () => {
    const row = {};
    for (let i = 0; i < 15; i++) row[`c${i}`] = `v${i}`;
    row['DriverName'] = 'evil.sys';
    row['DriverId']   = 'abc123';
    row['SignatureStatus'] = 'Expired';
    row['Signed'] = 'False';
    const raw = buildSlimRaw(row, 'amcache');
    expect(raw.DriverName).toBe('evil.sys');
    expect(raw.DriverId).toBe('abc123');
    expect(raw.SignatureStatus).toBe('Expired');
    expect(raw.Signed).toBe('False');
  });
});

describe('extractEvtxFields — Class B (Sysmon fields from payload)', () => {
  test('process-create (EventID 1) yields Image + CommandLine + ParentImage', () => {
    const clean = {
      EventId: '1',
      PayloadData1: 'Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      PayloadData2: 'CommandLine: powershell.exe -enc SQBFAFgA',
      PayloadData3: 'ParentImage: C:\\Windows\\explorer.exe',
      ExtraFieldInfo: 'User: CORP\\admin, IntegrityLevel: High',
    };
    const f = extractEvtxFields(clean);
    expect(f.Image).toBe('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
    expect(f.CommandLine).toBe('powershell.exe -enc SQBFAFgA');
    expect(f.ParentImage).toBe('C:\\Windows\\explorer.exe');
    expect(f.User).toBe('CORP\\admin');
  });

  test('process-access (EventID 10) yields TargetImage + GrantedAccess + CallTrace (LSASS/mimikatz)', () => {
    const clean = {
      EventId: '10',
      PayloadData1: 'SourceImage: C:\\Temp\\mimikatz.exe',
      PayloadData2: 'TargetImage: C:\\Windows\\System32\\lsass.exe',
      PayloadData3: 'GrantedAccess: 0x1410',
      ExtraFieldInfo: 'CallTrace: C:\\Windows\\SYSTEM32\\ntdll.dll+9d2e4|UNKNOWN(0x7ff0), User: CORP\\admin',
    };
    const f = extractEvtxFields(clean);
    expect(f.TargetImage).toBe('C:\\Windows\\System32\\lsass.exe');
    expect(f.SourceImage).toBe('C:\\Temp\\mimikatz.exe');
    expect(f.GrantedAccess).toBe('0x1410');       // the field that distinguishes mimikatz from benign lsass access
    expect(f.CallTrace).toContain('ntdll.dll');
    expect(f.User).toBe('CORP\\admin');
  });

  test('file-create (EventID 11) yields TargetFilename', () => {
    const clean = { EventId: '11', PayloadData1: 'TargetFilename: C:\\Users\\Public\\evil.dll' };
    const f = extractEvtxFields(clean);
    expect(f.TargetFilename).toBe('C:\\Users\\Public\\evil.dll');
  });

  test('image-load (EventID 7) yields ImageLoaded + signature (DLL sideloading)', () => {
    const clean = {
      EventId: '7',
      PayloadData1: 'ImageLoaded: C:\\Users\\Public\\evil.dll',
      PayloadData2: 'Signed: false',
      PayloadData3: 'SignatureStatus: Unavailable',
    };
    const f = extractEvtxFields(clean);
    expect(f.ImageLoaded).toBe('C:\\Users\\Public\\evil.dll');
    expect(f.Signed).toBe('false');
    expect(f.SignatureStatus).toBe('Unavailable');
  });

  test('named-pipe (EventID 17) yields PipeName (C2 pattern)', () => {
    const clean = { EventId: '17', PayloadData1: 'PipeName: \\msagent_42' };
    const f = extractEvtxFields(clean);
    expect(f.PipeName).toBe('\\msagent_42');
  });

  test('command line containing spaces/commas is captured whole (line-parser, not per-field regex)', () => {
    const clean = { EventId: '1', PayloadData1: 'CommandLine: rundll32 shell32.dll,Control_RunDLL evil.cpl' };
    const f = extractEvtxFields(clean);
    expect(f.CommandLine).toBe('rundll32 shell32.dll,Control_RunDLL evil.cpl');
  });

  test('non-Sysmon evtx event (EventID 4624) extracts nothing process-related', () => {
    const clean = { EventId: '4624', PayloadData1: 'LogonType: 3' };
    const f = extractEvtxFields(clean);
    expect(f.Image).toBeUndefined();
    expect(f.CommandLine).toBeUndefined();
  });

  test('buildSlimRaw merges extracted fields without overwriting real columns', () => {
    const clean = {
      EventId: '1',
      PayloadData1: 'Image: C:\\a.exe',
      // a real column literally named CommandLine must NOT be overwritten by extraction
      CommandLine: 'REAL-COLUMN-VALUE',
      PayloadData2: 'CommandLine: SHOULD-NOT-WIN',
    };
    const raw = buildSlimRaw(clean, 'evtx');
    expect(raw.Image).toBe('C:\\a.exe');       // extracted (no real column)
    expect(raw.CommandLine).toBe('REAL-COLUMN-VALUE'); // real column preserved
  });

  test('network extraction still works after adding Sysmon extraction (non-regression)', () => {
    const clean = { EventId: '3', PayloadData2: 'DestinationIp: 1.2.3.4 DestinationPort: 80' };
    const raw = buildSlimRaw(clean, 'evtx');
    expect(raw.DstIP).toBe('1.2.3.4');
    expect(raw.DstPort).toBe('80');
  });
});
