// Construction pure et testable de l'objet `raw` stocké à l'ingestion CSV→base.
// Extraite de collection.js streamNormalizeToDB pour que le contrat de données
// des détecteurs se teste sur fixtures.
//
// Depuis le 2026-09-15, ce module n'écarte plus aucune colonne : il part de la
// ligne entière et ajoute, pour les evtx seulement, les champs déduits du texte
// de charge utile. Le détail du plafond levé est en tête de `buildSlimRaw`.


const NETWORK_EVENT_IDS = new Set([3, 22, 5156, 5158]);

// Sysmon operational EventIDs whose payloads carry process/file/registry/cred/persistence
// fields. Enriched with DFIR-relevant IDs beyond the process basics:
//   6=driver load (BYOVD), 15=FileCreateStreamHash (ADS/MOTW), 17/18=named pipes (C2),
//   19/20/21=WMI filter/consumer/binding (persistence), 25=ProcessTampering (hollowing).
const SYSMON_EVENT_IDS = new Set([1, 3, 5, 6, 7, 8, 10, 11, 12, 13, 15, 17, 18, 19, 20, 21, 22, 23, 25]);

// Curated fields the detectors query today, plus the DFIR-high-value fields Phase 2 will use
// (GrantedAccess for LSASS, OriginalFileName/Company for masquerading, ImageLoaded for DLL
// sideloading, CallTrace for injection, PipeName for C2, Consumer/Filter/Query for WMI).
const SYSMON_FIELDS = [
  // process create (EID 1)
  'Image', 'CommandLine', 'ParentImage', 'ParentCommandLine', 'OriginalFileName',
  'CurrentDirectory', 'IntegrityLevel', 'Company', 'Product', 'Hashes',
  // process access / injection (EID 8, 10)
  'TargetImage', 'SourceImage', 'GrantedAccess', 'CallTrace', 'StartModule', 'StartFunction',
  // image load / DLL sideloading (EID 7)
  'ImageLoaded', 'Signed', 'Signature', 'SignatureStatus',
  // file / ADS (EID 11, 15)
  'TargetFilename',
  // registry (EID 12, 13)
  'TargetObject',
  // named pipes / C2 (EID 17, 18)
  'PipeName',
  // WMI persistence (EID 19, 20, 21)
  'Consumer', 'Filter', 'Query', 'Destination',
  // logon / network context
  'User', 'LogonId', 'LogonType', 'Protocol',
  'SourceIp', 'SourcePort', 'DestinationIp', 'DestinationPort', 'DestinationHostname', 'QueryName',
];
const SYSMON_FIELD_SET = new Set(SYSMON_FIELDS);

// EvtxECmd emits one "Key: value" per PayloadData column and dumps the rest into
// ExtraFieldInfo as "Key: value, Key2: value2". We parse line-by-line (PayloadData) and
// comma-split ExtraFieldInfo, keeping only known SYSMON_FIELDS — robust to values that
// contain spaces/colons (e.g. command lines) with no catastrophic backtracking.
// ⚠️ PROVISIONAL: the exact PayloadData/ExtraFieldInfo layout varies by EvtxECmd map;
// re-validate against a real collection (see spec).
function extractEvtxFields(clean) {
  const eventId = parseInt(clean['EventId'] || clean['EventID'] || '0', 10);
  if (!SYSMON_EVENT_IDS.has(eventId)) return {};
  const segments = [];
  for (let i = 1; i <= 6; i++) if (clean['PayloadData' + i]) segments.push(clean['PayloadData' + i]);
  if (clean['ExtraFieldInfo']) {
    // split only before a "Key:" boundary so values containing commas survive
    segments.push(...clean['ExtraFieldInfo'].split(/,(?=\s*[A-Za-z][A-Za-z0-9]*\s*[:=])/));
  }
  const out = {};
  for (const seg of segments) {
    const m = seg.match(/^\s*([A-Za-z][A-Za-z0-9]*)\s*[:=]\s*(.*?)\s*$/);
    if (!m) continue;
    const key = m[1];
    const val = m[2];
    if (SYSMON_FIELD_SET.has(key) && val && val !== '-' && out[key] === undefined) out[key] = val;
  }
  return out;
}

// Toute colonne qu'un outil a su extraire de la preuve arrive en base. Le nom
// de cette fonction est resté celui d'avant le 2026-09-15, date à laquelle le
// plafond a été levé ; elle n'amincit plus rien, elle enrichit.
//
// Ce qu'il y avait avant : les 15 premières colonnes dans l'ordre du CSV, plus
// une liste blanche. Deux défauts en découlaient, invisibles à l'écran —
//   · la survie d'un champ dépendait de sa POSITION dans la sortie de l'outil.
//     `Arguments` passait dans un jumplist et tombait dans un LNK, pour la
//     seule raison que LECmd le met en 19ᵉ colonne.
//   · la liste blanche demandait à être étendue à chaque champ nouvellement
//     utile, et l'absence ne se découvrait qu'au moment d'en avoir besoin.
//
// Mesuré avant de lever : les artefacts Windows à colonnes larges pèsent 5 181
// lignes pour 2,8 Mo de `raw`. Le plafond ne bornait pas ce qui coûte cher.
function buildSlimRaw(clean, artifactType) {
  const slimRaw = { ...clean };

  if (artifactType === 'evtx') {
    const eventId = parseInt(clean['EventId'] || clean['EventID'] || '0', 10);
    if (NETWORK_EVENT_IDS.has(eventId)) {
      const payload = [
        clean['PayloadData1'] || '', clean['PayloadData2'] || '',
        clean['PayloadData3'] || '', clean['PayloadData4'] || '',
      ].join(' ');
      const dstIpM = payload.match(/Destination(?:Ip|Address|\ Address)[:\s]+(\d{1,3}(?:\.\d{1,3}){3})/i);
      if (dstIpM) slimRaw['DstIP'] = dstIpM[1];
      const dstPortM = payload.match(/Destination(?:Port|\ Port)[:\s]+(\d+)/i);
      if (dstPortM) slimRaw['DstPort'] = dstPortM[1];
      const hostM = payload.match(/(?:DestinationHostname|QueryName)[:\s]+([^\s,;]+)/i);
      if (hostM && hostM[1] !== '-') slimRaw['dst_host'] = hostM[1];
    }
    // Class B: named Sysmon fields from the payload text — never overwrite a real column.
    const extracted = extractEvtxFields(clean);
    for (const [k, v] of Object.entries(extracted)) {
      if (slimRaw[k] === undefined) slimRaw[k] = v;
    }
  }
  return slimRaw;
}

module.exports = { NETWORK_EVENT_IDS, SYSMON_EVENT_IDS, buildSlimRaw, extractEvtxFields };
