// Single source of truth for "which OS platform does this artifact type
// belong to." Two independent consumers read it, at two different times:
//
//  - collection.js, AT IMPORT, tags each *detected* artifact type (the
//    ARTIFACT_PATTERNS key: 'evtx', 'prefetch', 'mft', ...) so the collection's
//    platform can be persisted onto parser_results.platform (Task 2 of
//    docs/superpowers/plans/2026-08-07-sigma-platform-scoping-and-honest-counts.md).
//
//  - threatHunting.ts, AT HUNT TIME, derives the SET of platforms present in a
//    case's collection_timeline (Task 3 of the same plan), so a Sigma hunt
//    only evaluates rules that can possibly match. collection_timeline rows
//    use the same artifact-type vocabulary, PLUS the catscale_* family
//    (catscale_fstimeline, catscale_auth, catscale_process, ...) — CatScale
//    writes one row per artifact kind into the timeline, finer-grained than
//    the single 'catscale' key this map (and the frontend map it mirrors)
//    uses for the whole-archive detection at import time. Every member of
//    that family is Linux, handled by platformForArtifactType() below rather
//    than by enumerating every catscale_* suffix here.
//
// ARTIFACT_TYPE_PLATFORM started as a key-for-key copy of the frontend's
// ARTIFACT_PATTERNS platform fields (frontend/src/components/collection/
// CollectionImportPanel.jsx) — that import-time set. There is no build-time
// sharing between frontend and backend in this repo, so keep the two in sync
// by hand for that shared subset.
//
// It has since grown entries the frontend map does not carry, because the two
// answer different questions: the frontend tags a *collection at import*,
// this module also scopes a *hunt against collection_timeline rows already on
// disk*, and the timeline vocabulary is wider (EVTX-hunting tools write their
// own artifact_type, not 'evtx'):
//   - hayabusa  — Hayabusa parses Windows EVTX (collection.js sets
//                 artifact_type: 'hayabusa' explicitly; also queried
//                 alongside 'evtx' throughout detectionVectors.js/cases.js).
//   - sysmon    — Sysmon is a Windows kernel driver; its events are Windows
//                 EVTX under the hood. Queried defensively alongside 'evtx'
//                 in detectionVectors.js/cases.js even though no current
//                 write path tags a row 'sysmon' distinctly from 'evtx' —
//                 mapping it costs nothing and closes the gap if/when one
//                 does.
//   - chainsaw  — backend/config/timeline_mappings/chainsaw.yaml maps
//                 Chainsaw's `--csv` detections output (header signature
//                 includes Event.System.Channel/EventID/Computer) into
//                 collection_timeline with artifact_type: 'chainsaw'.
//                 Chainsaw, like Hayabusa, only ever hunts Windows EVTX.
//
// Deliberately NOT added here (found while auditing every collection_timeline
// writer for this task, listed so the gap doesn't get rediscovered):
//   - 'csv' (backend/config/timeline_mappings/generic_csv.yaml) — the
//     catch-all fallback mapping for arbitrary analyst-supplied CSVs with no
//     tool-specific mapping. It carries no OS signal at all; guessing a
//     platform for it would be worse than leaving it unmapped (which
//     correctly contributes nothing to the derived set rather than a wrong
//     platform).
//   - 'DNS' / 'HTTP' / 'TLS' / 'NetworkConnection' (backend/src/routes/
//     collection.js's PCAP import, ~l. 3658-3697) — protocol/network-flow
//     rows derived from packet capture, not a host artifact; a capture can
//     span hosts of any OS (or none), so there is no single platform to
//     assign. Note these are also a different, mixed-case vocabulary from
//     the lowercase 'dns' key below (Windows DNS *server* debug logs, a
//     genuine Windows host artifact) — a coincidence of naming, not the same
//     data, and left as-is since assigning either a platform here would be
//     the same unjustified guess.
const ARTIFACT_TYPE_PLATFORM = {
  evtx: 'windows', prefetch: 'windows', mft: 'windows', usn: 'windows', indx: 'windows',
  lnk: 'windows', registry: 'windows', userassist: 'windows', netprofile: 'windows',
  usb: 'windows', schtasks: 'windows', pwsh: 'windows', dns: 'windows', webcache: 'windows',
  pcap: 'windows', wmi: 'windows', rdpcache: 'windows', amcache: 'windows', shellbags: 'windows',
  jumplist: 'windows', srum: 'windows', recycle: 'windows', sum: 'windows', sqle: 'windows',
  wxtcmd: 'windows', appcompat: 'windows', bits: 'windows',
  hayabusa: 'windows', sysmon: 'windows', chainsaw: 'windows',
  auditd: 'linux', syslog: 'linux', bash_history: 'linux',
  unified_log: 'macos',
};

// The platform for a single collection_timeline.artifact_type value (or an
// ARTIFACT_PATTERNS key at import time — both vocabularies are accepted).
// Returns null for anything unrecognised: never a default, never a guess.
function platformForArtifactType(artifactType) {
  if (typeof artifactType !== 'string' || !artifactType) return null;
  if (artifactType.startsWith('catscale_')) return 'linux';
  return ARTIFACT_TYPE_PLATFORM[artifactType] || null;
}

module.exports = { ARTIFACT_TYPE_PLATFORM, platformForArtifactType };
