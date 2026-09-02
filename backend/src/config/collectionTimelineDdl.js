// Runtime safety net for collection_timeline.
//
// db/init.sql is the canonical schema, but it only runs on the *first*
// initialisation of an empty volume; db/migrations/ covers upgrades. This list
// re-asserts the shape the ingestion code depends on, so a deployment whose
// volume predates a column still gets it.
//
// Ordering is load-bearing. The previous version ran these inside a Promise.all,
// which raced: `CREATE INDEX ... (case_id, tool)` could start before
// `ADD COLUMN tool`. Columns first, then indexes, then type widening.
const COLLECTION_TIMELINE_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS collection_timeline (
     id            BIGSERIAL PRIMARY KEY,
     case_id       UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
     result_id     UUID REFERENCES parser_results(id) ON DELETE CASCADE,
     evidence_id   UUID REFERENCES evidence(id) ON DELETE CASCADE,
     -- Nullable: inventory rows (timestamp_kind = 'inventory') carry no date of
     -- their own. See db/migrations/20260818150000_collection_timeline_nullable_timestamp.sql
     -- — that migration is what converts an *existing* table; this CREATE only
     -- shapes a table born from this file, since the guarded batch below skips
     -- when every expected column is already present.
     timestamp     TIMESTAMPTZ,
     artifact_type VARCHAR(50)  NOT NULL DEFAULT '',
     artifact_name VARCHAR(100) NOT NULL DEFAULT '',
     description   TEXT         NOT NULL DEFAULT '',
     source        VARCHAR(200) NOT NULL DEFAULT '',
     raw           JSONB        NOT NULL DEFAULT '{}',
     created_at    TIMESTAMPTZ  DEFAULT NOW()
   )`,

  `ALTER TABLE collection_timeline ADD COLUMN IF NOT EXISTS evidence_id UUID REFERENCES evidence(id) ON DELETE CASCADE`,
  `ALTER TABLE collection_timeline ADD COLUMN IF NOT EXISTS source_device VARCHAR(256)`,

  // ECS columns (v2.13). Present in init.sql but absent from the CREATE TABLE
  // above, so a table born from this file lacked six columns the INSERT writes.
  `ALTER TABLE collection_timeline
     ADD COLUMN IF NOT EXISTS host_name            TEXT,
     ADD COLUMN IF NOT EXISTS user_name            TEXT,
     ADD COLUMN IF NOT EXISTS process_name         TEXT,
     ADD COLUMN IF NOT EXISTS mitre_technique_id   VARCHAR(20),
     ADD COLUMN IF NOT EXISTS mitre_technique_name VARCHAR(200),
     ADD COLUMN IF NOT EXISTS mitre_tactic         VARCHAR(64)`,

  // v2.23 — unified forensic columns (inspired by forensic-timeliner)
  `ALTER TABLE collection_timeline
     ADD COLUMN IF NOT EXISTS tool           VARCHAR(32),
     ADD COLUMN IF NOT EXISTS timestamp_kind VARCHAR(64),
     ADD COLUMN IF NOT EXISTS details        TEXT,
     ADD COLUMN IF NOT EXISTS "path"         TEXT,
     ADD COLUMN IF NOT EXISTS ext            VARCHAR(16),
     ADD COLUMN IF NOT EXISTS event_id       INTEGER,
     ADD COLUMN IF NOT EXISTS file_size      BIGINT,
     ADD COLUMN IF NOT EXISTS src_ip         INET,
     ADD COLUMN IF NOT EXISTS dst_ip         INET,
     ADD COLUMN IF NOT EXISTS sha1           CHAR(40),
     ADD COLUMN IF NOT EXISTS tags           TEXT[] NOT NULL DEFAULT '{}',
     ADD COLUMN IF NOT EXISTS dedupe_hash    CHAR(16)`,

  // v2.26 — per-row threat engine detections
  `ALTER TABLE collection_timeline ADD COLUMN IF NOT EXISTS detections JSONB`,

  `CREATE INDEX IF NOT EXISTS idx_ct_case_ts    ON collection_timeline(case_id, timestamp)`,

  // La grille ouvre sur `timestamp DESC NULLS LAST, id DESC`. Un parcours arriere de
  // idx_ct_case_ts, declare ASC NULLS LAST, rend DESC NULLS FIRST — jamais NULLS LAST,
  // et Postgres ne deduit pas l'equivalence meme quand le filtre exclut les NULL.
  // Faute de cet index la vue par defaut balayait la table entiere : mesure le
  // 2026-08-26 sur 2 978 351 lignes, 367 809 blocs lus et 4 639 ms, contre 270 blocs
  // et 0,75 ms avec lui. Le NULLS LAST reste une decision — un objet d'inventaire est
  // dans la vue et atteignable, jamais devant une ligne datee.
  `CREATE INDEX IF NOT EXISTS idx_ct_case_ts_desc ON collection_timeline(case_id, timestamp DESC NULLS LAST, id DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_ct_case_type  ON collection_timeline(case_id, artifact_type)`,
  `CREATE INDEX IF NOT EXISTS idx_ct_result     ON collection_timeline(result_id)`,
  `CREATE INDEX IF NOT EXISTS idx_ct_evidence   ON collection_timeline(evidence_id)`,
  `CREATE INDEX IF NOT EXISTS idx_ct_case_ev_ts ON collection_timeline(case_id, evidence_id, timestamp)`,
  `CREATE INDEX IF NOT EXISTS idx_ct_case_tool     ON collection_timeline(case_id, tool)     WHERE tool     IS NOT NULL`,
  `CREATE INDEX IF NOT EXISTS idx_ct_case_event_id ON collection_timeline(case_id, event_id) WHERE event_id IS NOT NULL`,
  `CREATE INDEX IF NOT EXISTS idx_ct_case_ext      ON collection_timeline(case_id, ext)      WHERE ext      IS NOT NULL`,
  `CREATE INDEX IF NOT EXISTS idx_ct_case_sha1     ON collection_timeline(case_id, sha1)     WHERE sha1     IS NOT NULL`,
  `CREATE UNIQUE INDEX IF NOT EXISTS uq_ct_case_dedupe ON collection_timeline(case_id, dedupe_hash) WHERE dedupe_hash IS NOT NULL`,
  `CREATE INDEX IF NOT EXISTS idx_ct_detections ON collection_timeline(case_id) WHERE detections IS NOT NULL`,

  // EVTX and other artifacts carry values longer than the legacy varchar caps; a
  // single overflow fails the whole UNNEST batch (pg 22001) → 0 rows. Metadata-only
  // change, so it is cheap even on a large table.
  `ALTER TABLE collection_timeline
     ALTER COLUMN host_name     TYPE text,
     ALTER COLUMN user_name     TYPE text,
     ALTER COLUMN source_device TYPE text,
     ALTER COLUMN process_name  TYPE text`,
];

// Every column the statements above are responsible for adding. When all of them
// are already present the batch has nothing to do, and running it anyway would
// take an ACCESS EXCLUSIVE lock for no reason — which, on a busy database, is how
// a no-op migration ends up disabling ingestion.
const COLLECTION_TIMELINE_EXPECTED_COLUMNS = [
  'evidence_id', 'source_device',
  'host_name', 'user_name', 'process_name',
  'mitre_technique_id', 'mitre_technique_name', 'mitre_tactic',
  'tool', 'timestamp_kind', 'details', 'path', 'ext', 'event_id', 'file_size',
  'src_ip', 'dst_ip', 'sha1', 'tags', 'dedupe_hash', 'detections',
];

module.exports = { COLLECTION_TIMELINE_STATEMENTS, COLLECTION_TIMELINE_EXPECTED_COLUMNS };
