-- ─── catscale_state: point-in-time host state from a CatScale collection ─────
--
-- A CatScale collection is ~158 files, and most of them are *state*, not events:
-- lsof (525k lines on a real host), kernel module hashes, loaded modules,
-- iptables rules, installed packages, /proc/<pid>/exe links. They have no
-- timestamp of their own — only the collection time — so forcing them into
-- collection_timeline would stack hundreds of thousands of rows on a single
-- second and make the timeline unusable, on top of the volume problem.
--
-- They still matter: a deleted-but-running binary, a tampered package or an
-- unexpected kernel module are prime Linux IR findings. So they live here,
-- searchable and correlatable, and the detection layer promotes a *finding*
-- into collection_timeline rather than the raw inventory.

CREATE TABLE IF NOT EXISTS catscale_state (
    id            BIGSERIAL   PRIMARY KEY,
    case_id       UUID        NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id   UUID        REFERENCES evidence(id) ON DELETE CASCADE,
    result_id     UUID        REFERENCES parser_results(id) ON DELETE CASCADE,
    host_name     TEXT        NOT NULL DEFAULT '',
    collected_at  TIMESTAMPTZ NOT NULL,
    -- artifact family: 'lsof', 'kernel_module', 'package_verify', 'proc_exe',
    -- 'docker_container', 'docker_image', 'network_config', ...
    kind          VARCHAR(64) NOT NULL,
    source_file   TEXT        NOT NULL DEFAULT '',
    -- primary human-readable key: a path, a module name, a container id
    label         TEXT        NOT NULL DEFAULT '',
    raw           JSONB       NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cs_state_case_kind
    ON catscale_state(case_id, kind);
CREATE INDEX IF NOT EXISTS idx_cs_state_case_host
    ON catscale_state(case_id, host_name);
CREATE INDEX IF NOT EXISTS idx_cs_state_evidence
    ON catscale_state(evidence_id) WHERE evidence_id IS NOT NULL;
-- Prefix search on paths and module names ("/tmp/%", "docker-%").
CREATE INDEX IF NOT EXISTS idx_cs_state_label
    ON catscale_state(case_id, label text_pattern_ops);
-- Key-existence and containment lookups over the per-artifact fields, the same
-- access pattern idx_ct_raw_gin serves on collection_timeline.
CREATE INDEX IF NOT EXISTS idx_cs_state_raw_gin
    ON catscale_state USING GIN (raw);
