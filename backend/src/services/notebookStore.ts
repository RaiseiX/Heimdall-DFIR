/** Le carnet borne sa taille pour rester un carnet, pas une decharge. */
export const NOTEBOOK_MAX = 200_000;

export function ensureNotebookTableSql(): string {
  return `
    CREATE TABLE IF NOT EXISTS case_notebooks (
      case_id    UUID PRIMARY KEY REFERENCES cases(id) ON DELETE CASCADE,
      content    TEXT NOT NULL DEFAULT '',
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    ALTER TABLE case_notebooks ADD COLUMN IF NOT EXISTS ydoc BYTEA`;
}

export function loadNotebookDocSql(): string {
  return `SELECT content, ydoc FROM case_notebooks WHERE case_id = $1`;
}

export function saveNotebookDocSql(): string {
  return `
    INSERT INTO case_notebooks (case_id, content, ydoc, updated_by, updated_at)
    VALUES ($1, $2, $3, $4, NOW())
    ON CONFLICT (case_id) DO UPDATE
      SET content    = EXCLUDED.content,
          ydoc       = EXCLUDED.ydoc,
          updated_by = COALESCE(EXCLUDED.updated_by, case_notebooks.updated_by),
          updated_at = NOW()
    RETURNING updated_at`;
}

export function getNotebookSql(): string {
  return `
    SELECT n.content, n.updated_at, u.full_name AS updated_by_name
      FROM case_notebooks n
      LEFT JOIN users u ON u.id = n.updated_by
     WHERE n.case_id = $1`;
}
