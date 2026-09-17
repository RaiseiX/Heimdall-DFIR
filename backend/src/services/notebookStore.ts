// Le carnet d'enquête, côté données.
//
// ── Il n'avait jamais fonctionné ────────────────────────────────────────────
//
// Mesure du 2026-09-17 : la table `case_notebooks` n'existait pas en base, et
// sa definition ne POUVAIT pas etre creee. Elle declarait
//
//   case_id INTEGER PRIMARY KEY REFERENCES cases(id)
//
// alors que `cases.id` est un uuid. Postgres refuse la contrainte :
//
//   Key columns "case_id" and "id" are of incompatible types: integer and uuid
//
// `ensureTable()` levait donc a chaque requete, lecture comme ecriture. Le
// panneau avalait l'erreur (`catch (_e) {}`) : l'analyste voyait un carnet
// vide, ecrivait ses notes, lisait « non enregistre » sans explication, et les
// perdait en quittant la page.
//
// Confirmation independante : `audit_log` comptait **zero** entree
// `save_notebook` depuis la creation du produit.
//
// ── Pourquoi l'ajout est atomique ───────────────────────────────────────────
//
// Le carnet est UN bloc de texte que le PUT remplace en entier. Deposer une
// trouvaille depuis un onglet d'analyse en relisant puis reecrivant ecraserait
// ce qu'un autre onglet — ou un autre analyste — a ecrit entre-temps. En DFIR,
// perdre une note d'enquete est pire que ne pas pouvoir en prendre.
//
// L'ajout se fait donc en UNE instruction, cote serveur, et deux ajouts
// simultanes sont tous deux conserves.

/** Le carnet borne sa taille pour rester un carnet, pas une decharge. */
export const NOTEBOOK_MAX = 200_000;

export function ensureNotebookTableSql(): string {
  return `
    CREATE TABLE IF NOT EXISTS case_notebooks (
      case_id    UUID PRIMARY KEY REFERENCES cases(id) ON DELETE CASCADE,
      content    TEXT NOT NULL DEFAULT '',
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )`;
}

export function getNotebookSql(): string {
  return `
    SELECT n.content, n.updated_at, u.full_name AS updated_by_name
      FROM case_notebooks n
      LEFT JOIN users u ON u.id = n.updated_by
     WHERE n.case_id = $1`;
}

export function saveNotebookSql(): string {
  return `
    INSERT INTO case_notebooks (case_id, content, updated_by, updated_at)
    VALUES ($1, left($2, ${NOTEBOOK_MAX}), $3, NOW())
    ON CONFLICT (case_id) DO UPDATE
      SET content    = EXCLUDED.content,
          updated_by = EXCLUDED.updated_by,
          updated_at = NOW()
    RETURNING updated_at`;
}

/**
 * Ajoute un bloc a la fin du carnet, sans le relire.
 *
 * Le separateur n'est pose que si le carnet contient deja quelque chose, et un
 * ajout vide ne laisse pas de ligne blanche orpheline. Le plafond s'applique
 * ici AUSSI : un plafond que l'ajout contourne ne borne rien.
 */
export function appendNotebookSql(): string {
  return `
    INSERT INTO case_notebooks (case_id, content, updated_by, updated_at)
    VALUES ($1, left($2, ${NOTEBOOK_MAX}), $3, NOW())
    ON CONFLICT (case_id) DO UPDATE
      SET content = left(
            CASE
              WHEN EXCLUDED.content = ''      THEN case_notebooks.content
              WHEN case_notebooks.content = '' THEN EXCLUDED.content
              ELSE case_notebooks.content || E'\\n\\n' || EXCLUDED.content
            END, ${NOTEBOOK_MAX}),
          updated_by = EXCLUDED.updated_by,
          updated_at = NOW()
    RETURNING updated_at`;
}
