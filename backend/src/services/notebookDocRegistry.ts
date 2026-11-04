import * as Y from 'yjs';
import { Pool } from 'pg';
import { createDocRegistry, DocRegistry } from './yDocRegistry';
import {
  loadNotebookDocSql, saveNotebookDocSql, getNotebookSql, NOTEBOOK_MAX,
} from './notebookStore';

export const TEXTE = 'carnet';

type Audit = (userId: string, action: string, type: string, id: string, details: Record<string, unknown>, ip: string | null) => unknown;

export class NotebookError extends Error {
  constructor(public code: 'TROP_LONG' | 'VERSION_PERIMEE' | 'VIDE', message: string) {
    super(message);
  }
}

export function separer(existant: string, bloc: string): string {
  if (!existant) return bloc;
  return existant.endsWith('\n\n') ? bloc : existant.endsWith('\n') ? `\n${bloc}` : `\n\n${bloc}`;
}

export function createNotebookRegistry({ audit, debounceMs }: { audit?: Audit; debounceMs?: number } = {}) {
  const registre: DocRegistry = createDocRegistry({
    async load(pool, caseId) {
      const doc = new Y.Doc();
      const { rows: [ligne] } = await pool.query(loadNotebookDocSql(), [caseId]);
      if (ligne?.ydoc) Y.applyUpdate(doc, new Uint8Array(ligne.ydoc), 'db');
      else if (ligne?.content) doc.getText(TEXTE).insert(0, ligne.content);
      return doc;
    },
    async save(pool, caseId, doc, meta) {
      const texte = doc.getText(TEXTE).toString();
      await pool.query(saveNotebookDocSql(), [caseId, texte, Buffer.from(Y.encodeStateAsUpdate(doc)), meta.auteur]);
      if (audit && meta.auteur && meta.distant) {
        await audit(meta.auteur, 'save_notebook', 'case', caseId, { chars: texte.length }, null);
      }
    },
  }, { label: 'notebook', debounceMs });

  async function lire(pool: Pool, caseId: string) {
    if (registre.isLive(caseId)) await registre.flush(pool, caseId);
    const { rows: [ligne] } = await pool.query(getNotebookSql(), [caseId]);
    return ligne || { content: '', updated_at: null, updated_by_name: null };
  }

  async function ajouter(pool: Pool, caseId: string, bloc: string, auteur: string) {
    const propre = String(bloc ?? '').trim();
    if (!propre) throw new NotebookError('VIDE', 'contenu requis');
    let refuse = false;
    const update = await registre.edit(pool, caseId, auteur, (doc) => {
      const texte = doc.getText(TEXTE);
      const ajout = separer(texte.toString(), propre);
      if (texte.length + ajout.length > NOTEBOOK_MAX) { refuse = true; return; }
      texte.insert(texte.length, ajout);
    });
    if (refuse) throw new NotebookError('TROP_LONG', 'carnet plein');
    return update;
  }

  async function remplacer(pool: Pool, caseId: string, contenu: string, base: string | null, auteur: string) {
    if (contenu.length > NOTEBOOK_MAX) throw new NotebookError('TROP_LONG', 'carnet plein');
    const actuel = await lire(pool, caseId);
    const versionActuelle = actuel.updated_at ? new Date(actuel.updated_at).toISOString() : null;
    const versionBase = base ? new Date(base).toISOString() : null;
    if (versionActuelle !== versionBase) throw new NotebookError('VERSION_PERIMEE', 'le carnet a changé depuis la lecture');
    return registre.edit(pool, caseId, auteur, (doc) => {
      const texte = doc.getText(TEXTE);
      if (texte.toString() === contenu) return;
      texte.delete(0, texte.length);
      texte.insert(0, contenu);
    });
  }

  return { ...registre, lire, ajouter, remplacer };
}

export type NotebookRegistry = ReturnType<typeof createNotebookRegistry>;
