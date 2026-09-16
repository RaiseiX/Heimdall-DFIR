// Le filtre sur le Provider d'un evenement Windows.
//
// ── Pourquoi ce filtre existe ───────────────────────────────────────────────
//
// Un `event_id` n'est unique qu'A L'INTERIEUR d'un Provider. Mesure du
// 2026-09-16 sur `LAB_Xtended` : l'identifiant 1 couvre `Microsoft-Windows-
// Servicing` (280 lignes), `Crypto-NCrypt` (266), `PCI` (248),
// `UniversalTelemetryClient` (177), `Winlogon` (23), `FilterManager` (15) — et
// aucun Sysmon, absent de cet hote. L'analyste qui filtrait « eid:1 » en pensant
// Sysmon Process Create obtenait des transitions d'etat de bus PCI, sans que
// rien a l'ecran ne le detrompe.
//
// Le champ etait stocke dans `raw` depuis toujours ; il manquait d'etre
// filtrable. 82 395 lignes `evtx` le portent, plus 66 lignes `amcache`.
//
// ── Pourquoi la containment plutot que l'extraction ─────────────────────────
//
// Mesure du 2026-09-16 sur les 1 452 326 lignes du cas de reference :
//
//   raw->>'Provider' ILIKE '%PCI%'                   5 897 ms   Seq Scan
//   raw @> jsonb_build_object('Provider', $1)            3 ms   idx_ct_raw_gin
//
// L'index GIN ne sait servir que la containment. L'egalite passe donc par elle,
// et `contains` reste disponible en connaissance de cause : il ne peut pas etre
// indexe, mais un analyste veut parfois toute une famille de providers.

import { VALID_TEXT_OPS } from '../utils/textFilter';

const CONTIENT = `raw @> jsonb_build_object('Provider', $N::text)`;
const A_LA_CLE = `raw ? 'Provider'`;

export function buildProviderFilter(
  value: string,
  op: string,
): { sql: string; param: string | null } {
  const safeOp = VALID_TEXT_OPS.has(op) ? op : 'equals';
  const echappe = String(value ?? '').replace(/[%_]/g, '\\$&');

  switch (safeOp) {
    case 'equals':
      return { sql: CONTIENT, param: String(value ?? '') };

    // La cle doit exister : sans elle, la negation de la containment rendrait
    // les 3 034 230 lignes CatScale, qui n'ont pas de Provider. L'analyste
    // demande un AUTRE provider, pas tout ce qui n'est pas Windows.
    case 'not_equals':
      return { sql: `(${A_LA_CLE} AND NOT (${CONTIENT}))`, param: String(value ?? '') };

    case 'empty':
      return { sql: `NOT (${A_LA_CLE})`, param: null };

    case 'not_empty':
      return { sql: A_LA_CLE, param: null };

    case 'not_contains':
      return { sql: `(${A_LA_CLE} AND raw->>'Provider' NOT ILIKE $N)`, param: '%' + echappe + '%' };

    case 'starts_with':
      return { sql: `raw->>'Provider' ILIKE $N`, param: echappe + '%' };

    case 'ends_with':
      return { sql: `raw->>'Provider' ILIKE $N`, param: '%' + echappe };

    case 'regex':
      return { sql: `raw->>'Provider' ~* $N`, param: String(value ?? '') };

    default:
      return { sql: `raw->>'Provider' ILIKE $N`, param: '%' + echappe + '%' };
  }
}

export function pushProviderFilter(
  value: string,
  op: string,
  pi: number,
  conditions: string[],
  params: unknown[],
): number {
  const { sql, param } = buildProviderFilter(value, op);
  if (param !== null) {
    conditions.push(sql.replace(/\$N/g, `$${pi}`));
    params.push(param);
    return pi + 1;
  }
  conditions.push(sql);
  return pi;
}
