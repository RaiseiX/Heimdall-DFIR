// Parser configuration schema shared by the collection parse route and the UI.
//
// Each artifact type declares the knobs it actually supports. Everything here is
// applied server-side inside routes/collection.js (never passed raw to a shell),
// so adding an option is a deliberate, typed decision — not an arbitrary
// "extra args" escape hatch.
//
// `_global` holds options that apply to every parser in the run (the time
// window). `label`/`description`/`placeholder` are French because the backend
// already emits French operator-facing strings everywhere else.

const PARSER_OPTIONS = {
  _global: [
    {
      key: 'since',
      type: 'datetime',
      default: '',
      label: 'Depuis (UTC)',
      description: 'Ignorer les événements antérieurs à cet instant. Vide = aucune borne basse.',
      placeholder: '2024-01-01T00:00:00Z',
    },
    {
      key: 'until',
      type: 'datetime',
      default: '',
      label: "Jusqu'à (UTC)",
      description: 'Ignorer les événements postérieurs à cet instant. Vide = aucune borne haute.',
      placeholder: '2024-12-31T23:59:59Z',
    },
  ],
  prefetch: [
    {
      key: 'engine',
      type: 'enum',
      values: ['auto', 'python', 'dotnet'],
      default: 'auto',
      label: 'Moteur de parsing',
      description:
        'auto = Python (libscca/dissect) si disponible, sinon PECmd (.NET). ' +
        'python = forcer parse_prefetch.py. dotnet = forcer PECmd.dll.',
    },
  ],
  pcap: [
    {
      key: 'display_filter',
      type: 'string',
      default: '',
      label: 'Filtre tshark',
      description:
        "Filtre d'affichage Wireshark appliqué avant agrégation des flux (ex. « tcp.port == 443 »).",
      placeholder: 'tcp.port == 443',
    },
  ],
  catscale: [
    {
      key: 'exhaustive_fs_timeline',
      type: 'boolean',
      default: false,
      label: 'Timeline filesystem exhaustive',
      description:
        'Inclure chaque fichier de la collecte plutôt que le sous-ensemble retenu par le filtre de bruit. Peut multiplier les lignes par ~10.',
    },
  ],
  mft: [
    {
      key: 'resident_files',
      type: 'boolean',
      default: false,
      cli: { flag: '--dr' },
      label: 'Récupérer les fichiers residents',
      description:
        "MFTECmd --dr : extrait le contenu des fichiers residents (données stockées dans l'entrée $MFT) vers un sous-dossier Resident, copié dans la collecte (_mft_resident).",
    },
    {
      key: 'include_resident_data',
      type: 'boolean',
      default: false,
      cli: { flag: '--ir' },
      label: 'Inclure les données residents dans le CSV',
      description:
        "MFTECmd --ir : ajoute le contenu resident (brut) comme colonne du CSV de sortie, pour les petits fichiers logés dans le $MFT.",
    },
    {
      key: 'recover_slack',
      type: 'boolean',
      default: false,
      cli: { flag: '--rs' },
      label: 'Récupérer le slack des enregistrements',
      description:
        'MFTECmd --rs : tente de récupérer les données résiduelles dans le slack des enregistrements FILE du $MFT (utile pour des données supprimées).',
    },
  ],
};

// Map artifactType -> { optionKey: default }, derived once so sanitize and the
// defaults endpoint agree without re-deriving the schema shape by hand.
function _defaults() {
  const out = {};
  for (const [artifactType, opts] of Object.entries(PARSER_OPTIONS)) {
    out[artifactType] = {};
    for (const opt of opts) out[artifactType][opt.key] = opt.default;
  }
  return out;
}

function defaultParserOptions() {
  return _defaults();
}

function _coerce(opt, value) {
  if (opt.type === 'boolean') return value === true || value === 'true' || value === 1 || value === '1';
  if (opt.type === 'number') {
    const n = Number(value);
    return Number.isFinite(n) ? n : opt.default;
  }
  if (opt.type === 'enum') {
    return opt.values && opt.values.includes(value) ? value : opt.default;
  }
  if (opt.type === 'datetime') {
    if (value == null || value === '') return '';
    const t = Date.parse(String(value));
    return Number.isFinite(t) ? new Date(t).toISOString() : opt.default;
  }
  // string
  return value == null ? opt.default : String(value).slice(0, 500);
}

// Validate/coerce a client-provided options object against the schema. Unknown
// keys and out-of-range values are dropped so a malformed payload can never
// reach a spawned tool or the DB. Always returns the full shape (defaults
// filled) so callers can read `options.<type>.<key>` without guarding.
function sanitizeParserOptions(input) {
  const out = defaultParserOptions();
  if (!input || typeof input !== 'object') return out;

  for (const [artifactType, opts] of Object.entries(PARSER_OPTIONS)) {
    const incoming = input[artifactType];
    if (!incoming || typeof incoming !== 'object') continue;
    for (const opt of opts) {
      if (incoming[opt.key] === undefined) continue;
      out[artifactType][opt.key] = _coerce(opt, incoming[opt.key]);
    }
  }
  return out;
}

// Append the CLI flags enabled in `parserOptions` for `artifactType` onto an
// existing tool argv. Only options that declare a `cli.flag` (and were vetted
// against the real tool's help) are ever appended, and only for the artifact
// type that owns them — a boolean checked on in one parser can never leak a
// flag into another tool's invocation. Returns a fresh array; never mutates
// `args`.
function appendCliFlags(artifactType, parserOptions) {
  const opts = PARSER_OPTIONS[artifactType];
  if (!opts) return [];
  const provided = (parserOptions && parserOptions[artifactType]) || {};
  const out = [];
  for (const opt of opts) {
    if (!opt.cli || !opt.cli.flag || opt.type !== 'boolean') continue;
    if (provided[opt.key] === true) {
      out.push(opt.cli.flag);
      if (opt.cli.value) out.push(opt.cli.value);
    }
  }
  return out;
}

// { since: Date|null, until: Date|null } for ingest-time filtering. An empty
// string (or absent option) means "unbounded" on that side.
function buildTimeWindow(options) {
  const g = (options && options._global) || {};
  const since = g.since ? new Date(g.since) : null;
  const until = g.until ? new Date(g.until) : null;
  return {
    since: since && !isNaN(since.getTime()) ? since : null,
    until: until && !isNaN(until.getTime()) ? until : null,
  };
}

module.exports = { PARSER_OPTIONS, defaultParserOptions, sanitizeParserOptions, appendCliFlags, buildTimeWindow };
