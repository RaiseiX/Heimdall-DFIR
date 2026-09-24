const KIND_MAP = {
  type: 'artifactType',
  host: 'host',
  user: 'user',
  after: 'after',
  before: 'before',
  sev: 'sev',
  tag: 'tag',
  tool: 'tool',
  eid: 'eventId',
  ext: 'ext',
  provider: 'provider',
  sha1: 'sha1',
  hash: 'sha1',
};

const TOKEN_RE = new RegExp(`^(${Object.keys(KIND_MAP).join('|')}):(.+)$`, 'i');

export function parseToken(raw) {
  const texte = String(raw ?? '').trim();
  const m = texte.match(TOKEN_RE);
  if (!m) return { kind: 'search', value: texte };
  return { kind: KIND_MAP[m[1].toLowerCase()], value: m[2] };
}

export { KIND_MAP };
