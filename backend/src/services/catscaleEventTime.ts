export type StampKind = 'wall' | 'wall-no-offset' | 'uptime' | 'none';

export interface Stamp {
  time: string | null;
  kind: StampKind;
  text: string;
}

const MONTHS: Record<string, number> = {
  janv: 1, jan: 1,
  'févr': 2, fevr: 2, feb: 2,
  mars: 3, mar: 3,
  avril: 4, avr: 4, apr: 4,
  mai: 5, may: 5,
  juin: 6, jun: 6,
  juil: 7, jul: 7,
  'août': 8, aout: 8, aug: 8,
  sept: 9, sep: 9,
  oct: 10,
  nov: 11,
  'déc': 12, dec: 12,
};

const OFFSET_RE = /([+-])(\d{2}):?(\d{2})\s*$/;
const UPTIME_RE = /^\s*\d+\.\d+\s*$/;
const TIME_RE = /^\d{1,2}:\d{2}:\d{2}$/;
const YEAR_RE = /^\d{4}$/;
const DAY_RE = /^\d{1,2}$/;

export function hostUtcOffset(content: string): string | null {
  const m = OFFSET_RE.exec(content ?? '');
  if (!m) return null;
  const hours = Number(m[2]);
  const minutes = Number(m[3]);
  if (hours > 14 || minutes > 59) return null;
  return `${m[1]}${m[2]}:${m[3]}`;
}

function monthOf(token: string): number | null {
  const key = token.toLowerCase().replace(/\.+$/, '');
  return MONTHS[key] ?? null;
}

export function dmesgStamp(line: string, offset: string | null): Stamp {
  const raw = String(line ?? '');
  const m = /^\[([^\]]*)\]\s?(.*)$/.exec(raw);
  if (!m) return { time: null, kind: 'none', text: raw };

  const inside = m[1];
  const rest = m[2];

  if (UPTIME_RE.test(inside)) return { time: null, kind: 'uptime', text: rest };

  const parts = inside.trim().split(/\s+/);
  if (parts.length < 5) return { time: null, kind: 'none', text: raw };

  const [, a, b, clock, year] = parts;
  if (!TIME_RE.test(clock) || !YEAR_RE.test(year)) return { time: null, kind: 'none', text: raw };

  let day: string | null = null;
  let month: number | null = null;
  if (DAY_RE.test(a)) {
    day = a;
    month = monthOf(b);
  } else if (DAY_RE.test(b)) {
    day = b;
    month = monthOf(a);
  }
  if (!day || !month) return { time: null, kind: 'none', text: raw };

  if (!offset) return { time: null, kind: 'wall-no-offset', text: rest };

  const iso = `${year}-${String(month).padStart(2, '0')}-${day.padStart(2, '0')}T${clock.padStart(8, '0')}${offset}`;
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return { time: null, kind: 'none', text: raw };

  return { time: at.toISOString(), kind: 'wall', text: rest };
}

const ISO_HEAD_RE = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2}(?:\.\d+)?)(Z|[+-]\d{2}:?\d{2})?/;
const GIN_RE = /^\[GIN\]\s+(\d{4})\/(\d{2})\/(\d{2})\s+-\s+(\d{2}:\d{2}:\d{2})/;
const REDIS_RE = /^\d+:[A-Za-z]\s+(\d{1,2})\s+([A-Za-z]{3,5})\s+(\d{4})\s+(\d{2}:\d{2}:\d{2}\.\d{1,3})/;
const JSON_TIME_KEYS = ['@timestamp', 'timestamp', 'time', 'ts'];
const CLF_RE = /\[(\d{1,2})\/([A-Za-z]{3,5})\/(\d{4}):(\d{2}:\d{2}:\d{2})(?:\s+([+-]\d{2}):?(\d{2}))?\]/;

function isoOrNull(value: string): string | null {
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? null : at.toISOString();
}

// Container logs carry whatever format their image chose. Measured across the 15
// on the reference host: Elasticsearch writes ECS `@timestamp`, the worker writes
// `timestamp`, Traefik writes `time`, Ollama writes GIN, Redis writes its own — and
// five images (the entrypoints, nginx, postgres, the frontend) write no per-line
// time at all. Those five stay undated on purpose: that is a fact about the
// evidence, not a gap in this parser, and inventing a time for them would be worse
// than leaving the lines where they belong, in the undated inventory.
export function containerLogStamp(line: string, offset: string | null): string | null {
  const raw = String(line ?? '').trim();
  if (!raw) return null;

  if (raw.startsWith('{')) {
    let doc: unknown;
    try { doc = JSON.parse(raw); } catch { return null; }
    if (!doc || typeof doc !== 'object') return null;
    const rec = doc as Record<string, unknown>;
    for (const key of JSON_TIME_KEYS) {
      const v = rec[key];
      if (typeof v === 'string' && v) return isoOrNull(v);
    }
    return null;
  }

  const gin = GIN_RE.exec(raw);
  if (gin) {
    if (!offset) return null;
    return isoOrNull(`${gin[1]}-${gin[2]}-${gin[3]}T${gin[4]}${offset}`);
  }

  const redis = REDIS_RE.exec(raw);
  if (redis) {
    const month = monthOf(redis[2]);
    if (!month || !offset) return null;
    const day = redis[1].padStart(2, '0');
    return isoOrNull(`${redis[3]}-${String(month).padStart(2, '0')}-${day}T${redis[4]}${offset}`);
  }

  const clf = CLF_RE.exec(raw);
  if (clf) {
    const month = monthOf(clf[2]);
    const zone = clf[5] ? `${clf[5]}:${clf[6]}` : offset;
    if (!month || !zone) return null;
    const day = clf[1].padStart(2, '0');
    return isoOrNull(`${clf[3]}-${String(month).padStart(2, '0')}-${day}T${clf[4]}${zone}`);
  }

  const iso = ISO_HEAD_RE.exec(raw);
  if (iso) {
    const zone = iso[3] ?? offset;
    if (!zone) return null;
    return isoOrNull(`${iso[1]}T${iso[2]}${zone}`);
  }

  return null;
}
