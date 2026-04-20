/* eslint-disable no-restricted-globals */
// Chunked client-side grouping worker — fallback for offline / small datasets.
// Protocol:
//   post { type: 'group', rows, by: string[], chunk?: 5000 }
//   recv { type: 'progress', processed, total }
//   recv { type: 'done', groups: [{ key, count, first_ts, last_ts, sample_ids }] }

const DEFAULT_CHUNK = 5000;

function groupKey(row, by) {
  return by.map(c => {
    const v = row[c] ?? (row.raw && row.raw[c]);
    return v === undefined || v === null || v === '' ? '∅' : String(v);
  }).join('\u241f');
}

self.onmessage = (ev) => {
  const { type, rows, by, chunk = DEFAULT_CHUNK } = ev.data || {};
  if (type !== 'group' || !Array.isArray(rows) || !Array.isArray(by) || by.length === 0) {
    self.postMessage({ type: 'error', message: 'invalid input' });
    return;
  }

  const buckets = new Map();
  const total = rows.length;
  let i = 0;

  function step() {
    const end = Math.min(i + chunk, total);
    for (; i < end; i++) {
      const r = rows[i];
      const gk = groupKey(r, by);
      let b = buckets.get(gk);
      if (!b) {
        b = {
          key: by.map(c => {
            const v = r[c] ?? (r.raw && r.raw[c]);
            return v === undefined || v === null || v === '' ? null : v;
          }),
          count: 0,
          first_ts: r.timestamp,
          last_ts: r.timestamp,
          sample_ids: [],
        };
        buckets.set(gk, b);
      }
      b.count += 1;
      if (r.timestamp < b.first_ts) b.first_ts = r.timestamp;
      if (r.timestamp > b.last_ts) b.last_ts = r.timestamp;
      if (b.sample_ids.length < 3 && r.id != null) b.sample_ids.push(r.id);
    }
    self.postMessage({ type: 'progress', processed: i, total });
    if (i < total) {
      setTimeout(step, 0);
    } else {
      const groups = Array.from(buckets.values()).sort((a, b) => b.count - a.count);
      self.postMessage({ type: 'done', groups, total_groups: groups.length });
    }
  }

  step();
};
