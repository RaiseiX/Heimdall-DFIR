// Recursively list every .csv file under a directory. Extracted out of
// collection.js so scanCollectionCsvs.js (the collection-wide CSV scan) and
// collection.js's own per-artifact-type output-dir scans share one
// implementation instead of two directory walkers drifting apart.
const fs = require('fs');
const path = require('path');

function findCsvFilesRecursive(dir) {
  const results = [];
  try {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) results.push(...findCsvFilesRecursive(full));
      else if (entry.isFile() && entry.name.toLowerCase().endsWith('.csv')) results.push(full);
    }
  } catch (_e) { /* unreadable directory — best-effort listing */ }
  return results;
}

module.exports = { findCsvFilesRecursive };
