// In-memory registry of startup migrations that could not be applied.
//
// A migration that fails leaves collection_timeline without the columns the
// parsers write to; the INSERTs then fail row by row, which historically
// surfaced to the analyst as "0 event" rather than as an error. Recording the
// failure lets the write routes refuse work explicitly instead.
const degradations = new Map(); // migration name -> reason

function markDegraded(name, reason) {
  degradations.set(name, String(reason));
}

function clearDegraded(name) {
  degradations.delete(name);
}

function isDegraded() {
  return degradations.size > 0;
}

function getDegradations() {
  return [...degradations].map(([name, reason]) => ({ name, reason }));
}

// Test seam only — production never resets the registry, a degraded schema is
// cleared by a successful retry via clearDegraded().
function resetSchemaState() {
  degradations.clear();
}

module.exports = { markDegraded, clearDegraded, isDegraded, getDegradations, resetSchemaState };
