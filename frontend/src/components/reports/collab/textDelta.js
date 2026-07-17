// Single-range diff via common prefix + common suffix. Enough for a textarea's
// one-edit-per-input-event: returns the {index, remove, insert} to turn old into new.
export function computeTextDelta(oldStr, newStr) {
  if (oldStr === newStr) return { index: 0, remove: 0, insert: '' };
  const minLen = Math.min(oldStr.length, newStr.length);
  let start = 0;
  while (start < minLen && oldStr[start] === newStr[start]) start++;
  let endOld = oldStr.length;
  let endNew = newStr.length;
  while (endOld > start && endNew > start && oldStr[endOld - 1] === newStr[endNew - 1]) { endOld--; endNew--; }
  return { index: start, remove: endOld - start, insert: newStr.slice(start, endNew) };
}
