import { computeTextDelta } from './textDelta';

// Bind a Y.Text to a <textarea> element. Local input -> Y.Text delta; remote
// Y.Text change -> textarea value (best-effort caret preservation). Returns unbind().
export function bindTextareaToYText(ytext, el) {
  const onInput = () => {
    const { index, remove, insert } = computeTextDelta(ytext.toString(), el.value);
    if (remove === 0 && insert === '') return;
    ytext.doc.transact(() => {
      if (remove) ytext.delete(index, remove);
      if (insert) ytext.insert(index, insert);
    });
  };
  const onYChange = () => {
    const next = ytext.toString();
    if (el.value === next) return;   // no-op guard: this is what breaks the local input<->observe echo loop
    const caret = el.selectionStart;
    const before = el.value;
    el.value = next;
    // Best-effort caret restore relative to where the remote edit landed:
    //  - caret before the edit         -> unchanged
    //  - caret after the removed span   -> shift by the net length change
    //  - caret inside the removed span  -> clamp to the end of the inserted text
    const { index: editIndex, remove, insert } = computeTextDelta(before, next);
    let pos;
    if (caret <= editIndex) pos = caret;
    else if (caret >= editIndex + remove) pos = caret + (next.length - before.length);
    else pos = editIndex + insert.length;
    const clamped = Math.max(0, Math.min(pos, next.length));
    try { el.selectionStart = el.selectionEnd = clamped; } catch { /* detached */ }
  };
  el.value = ytext.toString();
  el.addEventListener('input', onInput);
  ytext.observe(onYChange);
  return () => { el.removeEventListener('input', onInput); ytext.unobserve(onYChange); };
}
