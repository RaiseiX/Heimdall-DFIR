// Shared status vocabulary for the investigation workspace.
// Extracted from WorkflowTracker.jsx so both the Phases view (WorkflowTracker)
// and the Kanban view (KanbanBoard) share one source of truth.

export const STATUS_CYCLE = ['todo', 'doing', 'done', 'blocked'];

export const STATUS_COLOR = {
  todo:    'var(--fl-subtle)',
  doing:   'var(--fl-gold)',
  done:    'var(--fl-ok)',
  blocked: 'var(--fl-danger)',
};

// status -> i18n key (the keys already exist in en.json / fr.json).
export const STATUS_LABEL_KEY = {
  todo:    'investigation.status_todo',
  doing:   'investigation.status_doing',
  done:    'investigation.status_done',
  blocked: 'investigation.status_blocked',
};

/**
 * Pure reducer for a Kanban drop.
 * Moves the step whose id matches `draggedId` to `targetStatus`, appended to the
 * END of that column (position = 1 + max existing position there, else 0).
 *
 * Ids are compared with String() coercion: dataTransfer payloads are always
 * strings, while step ids are UUID strings today (and could be numeric in tests).
 *
 * @returns {{ steps: Array, changed: {id, status, position} | null }}
 *   `changed === null` (and the input array returned unchanged) when the id is
 *   unknown or the card is already in `targetStatus`.
 */
export function applyDrop(steps, draggedId, targetStatus) {
  const dragged = steps.find(s => String(s.id) === String(draggedId));
  if (!dragged || dragged.status === targetStatus) {
    return { steps, changed: null };
  }
  const inTarget = steps.filter(s => s.status === targetStatus);
  const position = inTarget.length
    ? Math.max(...inTarget.map(s => s.position ?? 0)) + 1
    : 0;
  const nextSteps = steps.map(s =>
    String(s.id) === String(draggedId)
      ? { ...s, status: targetStatus, position }
      : s
  );
  return { steps: nextSteps, changed: { id: dragged.id, status: targetStatus, position } };
}
