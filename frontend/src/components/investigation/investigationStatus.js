
export const STATUS_CYCLE = ['todo', 'doing', 'done', 'blocked'];

export const STATUS_COLOR = {
  todo:    'var(--fl-subtle)',
  doing:   'var(--fl-gold)',
  done:    'var(--fl-ok)',
  blocked: 'var(--fl-danger)',
};

export const STATUS_LABEL_KEY = {
  todo:    'investigation.status_todo',
  doing:   'investigation.status_doing',
  done:    'investigation.status_done',
  blocked: 'investigation.status_blocked',
};

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
