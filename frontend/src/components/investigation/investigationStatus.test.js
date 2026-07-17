import { describe, it, expect } from 'vitest';
import { STATUS_CYCLE, STATUS_COLOR, STATUS_LABEL_KEY, applyDrop } from './investigationStatus';

const steps = () => [
  { id: 'a', status: 'todo',  position: 0 },
  { id: 'b', status: 'todo',  position: 1 },
  { id: 'c', status: 'doing', position: 0 },
  { id: 'd', status: 'done',  position: 5 },
];

describe('status constants', () => {
  it('exposes the four statuses in cycle order', () => {
    expect(STATUS_CYCLE).toEqual(['todo', 'doing', 'done', 'blocked']);
  });
  it('has a color and a label key for every status', () => {
    for (const s of STATUS_CYCLE) {
      expect(STATUS_COLOR[s]).toBeTruthy();
      expect(STATUS_LABEL_KEY[s]).toBe(`investigation.status_${s}`);
    }
  });
});

describe('applyDrop', () => {
  it('moves a card to the target status and appends after the max position there', () => {
    const { steps: next, changed } = applyDrop(steps(), 'a', 'done');
    expect(changed).toEqual({ id: 'a', status: 'done', position: 6 });
    const moved = next.find(s => s.id === 'a');
    expect(moved.status).toBe('done');
    expect(moved.position).toBe(6);
  });

  it('uses position 0 when the target column is empty', () => {
    const { changed } = applyDrop(steps(), 'a', 'blocked');
    expect(changed).toEqual({ id: 'a', status: 'blocked', position: 0 });
  });

  it('is a no-op when dropped onto the same status', () => {
    const input = steps();
    const { steps: next, changed } = applyDrop(input, 'a', 'todo');
    expect(changed).toBeNull();
    expect(next).toBe(input); // same reference, untouched
  });

  it('is a no-op for an unknown id', () => {
    const input = steps();
    const { steps: next, changed } = applyDrop(input, 'zzz', 'done');
    expect(changed).toBeNull();
    expect(next).toBe(input);
  });

  it('matches ids across string/number types (dataTransfer sends strings)', () => {
    const numeric = [{ id: 1, status: 'todo', position: 0 }];
    const { changed } = applyDrop(numeric, '1', 'doing');
    expect(changed).toEqual({ id: 1, status: 'doing', position: 0 });
  });
});
