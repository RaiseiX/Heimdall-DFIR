import { describe, it, expect } from 'vitest';
import { computeTextDelta } from './textDelta';

describe('computeTextDelta', () => {
  it('no-op when equal', () => {
    expect(computeTextDelta('abc', 'abc')).toEqual({ index: 0, remove: 0, insert: '' });
  });
  it('insert at end', () => {
    expect(computeTextDelta('abc', 'abcd')).toEqual({ index: 3, remove: 0, insert: 'd' });
  });
  it('insert at start', () => {
    expect(computeTextDelta('bc', 'abc')).toEqual({ index: 0, remove: 0, insert: 'a' });
  });
  it('insert in middle', () => {
    expect(computeTextDelta('ac', 'abc')).toEqual({ index: 1, remove: 0, insert: 'b' });
  });
  it('delete in middle', () => {
    expect(computeTextDelta('abc', 'ac')).toEqual({ index: 1, remove: 1, insert: '' });
  });
  it('replace a range', () => {
    expect(computeTextDelta('hello world', 'hello brave world')).toEqual({ index: 6, remove: 0, insert: 'brave ' });
  });
  it('replace with shrink', () => {
    expect(computeTextDelta('aXXXb', 'aYb')).toEqual({ index: 1, remove: 3, insert: 'Y' });
  });
  it('handles multi-line', () => {
    expect(computeTextDelta('a\nb', 'a\nX\nb')).toEqual({ index: 2, remove: 0, insert: 'X\n' });
  });
});
