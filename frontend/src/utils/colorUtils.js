
export function mixColor(color, pct, base = 'transparent') {
  return `color-mix(in srgb, ${color} ${pct}%, ${base})`;
}

export const mix = {
  bg:     (c) => mixColor(c, 8),
  border: (c) => mixColor(c, 30),
  hover:  (c) => mixColor(c, 12),
  strong: (c) => mixColor(c, 40),
  tint:   (c, pct) => mixColor(c, pct),
};
