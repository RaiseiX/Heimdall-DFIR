import path from 'path';

function contains(parent: string, child: string): boolean {
  if (child === parent) return true;
  const withSep = parent.endsWith(path.sep) ? parent : parent + path.sep;
  return child.startsWith(withSep);
}

export function commonParserDir(files: string[], floor: string): string | null {
  const dirs = (Array.isArray(files) ? files : [])
    .filter((f): f is string => typeof f === 'string' && f.length > 0)
    .map((f) => path.dirname(f));

  if (dirs.length === 0) return null;

  let candidate = dirs[0];
  while (!dirs.every((d) => contains(candidate, d))) {
    const up = path.dirname(candidate);
    if (up === candidate) break;
    candidate = up;
  }

  return contains(floor, candidate) ? candidate : floor;
}
