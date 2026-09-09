export const FS_TIMELINE_COLUMNS = [
  'inode', 'hard_link_count', 'path', 'last_access', 'last_modified',
  'last_status_change', 'file_creation', 'user', 'group', 'permissions', 'file_size',
] as const;

const SIZE_INDEX = 10;

function usable(value: string | undefined): boolean {
  return typeof value === 'string' && value.trim() !== '' && value.trim() !== '-';
}

export function fsTimelineRaw(parts: string[], hostname: string): Record<string, string> {
  const raw: Record<string, string> = {};
  FS_TIMELINE_COLUMNS.forEach((name, i) => {
    const value = parts?.[i];
    if (usable(value)) raw[name] = value.trim();
  });
  raw.host = hostname;
  return raw;
}

export function fsTimelineSize(parts: string[]): number | null {
  const value = parts?.[SIZE_INDEX];
  if (!usable(value)) return null;
  const n = Number.parseInt(value.trim(), 10);
  return Number.isFinite(n) ? n : null;
}
