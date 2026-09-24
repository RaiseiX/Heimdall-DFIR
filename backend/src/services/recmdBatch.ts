import path from 'path';

const BATCH_FILE = 'RECmd_Batch_MC.reb';

const BATCH_DIRS = [
  ['BatchExamples', 'RECmd', 'BatchExamples'],
  ['BatchExamples'],
];

export function resolveRecmdBatch(
  zimmermanDir: string,
  exists: (p: string) => boolean,
): string | null {
  for (const parts of BATCH_DIRS) {
    const candidate = path.join(zimmermanDir, ...parts, BATCH_FILE);
    if (exists(candidate)) return candidate;
  }
  return null;
}
