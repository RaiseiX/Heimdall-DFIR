export type ParserOutcomeStatus = 'SUCCESS' | 'DEGRADED' | 'FAILED';

export interface ParserOutcomeInput {
  exitCode: number;
  csvCount: number;
  totalRecords: number;
  expectsCsv: boolean;
}

export interface ParserOutcome {
  status: ParserOutcomeStatus;
  message: string;
}

const NO_CSV_PARSERS = new Set(['rdpcache']);

export function expectsCsvOutput(parser: string): boolean {
  return !NO_CSV_PARSERS.has(parser);
}

export function parserOutcome(input: ParserOutcomeInput): ParserOutcome {
  const { exitCode, csvCount, totalRecords, expectsCsv } = input;
  if (exitCode !== 0) {
    return { status: 'FAILED', message: `Processus terminé avec le code ${exitCode}` };
  }
  if (expectsCsv && csvCount === 0) {
    return { status: 'FAILED', message: 'Terminé sans produire de CSV — aucun résultat écrit par l\'outil' };
  }
  if (csvCount > 0 && totalRecords === 0) {
    return { status: 'DEGRADED', message: 'Terminé — 0 événements parsés (fichier vide ou format non reconnu)' };
  }
  return { status: 'SUCCESS', message: `Terminé — ${totalRecords.toLocaleString()} événements importés` };
}
