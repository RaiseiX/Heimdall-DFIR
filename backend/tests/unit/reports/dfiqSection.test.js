// Unit tests for the PURE buildDfiqReportData(rows) transformer in reportRenderer.js.
// Drawing (drawDfiq) uses pdfkit and is exercised indirectly via node --check + the
// full suite; only the pure grouping/filtering logic is unit-tested here.
const { buildDfiqReportData } = require('../../../src/services/reportRenderer');

function row(overrides = {}) {
  return {
    scenario_title: 'Scenario A',
    question_text: 'Was lateral movement observed?',
    status: 'answered',
    note: 'Confirmed via RDP logs',
    question_position: 0,
    evidence_title: null,
    ...overrides,
  };
}

describe('buildDfiqReportData', () => {
  test('empty rows → []', () => {
    expect(buildDfiqReportData([])).toEqual([]);
    expect(buildDfiqReportData(undefined)).toEqual([]);
    expect(buildDfiqReportData(null)).toEqual([]);
  });

  test('answered-only inclusion: a todo row is excluded', () => {
    const rows = [
      row({ status: 'answered', question_text: 'Q1' }),
      row({ status: 'todo', question_text: 'Q2' }),
      row({ status: 'not_applicable', question_text: 'Q3' }),
    ];
    const out = buildDfiqReportData(rows);
    expect(out).toHaveLength(1);
    expect(out[0].questions).toHaveLength(1);
    expect(out[0].questions[0].text).toBe('Q1');
  });

  test('multiple evidence rows for one question collapse into one question with an evidence array', () => {
    const rows = [
      row({ question_text: 'Q1', evidence_title: 'Bookmark A' }),
      row({ question_text: 'Q1', evidence_title: 'Bookmark B' }),
    ];
    const out = buildDfiqReportData(rows);
    expect(out).toHaveLength(1);
    expect(out[0].questions).toHaveLength(1);
    expect(out[0].questions[0].evidence).toEqual(['Bookmark A', 'Bookmark B']);
  });

  test('question with no evidence rows (LEFT JOIN NULL) yields an empty evidence array, not a null entry', () => {
    const rows = [row({ question_text: 'Q1', evidence_title: null })];
    const out = buildDfiqReportData(rows);
    expect(out[0].questions[0].evidence).toEqual([]);
  });

  test('groups multiple questions under the same scenario, and separates scenarios', () => {
    const rows = [
      row({ scenario_title: 'Scenario A', question_text: 'Q1', question_position: 0 }),
      row({ scenario_title: 'Scenario A', question_text: 'Q2', question_position: 1 }),
      row({ scenario_title: 'Scenario B', question_text: 'Q3', question_position: 0 }),
    ];
    const out = buildDfiqReportData(rows);
    expect(out).toHaveLength(2);
    const a = out.find(s => s.scenario_title === 'Scenario A');
    const b = out.find(s => s.scenario_title === 'Scenario B');
    expect(a.questions.map(q => q.text)).toEqual(['Q1', 'Q2']);
    expect(b.questions.map(q => q.text)).toEqual(['Q3']);
  });

  test('carries status and note through onto each question', () => {
    const rows = [row({ question_text: 'Q1', status: 'answered', note: 'my note' })];
    const out = buildDfiqReportData(rows);
    expect(out[0].questions[0]).toMatchObject({ text: 'Q1', status: 'answered', note: 'my note' });
  });
});
