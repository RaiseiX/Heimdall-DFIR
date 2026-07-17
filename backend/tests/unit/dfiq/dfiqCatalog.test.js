const { normalizeCatalog } = require('../../../src/services/dfiqCatalog');

test('normalizeCatalog flattens scenarios→questions→approaches with positions + raw', () => {
  const cat = { scenarios: [ { dfiq_id: 'S1', title: 'A', questions: [
    { dfiq_id: 'Q1', facet_name: 'f', text: 't1', approaches: [{ name: 'ap', data_sources: ['evtx'] }] },
    { dfiq_id: 'Q2', text: 't2', approaches: [] },
  ] } ] };
  const n = normalizeCatalog(cat);
  expect(n.scenarios).toHaveLength(1);
  expect(n.scenarios[0].dfiq_id).toBe('S1');
  expect(n.questions).toHaveLength(2);
  expect(n.questions[0].position).toBe(0);
  expect(n.questions[1].position).toBe(1);
  expect(n.approaches).toHaveLength(1);
  expect(n.approaches[0].data_sources).toEqual(['evtx']);
  expect(n.questions[0].raw).toMatchObject({ dfiq_id: 'Q1' });
});

test('normalizeCatalog rejects a scenario without title', () => {
  expect(() => normalizeCatalog({ scenarios: [{ dfiq_id: 'S', questions: [] }] })).toThrow(/title/);
});

test('normalizeCatalog rejects a catalog scenario or question missing dfiq_id', () => {
  // scenario without dfiq_id: catalog rows must always carry a stable dedupe key
  expect(() => normalizeCatalog({ scenarios: [{ title: 'x', questions: [{ text: 't' }] }] })).toThrow(/dfiq_id/);
  // scenario has dfiq_id, but a question under it doesn't
  expect(() => normalizeCatalog({ scenarios: [{ dfiq_id: 'S1', title: 'x', questions: [{ text: 't' }] }] })).toThrow(/dfiq_id/);
});
