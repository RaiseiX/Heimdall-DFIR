export const QUERY_KEYS = [
  'search', 'searchOp', 'startTime', 'endTime', 'artifactTypes',
  'artifactNameFilter', 'artifactNameFilterOp',
  'hostFilter', 'hostFilterOp', 'userFilter', 'userFilterOp',
  'toolFilter', 'toolFilterOp', 'extFilter', 'extFilterOp',
  'providerFilter', 'providerFilterOp',
  'sha1Filter', 'sha1FilterOp',
  'eventIdFilter', 'tagFilter', 'hitsOnly', 'detSeverity',
  'multiSort', 'groupByFields',
];

export const QUERY_KEY_SET = new Set(QUERY_KEYS);
