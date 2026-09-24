const fs = require('fs'); const path = require('path');
const { pool } = require('../src/config/database');
const { loadCatalog } = require('../src/services/dfiqCatalog');
(async () => {
  const cat = JSON.parse(fs.readFileSync(path.join(__dirname, '../data/dfiq/catalog.json'), 'utf8'));
  const counts = await loadCatalog(pool, cat);
  console.log('[dfiq:seed]', counts);
  await pool.end();
})().catch(e => { console.error('[dfiq:seed] failed', e.message); process.exit(1); });
