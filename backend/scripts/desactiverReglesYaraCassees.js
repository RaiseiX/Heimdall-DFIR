if (!process.env.JEST_WORKER_ID) {
  require('ts-node').register({
    transpileOnly: true,
    compilerOptions: { module: 'commonjs', esModuleInterop: true, allowSyntheticDefaultImports: true, resolveJsonModule: true },
  });
}

const { pool } = require('../src/config/database');
const { auditLog } = require('../src/middleware/auth');
const { validateRule } = require('../src/services/yaraService');
const { desactiverReglesCassees } = require('../src/services/reglesYaraCassees');

async function main() {
  const appliquer = process.argv.slice(2).includes('--appliquer');
  const resultat = await desactiverReglesCassees({
    appliquer,
    lister: async () => (await pool.query('SELECT id, name, content FROM yara_rules WHERE is_active = true ORDER BY name')).rows,
    valider: content => validateRule(content),
    desactiver: async ids => (await pool.query(
      'UPDATE yara_rules SET is_active = false, updated_at = NOW() WHERE id = ANY($1::uuid[]) AND is_active = true RETURNING id',
      [ids],
    )).rows.map(r => r.id),
    journaliser: details => auditLog(null, 'disable_broken_yara_rules', 'yara_rules', null, details, 'script'),
  });
  console.log(JSON.stringify({
    appliquer,
    verifiees: resultat.verifiees,
    cassees: resultat.cassees.length,
    non_verifiees: resultat.non_verifiees.length,
    desactivees: resultat.desactivees.length,
    detail: resultat.cassees.map(r => `${r.name} — ${r.erreur.split('\n')[0]}`),
  }, null, 1));
}

main()
  .catch(e => { console.error(e.message); process.exitCode = 1; })
  .finally(() => pool.end());
