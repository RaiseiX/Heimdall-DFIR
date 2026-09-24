if (!process.env.JEST_WORKER_ID) {
  require('ts-node').register({
    transpileOnly: true,
    compilerOptions: { module: 'commonjs', esModuleInterop: true, allowSyntheticDefaultImports: true, resolveJsonModule: true },
  });
}

const { pool } = require('../src/config/database');
const { auditLog } = require('../src/middleware/auth');
const { validateRule } = require('../src/services/yaraService');
const { reparerReglesPrivees } = require('../src/services/reglesPrivees');

async function main() {
  const appliquer = process.argv.slice(2).includes('--appliquer');
  const resultat = await reparerReglesPrivees({
    appliquer,
    lister: async () => (await pool.query('SELECT id, name, content, is_active FROM yara_rules ORDER BY name')).rows,
    valider: content => validateRule(content),
    enregistrer: (id, contenu) => pool.query(
      'UPDATE yara_rules SET content = $2, is_active = true, updated_at = NOW() WHERE id = $1 AND is_active = false',
      [id, contenu],
    ),
    journaliser: details => auditLog(null, 'repair_yara_private_rules', 'yara_rules', null, details, 'script'),
  });
  console.log(JSON.stringify({
    appliquer,
    reparables: resultat.reparables.map(r => `${r.name} (+${r.ajoutees.join(', ')} depuis ${r.origine.join(', ')})`),
    non_reparables: resultat.non_reparables.map(r => `${r.name} : ${r.raison.split('\n')[0]}`),
    reparees: resultat.reparees.length,
  }, null, 1));
}

main()
  .catch(e => { console.error(e.message); process.exitCode = 1; })
  .finally(() => pool.end());
