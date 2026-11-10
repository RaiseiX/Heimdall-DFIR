
try {
  require('../services/auditChain').assertAuditKeyConfigured();
} catch (err) {
  console.error(`Worker refused to start: ${err.message}`);
  process.exit(1);
}

require('ts-node').register({
  transpileOnly: true,
  compilerOptions: {
    module: 'commonjs',
    esModuleInterop: true,
    allowSyntheticDefaultImports: true,
    resolveJsonModule: true,
  },
});

require('./parserWorker');
require('./ingestionWorker');
require('./huntingWorker');
require('./integrityWorker');
