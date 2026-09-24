
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
