const { auditLog } = require('../middleware/auth');
const { createNotebookRegistry } = require('./notebookDocRegistry');

module.exports = createNotebookRegistry({ audit: auditLog });
