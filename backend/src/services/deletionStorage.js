const { Client } = require('minio');
const { parseMinioLocator } = require('./evidenceDeletionPlan');

let client;

function getClient() {
  if (client) return client;
  const endpoint = new URL((process.env.S3_ENDPOINT || 'http://minio:9000').replace(/\/$/, ''));
  client = new Client({
    endPoint: endpoint.hostname,
    port: endpoint.port ? parseInt(endpoint.port, 10) : (endpoint.protocol === 'https:' ? 443 : 80),
    useSSL: endpoint.protocol === 'https:',
    accessKey: process.env.AWS_ACCESS_KEY_ID || process.env.MINIO_ROOT_USER || '',
    secretKey: process.env.AWS_SECRET_ACCESS_KEY || process.env.MINIO_ROOT_PASSWORD || '',
  });
  return client;
}

async function deleteMinioLocator(locator) {
  const { bucket, objectKey } = parseMinioLocator(locator);
  try {
    await new Promise((resolve, reject) => {
      getClient().removeObject(bucket, objectKey, error => error ? reject(error) : resolve());
    });
    return { status: 'deleted', method: 'minio' };
  } catch (error) {
    if (error?.code === 'NoSuchKey' || error?.code === 'NotFound') {
      return { status: 'already_absent', method: 'minio' };
    }
    throw error;
  }
}

module.exports = { deleteMinioLocator };
