const path = require('path');

function validText(value) {
  return typeof value === 'string' && value.trim().length > 0 && !/[\0\r\n]/.test(value);
}

function parseMinioLocator(locator) {
  if (!validText(locator) || !locator.startsWith('minio://')) {
    throw Object.assign(new Error('Invalid storage reference'), { code: 'INVALID_STORAGE_REFERENCE' });
  }
  const raw = locator.slice('minio://'.length);
  const separator = raw.indexOf('/');
  const bucket = separator > 0 ? raw.slice(0, separator) : '';
  const objectKey = separator > 0 ? raw.slice(separator + 1) : '';
  if (!validText(bucket) || !validText(objectKey)) {
    throw Object.assign(new Error('Invalid storage reference'), { code: 'INVALID_STORAGE_REFERENCE' });
  }
  return { bucket, objectKey };
}

function parseAdditionalFiles(value) {
  const parsed = typeof value === 'string' ? JSON.parse(value) : (value ?? []);
  if (!Array.isArray(parsed)) throw new Error('Invalid manifest');
  return parsed;
}

function planEvidenceDeletion(row, defaultBucket = process.env.S3_BUCKET_NAME || 'volweb') {
  const targets = [];
  const primary = row.file_path;
  let primaryBucket = defaultBucket;

  if (primary != null) {
    if (!validText(primary)) throw new Error('Invalid primary reference');
    if (primary.startsWith('minio://')) {
      primaryBucket = parseMinioLocator(primary).bucket;
      targets.push({ kind: 'minio', locator: primary });
    } else {
      targets.push({ kind: 'disk', locator: primary });
    }
  }

  for (const item of parseAdditionalFiles(row.additional_files)) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('Invalid manifest');
    if (item.object_key != null) {
      if (!validText(item.object_key)) throw new Error('Invalid object key');
      targets.push({ kind: 'minio', locator: `minio://${primaryBucket}/${item.object_key}` });
      continue;
    }
    if (!validText(item.name) || !validText(primary) || primary.startsWith('minio://')) {
      throw new Error('Invalid disk reference');
    }
    if (path.basename(item.name) !== item.name) throw new Error('Invalid disk reference');
    targets.push({ kind: 'disk', locator: path.join(path.dirname(primary), item.name) });
  }

  const unique = new Map();
  for (const target of targets) unique.set(`${target.kind}:${target.locator}`, target);
  return Array.from(unique.values());
}

module.exports = { parseMinioLocator, planEvidenceDeletion };
