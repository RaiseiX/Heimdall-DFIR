function rawOf(record) {
  if (!record || typeof record !== 'object') return {};
  return { ...record };
}

module.exports = { rawOf };
