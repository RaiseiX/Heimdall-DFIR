
const IORedis = require('ioredis');
const logger = require('./logger').default;

let redisClient;

async function connectRedis() {
  redisClient = new IORedis({
    host:             process.env.REDIS_HOST     || 'localhost',
    port:             parseInt(process.env.REDIS_PORT || '6379', 10),
    password:         process.env.REDIS_PASSWORD || undefined,
    enableReadyCheck: false,
    maxRetriesPerRequest: null,
  });

  redisClient.on('error', (err) => logger.error('Redis error:', err.message));
  return redisClient;
}

function getRedis() {
  return redisClient;
}

module.exports = { connectRedis, getRedis };
