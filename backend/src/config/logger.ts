import winston from 'winston';
import { AsyncLocalStorage } from 'async_hooks';

export interface RequestContext {
  requestId?: string;
  userId?:    string;
  method?:    string;
  path?:      string;
}

export const requestContext = new AsyncLocalStorage<RequestContext>();

const injectContext = winston.format((info) => {
  const ctx = requestContext.getStore();
  if (ctx?.requestId) (info as any).requestId = ctx.requestId;
  if (ctx?.userId)    (info as any).userId    = ctx.userId;
  return info;
});

const transports: winston.transport[] = [
  new winston.transports.Console({
    format: winston.format.combine(
      injectContext(),
      winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
      process.env.NODE_ENV === 'production'
        ? winston.format.json()
        : winston.format.combine(
            winston.format.colorize(),
            winston.format.printf(({ level, message, timestamp, requestId, ...meta }) => {
              const rid   = requestId ? ` [${requestId}]` : '';
              const extra = Object.keys(meta).length ? ' ' + JSON.stringify(meta) : '';
              return `${timestamp}${rid} ${level}: ${message}${extra}`;
            }),
          ),
    ),
  }),
];

if (process.env.LOG_FILE === 'true') {
  transports.push(
    new winston.transports.File({
      filename: 'logs/heimdall.log',
      maxsize:  50 * 1024 * 1024,
      maxFiles: 5,
      tailable: true,
      format: winston.format.combine(
        injectContext(),
        winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
        winston.format.json(),
      ),
    }),
  );
}

const logger = winston.createLogger({
  level:      process.env.LOG_LEVEL || 'info',
  transports,
  exitOnError: false,
});

export default logger;
