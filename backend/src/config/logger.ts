import winston from 'winston';
import { foldDetail } from './loggerDetail';
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

const base = winston.createLogger({
  level:      process.env.LOG_LEVEL || 'info',
  transports,
  exitOnError: false,
});

// winston.format.splat() is deliberately absent from the chain above, and without
// it a second argument is dropped: `logger.error('import failed:', err.message)`
// wrote {"message":"import failed:"} and nothing else. Measured in the container,
// in JSON and in printf alike, on 163 error and warning sites.
//
// Folding happens here rather than at each call site: the sites are correct as
// written, it is the transport that could not carry what they passed.
const fold = (level: 'error' | 'warn' | 'info' | 'debug') =>
  (message: unknown, ...extras: unknown[]) => {
    const { message: text, meta } = foldDetail(String(message ?? ''), extras);
    return meta ? base[level](text, meta) : base[level](text);
  };

const logger = Object.assign(Object.create(base), {
  error: fold('error'),
  warn:  fold('warn'),
  info:  fold('info'),
  debug: fold('debug'),
});

export default logger;
