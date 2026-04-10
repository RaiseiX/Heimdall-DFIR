import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { requestContext } from '../config/logger';

export function requestIdMiddleware(req: Request, res: Response, next: NextFunction): void {
  const id = (req.headers['x-request-id'] as string | undefined) || uuidv4();
  (req as any).requestId = id;
  res.setHeader('X-Request-Id', id);

  const userId = (req as any).user?.id as string | undefined;

  requestContext.run(
    { requestId: id, userId, method: req.method, path: req.path },
    next,
  );
}
