import { Request, Response, NextFunction } from 'express';
import type { AuthRequest } from '../types/index';
import { parserQueue } from '../config/queue';
import logger from '../config/logger';

const MAX_CONCURRENT_JOBS = 5;

export async function parserRateLimiter(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const userId = (req as AuthRequest).user?.id;
  if (!userId) {
    res.status(401).json({ error: 'Authentification requise' });
    return;
  }

  try {

    const [waiting, active] = await Promise.all([
      parserQueue.getJobs(['waiting']),
      parserQueue.getJobs(['active']),
    ]);

    const userJobs = [...waiting, ...active].filter(
      (job) => job.data?.userId === userId,
    );

    if (userJobs.length >= MAX_CONCURRENT_JOBS) {
      logger.warn('[rateLimiter] 429 parser jobs limit reached', {
        userId,
        currentCount: userJobs.length,
        limit: MAX_CONCURRENT_JOBS,
        requestId: (req as any).requestId,
      });
      res.status(429).json({
        error: `Trop de jobs en attente. Limite : ${MAX_CONCURRENT_JOBS} jobs simultanés par utilisateur.`,
        current: userJobs.length,
        limit: MAX_CONCURRENT_JOBS,
      });
      return;
    }
  } catch (err: any) {

    logger.warn('[rateLimiter] Queue unreachable, skipping rate limit check', {
      error: err.message,
    });
  }

  next();
}
