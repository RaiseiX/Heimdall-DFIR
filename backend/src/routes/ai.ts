
import { Router, Response } from 'express';
import { Pool } from 'pg';
import type { AuthRequest } from '../types/index';
import * as aiService from '../services/aiService';
import * as llmService from '../services/llmService';

const { authenticate } = require('../middleware/auth');
const router = Router();

function pool(res: Response): Pool { return res.app.locals.pool; }
function io(res: Response)         { return res.app.locals.io; }

function sanitizeFreeText(text: string): string {
  return text.replace(/<[^>]*>/g, '').trim();
}

router.get('/ai/health', authenticate, (_req: AuthRequest, res: Response) => {
  res.json({ available: aiService.isAvailable() });
});

router.get('/ai/models', authenticate, async (_req: AuthRequest, res: Response) => {
  if (!aiService.isAvailable()) return res.json({ available: false, models: [] });
  try {
    const models = await llmService.listModels();
    res.json({ available: true, models });
  } catch {
    res.json({ available: false, models: [] });
  }
});

router.get('/cases/:caseId/ai/history', authenticate, async (req: AuthRequest, res: Response) => {
  const caseId = parseInt(req.params.caseId, 10);
  if (isNaN(caseId)) return res.status(400).json({ error: 'caseId invalide' });

  try {
    const history = await aiService.getConversationHistory(pool(res), caseId);
    res.json({ history });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/cases/:caseId/ai/chat', authenticate, async (req: AuthRequest, res: Response) => {
  const caseId = parseInt(req.params.caseId, 10);
  if (isNaN(caseId)) return res.status(400).json({ error: 'caseId invalide' });

  const { message, model } = req.body;
  if (!message?.trim()) return res.status(400).json({ error: 'message requis' });
  if (!aiService.isAvailable()) return res.status(503).json({ error: 'OLLAMA_URL non configuré' });

  try {
    const response = await aiService.chat(
      pool(res), caseId, parseInt(req.user.id, 10), message.trim(), model
    );
    res.json({ response });
  } catch (err: any) {
    res.status(502).json({ error: err.message });
  }
});

router.post('/cases/:caseId/ai/stream', authenticate, async (req: AuthRequest, res: Response) => {
  const caseId = parseInt(req.params.caseId, 10);
  if (isNaN(caseId)) return res.status(400).json({ error: 'caseId invalide' });

  const { message, model } = req.body;
  if (!message?.trim()) return res.status(400).json({ error: 'message requis' });
  if (!aiService.isAvailable()) return res.status(503).json({ error: 'OLLAMA_URL non configuré' });

  try {
    await aiService.chatStream(
      pool(res), caseId, parseInt(req.user.id, 10), message.trim(), res, model
    );
  } catch (err: any) {
    if (!res.headersSent) res.status(502).json({ error: err.message });
  }
});

router.delete('/cases/:caseId/ai/history', authenticate, async (req: AuthRequest, res: Response) => {
  const caseId = parseInt(req.params.caseId, 10);
  if (isNaN(caseId)) return res.status(400).json({ error: 'caseId invalide' });

  try {
    await aiService.clearConversationHistory(pool(res), caseId);
    res.json({ ok: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/cases/:caseId/ai/context', authenticate, async (req: AuthRequest, res: Response) => {
  const caseId = parseInt(req.params.caseId, 10);
  if (isNaN(caseId)) return res.status(400).json({ error: 'caseId invalide' });

  try {
    const ctx = await aiService.getInvestigatorContext(pool(res), caseId);
    res.json({ freeText: ctx.freeText, updatedBy: ctx.updatedBy, updatedAt: ctx.updatedAt });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.put('/cases/:caseId/ai/context', authenticate, async (req: AuthRequest, res: Response) => {
  const caseId = parseInt(req.params.caseId, 10);
  if (isNaN(caseId)) return res.status(400).json({ error: 'caseId invalide' });

  const rawText: string = req.body.freeText ?? '';
  const freeText = sanitizeFreeText(rawText);

  if (freeText.length > 4000) {
    return res.status(400).json({ error: 'Contexte trop long (max 4000 caractères)' });
  }

  try {
    await aiService.saveInvestigatorContext(pool(res), caseId, parseInt(req.user.id, 10), freeText);

    io(res).to(`case:${caseId}`).emit('ai:context:updated', {
      caseId,
      updatedBy: req.user.username,
      preview:   freeText.slice(0, 100) + (freeText.length > 100 ? '...' : ''),
    });

    res.json({ ok: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/cases/:caseId/ai/context', authenticate, async (req: AuthRequest, res: Response) => {
  const caseId = parseInt(req.params.caseId, 10);
  if (isNaN(caseId)) return res.status(400).json({ error: 'caseId invalide' });

  try {
    await aiService.clearInvestigatorContext(pool(res), caseId);
    res.json({ ok: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export = router;
