
import { Router, Request, Response } from 'express';
const { authenticate } = require('../middleware/auth');
import * as llmService from '../services/llmService';
import * as aiRouter   from '../services/aiRouter';
import type { AuthRequest } from '../types/index';

const router = Router();

// Full Ollama status: reachability, available models with sizes, and tier
// recommendation (fast / standard / deep). Used by the admin AI panel.
router.get('/status', authenticate, async (_req: Request, res: Response) => {
  try {
    const status = await aiRouter.probe();
    res.json(status);
  } catch {
    res.json({ reachable: false, models: [], tier: 'none',
               preferred: { fast: null, standard: null, deep: null } });
  }
});

router.get('/models', authenticate, async (_req: Request, res: Response) => {
  try {
    const status = await aiRouter.probe();
    // Shape is backward-compatible with the previous llmService.listModels() response
    res.json({ available: status.reachable, models: status.models.map((m) => m.name) });
  } catch {
    res.json({ available: false, models: [] });
  }
});

router.post('/analyze', authenticate, async (req: Request, res: Response) => {
  const { prompt, model = 'qwen2.5:7b', stream = true } = req.body;
  if (!prompt) return res.status(400).json({ error: 'prompt required' });
  if (!llmService.isAvailable()) {
    return res.status(503).json({ error: 'OLLAMA_URL not configured' });
  }
  try {
    await llmService.streamAnalysis(prompt, model, res);
  } catch (err: any) {
    if (!res.headersSent) res.status(502).json({ error: err.message });
  }
});

router.post('/pull', authenticate, async (req: Request, res: Response) => {
  const { model } = req.body;
  if (!model) return res.status(400).json({ error: 'model required' });
  if (!llmService.isAvailable()) {
    return res.status(503).json({ error: 'OLLAMA_URL not configured' });
  }
  try {
    await llmService.pullModel(model, res);
  } catch (err: any) {
    if (!res.headersSent) res.status(502).json({ error: err.message });
  }
});

router.delete('/models/:model', authenticate, async (req: Request, res: Response) => {
  const model = decodeURIComponent(req.params.model);
  if (!llmService.isAvailable()) {
    return res.status(503).json({ error: 'OLLAMA_URL not configured' });
  }
  try {
    await llmService.deleteModel(model);
    res.json({ ok: true });
  } catch (err: any) {
    res.status(502).json({ error: err.message });
  }
});

export = router;
