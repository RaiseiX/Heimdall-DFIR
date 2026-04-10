const express   = require('express');
const { spawnSync } = require('child_process');
const fs        = require('fs');
const path      = require('path');
const net       = require('net');
const { pool }  = require('../config/database');
const { authenticate, requireRole, auditLog } = require('../middleware/auth');
const logger    = require('../config/logger').default;

const router = express.Router();
const BACKUP_DIR = process.env.BACKUP_DIR || '/app/backups';

function withTimeout(promise, ms, fallback) {
  return Promise.race([promise, new Promise(r => setTimeout(() => r(fallback), ms))]);
}

function tcpCheck(host, port, timeoutMs = 3000) {
  return new Promise(resolve => {
    const sock = new net.Socket();
    let done = false;
    const finish = (ok) => { if (!done) { done = true; sock.destroy(); resolve(ok); } };
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => finish(true));
    sock.on('error',   () => finish(false));
    sock.on('timeout', () => finish(false));
    sock.connect(port, host);
  });
}

router.get('/health', authenticate, requireRole('admin'), async (req, res) => {
  const checks = await Promise.allSettled([
    withTimeout(pool.query('SELECT 1').then(() => ({ ok: true })), 3000, { ok: false, reason: 'timeout' }),

    withTimeout(
      (async () => {
        try {
          const esUrl = (process.env.ELASTICSEARCH_URL || 'http://elasticsearch:9200') + '/_cluster/health';
          const r = await fetch(esUrl, { signal: AbortSignal.timeout(3000) });
          if (!r.ok) return { ok: false, reason: `HTTP ${r.status}` };
          const j = await r.json();
          return { ok: true, status: j.status, shards: j.active_shards };
        } catch (e) { return { ok: false, reason: e.message }; }
      })(),
      4000,
      { ok: false, reason: 'timeout' }
    ),

    withTimeout(
      (async () => {
        const { getRedis } = require('../config/redis');
        const client = getRedis();
        if (!client) return { ok: false, reason: 'not_connected' };
        await client.ping();
        return { ok: true };
      })(),
      3000,
      { ok: false, reason: 'timeout' }
    ),

    withTimeout(
      tcpCheck(process.env.CLAMAV_HOST || 'clamav', parseInt(process.env.CLAMAV_PORT || '3310')).then(ok => ({ ok })),
      4000,
      { ok: false, reason: 'timeout' }
    ),

    withTimeout(
      (async () => {
        const { parserQueue } = require('../config/queue');
        const [waiting, active, completed, failed] = await Promise.all([
          parserQueue.getWaitingCount(),
          parserQueue.getActiveCount(),
          parserQueue.getCompletedCount(),
          parserQueue.getFailedCount(),
        ]);
        return { ok: true, waiting, active, completed, failed };
      })(),
      5000,
      { ok: false, reason: 'timeout' }
    ),
  ]);

  const [pg, es, redis, clamav, bullmq] = checks.map(r => r.status === 'fulfilled' ? r.value : { ok: false, reason: r.reason?.message || 'error' });

  res.json({
    timestamp: new Date().toISOString(),
    services: {
      postgresql:    { ...pg,     name: 'PostgreSQL' },
      elasticsearch: { ...es,     name: 'Elasticsearch' },
      redis:         { ...redis,  name: 'Redis' },
      clamav:        { ...clamav, name: 'ClamAV' },
      bullmq_worker: { ...bullmq, name: 'BullMQ Worker' },
    },
  });
});

router.get('/backups', authenticate, requireRole('admin'), async (req, res) => {
  try {
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const files = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.endsWith('.sql.gz') || f.endsWith('.sql'))
      .map(f => {
        const stat = fs.statSync(path.join(BACKUP_DIR, f));
        return { name: f, size: stat.size, created_at: stat.mtime.toISOString() };
      })
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    res.json(files);
  } catch (err) {
    res.status(500).json({ error: 'Erreur lecture sauvegardes' });
  }
});

router.post('/backups/trigger', authenticate, requireRole('admin'), async (req, res) => {
  try {
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

    const ts       = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const filename = `heimdall-backup-${ts}.sql.gz`;
    const outPath  = path.join(BACKUP_DIR, filename);

    const dump = spawnSync('pg_dump', [
      '--host',     process.env.DB_HOST     || 'db',
      '--port',     process.env.DB_PORT     || '5432',
      '--username', process.env.DB_USER     || 'forensiclab',
      '--dbname',   process.env.DB_NAME     || 'forensiclab',
      '--no-password',
      '--format=plain',
    ], {
      env: { ...process.env, PGPASSWORD: process.env.DB_PASSWORD },
      encoding: 'buffer',
      maxBuffer: 512 * 1024 * 1024,
      timeout: 5 * 60 * 1000,
    });

    if (dump.status !== 0) {
      const errMsg = dump.stderr?.toString() || 'pg_dump failed';
      logger.error('[backup] pg_dump error:', errMsg);
      return res.status(500).json({ error: 'pg_dump échoué', detail: errMsg.slice(0, 200) });
    }

    const gzip = spawnSync('gzip', [], { input: dump.stdout, encoding: 'buffer', maxBuffer: 512 * 1024 * 1024 });
    if (gzip.status !== 0) return res.status(500).json({ error: 'gzip échoué' });

    fs.writeFileSync(outPath, gzip.stdout);
    const stat = fs.statSync(outPath);

    await auditLog(req.user.id, 'backup_db', 'system', null,
      { filename, size: stat.size }, req.ip);

    res.json({ ok: true, filename, size: stat.size, created_at: stat.mtime.toISOString() });
  } catch (err) {
    logger.error('[backup]', err);
    res.status(500).json({ error: 'Erreur sauvegarde' });
  }
});

router.post('/backups/schedule', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const { parserQueue } = require('../config/queue');
    const cron = (req.body && req.body.cron) || '0 2 * * *';

    const repeatableJobs = await parserQueue.getRepeatableJobs();
    for (const job of repeatableJobs) {
      if (job.name === 'backup') {
        await parserQueue.removeRepeatableByKey(job.key);
      }
    }

    await parserQueue.add(
      'backup',
      { parser: 'backup', evidenceId: '', caseId: '', userId: req.user.id, socketId: '', extraArgs: {} },
      { repeat: { cron }, jobId: 'scheduled-backup' }
    );

    await auditLog(req.user.id, 'backup_schedule_set', 'system', null, { cron }, req.ip);
    res.json({ ok: true, cron });
  } catch (err) {
    logger.error('[backup/schedule]', err);
    res.status(500).json({ error: 'Erreur planification sauvegarde' });
  }
});

router.delete('/backups/schedule', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const { parserQueue } = require('../config/queue');
    const repeatableJobs = await parserQueue.getRepeatableJobs();
    let removed = 0;
    for (const job of repeatableJobs) {
      if (job.name === 'backup') {
        await parserQueue.removeRepeatableByKey(job.key);
        removed++;
      }
    }
    await auditLog(req.user.id, 'backup_schedule_removed', 'system', null, { removed }, req.ip);
    res.json({ ok: true, removed });
  } catch (err) {
    logger.error('[backup/schedule delete]', err);
    res.status(500).json({ error: 'Erreur suppression planification' });
  }
});

router.get('/backups/schedule', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const { parserQueue } = require('../config/queue');
    const repeatableJobs = await parserQueue.getRepeatableJobs();
    const backupJobs = repeatableJobs
      .filter(j => j.name === 'backup')
      .map(j => ({ cron: j.cron, next: j.next ? new Date(j.next).toISOString() : null, key: j.key }));
    res.json({ scheduled: backupJobs.length > 0, jobs: backupJobs });
  } catch (err) {
    logger.error('[backup/schedule get]', err);
    res.status(500).json({ error: 'Erreur lecture planification' });
  }
});

router.get('/backups/:filename', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const name = path.basename(req.params.filename);
    if (!name.match(/^heimdall-backup-[\d\-T]+\.sql(\.gz)?$/)) {
      return res.status(400).json({ error: 'Nom de fichier invalide' });
    }
    const filePath = path.join(BACKUP_DIR, name);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Fichier non trouvé' });

    await auditLog(req.user.id, 'download_backup', 'system', null, { filename: name }, req.ip);
    res.download(filePath, name);
  } catch (err) {
    res.status(500).json({ error: 'Erreur téléchargement' });
  }
});

router.get('/docker/containers', authenticate, requireRole('admin'), async (req, res) => {
  let Docker;
  try { Docker = require('dockerode'); } catch {
    return res.status(503).json({ error: 'dockerode non disponible — rebuild le conteneur backend' });
  }

  try {
    const docker = new Docker({ socketPath: '/var/run/docker.sock' });
    const allList = await docker.listContainers({ all: true });

    const PROJECT_NAMES = new Set(['heimdall', 'forensic-lab', 'forensiclab']);
    const CONTAINER_NAMES = new Set([
      'bifrost', 'asgard', 'odin', 'huginn', 'yggdrasil',
      'hermod', 'mimir', 'tyr', 'njord',
      'hel-api', 'hel-worker', 'hel-ui', 'hel-proxy',
    ]);
    const list = allList.filter(info => {
      const project = info.Labels?.['com.docker.compose.project'];
      if (project) return PROJECT_NAMES.has(project);
      const name = (info.Names[0] || '').replace(/^\
      return CONTAINER_NAMES.has(name);
    });

    const results = await Promise.allSettled(list.map(async (info) => {
      const base = {
        id:     info.Id.slice(0, 12),
        name:   (info.Names[0] || '').replace(/^\
        image:  info.Image.replace(/^sha256:/, '').slice(0, 60),
        status: info.Status,
        state:  info.State,
        cpu_percent: 0,
        mem_used: 0,
        mem_limit: 0,
        mem_percent: 0,
      };

      if (info.State !== 'running') return base;

      try {
        const container = docker.getContainer(info.Id);
        const stats = await withTimeout(container.stats({ stream: false }), 4000, null);
        if (!stats) return base;

        const cpuDelta    = (stats.cpu_stats.cpu_usage.total_usage || 0) - (stats.precpu_stats.cpu_usage.total_usage || 0);
        const sysDelta    = (stats.cpu_stats.system_cpu_usage || 0) - (stats.precpu_stats.system_cpu_usage || 0);
        const numCpus     = stats.cpu_stats.online_cpus || stats.cpu_stats.cpu_usage.percpu_usage?.length || 1;
        const cpuPercent  = sysDelta > 0 ? (cpuDelta / sysDelta) * numCpus * 100 : 0;

        const memUsed    = (stats.memory_stats.usage || 0) - (stats.memory_stats.stats?.cache || 0);
        const memLimit   = stats.memory_stats.limit || 0;
        const memPercent = memLimit > 0 ? (memUsed / memLimit) * 100 : 0;

        return {
          ...base,
          cpu_percent: Math.round(cpuPercent * 10) / 10,
          mem_used:    memUsed,
          mem_limit:   memLimit,
          mem_percent: Math.round(memPercent * 10) / 10,
        };
      } catch { return base; }
    }));

    const containers = results.map(r => r.status === 'fulfilled' ? r.value : null).filter(Boolean);
    res.json({ timestamp: new Date().toISOString(), containers });
  } catch (err) {
    const msg = err.code === 'EACCES'
      ? 'Permission refusée sur /var/run/docker.sock — vérifier DOCKER_GID dans .env'
      : err.code === 'ENOENT'
        ? 'Socket Docker introuvable — monter /var/run/docker.sock dans docker-compose.yml'
        : err.message;
    logger.error('[docker/containers]', err.message);
    res.status(503).json({ error: msg });
  }
});

router.get('/jobs', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const { filter, since } = req.query;
    let where = '';
    const params = [];

    if (since === '24h') {
      params.push(new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString());
      where = `WHERE pr.updated_at >= $${params.length}`;
    }

    const result = await pool.query(
      `SELECT pr.id, pr.case_id, pr.evidence_id, pr.record_count,
              pr.output_data, pr.parsed_at, pr.updated_at,
              c.case_number, c.title AS case_title,
              u.username AS analyst
         FROM parser_results pr
         JOIN cases c ON pr.case_id = c.id
         LEFT JOIN users u ON pr.created_by = u.id
         ${where}
         ORDER BY pr.updated_at DESC
         LIMIT 200`,
      params
    );

    const jobs = result.rows.map(row => {
      const parseResults = row.output_data?.parse_results || [];
      let status = 'ok';
      if (parseResults.some(r => r.status === 'error')) status = 'error';
      else if (parseResults.some(r => r.status === 'degraded')) status = 'degraded';
      return { ...row, status };
    });

    const filtered = filter === 'error'
      ? jobs.filter(j => j.status === 'error')
      : jobs;

    res.json(filtered);
  } catch (err) {
    logger.error('[admin/jobs]', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/ollama/status', authenticate, requireRole('admin'), async (req, res) => {
  let Docker;
  try { Docker = require('dockerode'); } catch {
    return res.status(503).json({ error: 'dockerode non disponible' });
  }
  try {
    const docker = new Docker({ socketPath: '/var/run/docker.sock' });
    const containers = await docker.listContainers({ all: true });
    const ollama = containers.find(c =>
      c.Names?.some(n => n.includes('ollama')) ||
      c.Image?.includes('ollama/ollama')
    );
    if (!ollama) return res.json({ exists: false, running: false, state: 'absent' });
    res.json({ exists: true, running: ollama.State === 'running', state: ollama.State, id: ollama.Id });
  } catch (err) {
    logger.error('[ollama/status]', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.post('/ollama/install', authenticate, requireRole('admin'), async (req, res) => {
  let Docker;
  try { Docker = require('dockerode'); } catch {
    return res.status(503).json({ error: 'dockerode non disponible' });
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  function send(data) { res.write(`data: ${JSON.stringify(data)}\n\n`); }

  const docker = new Docker({ socketPath: '/var/run/docker.sock' });

  try {
    const existing = await docker.listContainers({ all: true });
    const ollamaContainer = existing.find(c =>
      c.Names?.some(n => n.includes('ollama')) || c.Image?.includes('ollama/ollama')
    );

    if (ollamaContainer) {
      if (ollamaContainer.State === 'running') {
        send({ phase: 'done', message: 'Ollama est déjà démarré.' });
        res.write('data: [DONE]\n\n');
        return res.end();
      }
      send({ phase: 'starting', message: 'Démarrage du container Ollama existant…' });
      const container = docker.getContainer(ollamaContainer.Id);
      await container.start();
      send({ phase: 'done', message: 'Ollama démarré.' });
      res.write('data: [DONE]\n\n');
      return res.end();
    }

    send({ phase: 'pull', message: 'Téléchargement de ollama/ollama:latest…', pct: 0 });
    await new Promise((resolve, reject) => {
      docker.pull('ollama/ollama:latest', (err, stream) => {
        if (err) return reject(err);
        const layers = {};
        docker.modem.followProgress(stream,
          (err) => err ? reject(err) : resolve(),
          (event) => {
            if (event.id && event.progressDetail?.total) {
              layers[event.id] = { done: event.progressDetail.current || 0, total: event.progressDetail.total };
            }
            const totalBytes = Object.values(layers).reduce((s, l) => s + l.total, 0);
            const doneBytes  = Object.values(layers).reduce((s, l) => s + l.done, 0);
            const pct = totalBytes > 0 ? Math.round((doneBytes / totalBytes) * 100) : 0;
            send({ phase: 'pull', message: event.status || 'Téléchargement…', pct });
          }
        );
      });
    });
    send({ phase: 'pull', message: 'Image téléchargée.', pct: 100 });

    send({ phase: 'create', message: 'Création du container…' });
    const container = await docker.createContainer({
      Image: 'ollama/ollama:latest',
      name: 'ollama',
      Env: ['OLLAMA_HOST=0.0.0.0'],
      HostConfig: {
        RestartPolicy: { Name: 'unless-stopped' },
        Binds: ['ollama_data:/root/.ollama'],
        NetworkMode: 'forensic-lab_aesir-net',
      },
    });

    send({ phase: 'starting', message: 'Démarrage du container…' });
    await container.start();

    send({ phase: 'done', message: 'Ollama installé et démarré avec succès !' });
    res.write('data: [DONE]\n\n');
    res.end();
  } catch (err) {
    send({ phase: 'error', message: err.message });
    res.write('data: [DONE]\n\n');
    res.end();
    logger.error('[ollama/install]', err.message);
  }
});

router.post('/ollama/stop', authenticate, requireRole('admin'), async (req, res) => {
  let Docker;
  try { Docker = require('dockerode'); } catch {
    return res.status(503).json({ error: 'dockerode non disponible' });
  }
  try {
    const docker = new Docker({ socketPath: '/var/run/docker.sock' });
    const containers = await docker.listContainers({ all: true });
    const c = containers.find(x => x.Names?.some(n => n.includes('ollama')) || x.Image?.includes('ollama/ollama'));
    if (!c) return res.status(404).json({ error: 'Container Ollama introuvable' });
    const container = docker.getContainer(c.Id);
    if (c.State === 'running') await container.stop({ t: 5 });
    res.json({ ok: true });
  } catch (err) {
    logger.error('[ollama/stop]', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
