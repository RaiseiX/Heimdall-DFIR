#!/usr/bin/env node

'use strict';

require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });
const { Pool } = require('pg');

const pool = new Pool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     parseInt(process.env.DB_PORT || '5432', 10),
  database: process.env.DB_NAME     || 'forensiclab',
  user:     process.env.DB_USER     || 'forensiclab',
  password: process.env.DB_PASSWORD,
  ssl:      process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
});

async function upsertCase(client, data) {
  const { rows } = await client.query(
    `INSERT INTO cases (case_number, title, description, status, priority, created_at)
     VALUES ($1, $2, $3, $4, $5, NOW())
     ON CONFLICT (case_number) DO UPDATE SET
       title       = EXCLUDED.title,
       description = EXCLUDED.description,
       priority    = EXCLUDED.priority
     RETURNING id, case_number`,
    [data.case_number, data.title, data.description, data.status, data.priority],
  );
  return rows[0];
}

async function upsertIOC(client, caseId, data) {
  await client.query(
    `INSERT INTO iocs (case_id, ioc_type, value, severity, is_malicious, description, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, NOW())
     ON CONFLICT (case_id, value) DO UPDATE SET
       severity     = EXCLUDED.severity,
       is_malicious = EXCLUDED.is_malicious,
       description  = EXCLUDED.description`,
    [caseId, data.ioc_type, data.value, data.severity, data.is_malicious, data.description],
  );
}

async function upsertCollectionTimeline(client, caseId, rows) {
  for (const row of rows) {
    await client.query(
      `INSERT INTO collection_timeline
         (case_id, timestamp, artifact_type, source, description, raw)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT DO NOTHING`,
      [caseId, row.timestamp, row.artifact_type, row.source, row.description, JSON.stringify(row.raw || {})],
    );
  }
}

async function main() {
  const client = await pool.connect();
  try {
    console.log('[seed-demo] Connected to PostgreSQL');

    const caseA = await upsertCase(client, {
      case_number: 'DEMO-2026-001',
      title:       'Incident Ransomware — Département Finance',
      description: 'Chiffrement massif détecté sur serveur FS-FINANCE-01. Indicateurs LockBit 3.0.',
      status:      'active',
      priority:    'critical',
    });
    console.log(`[seed-demo] Case A: ${caseA.case_number} (${caseA.id})`);

    const sharedIP = '185.220.101.47';
    await upsertIOC(client, caseA.id, {
      ioc_type:    'ipv4',
      value:       sharedIP,
      severity:    10,
      is_malicious: true,
      description: 'C2 LockBit 3.0 — Tor exit node confirmé',
    });
    await upsertIOC(client, caseA.id, {
      ioc_type:    'sha256',
      value:       'a3b2c1d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef',
      severity:    9,
      is_malicious: true,
      description: 'Ransomware payload — LockBit3.exe',
    });
    await upsertIOC(client, caseA.id, {
      ioc_type:    'domain',
      value:       'lockbit3-decryptor.onion.ws',
      severity:    8,
      is_malicious: true,
      description: 'Domaine de paiement rançon',
    });
    await upsertIOC(client, caseA.id, {
      ioc_type:    'ipv4',
      value:       '10.10.0.55',
      severity:    5,
      is_malicious: false,
      description: 'Machine interne compromise FS-FINANCE-01',
    });

    await upsertCollectionTimeline(client, caseA.id, [
      {
        timestamp:     '2026-03-20T02:14:33Z',
        artifact_type: 'Prefetch',
        source:        'FS-FINANCE-01',
        description:   'vssadmin.exe exécuté — suppression VSS (T1490)',
        raw:           { ProcessName: 'vssadmin.exe', CommandLine: 'vssadmin delete shadows /all /quiet', IpAddress: sharedIP },
      },
      {
        timestamp:     '2026-03-20T02:15:01Z',
        artifact_type: 'EVTX',
        source:        'FS-FINANCE-01',
        description:   'PowerShell encodé exécuté (EID 4688)',
        raw:           { ProcessName: 'powershell.exe', CommandLine: '-EncodedCommand UwB0AG8AcAAtAFMAZQByAHYAaQBjAGUA', IpAddress: sharedIP },
      },
      {
        timestamp:     '2026-03-20T02:17:55Z',
        artifact_type: 'Network',
        source:        'FS-FINANCE-01',
        description:   `Connexion sortante C2 vers ${sharedIP}`,
        raw:           { DestinationAddress: sharedIP, DestinationPort: '443', Protocol: 'TCP' },
      },
    ]);

    await client.query(
      `UPDATE cases SET risk_score = 87, risk_level = 'CRITICAL', risk_computed_at = NOW() WHERE id = $1`,
      [caseA.id],
    );
    console.log('[seed-demo] Case A IOCs + timeline + risk score OK');

    const caseB = await upsertCase(client, {
      case_number: 'DEMO-2026-002',
      title:       'Phishing RH — Analyse préliminaire',
      description: 'Email de phishing reçu par 3 employés RH. Aucun exécutable téléchargé confirmé.',
      status:      'pending',
      priority:    'low',
    });
    console.log(`[seed-demo] Case B: ${caseB.case_number} (${caseB.id})`);

    await upsertIOC(client, caseB.id, {
      ioc_type:    'ipv4',
      value:       sharedIP,
      severity:    6,
      is_malicious: true,
      description: 'IP source du phishing — même infrastructure que DEMO-2026-001',
    });
    await upsertIOC(client, caseB.id, {
      ioc_type:    'domain',
      value:       'rh-portail-secure.com',
      severity:    7,
      is_malicious: true,
      description: 'Domaine de phishing mimant le portail RH interne',
    });
    await upsertIOC(client, caseB.id, {
      ioc_type:    'url',
      value:       'https://rh-portail-secure.com/login',
      severity:    7,
      is_malicious: true,
      description: 'URL de phishing avec formulaire de credentials',
    });

    await upsertCollectionTimeline(client, caseB.id, [
      {
        timestamp:     '2026-03-21T09:42:11Z',
        artifact_type: 'EVTX',
        source:        'WORKSTATION-RH-03',
        description:   'Accès navigateur vers domaine phishing',
        raw:           { URL: 'https://rh-portail-secure.com/login', IpAddress: sharedIP },
      },
    ]);

    await client.query(
      `UPDATE cases SET risk_score = 14, risk_level = 'LOW', risk_computed_at = NOW() WHERE id = $1`,
      [caseB.id],
    );
    console.log('[seed-demo] Case B IOCs + timeline + risk score OK');

    console.log(`
[seed-demo] ✅ Données démo créées avec succès
  Case A (CRITICAL) : ${caseA.id}
  Case B (LOW)      : ${caseB.id}
  IOC commun        : ${sharedIP} (visible dans les 2 cas — démo cross-case correlation)
    `);
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch(err => {
  console.error('[seed-demo] ERREUR:', err.message);
  process.exit(1);
});
