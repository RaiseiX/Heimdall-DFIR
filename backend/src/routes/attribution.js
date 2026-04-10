const express = require('express');
const logger = require('../config/logger').default;
const router = express.Router();
const { authenticate } = require('../middleware/auth');

const APT_GROUPS = [
  { id: 'G0007', name: 'APT28', aliases: ['Fancy Bear', 'Sofacy', 'STRONTIUM'], origin: 'Russia', motivation: 'Espionage', color: '#c0392b', techniques: ['T1566','T1059','T1547','T1053','T1078','T1021','T1003','T1071','T1041'], tactics: ['Initial Access','Execution','Persistence','Privilege Escalation','Credential Access','Lateral Movement','Collection','Exfiltration'] },
  { id: 'G0016', name: 'APT29', aliases: ['Cozy Bear', 'NOBELIUM', 'The Dukes'], origin: 'Russia', motivation: 'Espionage', color: '#8e44ad', techniques: ['T1566','T1059','T1547','T1027','T1036','T1003','T1071','T1041','T1105'], tactics: ['Initial Access','Execution','Persistence','Defense Evasion','Credential Access','Collection','Exfiltration'] },
  { id: 'G0050', name: 'APT32', aliases: ['OceanLotus', 'SeaLotus'], origin: 'Vietnam', motivation: 'Espionage', color: '#27ae60', techniques: ['T1566','T1059','T1547','T1055','T1036','T1003','T1071'], tactics: ['Initial Access','Execution','Persistence','Defense Evasion','Credential Access'] },
  { id: 'G0096', name: 'APT41', aliases: ['Winnti', 'BARIUM', 'Double Dragon'], origin: 'China', motivation: 'Espionage + Financial', color: '#e74c3c', techniques: ['T1190','T1059','T1078','T1543','T1547','T1036','T1027','T1055','T1003','T1071','T1105'], tactics: ['Initial Access','Execution','Persistence','Privilege Escalation','Defense Evasion','Credential Access','Lateral Movement','Command and Control','Exfiltration'] },
  { id: 'G0065', name: 'Lazarus Group', aliases: ['HIDDEN COBRA', 'APT38', 'Zinc'], origin: 'North Korea', motivation: 'Espionage + Financial', color: '#2980b9', techniques: ['T1566','T1059','T1078','T1547','T1027','T1036','T1055','T1003','T1041','T1486'], tactics: ['Initial Access','Execution','Persistence','Defense Evasion','Credential Access','Impact'] },
  { id: 'G0034', name: 'Sandworm', aliases: ['Voodoo Bear', 'ELECTRUM', 'Telebots'], origin: 'Russia', motivation: 'Espionage + Destruction', color: '#e67e22', techniques: ['T1190','T1059','T1486','T1490','T1561','T1078','T1071'], tactics: ['Initial Access','Execution','Persistence','Impact'] },
  { id: 'G0022', name: 'FIN7', aliases: ['Carbanak', 'Navigator Group'], origin: 'Russia', motivation: 'Financial', color: '#145a32', techniques: ['T1566','T1059','T1547','T1055','T1036','T1003','T1041','T1486'], tactics: ['Initial Access','Execution','Persistence','Defense Evasion','Credential Access','Impact'] },
  { id: 'G0010', name: 'Turla', aliases: ['Snake', 'Uroburos', 'Waterbug'], origin: 'Russia', motivation: 'Espionage', color: '#6c3483', techniques: ['T1566','T1059','T1547','T1027','T1055','T1071','T1041'], tactics: ['Initial Access','Execution','Persistence','Defense Evasion','Command and Control'] },
  { id: 'G0087', name: 'APT39', aliases: ['Chafer', 'ITG07'], origin: 'Iran', motivation: 'Espionage', color: '#1a5276', techniques: ['T1566','T1059','T1547','T1021','T1003','T1071','T1041'], tactics: ['Initial Access','Execution','Persistence','Lateral Movement','Credential Access'] },
  { id: 'G0049', name: 'OilRig', aliases: ['APT34', 'Helix Kitten', 'CHRYSENE'], origin: 'Iran', motivation: 'Espionage', color: '#784212', techniques: ['T1566','T1059','T1547','T1055','T1071','T1003','T1041'], tactics: ['Initial Access','Execution','Persistence','Defense Evasion','Credential Access'] },
  { id: 'G0045', name: 'menuPass', aliases: ['APT10', 'Stone Panda', 'POTASSIUM'], origin: 'China', motivation: 'Espionage', color: '#0e6655', techniques: ['T1190','T1059','T1078','T1021','T1003','T1071','T1041'], tactics: ['Initial Access','Execution','Persistence','Lateral Movement','Credential Access','Exfiltration'] },
  { id: 'G0047', name: 'Gamaredon Group', aliases: ['Primitive Bear', 'ACTINIUM'], origin: 'Russia', motivation: 'Espionage', color: '#922b21', techniques: ['T1566','T1059','T1547','T1027','T1071'], tactics: ['Initial Access','Execution','Persistence','Defense Evasion'] },
];

router.get('/:caseId', authenticate, async (req, res) => {
  const { caseId } = req.params;
  const pool = req.app.locals.pool;

  try {

    const techniqueSets = await Promise.allSettled([
      pool.query(`SELECT DISTINCT technique_id FROM case_mitre_techniques WHERE case_id = $1 AND technique_id IS NOT NULL`, [caseId]),
      pool.query(`SELECT DISTINCT mitre_technique AS technique_id FROM timeline_bookmarks WHERE case_id = $1 AND mitre_technique IS NOT NULL`, [caseId]),
      pool.query(`SELECT matched_events FROM sigma_hunt_results WHERE case_id = $1`, [caseId]),
    ]);

    const caseSet = new Set();

    if (techniqueSets[0].status === 'fulfilled') {
      techniqueSets[0].value.rows.forEach(r => { if (r.technique_id) caseSet.add(r.technique_id.toUpperCase()); });
    }

    if (techniqueSets[1].status === 'fulfilled') {
      techniqueSets[1].value.rows.forEach(r => { if (r.technique_id) caseSet.add(r.technique_id.toUpperCase()); });
    }

    if (techniqueSets[2].status === 'fulfilled') {
      const mitreTagRe = /attack\.(t\d{4}(?:\.\d{3})?)/gi;
      techniqueSets[2].value.rows.forEach(r => {
        const events = Array.isArray(r.matched_events) ? r.matched_events : [];
        events.forEach(ev => {
          const tags = ev.Tags || ev.tags || [];
          const tagStr = Array.isArray(tags) ? tags.join(' ') : String(tags || '');
          let m;
          while ((m = mitreTagRe.exec(tagStr)) !== null) {
            caseSet.add(m[1].toUpperCase());
          }
        });
      });
    }

    const caseTechniques = [...caseSet];

    const attributions = APT_GROUPS.map(group => {
      const matched = group.techniques.filter(t => caseSet.has(t.toUpperCase()));
      const matchScore = group.techniques.length > 0 ? (matched.length / group.techniques.length * 100) : 0;
      return {
        id: group.id,
        name: group.name,
        aliases: group.aliases,
        origin: group.origin,
        motivation: group.motivation,
        color: group.color,
        match_score: +matchScore.toFixed(1),
        match_count: matched.length,
        matched_techniques: matched,
        confidence: matchScore >= 60 ? 'high' : matchScore >= 30 ? 'medium' : 'low',
      };
    })
    .filter(a => a.match_count > 0)
    .sort((a, b) => b.match_score - a.match_score);

    res.json({ case_techniques: caseTechniques, total_case_techniques: caseTechniques.length, attributions });
  } catch (err) {
    logger.error('[attribution] error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;
