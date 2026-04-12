import { useState } from 'react';
import { Copy, CheckCheck, ChevronDown, ChevronRight, CheckSquare, Square } from 'lucide-react';
import { useTheme } from '../../utils/theme';

function CopyBtn({ text }) {
  const [ok, setOk] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text).then(() => { setOk(true); setTimeout(() => setOk(false), 1800); }); }}
      title="Copier"
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 3,
        padding: '2px 6px', borderRadius: 4, cursor: 'pointer',
        fontSize: 9, fontFamily: 'monospace', flexShrink: 0,
        background: ok ? '#22c55e18' : 'var(--fl-card)',
        color: ok ? '#22c55e' : 'var(--fl-dim)',
        border: `1px solid ${ok ? '#22c55e40' : 'var(--fl-border)'}`,
      }}>
      {ok ? <CheckCheck size={9} /> : <Copy size={9} />}
    </button>
  );
}

function ChecklistSection({ title, items, color }) {
  const T = useTheme();
  const [checked, setChecked] = useState({});
  const toggle = (i) => setChecked(p => ({ ...p, [i]: !p[i] }));
  const c = color || 'var(--fl-accent)';

  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: c, marginBottom: 8 }}>{title}</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        {items.map((item, i) => (
          <button key={i} onClick={() => toggle(i)}
            style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '6px 10px', borderRadius: 5, cursor: 'pointer',
              background: checked[i] ? 'color-mix(in srgb, var(--fl-ok) 8%, transparent)' : T.panel,
              border: `1px solid ${checked[i] ? 'color-mix(in srgb, var(--fl-ok) 25%, transparent)' : T.border}`,
              textAlign: 'left', width: '100%' }}>
            {checked[i]
              ? <CheckSquare size={12} style={{ color: 'var(--fl-ok)', flexShrink: 0, marginTop: 1 }} />
              : <Square size={12} style={{ color: T.dim, flexShrink: 0, marginTop: 1 }} />}
            <span style={{ fontFamily: 'monospace', fontSize: 11, color: checked[i] ? T.dim : T.text, textDecoration: checked[i] ? 'line-through' : 'none', lineHeight: 1.5 }}>{item}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

function PhaseCard({ phase }) {
  const T = useTheme();
  const [open, setOpen] = useState(false);

  return (
    <div style={{ border: `1px solid ${phase.borderColor}`, borderRadius: 8, overflow: 'hidden', marginBottom: 10 }}>
      <button onClick={() => setOpen(o => !o)} className="w-full text-left"
        style={{ padding: '12px 16px', background: phase.bgColor, border: 'none', cursor: 'pointer', display: 'block', width: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 700, padding: '2px 7px', borderRadius: 3,
              background: phase.badgeBg, color: phase.badgeColor, border: `1px solid ${phase.borderColor}` }}>
              {phase.number}
            </div>
            <span style={{ fontSize: 15 }}>{phase.icon}</span>
            <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: 13, color: T.text }}>{phase.title}</span>
          </div>
          {open ? <ChevronDown size={13} style={{ color: T.dim, flexShrink: 0 }} /> : <ChevronRight size={13} style={{ color: T.dim, flexShrink: 0 }} />}
        </div>
        <p style={{ fontSize: 11, marginTop: 5, marginLeft: 55, color: T.muted, fontFamily: 'monospace', lineHeight: 1.5 }}>{phase.desc}</p>
      </button>

      {open && (
        <div style={{ background: T.bg, padding: '16px 16px' }}>
          {phase.sections.map((s, i) => {
            if (s.type === 'checklist') {
              return <ChecklistSection key={i} title={s.label} items={s.items} color={phase.badgeColor} />;
            }
            if (s.type === 'commands') {
              return (
                <div key={i} style={{ marginBottom: 16 }}>
                  <div style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: phase.badgeColor, marginBottom: 8 }}>{s.label}</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                    {s.items.map((cmd, j) => (
                      <div key={j} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, padding: '5px 9px', borderRadius: 4,
                        background: T.panel, border: '1px solid var(--fl-border)' }}>
                        <code style={{ fontFamily: 'monospace', fontSize: 11, color: cmd.startsWith('#') ? T.dim : 'var(--fl-ok)', wordBreak: 'break-all', flex: 1, lineHeight: 1.5 }}>{cmd}</code>
                        {!cmd.startsWith('#') && <CopyBtn text={cmd} />}
                      </div>
                    ))}
                  </div>
                </div>
              );
            }
            if (s.type === 'text') {
              return (
                <div key={i} style={{ marginBottom: 16 }}>
                  <div style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: phase.badgeColor, marginBottom: 8 }}>{s.label}</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {s.items.map((item, j) => (
                      <div key={j} style={{ display: 'flex', alignItems: 'flex-start', gap: 6, fontSize: 11, fontFamily: 'monospace', color: T.text }}>
                        <span style={{ color: phase.badgeColor, flexShrink: 0 }}>›</span>
                        <span>{item}</span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            }
            return null;
          })}
        </div>
      )}
    </div>
  );
}

const PHASES = [
  {
    number: '01',
    icon: '🚨',
    title: 'Détection & Triage Initial',
    desc: 'Confirmer ou infirmer l\'incident, estimer le périmètre, activer la cellule de crise. Ne pas contaminer les preuves.',
    bgColor: 'color-mix(in srgb, #f97316 6%, transparent)',
    borderColor: 'color-mix(in srgb, #f97316 30%, transparent)',
    badgeBg: 'color-mix(in srgb, #f97316 15%, transparent)',
    badgeColor: '#f97316',
    sections: [
      {
        type: 'checklist',
        label: 'Triage initial (5 premières minutes)',
        items: [
          'Confirmer la source de l\'alerte (EDR, SIEM, utilisateur, partenaire, threat intel)',
          'Identifier le ou les systèmes initialement affectés',
          'Vérifier si l\'alerte est un vrai positif (faux positif possible)',
          'Documenter l\'heure de détection et l\'heure estimée de compromission',
          'Notifier le responsable sécurité / RSSI / cellule de crise selon procédure',
          'Ouvrir un ticket d\'incident avec chronologie et preuves initiales',
          'NE PAS redémarrer les systèmes compromis (perte mémoire RAM)',
          'NE PAS supprimer les fichiers suspects avant analyse',
        ],
      },
      {
        type: 'text',
        label: 'Classification de l\'incident',
        items: [
          'Niveau 1 — Incident isolé : un seul endpoint, pas de mouvement latéral détecté',
          'Niveau 2 — Incident étendu : plusieurs endpoints, credentials compromis',
          'Niveau 3 — Incident critique : compromission DC / domaine, ransomware, exfiltration',
          'Critères : données sensibles impactées ? Infrastructure critique ? Propagation active ?',
          'NIST IR Levels : Low / Medium / High / Critical',
        ],
      },
      {
        type: 'checklist',
        label: 'Questions clés à documenter immédiatement',
        items: [
          'Quand l\'incident a-t-il débuté ? (date/heure UTC)',
          'Quels systèmes sont confirmés compromis ?',
          'Quels systèmes sont suspectés compromis ?',
          'Y a-t-il des preuves de mouvement latéral ?',
          'Y a-t-il des preuves d\'exfiltration de données ?',
          'Quelle est l\'identité de l\'attaquant (APT ? Ransomware ? Insider ?) ?',
          'L\'attaquant est-il toujours actif sur le réseau ?',
          'Quels comptes privilégiés sont potentiellement compromis ?',
        ],
      },
    ],
  },
  {
    number: '02',
    icon: '🔒',
    title: 'Confinement',
    desc: 'Limiter la propagation sans détruire les preuves. Confinement court terme puis long terme.',
    bgColor: 'color-mix(in srgb, #ef4444 6%, transparent)',
    borderColor: 'color-mix(in srgb, #ef4444 30%, transparent)',
    badgeBg: 'color-mix(in srgb, #ef4444 15%, transparent)',
    badgeColor: '#ef4444',
    sections: [
      {
        type: 'checklist',
        label: 'Confinement court terme (pendant l\'investigation)',
        items: [
          'Isoler les systèmes compromis du réseau (VLAN isolation ou débranchement câble)',
          'Révoquer les tokens / sessions actives des comptes compromis (Azure AD, VPN)',
          'Bloquer les IPs/domaines C2 identifiés (firewall, DNS sinkhole)',
          'Désactiver les comptes utilisateurs compromis (sans les supprimer)',
          'Bloquer l\'exécution du malware identifié (hash IoC dans EDR)',
          'Activer le logging renforcé sur tous les systèmes critiques',
          'Conserver une copie de la mémoire RAM avant tout confinement réseau (si possible)',
          'DOCUMENTER chaque action de confinement avec timestamp',
        ],
      },
      {
        type: 'checklist',
        label: 'Confinement long terme',
        items: [
          'Réinitialisation des mots de passe de tous les comptes potentiellement exposés',
          'Rotation du compte KRBTGT (si DC compromis — 2 fois à 24h d\'intervalle)',
          'Révocation de tous les tokens d\'accès actifs (Azure, VPN)',
          'Désactivation de protocoles vulnérables (NTLM, WDigest si encore actifs)',
          'Mise en quarantaine des partages réseau accessibles depuis les machines compromises',
          'Vérifier et révoquer les clés SSH sur tous les serveurs Linux accessibles',
          'Bloquer les ports de mouvement latéral entre workstations (445, 135, 5985)',
        ],
      },
      {
        type: 'text',
        label: 'Décision : isoler vs surveiller',
        items: [
          'ISOLER si : ransomware actif, exfiltration en cours, propagation détectée',
          'SURVEILLER si : accès initial seulement, attaquant non encore actif, besoin d\'attribution',
          'Compromis : honeypot network — laisser la session active dans un réseau coupé d\'Internet',
          'Toujours consulter direction + juridique avant de décider de surveiller un attaquant actif',
        ],
      },
    ],
  },
  {
    number: '03',
    icon: '🔬',
    title: 'Acquisition Forensique',
    desc: 'Collecter les preuves de façon légale et reproductible. Ordre de volatilité : RAM → réseau → disque.',
    bgColor: 'color-mix(in srgb, #3b82f6 6%, transparent)',
    borderColor: 'color-mix(in srgb, #3b82f6 30%, transparent)',
    badgeBg: 'color-mix(in srgb, #3b82f6 15%, transparent)',
    badgeColor: '#3b82f6',
    sections: [
      {
        type: 'text',
        label: 'Ordre de volatilité (RFC 3227)',
        items: [
          '1. Mémoire RAM (plus volatile — disparaît au reboot)',
          '2. État réseau actuel (connexions, tables ARP, routage)',
          '3. Processus en cours, comptes connectés',
          '4. Fichiers temporaires (ouvert par des processus)',
          '5. Disque dur / SSD (moins volatile)',
          '6. Logs distants (SIEM, Syslog serveur)',
          '7. Backups et archives (le moins volatile)',
        ],
      },
      {
        type: 'commands',
        label: 'Acquisition mémoire RAM (Windows)',
        items: [
          '# WinPmem (open source)',
          'winpmem_mini_x64_rc2.exe memory.raw',
          '# DumpIt (GUI)',
          'DumpIt.exe /OUTPUT memory.raw /Q',
          '# Magnet RAM Capture (GUI gratuit)',
          '# RAMMap + NotMyFault.exe (Sysinternals)',
          '# Via WinRM/PowerShell à distance',
          'Invoke-Command -ComputerName TARGET -ScriptBlock { winpmem.exe C:\\temp\\memory.raw }',
        ],
      },
      {
        type: 'commands',
        label: 'Acquisition mémoire RAM (Linux)',
        items: [
          '# LiME (Linux Memory Extractor) — module kernel',
          'insmod lime.ko "path=/evidence/memory.raw format=raw"',
          '# Via /proc/kcore (si root)',
          'dd if=/proc/kcore of=/evidence/memory.raw bs=1M',
          '# Avml (Amazon)',
          'avml /evidence/memory.raw',
        ],
      },
      {
        type: 'commands',
        label: 'Acquisition disque (Windows)',
        items: [
          '# FTK Imager — image DD/E01',
          '# kape.exe — collecte ciblée artefacts',
          'kape.exe --tsource C:\\ --tdest E:\\evidence\\ --target WindowsEvidenceCollection',
          '# DCFLdd / dd avec hash intégré',
          'dcfldd if=\\\\.\\PhysicalDrive0 of=E:\\disk.dd bs=512 hash=md5,sha256 hashlog=E:\\hash.txt',
          '# Hash SHA256 de l\'image',
          'certutil -hashfile disk.dd SHA256',
        ],
      },
      {
        type: 'commands',
        label: 'Acquisition disque (Linux)',
        items: [
          '# Copie avec vérification hash',
          'dd if=/dev/sda bs=4M | tee >(sha256sum > /evidence/disk.sha256) > /evidence/disk.dd',
          '# Avec compression',
          'dd if=/dev/sda bs=4M | gzip > /evidence/disk.dd.gz',
          '# Copie réseau (SSH)',
          'dd if=/dev/sda bs=4M | ssh analyst@forensic-server "dd of=/evidence/disk.dd"',
          '# Collecte artefacts Linux ciblée',
          'tar czf /evidence/linux_artifacts.tar.gz /var/log/ /etc/ /root/.bash_history /home/*/.bash_history 2>/dev/null',
        ],
      },
      {
        type: 'checklist',
        label: 'Chaîne de Custody',
        items: [
          'Étiqueter chaque support : numéro de cas, date, heure, acquéreur, machine source',
          'Calculer et enregistrer le hash SHA-256 de chaque image',
          'Conserver une copie "master" non modifiée',
          'Travailler sur une copie de travail uniquement',
          'Documenter chaque accès au support original',
          'Stocker les supports dans un lieu sécurisé avec accès tracé',
          'Signer et dater chaque formulaire de custody',
        ],
      },
    ],
  },
  {
    number: '04',
    icon: '🔍',
    title: 'Investigation & Analyse',
    desc: 'Reconstruire la chronologie, identifier le vecteur initial, cartographier la compromission.',
    bgColor: 'color-mix(in srgb, #a855f7 6%, transparent)',
    borderColor: 'color-mix(in srgb, #a855f7 30%, transparent)',
    badgeBg: 'color-mix(in srgb, #a855f7 15%, transparent)',
    badgeColor: '#a855f7',
    sections: [
      {
        type: 'text',
        label: 'Méthodologie d\'investigation Windows',
        items: [
          '1. EVTX — Hayabusa / Chainsaw : timeline des alertes Sigma',
          '2. MFT — MFTECmd : timeline des fichiers créés/modifiés',
          '3. Prefetch — PECmd : exécutables exécutés + timestamps',
          '4. Registry — RECmd : persistence, user activity, services',
          '5. Memory — Volatility3 : processus, connexions, malware',
          '6. Network — Zeek/Tshark : connexions C2, mouvement latéral',
          '7. Browser — Hindsight : historique, téléchargements',
          '8. Super-timeline — Plaso : corrélation toutes sources',
        ],
      },
      {
        type: 'checklist',
        label: 'Questions d\'investigation à répondre',
        items: [
          'Quel est le vecteur d\'accès initial (phishing, exploit, credential stuffing, insider) ?',
          'Quelle est la date/heure de la première activité malveillante ?',
          'Quels comptes ont été compromis ou créés par l\'attaquant ?',
          'Quels outils offensifs ont été déployés (Cobalt Strike, Mimikatz, etc.) ?',
          'Y a-t-il eu mouvement latéral ? Vers quelles machines ?',
          'Quelles données ont été accédées ou exfiltrées ?',
          'L\'attaquant a-t-il maintenu une persistance ? Via quel mécanisme ?',
          'L\'attaquant est-il toujours présent dans l\'environnement ?',
        ],
      },
      {
        type: 'text',
        label: 'Reconstruction de la timeline',
        items: [
          'Heure T0 : première activité malveillante identifiée (alerte EDR, log suspect)',
          'Heure T1 : vecteur initial (email phishing ouvert, exploit web, connexion RDP)',
          'Heure T2 : payload exécuté / persistence établie',
          'Heure T3 : credential access (LSASS dump, DCSync...)',
          'Heure T4 : mouvement latéral vers d\'autres machines',
          'Heure T5 : objectif final (exfiltration, ransomware, impact)',
          'Heure T6 : détection par les équipes de défense',
          'Dwell time = T6 - T0 (temps de présence avant détection)',
        ],
      },
      {
        type: 'commands',
        label: 'Outils de corrélation timeline',
        items: [
          '# Super-timeline avec Plaso',
          'log2timeline.py evidence.plaso /evidence/ && psort.py -o l2tcsv evidence.plaso -w timeline.csv',
          '# Timeline MFT + Prefetch + EVTX',
          'MFTECmd.exe -f $MFT --csv output\\ && PECmd.exe -d Prefetch\\ --csv output\\',
          '# Hayabusa timeline',
          'hayabusa.exe csv-timeline -d EVTX\\ -o hayabusa_timeline.csv',
          '# Corrélation dans Timesketch (Plaso)',
          'timesketch_import_client.py --sketch_id 1 evidence.plaso',
        ],
      },
    ],
  },
  {
    number: '05',
    icon: '🛠️',
    title: 'Éradication',
    desc: 'Supprimer tous les artefacts malveillants, persistence, accès backdoor de l\'environnement.',
    bgColor: 'color-mix(in srgb, #10b981 6%, transparent)',
    borderColor: 'color-mix(in srgb, #10b981 30%, transparent)',
    badgeBg: 'color-mix(in srgb, #10b981 15%, transparent)',
    badgeColor: '#10b981',
    sections: [
      {
        type: 'checklist',
        label: 'Checklist d\'éradication',
        items: [
          'Identifier et supprimer TOUS les mécanismes de persistance (Run keys, services, tâches, crons)',
          'Supprimer les comptes backdoor créés par l\'attaquant',
          'Supprimer les clés SSH injectées dans authorized_keys',
          'Supprimer les webshells et autres backdoors web',
          'Identifier et supprimer les outils offensifs déposés (Cobalt Strike, Mimikatz, etc.)',
          'Réimager les systèmes fortement compromis (plus fiable que le nettoyage)',
          'Vérifier les GPO et scripts de démarrage pour persistence',
          'Vérifier les abonnements WMI malveillants',
          'Vérifier les drivers et services kernel (rootkits)',
          'Scanner tous les systèmes avec IOCs connus (hashes, noms de fichiers)',
        ],
      },
      {
        type: 'text',
        label: 'Réimage vs. nettoyage',
        items: [
          'RÉIMAGE recommandé si : rootkit détecté, SYSTEM compromis, hyperviseur touché',
          'RÉIMAGE recommandé si : doute sur l\'exhaustivité du nettoyage',
          'NETTOYAGE acceptable si : malware classique sans kernel-level, artefacts connus et limités',
          'Toujours réimager les DCs compromis (trop risqué de nettoyer)',
          'Golden image : partir d\'une image saine validée, pas d\'un backup potentiellement compromis',
        ],
      },
    ],
  },
  {
    number: '06',
    icon: '🔄',
    title: 'Remédiation & Durcissement',
    desc: 'Corriger les faiblesses exploitées et renforcer l\'environnement pour prévenir une récidive.',
    bgColor: 'color-mix(in srgb, #06b6d4 6%, transparent)',
    borderColor: 'color-mix(in srgb, #06b6d4 30%, transparent)',
    badgeBg: 'color-mix(in srgb, #06b6d4 15%, transparent)',
    badgeColor: '#06b6d4',
    sections: [
      {
        type: 'checklist',
        label: 'Remédiation immédiate',
        items: [
          'Patcher la vulnérabilité exploitée (CVE + version patching)',
          'Réinitialiser les credentials de tous les comptes exposés',
          'Rotation KRBTGT x2 à 24h d\'intervalle (si AD compromis)',
          'Révoquer et renouveler tous les certificats potentiellement compromis',
          'Mettre à jour les règles de détection EDR/SIEM avec les IOCs de l\'incident',
          'Ajouter les domaines/IPs C2 en blocage permanent (proxy, DNS, firewall)',
          'Activer MFA sur tous les comptes qui ne l\'avaient pas',
        ],
      },
      {
        type: 'checklist',
        label: 'Durcissement post-incident',
        items: [
          'Implémenter Credential Guard sur tous les endpoints Windows 10/11',
          'Activer Protected Users Security Group pour les comptes admin',
          'Déployer Sysmon sur tous les endpoints (config SwiftOnSecurity ou Olaf Hartong)',
          'Activer PowerShell Constrained Language Mode',
          'Implémenter LAPS pour les mots de passe admin locaux',
          'Segmenter les réseaux (workstations ne peuvent pas contacter d\'autres workstations en SMB)',
          'Activer AppLocker / WDAC pour restreindre les exécutables',
          'Mettre en place un Tiered Administration Model (Tier 0/1/2)',
          'Réviser et réduire les membres des groupes à privilèges (Domain Admins, Enterprise Admins)',
          'Activer les logs PowerShell (ScriptBlock, Module, Transcription) via GPO',
        ],
      },
    ],
  },
  {
    number: '07',
    icon: '📝',
    title: 'Rapport & Retour d\'Expérience',
    desc: 'Documenter l\'incident, communiquer avec les parties prenantes, améliorer les processus.',
    bgColor: 'color-mix(in srgb, #94a3b8 6%, transparent)',
    borderColor: 'color-mix(in srgb, #94a3b8 30%, transparent)',
    badgeBg: 'color-mix(in srgb, #94a3b8 15%, transparent)',
    badgeColor: '#94a3b8',
    sections: [
      {
        type: 'text',
        label: 'Structure du rapport d\'incident',
        items: [
          '1. RÉSUMÉ EXÉCUTIF : 1 page max — impact, actions prises, état actuel',
          '2. CHRONOLOGIE : timeline détaillée de T0 à résolution',
          '3. VECTEUR INITIAL : comment l\'attaquant est entré',
          '4. ACTIONS MALVEILLANTES : TTPs MITRE utilisés, outils déployés',
          '5. SYSTÈMES IMPACTÉS : liste complète avec niveau de compromission',
          '6. DONNÉES EXPOSÉES : nature et volume des données accédées/exfiltrées',
          '7. INDICATEURS DE COMPROMISSION (IOCs) : hashes, IPs, domaines, paths',
          '8. ACTIONS DE REMÉDIATION : ce qui a été fait',
          '9. RECOMMANDATIONS : lacunes identifiées, améliorations à apporter',
          '10. LEÇONS APPRISES : ce qui a fonctionné, ce qui a manqué',
        ],
      },
      {
        type: 'checklist',
        label: 'Post-mortem / Lessons Learned',
        items: [
          'Organiser un debrief avec tous les intervenants (sécurité, IT, direction, juridique)',
          'Identifier les lacunes de détection (pourquoi n\'a-t-on pas détecté plus tôt ?)',
          'Identifier les lacunes de réponse (qu\'est-ce qui a ralenti la réponse ?)',
          'Mettre à jour les playbooks d\'incident response',
          'Créer de nouvelles règles de détection basées sur les TTPs observés',
          'Vérifier si les IOCs sont présents sur d\'autres systèmes (threat hunting)',
          'Notifier les autorités compétentes si requis (CNIL, ANSSI, assureur cyber)',
          'Communiquer aux utilisateurs impactés si données personnelles exposées (RGPD 72h)',
        ],
      },
      {
        type: 'text',
        label: 'Métriques d\'incident',
        items: [
          'MTTD (Mean Time To Detect) : T0 - heure de compromission',
          'MTTR (Mean Time To Respond) : heure détection - début confinement',
          'MTTE (Mean Time To Eradicate) : début confinement - éradication complète',
          'Dwell time : temps total de présence de l\'attaquant',
          'Blast radius : nombre de systèmes compromis',
          'Business impact : coût estimé (downtime, data breach, rançon)',
        ],
      },
    ],
  },
];

const SEVERITY_MATRIX = [
  { level: 'P1 — Critique', color: '#ef4444', trigger: 'Ransomware actif, DC compromis, exfiltration confirmée, infrastructure critique', response: '< 15 min', escalade: 'RSSI + Direction + Juridique + Assureur cyber' },
  { level: 'P2 — Haute',    color: '#f97316', trigger: 'Mouvement latéral détecté, credentials admin compromis, C2 actif', response: '< 1h', escalade: 'RSSI + Équipe IR' },
  { level: 'P3 — Moyenne',  color: '#eab308', trigger: 'Endpoint compromis (malware isolé), phishing réussi sans propagation', response: '< 4h', escalade: 'Équipe sécurité' },
  { level: 'P4 — Basse',    color: '#84cc16', trigger: 'Tentative bloquée, scan externe, phishing bloqué', response: '< 24h', escalade: 'SOC analyst' },
];

export default function DFIRMethodologyDoc({ search }) {
  const T = useTheme();

  const filtered = PHASES.filter(p => {
    if (!search) return true;
    const q = search.toLowerCase();
    return p.title.toLowerCase().includes(q) ||
      p.desc.toLowerCase().includes(q) ||
      p.sections.some(s => (s.items || []).some(i => i.toLowerCase().includes(q)));
  });

  return (
    <div style={{ padding: '24px 28px', maxWidth: 960 }}>
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontFamily: 'monospace', fontSize: 16, fontWeight: 700, color: T.text, marginBottom: 3 }}>Méthodologie DFIR</h1>
        <p style={{ fontFamily: 'monospace', fontSize: 11, color: T.muted }}>
          Cycle complet de réponse à incident — 7 phases · checklists interactives · matrice de sévérité
        </p>
      </div>

      {/* Severity Matrix */}
      {!search && (
        <div style={{ marginBottom: 22 }}>
          <div style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: T.dim, marginBottom: 10 }}>Matrice de Sévérité & Escalade</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {SEVERITY_MATRIX.map((row, i) => (
              <div key={i} style={{ display: 'grid', gridTemplateColumns: '160px 1fr 80px 200px', gap: 8, padding: '8px 12px', borderRadius: 6,
                background: T.panel, border: '1px solid var(--fl-border)' }}>
                <span style={{ fontFamily: 'monospace', fontSize: 10, fontWeight: 700, color: row.color }}>{row.level}</span>
                <span style={{ fontFamily: 'monospace', fontSize: 10, color: T.text }}>{row.trigger}</span>
                <span style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-ok)', textAlign: 'center' }}>{row.response}</span>
                <span style={{ fontFamily: 'monospace', fontSize: 9, color: T.muted }}>{row.escalade}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* IR Cycle visual */}
      {!search && (
        <div style={{ marginBottom: 20, overflowX: 'auto' }}>
          <div style={{ display: 'flex', alignItems: 'center', minWidth: 'max-content' }}>
            {PHASES.map((phase, i) => (
              <div key={phase.number} style={{ display: 'flex', alignItems: 'center' }}>
                <div style={{
                  padding: '4px 10px', fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
                  background: phase.badgeBg, color: phase.badgeColor,
                  border: `1px solid ${phase.borderColor}`,
                  borderRadius: i === 0 ? '4px 0 0 4px' : i === PHASES.length - 1 ? '0 4px 4px 0' : 0,
                  borderLeft: i > 0 ? 'none' : undefined,
                  whiteSpace: 'nowrap',
                }}>{phase.icon} {phase.title.split(' ').slice(0, 2).join(' ')}</div>
                {i < PHASES.length - 1 && (
                  <div style={{ width: 0, height: 0, flexShrink: 0,
                    borderTop: '12px solid transparent', borderBottom: '12px solid transparent',
                    borderLeft: `6px solid ${phase.borderColor}`,
                  }} />
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Phase cards */}
      {filtered.map(phase => <PhaseCard key={phase.number} phase={phase} />)}

      {filtered.length === 0 && (
        <div style={{ textAlign: 'center', padding: '60px 0', color: T.muted }}>
          <p style={{ fontFamily: 'monospace', fontSize: 13 }}>Aucune phase ne correspond à "{search}"</p>
        </div>
      )}
    </div>
  );
}
