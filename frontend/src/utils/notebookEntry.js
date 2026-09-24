import { lienSource, fenetre, horodatageUtc } from './notebookSource';

const MAX_CMD = 200;

function horodatage(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d.toISOString().replace('T', ' ').slice(0, 19);
}

function lignes(parts) {
  return parts.filter(Boolean).join('\n');
}

function provenance(source, quand) {
  const morceaux = [source, horodatage(quand || new Date().toISOString())].filter(Boolean);
  return morceaux.length ? `*${morceaux.join(' · ')}*` : null;
}

export function entreeProcessus(p, { source, quand, caseId, evidenceId } = {}) {
  if (!p) return '';

  const signaux = [];
  if (p.exe_deleted) signaux.push('binaire supprimé du disque');
  if (Number(p.net_listen_exposed) > 0) {
    signaux.push(`${p.net_listen_exposed} en écoute au-delà de la loopback`);
  }
  if (Number(p.net_estab_external) > 0) {
    signaux.push(`${p.net_estab_external} établie(s) vers l'extérieur`);
  }

  const cmd = String(p.command_line || '').slice(0, MAX_CMD);

  const lien = lienSource({
    caseId, evidenceId, vue: 'processes',
    libelle: [`processus ${p.name || ''} (pid ${p.pid})`, p.host_name].filter(Boolean).join(' · '),
  });

  return lignes([
    `## ${p.name || 'processus'} (pid ${p.pid})`,
    provenance(source, quand),
    lien,
    '',
    p.user_name ? `- Utilisateur : ${p.user_name}` : null,
    p.exe ? `- Binaire : \`${p.exe}\`` : null,
    p.sha1 ? `- SHA-1 : \`${p.sha1}\`` : null,
    cmd ? `- Commande : \`${cmd}\`` : null,
    signaux.length ? `- Signaux : ${signaux.join(' · ')}` : null,
  ]);
}

export function entreeEvenement(e, { source, quand, caseId } = {}) {
  if (!e) return '';

  const t = horodatage(e.timestamp);
  const lien = lienSource({
    caseId,
    evidenceId: e.evidence_id,
    vue: 'timeline',
    filtres: {
      ...fenetre(e.timestamp),
      ...(e.artifact_type ? { artifactTypes: e.artifact_type } : {}),
      ...(e.host_name ? { hostFilter: e.host_name } : {}),
    },
    libelle: [e.artifact_type || 'événement', horodatageUtc(e.timestamp) || 'sans horodatage', e.host_name].filter(Boolean).join(' · '),
  });

  return lignes([
    `## ${t || 'sans horodatage'} — ${e.artifact_type || 'événement'}`,
    provenance(source, quand),
    lien,
    '',
    e.description ? `- ${e.description}` : null,
    e.host_name ? `- Hôte : ${e.host_name}` : null,
    e.user_name ? `- Utilisateur : ${e.user_name}` : null,
    e.event_id ? `- Event ID : ${e.event_id}` : null,
    e.sha1 ? `- SHA-1 : \`${e.sha1}\`` : null,
  ]);
}

function dossierParent(chemin) {
  const i = String(chemin || '').lastIndexOf('/');
  return i > 0 ? chemin.slice(0, i) : '';
}

export function entreeFichier(f, { source, quand, caseId, evidenceId } = {}) {
  if (!f || !f.chemin) return '';

  const lien = lienSource({
    caseId, evidenceId, vue: 'files',
    filtres: { path: dossierParent(f.chemin), file: f.chemin },
    libelle: `fichier ${f.chemin}`,
  });

  return lignes([
    `## Fichier ${f.chemin.split('/').pop()}`,
    provenance(source, quand),
    lien,
    '',
    `- Chemin dans la collecte : \`${f.chemin}\``,
    f.taille != null ? `- Taille : ${f.taille} octets` : null,
    f.modifie ? `- Modifié (système de fichiers de la collecte) : ${horodatage(f.modifie)}` : null,
  ]);
}

export function entreeArete(a, { source, quand, caseId, evidenceId } = {}) {
  if (!a) return '';

  const lien = lienSource({
    caseId, evidenceId, vue: 'timeline',
    filtres: { ...a.filtres, ...fenetre(a.premier, a.dernier) },
    libelle: [`authentifications ${a.utilisateur} → ${a.machine}`, horodatageUtc(a.premier), horodatageUtc(a.dernier)].filter(Boolean).join(' · '),
  });

  return lignes([
    `## ${a.utilisateur} → ${a.machine}`,
    provenance(source, quand),
    lien,
    '',
    `- Échecs : ${a.echec ?? 0} · Succès : ${a.succes ?? 0} · Explicites : ${a.explicite ?? 0}`,
    a.premier ? `- Premier : ${horodatage(a.premier)}` : null,
    a.dernier ? `- Dernier : ${horodatage(a.dernier)}` : null,
    a.sources ? `- Sources : ${a.sources}` : null,
  ]);
}
