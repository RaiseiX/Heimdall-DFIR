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

export function entreeProcessus(p, { source, quand } = {}) {
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

  return lignes([
    `## ${p.name || 'processus'} (pid ${p.pid})`,
    provenance(source, quand),
    '',
    p.user_name ? `- Utilisateur : ${p.user_name}` : null,
    p.exe ? `- Binaire : \`${p.exe}\`` : null,
    p.sha1 ? `- SHA-1 : \`${p.sha1}\`` : null,
    cmd ? `- Commande : \`${cmd}\`` : null,
    signaux.length ? `- Signaux : ${signaux.join(' · ')}` : null,
  ]);
}

export function entreeEvenement(e, { source, quand } = {}) {
  if (!e) return '';

  const t = horodatage(e.timestamp);

  return lignes([
    `## ${t || 'sans horodatage'} — ${e.artifact_type || 'événement'}`,
    provenance(source, quand),
    '',
    e.description ? `- ${e.description}` : null,
    e.host_name ? `- Hôte : ${e.host_name}` : null,
    e.user_name ? `- Utilisateur : ${e.user_name}` : null,
    e.event_id ? `- Event ID : ${e.event_id}` : null,
    e.sha1 ? `- SHA-1 : \`${e.sha1}\`` : null,
  ]);
}
