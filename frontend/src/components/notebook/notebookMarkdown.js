import { LIEN_MARKDOWN_RE, analyserSource, cheminSource } from '../../utils/notebookSource';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
const JETON = '\u0001';

const STYLE_SOURCE = 'display:inline-flex;align-items:center;gap:4px;padding:1px 7px;border-radius:10px;'
  + 'background:color-mix(in srgb, var(--fl-accent) 10%, transparent);border:1px solid color-mix(in srgb, var(--fl-accent) 30%, transparent);'
  + 'color:var(--fl-accent);text-decoration:none;font-family:' + MONO + ';font-size:10.5px';

function lienSourceHtml(libelle, cheminEchappe) {
  const analyse = analyserSource(cheminEchappe.replace(/&amp;/g, '&'));
  if (!analyse) return null;
  const href = cheminSource(analyse).replace(/&/g, '&amp;');
  return `<a href="${href}" data-source="1" style="${STYLE_SOURCE}">${libelle}</a>`;
}

export function mdToHtml(md) {
  const liens = [];
  const echappe = String(md || '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(LIEN_MARKDOWN_RE, (brut, libelle, chemin) => {
      const html = lienSourceHtml(libelle, chemin);
      if (!html) return brut;
      liens.push(html);
      return `${JETON}${liens.length - 1}${JETON}`;
    });
  return echappe
    .replace(/^### (.+)$/gm, '<h3 style="margin:.8em 0 .3em;font-size:13px;color:var(--fl-text)">$1</h3>')
    .replace(/^## (.+)$/gm,  '<h2 style="margin:.9em 0 .3em;font-size:14px;color:var(--fl-text)">$1</h2>')
    .replace(/^# (.+)$/gm,   '<h1 style="margin:1em 0 .4em;font-size:16px;color:var(--fl-text)">$1</h1>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g,     '<em>$1</em>')
    .replace(/`([^`]+)`/g, '<code style="background:var(--fl-card);padding:1px 5px;border-radius:3px;font-family:'+MONO+';font-size:10.5px">$1</code>')
    .replace(/\b(T\d{4}(?:\.\d{3})?)\b/g, '<a href="https://attack.mitre.org/techniques/$1" target="_blank" rel="noreferrer" style="color:var(--fl-accent);text-decoration:none;font-family:'+MONO+';font-size:10.5px">$1</a>')
    .replace(/^[-*] (.+)$/gm, '<li style="margin:.15em 0">$1</li>')
    .replace(/(<li[\s\S]*?<\/li>\n?)+/g, m => '<ul style="margin:.4em 0 .4em 1.2em;padding:0">'+m+'</ul>')
    .replace(/\n{2,}/g, '</p><p style="margin:.5em 0">')
    .replace(/^(.+)$/gm, s => s.startsWith('<') ? s : s)
    .replace(new RegExp(`${JETON}(\\d+)${JETON}`, 'g'), (_, i) => liens[Number(i)]);
}

