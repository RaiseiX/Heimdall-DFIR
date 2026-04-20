import { useMemo, useState, useEffect } from 'react';
import { Pin, Trash2, ExternalLink, Search, Download, Copy, CheckCircle2, Circle, FileCheck2, LayoutList, LayoutGrid, FileText, Shield, LogIn, ShieldCheck } from 'lucide-react';
import { PersistenceSweep, LogonSessions } from './WorkbenchAnalyzers';
import WorkbenchAuditLedger from './WorkbenchAuditLedger';
import { useNavigate } from 'react-router-dom';
import { useEvidenceBridge, PIN_MAX_PER_CASE } from '../../state/evidenceBridge';
import { artifactColor } from '../../constants/artifactColors';
import { fmtTs as fmtTsUtil } from '../../utils/formatters';
import { casesAPI } from '../../utils/api';
import { useSocket, useSocketEvent } from '../../hooks/useSocket';

function escHtml(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function fmtUtc(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    const p = (n, l = 2) => String(n).padStart(l, '0');
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} UTC`;
  } catch { return String(ts); }
}

const STATUS_OPTS = [
  { id: 'triage',    label: 'Triage',    color: 'var(--fl-dim)' },
  { id: 'confirmed', label: 'Confirmé',  color: 'var(--fl-ok, #22c55e)' },
  { id: 'reported',  label: 'Rapporté',  color: 'var(--fl-purple, #c96898)' },
];

export default function WorkbenchEvidenceTab({ caseId }) {
  const navigate = useNavigate();
  const pins = useEvidenceBridge(s => s.pinned[String(caseId)] || []);
  const unpin = useEvidenceBridge(s => s.unpin);
  const updatePin = useEvidenceBridge(s => s.updatePin);
  const clear = useEvidenceBridge(s => s.clear);
  const hydrateFromServer = useEvidenceBridge(s => s.hydrateFromServer);
  const applyServerPin = useEvidenceBridge(s => s.applyServerPin);
  const applyServerUpdate = useEvidenceBridge(s => s.applyServerUpdate);
  const applyServerRemove = useEvidenceBridge(s => s.applyServerRemove);
  const applyServerClear = useEvidenceBridge(s => s.applyServerClear);

  useEffect(() => {
    if (caseId) hydrateFromServer(caseId);
  }, [caseId, hydrateFromServer]);

  const { socket } = useSocket();
  useSocketEvent(socket, 'workbench:pin:added',   (pin) => { if (pin) applyServerPin(caseId, pin); });
  useSocketEvent(socket, 'workbench:pin:updated', (pin) => { if (pin) applyServerUpdate(caseId, pin); });
  useSocketEvent(socket, 'workbench:pin:removed', (msg) => { if (msg?.pin_id) applyServerRemove(caseId, msg.pin_id); });
  useSocketEvent(socket, 'workbench:pin:cleared', (msg) => { if (!msg?.case_id || String(msg.case_id) === String(caseId)) applyServerClear(caseId); });

  const [q, setQ] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sortBy, setSortBy] = useState('pinned_at');
  const [viewMode, setViewMode] = useState(() => {
    try { return localStorage.getItem(`heimdall.wb.view.${caseId}`) || 'list'; } catch (_e) { return 'list'; }
  });
  const setView = (v) => {
    setViewMode(v);
    try { localStorage.setItem(`heimdall.wb.view.${caseId}`, v); } catch (_e) {}
  };

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    let list = pins;
    if (statusFilter !== 'all') list = list.filter(p => (p.status || 'triage') === statusFilter);
    if (needle) {
      list = list.filter(p =>
        (p.description || '').toLowerCase().includes(needle) ||
        (p.source || '').toLowerCase().includes(needle) ||
        (p.artifact_type || '').toLowerCase().includes(needle) ||
        (p.tool || '').toLowerCase().includes(needle) ||
        (p.host_name || '').toLowerCase().includes(needle) ||
        (p.user_name || '').toLowerCase().includes(needle) ||
        (p.note || '').toLowerCase().includes(needle)
      );
    }
    const sorted = [...list];
    if (sortBy === 'pinned_at')      sorted.sort((a, b) => String(b.pinned_at).localeCompare(String(a.pinned_at)));
    else if (sortBy === 'timestamp') sorted.sort((a, b) => String(a.timestamp || '').localeCompare(String(b.timestamp || '')));
    else if (sortBy === 'artifact')  sorted.sort((a, b) => String(a.artifact_type || '').localeCompare(String(b.artifact_type || '')));
    return sorted;
  }, [pins, q, statusFilter, sortBy]);

  const counts = useMemo(() => {
    const c = { triage: 0, confirmed: 0, reported: 0 };
    for (const p of pins) c[p.status || 'triage'] = (c[p.status || 'triage'] || 0) + 1;
    return c;
  }, [pins]);

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify({ case_id: String(caseId), exported_at: new Date().toISOString(), pins }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `workbench-evidence-${caseId}-${Date.now()}.json`;
    a.click(); URL.revokeObjectURL(url);
  };

  const generateReport = async () => {
    let caseMeta = null;
    try {
      const res = await casesAPI.get(caseId);
      caseMeta = res?.data || res;
    } catch (_e) { caseMeta = null; }

    const byStatus = { triage: [], confirmed: [], reported: [] };
    for (const p of filtered) {
      const s = p.status || 'triage';
      (byStatus[s] || byStatus.triage).push(p);
    }

    const statusBlock = (label, items, accent) => {
      if (items.length === 0) return '';
      const rows = items.map((p, idx) => `
        <section class="finding">
          <header>
            <span class="idx">#${idx + 1}</span>
            <span class="chip" style="background:${accent}20;color:${accent};border-color:${accent}60">${escHtml(p.artifact_type || '—')}</span>
            ${p.tool ? `<span class="tool">${escHtml(p.tool)}</span>` : ''}
            ${p.event_id != null ? `<span class="eid">EID ${escHtml(p.event_id)}</span>` : ''}
            ${p.mitre_technique_id ? `<span class="mitre">${escHtml(p.mitre_technique_id)}</span>` : ''}
          </header>
          <div class="ts"><strong>Timestamp événement:</strong> ${escHtml(fmtUtc(p.timestamp))}</div>
          <div class="desc">${escHtml(p.description || '(aucune description)')}</div>
          ${p.source ? `<div class="src"><strong>Source:</strong> <code>${escHtml(p.source)}</code></div>` : ''}
          ${(p.host_name || p.user_name) ? `<div class="ctx">${p.host_name ? `<span>⚙ Host: <code>${escHtml(p.host_name)}</code></span>` : ''}${p.user_name ? `<span>👤 Utilisateur: <code>${escHtml(p.user_name)}</code></span>` : ''}</div>` : ''}
          ${p.note ? `<div class="note"><strong>Note analyste:</strong> ${escHtml(p.note)}</div>` : ''}
          <table class="coc">
            <tr><th>pin_id</th><td><code>${escHtml(p.pin_id)}</code></td></tr>
            <tr><th>Épinglé le</th><td>${escHtml(fmtUtc(p.pinned_at))}</td></tr>
            <tr><th>Épinglé par</th><td>${escHtml(p.pinned_by || 'analyste')}</td></tr>
            <tr><th>collection_timeline_id</th><td>${escHtml(p.collection_timeline_id ?? '—')}</td></tr>
            <tr><th>dedupe_hash</th><td><code>${escHtml(p.dedupe_hash || '—')}</code></td></tr>
          </table>
        </section>`).join('');
      return `
        <section class="col">
          <h2 style="border-bottom:3px solid ${accent};color:${accent}">${label} · ${items.length}</h2>
          ${rows}
        </section>`;
    };

    const title = caseMeta?.case_number ? `${caseMeta.case_number} — ${caseMeta.title || ''}` : `Case ${caseId}`;
    const html = `<!doctype html>
<html><head><meta charset="utf-8"><title>Heimdall Findings — ${escHtml(title)}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif; padding: 32px 44px; color: #1a1a1a; max-width: 1100px; margin: 0 auto; }
  h1 { color: #3a2a5a; margin: 0 0 4px; font-size: 24px; }
  h2 { padding: 4px 0; margin: 28px 0 12px; font-size: 17px; letter-spacing: 0.02em; }
  h3 { color: #555; font-weight: 600; font-size: 13px; text-transform: uppercase; margin: 18px 0 8px; }
  .cover { border: 1px solid #ddd; border-radius: 6px; padding: 16px 20px; background: #fafafa; margin-bottom: 24px; }
  .cover p { margin: 4px 0; }
  .summary { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 12px 0 20px; }
  .stat { border: 1px solid #ddd; border-left-width: 4px; padding: 8px 12px; border-radius: 4px; background: #fff; }
  .stat b { font-size: 22px; display: block; }
  .stat s { display: block; font-size: 10px; color: #666; text-decoration: none; text-transform: uppercase; letter-spacing: 0.08em; }
  .finding { border: 1px solid #e2e2e2; border-radius: 5px; padding: 10px 14px; margin-bottom: 10px; page-break-inside: avoid; }
  .finding header { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 6px; }
  .finding .idx { font-weight: 700; color: #888; font-size: 12px; }
  .finding .chip { font-size: 10px; padding: 2px 8px; border-radius: 3px; border: 1px solid; text-transform: uppercase; letter-spacing: 0.04em; font-weight: 700; }
  .finding .tool { font-size: 11px; color: #666; font-family: monospace; }
  .finding .eid { font-size: 10px; padding: 2px 7px; background: #1c6ef215; color: #1c6ef2; border-radius: 3px; }
  .finding .mitre { font-size: 10px; padding: 2px 7px; background: #c9689815; color: #88296a; border-radius: 3px; }
  .finding .ts { font-size: 12px; font-family: monospace; margin: 4px 0; }
  .finding .desc { font-size: 12px; margin: 6px 0; line-height: 1.4; word-break: break-word; }
  .finding .src { font-size: 11px; margin: 4px 0; color: #444; word-break: break-all; }
  .finding .ctx { display: flex; gap: 14px; font-size: 11px; color: #444; margin: 4px 0; }
  .finding .note { font-size: 12px; padding: 6px 10px; background: #fff8e1; border-left: 3px solid #f59e0b; margin: 6px 0; border-radius: 3px; }
  .coc { font-size: 10px; border-collapse: collapse; width: 100%; margin-top: 8px; background: #fafafa; }
  .coc th { text-align: left; padding: 3px 8px; color: #666; font-weight: 600; width: 180px; border: 1px solid #eee; }
  .coc td { padding: 3px 8px; font-family: monospace; border: 1px solid #eee; word-break: break-all; }
  footer { margin-top: 40px; padding-top: 14px; border-top: 1px solid #ccc; color: #888; font-size: 11px; text-align: center; }
  @media print { body { padding: 0; } .finding { break-inside: avoid; } }
</style></head><body>
<h1>HEIMDALL DFIR — Rapport de preuves épinglées (Workbench)</h1>
<div class="cover">
  <p><strong>${escHtml(title)}</strong></p>
  ${caseMeta ? `
    <p>Statut: <strong>${escHtml(caseMeta.status || '—')}</strong> · Priorité: <strong>${escHtml(caseMeta.priority || '—')}</strong> · Investigateur: <strong>${escHtml(caseMeta.investigator_name || '—')}</strong></p>
    ${caseMeta.description ? `<p>${escHtml(caseMeta.description)}</p>` : ''}
  ` : ''}
  <p style="color:#666;font-size:11px">Rapport généré: ${escHtml(fmtUtc(new Date().toISOString()))}</p>
</div>

<div class="summary">
  <div class="stat" style="border-left-color:#999"><s>Triage</s><b>${byStatus.triage.length}</b></div>
  <div class="stat" style="border-left-color:#22c55e"><s>Confirmé</s><b>${byStatus.confirmed.length}</b></div>
  <div class="stat" style="border-left-color:#c96898"><s>Rapporté</s><b>${byStatus.reported.length}</b></div>
</div>

${statusBlock('Rapporté', byStatus.reported, '#c96898')}
${statusBlock('Confirmé', byStatus.confirmed, '#22c55e')}
${statusBlock('Triage', byStatus.triage, '#888')}

${filtered.length === 0 ? '<p style="color:#888;font-style:italic">Aucune preuve épinglée à rapporter.</p>' : ''}

<footer>
  Généré par Heimdall DFIR — Workbench Evidence Bridge · Chain of custody: chaque preuve liste pin_id, pinned_at UTC, pinned_by, collection_timeline_id, dedupe_hash.
</footer>
</body></html>`;

    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const w = window.open(url, '_blank');
    setTimeout(() => { try { URL.revokeObjectURL(url); } catch (_e) {} }, 60_000);
    if (w) setTimeout(() => { try { w.focus(); w.print(); } catch (_e) {} }, 600);
  };

  const copyMarkdown = async () => {
    const lines = ['# Workbench Evidence', ''];
    for (const p of filtered) {
      lines.push(`## ${p.artifact_type || '—'} — ${p.tool || ''}`);
      lines.push(`- **Timestamp**: ${p.timestamp || '—'}`);
      if (p.event_id) lines.push(`- **EventID**: ${p.event_id}`);
      if (p.host_name) lines.push(`- **Host**: ${p.host_name}`);
      if (p.user_name) lines.push(`- **User**: ${p.user_name}`);
      if (p.mitre_technique_id) lines.push(`- **MITRE**: ${p.mitre_technique_id}`);
      lines.push(`- **Source**: \`${p.source || ''}\``);
      lines.push(`- **Description**: ${p.description || ''}`);
      if (p.note) lines.push(`- **Note analyste**: ${p.note}`);
      lines.push(`- **Status**: ${p.status || 'triage'}`);
      lines.push('');
    }
    try { await navigator.clipboard.writeText(lines.join('\n')); } catch (_e) {}
  };

  if (pins.length === 0 && viewMode !== 'ledger') {
    return (
      <div style={{
        padding: '48px 24px', textAlign: 'center', color: 'var(--fl-dim)',
        border: '1px dashed var(--fl-sep)', borderRadius: 10, background: 'var(--fl-bg)',
        fontFamily: 'monospace',
      }}>
        <Pin size={28} style={{ opacity: 0.5, marginBottom: 12 }} />
        <div style={{ fontSize: 13, color: 'var(--fl-on-dark)', marginBottom: 6 }}>Aucune preuve épinglée pour ce cas</div>
        <div style={{ fontSize: 11 }}>
          Dans la <b>Super Timeline</b>, clic droit sur une cellule → <span style={{ color: 'var(--fl-purple, #c96898)' }}>📌 Épingler dans le Workbench</span>
          <br />ou appuyer sur la touche <kbd style={{ padding: '1px 6px', border: '1px solid var(--fl-sep)', borderRadius: 3, background: 'var(--fl-card)' }}>P</kbd> sur une ligne sélectionnée.
        </div>
      </div>
    );
  }

  return (
    <div style={{ fontFamily: 'monospace' }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10, padding: '8px 12px',
        background: 'var(--fl-bg)', border: '1px solid var(--fl-card)', borderRadius: 8,
      }}>
        <Pin size={14} style={{ color: 'var(--fl-purple, #c96898)' }} />
        <span style={{ fontSize: 12, color: 'var(--fl-on-dark)', fontWeight: 600 }}>
          {pins.length} / {PIN_MAX_PER_CASE}
        </span>
        <span style={{ fontSize: 10, color: 'var(--fl-dim)' }}>épinglée(s)</span>

        <div style={{ display: 'flex', gap: 6, marginLeft: 10 }}>
          {['all', ...STATUS_OPTS.map(s => s.id)].map(s => {
            const isAll = s === 'all';
            const opt = STATUS_OPTS.find(o => o.id === s);
            const n = isAll ? pins.length : (counts[s] || 0);
            const active = statusFilter === s;
            return (
              <button key={s} onClick={() => setStatusFilter(s)} style={{
                padding: '3px 10px', fontSize: 10, fontFamily: 'monospace',
                border: `1px solid ${active ? (opt?.color || 'var(--fl-accent)') : 'var(--fl-sep)'}`,
                background: active ? `${opt?.color || 'var(--fl-accent)'}20` : 'var(--fl-card)',
                color: active ? (opt?.color || 'var(--fl-accent)') : 'var(--fl-dim)',
                borderRadius: 4, cursor: 'pointer',
              }}>
                {isAll ? 'Tous' : opt.label} · {n}
              </button>
            );
          })}
        </div>

        <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 6, border: '1px solid var(--fl-sep)', borderRadius: 5, padding: '3px 8px', background: 'var(--fl-card)' }}>
          <Search size={12} style={{ color: 'var(--fl-dim)' }} />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Rechercher…"
            style={{ flex: 1, background: 'none', border: 'none', outline: 'none', color: 'var(--fl-on-dark)', fontFamily: 'monospace', fontSize: 11 }} />
        </div>

        <div style={{ display: 'flex', gap: 0, border: '1px solid var(--fl-sep)', borderRadius: 4, overflow: 'hidden' }}>
          {[
            { id: 'list',        label: 'Liste',       icon: LayoutList, color: 'var(--fl-accent)' },
            { id: 'board',       label: 'Board',       icon: LayoutGrid, color: 'var(--fl-purple, #c96898)' },
            { id: 'persistence', label: 'Persistance', icon: Shield,     color: 'var(--fl-warn)' },
            { id: 'logons',      label: 'Sessions',    icon: LogIn,      color: 'var(--fl-gold)' },
            { id: 'ledger',      label: 'Ledger',      icon: ShieldCheck,color: 'var(--fl-ok, #22c55e)' },
          ].map((m, i) => {
            const Icon = m.icon;
            const active = viewMode === m.id;
            return (
              <button key={m.id} onClick={() => setView(m.id)} title={m.label}
                style={{
                  padding: '3px 8px', fontSize: 10, fontFamily: 'monospace', cursor: 'pointer',
                  background: active ? m.color : 'var(--fl-card)',
                  color: active ? 'var(--fl-bg)' : 'var(--fl-dim)',
                  border: 'none', borderLeft: i === 0 ? 'none' : '1px solid var(--fl-sep)',
                  display: 'flex', alignItems: 'center', gap: 4,
                }}>
                <Icon size={11} /> {m.label}
              </button>
            );
          })}
        </div>

        <select value={sortBy} onChange={e => setSortBy(e.target.value)} style={{
          fontSize: 10, fontFamily: 'monospace', padding: '3px 8px',
          background: 'var(--fl-card)', border: '1px solid var(--fl-sep)', color: 'var(--fl-on-dark)', borderRadius: 4, cursor: 'pointer',
        }}>
          <option value="pinned_at">Trier: épinglé récemment</option>
          <option value="timestamp">Trier: timestamp événement</option>
          <option value="artifact">Trier: type artifact</option>
        </select>

        <button onClick={generateReport} title="Générer un rapport forensique (PDF via impression)"
          style={{ ...iconBtn, color: 'var(--fl-purple, #c96898)', borderColor: 'var(--fl-purple, #c96898)60' }}>
          <FileText size={12} /> <span style={{ fontSize: 10 }}>Rapport</span>
        </button>
        <button onClick={copyMarkdown} title="Copier en Markdown" style={iconBtn}>
          <Copy size={12} /> <span style={{ fontSize: 10 }}>MD</span>
        </button>
        <button onClick={exportJSON} title="Exporter JSON" style={iconBtn}>
          <Download size={12} /> <span style={{ fontSize: 10 }}>JSON</span>
        </button>
        <button onClick={() => { if (confirm(`Retirer les ${pins.length} épingles de ce cas ?`)) clear(caseId); }}
          title="Vider le Workbench" style={{ ...iconBtn, color: 'var(--fl-danger)' }}>
          <Trash2 size={12} />
        </button>
      </div>

      {viewMode === 'ledger' ? (
        <WorkbenchAuditLedger caseId={caseId} />
      ) : viewMode === 'persistence' ? (
        <PersistenceSweep pins={filtered} caseId={caseId} navigate={navigate} />
      ) : viewMode === 'logons' ? (
        <LogonSessions pins={filtered} caseId={caseId} navigate={navigate} />
      ) : viewMode === 'board' ? (
        <BoardView pins={filtered} caseId={caseId} updatePin={updatePin} unpin={unpin} navigate={navigate} />
      ) : (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {filtered.map(p => {
          const stripe = artifactColor(p.artifact_type || '');
          const statusOpt = STATUS_OPTS.find(s => s.id === (p.status || 'triage'));
          return (
            <div key={p.pin_id} style={{
              display: 'flex', gap: 0, background: 'var(--fl-bg)', border: '1px solid var(--fl-card)',
              borderLeft: `3px solid ${stripe}`, borderRadius: 6, overflow: 'hidden',
            }}>
              <div style={{ flex: 1, padding: '8px 12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
                  <span style={{
                    fontSize: 9, padding: '1px 6px', borderRadius: 3, background: `${stripe}25`,
                    color: stripe, textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600,
                  }}>{p.artifact_type || '—'}</span>
                  {p.tool && (
                    <span style={{ fontSize: 9, color: 'var(--fl-dim)' }}>{p.tool}</span>
                  )}
                  {p.event_id != null && (
                    <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 3, background: 'var(--fl-card)', color: 'var(--fl-accent)' }}>
                      EID {p.event_id}
                    </span>
                  )}
                  {p.mitre_technique_id && (
                    <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 3, background: 'var(--fl-purple-bg, #c9689820)', color: 'var(--fl-purple, #c96898)' }}>
                      {p.mitre_technique_id}
                    </span>
                  )}
                  <span style={{ fontSize: 10, color: 'var(--fl-on-dark)', fontFamily: 'monospace' }}>
                    {p.timestamp ? fmtTsUtil(p.timestamp) : '—'}
                  </span>
                  {p.host_name && <span style={{ fontSize: 10, color: 'var(--fl-dim)' }}>⚙ {p.host_name}</span>}
                  {p.user_name && <span style={{ fontSize: 10, color: 'var(--fl-dim)' }}>👤 {p.user_name}</span>}
                </div>

                <div style={{ fontSize: 11, color: 'var(--fl-on-dark)', marginBottom: 4, wordBreak: 'break-word' }}>
                  {p.description || <span style={{ color: 'var(--fl-dim)', fontStyle: 'italic' }}>(aucune description)</span>}
                </div>

                {p.source && (
                  <div style={{ fontSize: 10, color: 'var(--fl-dim)', marginBottom: 6, wordBreak: 'break-all' }}>
                    {p.source}
                  </div>
                )}

                <textarea
                  placeholder="Note analyste — pourquoi cette preuve compte…"
                  value={p.note || ''}
                  onChange={e => updatePin(caseId, p.pin_id, { note: e.target.value })}
                  rows={2}
                  style={{
                    width: '100%', resize: 'vertical', minHeight: 28,
                    background: 'var(--fl-card)', border: '1px solid var(--fl-sep)',
                    color: 'var(--fl-on-dark)', fontFamily: 'monospace', fontSize: 11,
                    padding: '5px 8px', borderRadius: 4, outline: 'none', boxSizing: 'border-box',
                  }}
                />
              </div>

              <div style={{
                display: 'flex', flexDirection: 'column', gap: 4, padding: '8px 10px',
                borderLeft: '1px solid var(--fl-card)', background: 'var(--fl-card)', minWidth: 134,
              }}>
                <select value={p.status || 'triage'} onChange={e => updatePin(caseId, p.pin_id, { status: e.target.value })}
                  style={{
                    fontSize: 10, fontFamily: 'monospace', padding: '3px 6px',
                    background: 'var(--fl-bg)', border: `1px solid ${statusOpt?.color || 'var(--fl-sep)'}`,
                    color: statusOpt?.color || 'var(--fl-on-dark)', borderRadius: 3, cursor: 'pointer',
                  }}>
                  {STATUS_OPTS.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
                </select>

                <button onClick={() => {
                    const qs = new URLSearchParams({ caseId: String(caseId) });
                    if (p.collection_timeline_id != null) qs.set('focus', String(p.collection_timeline_id));
                    navigate(`/super-timeline?${qs.toString()}`);
                  }}
                  title="Ouvrir dans la Super Timeline"
                  style={rowBtn}>
                  <ExternalLink size={10} /> Timeline
                </button>

                <button onClick={() => unpin(caseId, p.pin_id)} title="Retirer du Workbench"
                  style={{ ...rowBtn, color: 'var(--fl-danger)', borderColor: 'var(--fl-sep)' }}>
                  <Trash2 size={10} /> Unpin
                </button>

                <div style={{ fontSize: 9, color: 'var(--fl-dim)', marginTop: 2, textAlign: 'right' }}>
                  {p.pinned_at ? new Date(p.pinned_at).toLocaleString() : ''}
                </div>
              </div>
            </div>
          );
        })}
      </div>
      )}
    </div>
  );
}

function BoardView({ pins, caseId, updatePin, unpin, navigate }) {
  const [dragId, setDragId] = useState(null);
  const [dropTarget, setDropTarget] = useState(null);

  const columns = useMemo(() => {
    const grouped = { triage: [], confirmed: [], reported: [] };
    for (const p of pins) {
      const s = p.status || 'triage';
      (grouped[s] || grouped.triage).push(p);
    }
    return grouped;
  }, [pins]);

  const onDrop = (targetStatus) => {
    if (dragId) {
      updatePin(caseId, dragId, { status: targetStatus });
    }
    setDragId(null);
    setDropTarget(null);
  };

  return (
    <div style={{
      display: 'grid', gridTemplateColumns: `repeat(${STATUS_OPTS.length}, minmax(0, 1fr))`,
      gap: 10, alignItems: 'flex-start',
    }}>
      {STATUS_OPTS.map(col => {
        const items = columns[col.id] || [];
        const isOver = dropTarget === col.id;
        return (
          <div key={col.id}
            onDragOver={e => { e.preventDefault(); if (dropTarget !== col.id) setDropTarget(col.id); }}
            onDragLeave={() => setDropTarget(prev => prev === col.id ? null : prev)}
            onDrop={() => onDrop(col.id)}
            style={{
              background: 'var(--fl-bg)', border: `1px solid ${isOver ? col.color : 'var(--fl-card)'}`,
              borderTop: `3px solid ${col.color}`, borderRadius: 6, minHeight: 200, padding: 8,
              transition: 'border-color 0.12s',
            }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8,
              paddingBottom: 6, borderBottom: '1px solid var(--fl-sep)',
            }}>
              <span style={{
                width: 8, height: 8, borderRadius: '50%', background: col.color,
                boxShadow: `0 0 6px ${col.color}80`,
              }} />
              <span style={{ fontSize: 11, color: col.color, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                {col.label}
              </span>
              <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--fl-dim)' }}>
                {items.length}
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {items.length === 0 && (
                <div style={{ padding: '16px 8px', textAlign: 'center', fontSize: 10, color: 'var(--fl-dim)', fontStyle: 'italic' }}>
                  {isOver ? '↓ relâcher ici' : 'vide'}
                </div>
              )}
              {items.map(p => {
                const stripe = artifactColor(p.artifact_type || '');
                const isDragging = dragId === p.pin_id;
                return (
                  <div key={p.pin_id}
                    draggable
                    onDragStart={() => setDragId(p.pin_id)}
                    onDragEnd={() => { setDragId(null); setDropTarget(null); }}
                    style={{
                      background: 'var(--fl-card)', border: '1px solid var(--fl-sep)',
                      borderLeft: `3px solid ${stripe}`, borderRadius: 4, padding: '7px 9px',
                      cursor: 'grab', opacity: isDragging ? 0.4 : 1, userSelect: 'none',
                    }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 4, flexWrap: 'wrap' }}>
                      <span style={{
                        fontSize: 9, padding: '1px 5px', borderRadius: 3, background: `${stripe}25`,
                        color: stripe, textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600,
                      }}>{p.artifact_type || '—'}</span>
                      {p.event_id != null && (
                        <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, background: 'var(--fl-bg)', color: 'var(--fl-accent)' }}>
                          {p.event_id}
                        </span>
                      )}
                      {p.mitre_technique_id && (
                        <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, background: '#c9689820', color: 'var(--fl-purple, #c96898)' }}>
                          {p.mitre_technique_id}
                        </span>
                      )}
                    </div>
                    <div style={{
                      fontSize: 10, color: 'var(--fl-on-dark)', marginBottom: 4,
                      overflow: 'hidden', display: '-webkit-box', WebkitLineClamp: 3, WebkitBoxOrient: 'vertical', wordBreak: 'break-word',
                    }}>
                      {p.description || <span style={{ color: 'var(--fl-dim)', fontStyle: 'italic' }}>(aucune description)</span>}
                    </div>
                    {(p.host_name || p.user_name || p.timestamp) && (
                      <div style={{ fontSize: 9, color: 'var(--fl-dim)', marginBottom: 4, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {p.timestamp && <span>⏱ {String(p.timestamp).replace('T', ' ').slice(0, 19)}</span>}
                        {p.host_name && <span>⚙ {p.host_name}</span>}
                        {p.user_name && <span>👤 {p.user_name}</span>}
                      </div>
                    )}
                    {p.note && (
                      <div style={{
                        fontSize: 9, color: 'var(--fl-on-dark)', padding: '3px 5px',
                        background: 'var(--fl-bg)', borderRadius: 3, border: '1px solid var(--fl-sep)',
                        marginBottom: 4, overflow: 'hidden', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
                      }}>
                        📝 {p.note}
                      </div>
                    )}
                    <div style={{ display: 'flex', gap: 4, marginTop: 4 }}>
                      <button onClick={(e) => {
                          e.stopPropagation();
                          const qs = new URLSearchParams({ caseId: String(caseId) });
                          if (p.collection_timeline_id != null) qs.set('focus', String(p.collection_timeline_id));
                          navigate(`/super-timeline?${qs.toString()}`);
                        }}
                        title="Ouvrir dans la Super Timeline"
                        style={miniBtn}>
                        <ExternalLink size={9} />
                      </button>
                      <button onClick={(e) => { e.stopPropagation(); unpin(caseId, p.pin_id); }}
                        title="Retirer" style={{ ...miniBtn, color: 'var(--fl-danger)' }}>
                        <Trash2 size={9} />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}

const miniBtn = {
  display: 'flex', alignItems: 'center', justifyContent: 'center',
  padding: '3px 6px', fontSize: 9, fontFamily: 'monospace',
  background: 'var(--fl-bg)', border: '1px solid var(--fl-sep)', color: 'var(--fl-on-dark)',
  borderRadius: 3, cursor: 'pointer',
};

const iconBtn = {
  display: 'flex', alignItems: 'center', gap: 4, padding: '3px 8px', fontSize: 10,
  background: 'var(--fl-card)', border: '1px solid var(--fl-sep)', color: 'var(--fl-on-dark)',
  borderRadius: 4, cursor: 'pointer', fontFamily: 'monospace',
};

const rowBtn = {
  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4,
  padding: '3px 6px', fontSize: 10, fontFamily: 'monospace',
  background: 'var(--fl-bg)', border: '1px solid var(--fl-sep)', color: 'var(--fl-on-dark)',
  borderRadius: 3, cursor: 'pointer',
};
