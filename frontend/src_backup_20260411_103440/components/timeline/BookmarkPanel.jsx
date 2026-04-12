import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { Plus, Pencil, Trash2, Bookmark, X, RefreshCw, FileDown, FileText } from 'lucide-react';
import { bookmarksAPI } from '../../utils/api';

const MITRE_TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
];

const TACTIC_COLOR = {
  'Reconnaissance':       '#7d8590',
  'Resource Development': '#7d8590',
  'Initial Access':       '#d97c20',
  'Execution':            '#da3633',
  'Persistence':          '#c96898',
  'Privilege Escalation': '#8b72d6',
  'Defense Evasion':      '#4d82c0',
  'Credential Access':    '#da3633',
  'Discovery':            '#c89d1d',
  'Lateral Movement':     '#d97c20',
  'Collection':           '#3fb950',
  'Command and Control':  '#da3633',
  'Exfiltration':         '#f43f5e',
  'Impact':               '#da3633',
};

const PALETTE = ['#4d82c0', '#da3633', '#d97c20', '#c89d1d', '#3fb950', '#8b72d6', '#c96898', '#f43f5e'];

const EMPTY_FORM = { title: '', description: '', mitre_tactic: '', mitre_technique: '', color: '#4d82c0' };

function BookmarkForm({ initial, onSave, onCancel }) {
  const { t } = useTranslation();
  const [form, setForm] = useState(initial || EMPTY_FORM);
  const [saving, setSaving] = useState(false);

  function set(k, v) { setForm(p => ({ ...p, [k]: v })); }

  async function submit(e) {
    e.preventDefault();
    if (!form.title.trim()) return;
    setSaving(true);
    try { await onSave(form); } finally { setSaving(false); }
  }

  return (
    <form onSubmit={submit} style={{
      padding: '12px 14px', background: '#07101f', border: '1px solid #1a2035',
      borderRadius: 8, display: 'flex', flexDirection: 'column', gap: 8,
    }}>
      
      <input
        autoFocus
        placeholder={t('bookmark.title_ph')}
        value={form.title}
        onChange={e => set('title', e.target.value)}
        style={{
          background: '#050c18', border: '1px solid #1a2a3a', borderRadius: 4,
          color: '#c8d8ec', fontFamily: 'monospace', fontSize: 11,
          padding: '5px 8px', outline: 'none', width: '100%', boxSizing: 'border-box',
        }}
      />

      <select
        value={form.mitre_tactic}
        onChange={e => set('mitre_tactic', e.target.value)}
        style={{
          background: '#050c18', border: '1px solid #1a2a3a', borderRadius: 4,
          color: form.mitre_tactic ? (TACTIC_COLOR[form.mitre_tactic] || '#c8d8ec') : '#3d5070',
          fontFamily: 'monospace', fontSize: 11, padding: '5px 8px', outline: 'none',
          width: '100%', boxSizing: 'border-box',
        }}
      >
        <option value="">{t('bookmark.tactic_ph')}</option>
        {MITRE_TACTICS.map(tactic => (
          <option key={tactic} value={tactic} style={{ color: TACTIC_COLOR[tactic] || '#c8d8ec' }}>{tactic}</option>
        ))}
      </select>

      <input
        placeholder={t('bookmark.technique_ph')}
        value={form.mitre_technique}
        onChange={e => set('mitre_technique', e.target.value)}
        style={{
          background: '#050c18', border: '1px solid #1a2a3a', borderRadius: 4,
          color: '#c8d8ec', fontFamily: 'monospace', fontSize: 11,
          padding: '5px 8px', outline: 'none', width: '100%', boxSizing: 'border-box',
        }}
      />

      <textarea
        placeholder={t('bookmark.desc_ph')}
        value={form.description}
        onChange={e => set('description', e.target.value)}
        rows={2}
        style={{
          background: '#050c18', border: '1px solid #1a2a3a', borderRadius: 4,
          color: '#c8d8ec', fontFamily: 'monospace', fontSize: 11,
          padding: '5px 8px', outline: 'none', resize: 'vertical',
          width: '100%', boxSizing: 'border-box',
        }}
      />

      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <span style={{ fontSize: 10, color: '#3d5070', fontFamily: 'monospace' }}>{t('workbench.color_label')}</span>
        {PALETTE.map(c => (
          <button
            key={c} type="button"
            onClick={() => set('color', c)}
            style={{
              width: 18, height: 18, borderRadius: '50%', background: c, border: 'none', cursor: 'pointer',
              outline: form.color === c ? `2px solid ${c}` : 'none',
              outlineOffset: 2,
            }}
          />
        ))}
      </div>

      <div style={{ display: 'flex', gap: 6 }}>
        <button type="submit" disabled={saving || !form.title.trim()} style={{
          flex: 1, padding: '5px 10px', borderRadius: 4,
          background: form.title.trim() ? '#1a3a5a' : '#0a1020',
          border: `1px solid ${form.title.trim() ? '#2a5080' : '#0e1828'}`,
          color: form.title.trim() ? '#4d82c0' : '#1e2a3a',
          fontSize: 11, fontFamily: 'monospace', cursor: form.title.trim() ? 'pointer' : 'default',
        }}>
          {saving ? t('bookmark.creating') : t('common.save')}
        </button>
        <button type="button" onClick={onCancel} style={{
          padding: '5px 10px', borderRadius: 4, background: 'none',
          border: '1px solid #1a2a3a', color: '#3d5070',
          fontSize: 11, fontFamily: 'monospace', cursor: 'pointer',
        }}>
          {t('common.cancel')}
        </button>
      </div>
    </form>
  );
}

export default function BookmarkPanel({ caseId }) {
  const { t } = useTranslation();
  const [bookmarks, setBookmarks] = useState([]);
  const [loading, setLoading]     = useState(false);
  const [showForm, setShowForm]   = useState(false);
  const [editId, setEditId]       = useState(null);
  const [editInitial, setEditInitial] = useState(null);

  const load = useCallback(() => {
    if (!caseId) return;
    setLoading(true);
    bookmarksAPI.list(caseId)
      .then(res => setBookmarks((res.data || []).filter(b => b.source !== 'mitre')))
      .catch(() => setBookmarks([]))
      .finally(() => setLoading(false));
  }, [caseId]);

  useEffect(() => { load(); }, [load]);

  async function handleCreate(form) {
    await bookmarksAPI.create(caseId, form);
    setShowForm(false);
    load();
  }

  async function handleUpdate(form) {
    await bookmarksAPI.update(caseId, editId, form);
    setEditId(null);
    setEditInitial(null);
    load();
  }

  async function remove(id) {
    try {
      await bookmarksAPI.remove(caseId, id);
      load();
    } catch {}
  }

  function exportCSV() {
    const cols = [t('bookmark.col_ts'), t('bookmark.col_title'), t('bookmark.col_desc'), t('bookmark.col_tactic'), t('bookmark.col_tech'), t('bookmark.col_color'), t('bookmark.col_author'), t('bookmark.col_created')];
    const header = cols.map(c => `"${c}"`).join(',');
    const rows = bookmarks.map(b => [
      b.event_timestamp ? `"${new Date(b.event_timestamp).toLocaleString()}"` : '""',
      `"${(b.title || '').replace(/"/g, '""')}"`,
      `"${(b.description || '').replace(/"/g, '""')}"`,
      `"${(b.mitre_tactic || '').replace(/"/g, '""')}"`,
      `"${(b.mitre_technique || '').replace(/"/g, '""')}"`,
      `"${(b.color || '').replace(/"/g, '""')}"`,
      `"${(b.author_name || b.username || '').replace(/"/g, '""')}"`,
      `"${new Date(b.created_at).toLocaleString()}"`,
    ].join(','));
    const csv = '\uFEFF' + header + '\n' + rows.join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bookmarks_${caseId}_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportPDF() {
    const printWin = window.open('', '_blank');
    if (!printWin) return;
    const rows = bookmarks.map(b => {
      const tc = TACTIC_COLOR[b.mitre_tactic] || '#7d8590';
      return `
        <tr>
          <td style="color:#7abfff;white-space:nowrap">${b.event_timestamp ? new Date(b.event_timestamp).toLocaleString() : '—'}</td>
          <td style="font-weight:600">${b.title || ''}</td>
          <td>${b.description || ''}</td>
          <td style="color:${tc}">${b.mitre_tactic || ''}</td>
          <td style="color:#a0b8d0">${b.mitre_technique || ''}</td>
          <td><span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:${b.color || '#4d82c0'}"></span></td>
          <td style="color:#7d8590">${b.author_name || b.username || ''}</td>
        </tr>`;
    }).join('');
    printWin.document.write(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Bookmarks — Cas ${caseId}</title>
  <style>
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #fff; color: #1a1a2e; margin: 24px; }
    h1 { font-size: 18px; margin-bottom: 4px; }
    p.sub { font-size: 11px; color: #666; margin-bottom: 16px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th { background: #1a1a2e; color: #fff; text-align: left; padding: 6px 10px; font-size: 11px; }
    td { padding: 5px 10px; border-bottom: 1px solid #e0e0e0; vertical-align: top; }
    tr:nth-child(even) td { background: #f8f8fc; }
    @media print { body { margin: 8px; } }
  </style>
</head>
<body>
  <h1>${t('bookmark.pdf_title')}</h1>
  <p class="sub">${t('timeline.export_case_label')} : ${caseId} &nbsp;|&nbsp; ${t('bookmark.pdf_exported')} ${new Date().toLocaleString()} &nbsp;|&nbsp; ${bookmarks.length} bookmark(s)</p>
  <table>
    <thead>
      <tr>
        <th>${t('bookmark.col_ts')}</th><th>${t('bookmark.col_title')}</th><th>${t('bookmark.col_desc')}</th>
        <th>${t('bookmark.col_tactic')}</th><th>${t('bookmark.col_tech')}</th><th>${t('bookmark.col_color')}</th><th>${t('bookmark.col_author')}</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>
</body>
</html>`);
    printWin.document.close();
    printWin.focus();
    setTimeout(() => { printWin.print(); }, 400);
  }

  function startEdit(b) {
    setEditId(b.id);
    setEditInitial({
      title: b.title,
      description: b.description || '',
      mitre_tactic: b.mitre_tactic || '',
      mitre_technique: b.mitre_technique || '',
      color: b.color || '#4d82c0',
    });
    setShowForm(false);
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Bookmark size={13} style={{ color: '#4d82c0' }} />
          <span style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 700, color: '#8aa0bc', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Bookmarks ({bookmarks.length})
          </span>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <button onClick={load} title={t('common.refresh')} style={{ background: 'none', border: '1px solid #1a2035', borderRadius: 4, cursor: 'pointer', padding: '5px 9px', color: '#3d5070' }}>
            <RefreshCw size={11} />
          </button>
          {bookmarks.length > 0 && (
            <>
              <button
                onClick={exportCSV}
                title={t('common.export') + ' CSV'}
                style={{
                  display: 'flex', alignItems: 'center', gap: 3,
                  background: 'none', border: '1px solid #1a2035', borderRadius: 4,
                  cursor: 'pointer', padding: '5px 10px', color: '#3d5070',
                  fontSize: 10, fontFamily: 'monospace',
                }}
              >
                <FileText size={10} /> CSV
              </button>
              <button
                onClick={exportPDF}
                title={t('common.export') + ' PDF'}
                style={{
                  display: 'flex', alignItems: 'center', gap: 3,
                  background: 'none', border: '1px solid #1a2035', borderRadius: 4,
                  cursor: 'pointer', padding: '5px 10px', color: '#8b72d6',
                  fontSize: 10, fontFamily: 'monospace',
                }}
              >
                <FileDown size={10} /> PDF
              </button>
            </>
          )}
          <button
            onClick={() => { setShowForm(v => !v); setEditId(null); }}
            style={{
              display: 'flex', alignItems: 'center', gap: 4,
              background: showForm ? '#1a3a5a' : 'none',
              border: '1px solid #2a4a6a', borderRadius: 4, cursor: 'pointer',
              padding: '3px 8px', color: '#4d82c0', fontSize: 10, fontFamily: 'monospace',
            }}
          >
            {showForm ? <X size={11} /> : <Plus size={11} />}
            {showForm ? t('common.cancel') : t('bookmark.new')}
          </button>
        </div>
      </div>

      {showForm && (
        <BookmarkForm
          onSave={handleCreate}
          onCancel={() => setShowForm(false)}
        />
      )}

      {loading && (
        <div style={{ textAlign: 'center', color: '#3d5070', fontFamily: 'monospace', fontSize: 11, padding: 16 }}>
          {t('common.loading')}
        </div>
      )}

      {!loading && bookmarks.length === 0 && !showForm && (
        <div style={{
          textAlign: 'center', color: '#2a3a50', fontFamily: 'monospace', fontSize: 11,
          padding: '24px 16px', border: '1px dashed #1a2035', borderRadius: 8,
        }}>
          {t('bookmark.empty')}
        </div>
      )}

      {bookmarks.map(b => {
        const tc = TACTIC_COLOR[b.mitre_tactic] || '#7d8590';
        const isEditing = editId === b.id;
        return (
          <div key={b.id}>
            {isEditing ? (
              <BookmarkForm
                initial={editInitial}
                onSave={handleUpdate}
                onCancel={() => { setEditId(null); setEditInitial(null); }}
              />
            ) : (
              <div style={{
                borderRadius: 8, border: `1px solid ${b.color || '#1a2035'}30`,
                borderLeft: `3px solid ${b.color || '#4d82c0'}`,
                background: '#07101f', padding: '10px 12px',
                display: 'flex', flexDirection: 'column', gap: 6,
              }}>
                
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: '#c8d8ec', lineHeight: 1.4, flex: 1 }}>
                    {b.title}
                  </span>
                  <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
                    <button onClick={() => startEdit(b)} title={t('common.edit')} style={{ background: 'none', border: '1px solid #1a2035', borderRadius: 4, cursor: 'pointer', color: '#3d5070', padding: '4px 7px', display: 'flex', alignItems: 'center' }}>
                      <Pencil size={10} />
                    </button>
                    <button onClick={() => remove(b.id)} title={t('common.delete')} style={{ background: 'none', border: '1px solid #da363330', borderRadius: 4, cursor: 'pointer', color: '#da3633', padding: '4px 7px', display: 'flex', alignItems: 'center' }}>
                      <Trash2 size={10} />
                    </button>
                  </div>
                </div>

                {b.description && (
                  <div style={{ fontSize: 11, color: '#7d8590', lineHeight: 1.4 }}>{b.description}</div>
                )}

                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, alignItems: 'center' }}>
                  {b.mitre_tactic && (
                    <span style={{
                      padding: '1px 7px', borderRadius: 4, fontSize: 9, fontWeight: 700,
                      fontFamily: 'monospace', background: `${tc}18`, color: tc, border: `1px solid ${tc}30`,
                    }}>
                      {b.mitre_tactic}
                    </span>
                  )}
                  {b.mitre_technique && (
                    <span style={{
                      padding: '1px 7px', borderRadius: 4, fontSize: 9, fontFamily: 'monospace',
                      background: '#1a2035', color: '#7d8590', border: '1px solid #2a3045',
                    }}>
                      {b.mitre_technique}
                    </span>
                  )}
                  {b.event_timestamp && (
                    <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#3d5070' }}>
                      {new Date(b.event_timestamp).toLocaleString()}
                    </span>
                  )}
                  <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#2a3a50', marginLeft: 'auto' }}>
                    {b.author_name || b.username} · {new Date(b.created_at).toLocaleDateString('fr-FR')}
                  </span>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
