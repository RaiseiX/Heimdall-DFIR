import { Sparkles, RefreshCw, Loader2 } from 'lucide-react';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

// Each AI-generated narrative field, shown as an editable code block.
const AI_FIELDS = [
  ['executive_summary', 'Executive summary'],
  ['key_findings', 'Key findings'],
  ['ioc_analysis', 'IOC analysis'],
  ['mitre_analysis', 'ATT&CK / TTP analysis'],
  ['timeline_narrative', 'Timeline narrative'],
  ['recommendations', 'Recommendations'],
];

// Deliberate VS Code-dark editor surface (kept dark in both app themes for the "code editor" feel).
const ED_BG = '#16181D', ED_BAR = '#1B1D24', ED_LINE = '#2A2D36', ED_TXT = '#D9DCE3', ED_COMMENT = '#6BA678', ED_DIM = '#6B7280';

/**
 * VS Code-style editor for the AI-generated report narrative.
 * The analyst reviews/edits each block (`// Champ` comment header + editable text)
 * before it is baked into the PDF.
 */
export default function ReportAiEditor({ value, onChange, onRegenerate, loading }) {
  return (
    <div style={{ border: '1px solid var(--fl-border2)', borderRadius: 8, overflow: 'hidden', background: ED_BG, marginBottom: 12 }}>
      {/* editor title bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 12px', background: ED_BAR, borderBottom: `1px solid ${ED_LINE}` }}>
        <span style={{ display: 'flex', gap: 5 }}>
          <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#E06C5B' }} />
          <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#E2B450' }} />
          <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#6BA678' }} />
        </span>
        <Sparkles size={12} style={{ color: 'var(--fl-accent)', marginLeft: 4 }} />
        <span style={{ fontFamily: MONO, fontSize: 11, color: '#C9CDD6' }}>analyse-ia.md</span>
        <span style={{ fontFamily: MONO, fontSize: 9.5, color: ED_DIM }}>- edit the text before including it in the report</span>
        <span style={{ flex: 1 }} />
        <button
          onClick={onRegenerate}
          disabled={loading}
          title="Regenerate the analysis with AI"
          style={{
            display: 'flex', alignItems: 'center', gap: 5, padding: '3px 9px', borderRadius: 5,
            fontFamily: MONO, fontSize: 10, cursor: loading ? 'wait' : 'pointer',
            background: 'transparent', border: `1px solid ${ED_LINE}`, color: '#C9CDD6',
          }}
        >
          {loading ? <Loader2 size={11} style={{ animation: 'fl-spin 0.9s linear infinite' }} /> : <RefreshCw size={11} />}
          Regenerate
        </button>
      </div>

      {/* code body */}
      <div style={{ padding: '12px 0', maxHeight: 420, overflowY: 'auto' }}>
        {AI_FIELDS.map(([key, label], i) => (
          <div key={key} style={{ display: 'flex', padding: '0 0 16px' }}>
            {/* gutter (line marker) */}
            <div style={{ width: 34, flexShrink: 0, textAlign: 'right', paddingRight: 10, fontFamily: MONO, fontSize: 11, color: '#3C4049', userSelect: 'none', lineHeight: 1.6 }}>
              {i + 1}
            </div>
            <div style={{ flex: 1, minWidth: 0, paddingRight: 14 }}>
              <div style={{ fontFamily: MONO, fontSize: 11, color: ED_COMMENT, marginBottom: 4 }}>{`// ${label}`}</div>
              <textarea
                value={value?.[key] || ''}
                onChange={e => onChange(key, e.target.value)}
                spellCheck={false}
                rows={Math.max(2, Math.min(8, Math.ceil(((value?.[key] || '').length || 1) / 88) + (value?.[key] || '').split('\n').length - 1))}
                placeholder="(empty - this block will be omitted from the report)"
                style={{
                  width: '100%', boxSizing: 'border-box', resize: 'vertical',
                  background: 'transparent', color: ED_TXT, border: 'none', outline: 'none',
                  borderLeft: `2px solid ${ED_LINE}`, paddingLeft: 12,
                  fontFamily: MONO, fontSize: 12, lineHeight: 1.6,
                }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
