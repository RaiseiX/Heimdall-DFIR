import { ChevronLeft, ChevronRight } from 'lucide-react';

export default function Pagination({ page, totalPages, onChange, siblingCount = 1 }) {
  if (totalPages <= 1) return null;

  const pages = buildPageRange(page, totalPages, siblingCount);

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 4,
      padding: '10px 0',
      justifyContent: 'center',
    }}>
      <PageBtn
        disabled={page <= 1}
        onClick={() => onChange(page - 1)}
        title="Page précédente"
      >
        <ChevronLeft size={14} />
      </PageBtn>

      {pages.map((p, i) =>
        p === '…' ? (
          <span key={`ellipsis-${i}`} style={{ padding: '0 4px', color: 'var(--fl-dim)', fontSize: 13 }}>…</span>
        ) : (
          <PageBtn
            key={p}
            active={p === page}
            onClick={() => p !== page && onChange(p)}
          >
            {p}
          </PageBtn>
        )
      )}

      <PageBtn
        disabled={page >= totalPages}
        onClick={() => onChange(page + 1)}
        title="Page suivante"
      >
        <ChevronRight size={14} />
      </PageBtn>
    </div>
  );
}

function PageBtn({ children, active, disabled, onClick, title }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      style={{
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
        minWidth: 30, height: 30, padding: '0 6px',
        borderRadius: 6,
        fontSize: 13, fontFamily: 'monospace', fontWeight: active ? 700 : 500,
        background: active ? 'color-mix(in srgb, var(--fl-accent) 15%, transparent)' : 'transparent',
        color: active ? 'var(--fl-accent)' : disabled ? 'var(--fl-muted)' : 'var(--fl-dim)',
        border: active ? '1px solid color-mix(in srgb, var(--fl-accent) 30%, transparent)' : '1px solid transparent',
        cursor: disabled ? 'not-allowed' : active ? 'default' : 'pointer',
        transition: 'background 0.1s, color 0.1s',
      }}
    >
      {children}
    </button>
  );
}

function buildPageRange(current, total, siblings) {
  const totalButtons = siblings * 2 + 5;
  if (total <= totalButtons) {
    return Array.from({ length: total }, (_, i) => i + 1);
  }

  const leftSibling  = Math.max(current - siblings, 2);
  const rightSibling = Math.min(current + siblings, total - 1);
  const showLeftEllipsis  = leftSibling  > 2;
  const showRightEllipsis = rightSibling < total - 1;

  const result = [1];
  if (showLeftEllipsis)  result.push('…');
  for (let i = leftSibling; i <= rightSibling; i++) result.push(i);
  if (showRightEllipsis) result.push('…');
  result.push(total);
  return result;
}
