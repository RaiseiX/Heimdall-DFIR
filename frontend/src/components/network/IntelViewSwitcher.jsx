/**
 * IntelViewSwitcher — premium segmented control for switching between intelligence views.
 *
 * Design contract (Observatory charter): color = signal, single accent.
 *  - Inactive tabs: graphite (--fl-dim), transparent background.
 *  - Active tab: --fl-text label on a --fl-raised fill with a subtle inset ring;
 *    the icon is the ONLY accent (violet) — no per-view "rainbow" colors.
 *  - Hover on inactive: neutral text/background brighten, never a status color.
 *
 * Shared between CaseIntelligencePage (case mode) and GlobalNetworkMapPage (global mode)
 * so both surfaces read as one coherent product.
 */
export default function IntelViewSwitcher({ views, active, onChange }) {
  return (
    <div
      role="tablist"
      style={{
        display: 'flex', alignItems: 'center', gap: 2,
        padding: 2, borderRadius: 9,
        border: '1px solid var(--fl-border)', background: 'var(--fl-bg)',
      }}
    >
      {views.map(v => {
        const isActive = v.id === active;
        const Icon = v.icon;
        return (
          <button
            key={v.id}
            role="tab"
            aria-selected={isActive}
            onClick={() => onChange(v.id)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '5px 11px', borderRadius: 7,
              fontSize: 12, fontWeight: isActive ? 600 : 400,
              border: 'none', cursor: 'pointer',
              color: isActive ? 'var(--fl-text)' : 'var(--fl-dim)',
              background: isActive ? 'var(--fl-raised)' : 'transparent',
              boxShadow: isActive ? 'inset 0 0 0 1px var(--fl-border3)' : 'none',
              transition: 'color 0.15s, background 0.15s',
            }}
            onMouseEnter={e => {
              if (isActive) return;
              e.currentTarget.style.color = 'var(--fl-text)';
              e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-text) 4%, transparent)';
            }}
            onMouseLeave={e => {
              if (isActive) return;
              e.currentTarget.style.color = 'var(--fl-dim)';
              e.currentTarget.style.background = 'transparent';
            }}
          >
            {Icon && (
              <Icon
                size={13}
                style={{ color: isActive ? 'var(--fl-accent)' : 'currentColor', flexShrink: 0 }}
              />
            )}
            {v.label}
          </button>
        );
      })}
    </div>
  );
}
