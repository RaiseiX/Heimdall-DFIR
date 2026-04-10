
import { NavLink } from 'react-router-dom';

function Badge({ children }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
      minWidth: 18, height: 18, borderRadius: 9,
      background: 'var(--fl-danger)', color: '#fff',
      fontSize: 10, fontWeight: 700, padding: '0 4px',
    }}>{children}</span>
  );
}

export default function TabGroup({ active, onChange, tabs, className = '' }) {
  return (
    <div className={['fl-tabs', className].filter(Boolean).join(' ')}>
      {tabs.map((t) => {
        const activeColor = t.color;

        if (t.to) {

          return (
            <NavLink
              key={t.id}
              to={t.to}
              className={({ isActive }) =>
                ['fl-tab', isActive ? 'fl-tab-active' : ''].filter(Boolean).join(' ')
              }
              style={({ isActive }) =>
                isActive && activeColor ? { color: activeColor, borderBottomColor: activeColor } : {}
              }
            >
              {t.icon && <t.icon size={14} />}
              {t.label}
              {t.badge != null && t.badge > 0 && <Badge>{t.badge}</Badge>}
            </NavLink>
          );
        }

        const isActive = active === t.id;
        return (
          <button
            key={t.id}
            onClick={() => onChange(t.id)}
            className={['fl-tab', isActive ? 'fl-tab-active' : ''].filter(Boolean).join(' ')}
            style={isActive && activeColor ? { color: activeColor, borderBottomColor: activeColor } : {}}
          >
            {t.icon && <t.icon size={14} />}
            {t.label}
            {t.badge != null && t.badge > 0 && <Badge>{t.badge}</Badge>}
          </button>
        );
      })}
    </div>
  );
}
