
export default function EmptyState({ icon: Icon, title, subtitle, action, iconSize = 32 }) {
  return (
    <div className="fl-empty">
      {Icon && (
        <div className="fl-empty-icon">
          <Icon size={iconSize} />
        </div>
      )}
      {title    && <p className="fl-empty-title">{title}</p>}
      {subtitle && <p className="fl-empty-sub">{subtitle}</p>}
      {action   && <div style={{ marginTop: 8 }}>{action}</div>}
    </div>
  );
}
