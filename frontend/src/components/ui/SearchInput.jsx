import { Search, X } from 'lucide-react';

export default function SearchInput({
  value,
  onChange,
  onClear,
  placeholder = 'Rechercher…',
  style,
}) {
  return (
    <div style={{ position: 'relative', ...style }}>
      <Search
        size={13}
        style={{
          position: 'absolute', left: 9, top: '50%',
          transform: 'translateY(-50%)', color: 'var(--fl-muted)',
          pointerEvents: 'none',
        }}
      />
      <input
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="fl-input"
        style={{
          paddingLeft: 28,
          paddingRight: value ? 28 : 10,
          fontSize: 12,
          fontFamily: 'monospace',
          padding: `5px 28px 5px 28px`,
        }}
      />
      {value && onClear && (
        <X
          size={13}
          onClick={onClear}
          style={{
            position: 'absolute', right: 9, top: '50%',
            transform: 'translateY(-50%)',
            color: 'var(--fl-dim)', cursor: 'pointer',
          }}
        />
      )}
    </div>
  );
}
