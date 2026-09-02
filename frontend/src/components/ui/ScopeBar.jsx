import { X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import FilterChip from './FilterChip';

export default function ScopeBar({ tokens = [], className }) {
  const { t } = useTranslation();
  if (tokens.length === 0) return null;

  const rootClass = ['scope-bar', className].filter(Boolean).join(' ');

  return (
    <div className={rootClass}>
      {tokens.map(token => (
        <FilterChip
          key={token.key}
          active
          icon={X}
          onClick={token.onRemove}
          ariaLabel={t('ui.scope_token_remove', { label: token.label })}
        >
          {token.label}: {token.value}
        </FilterChip>
      ))}
    </div>
  );
}
