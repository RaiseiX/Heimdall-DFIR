import { X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import FilterChip from './FilterChip';

/**
 * `ScopeBar` — one removable token per constant lifted out of a `DataTable`
 * by `constantColumns` (see `./DataTable.jsx`). On the real YARA rule set
 * that's `description`, two tags, and author+date: five-sixths of every
 * card's content, identical across all 566 rows, now stated once instead of
 * 566 times.
 *
 * A scope token IS a removable chip — `FilterChip` already renders exactly
 * that (an `active`-tinted pill with an optional leading icon and an
 * `onClick`), so `ScopeBar` composes it rather than re-implementing its own
 * chip styling. The `X` icon signals "removable" and `onClick` runs the
 * caller's `onRemove`; the only thing `FilterChip` didn't already have was a
 * way to attach a translated `aria-label` distinct from its visible text, so
 * that one prop (`ariaLabel`, additive and optional) was added there rather
 * than duplicated here.
 *
 * Renders nothing when there are no tokens — that's the caller's decision
 * (an empty `constantColumns` result), not a hidden choice made in here.
 *
 * @param {object} props
 * @param {Array<{ key: string, label: string, value: React.ReactNode, onRemove: () => void }>} props.tokens
 * @param {string} [props.className]
 */
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
