
import { useTranslation } from 'react-i18next';
import { Action } from './MapControls';

export default function ColorblindToggle({ active = false, onToggle }) {
  const { t } = useTranslation();

  return (
    <Action onClick={onToggle} active={active} title={t('networkMap.band.colorblind_hint')}>
      {t('networkMap.band.colorblind')}
    </Action>
  );
}
