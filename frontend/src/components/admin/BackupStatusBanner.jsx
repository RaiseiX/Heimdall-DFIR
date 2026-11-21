import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import Alert from '../ui/Alert';
import { adminAPI } from '../../utils/api';
import { backupBanner } from './backupBanner';

export default function BackupStatusBanner({ style }) {
  const { t } = useTranslation();
  const [banner, setBanner] = useState(null);

  useEffect(() => {
    let actif = true;
    adminAPI.backupStatus()
      .then((r) => { if (actif) setBanner(backupBanner(r.data)); })
      .catch(() => { if (actif) setBanner(backupBanner(null)); });
    return () => { actif = false; };
  }, []);

  if (!banner) return null;
  return <Alert variant="warn" message={t(banner.key, banner.params)} style={style} />;
}
