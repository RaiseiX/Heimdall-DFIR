import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { threatHuntingAPI } from '../../utils/api';
import { SectionHead, Row, Btn, Skeletons } from './shared';
import GitHubImportModal from '../threathunt/GitHubImportModal';

export default function RulesImportSection() {
  const { t, i18n } = useTranslation();
  const n = (v) => Number(v ?? 0).toLocaleString(i18n.language);
  const [counts, setCounts] = useState(null);
  const [importing, setImporting] = useState(null);

  const load = () => Promise.all([
    threatHuntingAPI.yaraRules().then(r => r.data.rules ?? []).catch(() => null),
    threatHuntingAPI.sigmaRules().then(r => r.data.rules ?? []).catch(() => null),
  ]).then(([yara, sigma]) => setCounts({
    yara: yara ? { total: yara.length, active: yara.filter(r => r.is_active !== false).length } : null,
    sigma: sigma ? { total: sigma.length } : null,
  }));

  useEffect(() => { load(); }, []);

  if (!counts) return <Skeletons n={2} />;

  const line = (c, fallback) => (c ? fallback : t('settings.rules_import.count_unavailable'));

  return (
    <>
      <SectionHead title={t('settings.rules_import.title')} desc={t('settings.rules_import.desc')} />

      <Row
        label={t('settings.rules_import.yara_label')}
        desc={line(counts.yara, t('settings.rules_import.yara_count', {
          total: n(counts.yara?.total), active: n(counts.yara?.active),
        }))}
      >
        <Btn onClick={() => setImporting('yara')}>{t('settings.rules_import.action')}</Btn>
      </Row>

      <Row
        label={t('settings.rules_import.sigma_label')}
        desc={line(counts.sigma, t('settings.rules_import.sigma_count', { total: n(counts.sigma?.total) }))}
        last
      >
        <Btn onClick={() => setImporting('sigma')}>{t('settings.rules_import.action')}</Btn>
      </Row>

      <GitHubImportModal
        open={importing !== null}
        type={importing || 'yara'}
        onClose={() => setImporting(null)}
        onImported={load}
      />
    </>
  );
}
