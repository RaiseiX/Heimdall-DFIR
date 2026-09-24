import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Github, Download, X } from 'lucide-react';
import { threatHuntingAPI } from '../../utils/api';
import { Button, Spinner } from '../ui';
import { C } from './shared';

export default function GitHubImportModal({ open, type, onClose, onImported }) {
  const { t } = useTranslation();
  const accentColor = type === 'sigma' ? C.sigma : C.yara;

  const [step, setStep]       = useState('repos');
  const [repos, setRepos]     = useState([]);
  const [selRepo, setSelRepo] = useState(null);
  const [result, setResult]   = useState(null);

  useEffect(() => {
    if (!open) return;
    setStep('repos'); setSelRepo(null); setResult(null);
    threatHuntingAPI.githubRepos(type)
      .then(r => setRepos(r.data.repos ?? []))
      .catch(() => {});
  }, [open, type]);

  async function doImport() {
    setStep('importing');
    try {
      const r = await threatHuntingAPI.githubImportZip({
        owner: selRepo.owner, repo: selRepo.repo,
        branch: selRepo.branch, type,
      });
      setResult(r.data);
      onImported?.();
    } catch (e) {
      setResult({ total: 0, imported: 0, skipped: 0, errors: [e.response?.data?.error || e.message] });
    }
    setStep('done');
  }

  if (!open) return null;

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(0,0,0,0.65)', backdropFilter: 'blur(4px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20,
    }} onClick={e => { if (e.target === e.currentTarget && step !== 'importing') onClose(); }}>
      <div style={{
        background: 'var(--fl-panel)', border: `1px solid color-mix(in srgb, ${accentColor} 25%, transparent)`,
        borderRadius: 12, width: '100%', maxWidth: 560,
        display: 'flex', flexDirection: 'column',
        boxShadow: 'var(--fl-shadow-lg)',
      }}>
        
        <div style={{ padding: '16px 20px', borderBottom: `1px solid ${C.border}`, display: 'flex', alignItems: 'center', gap: 10 }}>
          <Github size={18} style={{ color: accentColor }} />
          <span style={{ fontWeight: 700, fontSize: 15, color: 'var(--fl-text)' }}>
            {t('threat_hunt.github.title', { type: type === 'sigma' ? t('threat_hunt.sigma_rules_lower') : t('threat_hunt.yara_rules_lower') })}
          </span>
          {step !== 'importing' && (
            <button onClick={onClose} style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-dim)', padding: 4 }}>
              <X size={16} />
            </button>
          )}
        </div>

        <div style={{ padding: '20px' }}>

          {step === 'repos' && (
            <div>
              <p style={{ margin: '0 0 14px', fontSize: 13, color: 'var(--fl-dim)' }}>
                {t('threat_hunt.github.select_repo_desc')}
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {repos.map(r => (
                  <button key={`${r.owner}/${r.repo}`}
                    onClick={() => { setSelRepo(r); setStep('confirm'); }}
                    style={{
                      background: C.surface, border: `1px solid ${C.border}`,
                      borderRadius: 8, padding: '14px 16px', cursor: 'pointer',
                      textAlign: 'left', transition: 'border-color 0.15s',
                    }}
                    onMouseEnter={e => e.currentTarget.style.borderColor = accentColor + '80'}
                    onMouseLeave={e => e.currentTarget.style.borderColor = C.border}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                      <Github size={14} style={{ color: accentColor }} />
                      <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--fl-text)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                        {r.owner}/{r.repo}
                      </span>
                    </div>
                    <p style={{ margin: 0, fontSize: 12, color: 'var(--fl-dim)' }}>{r.description}</p>
                  </button>
                ))}
              </div>
            </div>
          )}

          
          {step === 'confirm' && selRepo && (
            <div style={{ textAlign: 'center', padding: '8px 0' }}>
              <Download size={32} style={{ color: accentColor, marginBottom: 14 }} />
              <p style={{ margin: '0 0 6px', fontWeight: 700, fontSize: 15, color: 'var(--fl-text)' }}>
                {t('threat_hunt.github.confirm_title')}
              </p>
              <p style={{ margin: '0 0 4px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 13, color: accentColor }}>
                {selRepo.owner}/{selRepo.repo}
              </p>
              <p style={{ margin: '0 0 20px', fontSize: 12, color: 'var(--fl-dim)' }}>
                {selRepo.description}
              </p>
              <div style={{ padding: '10px 14px', background: 'var(--fl-card)', border: `1px solid ${C.border}`, borderRadius: 8, fontSize: 12, color: 'var(--fl-dim)', textAlign: 'left' }}>
                {t('threat_hunt.github.confirm_desc_before')}
                <strong style={{ color: 'var(--fl-text)' }}>{t('threat_hunt.github.confirm_desc_emphasis')}</strong>
                {t('threat_hunt.github.confirm_desc_after')}
              </div>
            </div>
          )}

          {step === 'importing' && (
            <div style={{ textAlign: 'center', padding: '32px 0' }}>
              <Spinner size={32} />
              <p style={{ marginTop: 16, fontWeight: 600, fontSize: 14, color: 'var(--fl-text)' }}>
                {t('threat_hunt.github.importing')}
              </p>
              <p style={{ margin: '6px 0 0', fontSize: 12, color: 'var(--fl-dim)' }}>
                {t('threat_hunt.github.importing_steps')}
              </p>
              <p style={{ margin: '4px 0 0', fontSize: 12, color: 'var(--fl-muted)' }}>
                {t('threat_hunt.github.keep_open')}
              </p>
            </div>
          )}

          {step === 'done' && result && (
            <div>
              <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
                <div style={{ flex: 1, textAlign: 'center', padding: '14px 10px', background: 'color-mix(in srgb, var(--fl-ok) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-ok) 22%, transparent)', borderRadius: 8 }}>
                  <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--fl-ok)' }}>{result.imported}</div>
                  <div style={{ fontSize: 12, color: 'var(--fl-dim)' }}>{t('threat_hunt.github.imported')}</div>
                </div>
                <div style={{ flex: 1, textAlign: 'center', padding: '14px 10px', background: 'rgba(217,124,32,0.08)', border: '1px solid rgba(217,124,32,0.25)', borderRadius: 8 }}>
                  <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--fl-warn)' }}>{result.skipped}</div>
                  <div style={{ fontSize: 12, color: 'var(--fl-dim)' }}>{t('threat_hunt.github.skipped_invalid')}</div>
                </div>
                {result.total > 0 && (
                  <div style={{ flex: 1, textAlign: 'center', padding: '14px 10px', background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8 }}>
                    <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--fl-dim)' }}>{result.total}</div>
                    <div style={{ fontSize: 12, color: 'var(--fl-dim)' }}>{t('threat_hunt.github.found')}</div>
                  </div>
                )}
              </div>
              {result.errors?.length > 0 && (
                <div>
                  <p style={{ fontSize: 12, color: 'var(--fl-dim)', margin: '0 0 6px' }}>
                    {t('threat_hunt.github.errors_count', { count: result.errors.length })}
                  </p>
                  <div style={{ maxHeight: 140, overflowY: 'auto', background: C.surface, borderRadius: 6, padding: '8px 12px', border: `1px solid ${C.border}` }}>
                    {result.errors.map((e, i) => (
                      <div key={i} style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-danger)', marginBottom: 3 }}>
                        {e}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        <div style={{ padding: '12px 20px', borderTop: `1px solid ${C.border}`, display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          {step === 'repos' && (
            <Button variant="secondary" onClick={onClose}>{t('common.close')}</Button>
          )}
          {step === 'confirm' && (
            <>
              <Button variant="secondary" onClick={() => setStep('repos')}>{t('common.back')}</Button>
              <Button variant="primary" onClick={doImport} style={{ background: accentColor }}>
                {t('threat_hunt.github.import_all')}
              </Button>
            </>
          )}
          {step === 'importing' && (
            <Button variant="secondary" disabled>{t('threat_hunt.github.importing')}</Button>
          )}
          {step === 'done' && (
            <Button variant="primary" onClick={onClose}>{t('common.close')}</Button>
          )}
        </div>
      </div>
    </div>
  );
}
