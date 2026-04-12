import { useState, useEffect } from 'react';
import { BookOpen, CheckCircle2, Circle, ChevronRight, ChevronDown, Shield, Zap, Mail, Tag } from 'lucide-react';
import { playbooksAPI } from '../utils/api';
import { useTranslation } from 'react-i18next';

const S = {
  bg:      'var(--fl-bg)',
  card:    'var(--fl-panel)',
  border:  'var(--fl-border)',
  text:    'var(--fl-text)',
  muted:   'var(--fl-dim)',
  blue:    'var(--fl-accent)',
  green:   'var(--fl-ok)',
  orange:  '#d29922',
  red:     'var(--fl-danger)',
  purple:  'var(--fl-purple)',
};

const TYPE_ICON = {
  ransomware: { icon: Shield, color: S.red,    label: 'Ransomware' },
  rdp:        { icon: Zap,    color: S.orange,  label: 'RDP' },
  phishing:   { icon: Mail,   color: S.purple,  label: 'Phishing' },
  generic:    { icon: BookOpen, color: S.blue,  label: 'Générique' },
};

function TypeBadge({ type }) {
  const meta = TYPE_ICON[type] || TYPE_ICON.generic;
  const Icon = meta.icon;
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono"
      style={{ background: meta.color + '22', border: `1px solid ${meta.color}44`, color: meta.color }}>
      <Icon size={11} /> {meta.label}
    </span>
  );
}

function MitreBadge({ technique }) {
  if (!technique) return null;
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-mono"
      style={{ background: '#8b72d622', border: '1px solid #8b72d644', color: S.purple }}>
      <Tag size={10} /> {technique}
    </span>
  );
}

function PlaybookCard({ playbook, onSelect, selected }) {
  return (
    <button onClick={() => onSelect(playbook)}
      className="w-full text-left p-4 rounded-lg border transition-all"
      style={{
        background: selected ? '#4d82c015' : S.card,
        borderColor: selected ? S.blue : S.border,
        outline: 'none',
      }}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <TypeBadge type={playbook.incident_type} />
            <span className="text-sm font-semibold" style={{ color: S.text }}>{playbook.title}</span>
          </div>
          <p className="text-xs line-clamp-2" style={{ color: S.muted }}>{playbook.description}</p>
        </div>
        <div className="flex flex-col items-end gap-1 shrink-0">
          <span className="text-xs font-mono px-2 py-0.5 rounded"
            style={{ background: 'var(--fl-border)', color: S.muted }}>{playbook.step_count} étapes</span>
          <ChevronRight size={16} style={{ color: S.muted }} />
        </div>
      </div>
    </button>
  );
}

function StepRow({ step }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border rounded-lg overflow-hidden" style={{ borderColor: S.border }}>
      <button className="w-full flex items-center gap-3 p-3 text-left hover:bg-white/5 transition-colors"
        onClick={() => setOpen(v => !v)}>
        <span className="flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-xs font-mono font-bold"
          style={{ background: S.blue + '33', color: S.blue }}>{step.step_order}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium" style={{ color: S.text }}>{step.title}</span>
            {step.note_required && (
              <span className="text-xs px-1.5 py-0.5 rounded"
                style={{ background: S.orange + '22', color: S.orange }}>Note requise</span>
            )}
            <MitreBadge technique={step.mitre_technique} />
          </div>
        </div>
        {open ? <ChevronDown size={14} style={{ color: S.muted }} /> : <ChevronRight size={14} style={{ color: S.muted }} />}
      </button>
      {open && step.description && (
        <div className="px-4 pb-3 pt-1 text-sm" style={{ color: S.muted, background: '#0d111788' }}>
          {step.description}
        </div>
      )}
    </div>
  );
}

export default function PlaybooksPage() {
  const { t } = useTranslation();
  const [playbooks, setPlaybooks] = useState([]);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadingDetail, setLoadingDetail] = useState(false);

  useEffect(() => {
    playbooksAPI.list()
      .then(r => { setPlaybooks(r.data); if (r.data.length > 0) handleSelect(r.data[0]); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const handleSelect = async (pb) => {
    setSelected(pb);
    setLoadingDetail(true);
    try {
      const r = await playbooksAPI.get(pb.id);
      setDetail(r.data);
    } catch {}
    setLoadingDetail(false);
  };

  return (
    <div className="p-6 max-w-7xl mx-auto">
      
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-1">
          <BookOpen size={22} style={{ color: S.blue }} />
          <h1 className="text-xl font-bold font-mono" style={{ color: S.text }}>Playbooks DFIR</h1>
        </div>
        <p className="text-sm" style={{ color: S.muted }}>
          Runbooks d'investigation de référence par type d'incident. Applicables depuis un dossier via l'onglet Playbooks.
        </p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-24 text-sm" style={{ color: S.muted }}>{t('common.loading')}</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          
          <div className="flex flex-col gap-3">
            <p className="text-xs font-mono uppercase tracking-widest mb-1" style={{ color: S.muted }}>
              {playbooks.length} playbook{playbooks.length !== 1 ? 's' : ''}
            </p>
            {playbooks.map(pb => (
              <PlaybookCard key={pb.id} playbook={pb} selected={selected?.id === pb.id} onSelect={handleSelect} />
            ))}
          </div>

          
          <div className="lg:col-span-2">
            {loadingDetail && (
              <div className="flex items-center justify-center py-24 text-sm" style={{ color: S.muted }}>{t('common.loading')}</div>
            )}
            {!loadingDetail && detail && (
              <div className="rounded-xl border p-5" style={{ background: S.card, borderColor: S.border }}>
                <div className="flex items-start gap-3 mb-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <TypeBadge type={detail.incident_type} />
                      <h2 className="text-lg font-bold" style={{ color: S.text }}>{detail.title}</h2>
                    </div>
                    <p className="text-sm" style={{ color: S.muted }}>{detail.description}</p>
                  </div>
                  <span className="text-sm font-mono px-3 py-1 rounded-full"
                    style={{ background: S.blue + '22', color: S.blue }}>{detail.steps?.length} étapes</span>
                </div>

                
                {detail.steps?.some(s => s.mitre_technique) && (
                  <div className="mb-4 p-3 rounded-lg" style={{ background: '#8b72d611', border: '1px solid #8b72d630' }}>
                    <p className="text-xs font-mono uppercase mb-2" style={{ color: S.purple }}>Techniques MITRE ATT&CK couvertes</p>
                    <div className="flex flex-wrap gap-1.5">
                      {[...new Set(detail.steps.filter(s => s.mitre_technique).map(s => s.mitre_technique))].map(t => (
                        <MitreBadge key={t} technique={t} />
                      ))}
                    </div>
                  </div>
                )}

                
                <div className="flex flex-col gap-2">
                  {detail.steps?.map(step => <StepRow key={step.id} step={step} />)}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
