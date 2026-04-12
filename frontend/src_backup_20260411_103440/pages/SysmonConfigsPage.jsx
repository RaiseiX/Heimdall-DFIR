import { useState, useEffect } from 'react';
import { Download, CheckCircle, Clock, Shield, AlertTriangle, Star, BookOpen, ChevronDown, ChevronRight, Loader2, Tag } from 'lucide-react';
import { sysmonAPI } from '../utils/api';

const NOISE_COLOR = { low: '#3fb950', medium: '#d97c20', high: '#da3633' };
const NOISE_LABEL = { low: 'Faible', medium: 'Moyen', high: 'Élevé' };

const DEPLOY_GUIDE = `# Déploiement Sysmon — Guide rapide

## 1. Télécharger Sysmon
https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

## 2. Installation initiale
sysmon64.exe -accepteula -i <config.xml>

## 3. Mise à jour de la configuration
sysmon64.exe -c <config.xml>

## 4. Vérification
sysmon64.exe -c   # affiche la config active
Get-Service Sysmon64  # vérifie que le service tourne

## 5. Accès aux logs
Observateur d'événements > Applications and Services Logs
  > Microsoft > Windows > Sysmon > Operational

## 6. Collecte centralisée (gratuit)
wevtutil.exe sl Microsoft-Windows-Sysmon/Operational \\
  /ca:O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)
# Ensuite configurer Windows Event Forwarding (WEF)`;

function ConfigCard({ config, onDownload, onMarkDeployed, downloading }) {
  const [showTech, setShowTech] = useState(false);

  return (
    <div className="fl-card p-5" style={{ borderLeft: config.is_recommended ? '3px solid #4d82c0' : '3px solid #30363d' }}>
      
      <div className="flex items-start justify-between gap-4 mb-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h3 className="font-semibold text-sm" style={{ color: '#e6edf3' }}>{config.name}</h3>
            {config.is_recommended && (
              <span className="fl-badge" style={{ background: '#4d82c015', color: '#4d82c0', border: '1px solid #4d82c030' }}>
                <Star size={9} className="inline mr-1" />Recommandée
              </span>
            )}
            {config.mitre_tagged && (
              <span className="fl-badge" style={{ background: '#8b72d615', color: '#8b72d6', border: '1px solid #8b72d630' }}>
                <Tag size={9} className="inline mr-1" />ATT&CK
              </span>
            )}
            {config.risk_scored && (
              <span className="fl-badge" style={{ background: '#d97c2015', color: '#d97c20', border: '1px solid #d97c2030' }}>
                <Shield size={9} className="inline mr-1" />Risk-scoré
              </span>
            )}
          </div>
          <p className="text-xs" style={{ color: '#7d8590', lineHeight: 1.5, maxWidth: 600 }}>{config.description}</p>
        </div>
        <div className="flex gap-2 shrink-0">
          <button
            onClick={() => onMarkDeployed(config.id)}
            className="fl-btn fl-btn-ghost fl-btn-sm"
            title="Marquer comme déployée"
          >
            <CheckCircle size={13} /> Déployée
          </button>
          <button
            onClick={() => onDownload(config.id, config.filename)}
            disabled={!config.available || downloading === config.id}
            className="fl-btn fl-btn-primary fl-btn-sm"
          >
            {downloading === config.id
              ? <Loader2 size={13} className="animate-spin" />
              : <Download size={13} />}
            Télécharger
          </button>
        </div>
      </div>

      <div className="grid grid-cols-5 gap-3 mb-3 text-xs">
        <div>
          <div style={{ color: '#7d8590' }}>Schéma</div>
          <div className="font-mono font-semibold" style={{ color: '#e6edf3' }}>v{config.schema_version}</div>
        </div>
        <div>
          <div style={{ color: '#7d8590' }}>Stratégie</div>
          <div className="font-mono font-semibold" style={{ color: '#4d82c0' }}>{config.strategy}</div>
        </div>
        <div>
          <div style={{ color: '#7d8590' }}>Bruit</div>
          <div className="font-mono font-semibold" style={{ color: NOISE_COLOR[config.noise_level] }}>
            {NOISE_LABEL[config.noise_level]}
          </div>
        </div>
        <div>
          <div style={{ color: '#7d8590' }}>Hashes</div>
          <div className="font-mono" style={{ color: '#e6edf3', fontSize: 10 }}>{config.hash_algorithms}</div>
        </div>
        <div>
          <div style={{ color: '#7d8590' }}>Taille</div>
          <div className="font-mono font-semibold" style={{ color: '#e6edf3' }}>
            {config.file_size ? `${Math.round(config.file_size / 1024)} KB` : '—'}
          </div>
        </div>
      </div>

      <div className="text-xs mb-3 px-3 py-2 rounded" style={{ background: 'rgba(77,130,192,0.04)', border: '1px solid rgba(77,130,192,0.12)', color: '#7d8590' }}>
        <span style={{ color: '#4d82c0' }}>Audience cible :</span> {config.target_audience}
      </div>

      <div className="flex items-center justify-between">
        <button
          onClick={() => setShowTech(v => !v)}
          className="flex items-center gap-1 text-xs"
          style={{ color: '#7d8590' }}
        >
          {showTech ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          Event IDs couverts ({config.event_ids?.length || 0})
        </button>
        <div className="flex items-center gap-2 text-xs">
          {config.deployed_at ? (
            <span style={{ color: '#3fb950' }}>
              <CheckCircle size={11} className="inline mr-1" />
              Déployée le {new Date(config.deployed_at).toLocaleDateString('fr-FR')}
            </span>
          ) : (
            <span style={{ color: '#484f58' }}>
              <Clock size={11} className="inline mr-1" />Non déployée
            </span>
          )}
          <a
            href={config.source_url}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1"
            style={{ color: '#4d82c0' }}
          >
            <BookOpen size={11} /> Source
          </a>
        </div>
      </div>

      {showTech && (
        <div className="flex flex-wrap gap-1 mt-2">
          {(config.event_ids || []).map(eid => (
            <span key={eid} className="font-mono text-xs px-2 py-0.5 rounded" style={{ background: '#4d82c010', color: '#4d82c0', border: '1px solid #4d82c020' }}>
              EID {eid}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export default function SysmonConfigsPage() {
  const [configs, setConfigs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(null);
  const [showGuide, setShowGuide] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    sysmonAPI.list()
      .then(r => setConfigs(r.data))
      .catch(() => setError('Erreur de chargement'))
      .finally(() => setLoading(false));
  }, []);

  async function handleDownload(id, filename) {
    setDownloading(id);
    try {
      const res = await sysmonAPI.download(id);
      const url = URL.createObjectURL(new Blob([res.data], { type: 'application/xml' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setError('Erreur lors du téléchargement');
    } finally {
      setDownloading(null);
    }
  }

  async function handleMarkDeployed(id) {
    try {
      await sysmonAPI.markDeployed(id, null);
      const res = await sysmonAPI.list();
      setConfigs(res.data);
    } catch {
      setError('Erreur mise à jour');
    }
  }

  return (
    <div className="p-6">
      
      <div className="fl-header">
        <div>
          <h1 className="fl-header-title">Configurations Sysmon</h1>
          <p className="fl-header-sub">
            {configs.length} configurations open-source bundlées · Télécharger et déployer sur les endpoints
          </p>
        </div>
        <button
          onClick={() => setShowGuide(v => !v)}
          className="fl-btn fl-btn-secondary"
        >
          <BookOpen size={14} /> Guide de déploiement
        </button>
      </div>

      {error && (
        <div className="mb-4 p-3 rounded text-sm" style={{ background: '#da363314', color: '#da3633', border: '1px solid #da363330' }}>
          {error}
        </div>
      )}

      {showGuide && (
        <div className="mb-5 rounded-lg overflow-hidden" style={{ border: '1px solid #30363d' }}>
          <div className="px-4 py-3 flex items-center gap-2" style={{ background: '#161b22', borderBottom: '1px solid #30363d' }}>
            <BookOpen size={14} style={{ color: '#4d82c0' }} />
            <span className="text-sm font-semibold" style={{ color: '#e6edf3' }}>Guide de déploiement Sysmon</span>
          </div>
          <pre className="p-4 text-xs font-mono overflow-x-auto" style={{ background: '#0d1117', color: '#7d8590', lineHeight: 1.7, margin: 0 }}>
            {DEPLOY_GUIDE}
          </pre>
        </div>
      )}

      <div className="mb-5 p-3 rounded-lg flex items-start gap-3 text-xs" style={{ background: 'rgba(217,124,32,0.06)', border: '1px solid rgba(217,124,32,0.2)', color: '#d97c20' }}>
        <AlertTriangle size={14} className="shrink-0 mt-0.5" />
        <div>
          <strong>Ces configurations sont des outils de collecte, pas des règles de détection.</strong> Elles définissent ce que Sysmon va logger sur les endpoints. Plus la stratégie est "include", moins il y a de bruit — mais des angles morts sont possibles. Adapter selon l'environnement.
        </div>
      </div>

      {loading ? (
        <div className="fl-empty"><Loader2 size={28} className="animate-spin" style={{ color: '#4d82c0' }} /></div>
      ) : (
        <div className="space-y-4">
          {configs.map(c => (
            <ConfigCard
              key={c.id}
              config={c}
              onDownload={handleDownload}
              onMarkDeployed={handleMarkDeployed}
              downloading={downloading}
            />
          ))}
        </div>
      )}
    </div>
  );
}
