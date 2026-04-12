import { useState } from 'react';
import { useTheme } from '../utils/theme';

const STEPS = [
  { icon: '📊', title: 'Dashboard', desc: 'Vue d\'ensemble de votre activité : cas actifs, IOCs détectés, statistiques et raccourcis vers les actions principales.' },
  { icon: '📁', title: 'Gestion des Cas', desc: 'Créez et gérez vos cas forensiques. Chaque cas regroupe preuves, timeline, IOCs et rapports. Cliquez sur un cas pour y accéder.' },
  { icon: '📦', title: 'Import Collecte', desc: 'Glissez-déposez votre archive Magnet RESPONSE, KAPE, Velociraptor ou CyLR. Les artéfacts sont détectés puis parsés automatiquement avec les outils Eric Zimmerman.' },
  { icon: '⏱️', title: 'Super Timeline', desc: 'Timeline unifiée de tous les artéfacts. Colonnes dynamiques par type (EVTX, Prefetch, MFT, LNK, Registry, Amcache). Filtrez, recherchez, surlignez et ajoutez des notes d\'investigation.' },
  { icon: '🦅', title: 'Hayabusa', desc: 'Module dédié au parser EVTX du CERT Japonais. Détections basées sur les règles Sigma avec niveaux de sévérité (critical, high, medium, low). Génère sa propre Super Timeline.' },
  { icon: '🎯', title: 'IOCs & Threat Hunting', desc: 'Les IOCs sont auto-extraits de la Super Timeline et enrichis manuellement. Recherchez un hash, une IP ou un domaine dans tous les cas simultanément.' },
  { icon: '🗺️', title: 'Intelligence du Cas', desc: 'Hub visuel avec 3 vues : Topologie Réseau (D3 force graph), Kill Chain MITRE ATT&CK (colonnes tactiques colorées) et Propagation Latérale (authentifications Windows 4624/4648). Accessible via l\'onglet "Réseau & Kill Chain" de chaque cas.' },
  { icon: '⚙️', title: 'Administration', desc: 'Créez des comptes sans email, gérez les rôles et statuts. Consultez le journal d\'audit. Module RGPD pour l\'effacement définitif et irréversible des données.' },
];

export default function GuidedTour({ onClose }) {
  const T = useTheme();
  const [step, setStep] = useState(0);
  const s = STEPS[step];
  const pct = ((step + 1) / STEPS.length) * 100;

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9999,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'rgba(0,0,0,0.65)', backdropFilter: 'blur(6px)',
    }}>
      <div style={{
        width: 460, background: T.panel, border: `1px solid ${T.border}`,
        borderRadius: 16, overflow: 'hidden', boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
      }}>
        <div style={{ height: 4, background: T.border }}>
          <div style={{
            height: '100%', width: `${pct}%`,
            background: `linear-gradient(90deg, ${T.accent}, ${T.purple})`,
            transition: 'width 0.3s ease',
          }} />
        </div>

        <div style={{ padding: 28 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
            <div style={{
              width: 48, height: 48, borderRadius: 12,
              background: `${T.accent}15`, display: 'flex',
              alignItems: 'center', justifyContent: 'center', fontSize: 24,
            }}>
              {s.icon}
            </div>
            <div>
              <div style={{ fontSize: 11, fontFamily: 'monospace', color: T.dim }}>
                ÉTAPE {step + 1} / {STEPS.length}
              </div>
              <div style={{ fontSize: 18, fontWeight: 700, color: T.text }}>{s.title}</div>
            </div>
          </div>

          <p style={{ fontSize: 13, lineHeight: 1.7, color: T.dim, marginBottom: 24 }}>
            {s.desc}
          </p>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <button
              onClick={onClose}
              style={{
                fontSize: 11, color: T.dim, background: 'none',
                border: 'none', cursor: 'pointer', fontFamily: 'inherit',
              }}
            >
              Passer le tutoriel
            </button>
            <div style={{ display: 'flex', gap: 8 }}>
              {step > 0 && (
                <button
                  onClick={() => setStep(step - 1)}
                  className="px-4 py-2 rounded-lg text-xs font-semibold"
                  style={{ border: `1px solid ${T.border}`, color: T.dim, background: 'transparent', cursor: 'pointer' }}
                >
                  ← Précédent
                </button>
              )}
              {step < STEPS.length - 1 ? (
                <button
                  onClick={() => setStep(step + 1)}
                  className="px-4 py-2 rounded-lg text-xs font-semibold"
                  style={{ background: T.accent, color: T.bg, border: 'none', cursor: 'pointer', borderRadius: 8, padding: '8px 16px' }}
                >
                  Suivant →
                </button>
              ) : (
                <button
                  onClick={onClose}
                  className="px-4 py-2 rounded-lg text-xs font-semibold"
                  style={{ background: T.ok, color: '#fff', border: 'none', cursor: 'pointer', borderRadius: 8, padding: '8px 16px' }}
                >
                  ✓ Terminé !
                </button>
              )}
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'center', gap: 6, marginTop: 16 }}>
            {STEPS.map((_, i) => (
              <div
                key={i}
                onClick={() => setStep(i)}
                style={{
                  width: i === step ? 20 : 6, height: 6, borderRadius: 3,
                  background: i === step ? T.accent : T.border,
                  cursor: 'pointer', transition: 'all 0.2s',
                }}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
