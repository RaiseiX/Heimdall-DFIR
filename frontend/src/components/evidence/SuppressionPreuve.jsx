import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Trash2, RotateCcw } from 'lucide-react';
import { evidenceAPI } from '../../utils/api';
import { Button, Modal, Spinner, Alert } from '../ui';
import { fmtOctets } from '../collection/octets';
import { octetsArchiveDe } from '../../pages/evidenceRow';
import { lignesSupprimees, lignesConservees, issueDeLEchec, empreinteCourte } from './suppressionVue';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

const S = {
  entete: { display: 'grid', gap: 3, marginBottom: 14 },
  nom: { fontFamily: MONO, fontSize: 12, fontWeight: 600, color: 'var(--fl-text)', wordBreak: 'break-all' },
  sous: { fontFamily: MONO, fontSize: 10, color: 'var(--fl-dim)' },
  section: { marginBottom: 12 },
  titre: (couleur) => ({ margin: '0 0 6px', fontFamily: MONO, fontSize: 10, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: couleur }),
  liste: { display: 'grid', gap: 0, margin: 0, borderTop: '1px solid var(--fl-border)' },
  ligne: { display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto', gap: 12, padding: '5px 0', borderBottom: '1px solid var(--fl-border)' },
  libelle: { margin: 0, fontSize: 11, color: 'var(--fl-text)' },
  valeur: { margin: 0, fontFamily: MONO, fontSize: 11, color: 'var(--fl-text)', textAlign: 'right', whiteSpace: 'nowrap' },
  detail: { gridColumn: '1 / -1', margin: 0, fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)' },
  avertissement: { margin: '12px 0 0', fontSize: 11, color: 'var(--fl-muted)' },
  irreversible: { color: 'var(--fl-danger)', fontWeight: 700 },
  enCours: { margin: '6px 0 0', fontFamily: MONO, fontSize: 10, color: 'var(--fl-dim)' },
  alerte: { marginBottom: 12 },
};

function Ligne({ libelle, valeur, detail, titre }) {
  return (
    <div style={S.ligne}>
      <dt style={S.libelle}>{libelle}</dt>
      <dd style={S.valeur} title={titre}>{valeur}</dd>
      {detail && <dd style={S.detail}>{detail}</dd>}
    </div>
  );
}

export default function SuppressionPreuve({ evidence, onClose, onDeleted }) {
  const { t, i18n } = useTranslation();
  const [apercu, setApercu] = useState(null);
  const [chargement, setChargement] = useState(true);
  const [apercuIndisponible, setApercuIndisponible] = useState(false);
  const [enCours, setEnCours] = useState(false);
  const [echec, setEchec] = useState(null);

  useEffect(() => {
    let actif = true;
    setChargement(true);
    setApercu(null);
    setApercuIndisponible(false);
    evidenceAPI.deletionPreview(evidence.id)
      .then((r) => { if (actif) setApercu(r.data); })
      .catch(() => { if (actif) setApercuIndisponible(true); })
      .finally(() => { if (actif) setChargement(false); });
    return () => { actif = false; };
  }, [evidence.id]);

  const k = (cle, options) => t(`casedetail.suppression.${cle}`, options);
  const nombre = (n) => {
    if (n === null || n === undefined) return k('inconnu');
    if (n === 0) return k('aucun');
    return Number(n).toLocaleString(i18n.language);
  };
  const date = (iso) => (iso ? new Date(iso).toLocaleString(i18n.language) : '—');

  const preuve = apercu?.preuve;
  const scelle = preuve?.scelle === true || echec?.type === 'scelle';
  const affaire = preuve?.affaire || '—';
  const collecte = octetsArchiveDe(evidence.metadata) !== null;

  const fermer = () => { if (!enCours) onClose(); };

  const supprimer = async () => {
    setEnCours(true);
    setEchec(null);
    try {
      await evidenceAPI.delete(evidence.id);
      onDeleted(evidence.id);
    } catch (e) {
      setEchec(issueDeLEchec(e));
      setEnCours(false);
    }
  };

  const valeurSupprimee = (l) => {
    if ('octets' in l) return l.octets === null ? k('inconnu') : fmtOctets(l.octets);
    if (l.cle === 'fiche') return empreinteCourte(l.empreinte) || '—';
    return nombre(l.nombre);
  };

  const detailSupprime = (l) => {
    if (l.cle === 'lignes' && l.detail) {
      return k('lignes_detail', { detections: nombre(l.detail.detections), etiquetees: nombre(l.detail.etiquetees) });
    }
    if (l.cle === 'resultats' && l.resultats.length) {
      return l.resultats.map((r) => (r.lignes === null ? r.nom : `${r.nom} (${Number(r.lignes).toLocaleString(i18n.language)})`)).join(' · ');
    }
    return null;
  };

  const valeurConservee = (l) => {
    if (l.cle === 'audit') return k('audit_valeur');
    if (l.cle === 'journal') return l.cibles === null ? k('inconnu') : k('journal_valeur', { count: l.cibles });
    if (l.cle === 'volweb') return k('volweb_valeur');
    return nombre(l.nombre);
  };

  const libelleBouton = enCours ? k('bouton_cours') : echec?.type === 'incomplet' ? k('bouton_reprendre') : k('bouton');

  return (
    <Modal open title={k('titre')} onClose={fermer} size="md" accentColor="var(--fl-danger)">
      <Modal.Body>
        <div style={S.entete}>
          <span style={S.nom}>{preuve?.nom || evidence.original_filename || evidence.name}</span>
          {preuve && <span style={S.sous}>{k('importee', { affaire, date: date(preuve.importee_le) })}</span>}
        </div>

        {scelle && (
          <Alert style={S.alerte} message={<><strong>{k('scelle_titre', { affaire })}</strong> {k('scelle_texte')}</>} />
        )}
        {echec?.type === 'incomplet' && (
          <Alert style={S.alerte} message={<>
            <strong>{k('echec_titre')}</strong> {k('echec_reprise')}
            {echec.cible && <> {k('echec_cible', { type: k(`type_${echec.cible.type}`, { defaultValue: echec.cible.type }), code: echec.cible.code || '?' })}</>}
          </>} />
        )}
        {echec?.type === 'erreur' && <Alert style={S.alerte} message={echec.message} />}
        {apercuIndisponible && <Alert variant="warn" style={S.alerte} message={k('apercu_indisponible')} />}

        {chargement && <Spinner text={k('calcul')} />}

        {apercu && (
          <>
            <section style={S.section} aria-label={k('supprime')}>
              <h3 style={S.titre('var(--fl-danger)')}>{k('supprime')}</h3>
              <dl style={S.liste}>
                {lignesSupprimees(apercu, { collecte }).map((l) => (
                  <Ligne key={l.cle} libelle={k(l.cle)} valeur={valeurSupprimee(l)} detail={detailSupprime(l)}
                    titre={l.cle === 'fiche' ? l.empreinte || undefined : undefined} />
                ))}
              </dl>
            </section>
            <section style={S.section} aria-label={k('conserve')}>
              <h3 style={S.titre('var(--fl-ok)')}>{k('conserve')}</h3>
              <dl style={S.liste}>
                {lignesConservees(apercu).map((l) => (
                  <Ligne key={l.cle} libelle={k(l.cle)} valeur={valeurConservee(l)} detail={l.detail ? k('favoris_detail') : null} />
                ))}
              </dl>
            </section>
          </>
        )}

        {!scelle && !chargement && (
          <p style={S.avertissement}><span style={S.irreversible}>{k('irreversible')}</span> {k('phrase')}</p>
        )}
        {enCours && <p style={S.enCours} role="status">{k('en_cours')}</p>}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" size="sm" onClick={fermer} disabled={enCours}>{t('common.cancel')}</Button>
        <Button variant="danger" size="sm" loading={enCours} disabled={scelle || chargement}
          icon={enCours ? undefined : echec?.type === 'incomplet' ? RotateCcw : Trash2} onClick={supprimer}>
          {libelleBouton}
        </Button>
      </Modal.Footer>
    </Modal>
  );
}
