import { useState, useRef, useMemo, useCallback, useEffect, useLayoutEffect, Fragment } from 'react';
import { NavLink } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ExternalLink, ChevronDown } from 'lucide-react';
import { collectionTabs, EXTERNAL_TABS, repartirOnglets } from './collectionTabs';
import { controlStyle, controlHover, separatorStyle, FS_CONTROL } from '../components/ui/controlIdiom';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

const BAR_STYLE = {
  position: 'sticky', top: 36, zIndex: 101,
  display: 'flex', alignItems: 'center',
  height: 36, padding: '0 12px', gap: 18,
  background: 'var(--fl-bg)',
  borderBottom: '1px solid var(--fl-border)',
  flexShrink: 0,
};
const EXT_ICON_STYLE = { opacity: 0.55, alignSelf: 'center' };
const LAYER_STYLE = {
  position: 'absolute', top: 0, left: 0, width: 0, height: 0,
  overflow: 'hidden', visibility: 'hidden', pointerEvents: 'none', display: 'flex',
};
const PLUS_WRAP_STYLE = { position: 'relative', alignSelf: 'center', flexShrink: 0 };
const MENU_STYLE = {
  position: 'absolute', top: '100%', right: 0, marginTop: 4, zIndex: 102,
  display: 'flex', flexDirection: 'column', padding: '4px 0', minWidth: 140,
  background: 'var(--fl-card)', border: '1px solid var(--fl-border)',
  borderRadius: 4, boxShadow: 'var(--fl-shadow-md)',
};
const ITEM_STYLE = {
  display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px',
  fontFamily: MONO, fontSize: FS_CONTROL, color: 'var(--fl-muted)',
  textDecoration: 'none', whiteSpace: 'nowrap', cursor: 'pointer',
  background: 'transparent',
};

const ONGLETS = collectionTabs();

const egales = (a, b) => {
  if (!a || !b) return false;
  if (a.disponible !== b.disponible || a.plus !== b.plus || a.separateur !== b.separateur) return false;
  return ONGLETS.every(o => a.onglets[o.id] === b.onglets[o.id]);
};

export default function CollectionTabsBar({ base, volwebUrl, actifId }) {
  const { t } = useTranslation();
  const barreRef = useRef(null);
  const coucheRef = useRef(null);
  const boutonRef = useRef(null);
  const menuRef = useRef(null);
  const [mesures, setMesures] = useState(null);
  const [ouvert, setOuvert] = useState(false);

  const mesurer = useCallback(() => {
    const barre = barreRef.current;
    const couche = coucheRef.current;
    if (!barre || !couche) return;
    const style = getComputedStyle(barre);
    const ecart = parseFloat(style.columnGap) || 0;
    const marges = (parseFloat(style.paddingLeft) || 0) + (parseFloat(style.paddingRight) || 0);
    const largeur = (sel) => couche.querySelector(sel)?.getBoundingClientRect().width || 0;
    const onglets = {};
    couche.querySelectorAll('[data-onglet]').forEach(el => {
      onglets[el.dataset.onglet] = el.getBoundingClientRect().width + ecart;
    });
    const suivant = {
      disponible: barre.clientWidth - marges + ecart,
      plus: largeur('[data-plus]') + ecart,
      separateur: largeur('[data-separateur]') + ecart,
      onglets,
    };
    setMesures(prev => (egales(prev, suivant) ? prev : suivant));
  }, []);

  useLayoutEffect(() => {
    mesurer();
    if (typeof ResizeObserver === 'undefined') return undefined;
    const observateur = new ResizeObserver(mesurer);
    observateur.observe(barreRef.current);
    coucheRef.current.querySelectorAll('[data-onglet], [data-plus]').forEach(el => observateur.observe(el));
    return () => observateur.disconnect();
  }, [mesurer]);

  const { visibles, plus } = useMemo(() => {
    if (!mesures) return { visibles: ONGLETS, plus: [] };
    const largeurDe = (o) => mesures.onglets[o.id] || 0;
    return repartirOnglets(ONGLETS, mesures.disponible, largeurDe, {
      actifId, largeurPlus: mesures.plus, largeurSeparateur: mesures.separateur,
    });
  }, [mesures, actifId]);

  const fermer = useCallback((rendreFocus) => {
    setOuvert(false);
    if (rendreFocus) boutonRef.current?.focus();
  }, []);

  const elements = () => Array.from(menuRef.current?.querySelectorAll('[role="menuitem"]') || []);

  const focaliser = (position) => {
    const liste = elements();
    if (!liste.length) return;
    liste[(position + liste.length) % liste.length].focus();
  };

  useEffect(() => {
    if (!ouvert) return undefined;
    const dehors = (e) => {
      if (menuRef.current?.contains(e.target) || boutonRef.current?.contains(e.target)) return;
      setOuvert(false);
    };
    document.addEventListener('mousedown', dehors);
    return () => document.removeEventListener('mousedown', dehors);
  }, [ouvert]);

  useEffect(() => {
    if (ouvert && plus.length === 0) setOuvert(false);
  }, [ouvert, plus.length]);

  const surBouton = (e) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const cible = e.key === 'ArrowDown' ? 0 : -1;
      if (ouvert) { focaliser(cible); return; }
      setOuvert(true);
      requestAnimationFrame(() => focaliser(cible));
    } else if (e.key === 'Escape' && ouvert) {
      e.preventDefault();
      fermer(true);
    }
  };

  const surMenu = (e) => {
    const liste = elements();
    const courant = liste.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') { e.preventDefault(); focaliser(courant + 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); focaliser(courant - 1); }
    else if (e.key === 'Home') { e.preventDefault(); focaliser(0); }
    else if (e.key === 'End') { e.preventDefault(); focaliser(-1); }
    else if (e.key === 'Escape') { e.preventDefault(); fermer(true); }
    else if (e.key === 'Tab') { fermer(true); }
  };

  const basculer = (e) => {
    if (ouvert) { fermer(false); return; }
    setOuvert(true);
    if (e.detail === 0) requestAnimationFrame(() => focaliser(0));
  };

  const rendreOnglet = ({ id: tid, label }) => (
    EXTERNAL_TABS.has(tid) ? (
      <a key={tid} href={volwebUrl} target="_blank" rel="noopener noreferrer"
        title={t('collection.tabs.volweb_hint')}
        style={controlStyle(false)} {...controlHover(false)}>
        {label}
        <ExternalLink size={8} style={EXT_ICON_STYLE} />
      </a>
    ) : (
      <NavLink key={tid} to={`${base}/${tid}`}
        style={({ isActive }) => controlStyle(isActive)}
        {...controlHover(false)}>
        {label}
      </NavLink>
    )
  );

  const rendreEntree = ({ id: tid, label }) => (
    EXTERNAL_TABS.has(tid) ? (
      <a key={tid} role="menuitem" tabIndex={-1} href={volwebUrl} target="_blank" rel="noopener noreferrer"
        title={t('collection.tabs.volweb_hint')}
        onClick={() => fermer(false)}
        style={ITEM_STYLE}>
        {label}
        <ExternalLink size={8} style={EXT_ICON_STYLE} />
      </a>
    ) : (
      <NavLink key={tid} role="menuitem" tabIndex={-1} to={`${base}/${tid}`}
        onClick={() => fermer(false)}
        style={ITEM_STYLE}>
        {label}
      </NavLink>
    )
  );

  return (
    <div ref={barreRef} style={BAR_STYLE}>
      <div ref={coucheRef} aria-hidden="true" style={LAYER_STYLE}>
        {ONGLETS.map(({ id: tid, label }) => (
          <span key={tid} data-onglet={tid} style={controlStyle(true)}>
            {label}
            {EXTERNAL_TABS.has(tid) && <ExternalLink size={8} style={EXT_ICON_STYLE} />}
          </span>
        ))}
        <span data-separateur style={separatorStyle} />
        <span data-plus style={controlStyle(true)}>
          {t('collection.tabs.more')}
          <ChevronDown size={8} />
        </span>
      </div>

      {visibles.map((onglet, i) => (
        <Fragment key={onglet.id}>
          {i > 0 && visibles[i - 1].groupe !== onglet.groupe && <span style={separatorStyle} />}
          {rendreOnglet(onglet)}
        </Fragment>
      ))}

      {plus.length > 0 && (
        <span style={PLUS_WRAP_STYLE}>
          <button ref={boutonRef} type="button"
            aria-haspopup="menu" aria-expanded={ouvert} aria-controls="collection-tabs-plus"
            onClick={basculer} onKeyDown={surBouton}
            style={{ ...controlStyle(ouvert), outline: undefined }}
            {...controlHover(ouvert)}>
            {t('collection.tabs.more')}
            <ChevronDown size={8} style={EXT_ICON_STYLE} />
          </button>
          {ouvert && (
            <div ref={menuRef} id="collection-tabs-plus" role="menu"
              aria-label={t('collection.tabs.more')}
              onKeyDown={surMenu} style={MENU_STYLE}>
              {plus.map(rendreEntree)}
            </div>
          )}
        </span>
      )}
    </div>
  );
}
