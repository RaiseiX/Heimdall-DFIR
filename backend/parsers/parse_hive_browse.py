#!/usr/bin/env python3
import argparse
import json
import sys

TYPES = {
    0: 'REG_NONE', 1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY', 4: 'REG_DWORD',
    5: 'REG_DWORD_BIG_ENDIAN', 6: 'REG_LINK', 7: 'REG_MULTI_SZ', 8: 'REG_RESOURCE_LIST',
    9: 'REG_FULL_RESOURCE_DESCRIPTOR', 10: 'REG_RESOURCE_REQUIREMENTS_LIST', 11: 'REG_QWORD',
}
TYPES_TEXTE = {1, 2, 4, 5, 7, 11}
TYPES_CHAINE = {1, 2, 7}
DONNEES_MAX = 8192
EXTRAIT_MAX = 160
PROFONDEUR_MAX = 64


def nom_type(code):
    return TYPES.get(code, f'0x{code:x}' if isinstance(code, int) else str(code))


def horodatage(noeud):
    try:
        ts = noeud.timestamp
        return ts.isoformat() if ts else ''
    except Exception:
        return ''


def texte_de(valeur):
    brut = valeur.value
    if isinstance(brut, (list, tuple)):
        return '\n'.join(str(x) for x in brut)
    return str(brut)


def formater_valeur(valeur):
    nom = getattr(valeur, 'name', '') or '(Default)'
    try:
        code = int(getattr(valeur, 'type', 0) or 0)
    except Exception:
        code = -1
    if code in TYPES_TEXTE:
        try:
            texte = texte_de(valeur)
            return {'name': nom, 'type': nom_type(code), 'data': texte[:DONNEES_MAX], 'truncated': len(texte) > DONNEES_MAX}
        except Exception:
            pass
    try:
        brut = valeur.data
        brut = bytes(brut) if not isinstance(brut, (bytes, bytearray)) else bytes(brut)
    except Exception as exc:
        return {'name': nom, 'type': nom_type(code), 'data': '', 'binary': True, 'truncated': False, 'error': str(exc)[:200]}
    return {
        'name': nom,
        'type': nom_type(code),
        'data': brut[:DONNEES_MAX].hex(),
        'binary': True,
        'size': len(brut),
        'truncated': len(brut) > DONNEES_MAX,
    }


def chemin_de(noeud, parent=''):
    chemin = getattr(noeud, 'path', None)
    if chemin:
        return chemin
    nom = getattr(noeud, 'name', '') or ''
    return f'{parent}\\{nom}' if parent else nom


def lister(ruche, chemin, limite):
    erreurs = []
    chemin = (chemin or '').strip('\\')
    noeud = ruche.open(chemin) if chemin else ruche.root()

    valeurs = []
    total_valeurs = 0
    try:
        for v in noeud.values():
            total_valeurs += 1
            if len(valeurs) < limite:
                valeurs.append(formater_valeur(v))
    except Exception as exc:
        erreurs.append({'path': chemin, 'what': 'values', 'error': str(exc)[:200]})

    brutes = []
    try:
        brutes = list(noeud.subkeys())
    except Exception as exc:
        erreurs.append({'path': chemin, 'what': 'subkeys', 'error': str(exc)[:200]})
    brutes.sort(key=lambda s: (getattr(s, 'name', '') or '').lower())

    sous_cles = []
    for sk in brutes[:limite]:
        entree = {'name': sk.name, 'path': chemin_de(sk, chemin), 'lastWrite': horodatage(sk), 'valueCount': None, 'subkeyCount': None}
        try:
            entree['valueCount'] = sum(1 for _ in sk.values())
            entree['subkeyCount'] = sum(1 for _ in sk.subkeys())
        except Exception as exc:
            erreurs.append({'path': entree['path'], 'what': 'counts', 'error': str(exc)[:200]})
        sous_cles.append(entree)

    return {
        'path': chemin,
        'name': chemin.split('\\')[-1] if chemin else '',
        'lastWrite': horodatage(noeud),
        'values': valeurs,
        'valuesTotal': total_valeurs,
        'valuesTruncated': total_valeurs > limite,
        'subkeys': sous_cles,
        'subkeysTotal': len(brutes),
        'subkeysTruncated': len(brutes) > limite,
        'errors': erreurs,
    }


def rechercher(ruche, terme, limite, parcours_max):
    aiguille = terme.lower()
    resultats = []
    erreurs = []
    etat = {'visites': 0, 'arret': None}

    def plein():
        if len(resultats) >= limite:
            etat['arret'] = 'results'
        elif etat['visites'] >= parcours_max:
            etat['arret'] = 'walk'
        return etat['arret'] is not None

    def visiter(noeud, chemin, profondeur):
        if plein():
            return
        if profondeur > PROFONDEUR_MAX:
            erreurs.append({'path': chemin, 'what': 'depth', 'error': 'profondeur maximale atteinte'})
            return
        etat['visites'] += 1
        try:
            for v in noeud.values():
                if plein():
                    return
                nom = getattr(v, 'name', '') or ''
                extrait = ''
                trouve = aiguille in nom.lower()
                if not trouve:
                    try:
                        if int(getattr(v, 'type', 0) or 0) in TYPES_CHAINE:
                            texte = texte_de(v)
                            position = texte.lower().find(aiguille)
                            if position >= 0:
                                trouve = True
                                debut = max(0, position - 40)
                                extrait = texte[debut:debut + EXTRAIT_MAX]
                    except Exception:
                        pass
                if trouve:
                    resultats.append({'kind': 'value', 'name': nom or '(Default)', 'path': chemin, 'snippet': extrait})
        except Exception as exc:
            erreurs.append({'path': chemin, 'what': 'values', 'error': str(exc)[:200]})
        try:
            sous_cles = list(noeud.subkeys())
        except Exception as exc:
            erreurs.append({'path': chemin, 'what': 'subkeys', 'error': str(exc)[:200]})
            return
        for sk in sous_cles:
            if plein():
                return
            chemin_sk = chemin_de(sk, chemin)
            if aiguille in (getattr(sk, 'name', '') or '').lower():
                resultats.append({'kind': 'key', 'name': sk.name, 'path': chemin_sk, 'lastWrite': horodatage(sk)})
            visiter(sk, chemin_sk, profondeur + 1)

    visiter(ruche.root(), '', 0)
    return {
        'search': terme,
        'matches': resultats,
        'visited': etat['visites'],
        'truncated': etat['arret'] is not None,
        'stoppedBy': etat['arret'],
        'errors': erreurs,
    }


def ouvrir(chemin_fichier):
    from dissect.regf import regf
    return regf.RegistryHive(open(chemin_fichier, 'rb'))


def main(argv=None, ouvrir_ruche=ouvrir, sortie=sys.stdout):
    ap = argparse.ArgumentParser()
    ap.add_argument('-f', '--file', required=True)
    ap.add_argument('-p', '--path', default='')
    ap.add_argument('-s', '--search', default='')
    ap.add_argument('--limit', type=int, default=500)
    ap.add_argument('--max-walk', type=int, default=100000)
    args = ap.parse_args(argv)
    limite = max(1, min(args.limit, 5000))

    try:
        ruche = ouvrir_ruche(args.file)
    except ImportError as exc:
        sortie.write(json.dumps({'error': f'dissect.regf indisponible : {exc}', 'code': 'DEPENDANCE'}) + '\n')
        return 2
    except Exception as exc:
        sortie.write(json.dumps({'error': f'Ruche illisible : {type(exc).__name__} {exc}'.strip(), 'code': 'RUCHE_ILLISIBLE'}, ensure_ascii=False) + '\n')
        return 1

    if args.search:
        terme = args.search.strip()
        if len(terme) < 2:
            sortie.write(json.dumps({'error': 'Terme trop court', 'code': 'TERME_INVALIDE'}) + '\n')
            return 1
        sortie.write(json.dumps(rechercher(ruche, terme[:200], limite, max(1, args.max_walk)), ensure_ascii=False) + '\n')
        return 0

    try:
        resultat = lister(ruche, args.path, limite)
    except Exception as exc:
        sortie.write(json.dumps({'error': f'Clé introuvable : {args.path} ({exc})', 'code': 'CLE_INTROUVABLE'}, ensure_ascii=False) + '\n')
        return 1
    sortie.write(json.dumps(resultat, ensure_ascii=False) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
