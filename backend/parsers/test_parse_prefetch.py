#!/usr/bin/env python3
"""
Tests de la mise en forme des fichiers chargés d'un prefetch.

Pourquoi ce fichier existe : `parse_prefetch.py` jetait la liste des fichiers
qu'un exécutable charge au démarrage. Un prefetch ne dit pas seulement « ce
programme a tourné » — il dit CE QU'IL A OUVERT, et c'est ce qui distingue un
`rundll32` normal d'un `rundll32` qui charge une DLL depuis %TEMP%.

Mesuré le 2026-09-15 sur les 358 fichiers .pf du cas de référence : 33 437
chargements, 93 en moyenne, 916 pour un seul exécutable, 3,1 Mo au total.

Ne teste QUE la transformation pure, volontairement : lire un vrai .pf demande
`dissect`, absent de l'hôte, et un test qui dépend d'une preuve précise se
périme dès que la preuve bouge — c'est exactement ce qui a mis
`fixtureProbe.test.ts` au rouge en permanence.

Exécution :  python3 -m unittest discover -s backend/parsers -p 'test_*.py'
"""
import unittest

from parse_prefetch import files_loaded_fields

# Entrées réelles rendues par dissect sur MSEDGEWEBVIEW2.EXE-CFFB659A.pf.
REELLES = [
    r'\VOLUME{01dc68ee596edb1b-505992a4}\WINDOWS\SYSTEM32\NTDLL.DLL',
    r'\VOLUME{01dc68ee596edb1b-505992a4}\PROGRAM FILES (X86)\MICROSOFT\EDGEWEBVIEW\APPLICATION\146.0.3856.62\MSEDGEWEBVIEW2.EXE',
    r'\VOLUME{01dc68ee596edb1b-505992a4}\WINDOWS\SYSTEM32\C_1252.NLS',
]


class MiseEnFormeDesChargements(unittest.TestCase):

    def test_les_chemins_sont_tous_conserves(self):
        champs = files_loaded_fields(REELLES)
        for chemin in REELLES:
            self.assertIn(chemin, champs['FilesLoaded'])

    def test_le_compte_accompagne_la_liste(self):
        # Le compte seul permet de trier et de repérer un exécutable qui charge
        # anormalement peu ou anormalement beaucoup, sans lire 9 Ko de chemins.
        self.assertEqual(files_loaded_fields(REELLES)['FilesLoadedCount'], '3')

    def test_le_numero_de_serie_de_volume_est_extrait(self):
        # `pf.volumes` rend None sur les 358 fichiers du cas, mais le numéro est
        # présent dans chaque chemin : \VOLUME{<creation>-<serie>}\...
        # C'est lui qui rattache une exécution à un volume précis, une clé USB
        # par exemple.
        self.assertEqual(files_loaded_fields(REELLES)['VolumeSerialNumber'], '505992A4')

    def test_un_prefetch_sans_chargement_ne_casse_pas(self):
        champs = files_loaded_fields([])
        self.assertEqual(champs['FilesLoaded'], '')
        self.assertEqual(champs['FilesLoadedCount'], '0')
        self.assertEqual(champs['VolumeSerialNumber'], '')

    def test_une_entree_None_est_ignoree_sans_lever(self):
        champs = files_loaded_fields([None, r'\WINDOWS\X.DLL', ''])
        self.assertEqual(champs['FilesLoadedCount'], '1')

    # Deux volumes dans un même prefetch : un exécutable lancé depuis une clé
    # USB charge aussi des DLL système. Ne pas en inventer un seul.
    def test_plusieurs_volumes_sont_tous_rendus(self):
        champs = files_loaded_fields([
            r'\VOLUME{01dc68ee596edb1b-505992a4}\WINDOWS\SYSTEM32\NTDLL.DLL',
            r'\VOLUME{01d9aaaaaaaaaaaa-deadbeef}\TOOLS\MIMIKATZ.EXE',
        ])
        self.assertEqual(champs['VolumeSerialNumber'], '505992A4, DEADBEEF')

    # Contrôle négatif : un chemin sans bloc VOLUME ne doit pas fabriquer
    # un numéro de série à partir de rien.
    def test_un_chemin_sans_volume_ne_fabrique_pas_de_numero(self):
        champs = files_loaded_fields([r'\WINDOWS\SYSTEM32\NTDLL.DLL'])
        self.assertEqual(champs['VolumeSerialNumber'], '')
        self.assertEqual(champs['FilesLoadedCount'], '1')

    # Le séparateur doit survivre au CSV : les chemins Windows ne contiennent
    # pas de virgule, mais le champ est quand même cité par csv.DictWriter.
    def test_les_chemins_sont_separes_lisiblement(self):
        self.assertEqual(
            files_loaded_fields([r'\A\B.DLL', r'\C\D.DLL'])['FilesLoaded'],
            r'\A\B.DLL, \C\D.DLL')


if __name__ == '__main__':
    unittest.main()
