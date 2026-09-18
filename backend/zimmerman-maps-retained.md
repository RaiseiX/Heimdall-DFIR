# Maps EvtxECmd conservees

Ces 73 maps ne sont plus distribuees par Eric Zimmerman. Elles decrivent des
sources d'evenements encore presentes sur les parcs analyses, et sans elles
EvtxECmd rend les EventData de ces sources sans noms.

## Pourquoi elles sont ici

Releve du 2026-09-18, en comparant le volume `zimmerman_tools` de production
(accumule depuis avril 2026) a l'archive amont du jour :

| | maps |
|---|---|
| production | 453 |
| `EvtxECmd.zip` amont | 383 |
| presentes en production, absentes de l'amont | **73** |
| presentes a l'amont, absentes de production | 3 |

Adopter les outils `2026.5.0` sans ce repertoire aurait fait tomber la
couverture de 453 a 383 : une regression de detection offerte par une montee de
version, et invisible puisque les evenements continuent d'apparaitre.

Une map absente ne supprime pas l'evenement. Elle lui retire ses champs nommes :
la ligne reste, sa substance part.

## Ce qu'elles couvrent

Entre autres :

- `Application_MSSQLSERVER_18456` — echec de connexion SQL Server, donc du
  brute-force contre une base de donnees
- `Splashtop-…_1100`, `1101`, `1110`, `1111` — sessions et **transferts de
  fichiers** via Splashtop Streamer, un outil d'acces distant : exfiltration par
  RMM (voir `backend/config/threat_rules/rmm.yaml`)
- `Application_ESENT_*` — erreurs de base ESE
- `Application_FSecure-*`, `Application_McAfee-Endpoint-Security_3` — antivirus
- `Application_MetaFrameEvents_1106` — Citrix

## Entretien

Apres `backend/scripts/relock-zimmerman.sh`, verifier qu'une map conservee n'est
pas revenue dans l'archive amont. Une map presente des deux cotes est ecrasee par
celle d'ici au `COPY` du Dockerfile, ce qui figerait une version ancienne :

    # depuis un conteneur portant la nouvelle image
    comm -12 <(ls backend/zimmerman-maps-retained | LC_ALL=C sort) \
             <(unzip -l EvtxECmd.zip | awk '/\.map$/{print $4}' | xargs -n1 basename | LC_ALL=C sort)

Toute ligne rendue par cette commande doit etre SUPPRIMEE de ce repertoire.
