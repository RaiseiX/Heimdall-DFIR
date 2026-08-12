# Guide utilisateur de Heimdall DFIR

[English](TUTORIAL.md) · [README](README.fr.md) · [Roadmap](ROADMAP.fr.md) · [Sécurité](SECURITY.md)

Ce guide suit l'interface actuellement disponible sur la branche `main`. Heimdall est encore en développement actif : utilisez des preuves synthétiques ou jetables pour découvrir le workflow.

L'application est conçue pour un navigateur de bureau. Certains libellés restent en anglais lorsque l'interface française est sélectionnée, et la documentation forensique intégrée n'est pas encore entièrement traduite en anglais.

## 1. Avant de commencer

Les prérequis d'installation et les avertissements de déploiement se trouvent dans le [README](README.fr.md). Une installation locale démarre ainsi :

```bash
git clone https://github.com/RaiseiX/Heimdall-DFIR.git
cd Heimdall-DFIR
bash start.sh
```

Sous Windows, exécutez plutôt `start.ps1` depuis PowerShell. Ouvrez `https://localhost` lorsque la stack est prête. Le certificat local est auto-signé ; le navigateur affiche donc normalement un avertissement lors de la première visite.

Les utilisateurs initiaux sont `admin` et `analyst`. Leurs mots de passe proviennent de `ADMIN_DEFAULT_PASSWORD` et `ANALYST_DEFAULT_PASSWORD` dans `.env`. Changez-les dans Heimdall après la première connexion. Modifier ces variables après la création des utilisateurs dans PostgreSQL ne met pas à jour les mots de passe existants.

Avant d'importer des preuves :

- vérifiez avec `docker compose ps` que les services nécessaires sont sains ;
- conservez l'installation sur un réseau de confiance ;
- commencez avec une petite collecte sans données réelles de client ou de salarié ;
- choisissez l'affichage UTC ou l'heure locale du navigateur dans **Paramètres → Profil**.

![Page de connexion de Heimdall](shots/login.webp)

## 2. Se repérer dans l'interface

Le contenu de la barre latérale varie légèrement selon le rôle de l'utilisateur connecté.

| Section | Usage |
| --- | --- |
| Dashboard | Activité des dossiers, échéances, triage et état des services |
| Triage | File des alertes et éléments en attente de revue |
| Cas | Créer, filtrer et ouvrir les investigations |
| IOCs | Gestion globale des indicateurs ; visible pour les administrateurs |
| Agent Collecte | Préparer des commandes ou paquets de collecte pour les endpoints |
| Documentation | Référentiel DFIR intégré |
| Calendrier | Échéances et dates d'investigation |
| Paramètres | Profil, sessions, intégrations et politiques de la plateforme |
| Opérations | Conteneurs, travaux, sauvegardes et santé ; administrateurs uniquement |

Dans **Paramètres → Profil**, vous pouvez choisir le français ou l'anglais, UTC ou l'heure locale, la densité des tableaux et votre couleur dans le chat. Les horodatages forensiques bruts restent stockés en UTC, quel que soit l'affichage choisi.

`Ctrl+K` ou `Cmd+K` ouvre la palette de commandes globale. Dans la Super Timeline, le même raccourci place le curseur dans la recherche.

![Dashboard de Heimdall](shots/dashboard.webp)

## 3. Créer un dossier

Ouvrez **Cas**, puis choisissez **Nouveau cas**. Renseignez :

- un titre qui identifie l'investigation ;
- une courte description ;
- une priorité ;
- une échéance de rapport facultative.

Heimdall attribue le numéro du dossier et le crée avec un statut actif. Ouvrez la nouvelle ligne pour rejoindre l'espace du dossier. L'en-tête indique son numéro, son titre, sa priorité, son statut, les personnes assignées et l'échéance. Les administrateurs et responsables d'équipe peuvent gérer les assignations.

Les onglets au niveau du dossier sont volontairement peu nombreux :

| Onglet | Usage |
| --- | --- |
| Preuves | Importer des collectes, téléverser de la mémoire et consulter l'inventaire |
| Réseau Global | Examiner les relations entre les collectes du dossier |
| Investigation | Suivre les phases ou tâches Kanban, les constats, les questions DFIQ et la kill chain |
| Notebook | Conserver les notes longues du dossier à part des événements de timeline |

Le menu **Actions** contient aussi des opérations administratives comme le legal hold, l'export du manifeste et la suppression du dossier. Ce sont des contrôles applicatifs, pas un remplacement de la procédure de traitement des preuves de votre organisation. L'état du legal hold est enregistré et audité, mais il ne bloque pas encore tous les chemins de suppression du backend ; il doit donc aussi être appliqué par une procédure administrateur.

## 4. Importer une collecte forensique

Depuis l'onglet **Preuves**, choisissez **Import Collecte**. Le panneau reconnaît les arborescences Windows courantes produites par KAPE, Magnet RESPONSE, Velociraptor et CyLR, ainsi que les collectes Linux issues de CatScale. Il peut aussi reconnaître les contenus CSV et PCAP pris en charge dans une collecte.

Le parcours normal est le suivant :

1. Déposez une archive, un répertoire ou un ensemble de fichiers dans le panneau d'import.
2. Attendez la fin du téléversement et de l'inspection de l'arborescence.
3. Vérifiez les familles d'artefacts détectées. Pour une collecte Windows, ne gardez que les parseurs utiles aux preuves présentes. CatScale utilise son pipeline Linux.
4. Lancez le pipeline et laissez la page ouverte jusqu'à l'apparition des premiers statuts.
5. Lisez le résultat de chaque parseur plutôt que de vous fier uniquement au nombre total d'enregistrements.

Les statuts de parsing ont des sens distincts :

| Statut | Signification |
| --- | --- |
| En attente | Attend un worker |
| Parsing | Le parseur est en cours d'exécution |
| Terminé | Des enregistrements ont été produits ou l'étape s'est terminée normalement |
| Ignoré | Le fichier ne relevait pas de ce parseur, était un doublon ou n'avait pas de correspondance exploitable |
| Erreur | Le parseur a échoué ; consultez les logs avant de relancer |

Un fichier ignoré n'est pas un parsing réussi, et un résultat vide ne prouve pas que la source ne contenait aucune activité. L'onglet **Logs** indique les décisions par fichier, la sortie des parseurs et les causes d'échec. Le journal peut être exporté pour le dépannage.

Une fois l'import terminé, la collecte apparaît sous forme de carte dans **Preuves**. Sélectionnez-la pour ouvrir son espace. Un nouveau parsing remplace les résultats dérivés de cette collecte : relisez l'avertissement avant de confirmer.

## 5. Travailler dans une collecte

Chaque collecte possède sa propre barre de navigation.

| Vue | Contenu |
| --- | --- |
| Preuves | Résumé, nombre d'enregistrements et répartition des artefacts |
| IOCs | Indicateurs associés au périmètre courant |
| Détections | Résultats des détections et événements associés |
| Réseau | Connexions, topologie et mouvements latéraux |
| MITRE | Techniques ATT&CK mappées depuis les enregistrements disponibles |
| Audit | Actions enregistrées pour le périmètre d'investigation |
| Super Timeline | Timeline recherchable des événements et artefacts |
| Logs | Décisions d'import et sorties des parseurs |
| Hayabusa | Revue orientée Sigma des journaux d'événements Windows |
| CyberChef | Outils locaux de décodage et de transformation |
| Threat Hunting | Actions YARA, Sigma et combinées sur la collecte |
| VolWeb | Ouvre l'interface VolWeb séparée pour l'analyse mémoire |

Les compteurs et détections dépendent toujours des données importées, des parseurs terminés et de la collecte sélectionnée. Vérifiez son nom dans la barre supérieure avant de tirer une conclusion.

## 6. Examiner la Super Timeline

Ouvrez une collecte puis choisissez **Super Timeline**. L'écran contient une recherche, des filtres d'artefacts, la grille d'événements, un panneau de détail et un panneau de contexte facultatif.

![Super Timeline de Heimdall](shots/timeline.webp)

### Recherche et filtres

Le texte libre porte sur la description principale, la source et le type d'artefact. Des préfixes permettent de cibler un champ :

| Exemple | Résultat |
| --- | --- |
| `host:DC01` | Événements associés à un hôte |
| `user:Administrator` | Événements associés à un compte |
| `type:evtx` | Une famille d'artefacts |
| `tool:Hayabusa` | Enregistrements produits par un outil |
| `eid:4624` | Un Event ID Windows |
| `ext:ps1` | Une extension de fichier |
| `tag:T1059` | Un tag ou une technique |
| `sev:critical` | Une sévérité de détection |
| `after:2026-01-01` | Événements postérieurs à une date |
| `before:2026-02-01` | Événements antérieurs à une date |

Appuyez sur `Entrée` pour appliquer la recherche. Le menu **Filters** ajoute des filtres par champ, le mode réservé aux détections, la sévérité et la déduplication. Les pastilles d'artefacts peuvent se combiner ; `Ctrl`-clic ou `Cmd`-clic isole un type. Une recherche peut être enregistrée pour vous-même ou partagée avec le dossier.

### Lire un événement

Sélectionnez une ligne pour ouvrir le panneau de détail. Ses onglets présentent les champs normalisés, les correspondances MITRE, les tags forensiques, les notes analyste, les données brutes du parseur, le schéma et, s'il est configuré, l'assistant local.

L'action de contexte charge les événements voisins de l'horodatage sélectionné. Le contexte du même hôte est souvent le plus utile ; l'élargissement à tous les hôtes peut introduire une activité sans rapport dans un dossier chargé.

Un clic droit sur une cellule propose les filtres contient, égal et exclusion. Les en-têtes de colonnes peuvent être glissés dans la zone de regroupement. La vue **Diff** compare deux timelines de collecte ; confirmez les deux périmètres avant d'interpréter le résultat.

Les exports de timeline reprennent les filtres actifs. Notez ces filtres ou enregistrez la recherche lorsque l'export doit soutenir un constat.

Raccourcis utiles dans la timeline :

| Touche | Action |
| --- | --- |
| `/` ou `Ctrl/Cmd+K` | Placer le curseur dans la recherche |
| `Haut` / `Bas` | Passer d'une ligne à l'autre après une sélection |
| `Échap` | Fermer la ligne sélectionnée ou annuler la saisie |
| `Ctrl/Cmd+C` | Copier la ligne sélectionnée au format CSV |
| `Ctrl+Entrée` | Envoyer une note d'événement pendant sa saisie |

## 7. Détections et threat hunting

Les détections sont des pistes. Confirmez-les avec l'enregistrement d'origine, les événements voisins et l'état du parsing avant d'en faire un constat.

Les vues de la collecte répondent à des questions différentes :

- **Détections** rassemble les résultats des règles et les enregistrements associés ;
- **Hayabusa** se concentre sur les résultats Sigma issus des journaux Windows ;
- **Threat Hunting** lance ou affiche les chasses YARA, Sigma et combinées disponibles ;
- **MITRE** regroupe les techniques mappées ; une correspondance de technique n'est pas une attribution à un groupe ;
- la file globale **Triage** aide à organiser les éléments qui restent à examiner.

La gestion des règles et des intégrations externes se trouve dans **Paramètres**, selon votre rôle. Si une chasse ne retourne rien, vérifiez d'abord que l'artefact concerné a été parsé, que la règle est active et que la collecte contient les champs attendus.

## 8. Preuves réseau et mémoire

### Réseau

La vue **Réseau** d'une collecte utilise les connexions importées depuis les PCAP et les événements d'authentification pris en charge. Elle propose des vues de topologie, de chemin d'attaque et de mouvement latéral. Sélectionnez les nœuds et liens pour examiner les enregistrements à l'origine d'une relation ; une connexion ne prouve pas à elle seule une authentification réussie ou une compromission.

La vue **Réseau Global** du dossier combine les graphes disponibles. Revenez au périmètre d'une collecte pour vérifier la preuve d'origine.

![Vue réseau de Heimdall](shots/network.webp)

### Mémoire

Depuis l'onglet **Preuves** du dossier, utilisez l'action **RAM** pour téléverser un dump mémoire pris en charge. L'interface actuelle envoie le fichier en flux multipart et affiche sa progression dans le navigateur. Elle ne propose pas la reprise par blocs décrite par les anciennes versions de ce guide. La capacité pratique dépend du navigateur, du proxy, du stockage et du temps disponible ; testez un dump représentatif avant de compter sur ce workflow.

Après le téléversement, la carte de preuve indique l'état du transfert et de VolWeb. Utilisez **Ouvrir dans VolWeb** lorsque l'élément est prêt. VolWeb s'exécute séparément sur `http://localhost:8888` et fournit l'interface des plugins Volatility 3.

Ne supposez pas que tous les résultats Volatility sont recopiés dans la timeline de Heimdall. Conservez le résultat VolWeb, le nom du plugin et ses paramètres avec tout constat fondé sur l'analyse mémoire.

## 9. Construire le dossier d'investigation

L'onglet **Investigation** du dossier rassemble quatre ensembles liés :

- les phases ou tâches Kanban qui restent à traiter ;
- les constats structurés ;
- les questionnaires DFIQ et leurs preuves liées ;
- une kill chain construite depuis les constats enregistrés.

Utilisez les constats pour les conclusions soutenues par des preuves. Le **Notebook** convient aux notes de travail, hypothèses et questions qui ne sont pas encore prêtes. Les notes propres à un événement se placent dans le panneau de détail de la Super Timeline.

Le chat du dossier est accessible depuis sa page. Les messages et la présence facilitent la coordination, mais les décisions importantes doivent aussi être consignées dans un constat, le notebook ou le rapport plutôt que de rester uniquement dans le chat.

La vue **IOCs** d'une collecte, ainsi que la vue globale réservée aux administrateurs, permettent d'ajouter des indicateurs et de les enrichir si les intégrations sont configurées. Notez la source et le sens de chaque IOC ; les réponses des fournisseurs d'enrichissement peuvent changer et ne remplacent pas l'observation d'origine.

## 10. Générer un rapport

La zone **Synthèse & Rapport** se trouve dans la page **Preuves** du dossier. Au moins une collecte parsée est nécessaire.

1. Choisissez un modèle de rapport ou sélectionnez manuellement les sections.
2. Ajoutez une note analyste si le rapport demande un contexte qui ne peut pas être déduit des champs enregistrés.
3. Relisez les sections narratives collaboratives.
4. Générez le PDF puis téléchargez-le depuis l'état de rapport terminé.

Si Ollama est configuré, Heimdall peut préparer un brouillon. Considérez-le comme un texte modifiable, pas comme une conclusion forensique. Vérifiez les noms, dates, compteurs, correspondances MITRE et chaque affirmation avec les preuves citées avant toute diffusion du rapport.

Le journal d'audit et le manifeste de legal hold n'ont pas le même rôle. Le journal enregistre les actions de l'application ; le manifeste capture une vue signée du dossier lorsqu'il est demandé. Aucun des deux ne démontre à lui seul toute la chaîne de possession externe, et le legal hold actuel ne constitue pas une barrière technique complète contre la suppression.

## 11. Paramètres et opérations

Chaque utilisateur peut gérer son profil, ses sessions personnelles et les clés d'intégration autorisées par son rôle. Les administrateurs voient en plus l'équipe, les rôles, l'audit, la sécurité, la rétention, les intégrations et les SLA.

La zone **Opérations** est réservée aux administrateurs. Elle expose l'état des services, les travaux, les sauvegardes, Docker et l'administration du modèle local. Comme le backend utilise le socket Docker de l'hôte pour une partie de cette vue, l'accès administrateur est sensible au niveau de l'hôte.

Avant d'utiliser de vraies preuves :

- changez les mots de passe initiaux et vérifiez les sessions actives ;
- configurez la politique de mot de passe et de verrouillage ;
- contrôlez les origines autorisées, TLS et les ports exposés ;
- lancez une vérification d'intégrité du journal d'audit ;
- créez une sauvegarde et faites un exercice de restauration ;
- examinez la rétention avant d'activer une purge automatique.

Utilisez la procédure privée de [SECURITY.md](SECURITY.md) pour toute vulnérabilité présumée. Ne placez jamais de preuve client, d'identifiant ou de détail d'exploitation dans une issue publique ou sur Discord.

## 12. Dépannage

Commencez par l'état des services et les journaux correspondant à la frontière en échec :

```bash
docker compose ps
docker compose logs -f backend
docker compose logs -f worker
docker compose logs -f traefik
curl -k https://localhost/api/health
```

| Symptôme | Premiers contrôles |
| --- | --- |
| Connexion impossible après modification de `.env` | Les mots de passe existants sont stockés dans PostgreSQL ; modifier les variables initiales ne les fait pas tourner |
| La collecte ne produit aucun événement | Ouvrez **Logs**, examinez les fichiers ignorés ou en erreur, confirmez les artefacts choisis et le périmètre de collecte |
| Un parseur reste en attente | Vérifiez le `worker`, Redis et PostgreSQL |
| La timeline semble vide | Effacez les filtres, confirmez le nom de la collecte et consultez les compteurs du parsing |
| Hayabusa ne retourne rien | Confirmez que les EVTX ont été détectés et parsés ; un résultat vide peut aussi signifier qu'aucune règle active ne correspond |
| VolWeb ne s'ouvre pas | Vérifiez `hel-api`, les workers VolWeb, MinIO et le port `8888` |
| L'assistant local est indisponible | Vérifiez le service Ollama et la présence d'un modèle installé |
| Le navigateur affiche un avertissement de certificat | C'est attendu pour le certificat local auto-signé ; un déploiement public demande une configuration Traefik revue |

Pour signaler un bug ordinaire, indiquez le commit ou la date d'installation, les étapes exactes, le périmètre du dossier et de la collecte, ainsi que des journaux nettoyés. Ne joignez jamais de vraie preuve sans avoir convenu d'un canal de transfert privé.

## 13. Exemples de parcours courts

### Collecte Windows

1. Créez un dossier de test et importez une petite collecte KAPE, Magnet, Velociraptor ou CyLR.
2. Vérifiez les artefacts détectés avant de lancer les parseurs.
3. Consultez **Logs** pour repérer les fichiers ignorés et en erreur.
4. Ouvrez la **Super Timeline** et filtrez par hôte, Event ID ou outil.
5. Examinez les détections dans leur contexte et consignez les conclusions soutenues sous forme de constats.
6. Générez un brouillon de rapport, relisez-le puis exportez le PDF.

### Collecte Linux

1. Importez une archive CatScale.
2. Confirmez que la collecte est identifiée comme Linux.
3. Examinez les statuts CatScale et les nombres d'enregistrements.
4. Utilisez les filtres `host:`, `user:` et les pastilles d'artefacts.
5. Vérifiez les tags de détection Linux avec les lignes de log d'origine avant de créer des constats.

### Investigation mémoire

1. Téléversez un dump de test avec l'action **RAM**.
2. Attendez que la carte de preuve indique que VolWeb est prêt.
3. Notez le plugin Volatility et les paramètres utilisés pour chaque résultat pertinent.
4. Corrélez si possible les horodatages et identifiants avec les autres preuves du dossier.
5. Ajoutez la conclusion soutenue au dossier d'investigation et au rapport.

Les fonctions prévues et les limites connues sont décrites dans la [roadmap](ROADMAP.fr.md).
