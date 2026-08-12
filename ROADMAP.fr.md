# Roadmap de Heimdall DFIR

Dernière revue : 10 août 2026

[English](ROADMAP.md) · [README](README.fr.md) · [Historique des changements](CHANGELOG.md)

Cette roadmap donne une direction, pas des promesses de livraison. Les priorités peuvent changer lorsqu'une investigation révèle un problème d'intégrité, de sécurité ou de workflow. Le travail déjà livré appartient à l'[historique des changements](CHANGELOG.md) ; ce document ne garde que le contexte récent nécessaire pour comprendre la suite.

## État actuel

Heimdall permet déjà de suivre un dossier de laboratoire de bout en bout : ouvrir une investigation, importer une collecte Windows ou Linux, examiner la timeline, lancer les détections, organiser les constats et préparer un rapport. Le travail principal consiste maintenant à rendre ce parcours prévisible et maintenable avant d'ajouter une nouvelle série d'écrans.

| Domaine | État dans le dépôt |
| --- | --- |
| Suivi des dossiers | Dossiers, assignations, phases d'investigation, Kanban, constats, questions DFIQ et brouillons de rapport collaboratifs sont présents |
| Import | Les collectes Windows, CatScale, CSV, PCAP et mémoire sont prises en charge ; les travaux récents ont ajouté l'état par fichier, la déduplication et des résultats de parsing plus clairs |
| Timeline | Recherche, regroupement, préférences de colonnes, recherches enregistrées, contexte et comparaison sont présents |
| Chasse | YARA, Sigma, Hayabusa, corrélation d'IOC et packs de règles YAML sont présents ; certains anciens panneaux de revue et d'alerte doivent encore être rebranchés ou retirés |
| Analyse réseau | Graphes par dossier et globaux, mouvements latéraux, annotations et connexions extraites des PCAP sont présents |
| Collaboration | Assignations, chat par dossier, notebooks, salons temps réel et édition partagée des rapports sont présents |
| Administration | Comptes, sessions, politique de mot de passe, rétention, vérification de l'audit, sauvegardes et état des services sont présents |
| Tests | Des suites unitaires et d'intégration existent côté backend et frontend, mais les parcours navigateur critiques et les tests de déploiement manquent encore |

La version de l'application n'est volontairement pas indiquée ici : les paquets, l'endpoint de santé et le changelog ne donnent pas encore le même numéro. L'établissement d'une version unique fait partie des travaux ci-dessous.

## Travaux récents

Depuis la rédaction de l'ancienne roadmap, le dépôt a notamment reçu ou profondément revu :

- l'espace d'investigation, les questionnaires DFIQ, le Kanban et l'édition collaborative des rapports ;
- les recherches de timeline enregistrées, les vues de contexte et la comparaison ;
- une chaîne d'import plus explicite, avec état par fichier, déduplication, import CSV et lancement automatique des chasses ;
- le parsing CatScale et des règles de détection propres à Linux ;
- des salons temps réel isolés par dossier et des contrôles d'accès renforcés au niveau des routes ;
- le chaînage du journal d'audit et les paramètres de sécurité et de rétention ;
- le workflow d'investigation réseau et les vues de mouvement latéral ;
- un langage visuel commun aux principaux écrans et au threat hunting ;
- des suites de tests backend et frontend beaucoup plus fournies.

## Maintenant : fiabilité et confiance

Ces sujets passent avant l'ajout de nouveaux domaines forensiques.

### Une seule version de référence

Utiliser le même numéro de version dans le backend, le frontend, l'endpoint de santé, l'installeur et le changelog. Les notes de version doivent distinguer clairement la version de l'application des numéros de migration de la base.

Ce travail sera terminé lorsqu'un build tagué donnera la même version partout et que les deux README pourront pointer vers les mêmes notes de version.

### Une première installation sûre

Supprimer les mots de passe initiaux faibles, rendre les services optionnels réellement optionnels et nettoyer les commentaires obsolètes de Compose et des installeurs. Documenter la frontière de confiance créée par le socket Docker, les ports MinIO exposés et un service Elasticsearch sans authentification interne.

Ce travail sera terminé lorsqu'une installation neuve pourra se faire sans mot de passe connu et que l'opérateur pourra choisir de démarrer ou non Ollama et les fonctions d'administration de l'hôte.

### Un parcours analyste testé

Rebrancher ou retirer les anciens panneaux de revue, de playbooks, de SOAR et de triage. Corriger la navigation selon les rôles afin qu'une action ne mène jamais vers une page inaccessible à l'utilisateur. Ajouter des tests navigateur depuis la création du dossier jusqu'à l'import, la timeline, le constat et le rapport.

Ce travail sera terminé lorsque le parcours pris en charge ne contiendra plus de navigation morte et s'exécutera en CI sur une base neuve.

### Des imports prévisibles

Étendre les tests sur des collectes réelles et versionnées : interruption d'un travail, échec d'un parseur, nouvel import et variantes d'arborescence. Aligner les limites d'import documentées avec celles que chaque route applique réellement. Rendre les étapes de reprise visibles pour l'opérateur.

Ce travail sera terminé lorsque chaque fichier importé atteindra un état final clair et qu'une relance ne pourra pas dupliquer silencieusement la timeline.

### Exercices de restauration et d'audit

Tester ensemble la restauration de PostgreSQL, Elasticsearch, MinIO et des volumes de preuves. Maintenir une clé d'audit distincte et vérifier à la fois l'intégrité des lignes et la continuité de la chaîne. Décrire l'effacement sécurisé comme une propriété dépendante du stockage, sans promettre une norme donnée sur tous les volumes.

Ce travail sera terminé lorsqu'un exercice documenté pourra restaurer un dossier représentatif et expliquer ce qui est vérifié, ainsi que ce qui ne l'est pas.

## Ensuite : les manques utiles

L'ordre au sein de chaque groupe reste volontairement ouvert. Une issue doit définir le périmètre et les critères d'acceptation avant le début de l'implémentation.

### Workflow analyste

- des modèles de dossier réutilisables avec checklist, champs obligatoires et rapport par défaut ;
- l'assignation à des équipes ou groupes, au-delà des personnes ;
- une base responsive pour le triage et la revue, sans prétendre faire tenir toute la timeline de bureau sur un téléphone ;
- la traduction anglaise complète de la documentation forensique intégrée ;
- des tests de bout en bout pour les confirmations destructives, le legal hold et l'édition concurrente des rapports.

### Qualité des détections

- une boucle de retour analyste pour les faux positifs et les exceptions de règles ;
- des signaux de prévalence et de fichiers connus pour réduire le bruit ;
- le contexte de signature et de vulnérabilité des pilotes ;
- une mesure de qualité des packs fondée sur des jeux de test versionnés ;
- une meilleure analyse du beaconing irrégulier ou à faible volume.

### Interopérabilité

- une documentation OpenAPI et des webhooks sortants ;
- le transfert du journal d'audit et un format d'export SIEM documenté, notamment Splunk HEC ;
- des échanges MISP bidirectionnels ; l'intégration actuelle importe seulement les indicateurs ;
- une passerelle vers Velociraptor pour la réponse à distance, sans reconstruire la collecte d'endpoints dans Heimdall ;
- des contrats d'import et d'export testables sans passer par l'interface.

### Sources de preuves supplémentaires

- les messages et conteneurs de messagerie (`.eml`, `.msg`, `.pst`) ;
- les journaux cloud de Microsoft 365, Azure et AWS ;
- NTDS.dit et des artefacts Active Directory plus complets ;
- les artefacts de conteneurs et de Docker ;
- le triage local de binaires, avec des limites explicites pour la sandbox et les licences.

### Exploitation et identité

- la MFA par TOTP ou WebAuthn/FIDO2 ;
- la revue périodique de la politique de sécurité, des versions prises en charge et du canal de signalement privé ;
- le SSO par SAML ou OIDC, puis LDAP uniquement si le besoin de déploiement est clair ;
- des métriques Prometheus et un tableau Grafana restreint et maintenu ;
- la planification testée des sauvegardes, les alertes de capacité et de saturation des files ;
- un guide de déploiement pour les réseaux isolés.

## Plus tard : mesurer avant de distribuer

Le travail multi-serveur ne devrait commencer qu'après des tests de charge représentatifs montrant les limites réelles du déploiement Compose.

- workers de parsing et de chasse horizontaux ;
- analyse de campagnes entre dossiers avec des règles d'accès explicites ;
- stockage de timelines plus volumineuses, ClickHouse n'étant envisagé qu'après mesure ;
- multi-tenant MSSP avec isolation stricte entre clients ;
- API de plugins versionnée ;
- packaging Kubernetes lorsque les contrats de service et de stockage seront stables.

## Limites du projet

Heimdall ne cherche pas à devenir un SIEM généraliste, un service hébergé de conservation des preuves ou un remplacement de la réponse à distance sur les endpoints. Les fonctions basées sur un modèle local peuvent aider à chercher ou à rédiger, mais elles ne doivent jamais transformer une réponse non vérifiée en conclusion forensique ni masquer les preuves qui la soutiennent.

## Choix des travaux

Lorsque deux sujets sont en concurrence, la priorité va à celui qui :

1. protège l'isolation des dossiers ou l'intégrité des preuves ;
2. supprime un échec du parcours normal de l'analyste ;
3. améliore la répétabilité par des tests, des journaux ou une procédure de reprise ;
4. prend en charge une source de preuve pour laquelle des exemples peuvent être fournis et maintenus ;
5. conserve un déploiement auto-hébergé compréhensible.

Pour proposer un sujet, ouvrez une issue en décrivant le problème rencontré par l'analyste, une entrée représentative et le résultat attendu. Une modification réduite et testable est plus simple à relire qu'une proposition de fonctionnalité sans échantillon de preuve.
