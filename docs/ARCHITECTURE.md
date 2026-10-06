# Architecture

```
navigateur (HTML/CSS/JS)  ──HTTP 127.0.0.1──►  FastAPI (app/main.py)
                                                   │
                         app/api/*  (routes, validation des entrées)
                                                   │
                         app/core/* (services)  ──► CommandRunner ──► adb / fastboot
                                                   │                    (liste blanche, sans shell)
                         app/security/*, app/graphene/*  (phases 3 à 8)
```

## Modules livrés en phase 1

| Fichier | Rôle |
|---------|------|
| `app/config.py` | Paramètres `LMS_*` validés (loopback uniquement, source GrapheneOS HTTPS officielle), répertoires par plateforme. |
| `app/logging_config.py` | Format `AAAA-MM-JJ HH:MM:SS NIVEAU message`, masquage des secrets et des numéros de série, tampon mémoire pour `/api/logs`. |
| `app/core/errors.py` | Erreurs utilisateur `ERREUR / CAUSE POSSIBLE / ACTION`. |
| `app/core/safety.py` | Validation des numéros de série, masquage, protection path traversal. |
| `app/core/platform_tools.py` | Localisation d'adb/fastboot, **liste blanche des commandes**, exécution `subprocess` sécurisée, détection de version. |
| `app/core/environment.py` | Diagnostic de l'ordinateur (Python, disque, outils, udev, fwupd, pilote Windows). |
| `app/core/audit_logger.py` | Journal d'audit JSONL chaîné par SHA-256 (falsification détectable). |
| `app/api/routes.py` | `/api/health`, `/api/session`, `/api/system/environment`, `/api/settings`, `/api/logs`, `/api/audit`, `/api/audit/verify`. |
| `app/main.py` | Fabrique `create_app`, middlewares de sécurité, CLI (`--check`, `--json`, `--port`, `--no-browser`). |
| `frontend/` | Shell de l'interface : Dashboard (diagnostic), Logs temps réel, Paramètres + audit. |

## Modules livrés en phase 2

| Fichier | Rôle |
|---------|------|
| `app/core/adb_manager.py` | Parsing de `adb devices -l`, `getprop` (liste blanche de propriétés, numéros de série écartés), `df -k /data`, `dumpsys battery`, `settings get`. |
| `app/core/fastboot_manager.py` | Parsing de `fastboot devices` et `fastboot getvar all` (lecture seule). |
| `app/core/device_manager.py` | États de connexion → message + action, identifiants opaques, sélection de l'appareil cible, détails, audit des connexions/déconnexions. |
| `app/models/device.py` | Modèles Pydantic `DeviceStatus`, `DeviceConnection`, `DeviceDetails`. |
| `app/api/device_routes.py` | `GET /api/device/status`, `GET /api/device`, `POST /api/device/adb/restart-server`. |
| `frontend/js/devices.js` | Vue Appareils : liste, sélection, détails, redémarrage ADB avec confirmation. |

### Identifiants d'appareil
Le navigateur ne reçoit jamais le numéro de série : seulement sa forme masquée
(`HU•••••••••01`) et un `device_id` = HMAC-SHA256(numéro de série, clé aléatoire
générée à chaque lancement), tronqué à 16 caractères hexadécimaux. Le backend
retrouve le numéro de série à partir d'une énumération fraîche ; un identifiant
inconnu (appareil débranché) ou mal formé est refusé.

### Sélection de l'appareil cible
Sans `device_id`, l'opération cible l'unique appareil prêt. S'il y en a plusieurs,
la requête est refusée (`multiple_devices`) ; s'il n'y en a aucun, l'erreur
explique quoi faire selon l'état (non autorisé, hors ligne, accès USB refusé…).

## Exécution des commandes

Aucune ligne de commande n'est construite à partir d'une saisie libre. Un module
appelle `runner.run("adb.devices")` ; le nom référence une entrée de
`COMMAND_WHITELIST`, dont le gabarit est fixe. Les parties variables sont des
`Arg` validées par expression régulière (pas de `-` initial, pas d'espace ni de
métacaractère). Le numéro de série est injecté via `-s` après validation.
Les commandes marquées `destructive=True` exigent `confirmed=True`.
`subprocess.run` est toujours appelé avec une liste d'arguments, `shell=False`,
`stdin=DEVNULL` et un timeout ; le processus est tué à expiration.

## Modules livrés en phase 3 — Security Scanner

```
AuditCollector (android_audit.py) ── commandes ADB en lecture seule ──► DeviceSnapshot
        │
        ├─ analyze_system            (android_audit.py)  débogage, options développeur, sources inconnues
        ├─ boot_security             bootloader, Verified Boot, SELinux, root, build de debug, clés de test
        ├─ encryption                ro.crypto.state / type
        ├─ updates                   âge du correctif, version Android maintenue
        ├─ network                   proxy, DNS privé, Wi-Fi, VPN, ADB sans fil
        ├─ applications              origine, installations récentes
        └─ permissions               groupes sensibles, accès spéciaux, score contextuel par application
                │
        recommendations.py ── score 0-100, note, tri ──► SecurityReport
```

| Fichier | Rôle |
|---------|------|
| `app/security/android_audit.py` | Collecte (une étape par source, chaque échec devient une *limite*), constats « système », orchestration `run_audit`. Abandon propre si le téléphone disparaît pendant l'analyse. |
| `app/security/applications.py` | Parsing de `dumpsys package packages` (utilisateur 0 uniquement, paquets cachés ignorés) et de `pm list packages`. |
| `app/security/permissions.py` | Groupes de permissions, `device_policy`, `appops`, services d'accessibilité / écouteurs de notifications, score de risque par application. |
| `app/security/network.py` | `cmd wifi status`, `dumpsys connectivity`, paramètres proxy / DNS / VPN. SSID, BSSID, MAC et IP ne sont pas conservés. |
| `app/security/boot_security.py`, `encryption.py`, `updates.py` | Sections et constats correspondants. |
| `app/security/recommendations.py` | Calcul du score. |
| `app/core/security_scanner.py` | Analyse en tâche de fond (une à la fois), progression, rapports en mémoire et sur disque, sections à la demande. |
| `app/api/security_routes.py` | Endpoints de sécurité. |
| `frontend/js/security.js` | Vues Security Scan, Applications, Permissions, Réseau, Chiffrement, Bootloader, Mises à jour. |

### Score
Chaque constat retire des points selon sa gravité (critique 35, élevée 15, moyenne 6,
faible 2, info 0). La pénalité est plafonnée par catégorie (système 30, démarrage 50,
applications 15, permissions 25, réseau 20, chiffrement 40, mises à jour 30) pour que
de nombreux constats mineurs du même type ne suffisent pas à faire tomber le score.
Un constat critique plafonne le score à 39, un constat élevé à 74.
Notes : 90-100 Excellent, 75-89 Bon, 60-74 Moyen, 40-59 Faible, 0-39 Critique.

### Score contextuel des applications
Une permission n'est jamais considérée comme malveillante en soi. Le score d'une
application tierce cumule des poids par capacité (micro 10, localisation en
arrière-plan 12, SMS 12…), par accès spécial (accessibilité 30, lecture des
notifications 18, administrateur 15…), son origine (hors magasin +15) et des
combinaisons (origine non vérifiée + nombreuses permissions +10). Le contexte
réduit le poids (accès SMS de l'application SMS par défaut). Les applications
système ne sont pas notées.

### Confidentialité
Seules des listes blanches de propriétés et de paramètres sont conservées
(`android_id`, nom de l'appareil, adresse Bluetooth sont écartés). Les rapports
sauvegardés dans `<données>/reports/` (permissions 0600) ne contiennent que le
numéro de série masqué.

## Modules livrés en phase 4 — Security Hardening

| Fichier | Rôle |
|---------|------|
| `app/security/hardening.py` | Actions (lecture de l'état, application, vérification), plan signé, liste de vérifications manuelles. |
| `app/core/hardening_service.py` | Résolution de l'appareil, une modification à la fois, refus pendant une analyse, journal d'audit. |
| `app/api/hardening_routes.py` | `GET /api/hardening/plan`, `POST /api/hardening/apply`. |
| `frontend/js/hardening.js` | Vue Renforcement. |

### Actions disponibles

| Action | Commande (téléphone) | Vérification |
|--------|----------------------|--------------|
| `disable_accessibility` | `settings put secure enabled_accessibility_services <autres services>` (ou `settings delete` s'il n'en reste aucun) | relecture du paramètre |
| `unknown_sources` | `appops set <paquet> REQUEST_INSTALL_PACKAGES deny` | `appops query-op` |
| `unknown_sources_legacy` (Android < 8) | `settings put secure install_non_market_apps 0` | relecture |
| `revoke_permission` | `pm revoke <paquet> <permission>` pour chaque permission accordée du groupe | `dumpsys package <paquet>` |
| `clear_global_proxy` | `settings put global http_proxy :0` | relecture |
| `enable_private_dns` | `settings put global private_dns_mode opportunistic` | relecture |
| `disable_adb_wifi` | `settings put global adb_wifi_enabled 0` | relecture |
| `enable_adb_install_verification` | `settings put global verifier_verify_adb_installs 1` | relecture |
| `disable_usb_debugging` (toujours en dernier) | `settings put global adb_enabled 0` | disparition du téléphone de `adb devices` |

Non automatisés (pas de mécanisme ADB fiable sans root, ou risque de perte de
données) : retrait d'un administrateur de l'appareil, désinstallation
d'applications, accès aux notifications, interrupteur des options développeur,
code de verrouillage. Ils figurent dans les « vérifications manuelles ».

### Garanties côté serveur
1. Les commandes de modification sont marquées `mutating` dans la liste blanche :
   le `CommandRunner` les refuse sans `confirmed=True`.
2. Toute partie variable d'une commande doit respecter `[A-Za-z0-9._:/@+=,-]+` :
   `adb shell` transmet la ligne au shell du téléphone, aucun métacaractère
   n'est donc possible.
3. `POST /api/hardening/apply` exige `confirm: true`, le jeton CSRF et le jeton
   du plan (HMAC de l'appareil, de l'action, de la cible, de l'état AVANT et de
   l'heure d'émission ; validité 15 minutes). L'état AVANT est relu sur le
   téléphone : s'il diffère de celui affiché, la requête est refusée.
4. Le résultat n'est « vérifié » qu'après une nouvelle lecture montrant la valeur
   attendue ; sinon il est rapporté « non vérifié ».
5. Chaque demande, réussite, échec ou non-vérification est inscrite dans l'audit.

## Modules livrés en phase 5 — Backup

| Fichier | Rôle |
|---------|------|
| `app/core/backup_manager.py` | Estimation, choix de la destination, sauvegarde en tâche de fond, vérification, liste et revérification des sauvegardes. |
| `app/api/backup_routes.py` | `/api/backup/estimate`, `browse`, `start`, `status`, `cancel`, `list`, `verify`. |
| `frontend/js/backup.js` | Vue Backup. |

### Déroulement
1. Contrôles préalables : appareil ADB prêt, dossiers dans la liste autorisée,
   destination absolue existante et accessible en écriture, espace libre ≥
   taille estimée × 1,05 + 200 Mo.
2. Pour chaque dossier : `find <dossier> -type f -exec sha256sum {} +` **sur le
   téléphone**, puis `adb pull` vers `<destination>/LMS-backup-<modèle>-<date>.partial/shared/`.
3. Chaque fichier est haché **sur l'ordinateur** et comparé. Un fichier
   différent n'est pas inscrit dans `SHA256SUMS` ; il est listé dans les anomalies.
   Un fichier apparu pendant la copie est signalé comme non vérifié.
4. Option APK : `pm path` puis `sha256sum` et `adb pull` de chaque APK.
5. Écriture de `SHA256SUMS` (compatible `sha256sum -c`) et `backup.json`, puis
   renommage du dossier sans `.partial`. Statut `verified` uniquement si tout
   correspond, sinon `incomplete`.
6. Annulation ou échec (câble débranché, disque plein) : le processus adb est
   tué et le dossier `.partial` supprimé.

### Limites (affichées dans l'interface)
Données privées des applications, SMS, journal d'appels et contacts ne sont pas
accessibles à ADB sans root ; `adb backup` n'est pas utilisé (obsolète, ignoré
par les applications récentes) ; `Android/` est exclu.

### Sécurité
Le chemin local de destination est transmis à `adb` par la liste d'arguments
(jamais par un shell, ni au shell du téléphone) : il peut donc contenir espaces
et accents. Les chemins lus depuis le téléphone ou depuis un `SHA256SUMS` sont
résolus avec `safe_join` : un chemin sortant du dossier de sauvegarde est refusé.

## Modules livrés en phase 6 — Compatibilité GrapheneOS

| Fichier | Rôle |
|---------|------|
| `app/graphene/compatibility.py` | Catalogue officiel (21 appareils, fin du support constructeur, appareils en fin de vie) au `CATALOG_DATE`, vérifications appareil et ordinateur. |
| `app/graphene/releases.py` | Client HTTPS des métadonnées officielles. |
| `app/core/grapheneos_manager.py` | Compatibilité du téléphone connecté (ADB ou Fastboot), catalogue enrichi des versions publiées. |
| `app/models/graphene_release.py` | `GrapheneRelease`, `CompatibilityResult`. |
| `app/api/graphene_routes.py` | `GET /api/graphene/compatibility`, `GET /api/graphene/releases`, `GET /api/graphene/releases/{codename}`. |
| `frontend/js/graphene.js` | Vue GrapheneOS. |

### Sources officielles utilisées
- `https://releases.grapheneos.org/<codename>-<canal>` : `VERSION TIMESTAMP CODENAME CANAL`, **source de vérité** pour la
  disponibilité d'une version. La réponse doit nommer l'appareil et le canal demandés.
- `https://releases.grapheneos.org/overview.json` : vue d'ensemble lue par la page officielle des versions. Elle peut
  être incomplète (Pixel 10a et Pixel 9a absents le 2026-10-06 alors que leurs fichiers par appareil existent) : les
  appareils manquants sont complétés par leur fichier `<codename>-stable`.
- Image `<codename>-install-<version>.zip`, signature `.zip.sig`, clé `allowed_signers` (vérification en phase 7).

Le client force HTTPS sur un hôte officiel (validé dans la configuration), valide les certificats TLS, refuse les
redirections, limite la taille des métadonnées à 256 Ko et met la vue d'ensemble en cache 5 minutes.

### Vérifications
| Point | Source | Bloquant si |
|-------|--------|-------------|
| Modèle | `ro.product.device` (ADB) ou `getvar product` (Fastboot) | absent du catalogue, ou en fin de vie |
| Version officielle | `<codename>-<canal>` | aucune version publiée (serveur injoignable = avertissement) |
| Durée de support | catalogue | jamais (avertissement à moins de 6 mois ou après la fin) |
| Déverrouillage | `ro.oem_unlock_supported`, `sys.oem_unlock_allowed` (ADB) ; `fastboot flashing get_unlock_ability` | appareil non déverrouillable (variante opérateur) — jamais contourné |
| Fastboot de l'ordinateur | `fastboot --version` | < 35.0.1 |
| Espace disque | dossier de téléchargement | < 32 Go (prérequis du guide officiel) |

## Modules livrés en phase 7 — Téléchargement et vérification

| Fichier | Rôle |
|---------|------|
| `app/graphene/verifier.py` | Vérification SSHSIG (Ed25519) en Python, clé GrapheneOS épinglée, SHA-256/SHA-512, contrôle de l'archive. |
| `app/graphene/downloader.py` | Téléchargement HTTPS avec reprise (`Range`), annulation, puis vérification ; `verified.json`. |
| `app/api/graphene_routes.py` | `POST /api/graphene/download`, `GET /api/graphene/download/status`, `POST /api/graphene/download/cancel`, `POST /api/graphene/verify`, `GET /api/graphene/images`, `POST /api/graphene/images/delete`. |

### Vérification (équivalent exact de la commande du guide officiel)
`ssh-keygen -Y verify -f allowed_signers -I contact@grapheneos.org -n "factory images" -s <image>.zip.sig < <image>.zip`
est réimplémentée avec `cryptography` (pas besoin d'OpenSSH) :

1. `allowed_signers` téléchargé **doit contenir la clé épinglée** dans le code
   (`ssh-ed25519 AAAAC3…xdJE`, empreinte `SHA256:AhgHif0mei+9aNyKLfMZBh2yptHdw/aN7Tlh/j2eFwM`,
   publiée sur grapheneos.org/install/cli). Une clé différente est refusée : la
   confiance ne dépend jamais uniquement de ce que renvoie le réseau.
2. Signature SSHSIG : magie, version 1, clé = clé épinglée, espace de noms
   `factory images`, type `ssh-ed25519`, hachage sha512 (ou sha256).
3. SHA-512 du fichier (et SHA-256 pour l'affichage et le contrôle avant flashage),
   vérification Ed25519 de `"SSHSIG" ‖ namespace ‖ reserved ‖ hash_alg ‖ H(fichier)`.
4. Taille identique à celle annoncée par le serveur officiel.
5. Archive : toutes les entrées sous `<codename>-install-<version>/`, aucun chemin
   dangereux, `flash-all.sh` et `flash-all.bat` présents → une image signée mais
   destinée à un autre appareil ou une autre version est refusée.

Résultat : **Download → Verification → Ready**. Au moindre échec :
**Verification FAILED — Installation blocked**, fichiers supprimés.

Validé le 2026-10-06 sur les vraies images officielles `husky-install-2026100200.zip`
(1 873 867 524 octets) et `shiba-install-2026100200.zip` (reprise après annulation à 306 Mo).

### Téléchargement
- Version toujours issue des métadonnées officielles (le client ne choisit que l'appareil et le canal).
- HTTPS vérifié, hôte officiel uniquement, redirections refusées, taille ≤ 4 Gio et
  égale à l'annonce du serveur, espace libre ≥ 2,5 × taille.
- Fichier `.part` conservé après interruption ou annulation, reprise par `Range`
  avec contrôle de `Content-Range`.

## Modules livrés en phase 8 — Installation guidée

| Fichier | Rôle |
|---------|------|
| `app/graphene/installer.py` | Machine à états de l'assistant (13 étapes), contrôles préalables, exécution du script officiel, verrouillage, vérification finale. |
| `app/api/graphene_routes.py` | `POST /api/graphene/install`, `/install/confirm`, `/install/action`, `GET /install/status`, `POST /install/abandon`. |
| `frontend/js/install.js` | Vue « Installation ». |

### Étapes et garde-fous (appliqués côté serveur)
| # | Étape | Contrôle |
|---|-------|----------|
| 1-3 | Connexion, modèle, compatibilité | refus si l'appareil n'est pas compatible (phase 6) |
| 4-5 | Avertissement « Cette opération peut effacer toutes les données du téléphone. » + confirmation | phrase exacte `EFFACER <CODENAME>` + deux cases cochées |
| 6 | ADB / Fastboot | fastboot ≥ 35.0.1 |
| 7 | Préparation | « Déverrouillage OEM » activé (lu sur le téléphone) → `adb reboot bootloader` → `fastboot flashing unlock` (validation sur le téléphone) → `unlocked: yes` relu |
| 8-9 | Composants | image officielle présente, revérification complète (signature, SHA-256/512, archive, clé AVB) |
| 10 | Flashage | contrôles préalables tous verts → **READY TO INSTALL** (valable 15 min, usage unique) → script officiel |
| 11 | Résultat | variables du bootloader relues ; `fastboot flashing lock` **uniquement si le flashage de cette session a réussi** ; `unlocked: no` relu |
| 12 | Configuration | `fastboot reboot` + consignes (désactiver le déverrouillage OEM à la fin de l'assistant, code robuste) |
| 13 | Vérification | via ADB si l'utilisateur le réactive : Verified Boot `yellow`, bootloader verrouillé, bon modèle ; empreinte officielle de la clé affichée pour comparaison avec l'écran de démarrage |

Contrôles préalables : Device detected, Single device, Fastboot mode, Compatible Pixel
(`getvar product`), Bootloader unlocked, Battery information available (`battery-soc-ok`),
Correct release, SHA-256 verified, Signature verified, Fastboot available,
Official flash script runnable, Disk space, Write permissions, User confirmation received.

### Exécution du script officiel (exception justifiée au « pas de shell »)
Le flashage exécute **le script `flash-all.sh` (ou `flash-all.bat`) contenu dans l'image
vérifiée**, exactement comme le guide officiel : c'est la procédure publiée et signée par
GrapheneOS, la réimplémenter divergerait de la méthode officielle. Il est lancé avec une
liste d'arguments (`bash flash-all.sh` / `cmd /c flash-all.bat`, `shell=False`), aucune
donnée utilisateur, le dossier extrait comme répertoire courant (extraction sûre : aucun
chemin hors du préfixe attendu), `PATH` commençant par les platform-tools,
`ANDROID_SERIAL` = appareil ciblé (et un seul appareil autorisé), `TMPDIR` dans le dossier
de données (cf. remarque tmpfs du guide), délai maximal `LMS_FLASH_TIMEOUT` (1800 s) avec
minuterie indépendante. Toute la sortie Fastboot est affichée et journalisée ; le dossier
extrait est supprimé ensuite.

En cas d'échec : verrouillage refusé, consignes (ne pas redémarrer, ne pas verrouiller,
relancer contrôles + flashage).

Validation du 2026-10-06 : le vrai `flash-all.sh` de `husky-install-2026100200.zip`
(image officielle vérifiée) exécuté de bout en bout via l'assistant contre un Pixel simulé :
32 opérations Fastboot dans l'ordre officiel, puis verrouillage.

### Empreinte de clé Verified Boot
`VERIFIED_BOOT_KEY_HASHES` reprend les empreintes officielles de chaque modèle. L'image doit
contenir un `avb_pkmd.bin` dont le SHA-256 est identique (vérifié en phase 7 et avant le
flashage) : la clé écrite dans l'élément sécurisé est donc forcément celle de GrapheneOS.
