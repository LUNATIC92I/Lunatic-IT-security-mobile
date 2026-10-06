# Tests

```bash
.venv/bin/python -m pytest                 # suite complète, aucun matériel requis (~1 min 30)
.venv/bin/python -m pytest --cov           # couverture des branches, échec sous 90 %
.venv/bin/python -m pytest tests/test_scenarios.py -v   # scénarios du cahier des charges
LMS_REAL_PLATFORM_TOOLS=~/platform-tools .venv/bin/python -m pytest tests/test_real_platform_tools.py
```

## Comment le matériel est simulé

| Élément | Simulation | Fichier |
|---------|-----------|---------|
| `adb`, `fastboot` | Vrais exécutables (shebang Python) lancés par le vrai `subprocess` de l'application : timeouts, codes de sortie et sorties texte réels. | `tests/fakes/fake_platform_tool.py` |
| Téléphones branchés | Fichier JSON (`LMS_FAKE_DEVICES`) : état (`device`, `unauthorized`, `offline`, `no permissions`, `fastboot`), profil, pannes à injecter. Un fichier `.state.json` mémorise les modifications (paramètres, mode fastboot, partitions flashées). | `tests/conftest.py` (`fake_devices`) |
| Sorties Android | `getprop`, `dumpsys`, `settings`, `pm`, `getvar all`… copiées du format des vrais outils. | `tests/fakes/profiles.py` |
| Serveur GrapheneOS | `httpx.MockTransport` : métadonnées, `Range`, coupure réseau, lenteur, redirection, serveur en panne. | `tests/fakes/release_server.py` |
| Signatures | Vraies signatures SSHSIG Ed25519 produites à la volée avec une clé de test (la clé officielle épinglée est remplacée pendant le test). | `tests/fakes/signing.py` |
| Image d'installation | Archive au format officiel contenant un `flash-all.sh` qui appelle le faux `fastboot`. | `tests/fakes/signing.py` |

Pannes injectables par appareil : `fail_pull`, `corrupt_pull`, `slow_pull`,
`disconnect_after` (câble débranché après N commandes), `flash_fail_on`
(partition refusée), `unplug_on` (câble débranché pendant l'écriture d'une
partition), `flash_sleep`, `refuse_unlock` / `refuse_lock`, `props`
(propriétés système modifiées), `battery_ok`, `adb_after_reboot`…

## Matrice des scénarios

| Scénario du cahier des charges | Ce qui est vérifié | Tests |
|---|---|---|
| Détection ADB | Appareil prêt, numéro de série masqué partout | `test_scenarios::test_adb_detection`, `test_device_manager` |
| Appareil non autorisé | Message « autorisez l'ordinateur », analyse/sauvegarde refusées (409, ERREUR/CAUSE/ACTION) | `test_scenarios::test_unauthorized_device`, `test_device_manager::test_unauthorized`, `test_graphene_install::test_unauthorized_phone_cannot_start_installation` |
| Appareil hors ligne | Action proposée, opérations refusées | `test_scenarios::test_offline_device`, `test_device_manager::test_offline` |
| Permissions USB insuffisantes | Règles udev expliquées, installation refusée | `test_scenarios::test_insufficient_usb_permissions`, `test_device_manager::test_no_permissions` |
| Plusieurs appareils | Sélection explicite obligatoire ; un seul appareil pendant le flashage | `test_scenarios::test_multiple_devices`, `test_graphene_install::test_second_device_blocks_flash` |
| Pixel compatible | Compatibilité + version officielle du jour | `test_scenarios::test_compatible_pixel`, `test_graphene_compat` |
| Appareil incompatible | Refus motivé, aucune session ouverte | `test_scenarios::test_incompatible_device`, `test_graphene_compat::test_checks_non_pixel_and_eol` |
| Téléchargement | Image officielle, SHA-256 enregistré = SHA-256 du fichier | `test_scenarios::test_download_and_checksum`, `test_graphene_download_api` |
| Somme de contrôle / fichier corrompu | Un bit modifié → vérification échouée, fichier supprimé, jamais flashable | `test_scenarios::test_corrupted_file`, `test_graphene_download::test_one_flipped_byte_is_rejected` |
| Image modifiée après vérification | Contrôles préalables et revérification avant extraction | `test_graphene_install::test_tampered_image_after_download`, `test_image_swapped_between_preflight_and_flash` |
| Fastboot indisponible | Diagnostic en échec, étape « outils » en échec, rien n'est envoyé au téléphone | `test_scenarios::test_fastboot_unavailable`, `test_graphene_install::test_fastboot_unavailable_blocks_installation` |
| Fastboot trop ancien | Avertissement + préparation bloquée | `test_environment::test_old_fastboot_is_a_warning_with_instructions`, `test_graphene_compat::test_compatibility_old_fastboot_blocks_preparation` |
| Interruption pendant le téléchargement | Erreur lisible, fichier partiel conservé, reprise `Range` exacte | `test_scenarios::test_interrupted_download_resumes`, `test_graphene_download::test_interrupted_download_resumes` |
| Interruption pendant le flashage | Erreur Fastboot brute affichée + cause en clair, verrouillage refusé, nouveau flash impossible sans nouveaux contrôles | `test_scenarios::test_interruption_during_flash`, `test_graphene_install::test_cable_pulled_during_flash`, `test_flash_timeout`, `test_flash_timeout_kills_a_hung_fastboot`, `test_flash_failure_is_reported_and_lock_refused` |
| Mauvaise version | Image signée d'un autre Pixel refusée ; version réellement installée comparée à la version vérifiée | `test_scenarios::test_wrong_device_image`, `test_graphene_install::test_wrong_version_detected_after_install`, `test_graphene_download::test_correctly_signed_image_for_another_device_is_rejected` |
| Permissions insuffisantes (ordinateur) | Dossier de données / destination inutilisable → erreur lisible, rien de partiel | `test_scenarios::test_download_directory_not_writable`, `test_backup::test_destination_that_is_not_a_directory`, `test_backup::test_disk_full_during_backup`, `test_environment::test_data_dir_not_writable` |
| Succès non présumé | « Terminé » seulement après relecture des variables du bootloader puis contrôle Verified Boot sur GrapheneOS | `test_scenarios::test_successful_installation_is_verified_not_assumed` |

## Sécurité testée

* Liste blanche : commandes inconnues, arguments hors gabarit, injection de
  métacaractères shell, chemins hors dossier → refus (`test_platform_tools`).
* Opérations destructives : refus sans `confirmed=True` au niveau du lanceur de
  commandes et sans `confirm` au niveau de l'API (`test_graphene_install`,
  `test_hardening_api`).
* CSRF, en-tête Host, origine, CSP (`test_api`), path traversal (`test_safety`,
  `test_backup`, archives GrapheneOS).
* Aucun numéro de série en clair dans les réponses, logs, rapports, audit
  (`test_scenarios`, `test_device_manager`, `test_logs_settings_api`).
* Interface : pas de script ni de gestionnaire en ligne (bloqués par la CSP),
  pas d'`innerHTML`, chaque élément référencé existe, chaque appel `/api/…`
  correspond à une route (`test_frontend`).

## Limites

* Les tests utilisent un shebang POSIX pour les faux outils : sous Windows,
  les tests dépendant d'`adb`/`fastboot` sont ignorés.
* `test_backup::test_read_only_destination` est ignoré en root (root ignore les
  permissions des dossiers) ; `test_destination_that_is_not_a_directory`
  couvre le même cas pour tous les utilisateurs.
* Aucun test automatique n'écrit sur un vrai téléphone.

## Validations sur données réelles (manuelles)

Faites pendant le développement, reproductibles :

* vrais `adb` / `fastboot` 35.0.2 officiels : versions, liste des appareils,
  diagnostic (`tests/test_real_platform_tools.py`) ;
* vraies images GrapheneOS `husky` et `shiba` 2026100200 téléchargées depuis
  releases.grapheneos.org : signature vérifiée avec la clé officielle épinglée,
  reprise d'un téléchargement interrompu, empreinte de `avb_pkmd.bin` égale à
  l'empreinte officielle de la clé Verified Boot ;
* vrai script officiel `flash-all.sh` extrait de l'image vérifiée, exécuté de
  bout en bout par l'assistant contre le faux Pixel, jusqu'à « INSTALLATION
  TERMINÉE ET VÉRIFIÉE » dans le navigateur ;
* parcours de toutes les vues dans Chromium (bureau et 390 px) : aucun
  débordement horizontal, aucune erreur JavaScript, contrôles au clavier.
