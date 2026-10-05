# Feuille de route

| Phase | Contenu | État |
|------:|---------|------|
| 1 | Architecture, configuration, logs, audit, exécution sécurisée ADB/Fastboot, diagnostic de l'environnement, shell de l'interface | ✅ Livrée |
| 2 | ADB/Fastboot + détection d'appareil (`device_manager`, `adb_manager`, `fastboot_manager`, `/api/device`), vue Appareils | ✅ Livrée |
| 3 | Security Scanner (`app/security/*`, score 0-100), vues Scan / Applications / Permissions / Réseau / Chiffrement / Bootloader / Mises à jour | ✅ Livrée |
| 4 | Security Hardening (assistant AVANT / APRÈS / RISQUE / CONFIRMATION) — actions déjà référencées par les constats : `disable_usb_debugging`, `unknown_sources`, `clear_global_proxy`, `disable_adb_wifi` | À faire |
| 5 | Backup (SHA-256, progression, vérification) | À faire |
| 6 | Compatibilité GrapheneOS (`graphene/compatibility.py`, `releases.py`) | À faire |
| 7 | Téléchargement + vérification cryptographique | À faire |
| 8 | Assistant d'installation (preflight checks, flash) | À faire |
| 9 | Frontend complet (toutes les vues) | À faire |
| 10 | Tests (scénarios unauthorized/offline/multi-appareils, interruption…) | À faire |
| 11 | Documentation complète | À faire |
| 12 | Packaging | À faire |

Les modules d'une phase ne sont créés qu'au moment où ils sont réellement
implémentés : le dépôt ne contient ni fichier vide ni fonctionnalité simulée.
L'interface n'affiche que les vues déjà fonctionnelles.
