# Feuille de route

| Phase | Contenu | État |
|------:|---------|------|
| 1 | Architecture, configuration, logs, audit, exécution sécurisée ADB/Fastboot, diagnostic de l'environnement, shell de l'interface | ✅ Livrée |
| 2 | ADB/Fastboot + détection d'appareil (`device_manager`, `adb_manager`, `fastboot_manager`, `/api/device`), vue Appareils | ✅ Livrée |
| 3 | Security Scanner (`app/security/*`, score 0-100), vues Scan / Applications / Permissions / Réseau / Chiffrement / Bootloader / Mises à jour | ✅ Livrée |
| 4 | Security Hardening : assistant AVANT / APRÈS / RISQUE / CONFIRMATION, 9 actions vérifiées, vérifications manuelles | ✅ Livrée |
| 5 | Backup : stockage partagé + APK, SHA-256 téléphone ↔ ordinateur, progression, annulation, revérification | ✅ Livrée |
| 6 | Compatibilité GrapheneOS : catalogue officiel, versions en direct depuis releases.grapheneos.org, vérifications appareil + ordinateur | ✅ Livrée |
| 7 | Téléchargement officiel avec reprise + vérification cryptographique (signature SSHSIG GrapheneOS, SHA-256/512, archive) | ✅ Livrée |
| 8 | Assistant d'installation en 13 étapes : confirmation, préparation officielle, contrôles préalables, script officiel flash-all, verrouillage, vérification | ✅ Livrée |
| 9 | Frontend complet (toutes les vues) | À faire |
| 10 | Tests (scénarios unauthorized/offline/multi-appareils, interruption…) | À faire |
| 11 | Documentation complète | À faire |
| 12 | Packaging | À faire |

Les modules d'une phase ne sont créés qu'au moment où ils sont réellement
implémentés : le dépôt ne contient ni fichier vide ni fonctionnalité simulée.
L'interface n'affiche que les vues déjà fonctionnelles.
