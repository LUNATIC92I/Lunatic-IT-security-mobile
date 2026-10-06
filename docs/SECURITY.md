# Modèle de sécurité

## Ce que le logiciel ne fera jamais
- Contourner le verrouillage du bootloader, Verified Boot, un FRP, un verrouillage opérateur ou un mécanisme antivol.
- Installer GrapheneOS par une autre voie que la procédure officielle documentée sur grapheneos.org.
- Héberger ou redistribuer des images GrapheneOS : elles sont téléchargées depuis `releases.grapheneos.org`.
- Exécuter une opération destructive sans confirmation explicite validée côté serveur.
- Annoncer le succès d'une opération qui n'a pas été vérifiée.

## Surface d'attaque locale
Le serveur pilote ADB/Fastboot, il doit donc être inaccessible au réseau et aux sites web visités :

| Menace | Protection |
|--------|------------|
| Accès réseau | Écoute uniquement sur une adresse loopback ; toute autre valeur de `LMS_HOST` est refusée au démarrage. |
| DNS rebinding | `TrustedHostMiddleware` : seuls `127.0.0.1`, `localhost`, `::1` sont acceptés comme Host. |
| CSRF depuis un site web | Requêtes non-GET : en-tête `X-LMS-Token` (jeton aléatoire par lancement, lisible seulement en same-origin) + contrôle de l'`Origin`. Toute requête `/api/` marquée `Sec-Fetch-Site: cross-site` par le navigateur (même un GET déclenché par `<img>`) est refusée. Aucune requête GET n'écrit sur le disque ni ne modifie le téléphone. Aucun en-tête CORS n'est émis. |
| Injection de commande | Liste blanche, `shell=False`, arguments validés, pas d'option injectable. |
| XSS via données de l'appareil | Le frontend insère tout via `textContent` ; CSP `default-src 'self'`, aucun script inline. |
| Path traversal | `safe_join` refuse `..`, chemins absolus et liens symboliques sortants. |
| Fuite d'informations | Exceptions jamais renvoyées brutes ; secrets et numéros de série masqués dans les logs et l'audit. |
| Données hostiles du téléphone | Chemins renvoyés par le téléphone (`pm path`) validés sans segment `..` ; sortie d'erreur du téléphone masquée avant d'être enregistrée. |
| Archive piégée | Image vérifiée par signature, revérifiée juste avant l'extraction, extraction limitée au dossier attendu et à 4 fois la taille de l'archive. |
| Falsification de l'historique | Audit chaîné SHA-256, vérifiable depuis l'interface. |

Fichiers de données créés avec des permissions propriétaire uniquement (`0700` / `0600`) sous Linux/macOS.

## Signaler une vulnérabilité
Ouvrez une issue privée (security advisory) sur le dépôt GitHub.
