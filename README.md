# Fiches Cardiogen

Appli web personnelle (iPhone, écran d'accueil) : fiches de synthèse et calculateurs.

- `index.html` : l'appli (écran de déverrouillage, fonctionne hors ligne via `sw.js`)
- `data/content.json` : contenu chiffré (AES-256-GCM, clé dérivée par PBKDF2) ; l'appli demande le mot de passe une fois par téléphone
- `tools/crypt.py` : chiffrement et déchiffrement (mot de passe dans `FC_PASSWORD`, jamais dans le dépôt)
