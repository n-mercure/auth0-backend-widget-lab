# Auth0 Backend + Widget Lab

Ce projet valide le scénario suivant :

1. Le navigateur demande une page protégée.
2. Le backend vérifie une session applicative serveur.
3. Si la session est absente, le backend redirige vers Auth0 Universal Login.
4. Auth0 retourne vers `/callback`.
5. Le backend échange le code OAuth contre des tokens, valide le ID token, puis crée une session serveur avec cookie HTTP-only.
6. Le backend rend `/protected`.
7. La page charge un widget.
8. Le widget utilise son propre client SPA Auth0 et tente `getTokenSilently()` pour obtenir un access token sans second login.
9. Le widget appelle `/api/widget-data` avec ce token.
10. Le backend valide l'access token du widget avec les JWKS Auth0 et l'audience `https://widget-api-lab`.

## Configuration Auth0 utilisée

```txt
Domain: dev-81jhzrtfubrnornr.us.auth0.com
Backend Client ID: wOB0YonouyCXQyVMumcnzCMUuGEbY7UV
Widget Client ID: E5DP7D6eLcinUpMUktNKjxl4pAyaHvES
Widget API Audience: https://widget-api-lab
```

## Variables d'environnement

Créer un fichier `.env` à partir de `.env.example`.

```bash
cp .env.example .env
```

Remplacer :

```txt
AUTH0_CLIENT_SECRET=PASTE_BACKEND_CLIENT_SECRET_HERE
SESSION_SECRET=replace-with-a-long-random-string
```

Pour générer un secret local :

```bash
openssl rand -hex 32
```

## Démarrage local

```bash
node server.js
```

Puis ouvrir :

```txt
http://localhost:3000/protected
```

## Routes principales

- `/` : accueil
- `/login` : démarre le login backend Auth0
- `/callback` : callback Auth0 backend
- `/protected` : page protégée par session serveur
- `/logout` : logout local + Auth0
- `/public/widget.html` : widget SPA
- `/config.json` : config publique du widget
- `/api/widget-data` : API protégée par access token du widget

## Important

Ce projet ne met jamais le `Client Secret` côté navigateur.

Le `Backend Client ID`, le `Widget Client ID`, le `Domain` et l'`Audience` peuvent être publics. Le `Client Secret` doit rester uniquement dans `.env` ou dans les variables d'environnement de l'hébergeur.
