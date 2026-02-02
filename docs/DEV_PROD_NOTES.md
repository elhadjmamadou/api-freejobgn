# 🔧 Notes de Développement et Production

## Configuration des variables d'environnement

### Fichier `.env` (développement)

```bash
# Django Settings
DEBUG=True
SECRET_KEY=dev-secret-key-not-for-production

# Allowed Hosts
ALLOWED_HOSTS=localhost,127.0.0.1

# Email (console pour dev)
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
DEFAULT_FROM_EMAIL=noreply@freejobgn.com

# Frontend URL (pour les liens d'activation)
FRONTEND_URL=http://localhost:3000

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# JWT
ACCESS_TOKEN_LIFETIME_MINUTES=15
REFRESH_TOKEN_LIFETIME_DAYS=7

# Activation Token
ACTIVATION_TOKEN_EXPIRY_HOURS=24
```

### Variables de production

```bash
# Django Settings
DEBUG=False
SECRET_KEY=<clé-secrète-générée-avec-django-get-random-secret-key>

# Allowed Hosts
ALLOWED_HOSTS=api.freejobgn.com,freejobgn.com

# Database (PostgreSQL recommandé)
DATABASE_URL=postgres://user:password@localhost:5432/freejobgn

# Email (SMTP réel)
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.sendgrid.net
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=apikey
EMAIL_HOST_PASSWORD=<your-sendgrid-api-key>
DEFAULT_FROM_EMAIL=noreply@freejobgn.com

# Frontend URL
FRONTEND_URL=https://freejobgn.com

# CORS
CORS_ALLOWED_ORIGINS=https://freejobgn.com,https://www.freejobgn.com

# JWT (ajuster selon vos besoins de sécurité)
ACCESS_TOKEN_LIFETIME_MINUTES=15
REFRESH_TOKEN_LIFETIME_DAYS=7

# Activation Token
ACTIVATION_TOKEN_EXPIRY_HOURS=24
```

---

## Configuration CORS pour SPA React

### Points clés

1. **`CORS_ALLOW_CREDENTIALS = True`** : Permet l'envoi des cookies (refresh token)
2. **`CORS_ALLOWED_ORIGINS`** : Liste des origines autorisées (frontend)
3. **Cookie `SameSite`** :
   - **Dev** : `Lax` (même domaine)
   - **Prod** : `None` (cross-origin, requiert `Secure=True`)

### Problèmes courants

| Problème              | Solution                                            |
| --------------------- | --------------------------------------------------- |
| Cookie non envoyé     | Vérifier `withCredentials: true` côté frontend      |
| CORS bloqué           | Ajouter l'origine frontend à `CORS_ALLOWED_ORIGINS` |
| Cookie rejeté en prod | S'assurer que `Secure=True` et connexion HTTPS      |

---

## Durées des tokens

### Configuration par défaut

| Token            | Durée   | Usage                     |
| ---------------- | ------- | ------------------------- |
| Access Token     | 15 min  | Authentification API      |
| Refresh Token    | 7 jours | Renouvellement de session |
| Activation Token | 24h     | Activation du compte      |

### Ajustement

- **Access Token** : Plus court = plus sécurisé, mais plus de refreshs
- **Refresh Token** : Plus long = meilleure UX, mais risque si compromis
- **Activation Token** : 24h est standard, peut être réduit à 1h si besoin

---

## Email Backend

### Développement (console)

```python
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
```

Les emails s'affichent dans la console du serveur Django.

### Production (SMTP)

```python
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.sendgrid.net'  # ou autre fournisseur
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'apikey'
EMAIL_HOST_PASSWORD = '<api-key>'
```

### Fournisseurs recommandés

- **SendGrid** : Gratuit jusqu'à 100 emails/jour
- **Mailgun** : Flexible, bonne délivrabilité
- **Amazon SES** : Économique à grande échelle
- **Postmark** : Excellent pour emails transactionnels

---

## Commandes utiles

### Développement

```bash
# Activer l'environnement virtuel
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt

# Appliquer les migrations
python manage.py migrate

# Créer un superutilisateur
python manage.py createsuperuser

# Lancer le serveur
python manage.py runserver

# Lancer les tests
python manage.py test users

# Générer le schéma OpenAPI
python manage.py spectacular --file schema.yaml
```

### Production

```bash
# Collecter les fichiers statiques
python manage.py collectstatic --noinput

# Vérifier la configuration
python manage.py check --deploy

# Appliquer les migrations
python manage.py migrate --noinput

# Lancer avec Gunicorn
gunicorn config.wsgi:application --bind 0.0.0.0:8000
```

---

## Sécurité en production

### Checklist

- [ ] `DEBUG=False`
- [ ] `SECRET_KEY` unique et sécurisée
- [ ] `ALLOWED_HOSTS` configuré
- [ ] HTTPS obligatoire
- [ ] `SECURE_SSL_REDIRECT=True`
- [ ] `SESSION_COOKIE_SECURE=True`
- [ ] `CSRF_COOKIE_SECURE=True`
- [ ] Base de données PostgreSQL (pas SQLite)
- [ ] Variables d'environnement (pas de secrets dans le code)

### Ajouts recommandés pour `settings.py` en production

```python
if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31536000  # 1 an
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
```

---

## Architecture des endpoints

```
/api/auth/
├── register/           POST  - Inscription
├── activate/           POST  - Activation du compte
├── resend-activation/  POST  - Renvoyer l'email d'activation
├── login/              POST  - Connexion (retourne access, set cookie refresh)
├── token/refresh/      POST  - Rafraîchir l'access token
├── logout/             POST  - Déconnexion
└── me/                 GET   - Utilisateur courant

/api/schema/            GET   - Schéma OpenAPI
/                       GET   - Swagger UI
/api/redoc/             GET   - ReDoc
/admin/                 GET   - Django Admin
```

---

## Structure des fichiers créés/modifiés

```
api-freejobgn/
├── .env                          # Variables d'environnement (gitignore)
├── .env.example                  # Exemple de configuration
├── config/
│   ├── settings.py               # Configuration Django (modifié)
│   └── urls.py                   # URLs principales (modifié)
├── users/
│   ├── admin.py                  # Configuration admin (modifié)
│   ├── emails.py                 # Envoi d'emails (nouveau)
│   ├── serializers.py            # Serializers DRF (nouveau)
│   ├── tests.py                  # Tests unitaires (modifié)
│   ├── tokens.py                 # Génération tokens (nouveau)
│   ├── urls.py                   # URLs auth (nouveau)
│   └── views.py                  # Vues API (modifié)
├── templates/
│   └── users/
│       └── emails/
│           └── activation.html   # Template email (nouveau)
└── docs/
    ├── FRONTEND_INTEGRATION.md   # Guide React (nouveau)
    └── DEV_PROD_NOTES.md         # Ce fichier (nouveau)
```
