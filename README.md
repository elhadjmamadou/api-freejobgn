# API FreeJobGN

API REST pour la plateforme FreeJobGN, développée avec Django et Django REST Framework.

## 🚀 Technologies

- **Python** 3.x
- **Django** 6.0.1
- **Django REST Framework** 3.16.1

## 📁 Structure du projet

```
api-freejobgn/
├── config/          # Configuration du projet Django
│   ├── settings.py  # Paramètres du projet
│   ├── urls.py      # URLs principales
│   └── wsgi.py      # Configuration WSGI
├── users/           # Application de gestion des utilisateurs
│   ├── models.py    # Modèles de données
│   ├── views.py     # Vues/Endpoints
│   └── admin.py     # Configuration admin
├── manage.py        # Script de gestion Django
└── requirements.txt # Dépendances Python
```

## ⚙️ Installation

### Prérequis

- Python 3.10 ou supérieur
- pip (gestionnaire de paquets Python)

### Étapes d'installation

1. **Cloner le dépôt**
   ```bash
   git clone <url-du-repo>
   cd api-freejobgn
   ```

2. **Créer un environnement virtuel**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   # ou
   venv\Scripts\activate     # Windows
   ```

3. **Installer les dépendances**
   ```bash
   pip install -r requirements.txt
   ```

4. **Appliquer les migrations**
   ```bash
   python manage.py migrate
   ```

5. **Lancer le serveur de développement**
   ```bash
   python manage.py runserver
   ```

L'API sera accessible à l'adresse : `http://127.0.0.1:8000/`

## 🔧 Commandes utiles

```bash
# Créer un superutilisateur
python manage.py createsuperuser

# Créer de nouvelles migrations
python manage.py makemigrations

# Appliquer les migrations
python manage.py migrate

# Lancer les tests
python manage.py test

# Lancer le shell Django
python manage.py shell
```

## 📝 Licence

Ce projet est sous licence MIT.

## 👥 Auteurs

- FreeJobGN Team
