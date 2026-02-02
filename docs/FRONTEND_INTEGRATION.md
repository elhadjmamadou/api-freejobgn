# 🔐 Notes d'intégration Frontend React

## Configuration de l'API

### Base URL

```javascript
const API_BASE_URL = "http://localhost:8000/api";
```

### Configuration Axios (recommandé)

```javascript
// api/axios.js
import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:8000/api",
  withCredentials: true, // IMPORTANT: Permet l'envoi des cookies
  headers: {
    "Content-Type": "application/json",
  },
});

// Intercepteur pour ajouter le token d'accès
api.interceptors.request.use((config) => {
  const accessToken = localStorage.getItem("accessToken");
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

// Intercepteur pour gérer le refresh automatique
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Si 401 et pas déjà retry
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        // Tenter le refresh (le cookie est envoyé automatiquement)
        const response = await axios.post(
          "http://localhost:8000/api/auth/token/refresh/",
          {},
          { withCredentials: true },
        );

        const { access } = response.data;
        localStorage.setItem("accessToken", access);

        // Retry la requête originale
        originalRequest.headers.Authorization = `Bearer ${access}`;
        return api(originalRequest);
      } catch (refreshError) {
        // Refresh échoué, déconnecter l'utilisateur
        localStorage.removeItem("accessToken");
        window.location.href = "/login";
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  },
);

export default api;
```

---

## Parcours "Choix du rôle" avant inscription

### Workflow complet

```
┌─────────────────┐
│  Landing Page   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      GET /api/auth/register/options/
│  Choix du rôle  │◄─────────────────────────────────────
│  CLIENT/PROVIDER│
└────────┬────────┘
         │
         ▼ (si PROVIDER)
┌─────────────────┐
│  Choix du type  │
│ FREELANCE/AGENCY│
└────────┬────────┘
         │
         ▼
┌─────────────────┐      POST /api/auth/register/
│   Formulaire    │◄────────────────────────────
│  d'inscription  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Check email    │
│  pour activation│
└─────────────────┘
```

### 1. Récupérer les options d'inscription (endpoint public)

```javascript
// GET /api/auth/register/options/
// Aucune authentification requise
const getRegistrationOptions = async () => {
  const response = await api.get("/auth/register/options/");
  return response.data;
};

// Réponse:
// {
//   "roles": [
//     { "value": "CLIENT", "label": "Client" },
//     { "value": "PROVIDER", "label": "Prestataire" }
//   ],
//   "provider_kinds": [
//     { "value": "FREELANCE", "label": "Freelance" },
//     { "value": "AGENCY", "label": "Agence" }
//   ],
//   "rules": {
//     "provider_kind_required_if_role": "PROVIDER",
//     "provider_kind_forbidden_if_role": "CLIENT"
//   }
// }
```

### 2. Récupérer les statistiques publiques (optionnel)

```javascript
// GET /api/auth/public/stats/
// Utile pour afficher des stats sur l'écran de choix
const getPublicStats = async () => {
  const response = await api.get("/auth/public/stats/");
  return response.data;
};

// Réponse:
// {
//   "clients_count": 150,
//   "providers_count": 75,
//   "freelances_count": 60,
//   "agencies_count": 15
// }
```

### 3. Composant React "Choix du rôle"

```jsx
// pages/ChooseRolePage.jsx
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/axios";

const ChooseRolePage = () => {
  const navigate = useNavigate();
  const [options, setOptions] = useState(null);
  const [stats, setStats] = useState(null);
  const [selectedRole, setSelectedRole] = useState(null);
  const [selectedProviderKind, setSelectedProviderKind] = useState(null);

  // Charger les options au mount
  useEffect(() => {
    const fetchData = async () => {
      const [optionsRes, statsRes] = await Promise.all([
        api.get("/auth/register/options/"),
        api.get("/auth/public/stats/"),
      ]);
      setOptions(optionsRes.data);
      setStats(statsRes.data);
    };
    fetchData();
  }, []);

  // Vérifier si provider_kind est requis
  const needsProviderKind =
    selectedRole === options?.rules?.provider_kind_required_if_role;

  // Gérer la soumission
  const handleContinue = () => {
    if (!selectedRole) return;
    if (needsProviderKind && !selectedProviderKind) return;

    // Stocker temporairement pour le formulaire suivant
    sessionStorage.setItem("registrationRole", selectedRole);
    sessionStorage.setItem(
      "registrationProviderKind",
      selectedProviderKind || "",
    );

    navigate("/register");
  };

  if (!options) return <div>Chargement...</div>;

  return (
    <div className="choose-role-page">
      <h1>Créez votre compte FreeJobGN</h1>

      {/* Stats optionnelles */}
      {stats && (
        <div className="stats-banner">
          <span>{stats.clients_count} clients</span>
          <span>{stats.providers_count} prestataires</span>
        </div>
      )}

      {/* Choix du rôle */}
      <h2>Vous êtes...</h2>
      <div className="role-cards">
        {options.roles.map((role) => (
          <button
            key={role.value}
            className={`role-card ${selectedRole === role.value ? "selected" : ""}`}
            onClick={() => {
              setSelectedRole(role.value);
              // Reset provider_kind si on change de rôle
              if (role.value !== options.rules.provider_kind_required_if_role) {
                setSelectedProviderKind(null);
              }
            }}
          >
            {role.label}
          </button>
        ))}
      </div>

      {/* Choix du type de prestataire (si PROVIDER) */}
      {needsProviderKind && (
        <>
          <h2>Quel type de prestataire ?</h2>
          <div className="provider-kind-cards">
            {options.provider_kinds.map((pk) => (
              <button
                key={pk.value}
                className={`pk-card ${selectedProviderKind === pk.value ? "selected" : ""}`}
                onClick={() => setSelectedProviderKind(pk.value)}
              >
                {pk.label}
              </button>
            ))}
          </div>
        </>
      )}

      <button
        className="continue-btn"
        onClick={handleContinue}
        disabled={!selectedRole || (needsProviderKind && !selectedProviderKind)}
      >
        Continuer vers l'inscription
      </button>
    </div>
  );
};

export default ChooseRolePage;
```

### 4. Formulaire d'inscription adapté

```jsx
// pages/RegisterPage.jsx
import { useState, useEffect } from "react";
import api from "../api/axios";

const RegisterPage = () => {
  const [formData, setFormData] = useState({
    email: "",
    username: "",
    password: "",
    password_confirm: "",
    role: "",
    provider_kind: null,
  });

  // Récupérer le rôle pré-sélectionné
  useEffect(() => {
    const role = sessionStorage.getItem("registrationRole");
    const providerKind = sessionStorage.getItem("registrationProviderKind");

    if (role) {
      setFormData((prev) => ({
        ...prev,
        role,
        provider_kind: providerKind || null,
      }));
    }
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const response = await api.post("/auth/register/", formData);
      // Nettoyer sessionStorage
      sessionStorage.removeItem("registrationRole");
      sessionStorage.removeItem("registrationProviderKind");

      // Rediriger vers page de confirmation
      navigate("/check-email", { state: { email: formData.email } });
    } catch (error) {
      // Gérer les erreurs de validation
      console.error(error.response?.data);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h1>
        Inscription {formData.role === "PROVIDER" ? "Prestataire" : "Client"}
      </h1>

      {/* Afficher le type si prestataire */}
      {formData.provider_kind && (
        <p className="badge">{formData.provider_kind}</p>
      )}

      <input
        type="email"
        placeholder="Email"
        value={formData.email}
        onChange={(e) => setFormData({ ...formData, email: e.target.value })}
        required
      />

      <input
        type="text"
        placeholder="Nom d'utilisateur"
        value={formData.username}
        onChange={(e) => setFormData({ ...formData, username: e.target.value })}
        required
      />

      <input
        type="password"
        placeholder="Mot de passe"
        value={formData.password}
        onChange={(e) => setFormData({ ...formData, password: e.target.value })}
        required
      />

      <input
        type="password"
        placeholder="Confirmer le mot de passe"
        value={formData.password_confirm}
        onChange={(e) =>
          setFormData({ ...formData, password_confirm: e.target.value })
        }
        required
      />

      {/* Champs cachés pour le role */}
      <input type="hidden" name="role" value={formData.role} />
      <input
        type="hidden"
        name="provider_kind"
        value={formData.provider_kind || ""}
      />

      <button type="submit">Créer mon compte</button>
    </form>
  );
};

export default RegisterPage;
```

---

## Endpoints d'authentification

### 1. Inscription

```javascript
// POST /api/auth/register/
const register = async (data) => {
  const response = await api.post("/auth/register/", {
    email: "user@example.com",
    username: "johndoe",
    password: "SecurePass123!",
    password_confirm: "SecurePass123!",
    role: "CLIENT", // ou 'PROVIDER'
    provider_kind: null, // 'FREELANCE' ou 'AGENCY' si role=PROVIDER
  });

  // Réponse: { message: '...', needs_activation: true, email: '...' }
  return response.data;
};
```

### 2. Activation du compte

```javascript
// POST /api/auth/activate/
// Les paramètres uid et token viennent de l'URL d'activation
const activate = async (uid, token) => {
  const response = await api.post("/auth/activate/", { uid, token });
  return response.data; // { message: 'Compte activé...' }
};

// Page d'activation React
const ActivationPage = () => {
  const searchParams = new URLSearchParams(window.location.search);
  const uid = searchParams.get("uid");
  const token = searchParams.get("token");

  useEffect(() => {
    if (uid && token) {
      activate(uid, token)
        .then(() => navigate("/login"))
        .catch(handleError);
    }
  }, [uid, token]);
};
```

### 3. Connexion

```javascript
// POST /api/auth/login/
const login = async (email, password) => {
  const response = await api.post("/auth/login/", { email, password });

  // Le refresh token est automatiquement stocké dans un cookie HttpOnly
  // Stocker l'access token en mémoire (ou localStorage pour persister)
  const { access, user } = response.data;
  localStorage.setItem("accessToken", access);

  return user;
};
```

### 4. Refresh du token

```javascript
// POST /api/auth/token/refresh/
// Le refresh token est dans le cookie, rien à envoyer dans le body
const refreshToken = async () => {
  const response = await api.post("/auth/token/refresh/");
  const { access } = response.data;
  localStorage.setItem("accessToken", access);
  return access;
};
```

### 5. Déconnexion

```javascript
// POST /api/auth/logout/
const logout = async () => {
  await api.post("/auth/logout/");
  localStorage.removeItem("accessToken");
  // Le cookie refresh est supprimé côté serveur
};
```

### 6. Utilisateur courant

```javascript
// GET /api/auth/me/
const getCurrentUser = async () => {
  const response = await api.get("/auth/me/");
  return response.data;
  // { id, email, username, role, provider_kind, is_active, date_joined }
};
```

### 7. Renvoyer l'email d'activation

```javascript
// POST /api/auth/resend-activation/
const resendActivation = async (email) => {
  const response = await api.post("/auth/resend-activation/", { email });
  return response.data;
};
```

---

## Gestion des erreurs

### Codes de réponse

| Code | Signification                           |
| ---- | --------------------------------------- |
| 200  | Succès                                  |
| 201  | Création réussie                        |
| 400  | Erreur de validation                    |
| 401  | Non authentifié (token invalide/expiré) |
| 403  | Compte non activé                       |
| 429  | Rate limit atteint                      |

### Exemple de gestion d'erreur

```javascript
try {
  await login(email, password);
} catch (error) {
  if (error.response?.status === 403) {
    // Compte non activé
    const { needs_activation, email } = error.response.data;
    if (needs_activation) {
      // Proposer de renvoyer l'email d'activation
      showResendActivationModal(email);
    }
  } else if (error.response?.status === 400) {
    // Erreur de validation (mauvais identifiants)
    setError(error.response.data.detail);
  } else if (error.response?.status === 429) {
    // Trop de tentatives
    setError("Trop de tentatives. Réessayez plus tard.");
  }
}
```

---

## Cookie Refresh Token

### Comportement

- **Nom**: `refresh_token`
- **HttpOnly**: `true` (non accessible via JavaScript)
- **Secure**: `true` en production (HTTPS uniquement)
- **SameSite**: `None` en production, `Lax` en développement
- **Path**: `/api/auth/` (envoyé uniquement pour les routes auth)
- **Durée**: 7 jours par défaut

### Important pour le développement local

Si vous développez avec le frontend sur `localhost:3000` et le backend sur `localhost:8000`:

1. Assurez-vous que `withCredentials: true` est configuré
2. Le backend a `CORS_ALLOW_CREDENTIALS = True`
3. L'origine frontend est dans `CORS_ALLOWED_ORIGINS`

---

## Context React (exemple)

```javascript
// contexts/AuthContext.jsx
import { createContext, useContext, useState, useEffect } from "react";
import api from "../api/axios";

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Vérifier si l'utilisateur est connecté au chargement
    const checkAuth = async () => {
      const token = localStorage.getItem("accessToken");
      if (token) {
        try {
          const response = await api.get("/auth/me/");
          setUser(response.data);
        } catch {
          localStorage.removeItem("accessToken");
        }
      }
      setLoading(false);
    };
    checkAuth();
  }, []);

  const login = async (email, password) => {
    const response = await api.post("/auth/login/", { email, password });
    localStorage.setItem("accessToken", response.data.access);
    setUser(response.data.user);
    return response.data.user;
  };

  const logout = async () => {
    await api.post("/auth/logout/");
    localStorage.removeItem("accessToken");
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
```

---

## Notes de sécurité

1. **Ne jamais stocker le refresh token en JavaScript** - Il est dans un cookie HttpOnly
2. **L'access token peut être en localStorage** - Durée courte (15 min)
3. **Toujours utiliser HTTPS en production**
4. **Le refresh automatique gère la session** - L'utilisateur reste connecté
