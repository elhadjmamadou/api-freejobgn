"""
URLs pour l'authentification.
"""

from django.urls import path

from .views import (
    RegisterView,
    ActivateView,
    ResendActivationView,
    LoginView,
    TokenRefreshView,
    LogoutView,
    MeView,
    RegistrationOptionsView,
    PublicStatsView,
)

app_name = "users"

urlpatterns = [
    # Métadonnées publiques (stateless)
    path(
        "register/options/", RegistrationOptionsView.as_view(), name="register-options"
    ),
    path("public/stats/", PublicStatsView.as_view(), name="public-stats"),
    # Inscription et activation
    path("register/", RegisterView.as_view(), name="register"),
    path("activate/", ActivateView.as_view(), name="activate"),
    path(
        "resend-activation/", ResendActivationView.as_view(), name="resend-activation"
    ),
    # Authentification
    path("login/", LoginView.as_view(), name="login"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),
    # Utilisateur courant
    path("me/", MeView.as_view(), name="me"),
]
