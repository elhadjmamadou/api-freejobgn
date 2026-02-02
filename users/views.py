"""
Vues d'authentification pour l'API FreeJobGN.
"""

from django.conf import settings as django_settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from drf_spectacular.utils import extend_schema, OpenApiResponse

from .serializers import (
    RegisterSerializer,
    RegisterResponseSerializer,
    ActivationSerializer,
    ActivationResponseSerializer,
    ResendActivationSerializer,
    ResendActivationResponseSerializer,
    LoginSerializer,
    LoginResponseSerializer,
    TokenRefreshResponseSerializer,
    LogoutResponseSerializer,
    UserMeSerializer,
    ErrorResponseSerializer,
    RegistrationOptionsSerializer,
    PublicStatsSerializer,
)
from .tokens import activation_token_generator, decode_uid
from .emails import send_activation_email
from .models import UserRole, ProviderKind

User = get_user_model()


# ============================================================
# Throttling personnalisé
# ============================================================


class AuthAnonRateThrottle(AnonRateThrottle):
    """Rate limit pour les endpoints auth anonymes."""

    rate = "5/minute"

    def allow_request(self, request, view):
        # Désactiver le throttling en mode test
        if getattr(django_settings, "TESTING", False):
            return True
        return super().allow_request(request, view)


class AuthUserRateThrottle(UserRateThrottle):
    """Rate limit pour les endpoints auth authentifiés."""

    rate = "10/minute"

    def allow_request(self, request, view):
        # Désactiver le throttling en mode test
        if getattr(django_settings, "TESTING", False):
            return True
        return super().allow_request(request, view)


class ResendActivationThrottle(AnonRateThrottle):
    """Rate limit strict pour le renvoi d'activation."""

    rate = "3/hour"

    def allow_request(self, request, view):
        # Désactiver le throttling en mode test
        if getattr(django_settings, "TESTING", False):
            return True
        return super().allow_request(request, view)


# ============================================================
# Helper pour les cookies
# ============================================================


def get_refresh_cookie_settings():
    """Retourne les paramètres du cookie refresh token."""
    from django.conf import settings

    # En production, Secure=True et SameSite=None pour cross-origin
    # En dev, Secure=False et SameSite=Lax
    is_production = not getattr(settings, "DEBUG", True)

    return {
        "key": "refresh_token",
        "httponly": True,
        "secure": is_production,
        "samesite": "None" if is_production else "Lax",
        "path": "/api/auth/",  # Cookie uniquement pour les routes auth
    }


def set_refresh_cookie(response, refresh_token: str):
    """Ajoute le cookie refresh token à la réponse."""
    from django.conf import settings
    from datetime import timedelta

    cookie_settings = get_refresh_cookie_settings()
    refresh_lifetime_days = getattr(settings, "REFRESH_TOKEN_LIFETIME_DAYS", 7)

    response.set_cookie(
        key=cookie_settings["key"],
        value=str(refresh_token),
        max_age=int(timedelta(days=refresh_lifetime_days).total_seconds()),
        httponly=cookie_settings["httponly"],
        secure=cookie_settings["secure"],
        samesite=cookie_settings["samesite"],
        path=cookie_settings["path"],
    )


def delete_refresh_cookie(response):
    """Supprime le cookie refresh token."""
    cookie_settings = get_refresh_cookie_settings()
    response.delete_cookie(
        key=cookie_settings["key"],
        path=cookie_settings["path"],
        samesite=cookie_settings["samesite"],
    )


# ============================================================
# Vues d'authentification
# ============================================================


@extend_schema(tags=["Authentication"])
class RegisterView(APIView):
    """
    Inscription d'un nouvel utilisateur.

    Crée un compte inactif et envoie un email d'activation.
    """

    permission_classes = [AllowAny]
    throttle_classes = [AuthAnonRateThrottle]

    @extend_schema(
        request=RegisterSerializer,
        responses={
            201: RegisterResponseSerializer,
            400: OpenApiResponse(description="Erreur de validation"),
        },
        summary="Inscription utilisateur",
        description="Crée un nouveau compte utilisateur. Un email d'activation est envoyé.",
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.save()

        # Envoi de l'email d'activation
        email_sent = send_activation_email(user)

        return Response(
            {
                "message": "Compte créé avec succès. Vérifiez votre email pour activer votre compte.",
                "needs_activation": True,
                "email": user.email,
            },
            status=status.HTTP_201_CREATED,
        )


@extend_schema(tags=["Authentication"])
class ActivateView(APIView):
    """
    Activation du compte utilisateur via token.
    """

    permission_classes = [AllowAny]
    throttle_classes = [AuthAnonRateThrottle]

    @extend_schema(
        request=ActivationSerializer,
        responses={
            200: ActivationResponseSerializer,
            400: ErrorResponseSerializer,
        },
        summary="Activation du compte",
        description="Active le compte utilisateur avec le token reçu par email.",
    )
    def post(self, request):
        serializer = ActivationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uid = decode_uid(serializer.validated_data["uid"])
        token = serializer.validated_data["token"]

        if uid is None:
            return Response(
                {"detail": "Lien d'activation invalide."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(pk=uid)
        except User.DoesNotExist:
            return Response(
                {"detail": "Lien d'activation invalide."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Vérifier si déjà actif
        if user.is_active:
            return Response(
                {"detail": "Ce compte est déjà activé."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Valider le token
        if not activation_token_generator.validate_token(user, token):
            # Vérifier si expiré pour un meilleur message
            if activation_token_generator.check_token_expired(token):
                return Response(
                    {
                        "detail": "Le lien d'activation a expiré. Demandez un nouveau lien."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            return Response(
                {"detail": "Lien d'activation invalide."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Activer l'utilisateur
        user.is_active = True
        user.save(update_fields=["is_active"])

        return Response(
            {
                "message": "Compte activé avec succès. Vous pouvez maintenant vous connecter."
            },
            status=status.HTTP_200_OK,
        )


@extend_schema(tags=["Authentication"])
class ResendActivationView(APIView):
    """
    Renvoi de l'email d'activation.
    """

    permission_classes = [AllowAny]
    throttle_classes = [ResendActivationThrottle]

    @extend_schema(
        request=ResendActivationSerializer,
        responses={
            200: ResendActivationResponseSerializer,
            400: ErrorResponseSerializer,
        },
        summary="Renvoyer l'email d'activation",
        description="Renvoie l'email d'activation si le compte existe et n'est pas activé.",
    )
    def post(self, request):
        serializer = ResendActivationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"].lower()

        # Message générique pour ne pas divulguer l'existence des comptes
        success_message = (
            "Si un compte non activé existe avec cet email, "
            "un nouveau lien d'activation a été envoyé."
        )

        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            # On retourne succès même si le compte n'existe pas
            return Response({"message": success_message}, status=status.HTTP_200_OK)

        if user.is_active:
            # Compte déjà activé, on retourne quand même succès
            return Response({"message": success_message}, status=status.HTTP_200_OK)

        # Envoyer le nouvel email
        send_activation_email(user)

        return Response({"message": success_message}, status=status.HTTP_200_OK)


@extend_schema(tags=["Authentication"])
class LoginView(APIView):
    """
    Connexion utilisateur.

    Retourne un access token en JSON et set le refresh token en cookie HttpOnly.
    """

    permission_classes = [AllowAny]
    throttle_classes = [AuthAnonRateThrottle]

    @extend_schema(
        request=LoginSerializer,
        responses={
            200: LoginResponseSerializer,
            400: ErrorResponseSerializer,
            403: ErrorResponseSerializer,
        },
        summary="Connexion",
        description="Authentifie l'utilisateur et retourne les tokens JWT.",
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"].lower()
        password = serializer.validated_data["password"]

        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            return Response(
                {"detail": "Email ou mot de passe incorrect."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not user.check_password(password):
            return Response(
                {"detail": "Email ou mot de passe incorrect."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Vérifier si le compte est activé
        if not user.is_active:
            return Response(
                {
                    "detail": "Votre compte n'est pas activé. Vérifiez votre email ou demandez un nouveau lien d'activation.",
                    "needs_activation": True,
                    "email": user.email,
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        # Générer les tokens JWT
        refresh = RefreshToken.for_user(user)
        access = str(refresh.access_token)

        # Préparer la réponse
        response_data = {
            "access": access,
            "user": UserMeSerializer(user).data,
        }

        response = Response(response_data, status=status.HTTP_200_OK)

        # Set le refresh token dans un cookie HttpOnly
        set_refresh_cookie(response, str(refresh))

        return response


@extend_schema(tags=["Authentication"])
class TokenRefreshView(APIView):
    """
    Rafraîchissement du token d'accès.

    Utilise le refresh token depuis le cookie HttpOnly.
    """

    permission_classes = [AllowAny]
    throttle_classes = [AuthUserRateThrottle]

    @extend_schema(
        request=None,
        responses={
            200: TokenRefreshResponseSerializer,
            401: ErrorResponseSerializer,
        },
        summary="Rafraîchir le token",
        description="Génère un nouveau access token à partir du refresh token (cookie).",
    )
    def post(self, request):
        refresh_token = request.COOKIES.get("refresh_token")

        if not refresh_token:
            return Response(
                {"detail": "Refresh token manquant."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            refresh = RefreshToken(refresh_token)

            # Rotation du refresh token (optionnel mais recommandé)
            # Génère un nouveau refresh token et blacklist l'ancien
            if hasattr(refresh, "blacklist"):
                try:
                    refresh.blacklist()
                except Exception:
                    pass  # Blacklist non configurée

            # Nouveau access token
            new_access = str(refresh.access_token)

            # Option: créer un nouveau refresh token pour rotation
            # new_refresh = RefreshToken.for_user(user)

            response = Response({"access": new_access}, status=status.HTTP_200_OK)

            # Si rotation activée, mettre à jour le cookie
            # set_refresh_cookie(response, str(new_refresh))

            return response

        except TokenError:
            response = Response(
                {"detail": "Refresh token invalide ou expiré."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
            delete_refresh_cookie(response)
            return response


@extend_schema(tags=["Authentication"])
class LogoutView(APIView):
    """
    Déconnexion utilisateur.

    Supprime le cookie refresh token et optionnellement blacklist le token.
    """

    permission_classes = [AllowAny]  # Permet logout même avec token expiré

    @extend_schema(
        request=None,
        responses={
            200: LogoutResponseSerializer,
        },
        summary="Déconnexion",
        description="Déconnecte l'utilisateur et supprime le refresh token.",
    )
    def post(self, request):
        refresh_token = request.COOKIES.get("refresh_token")

        # Tenter de blacklister le token si possible
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                if hasattr(token, "blacklist"):
                    token.blacklist()
            except TokenError:
                pass  # Token déjà invalide, on continue

        response = Response(
            {"message": "Déconnexion réussie."}, status=status.HTTP_200_OK
        )

        # Supprimer le cookie
        delete_refresh_cookie(response)

        return response


@extend_schema(tags=["Authentication"])
class MeView(APIView):
    """
    Informations de l'utilisateur connecté.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={
            200: UserMeSerializer,
            401: ErrorResponseSerializer,
        },
        summary="Utilisateur courant",
        description="Retourne les informations de l'utilisateur authentifié.",
    )
    def get(self, request):
        serializer = UserMeSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


# ============================================================
# Endpoints publics de métadonnées (stateless)
# ============================================================


@extend_schema(tags=["Public Metadata"])
class RegistrationOptionsView(APIView):
    """
    Options d'inscription disponibles.

    Endpoint public (AllowAny) pour permettre au frontend React
    d'afficher la page "Choisis ton rôle" avant l'inscription.

    Retourne:
    - Liste des rôles disponibles (CLIENT, PROVIDER)
    - Liste des types de prestataire (FREELANCE, AGENCY)
    - Règles de validation (provider_kind requis si role=PROVIDER)
    """

    permission_classes = [AllowAny]
    throttle_classes = []  # Pas de rate limiting pour les métadonnées

    @extend_schema(
        responses={
            200: RegistrationOptionsSerializer,
        },
        summary="Options d'inscription",
        description=(
            "Retourne les options disponibles pour l'inscription: "
            "rôles, types de prestataire, et règles de validation. "
            "Endpoint public sans authentification."
        ),
    )
    def get(self, request):
        # Conversion des TextChoices en liste de dicts {value, label}
        roles = [{"value": choice.value, "label": choice.label} for choice in UserRole]
        provider_kinds = [
            {"value": choice.value, "label": choice.label} for choice in ProviderKind
        ]

        data = {
            "roles": roles,
            "provider_kinds": provider_kinds,
            "rules": {
                "provider_kind_required_if_role": UserRole.PROVIDER.value,
                "provider_kind_forbidden_if_role": UserRole.CLIENT.value,
            },
        }

        return Response(data, status=status.HTTP_200_OK)


@extend_schema(tags=["Public Metadata"])
class PublicStatsView(APIView):
    """
    Statistiques publiques.

    Endpoint public pour afficher des statistiques sur la landing page
    ou l'écran de choix de rôle.
    """

    permission_classes = [AllowAny]
    throttle_classes = []  # Pas de rate limiting pour les stats publiques

    @extend_schema(
        responses={
            200: PublicStatsSerializer,
        },
        summary="Statistiques publiques",
        description=(
            "Retourne des statistiques publiques sur les utilisateurs. "
            "Endpoint public sans authentification."
        ),
    )
    def get(self, request):
        # Compter uniquement les utilisateurs actifs
        clients_count = User.objects.filter(
            role=UserRole.CLIENT, is_active=True
        ).count()
        providers_count = User.objects.filter(
            role=UserRole.PROVIDER, is_active=True
        ).count()
        freelances_count = User.objects.filter(
            role=UserRole.PROVIDER,
            provider_kind=ProviderKind.FREELANCE,
            is_active=True,
        ).count()
        agencies_count = User.objects.filter(
            role=UserRole.PROVIDER,
            provider_kind=ProviderKind.AGENCY,
            is_active=True,
        ).count()

        data = {
            "clients_count": clients_count,
            "providers_count": providers_count,
            "freelances_count": freelances_count,
            "agencies_count": agencies_count,
        }

        return Response(data, status=status.HTTP_200_OK)
