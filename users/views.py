"""
Vues d'authentification pour l'API FreeJobGN.
"""

from django.conf import settings as django_settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import status, generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from drf_spectacular.utils import (
    extend_schema,
    OpenApiResponse,
    OpenApiExample,
    PolymorphicProxySerializer,
)
from drf_spectacular.types import OpenApiTypes

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
    ClientProfileReadSerializer,
    ClientProfileCreateSerializer,
    ClientProfileUpdateSerializer,
    ClientProfileErrorSerializer,
    ClientProfileIndividualCreateSchema,
    ClientProfileCompanyCreateSchema,
    ClientCompanyDocumentReadSerializer,
    ClientCompanyDocumentCreateSerializer,
    ClientCompanyDocumentUpdateSerializer,
)
from .tokens import activation_token_generator, decode_uid
from .emails import send_activation_email
from .models import (
    UserRole,
    ProviderKind,
    ClientProfile,
    ClientType,
    ClientCompanyDocument,
    ClientCompanyDetails,
)
from .models import UserRole, ProviderKind, ProviderProfile

from rest_framework.generics import CreateAPIView, RetrieveUpdateAPIView, ListAPIView, RetrieveAPIView
from rest_framework.parsers import JSONParser, MultiPartParser, FormParser
from drf_spectacular.utils import extend_schema, OpenApiParameter
from .permissions import IsFreelance
from .serializers import ProviderProfileFreelanceSerializer
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from .models import FreelanceDocument, FreelanceDocumentType
from .serializers import FreelanceDocumentSerializer
from rest_framework.exceptions import APIException

from .permissions import IsAgency
from .models import AgencyDocument
from .serializers import ProviderProfileAgencySerializer, AgencyDocumentSerializer



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
            old_refresh = RefreshToken(refresh_token)

            # Récupérer l'utilisateur depuis le token
            user_id = old_refresh.get("user_id")
            if not user_id:
                raise TokenError("Token invalide")

            user = User.objects.get(pk=user_id)

            # Générer un nouveau refresh token pour cet utilisateur (rotation)
            new_refresh = RefreshToken.for_user(user)

            # Blacklister l'ancien refresh token
            if hasattr(old_refresh, "blacklist"):
                try:
                    old_refresh.blacklist()
                except Exception:
                    pass  # Blacklist non configurée ou déjà blacklisté

            # Nouveau access token depuis le nouveau refresh
            new_access = str(new_refresh.access_token)

            response = Response({"access": new_access}, status=status.HTTP_200_OK)

            # Mettre à jour le cookie avec le nouveau refresh token
            set_refresh_cookie(response, str(new_refresh))

            return response

        except (TokenError, User.DoesNotExist):
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
            200: OpenApiResponse(
                response=RegistrationOptionsSerializer,
                description="Options d'inscription récupérées avec succès.",
                examples=[
                    OpenApiExample(
                        name="Exemple de réponse",
                        summary="Options d'inscription complètes",
                        description="Retourne les rôles, types de prestataire et règles de validation.",
                        value={
                            "roles": [
                                {"value": "CLIENT", "label": "Client"},
                                {"value": "PROVIDER", "label": "Prestataire"},
                            ],
                            "provider_kinds": [
                                {"value": "FREELANCE", "label": "Freelance"},
                                {"value": "AGENCY", "label": "Agence"},
                            ],
                            "rules": {
                                "provider_kind_required_if_role": "PROVIDER",
                                "provider_kind_forbidden_if_role": "CLIENT",
                            },
                        },
                        response_only=True,
                    ),
                ],
            ),
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


# ============================================================
# Profil Client (CRUD)
# ============================================================


class IsClientUser:
    """
    Permission custom pour vérifier que l'utilisateur a le rôle CLIENT.
    """

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.role == UserRole.CLIENT
        )


@extend_schema(tags=["Client Profile"])
class ClientProfileMeView(APIView):
    """
    Endpoint unique pour gérer le profil du client connecté.

    - GET: Lire le profil (ou null si non créé)
    - POST: Créer le profil (une seule fois)
    - PATCH: Mettre à jour le profil existant
    """

    permission_classes = [IsAuthenticated]

    def _check_client_role(self, request):
        """
        Vérifie que l'utilisateur a le rôle CLIENT.
        Retourne une Response d'erreur ou None si OK.
        """
        if request.user.role != UserRole.CLIENT:
            return Response(
                {
                    "code": "wrong_role",
                    "detail": "Seuls les utilisateurs avec le rôle CLIENT peuvent accéder à ce profil.",
                },
                status=status.HTTP_403_FORBIDDEN,
            )
        return None

    def _get_profile_or_none(self, user):
        """Retourne le ClientProfile de l'utilisateur ou None."""
        try:
            return user.client_profile
        except ClientProfile.DoesNotExist:
            return None

    @extend_schema(
        responses={
            200: OpenApiResponse(
                response=ClientProfileReadSerializer,
                description="Profil client récupéré avec succès.",
                examples=[
                    OpenApiExample(
                        name="Profil particulier existant",
                        value={
                            "user": {
                                "id": 1,
                                "email": "client@example.com",
                                "username": "johndoe",
                                "role": "CLIENT",
                            },
                            "client_profile": {
                                "id": 1,
                                "client_type": "INDIVIDUAL",
                                "city_or_region": "Conakry",
                                "country": "Guinée",
                                "postal_code": "",
                                "phone": "+224 123 456 789",
                                "profile_picture": None,
                                "details": {
                                    "first_name": "John",
                                    "last_name": "Doe",
                                },
                                "created_at": "2026-02-01T10:00:00+00:00",
                                "updated_at": "2026-02-01T10:00:00+00:00",
                            },
                        },
                        response_only=True,
                    ),
                    OpenApiExample(
                        name="Profil non créé",
                        value={
                            "user": {
                                "id": 1,
                                "email": "client@example.com",
                                "username": "johndoe",
                                "role": "CLIENT",
                            },
                            "client_profile": None,
                        },
                        response_only=True,
                    ),
                ],
            ),
            401: OpenApiResponse(
                response=ClientProfileErrorSerializer,
                description="Non authentifié.",
            ),
            403: OpenApiResponse(
                response=ClientProfileErrorSerializer,
                description="Rôle incorrect (pas CLIENT).",
            ),
        },
        summary="Lire le profil client",
        description=(
            "Retourne le profil client de l'utilisateur connecté. "
            "Si le profil n'existe pas encore, retourne client_profile=null."
        ),
    )
    def get(self, request):
        # Vérifier le rôle
        error = self._check_client_role(request)
        if error:
            return error

        # Retourner le profil (ou null)
        serializer = ClientProfileReadSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @extend_schema(
        request=PolymorphicProxySerializer(
            component_name="ClientProfileCreateRequest",
            serializers={
                "INDIVIDUAL": ClientProfileIndividualCreateSchema,
                "COMPANY": ClientProfileCompanyCreateSchema,
            },
            resource_type_field_name="client_type",
        ),
        responses={
            201: OpenApiResponse(
                response=ClientProfileReadSerializer,
                description="Profil client créé avec succès.",
                examples=[
                    OpenApiExample(
                        name="Création particulier",
                        value={
                            "user": {
                                "id": 1,
                                "email": "client@example.com",
                                "username": "johndoe",
                                "role": "CLIENT",
                            },
                            "client_profile": {
                                "id": 1,
                                "client_type": "INDIVIDUAL",
                                "city_or_region": "Conakry",
                                "country": "Guinée",
                                "postal_code": "",
                                "phone": "",
                                "profile_picture": None,
                                "details": {
                                    "first_name": "John",
                                    "last_name": "Doe",
                                },
                                "created_at": "2026-02-01T10:00:00+00:00",
                                "updated_at": "2026-02-01T10:00:00+00:00",
                            },
                        },
                        response_only=True,
                    ),
                    OpenApiExample(
                        name="Création entreprise",
                        value={
                            "user": {
                                "id": 1,
                                "email": "company@example.com",
                                "username": "mycompany",
                                "role": "CLIENT",
                            },
                            "client_profile": {
                                "id": 2,
                                "client_type": "COMPANY",
                                "city_or_region": "Conakry",
                                "country": "Guinée",
                                "postal_code": "BP 100",
                                "phone": "+224 999 888 777",
                                "profile_picture": None,
                                "details": {
                                    "company_name": "Ma Super Entreprise",
                                },
                                "created_at": "2026-02-01T10:00:00+00:00",
                                "updated_at": "2026-02-01T10:00:00+00:00",
                            },
                        },
                        response_only=True,
                    ),
                ],
            ),
            400: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Erreur de validation.",
            ),
            401: OpenApiResponse(
                response=ClientProfileErrorSerializer,
                description="Non authentifié.",
            ),
            403: OpenApiResponse(
                response=ClientProfileErrorSerializer,
                description="Rôle incorrect (pas CLIENT).",
            ),
            409: OpenApiResponse(
                response=ClientProfileErrorSerializer,
                description="Profil déjà existant.",
                examples=[
                    OpenApiExample(
                        name="Profil existe déjà",
                        value={
                            "code": "profile_exists",
                            "detail": "Un profil client existe déjà pour cet utilisateur.",
                        },
                        response_only=True,
                    ),
                ],
            ),
        },
        summary="Créer le profil client",
        description=(
            "Crée le profil client de l'utilisateur connecté. "
            "Le client_type (INDIVIDUAL ou COMPANY) est immutable après création. "
            "Les champs requis dépendent du type choisi."
        ),
        examples=[
            OpenApiExample(
                name="Création particulier",
                value={
                    "client_type": "INDIVIDUAL",
                    "city_or_region": "Conakry",
                    "country": "Guinée",
                    "first_name": "John",
                    "last_name": "Doe",
                },
                request_only=True,
            ),
            OpenApiExample(
                name="Création entreprise",
                value={
                    "client_type": "COMPANY",
                    "city_or_region": "Conakry",
                    "country": "Guinée",
                    "postal_code": "BP 100",
                    "phone": "+224 999 888 777",
                    "company_name": "Ma Super Entreprise",
                },
                request_only=True,
            ),
        ],
    )
    def post(self, request):
        # Vérifier le rôle
        error = self._check_client_role(request)
        if error:
            return error

        # Vérifier si un profil existe déjà
        if self._get_profile_or_none(request.user):
            return Response(
                {
                    "code": "profile_exists",
                    "detail": "Un profil client existe déjà pour cet utilisateur.",
                },
                status=status.HTTP_409_CONFLICT,
            )

        # Créer le profil
        serializer = ClientProfileCreateSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        # Retourner le profil complet
        response_serializer = ClientProfileReadSerializer(request.user)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    @extend_schema(
        request=ClientProfileUpdateSerializer,
        responses={
            200: OpenApiResponse(
                response=ClientProfileReadSerializer,
                description="Profil client mis à jour avec succès.",
            ),
            400: OpenApiResponse(
                response=ClientProfileErrorSerializer,
                description="Erreur de validation (ex: tentative de modifier client_type).",
                examples=[
                    OpenApiExample(
                        name="client_type immutable",
                        value={
                            "client_type": {
                                "code": "client_type_immutable",
                                "detail": "Le type de client ne peut pas être modifié après création.",
                            }
                        },
                        response_only=True,
                    ),
                ],
            ),
            401: OpenApiResponse(
                response=ClientProfileErrorSerializer,
                description="Non authentifié.",
            ),
            403: OpenApiResponse(
                response=ClientProfileErrorSerializer,
                description="Rôle incorrect (pas CLIENT).",
            ),
            409: OpenApiResponse(
                response=ClientProfileErrorSerializer,
                description="Profil non créé.",
                examples=[
                    OpenApiExample(
                        name="Profil non existant",
                        value={
                            "code": "profile_not_created",
                            "detail": "Aucun profil client n'existe. Utilisez POST pour créer.",
                        },
                        response_only=True,
                    ),
                ],
            ),
        },
        summary="Mettre à jour le profil client",
        description=(
            "Met à jour partiellement le profil client existant. "
            "Le client_type ne peut PAS être modifié."
        ),
        examples=[
            OpenApiExample(
                name="Mise à jour particulier",
                value={
                    "city_or_region": "Kindia",
                    "first_name": "Johnny",
                },
                request_only=True,
            ),
            OpenApiExample(
                name="Mise à jour entreprise",
                value={
                    "phone": "+224 111 222 333",
                    "company_name": "Nouvelle Raison Sociale",
                },
                request_only=True,
            ),
        ],
    )
    def patch(self, request):
        # Vérifier le rôle
        error = self._check_client_role(request)
        if error:
            return error

        # Vérifier que le profil existe
        profile = self._get_profile_or_none(request.user)
        if not profile:
            return Response(
                {
                    "code": "profile_not_created",
                    "detail": "Aucun profil client n'existe. Utilisez POST pour créer.",
                },
                status=status.HTTP_409_CONFLICT,
            )

        # Mettre à jour
        serializer = ClientProfileUpdateSerializer(
            instance=profile,
            data=request.data,
            partial=True,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        # Retourner le profil complet
        response_serializer = ClientProfileReadSerializer(request.user)
        return Response(response_serializer.data, status=status.HTTP_200_OK)


# ============================================================
# Documents d'entreprise Client (CRUD)
# ============================================================


class ClientCompanyDocumentMixin:
    """
    Mixin pour la vérification du profil entreprise.
    Utilisé par les vues de documents.
    """

    def _get_company_or_error(self, request):
        """
        Retourne le ClientCompanyDetails du user ou une Response d'erreur.
        Returns: (company, error_response) - l'un des deux est None
        """
        # Vérifier authentification
        if not request.user.is_authenticated:
            return None, Response(
                {"code": "not_authenticated", "detail": "Authentification requise."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Vérifier rôle CLIENT
        if request.user.role != UserRole.CLIENT:
            return None, Response(
                {
                    "code": "wrong_role",
                    "detail": "Seuls les utilisateurs CLIENT peuvent accéder aux documents.",
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        # Vérifier profil existe
        try:
            profile = request.user.client_profile
        except ClientProfile.DoesNotExist:
            return None, Response(
                {
                    "code": "profile_not_created",
                    "detail": "Vous devez d'abord créer votre profil client.",
                },
                status=status.HTTP_409_CONFLICT,
            )

        # Vérifier client_type = COMPANY
        if profile.client_type != ClientType.COMPANY:
            return None, Response(
                {
                    "code": "company_profile_required",
                    "detail": "Les documents ne sont disponibles que pour les clients entreprise.",
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        # Récupérer company_details
        try:
            company = profile.company_details
        except ClientCompanyDetails.DoesNotExist:
            return None, Response(
                {
                    "code": "company_details_missing",
                    "detail": "Les détails de l'entreprise sont manquants.",
                },
                status=status.HTTP_409_CONFLICT,
            )

        return company, None


@extend_schema(tags=["Client Company Documents"])
class ClientCompanyDocumentListCreateView(
    ClientCompanyDocumentMixin, generics.ListCreateAPIView
):
    """
    Liste et création des documents d'entreprise du client connecté.

    - GET: Liste tous les documents de l'entreprise
    - POST: Upload un nouveau document (multipart/form-data)
    """

    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method == "POST":
            return ClientCompanyDocumentCreateSerializer
        return ClientCompanyDocumentReadSerializer

    def get_queryset(self):
        """Retourne uniquement les documents de l'entreprise du user connecté."""
        company, _ = self._get_company_or_error(self.request)
        if company:
            return ClientCompanyDocument.objects.filter(company=company).order_by(
                "-created_at"
            )
        return ClientCompanyDocument.objects.none()

    @extend_schema(
        responses={
            200: OpenApiResponse(
                response=ClientCompanyDocumentReadSerializer(many=True),
                description="Liste des documents de l'entreprise.",
                examples=[
                    OpenApiExample(
                        name="Liste avec documents",
                        value=[
                            {
                                "id": 1,
                                "doc_type": "RCCM",
                                "doc_type_display": "RCCM",
                                "reference_number": "GN-2026-12345",
                                "file_url": "http://localhost:8000/media/users/1/rccm.pdf",
                                "created_at": "2026-02-01T10:00:00Z",
                            },
                            {
                                "id": 2,
                                "doc_type": "LEGAL",
                                "doc_type_display": "Document juridique",
                                "reference_number": "",
                                "file_url": "http://localhost:8000/media/users/1/statuts.pdf",
                                "created_at": "2026-02-01T11:00:00Z",
                            },
                        ],
                        response_only=True,
                    ),
                ],
            ),
            401: OpenApiResponse(
                response=ClientProfileErrorSerializer, description="Non authentifié."
            ),
            403: OpenApiResponse(
                response=ClientProfileErrorSerializer,
                description="Rôle incorrect ou profil non entreprise.",
            ),
            409: OpenApiResponse(
                response=ClientProfileErrorSerializer,
                description="Profil non créé ou détails manquants.",
            ),
        },
        summary="Lister les documents entreprise",
        description="Retourne la liste des documents de l'entreprise du client connecté.",
    )
    def get(self, request, *args, **kwargs):
        company, error = self._get_company_or_error(request)
        if error:
            return error
        return super().get(request, *args, **kwargs)

    @extend_schema(
        request={
            "multipart/form-data": {
                "type": "object",
                "properties": {
                    "doc_type": {"type": "string", "enum": ["RCCM", "LEGAL", "OTHER"]},
                    "file": {"type": "string", "format": "binary"},
                    "reference_number": {"type": "string"},
                },
                "required": ["doc_type", "file"],
            }
        },
        responses={
            201: OpenApiResponse(
                response=ClientCompanyDocumentReadSerializer,
                description="Document créé avec succès.",
                examples=[
                    OpenApiExample(
                        name="Document créé",
                        value={
                            "id": 1,
                            "doc_type": "RCCM",
                            "doc_type_display": "RCCM",
                            "reference_number": "GN-2026-12345",
                            "file_url": "http://localhost:8000/media/users/1/rccm.pdf",
                            "created_at": "2026-02-01T10:00:00Z",
                        },
                        response_only=True,
                    ),
                ],
            ),
            400: OpenApiResponse(
                response=ErrorResponseSerializer, description="Erreur de validation."
            ),
            401: OpenApiResponse(
                response=ClientProfileErrorSerializer, description="Non authentifié."
            ),
            403: OpenApiResponse(
                response=ClientProfileErrorSerializer,
                description="Rôle incorrect ou profil non entreprise.",
            ),
            409: OpenApiResponse(
                response=ClientProfileErrorSerializer,
                description="Profil non créé.",
            ),
        },
        summary="Uploader un document entreprise",
        description="Upload un nouveau document pour l'entreprise du client connecté. Utiliser multipart/form-data.",
    )
    def post(self, request, *args, **kwargs):
        company, error = self._get_company_or_error(request)
        if error:
            return error

        serializer = ClientCompanyDocumentCreateSerializer(
            data=request.data, context={"request": request, "company": company}
        )
        serializer.is_valid(raise_exception=True)
        document = serializer.save()

        # Retourner le document créé avec le serializer de lecture
        response_serializer = ClientCompanyDocumentReadSerializer(
            document, context={"request": request}
        )
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)


@extend_schema(tags=["Client Company Documents"])
class ClientCompanyDocumentDetailView(
    ClientCompanyDocumentMixin, generics.RetrieveUpdateDestroyAPIView
):
    """
    Détail, mise à jour et suppression d'un document d'entreprise.

    - GET: Détail d'un document
    - PATCH: Mise à jour (doc_type, reference_number) sans changer le fichier
    - DELETE: Suppression du document
    """

    permission_classes = [IsAuthenticated]
    lookup_field = "pk"

    def get_serializer_class(self):
        if self.request.method in ["PATCH", "PUT"]:
            return ClientCompanyDocumentUpdateSerializer
        return ClientCompanyDocumentReadSerializer

    def get_queryset(self):
        """Retourne uniquement les documents de l'entreprise du user connecté."""
        company, _ = self._get_company_or_error(self.request)
        if company:
            return ClientCompanyDocument.objects.filter(company=company)
        return ClientCompanyDocument.objects.none()

    def _check_access(self, request):
        """Vérifie l'accès et retourne une erreur si nécessaire."""
        company, error = self._get_company_or_error(request)
        if error:
            return error
        return None

    @extend_schema(
        responses={
            200: ClientCompanyDocumentReadSerializer,
            401: ClientProfileErrorSerializer,
            403: ClientProfileErrorSerializer,
            404: ClientProfileErrorSerializer,
        },
        summary="Détail d'un document",
        description="Retourne les détails d'un document de l'entreprise.",
    )
    def get(self, request, *args, **kwargs):
        error = self._check_access(request)
        if error:
            return error
        return super().get(request, *args, **kwargs)

    @extend_schema(
        request=ClientCompanyDocumentUpdateSerializer,
        responses={
            200: OpenApiResponse(
                response=ClientCompanyDocumentReadSerializer,
                description="Document mis à jour.",
            ),
            400: ErrorResponseSerializer,
            401: ClientProfileErrorSerializer,
            403: ClientProfileErrorSerializer,
            404: ClientProfileErrorSerializer,
        },
        summary="Modifier un document",
        description="Modifie le type ou la référence d'un document (sans changer le fichier).",
    )
    def patch(self, request, *args, **kwargs):
        error = self._check_access(request)
        if error:
            return error

        instance = self.get_object()
        serializer = ClientCompanyDocumentUpdateSerializer(
            instance, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        # Retourner avec le serializer de lecture
        response_serializer = ClientCompanyDocumentReadSerializer(
            instance, context={"request": request}
        )
        return Response(response_serializer.data, status=status.HTTP_200_OK)

    @extend_schema(
        responses={
            204: OpenApiResponse(description="Document supprimé."),
            401: ClientProfileErrorSerializer,
            403: ClientProfileErrorSerializer,
            404: ClientProfileErrorSerializer,
        },
        summary="Supprimer un document",
        description="Supprime un document de l'entreprise.",
    )
    def delete(self, request, *args, **kwargs):
        error = self._check_access(request)
        if error:
            return error

@extend_schema(tags=["Freelance Profile"])
class FreelanceProfileInitView(CreateAPIView):
    """
    Création initiale du profil freelance (ProviderProfile + FreelanceDetails).
    """
    permission_classes = [IsFreelance]
    serializer_class = ProviderProfileFreelanceSerializer
    parser_classes = [JSONParser, MultiPartParser, FormParser]

    @extend_schema(
        summary="Initialiser mon profil freelance",
        description="Crée ProviderProfile + FreelanceDetails pour l'utilisateur connecté (FREELANCE).",
        responses={
            201: ProviderProfileFreelanceSerializer,
            400: OpenApiResponse(description="Erreur de validation"),
            409: OpenApiResponse(description="Profil déjà existant"),
        },
    )
    def post(self, request, *args, **kwargs):
        if hasattr(request.user, "provider_profile"):
            return Response({"detail": "Profil déjà existant."}, status=status.HTTP_409_CONFLICT)
        return super().post(request, *args, **kwargs)


@extend_schema(tags=["Freelance Profile"])
class FreelanceMeProfileView(RetrieveUpdateAPIView):
    """
    Récupérer / modifier mon profil freelance.
    """
    permission_classes = [IsFreelance]
    serializer_class = ProviderProfileFreelanceSerializer
    parser_classes = [JSONParser, MultiPartParser, FormParser]

    def get_object(self):
        # 404 si non initialisé
        return (
            ProviderProfile.objects
            .select_related("user", "speciality", "freelance_details")
            .prefetch_related("skills")
            .get(user=self.request.user)
        )

    @extend_schema(
        summary="Lire mon profil freelance",
        responses={200: ProviderProfileFreelanceSerializer, 404: OpenApiResponse(description="Profil non initialisé")},
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @extend_schema(
        summary="Mettre à jour mon profil freelance",
        description="PATCH recommandé. Supporte profile_picture via multipart/form-data.",
        responses={200: ProviderProfileFreelanceSerializer, 400: OpenApiResponse(description="Erreur de validation")},
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)


# ---------------------------
# Public browsing (clients)
# ---------------------------

@extend_schema(tags=["Freelancers Public"])
class FreelancePublicListView(ListAPIView):
    permission_classes = [AllowAny]
    serializer_class = ProviderProfileFreelanceSerializer

    def get_queryset(self):
        qs = (
            ProviderProfile.objects
            .select_related("user", "speciality", "freelance_details")
            .prefetch_related("skills")
            .filter(
                user__is_active=True,
                user__role=UserRole.PROVIDER,
                user__provider_kind=ProviderKind.FREELANCE,
            )
            .distinct()
            .order_by("-updated_at")
        )

        country = self.request.query_params.get("country")
        city = self.request.query_params.get("city")
        speciality_id = self.request.query_params.get("speciality_id")
        skill_id = self.request.query_params.get("skill_id")

        if country:
            qs = qs.filter(country__iexact=country)
        if city:
            qs = qs.filter(city_or_region__icontains=city)
        if speciality_id:
            qs = qs.filter(speciality_id=speciality_id)
        if skill_id:
            qs = qs.filter(skills__id=skill_id)

        return qs

    @extend_schema(
        summary="Lister les freelances (public)",
        parameters=[
            OpenApiParameter(name="country", required=False, type=str),
            OpenApiParameter(name="city", required=False, type=str),
            OpenApiParameter(name="speciality_id", required=False, type=int),
            OpenApiParameter(name="skill_id", required=False, type=int),
        ],
        responses={200: ProviderProfileFreelanceSerializer(many=True)},
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


@extend_schema(tags=["Freelancers Public"])
class FreelancePublicDetailView(RetrieveAPIView):
    permission_classes = [AllowAny]
    serializer_class = ProviderProfileFreelanceSerializer
    lookup_field = "pk"

    def get_queryset(self):
        return (
            ProviderProfile.objects
            .select_related("user", "speciality", "freelance_details")
            .prefetch_related("skills")
            .filter(
                user__is_active=True,
                user__role=UserRole.PROVIDER,
                user__provider_kind=ProviderKind.FREELANCE,
            )
        )

    @extend_schema(
        summary="Détail d’un freelance (public)",
        responses={200: ProviderProfileFreelanceSerializer, 404: OpenApiResponse(description="Not found")},
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


@extend_schema(tags=["Freelance Documents"])
class FreelanceDocumentListCreateView(ListCreateAPIView):
    """
    Lister + uploader les documents du freelance connecté.
    """
    permission_classes = [IsAuthenticated, IsFreelance]
    serializer_class = FreelanceDocumentSerializer
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get_queryset(self):
        return (
            FreelanceDocument.objects
            .select_related("provider_profile", "provider_profile__user")
            .filter(provider_profile__user=self.request.user)
            .order_by("-created_at")
        )

    @extend_schema(
        summary="Lister mes documents (freelance)",
        parameters=[
            OpenApiParameter(
                name="doc_type",
                required=False,
                type=str,
                description="Filtrer par type (ex: CV, CERTIFICATION, PORTFOLIO...)",
            ),
        ],
        responses={200: FreelanceDocumentSerializer(many=True)},
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def list(self, request, *args, **kwargs):
        qs = self.get_queryset()
        doc_type = request.query_params.get("doc_type")
        if doc_type:
            qs = qs.filter(doc_type=doc_type)
        page = self.paginate_queryset(qs)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)

    @extend_schema(
        summary="Uploader un document (freelance)",
        description=(
            "Upload en multipart/form-data.\n\n"
            "Champs requis: doc_type, file.\n"
            "Champs optionnels: title, reference_number, issued_at."
        ),
        responses={
            201: FreelanceDocumentSerializer,
            400: OpenApiResponse(description="Erreur de validation"),
        },
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def perform_create(self, serializer):
        # on force le rattachement au freelance connecté
        provider_profile = self.request.user.provider_profile
        serializer.save(provider_profile=provider_profile)


@extend_schema(tags=["Freelance Documents"])
class FreelanceDocumentDetailView(RetrieveUpdateDestroyAPIView):
    """
    Lire / modifier / supprimer un document appartenant au freelance connecté.
    """
    permission_classes = [IsAuthenticated, IsFreelance]
    serializer_class = FreelanceDocumentSerializer
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get_queryset(self):
        # sécurité: accès uniquement aux docs du user connecté
        return FreelanceDocument.objects.filter(provider_profile__user=self.request.user)

    @extend_schema(
        summary="Détail d’un document (freelance)",
        responses={200: FreelanceDocumentSerializer, 404: OpenApiResponse(description="Not found")},
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @extend_schema(
        summary="Mettre à jour un document (freelance)",
        description="PATCH recommandé. Tu peux remplacer le file si tu veux, ou juste title/reference_number/issued_at.",
        responses={200: FreelanceDocumentSerializer, 400: OpenApiResponse(description="Erreur de validation")},
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)

    @extend_schema(
        summary="Supprimer un document (freelance)",
        responses={204: OpenApiResponse(description="Deleted")},
    )
    def delete(self, request, *args, **kwargs):
        return super().delete(request, *args, **kwargs)


class AgencyProfileNotInitialized(APIException):
    status_code = 409
    default_detail = "Profil agence non initialisé. Faites d'abord /api/agency/profile/init/."
    default_code = "agency_profile_not_initialized"


@extend_schema(tags=["Agency Profile"])
class AgencyProfileInitView(CreateAPIView):
    """
    Création initiale du profil agence (ProviderProfile + AgencyDetails).
    """
    permission_classes = [IsAgency]
    serializer_class = ProviderProfileAgencySerializer
    parser_classes = [JSONParser, MultiPartParser, FormParser]

    @extend_schema(
        summary="Initialiser mon profil agence",
        description="Crée ProviderProfile + AgencyDetails pour l'utilisateur connecté (AGENCY).",
        responses={
            201: ProviderProfileAgencySerializer,
            400: OpenApiResponse(description="Erreur de validation"),
            409: OpenApiResponse(description="Profil déjà existant"),
        },
    )
    def post(self, request, *args, **kwargs):
        if hasattr(request.user, "provider_profile"):
            return Response({"detail": "Profil déjà existant."}, status=status.HTTP_409_CONFLICT)
        return super().post(request, *args, **kwargs)


@extend_schema(tags=["Agency Profile"])
class AgencyMeProfileView(RetrieveUpdateAPIView):
    """
    Lire / modifier mon profil agence.
    """
    permission_classes = [IsAgency]
    serializer_class = ProviderProfileAgencySerializer
    parser_classes = [JSONParser, MultiPartParser, FormParser]

    def get_object(self):
        return (
            ProviderProfile.objects
            .select_related("user", "speciality", "agency_details")
            .prefetch_related("skills")
            .get(user=self.request.user)
        )

    @extend_schema(
        summary="Lire mon profil agence",
        responses={200: ProviderProfileAgencySerializer, 404: OpenApiResponse(description="Profil non initialisé")},
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @extend_schema(
        summary="Mettre à jour mon profil agence",
        description="PATCH recommandé. Supporte profile_picture via multipart/form-data.",
        responses={200: ProviderProfileAgencySerializer, 400: OpenApiResponse(description="Erreur de validation")},
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)


# ---------------------------
# Public agencies (clients)
# ---------------------------

@extend_schema(tags=["Agencies Public"])
class AgencyPublicListView(ListAPIView):
    permission_classes = [AllowAny]
    serializer_class = ProviderProfileAgencySerializer

    def get_queryset(self):
        qs = (
            ProviderProfile.objects
            .select_related("user", "speciality", "agency_details")
            .prefetch_related("skills")
            .filter(
                user__is_active=True,
                user__role=UserRole.PROVIDER,
                user__provider_kind=ProviderKind.AGENCY,
            )
            .distinct()
            .order_by("-updated_at")
        )

        country = self.request.query_params.get("country")
        city = self.request.query_params.get("city")
        speciality_id = self.request.query_params.get("speciality_id")
        skill_id = self.request.query_params.get("skill_id")

        if country:
            qs = qs.filter(country__iexact=country)
        if city:
            qs = qs.filter(city_or_region__icontains=city)
        if speciality_id:
            qs = qs.filter(speciality_id=speciality_id)
        if skill_id:
            qs = qs.filter(skills__id=skill_id)

        return qs

    @extend_schema(
        summary="Lister les agences (public)",
        parameters=[
            OpenApiParameter(name="country", required=False, type=str),
            OpenApiParameter(name="city", required=False, type=str),
            OpenApiParameter(name="speciality_id", required=False, type=int),
            OpenApiParameter(name="skill_id", required=False, type=int),
        ],
        responses={200: ProviderProfileAgencySerializer(many=True)},
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


@extend_schema(tags=["Agencies Public"])
class AgencyPublicDetailView(RetrieveAPIView):
    permission_classes = [AllowAny]
    serializer_class = ProviderProfileAgencySerializer
    lookup_field = "pk"

    def get_queryset(self):
        return (
            ProviderProfile.objects
            .select_related("user", "speciality", "agency_details")
            .prefetch_related("skills")
            .filter(
                user__is_active=True,
                user__role=UserRole.PROVIDER,
                user__provider_kind=ProviderKind.AGENCY,
            )
        )


# ---------------------------
# Agency documents (private)
# ---------------------------

@extend_schema(tags=["Agency Documents"])
class AgencyDocumentListCreateView(ListCreateAPIView):
    permission_classes = [IsAuthenticated, IsAgency]
    serializer_class = AgencyDocumentSerializer
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def _agency_details(self):
        user = self.request.user
        if not hasattr(user, "provider_profile") or not hasattr(user.provider_profile, "agency_details"):
            raise AgencyProfileNotInitialized()
        return user.provider_profile.agency_details

    def get_queryset(self):
        agency = self._agency_details()
        return (
            AgencyDocument.objects
            .select_related("agency", "agency__provider_profile", "agency__provider_profile__user")
            .filter(agency=agency)
            .order_by("-created_at")
        )

    @extend_schema(
        summary="Lister mes documents (agence)",
        parameters=[
            OpenApiParameter(name="doc_type", required=False, type=str),
        ],
        responses={
            200: AgencyDocumentSerializer(many=True),
            409: OpenApiResponse(description="Profil non initialisé"),
        },
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def list(self, request, *args, **kwargs):
        qs = self.get_queryset()
        doc_type = request.query_params.get("doc_type")
        if doc_type:
            qs = qs.filter(doc_type=doc_type)

        page = self.paginate_queryset(qs)
        if page is not None:
            ser = self.get_serializer(page, many=True)
            return self.get_paginated_response(ser.data)

        ser = self.get_serializer(qs, many=True)
        return Response(ser.data)

    @extend_schema(
        summary="Uploader un document (agence)",
        description="multipart/form-data. Champs requis: doc_type, file. Optionnel: reference_number.",
        responses={
            201: AgencyDocumentSerializer,
            400: OpenApiResponse(description="Erreur de validation"),
            409: OpenApiResponse(description="Profil non initialisé"),
        },
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def perform_create(self, serializer):
        serializer.save(agency=self._agency_details())


@extend_schema(tags=["Agency Documents"])
class AgencyDocumentDetailView(RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated, IsAgency]
    serializer_class = AgencyDocumentSerializer
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def _agency_details(self):
        user = self.request.user
        if not hasattr(user, "provider_profile") or not hasattr(user.provider_profile, "agency_details"):
            raise AgencyProfileNotInitialized()
        return user.provider_profile.agency_details

    def get_queryset(self):
        return AgencyDocument.objects.filter(agency=self._agency_details())

    @extend_schema(
        summary="Détail d’un document agence",
        responses={
            200: AgencyDocumentSerializer,
            404: OpenApiResponse(description="Not found"),
            409: OpenApiResponse(description="Profil non initialisé"),
        },
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @extend_schema(
        summary="Mettre à jour un document agence",
        description="PATCH recommandé. Tu peux remplacer le file ou juste reference_number.",
        responses={200: AgencyDocumentSerializer, 400: OpenApiResponse(description="Erreur de validation")},
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)

    @extend_schema(
        summary="Supprimer un document agence",
        responses={204: OpenApiResponse(description="Deleted")},
    )
    def delete(self, request, *args, **kwargs):
        return super().delete(request, *args, **kwargs)
