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
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample

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
