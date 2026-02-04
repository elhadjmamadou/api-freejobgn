"""
Serializers pour l'authentification et la gestion des utilisateurs.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field, extend_schema_serializer
from drf_spectacular.extensions import OpenApiSerializerExtension

from .models import (
    UserRole,
    ProviderKind,
    ClientType,
    ClientProfile,
    ClientIndividualDetails,
    ClientCompanyDetails,
    ClientCompanyDocument,
    ClientCompanyDocumentType,
)

User = get_user_model()


class RegisterSerializer(serializers.Serializer):
    """
    Serializer pour l'inscription d'un nouvel utilisateur.
    """

    email = serializers.EmailField(
        required=True, help_text="Adresse email unique de l'utilisateur"
    )
    username = serializers.CharField(
        required=True,
        min_length=3,
        max_length=150,
        help_text="Nom d'utilisateur unique",
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"},
        help_text="Mot de passe (minimum 8 caractères, avec complexité)",
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"},
        help_text="Confirmation du mot de passe",
    )
    role = serializers.ChoiceField(
        choices=UserRole.choices, required=True, help_text="Rôle: CLIENT ou PROVIDER"
    )
    provider_kind = serializers.ChoiceField(
        choices=ProviderKind.choices,
        required=False,
        allow_null=True,
        allow_blank=True,
        help_text="Type de prestataire: FREELANCE ou AGENCY (requis si role=PROVIDER)",
    )

    def validate_email(self, value):
        """Vérifie que l'email n'est pas déjà utilisé."""
        email_lower = value.lower()
        if User.objects.filter(email__iexact=email_lower).exists():
            raise serializers.ValidationError("Un compte avec cet email existe déjà.")
        return email_lower

    def validate_username(self, value):
        """Vérifie que le username n'est pas déjà utilisé."""
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("Ce nom d'utilisateur est déjà pris.")
        return value

    def validate_password(self, value):
        """Valide la complexité du mot de passe avec les validators Django."""
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def validate(self, attrs):
        """Validation croisée des champs."""
        # Vérification correspondance mots de passe
        if attrs["password"] != attrs["password_confirm"]:
            raise serializers.ValidationError(
                {"password_confirm": "Les mots de passe ne correspondent pas."}
            )

        # Vérification cohérence role/provider_kind
        role = attrs.get("role")
        provider_kind = attrs.get("provider_kind")

        if role == UserRole.PROVIDER:
            if not provider_kind:
                raise serializers.ValidationError(
                    {
                        "provider_kind": "Le type de prestataire est requis pour un PROVIDER."
                    }
                )
        elif role == UserRole.CLIENT:
            if provider_kind:
                raise serializers.ValidationError(
                    {"provider_kind": "Un CLIENT ne doit pas avoir de provider_kind."}
                )
            # On force à None pour éviter les incohérences
            attrs["provider_kind"] = None

        return attrs

    def create(self, validated_data):
        """Crée l'utilisateur avec is_active=False."""
        validated_data.pop("password_confirm")
        password = validated_data.pop("password")

        user = User(
            email=validated_data["email"],
            username=validated_data["username"],
            role=validated_data["role"],
            provider_kind=validated_data.get("provider_kind"),
            is_active=False,  # Activation requise par email
        )
        user.set_password(password)
        user.full_clean()  # Valide les contraintes du modèle
        user.save()
        return user


class RegisterResponseSerializer(serializers.Serializer):
    """Serializer pour la réponse d'inscription."""

    message = serializers.CharField()
    needs_activation = serializers.BooleanField()
    email = serializers.EmailField()


class ActivationSerializer(serializers.Serializer):
    """Serializer pour l'activation du compte."""

    uid = serializers.CharField(
        required=True, help_text="Identifiant utilisateur encodé en base64"
    )
    token = serializers.CharField(required=True, help_text="Token d'activation signé")


class ActivationResponseSerializer(serializers.Serializer):
    """Serializer pour la réponse d'activation."""

    message = serializers.CharField()


class ResendActivationSerializer(serializers.Serializer):
    """Serializer pour renvoyer l'email d'activation."""

    email = serializers.EmailField(required=True, help_text="Email du compte à activer")


class ResendActivationResponseSerializer(serializers.Serializer):
    """Serializer pour la réponse de renvoi d'activation."""

    message = serializers.CharField()


class LoginSerializer(serializers.Serializer):
    """Serializer pour la connexion."""

    email = serializers.EmailField(required=True, help_text="Email de l'utilisateur")
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"},
        help_text="Mot de passe",
    )


class LoginResponseSerializer(serializers.Serializer):
    """Serializer pour la réponse de connexion."""

    access = serializers.CharField(help_text="JWT Access Token")
    user = serializers.SerializerMethodField()

    @extend_schema_field(serializers.DictField())
    def get_user(self, obj):
        return obj.get("user", {})


class TokenRefreshResponseSerializer(serializers.Serializer):
    """Serializer pour la réponse de refresh token."""

    access = serializers.CharField(help_text="Nouveau JWT Access Token")


class LogoutResponseSerializer(serializers.Serializer):
    """Serializer pour la réponse de déconnexion."""

    message = serializers.CharField()


class UserMeSerializer(serializers.ModelSerializer):
    """Serializer pour les informations de l'utilisateur connecté."""

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "username",
            "role",
            "provider_kind",
            "is_active",
            "date_joined",
        ]
        read_only_fields = fields


class ErrorResponseSerializer(serializers.Serializer):
    """Serializer générique pour les erreurs."""

    detail = serializers.CharField()


class ValidationErrorResponseSerializer(serializers.Serializer):
    """Serializer pour les erreurs de validation."""

    # Les erreurs de validation sont un dict avec les champs comme clés
    pass


# ============================================================
# Serializers pour les endpoints de métadonnées publiques
# ============================================================


class ChoiceItemSerializer(serializers.Serializer):
    """Représente un choix (value + label)."""

    value = serializers.CharField(help_text="Valeur technique")
    label = serializers.CharField(help_text="Libellé affiché")


class RegistrationRulesSerializer(serializers.Serializer):
    """Règles de validation pour l'inscription."""

    provider_kind_required_if_role = serializers.CharField(
        help_text="Role pour lequel provider_kind est requis"
    )
    provider_kind_forbidden_if_role = serializers.CharField(
        help_text="Role pour lequel provider_kind est interdit"
    )


class RegistrationOptionsSerializer(serializers.Serializer):
    """
    Options d'inscription disponibles pour le frontend.
    Permet d'afficher la page "Choisis ton rôle" côté React.
    """

    roles = ChoiceItemSerializer(many=True, help_text="Liste des rôles disponibles")
    provider_kinds = ChoiceItemSerializer(
        many=True, help_text="Liste des types de prestataire"
    )
    rules = RegistrationRulesSerializer(
        help_text="Règles de validation role/provider_kind"
    )


class PublicStatsSerializer(serializers.Serializer):
    """Statistiques publiques pour la landing page."""

    clients_count = serializers.IntegerField(help_text="Nombre de clients inscrits")
    providers_count = serializers.IntegerField(
        help_text="Nombre de prestataires inscrits"
    )
    freelances_count = serializers.IntegerField(help_text="Nombre de freelances")
    agencies_count = serializers.IntegerField(help_text="Nombre d'agences")


# ============================================================
# Serializers pour le profil Client
# ============================================================


class ClientUserSerializer(serializers.ModelSerializer):
    """Informations basiques de l'utilisateur pour le profil client."""

    class Meta:
        model = User
        fields = ["id", "email", "username", "role"]
        read_only_fields = fields


class ClientIndividualDetailsSerializer(serializers.ModelSerializer):
    """Serializer pour les détails d'un client particulier."""

    class Meta:
        model = ClientIndividualDetails
        fields = ["first_name", "last_name"]


class ClientCompanyDetailsSerializer(serializers.ModelSerializer):
    """Serializer pour les détails d'un client entreprise."""

    class Meta:
        model = ClientCompanyDetails
        fields = ["company_name"]


class ClientProfileReadSerializer(serializers.Serializer):
    """
    Serializer de lecture pour le profil client complet.
    Structure stable pour le frontend.
    """

    user = ClientUserSerializer(source="*", read_only=True)
    client_profile = serializers.SerializerMethodField()

    @extend_schema_field(serializers.DictField(allow_null=True))
    def get_client_profile(self, obj):
        """
        Retourne le profil client avec détails, ou None si non créé.
        obj = User instance
        """
        try:
            profile = obj.client_profile
        except ClientProfile.DoesNotExist:
            return None

        # Récupérer les détails selon le type
        details = None
        if profile.client_type == ClientType.INDIVIDUAL:
            try:
                details = ClientIndividualDetailsSerializer(
                    profile.individual_details
                ).data
            except ClientIndividualDetails.DoesNotExist:
                details = None
        elif profile.client_type == ClientType.COMPANY:
            try:
                details = ClientCompanyDetailsSerializer(profile.company_details).data
            except ClientCompanyDetails.DoesNotExist:
                details = None

        return {
            "id": profile.id,
            "client_type": profile.client_type,
            "city_or_region": profile.city_or_region,
            "country": profile.country,
            "postal_code": profile.postal_code,
            "phone": profile.phone,
            "profile_picture": (
                profile.profile_picture.url if profile.profile_picture else None
            ),
            "details": details,
            "created_at": profile.created_at.isoformat(),
            "updated_at": profile.updated_at.isoformat(),
        }


# ============================================================
# Serializers de documentation Swagger (oneOf pour création)
# ============================================================


@extend_schema_serializer(
    examples=[
        {
            "client_type": "INDIVIDUAL",
            "city_or_region": "Conakry",
            "country": "Guinée",
            "first_name": "John",
            "last_name": "Doe",
        }
    ]
)
class ClientProfileIndividualCreateSchema(serializers.Serializer):
    """
    Schéma Swagger pour la création d'un profil client PARTICULIER.
    Utilisé uniquement pour la documentation OpenAPI (oneOf).
    """

    client_type = serializers.ChoiceField(
        choices=[("INDIVIDUAL", "Particulier")],
        required=True,
        help_text="Type de client: doit être INDIVIDUAL",
    )
    city_or_region = serializers.CharField(
        max_length=120,
        required=True,
        help_text="Ville ou région",
    )
    country = serializers.CharField(
        max_length=120,
        required=True,
        help_text="Pays",
    )
    postal_code = serializers.CharField(
        max_length=20,
        required=False,
        allow_blank=True,
        help_text="Code postal (optionnel)",
    )
    phone = serializers.CharField(
        max_length=30,
        required=False,
        allow_blank=True,
        help_text="Téléphone (optionnel)",
    )
    first_name = serializers.CharField(
        max_length=80,
        required=True,
        help_text="Prénom (REQUIS pour INDIVIDUAL)",
    )
    last_name = serializers.CharField(
        max_length=80,
        required=True,
        help_text="Nom (REQUIS pour INDIVIDUAL)",
    )


@extend_schema_serializer(
    examples=[
        {
            "client_type": "COMPANY",
            "city_or_region": "Conakry",
            "country": "Guinée",
            "postal_code": "BP 100",
            "phone": "+224 999 888 777",
            "company_name": "Ma Super Entreprise",
        }
    ]
)
class ClientProfileCompanyCreateSchema(serializers.Serializer):
    """
    Schéma Swagger pour la création d'un profil client ENTREPRISE.
    Utilisé uniquement pour la documentation OpenAPI (oneOf).
    """

    client_type = serializers.ChoiceField(
        choices=[("COMPANY", "Entreprise")],
        required=True,
        help_text="Type de client: doit être COMPANY",
    )
    city_or_region = serializers.CharField(
        max_length=120,
        required=True,
        help_text="Ville ou région",
    )
    country = serializers.CharField(
        max_length=120,
        required=True,
        help_text="Pays",
    )
    postal_code = serializers.CharField(
        max_length=20,
        required=False,
        allow_blank=True,
        help_text="Code postal (optionnel)",
    )
    phone = serializers.CharField(
        max_length=30,
        required=False,
        allow_blank=True,
        help_text="Téléphone (optionnel)",
    )
    company_name = serializers.CharField(
        max_length=150,
        required=True,
        help_text="Nom de l'entreprise (REQUIS pour COMPANY)",
    )


class ClientProfileCreateSerializer(serializers.Serializer):
    """
    Serializer pour la création du profil client.
    Crée ClientProfile + Details selon client_type.
    """

    # Champs ClientProfile
    client_type = serializers.ChoiceField(
        choices=ClientType.choices,
        required=True,
        help_text="Type de client: INDIVIDUAL ou COMPANY",
    )
    city_or_region = serializers.CharField(
        max_length=120,
        required=True,
        help_text="Ville ou région",
    )
    country = serializers.CharField(
        max_length=120,
        required=True,
        help_text="Pays",
    )
    postal_code = serializers.CharField(
        max_length=20,
        required=False,
        allow_blank=True,
        default="",
        help_text="Code postal (optionnel)",
    )
    phone = serializers.CharField(
        max_length=30,
        required=False,
        allow_blank=True,
        default="",
        help_text="Téléphone (optionnel)",
    )

    # Champs pour INDIVIDUAL
    first_name = serializers.CharField(
        max_length=80,
        required=False,
        help_text="Prénom (requis si client_type=INDIVIDUAL)",
    )
    last_name = serializers.CharField(
        max_length=80,
        required=False,
        help_text="Nom (requis si client_type=INDIVIDUAL)",
    )

    # Champs pour COMPANY
    company_name = serializers.CharField(
        max_length=150,
        required=False,
        help_text="Nom de l'entreprise (requis si client_type=COMPANY)",
    )

    def validate(self, attrs):
        """Validation croisée selon client_type."""
        client_type = attrs.get("client_type")

        if client_type == ClientType.INDIVIDUAL:
            if not attrs.get("first_name"):
                raise serializers.ValidationError(
                    {"first_name": "Ce champ est requis pour un particulier."}
                )
            if not attrs.get("last_name"):
                raise serializers.ValidationError(
                    {"last_name": "Ce champ est requis pour un particulier."}
                )
        elif client_type == ClientType.COMPANY:
            if not attrs.get("company_name"):
                raise serializers.ValidationError(
                    {"company_name": "Ce champ est requis pour une entreprise."}
                )

        return attrs

    def create(self, validated_data):
        """Crée le profil client et les détails associés."""
        user = self.context["request"].user
        client_type = validated_data["client_type"]

        # Créer le ClientProfile
        profile = ClientProfile.objects.create(
            user=user,
            client_type=client_type,
            city_or_region=validated_data["city_or_region"],
            country=validated_data["country"],
            postal_code=validated_data.get("postal_code", ""),
            phone=validated_data.get("phone", ""),
        )

        # Créer les détails selon le type
        if client_type == ClientType.INDIVIDUAL:
            ClientIndividualDetails.objects.create(
                client_profile=profile,
                first_name=validated_data["first_name"],
                last_name=validated_data["last_name"],
            )
        elif client_type == ClientType.COMPANY:
            ClientCompanyDetails.objects.create(
                client_profile=profile,
                company_name=validated_data["company_name"],
            )

        return profile


class ClientProfileUpdateSerializer(serializers.Serializer):
    """
    Serializer pour la mise à jour partielle du profil client.
    client_type est immutable.
    """

    # Champs ClientProfile (tous optionnels pour PATCH)
    city_or_region = serializers.CharField(
        max_length=120,
        required=False,
        help_text="Ville ou région",
    )
    country = serializers.CharField(
        max_length=120,
        required=False,
        help_text="Pays",
    )
    postal_code = serializers.CharField(
        max_length=20,
        required=False,
        allow_blank=True,
        help_text="Code postal",
    )
    phone = serializers.CharField(
        max_length=30,
        required=False,
        allow_blank=True,
        help_text="Téléphone",
    )

    # Champs pour INDIVIDUAL
    first_name = serializers.CharField(
        max_length=80,
        required=False,
        help_text="Prénom (pour les particuliers)",
    )
    last_name = serializers.CharField(
        max_length=80,
        required=False,
        help_text="Nom (pour les particuliers)",
    )

    # Champs pour COMPANY
    company_name = serializers.CharField(
        max_length=150,
        required=False,
        help_text="Nom de l'entreprise (pour les entreprises)",
    )

    # client_type explicitement interdit
    client_type = serializers.CharField(required=False, write_only=True)

    def validate_client_type(self, value):
        """Interdit toute modification de client_type."""
        if value is not None:
            raise serializers.ValidationError(
                "Le type de client ne peut pas être modifié après création."
            )
        return value

    def validate(self, attrs):
        """Supprime client_type s'il est présent (déjà validé comme erreur si vraie valeur)."""
        # Si quelqu'un envoie client_type avec une valeur, l'erreur est levée dans validate_client_type
        # Si client_type n'est pas dans les données brutes, on continue normalement
        request = self.context.get("request")
        if request and hasattr(request, "data"):
            if "client_type" in request.data and request.data["client_type"]:
                raise serializers.ValidationError(
                    {
                        "client_type": {
                            "code": "client_type_immutable",
                            "detail": "Le type de client ne peut pas être modifié après création.",
                        }
                    }
                )
        attrs.pop("client_type", None)
        return attrs

    def update(self, instance, validated_data):
        """Met à jour le profil et ses détails."""
        profile = instance

        # Mise à jour des champs du profil
        profile_fields = ["city_or_region", "country", "postal_code", "phone"]
        for field in profile_fields:
            if field in validated_data:
                setattr(profile, field, validated_data[field])
        profile.save()

        # Mise à jour des détails selon le type
        if profile.client_type == ClientType.INDIVIDUAL:
            try:
                details = profile.individual_details
                if "first_name" in validated_data:
                    details.first_name = validated_data["first_name"]
                if "last_name" in validated_data:
                    details.last_name = validated_data["last_name"]
                details.save()
            except ClientIndividualDetails.DoesNotExist:
                pass

        elif profile.client_type == ClientType.COMPANY:
            try:
                details = profile.company_details
                if "company_name" in validated_data:
                    details.company_name = validated_data["company_name"]
                details.save()
            except ClientCompanyDetails.DoesNotExist:
                pass

        return profile


class ClientProfileErrorSerializer(serializers.Serializer):
    """Serializer pour les erreurs avec code."""

    code = serializers.CharField(help_text="Code d'erreur machine-readable")
    detail = serializers.CharField(help_text="Message d'erreur human-readable")


# ============================================================
# Serializers pour les documents d'entreprise Client
# ============================================================


class ClientCompanyDocumentReadSerializer(serializers.ModelSerializer):
    """Serializer de lecture pour les documents d'entreprise."""

    file_url = serializers.SerializerMethodField()
    doc_type_display = serializers.CharField(
        source="get_doc_type_display", read_only=True
    )

    class Meta:
        model = ClientCompanyDocument
        fields = [
            "id",
            "doc_type",
            "doc_type_display",
            "reference_number",
            "file_url",
            "created_at",
        ]
        read_only_fields = fields

    def get_file_url(self, obj) -> str | None:
        """Retourne l'URL du fichier."""
        if obj.file:
            request = self.context.get("request")
            if request:
                return request.build_absolute_uri(obj.file.url)
            return obj.file.url
        return None


class ClientCompanyDocumentCreateSerializer(serializers.ModelSerializer):
    """Serializer pour la création d'un document d'entreprise."""

    doc_type = serializers.ChoiceField(
        choices=ClientCompanyDocumentType.choices,
        required=True,
        help_text="Type de document: RCCM, LEGAL, OTHER",
    )
    file = serializers.FileField(
        required=True,
        help_text="Fichier à uploader",
    )
    reference_number = serializers.CharField(
        max_length=60,
        required=False,
        allow_blank=True,
        default="",
        help_text="Numéro de référence (optionnel)",
    )

    class Meta:
        model = ClientCompanyDocument
        fields = ["doc_type", "file", "reference_number"]

    def create(self, validated_data):
        """Crée le document rattaché à la company du user."""
        company = self.context["company"]
        return ClientCompanyDocument.objects.create(
            company=company,
            doc_type=validated_data["doc_type"],
            file=validated_data["file"],
            reference_number=validated_data.get("reference_number", ""),
        )


class ClientCompanyDocumentUpdateSerializer(serializers.ModelSerializer):
    """Serializer pour la mise à jour d'un document (sans changer le fichier)."""

    doc_type = serializers.ChoiceField(
        choices=ClientCompanyDocumentType.choices,
        required=False,
        help_text="Type de document: RCCM, LEGAL, OTHER",
    )
    reference_number = serializers.CharField(
        max_length=60,
        required=False,
        allow_blank=True,
        help_text="Numéro de référence",
    )

    class Meta:
        model = ClientCompanyDocument
        fields = ["doc_type", "reference_number"]
