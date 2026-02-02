"""
Serializers pour l'authentification et la gestion des utilisateurs.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field

from .models import UserRole, ProviderKind

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
