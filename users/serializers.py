"""
Serializers pour l'authentification et la gestion des utilisateurs.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field

from .models import UserRole, ProviderKind
from django.db import transaction
from rest_framework import serializers

from .models import ProviderProfile, FreelanceDetails, Skill, Speciality
from .models import FreelanceDocument, FreelanceDocumentType


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



class SkillMiniSerializer(serializers.ModelSerializer):
    class Meta:
        model = Skill
        fields = ("id", "name")


class SpecialityMiniSerializer(serializers.ModelSerializer):
    class Meta:
        model = Speciality
        fields = ("id", "name", "description")


class FreelanceDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = FreelanceDetails
        fields = ("first_name", "last_name", "business_name")


class ProviderProfileFreelanceSerializer(serializers.ModelSerializer):
    """
    Serializer du profil freelance:
    - ProviderProfile (profil commun prestataire)
    - FreelanceDetails (détails freelance)
    """

    # READ
    username = serializers.CharField(source="user.username", read_only=True)
    email = serializers.EmailField(source="user.email", read_only=True)

    skills = SkillMiniSerializer(many=True, read_only=True)
    speciality = SpecialityMiniSerializer(read_only=True)
    freelance_details = FreelanceDetailsSerializer(read_only=True)

    # WRITE
    skill_ids = serializers.PrimaryKeyRelatedField(
        source="skills",
        many=True,
        queryset=Skill.objects.filter(is_active=True),
        required=False,
        write_only=True,
    )
    speciality_id = serializers.PrimaryKeyRelatedField(
        source="speciality",
        queryset=Speciality.objects.filter(is_active=True),
        required=False,
        allow_null=True,
        write_only=True,
    )
    freelance = FreelanceDetailsSerializer(write_only=True, required=False)

    class Meta:
        model = ProviderProfile
        fields = (
            "id",
            "username",
            "email",

            "profile_picture",
            "bio",
            "hourly_rate",
            "city_or_region",
            "country",
            "postal_code",
            "phone",

            "skills",
            "skill_ids",

            "speciality",
            "speciality_id",

            "freelance_details",
            "freelance",

            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_at", "updated_at")

    def validate(self, attrs):
        """
        Règle: si speciality + skills envoyés => au moins 1 skill appartient à la spécialité.
        """
        speciality = attrs.get("speciality")
        skills = attrs.get("skills")

        if speciality and skills:
            spec_skill_ids = set(speciality.skills.values_list("id", flat=True))
            user_skill_ids = {s.id for s in skills}
            if spec_skill_ids and user_skill_ids and not (spec_skill_ids & user_skill_ids):
                raise serializers.ValidationError(
                    {"speciality_id": "Spécialité incompatible avec les skills fournis."}
                )
        return attrs

    def _get_user(self):
        user = self.context["request"].user
        if not getattr(user, "is_freelance", False):
            raise serializers.ValidationError("Accès réservé aux prestataires FREELANCE.")
        return user

    @transaction.atomic
    def create(self, validated_data):
        user = self._get_user()

        # empêcher double création
        if hasattr(user, "provider_profile"):
            raise serializers.ValidationError("Profil prestataire existe déjà.")

        freelance_payload = validated_data.pop("freelance", {})
        skills = validated_data.pop("skills", [])

        provider_profile = ProviderProfile.objects.create(user=user, **validated_data)

        if skills:
            provider_profile.skills.set(skills)

        if not freelance_payload:
            raise serializers.ValidationError({"freelance": "Les infos freelance sont requises à la création."})

        FreelanceDetails.objects.create(provider_profile=provider_profile, **freelance_payload)

        provider_profile.full_clean()
        return provider_profile

    @transaction.atomic
    def update(self, instance: ProviderProfile, validated_data):
        user = self._get_user()
        if instance.user_id != user.id:
            raise serializers.ValidationError("Accès interdit.")

        freelance_payload = validated_data.pop("freelance", None)
        skills = validated_data.pop("skills", None)  # None = ne pas toucher / [] = vider

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()

        if skills is not None:
            instance.skills.set(skills)

        if freelance_payload is not None:
            fd, _ = FreelanceDetails.objects.get_or_create(provider_profile=instance)
            for attr, value in freelance_payload.items():
                setattr(fd, attr, value)
            fd.save()

        instance.full_clean()
        return instance


from rest_framework import serializers
from django.core.exceptions import ValidationError as DjangoValidationError

from .models import FreelanceDocument, FreelanceDocumentType


class FreelanceDocumentSerializer(serializers.ModelSerializer):
    """
    Document du freelance.
    - file requis à la création
    - file optionnel en update (PATCH) si tu changes juste title/reference_number/issued_at
    """

    class Meta:
        model = FreelanceDocument
        fields = (
            "id",
            "doc_type",
            "file",
            "title",
            "reference_number",
            "issued_at",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_at", "updated_at")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # file requis seulement à la création
        if self.instance is not None:
            self.fields["file"].required = False

    def validate_doc_type(self, value):
        """
        Message clair côté API pour les types réservés aux agences.
        (Ton modèle a déjà un clean, mais on sécurise ici aussi.)
        """
        request = self.context.get("request")
        user = getattr(request, "user", None)

        agency_only = {
            FreelanceDocumentType.RCCM,
            FreelanceDocumentType.STATUTES,
            FreelanceDocumentType.TAX,
        }
        if user and getattr(user, "is_freelance", False) and value in agency_only:
            raise serializers.ValidationError("Ce type de document est réservé aux agences.")
        return value

    def create(self, validated_data):
        """
        On force provider_profile côté view (perform_create),
        donc ici on fait juste un full_clean safe.
        """
        instance = super().create(validated_data)
        try:
            instance.full_clean()
        except DjangoValidationError as e:
            raise serializers.ValidationError(e.message_dict)
        return instance

    def update(self, instance, validated_data):
        instance = super().update(instance, validated_data)
        try:
            instance.full_clean()
        except DjangoValidationError as e:
            raise serializers.ValidationError(e.message_dict)
        return instance
