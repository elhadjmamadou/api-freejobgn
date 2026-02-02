# users/models.py
from __future__ import annotations

import re
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q


# ============================================================
# Utils / Mixins
# ============================================================

class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


def upload_to_user_dir(instance, filename: str) -> str:
    """
    Stockage simple et stable pour médias.
    Ex: users/42/avatar.png
    """
    user_id = None
    if hasattr(instance, "user_id"):
        user_id = instance.user_id
    elif hasattr(instance, "provider_profile_id") and instance.provider_profile_id:
        user_id = instance.provider_profile.user_id
    elif hasattr(instance, "client_profile_id") and instance.client_profile_id:
        user_id = instance.client_profile.user_id
    return f"users/{user_id or 'unknown'}/{filename}"


# ============================================================
# Validators (anti-contact externe dans bio)
# ============================================================

EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
URL_RE = re.compile(r"https?://|www\.", re.I)
PHONE_RE = re.compile(r"(?:\+?\d[\s.-]?){7,}", re.I)

def validate_no_external_contact(value: str):
    if not value:
        return
    if EMAIL_RE.search(value) or URL_RE.search(value) or PHONE_RE.search(value):
        raise ValidationError("Pas de contact externe (email, téléphone, URL) dans la présentation.")


# ============================================================
# Référentiels
# ============================================================

class Skill(TimeStampedModel):
    name = models.CharField(max_length=80, unique=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ("name",)
        indexes = [models.Index(fields=["is_active", "name"])]

    def __str__(self) -> str:
        return self.name


class Speciality(TimeStampedModel):
    name = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=200, blank=True)
    skills = models.ManyToManyField(Skill, related_name="specialities", blank=False)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ("name",)
        indexes = [models.Index(fields=["is_active", "name"])]

    def __str__(self) -> str:
        return self.name


# ============================================================
# User (auth + rôle)
# ============================================================

class UserRole(models.TextChoices):
    CLIENT = "CLIENT", "Client"
    PROVIDER = "PROVIDER", "Prestataire"


class ProviderKind(models.TextChoices):
    FREELANCE = "FREELANCE", "Freelance"
    AGENCY = "AGENCY", "Agence"


class User(AbstractUser, TimeStampedModel):
    """
    User = compte + auth + rôle (API-first)
    - username = pseudo (hérité AbstractUser)
    - email unique
    - role: client ou prestataire
    - provider_kind: freelance/agence si role=provider
    """
    email = models.EmailField("Adresse e-mail", unique=True)

    role = models.CharField(
        max_length=10,
        choices=UserRole.choices,
        db_index=True,
    )
    provider_kind = models.CharField(
        max_length=10,
        choices=ProviderKind.choices,
        null=True,
        blank=True,
        db_index=True,
        help_text="Uniquement si role=PROVIDER",
    )

    class Meta:
        constraints = [
            # provider_kind doit être défini seulement si role=PROVIDER
            models.CheckConstraint(
                name="user_provider_kind_consistency",
                condition=(
                    Q(role=UserRole.PROVIDER, provider_kind__isnull=False)
                    | Q(~Q(role=UserRole.PROVIDER), provider_kind__isnull=True)
                ),
            )
        ]
        indexes = [
            models.Index(fields=["role", "provider_kind"]),
            models.Index(fields=["email"]),
        ]

    def clean(self):
        super().clean()
        if self.role == UserRole.CLIENT and self.provider_kind is not None:
            raise ValidationError({"provider_kind": "Un client ne doit pas avoir provider_kind."})
        if self.role == UserRole.PROVIDER and self.provider_kind is None:
            raise ValidationError({"provider_kind": "Un prestataire doit avoir provider_kind (FREELANCE/AGENCY)."})

    @property
    def is_client(self) -> bool:
        return self.role == UserRole.CLIENT

    @property
    def is_provider(self) -> bool:
        return self.role == UserRole.PROVIDER

    @property
    def is_freelance(self) -> bool:
        return self.is_provider and self.provider_kind == ProviderKind.FREELANCE

    @property
    def is_agency(self) -> bool:
        return self.is_provider and self.provider_kind == ProviderKind.AGENCY

    def __str__(self) -> str:
        return f"{self.username} ({self.role})"


# ============================================================
# Provider (profil commun + détails)
# ============================================================

class ProviderProfile(TimeStampedModel):
    """
    Profil commun à tous les prestataires (Freelance + Agence)
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="provider_profile",
    )

    profile_picture = models.ImageField(
        upload_to=upload_to_user_dir,
        blank=True,
        null=True,
    )

    bio = models.TextField(validators=[validate_no_external_contact])
    hourly_rate = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)

    city_or_region = models.CharField(max_length=120, db_index=True)
    country = models.CharField(max_length=120, db_index=True)
    postal_code = models.CharField(max_length=20, blank=True)
    phone = models.CharField(max_length=30, blank=True)

    # Référentiels
    skills = models.ManyToManyField(Skill, related_name="providers", blank=True)
    speciality = models.ForeignKey(
        Speciality,
        on_delete=models.PROTECT,
        related_name="providers",
        null=True,
        blank=True,
    )

    class Meta:
        indexes = [
            models.Index(fields=["country", "city_or_region"]),
            models.Index(fields=["hourly_rate"]),
        ]

    def clean(self):
        super().clean()
        if not self.user or not getattr(self.user, "is_provider", False):
            raise ValidationError("ProviderProfile réservé aux utilisateurs role=PROVIDER.")

        # hourly_rate conseillé (peut être obligatoire si vous voulez)
        # Ici on l'autorise null pour étape d'onboarding, mais on peut le forcer via serializer.
        if self.hourly_rate is not None and self.hourly_rate < 0:
            raise ValidationError({"hourly_rate": "hourly_rate ne peut pas être négatif."})

        # Validation speciality compatible avec skills:
        # ⚠️ En API, on recommande de faire ça dans le Serializer/Service (plus fiable).
        # Mais on garde une protection safe ici si la relation M2M existe déjà.
        if self.speciality_id and self.pk:
            skill_ids = set(self.skills.values_list("id", flat=True))
            if skill_ids:
                spec_skill_ids = set(self.speciality.skills.values_list("id", flat=True))
                if not (skill_ids & spec_skill_ids):
                    raise ValidationError({"speciality": "Spécialité incompatible avec vos skills."})

    def __str__(self) -> str:
        return f"ProviderProfile • {self.user.username}"


class FreelanceDetails(TimeStampedModel):
    """
    Détails spécifiques au freelance
    """
    provider_profile = models.OneToOneField(
        ProviderProfile,
        on_delete=models.CASCADE,
        related_name="freelance_details",
    )

    first_name = models.CharField(max_length=80)
    last_name = models.CharField(max_length=80)
    business_name = models.CharField(max_length=120, blank=True, help_text="Optionnel")

    class Meta:
        indexes = [models.Index(fields=["last_name", "first_name"])]

    def clean(self):
        super().clean()
        if not self.provider_profile or not self.provider_profile.user.is_freelance:
            raise ValidationError("FreelanceDetails réservé aux PROVIDER/FREELANCE.")

    def __str__(self) -> str:
        return f"FreelanceDetails • {self.provider_profile.user.username}"


class AgencyDetails(TimeStampedModel):
    """
    Détails spécifiques à l'agence
    """
    provider_profile = models.OneToOneField(
        ProviderProfile,
        on_delete=models.CASCADE,
        related_name="agency_details",
    )

    agency_name = models.CharField(max_length=150, db_index=True)
    founded_at = models.DateField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["agency_name"])]

    def clean(self):
        super().clean()
        if not self.provider_profile or not self.provider_profile.user.is_agency:
            raise ValidationError("AgencyDetails réservé aux PROVIDER/AGENCY.")

    def __str__(self) -> str:
        return f"AgencyDetails • {self.agency_name}"


class AgencyDocumentType(models.TextChoices):
    RCCM = "RCCM", "RCCM"
    STATUTES = "STATUTES", "Statuts"
    OTHER = "OTHER", "Autre"


class AgencyDocument(TimeStampedModel):
    agency = models.ForeignKey(
        AgencyDetails,
        on_delete=models.CASCADE,
        related_name="documents",
    )
    doc_type = models.CharField(max_length=20, choices=AgencyDocumentType.choices, db_index=True)
    file = models.FileField(upload_to=upload_to_user_dir)
    reference_number = models.CharField(max_length=60, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["doc_type"]),
            models.Index(fields=["agency", "doc_type"]),
        ]

    def __str__(self) -> str:
        return f"{self.agency.agency_name} • {self.doc_type}"


class FreelanceDocumentType(models.TextChoices):
    # Freelance / général
    CV = "CV", "CV"
    CERTIFICATION = "CERTIFICATION", "Certification"
    PORTFOLIO = "PORTFOLIO", "Portfolio"
    IDENTITY = "IDENTITY", "Pièce d'identité"
    OTHER = "OTHER", "Autre"

    # Plutôt agence / légal
    RCCM = "RCCM", "RCCM"
    STATUTES = "STATUTES", "Statuts"
    TAX = "TAX", "Document fiscal"


class FreelanceDocument(TimeStampedModel):
    provider_profile = models.ForeignKey(
        ProviderProfile,
        on_delete=models.CASCADE,
        related_name="documents",
    )

    doc_type = models.CharField(
        max_length=20,
        choices=FreelanceDocumentType.choices,
        db_index=True,
    )

    file = models.FileField(upload_to=upload_to_user_dir)

    # champs utiles (API)
    title = models.CharField(max_length=120, blank=True)
    reference_number = models.CharField(max_length=60, blank=True)
    issued_at = models.DateField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["doc_type"]),
            models.Index(fields=["provider_profile", "doc_type"]),
            models.Index(fields=["provider_profile", "created_at"]),
        ]

    def clean(self):
        super().clean()
        user = self.provider_profile.user

        # Exemple de règle stricte : RCCM/STATUTES réservés aux agences
        agency_only = {FreelanceDocumentType.RCCM, FreelanceDocumentType.STATUTES, FreelanceDocumentType.TAX}
        if user.is_freelance and self.doc_type in agency_only:
            raise ValidationError({"doc_type": "Ce type de document est réservé aux agences."})

        # Tu peux aussi décider l’inverse (CV réservé au freelance) si tu veux, mais souvent on laisse.

    def __str__(self) -> str:
        return f"{self.provider_profile.user.username} • {self.doc_type}"



# ============================================================
# Client (profil commun + sous-types)
# ============================================================

class ClientType(models.TextChoices):
    INDIVIDUAL = "INDIVIDUAL", "Particulier"
    COMPANY = "COMPANY", "Entreprise"


class ClientProfile(TimeStampedModel):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="client_profile",
    )

    profile_picture = models.ImageField(
        upload_to=upload_to_user_dir,
        blank=True,
        null=True,
    )

    client_type = models.CharField(max_length=12, choices=ClientType.choices, db_index=True)

    city_or_region = models.CharField(max_length=120, db_index=True)
    country = models.CharField(max_length=120, db_index=True)
    postal_code = models.CharField(max_length=20, blank=True)
    phone = models.CharField(max_length=30, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["client_type"]),
            models.Index(fields=["country", "city_or_region"]),
        ]

    def clean(self):
        super().clean()
        if not self.user or not getattr(self.user, "is_client", False):
            raise ValidationError("ClientProfile réservé aux utilisateurs role=CLIENT.")

    def __str__(self) -> str:
        return f"ClientProfile • {self.user.username} ({self.client_type})"


class ClientIndividualDetails(TimeStampedModel):
    client_profile = models.OneToOneField(
        ClientProfile,
        on_delete=models.CASCADE,
        related_name="individual_details",
    )
    first_name = models.CharField(max_length=80)
    last_name = models.CharField(max_length=80)

    def clean(self):
        super().clean()
        if not self.client_profile or self.client_profile.client_type != ClientType.INDIVIDUAL:
            raise ValidationError("ClientIndividualDetails réservé aux clients INDIVIDUAL.")

    def __str__(self) -> str:
        return f"ClientIndividual • {self.first_name} {self.last_name}"


class ClientCompanyDetails(TimeStampedModel):
    client_profile = models.OneToOneField(
        ClientProfile,
        on_delete=models.CASCADE,
        related_name="company_details",
    )
    company_name = models.CharField(max_length=150, db_index=True)

    def clean(self):
        super().clean()
        if not self.client_profile or not self.client_profile.client_type != ClientType.COMPANY:
            raise ValidationError("ClientCompanyDetails réservé aux clients COMPANY.")

    def __str__(self) -> str:
        return f"ClientCompany • {self.company_name}"


class ClientCompanyDocumentType(models.TextChoices):
    RCCM = "RCCM", "RCCM"
    LEGAL = "LEGAL", "Document juridique"
    OTHER = "OTHER", "Autre"


class ClientCompanyDocument(TimeStampedModel):
    company = models.ForeignKey(
        ClientCompanyDetails,
        on_delete=models.CASCADE,
        related_name="documents",
    )
    doc_type = models.CharField(max_length=20, choices=ClientCompanyDocumentType.choices, db_index=True)
    file = models.FileField(upload_to=upload_to_user_dir)
    reference_number = models.CharField(max_length=60, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["doc_type"]),
            models.Index(fields=["company", "doc_type"]),
        ]

    def __str__(self) -> str:
        return f"{self.company.company_name} • {self.doc_type}"

