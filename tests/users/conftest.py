"""
Fixtures partagées pour les tests de l'app users.
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from users.models import (
    UserRole,
    ProviderKind,
    Skill,
    Speciality,
    ProviderProfile,
    FreelanceDetails,
    FreelanceDocument,
    FreelanceDocumentType,
)

User = get_user_model()


# ============================================================
# APIClient fixtures
# ============================================================


@pytest.fixture
def api_client():
    """APIClient non authentifié."""
    return APIClient()


@pytest.fixture
def auth_client(api_client, freelance_user):
    """APIClient authentifié avec le freelance_user."""
    api_client.force_authenticate(user=freelance_user)
    return api_client


@pytest.fixture
def other_auth_client(api_client, other_freelance_user):
    """APIClient authentifié avec un autre freelance (pour tests d'isolation)."""
    client = APIClient()
    client.force_authenticate(user=other_freelance_user)
    return client


# ============================================================
# User fixtures
# ============================================================


@pytest.fixture
def freelance_user(db):
    """
    Utilisateur freelance actif, sans profil initialisé.
    """
    return User.objects.create_user(
        username="freelance_user",
        email="freelance@example.com",
        password="TestPass123!",
        role=UserRole.PROVIDER,
        provider_kind=ProviderKind.FREELANCE,
        is_active=True,
    )


@pytest.fixture
def other_freelance_user(db):
    """
    Autre utilisateur freelance actif, pour tester l'isolation.
    """
    return User.objects.create_user(
        username="other_freelance",
        email="other_freelance@example.com",
        password="TestPass123!",
        role=UserRole.PROVIDER,
        provider_kind=ProviderKind.FREELANCE,
        is_active=True,
    )


@pytest.fixture
def client_user(db):
    """
    Utilisateur client (non-freelance).
    """
    return User.objects.create_user(
        username="client_user",
        email="client@example.com",
        password="TestPass123!",
        role=UserRole.CLIENT,
        is_active=True,
    )


@pytest.fixture
def agency_user(db):
    """
    Utilisateur agence (provider mais pas freelance).
    """
    return User.objects.create_user(
        username="agency_user",
        email="agency@example.com",
        password="TestPass123!",
        role=UserRole.PROVIDER,
        provider_kind=ProviderKind.AGENCY,
        is_active=True,
    )


# ============================================================
# Référentiels (Skills, Speciality)
# ============================================================


@pytest.fixture
def skills(db):
    """
    Liste de 3 skills actifs.
    """
    return [
        Skill.objects.create(name="Python", is_active=True),
        Skill.objects.create(name="Django", is_active=True),
        Skill.objects.create(name="JavaScript", is_active=True),
    ]


@pytest.fixture
def inactive_skill(db):
    """
    Skill inactif (ne doit pas être sélectionnable).
    """
    return Skill.objects.create(name="InactiveSkill", is_active=False)


@pytest.fixture
def speciality(db, skills):
    """
    Spécialité liée aux skills Python et Django.
    """
    spec = Speciality.objects.create(
        name="Backend Development",
        description="Développement serveur",
        is_active=True,
    )
    # Associer Python et Django à la spécialité
    spec.skills.add(skills[0], skills[1])  # Python, Django
    return spec


@pytest.fixture
def other_speciality(db):
    """
    Autre spécialité sans skills communs avec la première.
    """
    other_skill = Skill.objects.create(name="Graphic Design", is_active=True)
    spec = Speciality.objects.create(
        name="Design",
        description="Design graphique",
        is_active=True,
    )
    spec.skills.add(other_skill)
    return spec


# ============================================================
# Provider Profile fixtures
# ============================================================


@pytest.fixture
def provider_profile(db, freelance_user, speciality, skills):
    """
    ProviderProfile + FreelanceDetails déjà initialisé.
    """
    profile = ProviderProfile.objects.create(
        user=freelance_user,
        city_or_region="Conakry",
        country="Guinée",
        bio="Développeur Python/Django expérimenté.",
        hourly_rate=50.00,
        speciality=speciality,
    )
    profile.skills.set([skills[0], skills[1]])  # Python, Django

    FreelanceDetails.objects.create(
        provider_profile=profile,
        first_name="John",
        last_name="Doe",
        business_name="JD Dev",
    )
    return profile


@pytest.fixture
def other_provider_profile(db, other_freelance_user, speciality, skills):
    """
    Profil d'un autre freelance (pour tests d'isolation).
    """
    profile = ProviderProfile.objects.create(
        user=other_freelance_user,
        city_or_region="Labé",
        country="Guinée",
        bio="Autre développeur.",
        hourly_rate=40.00,
        speciality=speciality,
    )
    profile.skills.set([skills[0]])

    FreelanceDetails.objects.create(
        provider_profile=profile,
        first_name="Jane",
        last_name="Smith",
        business_name="",
    )
    return profile


# ============================================================
# Document fixtures
# ============================================================


@pytest.fixture
def freelance_document(db, provider_profile):
    """
    Document du freelance principal.
    """
    from django.core.files.uploadedfile import SimpleUploadedFile

    file = SimpleUploadedFile("cv.pdf", b"PDF content here", content_type="application/pdf")
    return FreelanceDocument.objects.create(
        provider_profile=provider_profile,
        doc_type=FreelanceDocumentType.CV,
        file=file,
        title="Mon CV",
    )


@pytest.fixture
def other_freelance_document(db, other_provider_profile):
    """
    Document d'un autre freelance (pour tests d'isolation).
    """
    from django.core.files.uploadedfile import SimpleUploadedFile

    file = SimpleUploadedFile("other_cv.pdf", b"Other PDF content", content_type="application/pdf")
    return FreelanceDocument.objects.create(
        provider_profile=other_provider_profile,
        doc_type=FreelanceDocumentType.CV,
        file=file,
        title="CV de Jane",
    )


# ============================================================
# Helpers
# ============================================================


@pytest.fixture
def sample_pdf_file():
    """
    SimpleUploadedFile simulant un PDF pour les tests d'upload.
    """
    from django.core.files.uploadedfile import SimpleUploadedFile

    return SimpleUploadedFile(
        name="test_document.pdf",
        content=b"%PDF-1.4 fake pdf content",
        content_type="application/pdf",
    )


@pytest.fixture
def sample_txt_file():
    """
    SimpleUploadedFile simulant un fichier texte.
    """
    from django.core.files.uploadedfile import SimpleUploadedFile

    return SimpleUploadedFile(
        name="test_document.txt",
        content=b"Simple text content",
        content_type="text/plain",
    )
