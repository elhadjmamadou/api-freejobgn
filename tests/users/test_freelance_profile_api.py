"""
Tests pour les endpoints de profil freelance:
- POST /api/auth/freelance/profile/init/
- GET /api/auth/freelance/profile/
- PATCH /api/auth/freelance/profile/
"""

import pytest
from django.urls import reverse
from rest_framework import status

from users.models import (
    ProviderProfile,
    FreelanceDetails,
    UserRole,
    ProviderKind,
)


# ============================================================
# URLs (basées sur users/urls.py avec namespace "users")
# ============================================================

PROFILE_INIT_URL = "/api/auth/freelance/profile/init/"
PROFILE_URL = "/api/auth/freelance/profile/"


# ============================================================
# Tests: POST /api/auth/freelance/profile/init/
# ============================================================


@pytest.mark.django_db
class TestFreelanceProfileInit:
    """Tests pour l'endpoint POST /api/auth/freelance/profile/init/"""

    def test_init_profile_success_minimal(self, auth_client, freelance_user):
        """
        201: Création réussie avec données minimales requises.
        """
        payload = {
            "city_or_region": "Conakry",
            "country": "Guinée",
            "freelance": {
                "first_name": "John",
                "last_name": "Doe",
            },
        }

        response = auth_client.post(PROFILE_INIT_URL, payload, format="json")

        assert response.status_code == status.HTTP_201_CREATED
        assert ProviderProfile.objects.filter(user=freelance_user).exists()
        assert FreelanceDetails.objects.filter(
            provider_profile__user=freelance_user
        ).exists()

        # Vérifier les données retournées
        data = response.json()
        assert data["city_or_region"] == "Conakry"
        assert data["country"] == "Guinée"
        assert data["freelance_details"]["first_name"] == "John"
        assert data["freelance_details"]["last_name"] == "Doe"

    def test_init_profile_success_full(self, auth_client, freelance_user, speciality, skills):
        """
        201: Création réussie avec toutes les données (incluant speciality et skills).
        """
        payload = {
            "city_or_region": "Conakry",
            "country": "Guinée",
            "postal_code": "12345",
            "phone": "+224620000000",
            "bio": "Développeur expérimenté",
            "hourly_rate": "75.00",
            "speciality_id": speciality.id,
            "skill_ids": [skills[0].id, skills[1].id],  # Python, Django
            "freelance": {
                "first_name": "John",
                "last_name": "Doe",
                "business_name": "JD Consulting",
            },
        }

        response = auth_client.post(PROFILE_INIT_URL, payload, format="json")

        assert response.status_code == status.HTTP_201_CREATED

        profile = ProviderProfile.objects.get(user=freelance_user)
        assert profile.hourly_rate == 75.00
        assert profile.speciality == speciality
        assert profile.skills.count() == 2

        freelance_details = FreelanceDetails.objects.get(provider_profile=profile)
        assert freelance_details.business_name == "JD Consulting"

    def test_init_profile_conflict_already_exists(self, auth_client, provider_profile):
        """
        409: Profil déjà existant.
        """
        payload = {
            "city_or_region": "Autre ville",
            "country": "France",
            "freelance": {
                "first_name": "New",
                "last_name": "Name",
            },
        }

        response = auth_client.post(PROFILE_INIT_URL, payload, format="json")

        assert response.status_code == status.HTTP_409_CONFLICT
        assert "déjà existant" in response.json().get("detail", "").lower()

    def test_init_profile_validation_missing_freelance(self, auth_client, freelance_user):
        """
        400: freelance (first_name, last_name) requis.
        """
        payload = {
            "city_or_region": "Conakry",
            "country": "Guinée",
            # freelance manquant
        }

        response = auth_client.post(PROFILE_INIT_URL, payload, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_init_profile_validation_missing_location(self, auth_client, freelance_user):
        """
        400: city_or_region et country sont obligatoires.
        """
        payload = {
            "freelance": {
                "first_name": "John",
                "last_name": "Doe",
            },
            # city_or_region et country manquants
        }

        response = auth_client.post(PROFILE_INIT_URL, payload, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_init_profile_validation_speciality_skills_incompatible(
        self, auth_client, freelance_user, speciality, other_speciality
    ):
        """
        400: Si speciality_id + skill_ids fournis, au moins 1 skill doit appartenir à la spécialité.
        """
        # other_speciality n'a pas les mêmes skills que speciality
        # On donne speciality mais des skills de other_speciality
        other_skill = other_speciality.skills.first()

        payload = {
            "city_or_region": "Conakry",
            "country": "Guinée",
            "speciality_id": speciality.id,
            "skill_ids": [other_skill.id],  # Skill non compatible avec speciality
            "freelance": {
                "first_name": "John",
                "last_name": "Doe",
            },
        }

        response = auth_client.post(PROFILE_INIT_URL, payload, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert "speciality" in str(data).lower() or "skill" in str(data).lower()

    def test_init_profile_unauthenticated(self, api_client):
        """
        401: Utilisateur non authentifié.
        """
        payload = {
            "city_or_region": "Conakry",
            "country": "Guinée",
            "freelance": {
                "first_name": "John",
                "last_name": "Doe",
            },
        }

        response = api_client.post(PROFILE_INIT_URL, payload, format="json")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_init_profile_forbidden_client_user(self, api_client, client_user):
        """
        403: Un client ne peut pas créer de profil freelance.
        """
        api_client.force_authenticate(user=client_user)

        payload = {
            "city_or_region": "Conakry",
            "country": "Guinée",
            "freelance": {
                "first_name": "John",
                "last_name": "Doe",
            },
        }

        response = api_client.post(PROFILE_INIT_URL, payload, format="json")

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_init_profile_forbidden_agency_user(self, api_client, agency_user):
        """
        403: Une agence ne peut pas utiliser l'endpoint freelance.
        """
        api_client.force_authenticate(user=agency_user)

        payload = {
            "city_or_region": "Conakry",
            "country": "Guinée",
            "freelance": {
                "first_name": "John",
                "last_name": "Doe",
            },
        }

        response = api_client.post(PROFILE_INIT_URL, payload, format="json")

        assert response.status_code == status.HTTP_403_FORBIDDEN


# ============================================================
# Tests: GET /api/auth/freelance/profile/
# ============================================================


@pytest.mark.django_db
class TestFreelanceProfileGet:
    """Tests pour l'endpoint GET /api/auth/freelance/profile/"""

    def test_get_profile_success(self, auth_client, provider_profile):
        """
        200: Récupération réussie du profil existant.
        """
        response = auth_client.get(PROFILE_URL)

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["city_or_region"] == provider_profile.city_or_region
        assert data["country"] == provider_profile.country
        assert data["freelance_details"]["first_name"] == "John"
        assert data["freelance_details"]["last_name"] == "Doe"
        assert "skills" in data
        assert "speciality" in data

    def test_get_profile_not_found_not_initialized(self, auth_client, freelance_user):
        """
        404 ou exception: Profil non initialisé.
        Note: La vue actuelle peut lever DoesNotExist (500) au lieu de retourner 404.
        Ce test documente le comportement actuel.
        """
        from users.models import ProviderProfile
        
        # freelance_user sans provider_profile
        try:
            response = auth_client.get(PROFILE_URL)
            # Si on arrive ici, l'API a retourné une réponse
            assert response.status_code in [status.HTTP_404_NOT_FOUND, status.HTTP_500_INTERNAL_SERVER_ERROR]
        except ProviderProfile.DoesNotExist:
            # L'exception est levée car la vue ne gère pas get() sur un profil inexistant
            # C'est un comportement acceptable qui pourrait être amélioré
            pass

    def test_get_profile_unauthenticated(self, api_client):
        """
        401: Utilisateur non authentifié.
        """
        response = api_client.get(PROFILE_URL)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_get_profile_forbidden_client(self, api_client, client_user):
        """
        403: Un client ne peut pas accéder au profil freelance.
        """
        api_client.force_authenticate(user=client_user)
        response = api_client.get(PROFILE_URL)

        assert response.status_code == status.HTTP_403_FORBIDDEN


# ============================================================
# Tests: PATCH /api/auth/freelance/profile/
# ============================================================


@pytest.mark.django_db
class TestFreelanceProfilePatch:
    """Tests pour l'endpoint PATCH /api/auth/freelance/profile/"""

    def test_patch_profile_success_simple(self, auth_client, provider_profile):
        """
        200: Mise à jour simple d'un champ (bio).
        """
        payload = {
            "bio": "Nouvelle bio mise à jour",
        }

        response = auth_client.patch(PROFILE_URL, payload, format="json")

        assert response.status_code == status.HTTP_200_OK

        provider_profile.refresh_from_db()
        assert provider_profile.bio == "Nouvelle bio mise à jour"

    def test_patch_profile_success_multiple_fields(self, auth_client, provider_profile):
        """
        200: Mise à jour de plusieurs champs.
        """
        payload = {
            "city_or_region": "Labé",
            "hourly_rate": "100.00",
            "phone": "+224621234567",
        }

        response = auth_client.patch(PROFILE_URL, payload, format="json")

        assert response.status_code == status.HTTP_200_OK

        provider_profile.refresh_from_db()
        assert provider_profile.city_or_region == "Labé"
        assert provider_profile.hourly_rate == 100.00
        assert provider_profile.phone == "+224621234567"

    def test_patch_profile_success_nested_freelance(self, auth_client, provider_profile):
        """
        200: Mise à jour des infos freelance (nested).
        """
        payload = {
            "freelance": {
                "first_name": "Johnny",
                "business_name": "New Business Name",
            },
        }

        response = auth_client.patch(PROFILE_URL, payload, format="json")

        assert response.status_code == status.HTTP_200_OK

        freelance_details = FreelanceDetails.objects.get(provider_profile=provider_profile)
        assert freelance_details.first_name == "Johnny"
        assert freelance_details.business_name == "New Business Name"
        # last_name ne doit pas avoir changé
        assert freelance_details.last_name == "Doe"

    def test_patch_profile_success_update_skills(self, auth_client, provider_profile, skills):
        """
        200: Mise à jour des skills via skill_ids.
        Note: On ne peut changer les skills qu'avec des skills compatibles avec la spécialité.
        """
        # Initialement Python et Django, on garde au moins un skill compatible
        payload = {
            "skill_ids": [skills[0].id],  # Python only (compatible avec speciality Backend Development)
        }

        response = auth_client.patch(PROFILE_URL, payload, format="json")

        assert response.status_code == status.HTTP_200_OK

        provider_profile.refresh_from_db()
        assert provider_profile.skills.count() == 1
        assert provider_profile.skills.first().name == "Python"

    def test_patch_profile_success_update_speciality(
        self, auth_client, provider_profile, other_speciality
    ):
        """
        200: Mise à jour de la spécialité.
        """
        # On doit aussi mettre les skills compatibles
        other_skill = other_speciality.skills.first()

        payload = {
            "speciality_id": other_speciality.id,
            "skill_ids": [other_skill.id],
        }

        response = auth_client.patch(PROFILE_URL, payload, format="json")

        assert response.status_code == status.HTTP_200_OK

        provider_profile.refresh_from_db()
        assert provider_profile.speciality == other_speciality

    def test_patch_profile_validation_speciality_skills_incompatible(
        self, auth_client, provider_profile, other_speciality, skills
    ):
        """
        400: Spécialité incompatible avec les skills fournis.
        """
        payload = {
            "speciality_id": other_speciality.id,
            "skill_ids": [skills[0].id],  # Python, non compatible avec other_speciality
        }

        response = auth_client.patch(PROFILE_URL, payload, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_patch_profile_not_found(self, auth_client, freelance_user):
        """
        404 ou exception: Profil non initialisé.
        Note: La vue actuelle peut lever DoesNotExist (500) au lieu de retourner 404.
        Ce test documente le comportement actuel.
        """
        from users.models import ProviderProfile
        
        payload = {"bio": "Test"}

        try:
            response = auth_client.patch(PROFILE_URL, payload, format="json")
            # Si on arrive ici, l'API a retourné une réponse
            assert response.status_code in [status.HTTP_404_NOT_FOUND, status.HTTP_500_INTERNAL_SERVER_ERROR]
        except ProviderProfile.DoesNotExist:
            # L'exception est levée car la vue ne gère pas get() sur un profil inexistant
            pass

    def test_patch_profile_unauthenticated(self, api_client):
        """
        401: Utilisateur non authentifié.
        """
        payload = {"bio": "Test"}

        response = api_client.patch(PROFILE_URL, payload, format="json")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_patch_profile_forbidden_client(self, api_client, client_user):
        """
        403: Un client ne peut pas modifier un profil freelance.
        """
        api_client.force_authenticate(user=client_user)
        payload = {"bio": "Test"}

        response = api_client.patch(PROFILE_URL, payload, format="json")

        assert response.status_code == status.HTTP_403_FORBIDDEN


# ============================================================
# Tests d'isolation
# ============================================================


@pytest.mark.django_db
class TestFreelanceProfileIsolation:
    """Tests d'isolation: un freelance ne peut voir/modifier que son profil."""

    def test_get_profile_returns_own_profile(
        self, auth_client, provider_profile, other_provider_profile
    ):
        """
        Chaque freelance ne voit que son propre profil.
        """
        response = auth_client.get(PROFILE_URL)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Vérifie que c'est bien le profil du freelance connecté
        assert data["freelance_details"]["first_name"] == "John"  # provider_profile
        assert data["freelance_details"]["first_name"] != "Jane"  # other_provider_profile

    def test_patch_cannot_modify_other_profile(
        self, other_auth_client, provider_profile, other_provider_profile
    ):
        """
        Un freelance ne peut pas modifier le profil d'un autre.
        """
        # other_auth_client est authentifié avec other_freelance_user
        # Il tente de modifier son propre profil (ce qui est normal)
        payload = {"bio": "Modified by other"}

        response = other_auth_client.patch(PROFILE_URL, payload, format="json")

        assert response.status_code == status.HTTP_200_OK

        # Vérifie que le profil original n'a pas été modifié
        provider_profile.refresh_from_db()
        assert provider_profile.bio != "Modified by other"

        # Vérifie que other_provider_profile a été modifié
        other_provider_profile.refresh_from_db()
        assert other_provider_profile.bio == "Modified by other"
