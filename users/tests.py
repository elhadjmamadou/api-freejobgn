"""
Tests pour l'authentification.
"""

from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status

from .tokens import activation_token_generator, encode_uid, decode_uid
from .models import (
    UserRole,
    ProviderKind,
    ClientType,
    ClientProfile,
    ClientIndividualDetails,
    ClientCompanyDetails,
    ClientCompanyDocument,
)
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class TokenTests(TestCase):
    """Tests pour les tokens d'activation."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPass123!",
            role=UserRole.CLIENT,
            is_active=False,
        )

    def test_encode_decode_uid(self):
        """Test encodage/décodage de l'uid."""
        uid_encoded = encode_uid(self.user.pk)
        uid_decoded = decode_uid(uid_encoded)
        self.assertEqual(self.user.pk, uid_decoded)

    def test_decode_invalid_uid(self):
        """Test décodage uid invalide."""
        self.assertIsNone(decode_uid("invalid"))
        self.assertIsNone(decode_uid(""))

    def test_token_generation(self):
        """Test génération de token."""
        token = activation_token_generator.make_token(self.user)
        self.assertIsNotNone(token)
        self.assertIsInstance(token, str)

    def test_token_validation_valid(self):
        """Test validation token valide."""
        token = activation_token_generator.make_token(self.user)
        is_valid = activation_token_generator.validate_token(self.user, token)
        self.assertTrue(is_valid)

    def test_token_validation_invalid(self):
        """Test validation token invalide."""
        is_valid = activation_token_generator.validate_token(self.user, "invalid-token")
        self.assertFalse(is_valid)

    def test_token_invalid_after_activation(self):
        """Test que le token est invalide après activation."""
        token = activation_token_generator.make_token(self.user)

        # Activer l'utilisateur
        self.user.is_active = True
        self.user.save()

        # Le token ne doit plus être valide
        is_valid = activation_token_generator.validate_token(self.user, token)
        self.assertFalse(is_valid)


@override_settings(TESTING=True)
class RegisterViewTests(APITestCase):
    """Tests pour l'inscription."""

    def setUp(self):
        self.url = reverse("users:register")
        self.valid_client_data = {
            "email": "newuser@example.com",
            "username": "newuser",
            "password": "SecurePass123!",
            "password_confirm": "SecurePass123!",
            "role": "CLIENT",
        }
        self.valid_provider_data = {
            "email": "provider@example.com",
            "username": "provider",
            "password": "SecurePass123!",
            "password_confirm": "SecurePass123!",
            "role": "PROVIDER",
            "provider_kind": "FREELANCE",
        }

    def test_register_client_success(self):
        """Test inscription client réussie."""
        response = self.client.post(self.url, self.valid_client_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data["needs_activation"])
        self.assertEqual(response.data["email"], "newuser@example.com")

        # Vérifier que l'utilisateur est créé mais inactif
        user = User.objects.get(email="newuser@example.com")
        self.assertFalse(user.is_active)
        self.assertEqual(user.role, UserRole.CLIENT)
        self.assertIsNone(user.provider_kind)

    def test_register_provider_success(self):
        """Test inscription prestataire réussie."""
        response = self.client.post(self.url, self.valid_provider_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(email="provider@example.com")
        self.assertEqual(user.role, UserRole.PROVIDER)
        self.assertEqual(user.provider_kind, ProviderKind.FREELANCE)

    def test_register_provider_without_kind_fails(self):
        """Test inscription provider sans provider_kind échoue."""
        data = self.valid_provider_data.copy()
        del data["provider_kind"]
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("provider_kind", response.data)

    def test_register_client_with_kind_fails(self):
        """Test inscription client avec provider_kind échoue."""
        data = self.valid_client_data.copy()
        data["provider_kind"] = "FREELANCE"
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("provider_kind", response.data)

    def test_register_password_mismatch(self):
        """Test inscription avec mots de passe différents."""
        data = self.valid_client_data.copy()
        data["password_confirm"] = "DifferentPass123!"
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password_confirm", response.data)

    def test_register_weak_password(self):
        """Test inscription avec mot de passe faible."""
        data = self.valid_client_data.copy()
        data["password"] = "123"
        data["password_confirm"] = "123"
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)

    def test_register_duplicate_email(self):
        """Test inscription avec email existant."""
        User.objects.create_user(
            username="existing",
            email="newuser@example.com",
            password="Test123!",
            role=UserRole.CLIENT,
        )
        response = self.client.post(self.url, self.valid_client_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)


@override_settings(TESTING=True)
class ActivateViewTests(APITestCase):
    """Tests pour l'activation."""

    def setUp(self):
        self.url = reverse("users:activate")
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPass123!",
            role=UserRole.CLIENT,
            is_active=False,
        )
        self.uid = encode_uid(self.user.pk)
        self.token = activation_token_generator.make_token(self.user)

    def test_activate_success(self):
        """Test activation réussie."""
        response = self.client.post(
            self.url,
            {
                "uid": self.uid,
                "token": self.token,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)

    def test_activate_invalid_uid(self):
        """Test activation avec uid invalide."""
        response = self.client.post(
            self.url,
            {
                "uid": "invalid",
                "token": self.token,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_activate_invalid_token(self):
        """Test activation avec token invalide."""
        response = self.client.post(
            self.url,
            {
                "uid": self.uid,
                "token": "invalid-token",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_activate_already_active(self):
        """Test activation d'un compte déjà actif."""
        self.user.is_active = True
        self.user.save()

        response = self.client.post(
            self.url,
            {
                "uid": self.uid,
                "token": self.token,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("déjà activé", response.data["detail"])


@override_settings(TESTING=True)
class LoginViewTests(APITestCase):
    """Tests pour la connexion."""

    def setUp(self):
        self.url = reverse("users:login")
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPass123!",
            role=UserRole.CLIENT,
            is_active=True,
        )
        self.inactive_user = User.objects.create_user(
            username="inactive",
            email="inactive@example.com",
            password="TestPass123!",
            role=UserRole.CLIENT,
            is_active=False,
        )

    def test_login_success(self):
        """Test connexion réussie."""
        response = self.client.post(
            self.url,
            {
                "email": "test@example.com",
                "password": "TestPass123!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("user", response.data)

        # Vérifier le cookie refresh
        self.assertIn("refresh_token", response.cookies)
        self.assertTrue(response.cookies["refresh_token"]["httponly"])

    def test_login_wrong_password(self):
        """Test connexion avec mauvais mot de passe."""
        response = self.client.post(
            self.url,
            {
                "email": "test@example.com",
                "password": "WrongPass123!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_wrong_email(self):
        """Test connexion avec email inexistant."""
        response = self.client.post(
            self.url,
            {
                "email": "nonexistent@example.com",
                "password": "TestPass123!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_inactive_user(self):
        """Test connexion utilisateur non activé."""
        response = self.client.post(
            self.url,
            {
                "email": "inactive@example.com",
                "password": "TestPass123!",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertTrue(response.data["needs_activation"])


@override_settings(TESTING=True)
class MeViewTests(APITestCase):
    """Tests pour /me."""

    def setUp(self):
        self.url = reverse("users:me")
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPass123!",
            role=UserRole.PROVIDER,
            provider_kind=ProviderKind.FREELANCE,
            is_active=True,
        )

    def test_me_authenticated(self):
        """Test /me avec authentification."""
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], "test@example.com")
        self.assertEqual(response.data["role"], "PROVIDER")
        self.assertEqual(response.data["provider_kind"], "FREELANCE")

    def test_me_unauthenticated(self):
        """Test /me sans authentification."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


@override_settings(TESTING=True)
class TokenRefreshViewTests(APITestCase):
    """Tests pour le refresh token."""

    def setUp(self):
        self.url = reverse("users:token-refresh")
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPass123!",
            role=UserRole.CLIENT,
            is_active=True,
        )

    def test_refresh_success(self):
        """Test refresh token réussi."""
        # D'abord se connecter pour obtenir le cookie
        login_response = self.client.post(
            reverse("users:login"),
            {
                "email": "test@example.com",
                "password": "TestPass123!",
            },
        )
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)

        # Maintenant refresh avec le cookie
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)

    def test_refresh_without_cookie(self):
        """Test refresh sans cookie."""
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


@override_settings(TESTING=True)
class LogoutViewTests(APITestCase):
    """Tests pour la déconnexion."""

    def setUp(self):
        self.url = reverse("users:logout")
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPass123!",
            role=UserRole.CLIENT,
            is_active=True,
        )

    def test_logout_success(self):
        """Test déconnexion réussie."""
        # Se connecter d'abord
        self.client.post(
            reverse("users:login"),
            {
                "email": "test@example.com",
                "password": "TestPass123!",
            },
        )

        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Le cookie doit être supprimé (valeur vide et expiration passée)
        self.assertIn("refresh_token", response.cookies)


@override_settings(TESTING=True)
class ResendActivationViewTests(APITestCase):
    """Tests pour le renvoi d'activation."""

    def setUp(self):
        self.url = reverse("users:resend-activation")
        self.inactive_user = User.objects.create_user(
            username="inactive",
            email="inactive@example.com",
            password="TestPass123!",
            role=UserRole.CLIENT,
            is_active=False,
        )
        self.active_user = User.objects.create_user(
            username="active",
            email="active@example.com",
            password="TestPass123!",
            role=UserRole.CLIENT,
            is_active=True,
        )

    def test_resend_inactive_user(self):
        """Test renvoi pour utilisateur inactif."""
        response = self.client.post(
            self.url,
            {
                "email": "inactive@example.com",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_resend_active_user(self):
        """Test renvoi pour utilisateur déjà actif (pas d'info leak)."""
        response = self.client.post(
            self.url,
            {
                "email": "active@example.com",
            },
        )
        # Doit retourner succès pour ne pas divulguer l'existence du compte
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_resend_nonexistent_email(self):
        """Test renvoi pour email inexistant (pas d'info leak)."""
        response = self.client.post(
            self.url,
            {
                "email": "nonexistent@example.com",
            },
        )
        # Doit retourner succès pour ne pas divulguer l'existence du compte
        self.assertEqual(response.status_code, status.HTTP_200_OK)


# ============================================================
# Tests pour les endpoints publics de métadonnées
# ============================================================


class RegistrationOptionsViewTests(APITestCase):
    """Tests pour GET /api/auth/register/options/"""

    def setUp(self):
        self.url = reverse("users:register-options")

    def test_get_options_returns_200(self):
        """Test que l'endpoint retourne 200."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_get_options_contains_roles(self):
        """Test que la réponse contient les rôles."""
        response = self.client.get(self.url)
        data = response.json()

        self.assertIn("roles", data)
        self.assertIsInstance(data["roles"], list)
        self.assertEqual(len(data["roles"]), 2)

        # Vérifier structure
        role_values = [r["value"] for r in data["roles"]]
        self.assertIn("CLIENT", role_values)
        self.assertIn("PROVIDER", role_values)

        # Vérifier labels
        for role in data["roles"]:
            self.assertIn("value", role)
            self.assertIn("label", role)

    def test_get_options_contains_provider_kinds(self):
        """Test que la réponse contient les types de prestataire."""
        response = self.client.get(self.url)
        data = response.json()

        self.assertIn("provider_kinds", data)
        self.assertIsInstance(data["provider_kinds"], list)
        self.assertEqual(len(data["provider_kinds"]), 2)

        pk_values = [pk["value"] for pk in data["provider_kinds"]]
        self.assertIn("FREELANCE", pk_values)
        self.assertIn("AGENCY", pk_values)

    def test_get_options_contains_rules(self):
        """Test que la réponse contient les règles."""
        response = self.client.get(self.url)
        data = response.json()

        self.assertIn("rules", data)
        self.assertIsInstance(data["rules"], dict)
        self.assertEqual(data["rules"]["provider_kind_required_if_role"], "PROVIDER")
        self.assertEqual(data["rules"]["provider_kind_forbidden_if_role"], "CLIENT")

    def test_get_options_is_public(self):
        """Test que l'endpoint est accessible sans authentification."""
        # Pas de token, pas de session
        client = APIClient()
        response = client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class PublicStatsViewTests(APITestCase):
    """Tests pour GET /api/auth/public/stats/"""

    def setUp(self):
        self.url = reverse("users:public-stats")
        # Créer des utilisateurs de test
        User.objects.create_user(
            username="client1",
            email="client1@example.com",
            password="TestPass123!",
            role=UserRole.CLIENT,
            is_active=True,
        )
        User.objects.create_user(
            username="client2",
            email="client2@example.com",
            password="TestPass123!",
            role=UserRole.CLIENT,
            is_active=True,
        )
        User.objects.create_user(
            username="freelance1",
            email="freelance1@example.com",
            password="TestPass123!",
            role=UserRole.PROVIDER,
            provider_kind=ProviderKind.FREELANCE,
            is_active=True,
        )
        User.objects.create_user(
            username="agency1",
            email="agency1@example.com",
            password="TestPass123!",
            role=UserRole.PROVIDER,
            provider_kind=ProviderKind.AGENCY,
            is_active=True,
        )
        # Utilisateur inactif (ne doit pas être compté)
        User.objects.create_user(
            username="inactive",
            email="inactive@example.com",
            password="TestPass123!",
            role=UserRole.CLIENT,
            is_active=False,
        )

    def test_get_stats_returns_200(self):
        """Test que l'endpoint retourne 200."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_get_stats_contains_counts(self):
        """Test que la réponse contient les compteurs."""
        response = self.client.get(self.url)
        data = response.json()

        self.assertIn("clients_count", data)
        self.assertIn("providers_count", data)
        self.assertIn("freelances_count", data)
        self.assertIn("agencies_count", data)

    def test_get_stats_correct_values(self):
        """Test que les compteurs sont corrects."""
        response = self.client.get(self.url)
        data = response.json()

        # 2 clients actifs (pas l'inactif)
        self.assertEqual(data["clients_count"], 2)
        # 2 providers (1 freelance + 1 agency)
        self.assertEqual(data["providers_count"], 2)
        self.assertEqual(data["freelances_count"], 1)
        self.assertEqual(data["agencies_count"], 1)

    def test_get_stats_excludes_inactive_users(self):
        """Test que les utilisateurs inactifs ne sont pas comptés."""
        # Ajouter un provider inactif
        User.objects.create_user(
            username="inactive_provider",
            email="inactive_provider@example.com",
            password="TestPass123!",
            role=UserRole.PROVIDER,
            provider_kind=ProviderKind.FREELANCE,
            is_active=False,
        )

        response = self.client.get(self.url)
        data = response.json()

        # Toujours 1 seul freelance actif
        self.assertEqual(data["freelances_count"], 1)

    def test_get_stats_is_public(self):
        """Test que l'endpoint est accessible sans authentification."""
        client = APIClient()
        response = client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


# ============================================================
# Tests pour le profil Client
# ============================================================


@override_settings(TESTING=True)
class ClientProfileViewTests(APITestCase):
    """Tests pour GET/POST/PATCH /api/client/profile/"""

    def setUp(self):
        self.url = "/api/client/profile/"

        # Client user (sans profil)
        self.client_user = User.objects.create_user(
            username="clientuser",
            email="client@example.com",
            password="TestPass123!",
            role=UserRole.CLIENT,
            is_active=True,
        )

        # Provider user (ne doit pas accéder)
        self.provider_user = User.objects.create_user(
            username="provideruser",
            email="provider@example.com",
            password="TestPass123!",
            role=UserRole.PROVIDER,
            provider_kind=ProviderKind.FREELANCE,
            is_active=True,
        )

    def _auth_as(self, user):
        """Authentifie le client de test."""
        self.client.force_authenticate(user=user)

    # -------------------- GET Tests --------------------

    def test_get_without_auth_returns_401(self):
        """GET sans authentification retourne 401."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_provider_user_returns_403(self):
        """GET avec un PROVIDER retourne 403."""
        self._auth_as(self.provider_user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.json()["code"], "wrong_role")

    def test_get_client_without_profile_returns_200_with_null(self):
        """GET client sans profil retourne 200 avec client_profile=null."""
        self._auth_as(self.client_user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("user", data)
        self.assertIn("client_profile", data)
        self.assertIsNone(data["client_profile"])
        self.assertEqual(data["user"]["id"], self.client_user.id)

    def test_get_client_with_individual_profile(self):
        """GET client avec profil INDIVIDUAL retourne les détails."""
        self._auth_as(self.client_user)

        # Créer profil + détails
        profile = ClientProfile.objects.create(
            user=self.client_user,
            client_type=ClientType.INDIVIDUAL,
            city_or_region="Conakry",
            country="Guinée",
        )
        ClientIndividualDetails.objects.create(
            client_profile=profile,
            first_name="John",
            last_name="Doe",
        )

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIsNotNone(data["client_profile"])
        self.assertEqual(data["client_profile"]["client_type"], "INDIVIDUAL")
        self.assertEqual(data["client_profile"]["details"]["first_name"], "John")
        self.assertEqual(data["client_profile"]["details"]["last_name"], "Doe")

    def test_get_client_with_company_profile(self):
        """GET client avec profil COMPANY retourne les détails."""
        self._auth_as(self.client_user)

        profile = ClientProfile.objects.create(
            user=self.client_user,
            client_type=ClientType.COMPANY,
            city_or_region="Conakry",
            country="Guinée",
        )
        ClientCompanyDetails.objects.create(
            client_profile=profile,
            company_name="Ma Super Entreprise",
        )

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data["client_profile"]["client_type"], "COMPANY")
        self.assertEqual(
            data["client_profile"]["details"]["company_name"], "Ma Super Entreprise"
        )

    # -------------------- POST Tests --------------------

    def test_post_without_auth_returns_401(self):
        """POST sans authentification retourne 401."""
        response = self.client.post(self.url, {})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_post_provider_user_returns_403(self):
        """POST avec un PROVIDER retourne 403."""
        self._auth_as(self.provider_user)
        response = self.client.post(self.url, {})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_post_create_individual_success(self):
        """POST création profil INDIVIDUAL réussie."""
        self._auth_as(self.client_user)

        data = {
            "client_type": "INDIVIDUAL",
            "city_or_region": "Conakry",
            "country": "Guinée",
            "first_name": "Jean",
            "last_name": "Dupont",
        }

        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        result = response.json()
        self.assertIsNotNone(result["client_profile"])
        self.assertEqual(result["client_profile"]["client_type"], "INDIVIDUAL")
        self.assertEqual(result["client_profile"]["details"]["first_name"], "Jean")
        self.assertEqual(result["client_profile"]["details"]["last_name"], "Dupont")

        # Vérifier en base
        self.assertTrue(ClientProfile.objects.filter(user=self.client_user).exists())
        self.assertTrue(
            ClientIndividualDetails.objects.filter(
                client_profile__user=self.client_user
            ).exists()
        )

    def test_post_create_company_success(self):
        """POST création profil COMPANY réussie."""
        self._auth_as(self.client_user)

        data = {
            "client_type": "COMPANY",
            "city_or_region": "Kindia",
            "country": "Guinée",
            "postal_code": "BP 100",
            "phone": "+224 123 456 789",
            "company_name": "Entreprise SARL",
        }

        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        result = response.json()
        self.assertEqual(result["client_profile"]["client_type"], "COMPANY")
        self.assertEqual(
            result["client_profile"]["details"]["company_name"], "Entreprise SARL"
        )
        self.assertEqual(result["client_profile"]["postal_code"], "BP 100")

    def test_post_individual_missing_first_name_returns_400(self):
        """POST INDIVIDUAL sans first_name retourne 400."""
        self._auth_as(self.client_user)

        data = {
            "client_type": "INDIVIDUAL",
            "city_or_region": "Conakry",
            "country": "Guinée",
            "last_name": "Dupont",
        }

        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("first_name", response.json())

    def test_post_company_missing_company_name_returns_400(self):
        """POST COMPANY sans company_name retourne 400."""
        self._auth_as(self.client_user)

        data = {
            "client_type": "COMPANY",
            "city_or_region": "Conakry",
            "country": "Guinée",
        }

        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("company_name", response.json())

    def test_post_second_time_returns_409(self):
        """POST une seconde fois retourne 409 Conflict."""
        self._auth_as(self.client_user)

        # Première création
        ClientProfile.objects.create(
            user=self.client_user,
            client_type=ClientType.INDIVIDUAL,
            city_or_region="Conakry",
            country="Guinée",
        )

        # Deuxième tentative
        data = {
            "client_type": "COMPANY",
            "city_or_region": "Kindia",
            "country": "Guinée",
            "company_name": "Test",
        }

        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(response.json()["code"], "profile_exists")

    # -------------------- PATCH Tests --------------------

    def test_patch_without_auth_returns_401(self):
        """PATCH sans authentification retourne 401."""
        response = self.client.patch(self.url, {})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_patch_provider_user_returns_403(self):
        """PATCH avec un PROVIDER retourne 403."""
        self._auth_as(self.provider_user)
        response = self.client.patch(self.url, {})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_patch_without_profile_returns_409(self):
        """PATCH sans profil existant retourne 409."""
        self._auth_as(self.client_user)

        response = self.client.patch(
            self.url, {"city_or_region": "Kindia"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(response.json()["code"], "profile_not_created")

    def test_patch_update_individual_success(self):
        """PATCH mise à jour profil INDIVIDUAL réussie."""
        self._auth_as(self.client_user)

        # Créer profil
        profile = ClientProfile.objects.create(
            user=self.client_user,
            client_type=ClientType.INDIVIDUAL,
            city_or_region="Conakry",
            country="Guinée",
        )
        ClientIndividualDetails.objects.create(
            client_profile=profile,
            first_name="John",
            last_name="Doe",
        )

        # Mettre à jour
        data = {
            "city_or_region": "Kindia",
            "first_name": "Johnny",
        }

        response = self.client.patch(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        result = response.json()
        self.assertEqual(result["client_profile"]["city_or_region"], "Kindia")
        self.assertEqual(result["client_profile"]["details"]["first_name"], "Johnny")
        self.assertEqual(
            result["client_profile"]["details"]["last_name"], "Doe"
        )  # inchangé

    def test_patch_update_company_success(self):
        """PATCH mise à jour profil COMPANY réussie."""
        self._auth_as(self.client_user)

        profile = ClientProfile.objects.create(
            user=self.client_user,
            client_type=ClientType.COMPANY,
            city_or_region="Conakry",
            country="Guinée",
        )
        ClientCompanyDetails.objects.create(
            client_profile=profile,
            company_name="Ancienne SARL",
        )

        data = {
            "phone": "+224 999 888 777",
            "company_name": "Nouvelle SARL",
        }

        response = self.client.patch(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        result = response.json()
        self.assertEqual(result["client_profile"]["phone"], "+224 999 888 777")
        self.assertEqual(
            result["client_profile"]["details"]["company_name"], "Nouvelle SARL"
        )

    def test_patch_attempt_change_client_type_returns_400(self):
        """PATCH tentative de modifier client_type retourne 400."""
        self._auth_as(self.client_user)

        profile = ClientProfile.objects.create(
            user=self.client_user,
            client_type=ClientType.INDIVIDUAL,
            city_or_region="Conakry",
            country="Guinée",
        )
        ClientIndividualDetails.objects.create(
            client_profile=profile,
            first_name="John",
            last_name="Doe",
        )

        data = {
            "client_type": "COMPANY",
        }

        response = self.client.patch(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("client_type", response.json())


# ============================================================
# Tests Client Company Documents (CRUD)
# ============================================================


class ClientCompanyDocumentTests(APITestCase):
    """
    Tests des endpoints de gestion des documents entreprise.

    Endpoints testés:
    - GET /api/client/company/documents/
    - POST /api/client/company/documents/
    - GET /api/client/company/documents/{id}/
    - PATCH /api/client/company/documents/{id}/
    - DELETE /api/client/company/documents/{id}/
    """

    def setUp(self):
        """Configuration des tests."""
        self.list_url = reverse("client-company-documents-list")

        # User CLIENT avec profil COMPANY (setup complet)
        self.company_user = User.objects.create_user(
            username="company",
            email="company@example.com",
            password="Password123!",
            role=UserRole.CLIENT,
            is_active=True,
        )
        self.company_profile = ClientProfile.objects.create(
            user=self.company_user,
            client_type=ClientType.COMPANY,
            city_or_region="Conakry",
            country="Guinée",
        )
        self.company_details = ClientCompanyDetails.objects.create(
            client_profile=self.company_profile,
            company_name="Ma SARL",
        )

        # User CLIENT avec profil INDIVIDUAL (pas d'accès aux documents)
        self.individual_user = User.objects.create_user(
            username="individual",
            email="individual@example.com",
            password="Password123!",
            role=UserRole.CLIENT,
            is_active=True,
        )
        self.individual_profile = ClientProfile.objects.create(
            user=self.individual_user,
            client_type=ClientType.INDIVIDUAL,
            city_or_region="Kindia",
            country="Guinée",
        )
        ClientIndividualDetails.objects.create(
            client_profile=self.individual_profile,
            first_name="John",
            last_name="Doe",
        )

        # User PROVIDER
        self.provider_user = User.objects.create_user(
            username="provider",
            email="provider@example.com",
            password="Password123!",
            role=UserRole.PROVIDER,
            provider_kind=ProviderKind.FREELANCE,
            is_active=True,
        )

        # User CLIENT sans profil
        self.no_profile_user = User.objects.create_user(
            username="noprofile",
            email="noprofile@example.com",
            password="Password123!",
            role=UserRole.CLIENT,
            is_active=True,
        )

        # Autre user COMPANY (pour tester l'isolation)
        self.other_company_user = User.objects.create_user(
            username="othercompany",
            email="other@example.com",
            password="Password123!",
            role=UserRole.CLIENT,
            is_active=True,
        )
        other_profile = ClientProfile.objects.create(
            user=self.other_company_user,
            client_type=ClientType.COMPANY,
            city_or_region="Labé",
            country="Guinée",
        )
        self.other_company_details = ClientCompanyDetails.objects.create(
            client_profile=other_profile,
            company_name="Autre SARL",
        )

    def _auth_as(self, user):
        """Authentifie le client de test comme le user donné."""
        refresh = RefreshToken.for_user(user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

    def _create_test_file(self, name="test.pdf", content=b"dummy content"):
        """Crée un fichier temporaire pour les tests d'upload."""
        from io import BytesIO
        from django.core.files.uploadedfile import SimpleUploadedFile

        return SimpleUploadedFile(
            name=name,
            content=content,
            content_type="application/pdf",
        )

    def detail_url(self, pk):
        """Retourne l'URL de détail d'un document."""
        return reverse("client-company-documents-detail", kwargs={"pk": pk})

    # ---------- Tests GET list ----------

    def test_list_requires_authentication(self):
        """GET /documents/ sans auth retourne 401."""
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_list_provider_forbidden(self):
        """GET /documents/ avec PROVIDER retourne 403."""
        self._auth_as(self.provider_user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.json()["code"], "wrong_role")

    def test_list_individual_forbidden(self):
        """GET /documents/ avec CLIENT INDIVIDUAL retourne 403."""
        self._auth_as(self.individual_user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.json()["code"], "company_profile_required")

    def test_list_no_profile_returns_409(self):
        """GET /documents/ sans profil retourne 409."""
        self._auth_as(self.no_profile_user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(response.json()["code"], "profile_not_created")

    def test_list_empty_success(self):
        """GET /documents/ retourne liste vide si pas de documents."""
        self._auth_as(self.company_user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # DRF pagination activée
        data = response.json()
        self.assertEqual(data.get("count", len(data)), 0)
        results = data.get("results", data)
        self.assertEqual(results, [])

    def test_list_with_documents_success(self):
        """GET /documents/ retourne les documents de l'entreprise."""
        self._auth_as(self.company_user)

        # Créer 2 documents
        ClientCompanyDocument.objects.create(
            company=self.company_details,
            doc_type="RCCM",
            file="test1.pdf",
            reference_number="REF-001",
        )
        ClientCompanyDocument.objects.create(
            company=self.company_details,
            doc_type="LEGAL",
            file="test2.pdf",
        )

        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        data = response.json()
        # Gestion pagination
        results = data.get("results", data)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["doc_type"], "LEGAL")  # Plus récent en premier
        self.assertEqual(results[1]["doc_type"], "RCCM")

    def test_list_isolation_between_companies(self):
        """Un user ne voit pas les documents d'une autre entreprise."""
        # Créer document pour other_company
        ClientCompanyDocument.objects.create(
            company=self.other_company_details,
            doc_type="RCCM",
            file="other.pdf",
        )

        self._auth_as(self.company_user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Gestion pagination
        data = response.json()
        results = data.get("results", data)
        self.assertEqual(results, [])  # Ne voit pas le document de l'autre

    # ---------- Tests POST create ----------

    def test_create_document_success(self):
        """POST /documents/ crée un document avec succès."""
        self._auth_as(self.company_user)

        data = {
            "doc_type": "RCCM",
            "file": self._create_test_file("rccm.pdf"),
            "reference_number": "GN-2026-001",
        }

        response = self.client.post(self.list_url, data, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        result = response.json()
        self.assertEqual(result["doc_type"], "RCCM")
        self.assertEqual(result["reference_number"], "GN-2026-001")
        self.assertIn("file_url", result)
        self.assertIn("id", result)

        # Vérifier en base
        self.assertEqual(ClientCompanyDocument.objects.count(), 1)
        doc = ClientCompanyDocument.objects.first()
        self.assertEqual(doc.company, self.company_details)

    def test_create_document_without_reference(self):
        """POST /documents/ sans reference_number réussit."""
        self._auth_as(self.company_user)

        data = {
            "doc_type": "OTHER",
            "file": self._create_test_file("doc.pdf"),
        }

        response = self.client.post(self.list_url, data, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.json()["reference_number"], "")

    def test_create_document_missing_file_returns_400(self):
        """POST /documents/ sans fichier retourne 400."""
        self._auth_as(self.company_user)

        data = {"doc_type": "RCCM"}

        response = self.client.post(self.list_url, data, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("file", response.json())

    def test_create_document_invalid_doc_type_returns_400(self):
        """POST /documents/ avec doc_type invalide retourne 400."""
        self._auth_as(self.company_user)

        data = {
            "doc_type": "INVALID",
            "file": self._create_test_file(),
        }

        response = self.client.post(self.list_url, data, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("doc_type", response.json())

    def test_create_provider_forbidden(self):
        """POST /documents/ avec PROVIDER retourne 403."""
        self._auth_as(self.provider_user)

        data = {
            "doc_type": "RCCM",
            "file": self._create_test_file(),
        }

        response = self.client.post(self.list_url, data, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_create_individual_forbidden(self):
        """POST /documents/ avec CLIENT INDIVIDUAL retourne 403."""
        self._auth_as(self.individual_user)

        data = {
            "doc_type": "RCCM",
            "file": self._create_test_file(),
        }

        response = self.client.post(self.list_url, data, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # ---------- Tests GET detail ----------

    def test_detail_success(self):
        """GET /documents/{id}/ retourne les détails du document."""
        self._auth_as(self.company_user)

        doc = ClientCompanyDocument.objects.create(
            company=self.company_details,
            doc_type="RCCM",
            file="test.pdf",
            reference_number="REF-001",
        )

        response = self.client.get(self.detail_url(doc.pk))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["id"], doc.pk)
        self.assertEqual(response.json()["doc_type"], "RCCM")

    def test_detail_other_company_returns_404(self):
        """GET /documents/{id}/ pour un document d'une autre entreprise retourne 404."""
        self._auth_as(self.company_user)

        # Document de l'autre entreprise
        other_doc = ClientCompanyDocument.objects.create(
            company=self.other_company_details,
            doc_type="RCCM",
            file="other.pdf",
        )

        response = self.client.get(self.detail_url(other_doc.pk))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_detail_nonexistent_returns_404(self):
        """GET /documents/{id}/ pour un ID inexistant retourne 404."""
        self._auth_as(self.company_user)
        response = self.client.get(self.detail_url(99999))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    # ---------- Tests PATCH update ----------

    def test_patch_document_success(self):
        """PATCH /documents/{id}/ met à jour le document."""
        self._auth_as(self.company_user)

        doc = ClientCompanyDocument.objects.create(
            company=self.company_details,
            doc_type="OTHER",
            file="test.pdf",
            reference_number="OLD-REF",
        )

        data = {
            "doc_type": "LEGAL",
            "reference_number": "NEW-REF",
        }

        response = self.client.patch(self.detail_url(doc.pk), data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        result = response.json()
        self.assertEqual(result["doc_type"], "LEGAL")
        self.assertEqual(result["reference_number"], "NEW-REF")

        # Vérifier en base
        doc.refresh_from_db()
        self.assertEqual(doc.doc_type, "LEGAL")
        self.assertEqual(doc.reference_number, "NEW-REF")

    def test_patch_partial_update(self):
        """PATCH /documents/{id}/ avec un seul champ."""
        self._auth_as(self.company_user)

        doc = ClientCompanyDocument.objects.create(
            company=self.company_details,
            doc_type="RCCM",
            file="test.pdf",
            reference_number="REF-001",
        )

        data = {"reference_number": "UPDATED-REF"}

        response = self.client.patch(self.detail_url(doc.pk), data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        doc.refresh_from_db()
        self.assertEqual(doc.doc_type, "RCCM")  # Inchangé
        self.assertEqual(doc.reference_number, "UPDATED-REF")  # Modifié

    def test_patch_other_company_returns_404(self):
        """PATCH /documents/{id}/ pour un document d'une autre entreprise retourne 404."""
        self._auth_as(self.company_user)

        other_doc = ClientCompanyDocument.objects.create(
            company=self.other_company_details,
            doc_type="RCCM",
            file="other.pdf",
        )

        data = {"doc_type": "LEGAL"}

        response = self.client.patch(self.detail_url(other_doc.pk), data, format="json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    # ---------- Tests DELETE ----------

    def test_delete_document_success(self):
        """DELETE /documents/{id}/ supprime le document."""
        self._auth_as(self.company_user)

        doc = ClientCompanyDocument.objects.create(
            company=self.company_details,
            doc_type="RCCM",
            file="test.pdf",
        )

        response = self.client.delete(self.detail_url(doc.pk))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # Vérifier suppression
        self.assertEqual(ClientCompanyDocument.objects.count(), 0)

    def test_delete_other_company_returns_404(self):
        """DELETE /documents/{id}/ pour un document d'une autre entreprise retourne 404."""
        self._auth_as(self.company_user)

        other_doc = ClientCompanyDocument.objects.create(
            company=self.other_company_details,
            doc_type="RCCM",
            file="other.pdf",
        )

        response = self.client.delete(self.detail_url(other_doc.pk))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        # Document toujours là
        self.assertTrue(ClientCompanyDocument.objects.filter(pk=other_doc.pk).exists())

    def test_delete_provider_forbidden(self):
        """DELETE /documents/{id}/ avec PROVIDER retourne 403."""
        doc = ClientCompanyDocument.objects.create(
            company=self.company_details,
            doc_type="RCCM",
            file="test.pdf",
        )

        self._auth_as(self.provider_user)
        response = self.client.delete(self.detail_url(doc.pk))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_individual_forbidden(self):
        """DELETE /documents/{id}/ avec CLIENT INDIVIDUAL retourne 403."""
        doc = ClientCompanyDocument.objects.create(
            company=self.company_details,
            doc_type="RCCM",
            file="test.pdf",
        )

        self._auth_as(self.individual_user)
        response = self.client.delete(self.detail_url(doc.pk))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
