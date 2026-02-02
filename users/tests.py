"""
Tests pour l'authentification.
"""

from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status

from .tokens import activation_token_generator, encode_uid, decode_uid
from .models import UserRole, ProviderKind

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
