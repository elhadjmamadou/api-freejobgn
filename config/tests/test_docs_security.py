"""
Tests de sécurité pour les endpoints de documentation API.

Ces tests vérifient que:
- Les utilisateurs non authentifiés reçoivent 401 + WWW-Authenticate header
- Les utilisateurs normaux authentifiés reçoivent 403
- Les superusers ont accès (200)
"""

import base64

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

User = get_user_model()


class DocsSecurityTestCase(TestCase):
    """Tests de sécurité pour schema, swagger-ui et redoc."""

    @classmethod
    def setUpTestData(cls):
        """Création des utilisateurs de test."""
        cls.normal_user = User.objects.create_user(
            username="normaluser",
            email="normal@example.com",
            password="testpass123",
        )
        cls.superuser = User.objects.create_superuser(
            username="superadmin",
            email="admin@example.com",
            password="superpass123",
        )

    def setUp(self):
        """Initialisation du client API pour chaque test."""
        self.client = APIClient()

    def _get_basic_auth_header(self, username, password):
        """Génère le header Authorization Basic."""
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"

    # ========== Tests pour /api/schema/ ==========

    def test_schema_unauthenticated_returns_401_with_www_authenticate(self):
        """Accès non authentifié à /api/schema/ => 401 + WWW-Authenticate."""
        response = self.client.get(reverse("schema"))
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("WWW-Authenticate", response)
        self.assertIn("Basic", response["WWW-Authenticate"])

    def test_schema_normal_user_returns_403(self):
        """Utilisateur normal authentifié à /api/schema/ => 403."""
        auth_header = self._get_basic_auth_header("normaluser", "testpass123")
        response = self.client.get(
            reverse("schema"),
            HTTP_AUTHORIZATION=auth_header,
        )
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_schema_superuser_returns_200(self):
        """Superuser authentifié à /api/schema/ => 200."""
        auth_header = self._get_basic_auth_header("superadmin", "superpass123")
        response = self.client.get(
            reverse("schema"),
            HTTP_AUTHORIZATION=auth_header,
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    # ========== Tests pour / (Swagger UI) ==========

    def test_swagger_unauthenticated_returns_401_with_www_authenticate(self):
        """Accès non authentifié à / (swagger) => 401 + WWW-Authenticate."""
        response = self.client.get(reverse("swagger-ui"))
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("WWW-Authenticate", response)
        self.assertIn("Basic", response["WWW-Authenticate"])

    def test_swagger_normal_user_returns_403(self):
        """Utilisateur normal authentifié à / (swagger) => 403."""
        auth_header = self._get_basic_auth_header("normaluser", "testpass123")
        response = self.client.get(
            reverse("swagger-ui"),
            HTTP_AUTHORIZATION=auth_header,
        )
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_swagger_superuser_returns_200(self):
        """Superuser authentifié à / (swagger) => 200."""
        auth_header = self._get_basic_auth_header("superadmin", "superpass123")
        response = self.client.get(
            reverse("swagger-ui"),
            HTTP_AUTHORIZATION=auth_header,
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    # ========== Tests pour /api/redoc/ ==========

    def test_redoc_unauthenticated_returns_401_with_www_authenticate(self):
        """Accès non authentifié à /api/redoc/ => 401 + WWW-Authenticate."""
        response = self.client.get(reverse("redoc"))
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("WWW-Authenticate", response)
        self.assertIn("Basic", response["WWW-Authenticate"])

    def test_redoc_normal_user_returns_403(self):
        """Utilisateur normal authentifié à /api/redoc/ => 403."""
        auth_header = self._get_basic_auth_header("normaluser", "testpass123")
        response = self.client.get(
            reverse("redoc"),
            HTTP_AUTHORIZATION=auth_header,
        )
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_redoc_superuser_returns_200(self):
        """Superuser authentifié à /api/redoc/ => 200."""
        auth_header = self._get_basic_auth_header("superadmin", "superpass123")
        response = self.client.get(
            reverse("redoc"),
            HTTP_AUTHORIZATION=auth_header,
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    # ========== Tests supplémentaires ==========

    def test_staff_user_without_superuser_returns_403(self):
        """Un staff (is_staff=True) sans is_superuser => 403."""
        staff_user = User.objects.create_user(
            username="staffuser",
            email="staff@example.com",
            password="staffpass123",
            is_staff=True,
        )
        auth_header = self._get_basic_auth_header("staffuser", "staffpass123")
        response = self.client.get(
            reverse("schema"),
            HTTP_AUTHORIZATION=auth_header,
        )
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_invalid_credentials_returns_401(self):
        """Credentials invalides => 401."""
        auth_header = self._get_basic_auth_header("superadmin", "wrongpassword")
        response = self.client.get(
            reverse("schema"),
            HTTP_AUTHORIZATION=auth_header,
        )
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
