"""
Utilitaires pour la génération et validation des tokens d'activation.
Utilise les tokens signés Django (TimestampSigner) avec expiration.
"""

import base64
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from django.utils import timezone

User = get_user_model()


class AccountActivationTokenGenerator:
    """
    Générateur de tokens d'activation basé sur TimestampSigner.
    Le token est signé et contient un timestamp pour l'expiration.
    """

    def __init__(self):
        self.signer = TimestampSigner(salt="account-activation")

    def make_token(self, user) -> str:
        """
        Génère un token d'activation pour l'utilisateur.
        Le token inclut l'ID utilisateur et un hash de l'état du compte.
        """
        # On inclut is_active dans la signature pour invalider
        # automatiquement le token si l'utilisateur est déjà activé
        value = f"{user.pk}:{user.is_active}:{user.password[:20]}"
        return self.signer.sign(value)

    def validate_token(self, user, token: str) -> bool:
        """
        Valide un token d'activation.
        Retourne True si le token est valide et non expiré.
        """
        try:
            # Récupère la durée d'expiration depuis settings
            max_age_hours = getattr(settings, "ACTIVATION_TOKEN_EXPIRY_HOURS", 24)
            max_age = timedelta(hours=max_age_hours)

            # Décode et vérifie la signature + expiration
            value = self.signer.unsign(token, max_age=max_age)

            # Vérifie que le token correspond à l'état actuel
            expected = f"{user.pk}:{user.is_active}:{user.password[:20]}"
            return value == expected

        except SignatureExpired:
            return False
        except BadSignature:
            return False

    def check_token_expired(self, token: str) -> bool:
        """Vérifie si un token est expiré (pour messages d'erreur)."""
        try:
            max_age_hours = getattr(settings, "ACTIVATION_TOKEN_EXPIRY_HOURS", 24)
            max_age = timedelta(hours=max_age_hours)
            self.signer.unsign(token, max_age=max_age)
            return False
        except SignatureExpired:
            return True
        except BadSignature:
            return False  # Token invalide, pas expiré


def encode_uid(user_id: int) -> str:
    """Encode l'ID utilisateur en base64 URL-safe."""
    return base64.urlsafe_b64encode(str(user_id).encode()).decode()


def decode_uid(uid_b64: str) -> int | None:
    """Décode l'ID utilisateur depuis base64. Retourne None si invalide."""
    try:
        uid = base64.urlsafe_b64decode(uid_b64.encode()).decode()
        return int(uid)
    except (ValueError, TypeError, UnicodeDecodeError):
        return None


# Instance singleton du générateur
activation_token_generator = AccountActivationTokenGenerator()
