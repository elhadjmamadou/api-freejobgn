"""
Configuration pytest globale pour tous les tests.
"""

import pytest
from django.conf import settings


def pytest_configure(config):
    """
    Configuration de l'environnement de test avant l'exécution des tests.
    """
    # Désactiver le throttling pour les tests
    settings.TESTING = True
    # Forcer le backend email pour les tests
    settings.EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"


@pytest.fixture(autouse=True)
def _setup_mail_outbox():
    """
    Initialise mail.outbox pour chaque test (compatibilité Django 6+).
    """
    from django.core import mail
    if not hasattr(mail, 'outbox'):
        mail.outbox = []
    else:
        mail.outbox.clear()
    yield
    if hasattr(mail, 'outbox'):
        mail.outbox.clear()


@pytest.fixture(scope="session")
def django_db_setup():
    """
    Configuration de la base de données pour les tests.
    Utilise la configuration par défaut de pytest-django.
    """
    pass
