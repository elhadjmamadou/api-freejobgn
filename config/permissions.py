"""
Permissions personnalisées pour le projet.
"""

from rest_framework.permissions import BasePermission


class IsSuperUser(BasePermission):
    """
    Permission qui n'autorise l'accès qu'aux superusers.
    
    Contrairement à IsAdminUser qui accepte is_staff=True,
    cette permission exige strictement is_superuser=True.
    """

    message = "Accès réservé aux super-administrateurs."

    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.is_superuser
        )
