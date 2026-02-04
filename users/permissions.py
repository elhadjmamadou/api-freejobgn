from rest_framework.permissions import BasePermission


class IsFreelance(BasePermission):
    """
    Autorise uniquement les utilisateurs authentifiés:
    role=PROVIDER et provider_kind=FREELANCE
    """
    message = "Accès réservé aux prestataires FREELANCE."

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and getattr(user, "is_freelance", False))

class IsAgency(BasePermission):
    """Accès réservé aux utilisateurs PROVIDER/AGENCY."""
    message = "Accès réservé aux prestataires AGENCY."

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and getattr(user, "is_agency", False))
