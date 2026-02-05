# projects/services/guards.py
from __future__ import annotations

from django.core.exceptions import ValidationError

from projects.models import Contract, ACTIVE_CONTRACT_STATUSES
from users.models import UserRole


def ensure_provider(user) -> None:
    if not user or getattr(user, "role", None) != UserRole.PROVIDER:
        raise ValidationError("Action réservée aux prestataires (role=PROVIDER).")


def ensure_provider_has_capacity(user) -> None:
    """
    Règle business:
    - FREELANCE: max 1 contrat actif (IN_PROGRESS/ON_HOLD)
    - AGENCY: illimité
    """
    ensure_provider(user)

    # votre User expose is_freelance/is_agency :contentReference[oaicite:1]{index=1}
    if not getattr(user, "is_freelance", False):
        return

    has_active = Contract.objects.filter(
        provider_id=user.id,
        status__in=ACTIVE_CONTRACT_STATUSES,
    ).exists()

    if has_active:
        raise ValidationError(
            "Vous avez déjà un projet en cours. Terminez/Clôturez le contrat avant de postuler à un autre."
        )
