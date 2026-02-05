# projects/services/marketplace.py
from __future__ import annotations

from datetime import timedelta

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from projects.models import Project, ProjectStatus, Proposal, ProposalStatus
from projects.services.guards import ensure_provider_has_capacity
from projects.services.contracts import create_contract_from_confirmed_proposal


SELECTION_TTL_HOURS = 48


@transaction.atomic
def select_proposal_by_client(*, project_id, proposal_id, client_user) -> Proposal:
    """
    Client sélectionne une proposition:
    - Project doit être PUBLISHED
    - Proposal doit être PENDING/SHORTLISTED
    - Bloque si provider freelance déjà engagé
    - Refuse auto les autres propositions actives
    """
    project = Project.objects.select_for_update().get(id=project_id)

    if project.client_id != client_user.id:
        raise ValidationError("Ce projet ne vous appartient pas.")
    if project.status != ProjectStatus.PUBLISHED:
        raise ValidationError("Le projet doit être PUBLISHED pour sélectionner une proposition.")

    proposal = Proposal.objects.select_for_update().select_related("provider").get(id=proposal_id, project_id=project_id)

    if proposal.status not in {ProposalStatus.PENDING, ProposalStatus.SHORTLISTED}:
        raise ValidationError("Cette proposition n'est pas sélectionnable.")

    # ✅ règle: freelance ne doit pas avoir un contrat actif
    ensure_provider_has_capacity(proposal.provider)

    now = timezone.now()
    proposal.status = ProposalStatus.SELECTED
    proposal.decided_at = now
    proposal.selected_at = now
    proposal.selection_expires_at = now + timedelta(hours=SELECTION_TTL_HOURS)
    proposal.save(update_fields=["status", "decided_at", "selected_at", "selection_expires_at"])

    # auto-refus des autres propositions en attente
    Proposal.objects.filter(
        project_id=project_id,
        status__in=[ProposalStatus.PENDING, ProposalStatus.SHORTLISTED],
    ).exclude(id=proposal.id).update(
        status=ProposalStatus.REFUSED_AUTOCLOSE,
        decided_at=now,
    )

    return proposal


@transaction.atomic
def confirm_selected_proposal(*, proposal_id, provider_user, pay_full_upfront: bool = False):
    """
    Provider confirme:
    - proposal doit être SELECTED et non expirée
    - re-check capacity (freelance)
    - passe CONFIRMED
    - crée contrat (total_amount = proposal.price)
    """
    proposal = Proposal.objects.select_for_update().select_related("provider", "project").get(id=proposal_id)

    if proposal.provider_id != provider_user.id:
        raise ValidationError("Seul le prestataire de cette proposition peut confirmer.")
    if proposal.status != ProposalStatus.SELECTED:
        raise ValidationError("La proposition doit être SELECTED pour être confirmée.")

    # ✅ re-check capacity (anti course)
    ensure_provider_has_capacity(provider_user)

    if proposal.selection_expires_at and timezone.now() > proposal.selection_expires_at:
        # expire => on annule la sélection
        proposal.status = ProposalStatus.DECLINED_BY_PROVIDER
        proposal.decision_reason = "EXPIRED"
        proposal.decided_at = timezone.now()
        proposal.save(update_fields=["status", "decision_reason", "decided_at"])
        _reopen_project_after_decline(proposal.project_id)
        raise ValidationError("La période de confirmation a expiré. Le client doit re-sélectionner.")

    proposal.status = ProposalStatus.CONFIRMED
    proposal.decided_at = timezone.now()
    proposal.save(update_fields=["status", "decided_at"])

    contract = create_contract_from_confirmed_proposal(
        proposal_id=proposal.id,
        pay_full_upfront=pay_full_upfront,
    )
    return contract


@transaction.atomic
def decline_selected_proposal(*, proposal_id, provider_user, reason: str = "") -> Proposal:
    """
    Provider refuse:
    - proposal SELECTED -> DECLINED_BY_PROVIDER
    - réouvre projet + remet REFUSED_AUTOCLOSE en PENDING
    """
    proposal = Proposal.objects.select_for_update().select_related("project").get(id=proposal_id)

    if proposal.provider_id != provider_user.id:
        raise ValidationError("Seul le prestataire de cette proposition peut refuser.")
    if proposal.status != ProposalStatus.SELECTED:
        raise ValidationError("La proposition doit être SELECTED pour être refusée.")

    proposal.status = ProposalStatus.DECLINED_BY_PROVIDER
    proposal.decided_at = timezone.now()
    proposal.decision_reason = reason or ""
    proposal.save(update_fields=["status", "decided_at", "decision_reason"])

    _reopen_project_after_decline(proposal.project_id)
    return proposal


def _reopen_project_after_decline(project_id):
    Project.objects.filter(id=project_id).update(status=ProjectStatus.PUBLISHED)

    Proposal.objects.filter(
        project_id=project_id,
        status=ProposalStatus.REFUSED_AUTOCLOSE,
    ).update(
        status=ProposalStatus.PENDING,
        decided_at=None,
        decision_reason="",
    )
