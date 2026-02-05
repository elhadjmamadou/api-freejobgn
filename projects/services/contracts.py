# projects/services/contracts.py
from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from projects.models import (
    money, half_up,
    ProjectStatus,
    Proposal, ProposalStatus,
    Contract, ContractFundingPlan, ContractStatus,
    Milestone, MilestoneStatus,
)
from projects.services.guards import ensure_provider_has_capacity


def build_default_milestones_payload(total_amount, pay_full_upfront: bool) -> list[dict]:
    """
    Pré-remplissage métier:
    - défaut: 2 jalons (moitié, reste)
    - upfront: (total, 0) => le jalon à 0 n'est pas créé en DB
    """
    total_amount = money(total_amount)

    if pay_full_upfront:
        return [
            {"order": 1, "title": "Acompte (100%)", "amount": total_amount},
            {"order": 2, "title": "Solde", "amount": 0},
        ]

    first = half_up(total_amount)
    second = money(total_amount - first)
    return [
        {"order": 1, "title": "Acompte (50%)", "amount": first},
        {"order": 2, "title": "Solde", "amount": second},
    ]


@transaction.atomic
def create_contract_from_confirmed_proposal(*, proposal_id, pay_full_upfront: bool = False) -> Contract:
    """
    CŒUR:
    - proposition doit être CONFIRMED
    - total_amount = proposal.price
    - applique règle "freelance capacity" (re-check)
    - crée jalons
    - met le projet en IN_PROGRESS
    - idempotent: si contrat existe déjà, retourne le même
    """
    proposal = (
        Proposal.objects
        .select_for_update()
        .select_related("project", "provider", "project__client")
        .get(id=proposal_id)
    )

    if proposal.status != ProposalStatus.CONFIRMED:
        raise ValidationError("La proposition doit être CONFIRMED pour créer un contrat.")

    provider = proposal.provider
    ensure_provider_has_capacity(provider)

    project = proposal.project

    # idempotence (OneToOne project->contract) : si déjà créé, on retourne
    existing = Contract.objects.select_for_update().filter(project_id=project.id).first()
    if existing:
        return existing

    contract = Contract.objects.create(
        project=project,
        proposal=proposal,
        client=project.client,
        provider=provider,
        provider_kind_snapshot=provider.provider_kind,  # snapshot
        total_amount=proposal.price,                    # ✅ COPIE PRIX FINAL
        funding_plan=ContractFundingPlan.UPFRONT_100 if pay_full_upfront else ContractFundingPlan.SPLIT_50_50,
        status=ContractStatus.IN_PROGRESS,
        start_at=timezone.now(),
    )

    # jalons pré-remplis
    for p in build_default_milestones_payload(contract.total_amount, pay_full_upfront):
        amt = money(p["amount"])
        if amt <= 0:
            continue
        Milestone.objects.create(
            contract=contract,
            order=p["order"],
            title=p["title"],
            amount=amt,
            status=MilestoneStatus.PENDING,
        )

    # projet en cours
    if project.status != ProjectStatus.IN_PROGRESS:
        project.status = ProjectStatus.IN_PROGRESS
        project.save(update_fields=["status"])

    return contract
