# projects/models.py
from __future__ import annotations

import uuid
from decimal import Decimal, ROUND_UP

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from django.utils import timezone

from users.models import TimeStampedModel, Skill, Speciality, UserRole, ProviderKind


CENT = Decimal("0.01")
MIN_PROJECT_BUDGET = Decimal("2500000.00")  # 2 500 000


def money(value) -> Decimal:
    return Decimal(str(value)).quantize(CENT)


def half_up(amount: Decimal) -> Decimal:
    """Moitié arrondie vers le haut (garantit >= moitié)."""
    return (amount / Decimal("2")).quantize(CENT, rounding=ROUND_UP)


def upload_to_project_dir(instance, filename: str) -> str:
    """Ex: projects/<client_id>/<project_uuid>/file.pdf"""
    project_id = getattr(instance, "project_id", None) or "unknown"
    client_id = getattr(getattr(instance, "project", None), "client_id", None) or "unknown"
    return f"projects/{client_id}/{project_id}/{filename}"


# ============================================================
# Project
# ============================================================

class ProjectCategory(TimeStampedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    name = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ("name",)
        indexes = [models.Index(fields=["name"])]

    def __str__(self) -> str:
        return self.name


class ProjectStatus(models.TextChoices):
    DRAFT = "DRAFT", "Brouillon"
    PENDING_REVIEW = "PENDING_REVIEW", "En cours de validation"
    PUBLISHED = "PUBLISHED", "Publié"
    IN_PROGRESS = "IN_PROGRESS", "En cours"
    CLOSED = "CLOSED", "Clôturé"
    REJECTED = "REJECTED", "Refusé"
    CANCELLED = "CANCELLED", "Annulé"


class ProjectBudgetBand(models.TextChoices):
    BAND_25_50 = "BAND_25_50", "2 500 000 – 5 000 000"
    BAND_50_100 = "BAND_50_100", "5 000 000 – 10 000 000"
    BAND_100_PLUS = "BAND_100_PLUS", "10 000 000+"


BUDGET_BAND_MINMAX: dict[str, tuple[Decimal, Decimal | None]] = {
    ProjectBudgetBand.BAND_25_50: (Decimal("2500000.00"), Decimal("5000000.00")),
    ProjectBudgetBand.BAND_50_100: (Decimal("5000000.00"), Decimal("10000000.00")),
    ProjectBudgetBand.BAND_100_PLUS: (Decimal("10000000.00"), None),
}


class Project(TimeStampedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    client = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="projects",
        limit_choices_to={"role": UserRole.CLIENT},
    )
    category = models.ForeignKey(ProjectCategory, on_delete=models.PROTECT, related_name="projects")

    title = models.CharField(max_length=200)
    description = models.TextField()

    budget_band = models.CharField(max_length=20, choices=ProjectBudgetBand.choices, db_index=True)

    # Référentiels
    skills = models.ManyToManyField(Skill, related_name="projects", blank=True)
    speciality = models.ForeignKey(
        Speciality,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="projects",
    )

    deadline = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=ProjectStatus.choices, default=ProjectStatus.DRAFT, db_index=True)
    review_note = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["status", "created_at"]),
            models.Index(fields=["client", "status"]),
            models.Index(fields=["budget_band", "created_at"]),
        ]

    def clean(self):
        super().clean()

        if self.client_id and getattr(self.client, "role", None) != UserRole.CLIENT:
            raise ValidationError({"client": "Le client doit avoir role=CLIENT."})

        if self.budget_band not in ProjectBudgetBand.values:
            raise ValidationError({"budget_band": "Tranche budget invalide."})

        band_min, _ = BUDGET_BAND_MINMAX[self.budget_band]
        if band_min < MIN_PROJECT_BUDGET:
            raise ValidationError({"budget_band": "Budget minimum projet = 2 500 000."})

    @property
    def budget_min_value(self) -> Decimal:
        return BUDGET_BAND_MINMAX[self.budget_band][0]

    @property
    def budget_max_value(self) -> Decimal | None:
        return BUDGET_BAND_MINMAX[self.budget_band][1]

    def __str__(self) -> str:
        return self.title


# ============================================================
# Cahier de charge / documents projet
# ============================================================

class ProjectDocumentType(models.TextChoices):
    CAHIER_DE_CHARGE = "CAHIER_DE_CHARGE", "Cahier de charge"
    OTHER = "OTHER", "Autre"


class ProjectDocument(TimeStampedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="documents")
    doc_type = models.CharField(max_length=30, choices=ProjectDocumentType.choices, db_index=True)
    file = models.FileField(upload_to=upload_to_project_dir)
    title = models.CharField(max_length=160, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["project", "doc_type"]),
            models.Index(fields=["project", "created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.project.title} • {self.doc_type}"


# ============================================================
# Proposal
# ============================================================

class ProposalStatus(models.TextChoices):
    PENDING = "PENDING", "En attente"
    SHORTLISTED = "SHORTLISTED", "Pré-sélectionnée"
    SELECTED = "SELECTED", "Sélectionnée (attente confirmation)"
    CONFIRMED = "CONFIRMED", "Confirmée"
    DECLINED_BY_PROVIDER = "DECLINED_BY_PROVIDER", "Refusée par le prestataire"
    REFUSED = "REFUSED", "Refusée"
    REFUSED_AUTOCLOSE = "REFUSED_AUTOCLOSE", "Refusée (autre offre retenue)"
    WITHDRAWN = "WITHDRAWN", "Retirée"


class Proposal(TimeStampedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="proposals")
    provider = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="proposals",
        limit_choices_to={"role": UserRole.PROVIDER},
    )

    price = models.DecimalField(max_digits=14, decimal_places=2)
    duration_days = models.PositiveIntegerField()
    message = models.TextField()

    status = models.CharField(max_length=25, choices=ProposalStatus.choices, default=ProposalStatus.PENDING, db_index=True)
    decided_at = models.DateTimeField(null=True, blank=True)

    selected_at = models.DateTimeField(null=True, blank=True)
    selection_expires_at = models.DateTimeField(null=True, blank=True)

    decision_reason = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ("-created_at",)
        constraints = [
            models.UniqueConstraint(fields=["project", "provider"], name="uniq_proposal_per_provider_per_project"),
            # 1 seule proposition SELECTED/CONFIRMED par projet
            models.UniqueConstraint(
                fields=["project"],
                condition=Q(status__in=[ProposalStatus.SELECTED, ProposalStatus.CONFIRMED]),
                name="uniq_selected_or_confirmed_proposal_per_project",
            ),
        ]
        indexes = [
            models.Index(fields=["project", "status"]),
            models.Index(fields=["provider", "status"]),
        ]

    def clean(self):
        super().clean()

        if self.provider_id and getattr(self.provider, "role", None) != UserRole.PROVIDER:
            raise ValidationError({"provider": "Le provider doit avoir role=PROVIDER."})

        if self.price is not None and self.price <= 0:
            raise ValidationError({"price": "Le prix doit être > 0."})

        # prix figé dès SELECTED / CONFIRMED
        if self.pk:
            old = Proposal.objects.filter(pk=self.pk).only("price", "status").first()
            if old and old.status in {ProposalStatus.SELECTED, ProposalStatus.CONFIRMED} and old.price != self.price:
                raise ValidationError({"price": "Le prix est figé après sélection/confirmation."})


# ============================================================
# Contract + rule: 1 contrat actif max par freelance (DB-level)
# ============================================================

class ContractStatus(models.TextChoices):
    IN_PROGRESS = "IN_PROGRESS", "En cours"
    ON_HOLD = "ON_HOLD", "En pause"
    COMPLETED = "COMPLETED", "Terminé"
    CANCELLED = "CANCELLED", "Annulé"


class ContractFundingPlan(models.TextChoices):
    SPLIT_50_50 = "SPLIT_50_50", "50% puis reste"
    UPFRONT_100 = "UPFRONT_100", "100% au début"


ACTIVE_CONTRACT_STATUSES = (ContractStatus.IN_PROGRESS, ContractStatus.ON_HOLD)


class Contract(TimeStampedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    project = models.OneToOneField(Project, on_delete=models.CASCADE, related_name="contract")
    proposal = models.OneToOneField(Proposal, on_delete=models.PROTECT, related_name="contract")

    # denormalisation "senior" pour requêtes + contraintes DB propres
    client = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="client_contracts",
        limit_choices_to={"role": UserRole.CLIENT},
    )
    provider = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="provider_contracts",
        limit_choices_to={"role": UserRole.PROVIDER},
    )

    # snapshot du type prestataire (permet contrainte DB ciblée sur freelance)
    provider_kind_snapshot = models.CharField(max_length=10, choices=ProviderKind.choices, db_index=True)

    # ✅ total_amount COPIE le prix final accepté
    total_amount = models.DecimalField(max_digits=14, decimal_places=2)

    funding_plan = models.CharField(
        max_length=20,
        choices=ContractFundingPlan.choices,
        default=ContractFundingPlan.SPLIT_50_50,
        db_index=True,
    )

    start_at = models.DateTimeField(default=timezone.now)
    end_at = models.DateTimeField(null=True, blank=True)

    status = models.CharField(max_length=12, choices=ContractStatus.choices, default=ContractStatus.IN_PROGRESS, db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=["status", "created_at"]),
            models.Index(fields=["provider", "status"]),
            models.Index(fields=["client", "status"]),
        ]
        constraints = [
            models.CheckConstraint(name="contract_total_amount_gt_0", condition=Q(total_amount__gt=0)),
            # ✅ 1 seul contrat ACTIF par FREELANCE (les agences ne sont pas concernées)
            models.UniqueConstraint(
                fields=["provider"],
                condition=Q(
                    provider_kind_snapshot=ProviderKind.FREELANCE,
                    status__in=ACTIVE_CONTRACT_STATUSES,
                ),
                name="uniq_active_contract_per_freelance",
            ),
        ]

    def clean(self):
        super().clean()

        if self.client_id and getattr(self.client, "role", None) != UserRole.CLIENT:
            raise ValidationError({"client": "client doit être role=CLIENT."})
        if self.provider_id and getattr(self.provider, "role", None) != UserRole.PROVIDER:
            raise ValidationError({"provider": "provider doit être role=PROVIDER."})

        # snapshot immuable (anti incohérence)
        if self.pk:
            old = Contract.objects.filter(pk=self.pk).only("provider_kind_snapshot").first()
            if old and old.provider_kind_snapshot != self.provider_kind_snapshot:
                raise ValidationError({"provider_kind_snapshot": "Snapshot provider_kind immuable."})


# ============================================================
# Milestones
# ============================================================

class MilestoneStatus(models.TextChoices):
    PENDING = "PENDING", "À financer"
    FUNDED = "FUNDED", "Financé (escrow)"
    DELIVERED = "DELIVERED", "Livré"
    RELEASED = "RELEASED", "Payé au prestataire"
    REFUNDED = "REFUNDED", "Remboursé"
    CANCELLED = "CANCELLED", "Annulé"


class Milestone(TimeStampedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    contract = models.ForeignKey(Contract, on_delete=models.CASCADE, related_name="milestones")
    order = models.PositiveIntegerField(default=1)

    title = models.CharField(max_length=120)
    description = models.TextField(blank=True)

    amount = models.DecimalField(max_digits=14, decimal_places=2)
    due_date = models.DateField(null=True, blank=True)

    status = models.CharField(max_length=12, choices=MilestoneStatus.choices, default=MilestoneStatus.PENDING, db_index=True)

    # Branchements PSP/Djomy plus tard
    external_escrow_id = models.CharField(max_length=64, blank=True)
    funding_reference = models.CharField(max_length=100, blank=True)
    funded_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("contract", "order")
        constraints = [
            models.CheckConstraint(name="milestone_amount_gt_0", condition=Q(amount__gt=0)),
            models.UniqueConstraint(fields=["contract", "order"], name="uniq_milestone_order_per_contract"),
        ]
        indexes = [
            models.Index(fields=["contract", "status"]),
            models.Index(fields=["status", "created_at"]),
        ]
