"""
Modèles pour la gestion des abonnements FreeJobGN.

Ce module définit les modèles principaux :
- SubscriptionPlan : Définition des plans (FREE, PRO, PRO_MAX, AGENCY)
- Subscription : Abonnement d'un utilisateur à un plan
- SubscriptionPayment : Paiements liés aux abonnements
- SubscriptionUsage : Suivi de la consommation des quotas
"""

from __future__ import annotations

from decimal import Decimal
from typing import Optional, Dict, Any

from django.db import models
from django.conf import settings
from django.utils import timezone
from django.core.validators import MinValueValidator
from django.db.models import Q, UniqueConstraint

from payments.models import PaymentTransaction


# =============================================================================
# PLAN - Définition des plans d'abonnement
# =============================================================================

class PlanTier(models.TextChoices):
    """Niveaux de plans disponibles."""
    FREE = "FREE", "Gratuit"
    PRO = "PRO", "Freelance Pro"
    PRO_MAX = "PRO_MAX", "Freelance Pro Max"
    AGENCY = "AGENCY", "Agence"


class Plan(models.Model):
    """
    Définition d'un plan d'abonnement.
    
    Chaque plan a :
    - Un tier (FREE/PRO/PRO_MAX/AGENCY)
    - Un prix et une durée
    - Des features (liste de strings pour l'UI)
    - Des limits (dict de quotas et permissions)
    """
    
    # Identité
    name = models.CharField(
        "Nom",
        max_length=100,
        help_text="Nom du plan affiché aux utilisateurs"
    )
    slug = models.SlugField(
        "Slug",
        max_length=100,
        unique=True,
        help_text="Identifiant URL-friendly (ex: freelance-pro-monthly)"
    )
    description = models.CharField(
        "Description",
        max_length=500,
        blank=True,
        help_text="Description courte du plan"
    )
    
    # Classification
    tier = models.CharField(
        "Niveau",
        max_length=20,
        choices=PlanTier.choices,
        default=PlanTier.FREE,
        db_index=True,
        help_text="Niveau hiérarchique du plan"
    )
    sort_order = models.PositiveIntegerField(
        "Ordre d'affichage",
        default=0,
        help_text="Ordre dans les listes (0 = premier)"
    )
    
    # Tarification
    price = models.DecimalField(
        "Prix",
        max_digits=10,
        decimal_places=2,
        default=Decimal("0.00"),
        validators=[MinValueValidator(Decimal("0.00"))],
        help_text="Prix du plan (0 pour gratuit)"
    )
    currency = models.CharField(
        "Devise",
        max_length=3,
        default="GNF",
        help_text="Code devise ISO (GNF, EUR, USD)"
    )
    
    # Durée
    duration_months = models.PositiveIntegerField(
        "Durée (mois)",
        default=1,
        help_text="Durée de validité en mois (1=mensuel, 12=annuel)"
    )
    is_annual = models.BooleanField(
        "Plan annuel",
        default=False,
        db_index=True,
        help_text="True si c'est un plan annuel (permet le filtre front)"
    )
    
    # Features (pour l'UI - liste de strings)
    features = models.JSONField(
        "Fonctionnalités",
        default=list,
        blank=True,
        help_text="Liste des features à afficher (ex: ['Badge PRO', 'Chat illimité'])"
    )
    
    # Limits (quotas et permissions techniques)
    limits = models.JSONField(
        "Limites et permissions",
        default=dict,
        blank=True,
        help_text="""
        Dictionnaire des limites/permissions :
        - monthly_client_contacts: int (quota contacts/mois)
        - rank_stars: int (étoiles Codeur Rank)
        - show_directory: bool (présence annuaire)
        - show_client_contact: bool (voir coordonnées client)
        - show_own_contact: bool (afficher ses coordonnées)
        - premium_email_alerts: bool (alertes email premium)
        - suggested_profile: bool (profil suggéré)
        - chat_access: bool (accès chat prestataires)
        - instant_project_alerts: bool (alertes projets immédiates)
        """
    )
    
    # États
    is_active = models.BooleanField(
        "Actif",
        default=True,
        db_index=True,
        help_text="Désactiver pour masquer le plan"
    )
    is_featured = models.BooleanField(
        "Mis en avant",
        default=False,
        help_text="Afficher le badge 'Le plus apprécié'"
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Plan d'abonnement"
        verbose_name_plural = "Plans d'abonnement"
        ordering = ["sort_order", "price"]
        indexes = [
            models.Index(fields=["tier", "is_active"]),
            models.Index(fields=["is_annual", "is_active"]),
        ]
    
    def __str__(self) -> str:
        annual_suffix = " (annuel)" if self.is_annual else ""
        return f"{self.name}{annual_suffix}"
    
    @property
    def monthly_price(self) -> Decimal:
        """Prix mensuel équivalent."""
        if self.duration_months > 0:
            return self.price / self.duration_months
        return self.price
    
    @property
    def badge_label(self) -> Optional[str]:
        """Label du badge selon le tier."""
        badge_map = {
            PlanTier.PRO: "PRO",
            PlanTier.PRO_MAX: "PRO+",
            PlanTier.AGENCY: "PRO++",
        }
        return badge_map.get(self.tier)
    
    def get_limit(self, key: str, default: Any = None) -> Any:
        """Récupère une limite spécifique."""
        return self.limits.get(key, default)
    
    def has_feature(self, key: str) -> bool:
        """Vérifie si une permission/feature est activée."""
        return bool(self.limits.get(key, False))


# =============================================================================
# SUBSCRIPTION - Abonnement utilisateur
# =============================================================================

class SubscriptionStatus(models.TextChoices):
    """Statuts possibles d'un abonnement."""
    PENDING = "PENDING", "En attente de paiement"
    ACTIVE = "ACTIVE", "Actif"
    CANCELLED = "CANCELLED", "Annulé"
    EXPIRED = "EXPIRED", "Expiré"
    PAST_DUE = "PAST_DUE", "Paiement en retard"


class Subscription(models.Model):
    """
    Abonnement d'un utilisateur à un plan.
    
    Règles :
    - Un seul abonnement ACTIVE par utilisateur (contrainte unique)
    - status=PENDING jusqu'au paiement confirmé
    - Passage automatique à EXPIRED via tâche Celery
    """
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="subscriptions",
        help_text="Utilisateur propriétaire de l'abonnement"
    )
    plan = models.ForeignKey(
        Plan,
        on_delete=models.PROTECT,
        related_name="subscriptions",
        help_text="Plan souscrit"
    )
    
    # Statut
    status = models.CharField(
        "Statut",
        max_length=20,
        choices=SubscriptionStatus.choices,
        default=SubscriptionStatus.PENDING,
        db_index=True
    )
    is_active = models.BooleanField(
        "Actif",
        default=False,
        db_index=True,
        help_text="True uniquement si status=ACTIVE et non expiré"
    )
    
    # Dates
    start_date = models.DateField(
        "Date de début",
        null=True,
        blank=True,
        help_text="Défini au moment de l'activation"
    )
    end_date = models.DateField(
        "Date de fin",
        null=True,
        blank=True,
        db_index=True,
        help_text="Date d'expiration de l'abonnement"
    )
    canceled_at = models.DateTimeField(
        "Annulé le",
        null=True,
        blank=True,
        help_text="Date d'annulation (si applicable)"
    )
    
    # Renouvellement
    auto_renew = models.BooleanField(
        "Renouvellement automatique",
        default=True,
        help_text="Tenter de renouveler automatiquement à l'expiration"
    )
    
    # Période actuelle (pour suivi fin)
    current_period_start = models.DateField(
        "Début période courante",
        null=True,
        blank=True
    )
    current_period_end = models.DateField(
        "Fin période courante",
        null=True,
        blank=True
    )
    
    # Métadonnées
    metadata = models.JSONField(
        "Métadonnées",
        default=dict,
        blank=True,
        help_text="Données additionnelles (prorata, notes, etc.)"
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Abonnement"
        verbose_name_plural = "Abonnements"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "status"]),
            models.Index(fields=["status", "end_date"]),
        ]
        constraints = [
            # Un seul abonnement ACTIVE par utilisateur
            UniqueConstraint(
                fields=["user"],
                condition=Q(status="ACTIVE"),
                name="unique_active_subscription_per_user"
            )
        ]
    
    def __str__(self) -> str:
        return f"{self.user.username} → {self.plan.name} ({self.status})"
    
    @property
    def is_valid(self) -> bool:
        """True si l'abonnement est actif et non expiré."""
        if self.status != SubscriptionStatus.ACTIVE:
            return False
        if not self.end_date:
            return False
        return self.end_date >= timezone.now().date()
    
    @property
    def days_remaining(self) -> int:
        """Nombre de jours restants avant expiration."""
        if not self.end_date:
            return 0
        delta = self.end_date - timezone.now().date()
        return max(0, delta.days)
    
    @property
    def is_expiring_soon(self) -> bool:
        """True si l'abonnement expire dans 7 jours ou moins."""
        return 0 < self.days_remaining <= 7
    
    def activate(self) -> None:
        """Active l'abonnement après paiement réussi."""
        today = timezone.now().date()
        from dateutil.relativedelta import relativedelta
        
        self.status = SubscriptionStatus.ACTIVE
        self.is_active = True
        self.start_date = today
        self.end_date = today + relativedelta(months=self.plan.duration_months)
        self.current_period_start = today
        self.current_period_end = self.end_date
        self.save()
    
    def cancel(self, immediate: bool = False) -> None:
        """
        Annule l'abonnement.
        
        Args:
            immediate: Si True, désactive immédiatement. Sinon, à la fin de période.
        """
        self.canceled_at = timezone.now()
        self.auto_renew = False
        
        if immediate:
            self.status = SubscriptionStatus.CANCELLED
            self.is_active = False
        
        self.save()
    
    def expire(self) -> None:
        """Marque l'abonnement comme expiré."""
        self.status = SubscriptionStatus.EXPIRED
        self.is_active = False
        self.save()


# =============================================================================
# SUBSCRIPTION PAYMENT - Paiements d'abonnement
# =============================================================================

class SubscriptionPayment(models.Model):
    """
    Enregistrement d'un paiement pour un abonnement.
    
    Chaque paiement est lié à une Subscription et optionnellement
    à une PaymentTransaction (PSP).
    """
    
    subscription = models.ForeignKey(
        Subscription,
        on_delete=models.CASCADE,
        related_name="payments",
        help_text="Abonnement concerné"
    )
    amount = models.DecimalField(
        "Montant",
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(Decimal("0.00"))]
    )
    currency = models.CharField(
        "Devise",
        max_length=3,
        default="GNF"
    )
    
    status = models.CharField(
        "Statut",
        max_length=20,
        choices=[
            ("PENDING", "En attente"),
            ("SUCCESS", "Payé"),
            ("FAILED", "Échec"),
            ("REFUNDED", "Remboursé"),
        ],
        default="PENDING"
    )
    
    paid_at = models.DateTimeField(
        "Payé le",
        auto_now_add=True
    )
    
    # Lien vers la transaction PSP
    payment_transaction = models.OneToOneField(
        PaymentTransaction,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="subscription_payment",
        help_text="Transaction PSP associée"
    )
    
    # Détails
    description = models.CharField(
        "Description",
        max_length=255,
        blank=True,
        default=""
    )
    
    class Meta:
        verbose_name = "Paiement d'abonnement"
        verbose_name_plural = "Paiements d'abonnement"
        ordering = ["-paid_at"]
    
    def __str__(self) -> str:
        return f"Paiement {self.amount} {self.currency} - {self.subscription} ({self.status})"


# =============================================================================
# SUBSCRIPTION USAGE - Suivi de consommation des quotas
# =============================================================================

class SubscriptionUsage(models.Model):
    """
    Suivi de la consommation des quotas par période.
    
    Une entrée par mois pour chaque abonnement actif.
    Reset automatique via tâche Celery ou lazy à la demande.
    """
    
    subscription = models.ForeignKey(
        Subscription,
        on_delete=models.CASCADE,
        related_name="usage_records",
        help_text="Abonnement concerné"
    )
    
    # Période
    period_start = models.DateField(
        "Début de période",
        db_index=True,
        help_text="Premier jour du mois de la période"
    )
    period_end = models.DateField(
        "Fin de période",
        help_text="Dernier jour du mois de la période"
    )
    
    # Compteurs
    client_contacts_used = models.PositiveIntegerField(
        "Contacts clients utilisés",
        default=0,
        help_text="Nombre de contacts clients consommés ce mois"
    )
    
    # Timestamps
    last_reset_at = models.DateTimeField(
        "Dernier reset",
        auto_now_add=True,
        help_text="Date du dernier reset des compteurs"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Consommation d'abonnement"
        verbose_name_plural = "Consommations d'abonnement"
        ordering = ["-period_start"]
        indexes = [
            models.Index(fields=["subscription", "period_start"]),
        ]
        constraints = [
            UniqueConstraint(
                fields=["subscription", "period_start"],
                name="unique_usage_per_period"
            )
        ]
    
    def __str__(self) -> str:
        return f"Usage {self.subscription.user.username} - {self.period_start.strftime('%Y-%m')}"
    
    def reset_period(self) -> None:
        """Remet tous les compteurs à zéro."""
        self.client_contacts_used = 0
        self.last_reset_at = timezone.now()
        self.save()
    
    def increment_contacts(self, amount: int = 1) -> bool:
        """
        Incrémente le compteur de contacts.
        
        Returns:
            True si l'incrément a réussi, False si quota dépassé.
        """
        limit = self.subscription.plan.get_limit("monthly_client_contacts", float("inf"))
        
        if self.client_contacts_used + amount > limit:
            return False
        
        self.client_contacts_used += amount
        self.save(update_fields=["client_contacts_used", "updated_at"])
        return True
    
    @property
    def contacts_remaining(self) -> int:
        """Nombre de contacts restants pour la période."""
        limit = self.subscription.plan.get_limit("monthly_client_contacts", float("inf"))
        if limit == float("inf"):
            return 999999  # Illimité
        return max(0, limit - self.client_contacts_used)


# =============================================================================
# PROVIDER MONTHLY USAGE - Suivi des quotas par provider (indépendant de l'abo)
# =============================================================================

class ProviderMonthlyUsage(models.Model):
    """
    Suivi mensuel de la consommation des quotas par provider.
    
    Ce modèle est lié au User (provider), pas à la subscription.
    Cela permet de tracker les quotas même pour les utilisateurs FREE.
    
    Une entrée par mois pour chaque provider.
    """
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="monthly_usage_records",
        help_text="Provider concerné"
    )
    
    # Période
    period_start = models.DateField(
        "Début de période",
        db_index=True,
        help_text="Premier jour du mois"
    )
    period_end = models.DateField(
        "Fin de période",
        help_text="Dernier jour du mois"
    )
    
    # Compteurs
    proposals_used = models.PositiveIntegerField(
        "Propositions envoyées",
        default=0,
        help_text="Nombre de propositions envoyées ce mois"
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Usage mensuel provider"
        verbose_name_plural = "Usages mensuels providers"
        ordering = ["-period_start"]
        indexes = [
            models.Index(fields=["user", "period_start"]),
        ]
        constraints = [
            UniqueConstraint(
                fields=["user", "period_start"],
                name="unique_provider_usage_per_period"
            )
        ]
    
    def __str__(self) -> str:
        return f"Usage {self.user.username} - {self.period_start.strftime('%Y-%m')}"
    
    def reset_counters(self) -> None:
        """Remet tous les compteurs à zéro."""
        self.proposals_used = 0
        self.save(update_fields=["proposals_used", "updated_at"])
