"""
Modèles pour le système de ranking FreeJobGN.

Ce module définit :
- ProviderRank : Score et position de chaque provider (persistant, mis à jour par Celery)
- ProviderRankSnapshot : Historique des rankings (optionnel, pour analytics)
"""

from django.db import models
from django.conf import settings
from django.utils import timezone


class ProviderRank(models.Model):
    """
    Rang d'un provider (freelance ou agence).
    
    - score: 0-100 (calculé selon algorithme pondéré)
    - position: rang global (#1 = meilleur)
    - stars: 0-3 (★ à ★★★)
    - breakdown: JSON détaillant chaque composante du score
    """
    
    provider = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="provider_rank",
        limit_choices_to={"profile_choice": "PROVIDER"},
        verbose_name="Prestataire"
    )
    
    # Score principal (0.00 - 100.00)
    score = models.DecimalField(
        "Score",
        max_digits=5,
        decimal_places=2,
        default=0,
        db_index=True,
        help_text="Score global sur 100"
    )
    
    # Position dans le classement (1 = premier)
    position = models.PositiveIntegerField(
        "Position",
        default=0,
        db_index=True,
        help_text="Rang global (#1 = meilleur score)"
    )
    
    # Étoiles (0 à 3)
    STAR_CHOICES = [
        (0, "Aucune étoile"),
        (1, "★"),
        (2, "★★"),
        (3, "★★★"),
    ]
    stars = models.PositiveSmallIntegerField(
        "Étoiles",
        choices=STAR_CHOICES,
        default=0,
        db_index=True,
        help_text="Niveau affiché (0=<40, 1=40-59, 2=60-79, 3=80+)"
    )
    
    # Tier du provider (optionnel, miroir de subscription)
    TIER_CHOICES = [
        ("FREE", "Gratuit"),
        ("PRO", "Freelance Pro"),
        ("PRO_MAX", "Freelance Pro Max"),
        ("AGENCY", "Agence"),
    ]
    tier = models.CharField(
        "Tier abonnement",
        max_length=10,
        choices=TIER_CHOICES,
        default="FREE",
        blank=True,
        help_text="Niveau d'abonnement actuel (pour référence)"
    )
    
    # Détail du calcul (pour debug et transparence)
    breakdown = models.JSONField(
        "Détail du score",
        default=dict,
        blank=True,
        help_text="""
        Décomposition du score :
        {
            "rating_points": float,      # 0-35
            "contracts_points": float,   # 0-30
            "reliability_points": float, # 0-15
            "activity_points": float,    # 0-10
            "profile_points": float,     # 0-5
            "subscription_bonus": float, # 0-5
            "avg_rating": float,         # Note moyenne (0-5)
            "completed_contracts": int,
            "total_contracts": int,
            "completion_rate": float,
            "proposals_count": int,
            "messages_count": int,
            "profile_completeness": float
        }
        """
    )
    
    # Timestamps
    computed_at = models.DateTimeField(
        "Calculé le",
        default=timezone.now,
        help_text="Date du dernier calcul complet"
    )
    updated_at = models.DateTimeField(
        "Mis à jour le",
        auto_now=True
    )
    
    class Meta:
        verbose_name = "Rang provider"
        verbose_name_plural = "Rangs providers"
        ordering = ["position"]
        indexes = [
            models.Index(fields=["score"], name="ranking_score_idx"),
            models.Index(fields=["position"], name="ranking_position_idx"),
            models.Index(fields=["stars"], name="ranking_stars_idx"),
        ]
    
    def __str__(self):
        return f"#{self.position} {self.provider.username} ({self.score}/100, {'★' * self.stars or '☆'})"
    
    @property
    def stars_display(self):
        """Retourne les étoiles en caractères Unicode."""
        return "★" * self.stars if self.stars else ""
    
    @property
    def rank_label(self):
        """Retourne le label formaté (ex: 'Rank #12')."""
        return f"Rank #{self.position}" if self.position > 0 else "Non classé"


class ProviderRankSnapshot(models.Model):
    """
    Historique des rankings (pour analytics et évolution).
    Créé périodiquement (quotidien ou hebdomadaire).
    """
    
    provider = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="rank_snapshots",
        limit_choices_to={"profile_choice": "PROVIDER"},
        verbose_name="Prestataire"
    )
    
    # Données capturées
    score = models.DecimalField(
        "Score",
        max_digits=5,
        decimal_places=2,
        default=0
    )
    position = models.PositiveIntegerField(
        "Position",
        default=0
    )
    stars = models.PositiveSmallIntegerField(
        "Étoiles",
        default=0
    )
    
    # Période couverte
    period_start = models.DateField(
        "Début période",
        help_text="Début de la période de ce snapshot"
    )
    period_end = models.DateField(
        "Fin période",
        help_text="Fin de la période de ce snapshot"
    )
    
    # Détail
    breakdown = models.JSONField(
        "Détail du score",
        default=dict,
        blank=True
    )
    
    # Timestamp
    computed_at = models.DateTimeField(
        "Calculé le",
        default=timezone.now
    )
    
    class Meta:
        verbose_name = "Snapshot rang provider"
        verbose_name_plural = "Snapshots rangs providers"
        ordering = ["-period_end", "position"]
        indexes = [
            models.Index(fields=["provider", "period_end"], name="ranking_snap_prov_period_idx"),
        ]
        # Un seul snapshot par provider par période
        unique_together = [["provider", "period_start", "period_end"]]
    
    def __str__(self):
        return f"{self.provider.username} #{self.position} ({self.period_start} - {self.period_end})"
