"""
Database models for the payments application.

This module defines two key models used to manage payment flows in
the system:

1. ``InititePayement`` records the initial intent to make a payment.
   It captures details such as the order identifier, amount, currency
   and payment provider.  When saved without an explicit reference
   value, a unique reference is generated automatically.  This model
   is inspired by an example provided by a professor and serves as the
   entry point for creating payment links.

2. ``PaymentTransaction`` represents an individual payment event
   reported by the payment provider.  It stores identifiers from the
   provider, the current status, monetary amounts, raw payload data
   from provider webhooks, and timestamps.  Additional optional fields
   link a transaction back to a contract and milestone so that
   payments can be associated with project deliverables.
"""

from __future__ import annotations

import random
import string
from django.conf import settings
from django.db import models
import hashlib
from django.utils import timezone


try:
    # Import User from the users app via settings.AUTH_USER_MODEL.
    from users.models import User  # type: ignore
except Exception:
    User = None  # type: ignore

from projects.models import Contract, Milestone


class InititePayement(models.Model):
    """Record the initial intent to perform a payment."""

    class PaymentProvider(models.TextChoices):
        ORANGE_MONEY_WEBPAY = (
            "orange_money_webpay",
            "Orange Money WebPay",
        )
        ORANGE_MONEY_B2B = (
            "orange_money_b2b",
            "Orange Money B2B",
        )
        PAYCARD = (
            "paycard",
            "PayCard",
        )
        LENGOPAY = (
            "lengopay",
            "LengoPay",
        )
        DJOMY = (
            "djomy",
            "Djomy",
        )

    order_id = models.CharField(
        max_length=255,
        help_text=("Identifiant de l'ordre (par exemple ID de commande ou de jalon)."),
    )
    notif_token = models.CharField(
        max_length=255,
        help_text="Jeton aléatoire utilisé pour sécuriser les notifications.",
    )
    amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        help_text="Montant total à payer.",
    )
    amount_currency = models.CharField(
        max_length=10,
        help_text="Devise du montant (par exemple GNF, EUR, USD).",
    )
    pay_token = models.CharField(
        max_length=255,
        help_text="Jeton d'authentification ou de session retourné par le PSP.",
    )
    quantity = models.IntegerField(
        default=1,
        help_text="Quantité d'articles ou unités payées.",
    )
    reference = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text=(
            "Référence unique de la demande de paiement. Elle est générée "
            "automatiquement si absente lors de l'enregistrement."
        ),
    )
    status = models.CharField(
        max_length=50,
        help_text="Statut courant de l'initiation de paiement (PENDING, SUCCESS, etc.).",
    )
    provider = models.CharField(
        max_length=255,
        choices=PaymentProvider.choices,
        default=PaymentProvider.DJOMY,
        help_text="Fournisseur de paiement utilisé pour cette initiation.",
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="initial_payments",
        help_text="Utilisateur qui a initié le paiement.",
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Date et heure de création de l'enregistrement.",
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="Date et heure de la dernière mise à jour.",
    )

    def __str__(self) -> str:
        return f"InititePayement {self.order_id}"

    def generate_reference(self) -> str:
        """Generate a unique 12-character alphanumeric reference."""
        return "".join(random.choices(string.ascii_uppercase + string.digits, k=12))

    def save(self, *args, **kwargs) -> None:
        """Ensure a reference is present before saving to the database."""
        if not self.reference:
            self.reference = self.generate_reference()
        super().save(*args, **kwargs)


class PaymentTransaction(models.Model):
    """Represents a payment event reported by a payment provider."""

    provider = models.CharField(
        "fournisseur",
        max_length=255,
        choices=InititePayement.PaymentProvider.choices,
        help_text="Identifie le prestataire qui a traité cette transaction.",
    )
    reference = models.CharField(
        "Référence",
        max_length=255,
        db_index=True,
        help_text="Référence unique de la transaction (correspond à la référence InititePayement).",
    )
    transaction_id = models.CharField(
        "ID de la transaction",
        max_length=255,
        null=True,
        blank=True,
        help_text="Identifiant de transaction retourné par le prestataire.",
    )
    status = models.CharField(
        "Statut",
        max_length=50,
        help_text="Statut courant de la transaction (PENDING, SUCCESS, FAILED, etc.).",
    )
    amount = models.DecimalField(
        "Montant",
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Montant enregistré pour cette transaction.",
    )
    currency = models.CharField(
        "Devise",
        max_length=10,
        null=True,
        blank=True,
        help_text="Devise associée au montant (GNF, EUR, USD, ...).",
    )
    event_type = models.CharField(
        "Évènement",
        max_length=255,
        null=True,
        blank=True,
        help_text="Type d'évènement remonté par le prestataire (création, succès, échec, etc.).",
    )
    payer_identifier = models.CharField(
        "Payeur",
        max_length=255,
        null=True,
        blank=True,
        help_text="Identifiant du payeur retourné par le prestataire.",
    )
    raw_payload = models.JSONField(
        "Payload brut",
        null=True,
        blank=True,
        help_text="Contenu intégral du message reçu du prestataire.",
    )
    processed_at = models.DateTimeField(
        "Traité le",
        null=True,
        blank=True,
        help_text="Date et heure de traitement de cette transaction.",
    )
    created_at = models.DateTimeField(
        "Créé le",
        auto_now_add=True,
        help_text="Date et heure de création de l'enregistrement.",
    )

    # Optional links back to contracts and milestones
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="transactions",
        null=True,
        blank=True,
        help_text="Utilisateur qui a initié cette transaction.",
    )
    contract = models.ForeignKey(
        Contract,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="payment_transactions",
        help_text="Contrat concerné par cette transaction (optionnel).",
    )
    milestone = models.ForeignKey(
        Milestone,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="payment_transactions",
        help_text="Jalon financé par cette transaction (escrow).",
    )
    subscription = models.ForeignKey(
        "subscriptions.Subscription",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="payment_transactions",
        help_text="Souscription associée à cette transaction de paiement.",
    )

    class Meta:
        indexes = [
            models.Index(fields=["provider", "reference"]),
        ]
        verbose_name = "Transaction de paiement"
        verbose_name_plural = "Transactions de paiement"

    def __str__(self) -> str:
        return f"PaymentTransaction (provider={self.provider} - reference={self.reference})"


class WebhookEvent(models.Model):
    class Provider(models.TextChoices):
        DJOMY = "djomy", "Djomy"

    provider = models.CharField(max_length=50, choices=Provider.choices)
    dedupe_key = models.CharField(max_length=128, unique=True, db_index=True)

    event_id = models.CharField(max_length=64, null=True, blank=True)
    event_type = models.CharField(max_length=64, null=True, blank=True)
    reference = models.CharField(max_length=255, null=True, blank=True)

    signature = models.CharField(max_length=255, null=True, blank=True)
    payload = models.JSONField()

    received_at = models.DateTimeField(auto_now_add=True)

    processed = models.BooleanField(default=False)
    processed_at = models.DateTimeField(null=True, blank=True)

    retry_count = models.PositiveIntegerField(default=0)
    next_retry_at = models.DateTimeField(null=True, blank=True)

    last_error = models.TextField(blank=True, default="")

    class Meta:
        indexes = [
            models.Index(fields=["provider", "processed", "next_retry_at"]),
        ]

    def __str__(self) -> str:
        return f"WebhookEvent({self.provider}, processed={self.processed}, retry={self.retry_count})"
