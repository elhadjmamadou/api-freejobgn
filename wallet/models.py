# wallet/models.py
from django.db import models
from django.conf import settings

class Wallet(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="wallet",
    )
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    currency = models.CharField(max_length=3, default="GNF")

    def __str__(self):
        return f"Wallet de {self.user.username}: {self.balance} {self.currency}"


class WalletTransaction(models.Model):
    TRANSACTION_TYPES = [
        ("DEPOSIT", "Dépôt"),
        ("WITHDRAWAL", "Retrait"),
        ("TRANSFER_IN", "Transfert entrant"),
        ("TRANSFER_OUT", "Transfert sortant"),
        ("PAYMENT", "Paiement"),
        ("REFUND", "Remboursement"),
        ("ESCROW_LOCK", "Blocage en escrow"),
        ("ESCROW_RELEASE", "Libération escrow"),
    ]

    wallet = models.ForeignKey(
        Wallet,
        on_delete=models.CASCADE,
        related_name="transactions",
    )
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)

    # Liens de contexte
    contract = models.ForeignKey(
        "projects.Contract",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="wallet_transactions",
    )
    milestone = models.ForeignKey(
        "projects.Milestone",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="wallet_transactions",
    )
    payment_transaction = models.ForeignKey(
        "payments.PaymentTransaction",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="wallet_transactions",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    description = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return f"{self.transaction_type} {self.amount} sur {self.wallet}"


class WithdrawalRequest(models.Model):
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name="withdrawal_requests")
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    requested_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=[("PENDING", "En attente"), ("APPROVED", "Approuvée"), ("REJECTED", "Rejetée")], default="PENDING")
    comment = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["-requested_at"]

    def __str__(self):
        return f"Retrait {self.amount} {self.wallet.currency} – {self.get_status_display()}"
