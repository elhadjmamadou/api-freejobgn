"""
Utilitaires pour l'envoi d'emails d'activation.
"""

from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from .tokens import activation_token_generator, encode_uid


def send_activation_email(user) -> bool:
    """
    Envoie l'email d'activation à l'utilisateur.

    Args:
        user: Instance User à activer

    Returns:
        bool: True si l'email a été envoyé avec succès
    """
    # Génération du token et de l'uid encodé
    token = activation_token_generator.make_token(user)
    uid = encode_uid(user.pk)

    # URL d'activation pour le frontend
    frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:3000")
    activation_url = f"{frontend_url}/activate?uid={uid}&token={token}"

    # Contexte pour le template
    context = {
        "user": user,
        "activation_url": activation_url,
        "expiry_hours": getattr(settings, "ACTIVATION_TOKEN_EXPIRY_HOURS", 24),
        "site_name": "FreeJobGN",
    }

    # Sujet de l'email
    subject = "Activez votre compte FreeJobGN"

    # Message texte simple (fallback)
    message = f"""
Bonjour {user.username},

Merci de vous être inscrit sur FreeJobGN !

Pour activer votre compte, cliquez sur le lien ci-dessous :
{activation_url}

Ce lien expire dans {context['expiry_hours']} heures.

Si vous n'avez pas créé de compte sur FreeJobGN, ignorez cet email.

Cordialement,
L'équipe FreeJobGN
"""

    # Email HTML (optionnel, on utilise le texte simple pour l'instant)
    html_message = None
    try:
        html_message = render_to_string("users/emails/activation.html", context)
    except Exception:
        # Template non trouvé, on utilise le texte simple
        pass

    try:
        send_mail(
            subject=subject,
            message=message.strip(),
            from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@freejobgn.com"),
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        # Log l'erreur en production
        import logging

        logger = logging.getLogger(__name__)
        logger.error(f"Erreur envoi email activation pour {user.email}: {e}")
        return False
