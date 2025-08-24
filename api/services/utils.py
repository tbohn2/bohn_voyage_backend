from django.core.mail import send_mail
from django.conf import settings


def send_email(recipient, subject, message):
    """
    Send email using Gmail SMTP.

    Args:
        recipient (str): Email address of the recipient
        subject (str): Email subject
        message (str): Email message content

    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    try:
        print(f"Sending email to {recipient} with subject {subject} and message {message}")
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[recipient],
            fail_silently=False
        )
        return True
    except Exception:
        return False