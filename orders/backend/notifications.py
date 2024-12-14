import os
import smtplib
from email.message import EmailMessage
from typing import List, Type

from django.http import HttpResponseServerError
from rest_framework.viewsets import ModelViewSet

from backend import views
from backend.utils import get_admin_emails

SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = os.getenv('SMTP_PORT')
SENDER_EMAIL_ADDRESS = os.getenv('SENDER_EMAIL_ADDRESS')
SENDER_EMAIL_PASSWORD = os.getenv('SENDER_EMAIL_PASSWORD')


def get_message(view: Type[ModelViewSet], action: str, **kwargs) -> str:
    """Generate an HTML message for email notification based on user actions."""
    msg = None
    if view == views.UserView:
        if action == views.UserView.create.__name__:
            msg = f"<p>Your activation token key is <b>{kwargs['token'].key}</b></p>"
        elif action == views.UserView.request_new_password.__name__:
            msg = f"<p>Your password reset token key is <b>{kwargs['token'].key}</b></p>"
    elif view == views.OrderView:
        if action == views.OrderView.create.__name__:
            if kwargs.get('admin'):
                msg = f"<p>You have a new order with ID <b>{kwargs['order'].id}</b> " \
                      f"from a user with email <b>{kwargs['order'].user.email}</b>.</p>"
            else:
                msg = f"<p>You made an order.</p><p>Your order ID is " \
                      f"<b>{kwargs['order'].id}</b>.</p><p>The current state is <b>" \
                      f"{kwargs['order'].state}</b>.</p><p>For any questions " \
                      "regarding your order you should contact administrators: " \
                      f"{', '.join(get_admin_emails())}</p>"
        elif action == views.OrderView.partial_update.__name__:
            msg = f"<p>The state for your order with ID <b>{kwargs['order'].id}</b> " \
                  f"has been changed to <b>{kwargs['order'].state}</b></p>"
    return msg


def get_subject(view: Type[ModelViewSet], action: str, **kwargs) -> str:
    """Generate a subject line for email notifications based on user actions."""
    subject = None
    if view == views.UserView:
        if action == views.UserView.create.__name__:
            subject = "Activation token for your account"
        elif action == views.UserView.request_new_password.__name__:
            subject = "Password reset request for your account"
    elif view == views.OrderView:
        if action == views.OrderView.create.__name__:
            subject = "You received a new order" if kwargs.get('admin') else "You made a new order"
        elif action == views.OrderView.partial_update.__name__:
            subject = "New order state"
    return subject


def notify(receiver_email: str | List[str], view: Type[ModelViewSet], action: str, **kwargs):
    """Send an email notification to the specified recipient."""
    msg = EmailMessage()
    msg['Subject'] = get_subject(view, action)
    msg['From'] = SENDER_EMAIL_ADDRESS
    msg['To'] = receiver_email
    msg.set_content(get_message(view, action, **kwargs),  subtype='html')
    try:
        server = smtplib.SMTP_SSL(SMTP_SERVER, int(SMTP_PORT))
        server.login(SENDER_EMAIL_ADDRESS, SENDER_EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
    except (smtplib.SMTPAuthenticationError, smtplib.SMTPRecipientsRefused, TimeoutError, TypeError) as err:
        return HttpResponseServerError(
            {"status": False, "message": f"Error occurred while sending email to you: {err}"})
