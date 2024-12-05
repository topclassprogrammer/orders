import os
import smtplib
from email.message import EmailMessage

from django.http import HttpResponseServerError

from backend import views

SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT'))
SENDER_EMAIL_ADDRESS = os.getenv('SENDER_EMAIL_ADDRESS')
SENDER_EMAIL_PASSWORD = os.getenv('SENDER_EMAIL_PASSWORD')


def get_message(view, action, **kwargs):
    msg = None
    if view == views.UserView:
        if action == views.UserView.create.__name__:
            msg = f"<p>Your activation token key is <b>{kwargs['token'].key}</b></p>"
        elif action == views.UserView.request_new_password.__name__:
            msg = f"<p>Your password reset token key is <b>{kwargs['token'].key}</b></p>"
    elif view == views.OrderView:
        if action == views.OrderView.create.__name__:
            msg = f"<p>You successfully made an order.</p><p>Your order ID is <b>{kwargs['order'].id}</b>.</p><p>The current state is <b>{kwargs['order'].state}</b>.</p>"
        elif action == views.OrderView.partial_update.__name__:
            msg = f"<p>The state for your order with ID <b>{kwargs['order'].id}</b> has been changed to <b>{kwargs['order'].state}</b></p>"
    return msg


def notify(receiver_email, subject, message):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = receiver_email
    msg.set_content(message,  subtype='html')
    try:
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
    except (smtplib.SMTPAuthenticationError, smtplib.SMTPRecipientsRefused, TimeoutError) as err:
        return HttpResponseServerError({"status": False, "message": f"Error occurred while sending email to you: {err}"})

