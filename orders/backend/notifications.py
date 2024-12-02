import os
import smtplib
from email.message import EmailMessage

from django.http import HttpResponseServerError

SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT'))
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')


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

