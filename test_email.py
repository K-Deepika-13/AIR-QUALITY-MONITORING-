from flask import Flask
from flask_mail import Mail, Message
import os

app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'keerthikulandhaivel308@gmail.com'
app.config['MAIL_PASSWORD'] = 'kyvg qesm pkhj fsin'
app.config['MAIL_DEFAULT_SENDER'] = 'bdgk2027@gmail.com'

mail = Mail(app)

print("Attempting to send email...")
try:
    with app.app_context():
        msg = Message(subject="Test Email", recipients=['kulandhaivelkeerthi@gmail.com'], body="This is a test email.")
        mail.send(msg)
    print("Email sent successfully.")
except Exception as e:
    print(f"Failed to send email: {e}")
