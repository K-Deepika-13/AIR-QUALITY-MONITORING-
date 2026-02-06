"""
Send a test email using the same logic as the app:
- If SENDGRID_API_KEY is set, try SendGrid Web API.
- Otherwise try SMTP using SMTP_SERVER/SMTP_PORT and optional SMTP_USER/SMTP_PASS.

Usage (Windows cmd.exe):
  set SENDGRID_API_KEY=...
  set ALERT_TO_EMAIL=prosdgunal@gmail.com
  set ALERT_FROM_EMAIL=alerts@yourdomain.com
  python send_email_test.py

Or for SMTP:
  set SMTP_SERVER=smtp.gmail.com
  set SMTP_PORT=587
  set SMTP_USER=you@gmail.com
  set SMTP_PASS=your_app_password
  set ALERT_TO_EMAIL=prosdgunal@gmail.com
  set ALERT_FROM_EMAIL=you@gmail.com
  python send_email_test.py

This script prints detailed logs to help diagnose delivery/auth issues.
"""
import os
import json
import ssl
import smtplib
from email.message import EmailMessage
import requests

TO = os.environ.get('ALERT_TO_EMAIL', 'prosdgunal@gmail.com')
FROM = os.environ.get('ALERT_FROM_EMAIL', os.environ.get('SMTP_USER', 'noreply@example.com'))
SUBJECT = 'Test: Air Quality Notification'
BODY = 'This is a test email from your Air Quality app. If you receive this, email sending is configured.'


def send_via_sendgrid(to_addr, subject, body, from_addr):
    key = os.environ.get('SENDGRID_API_KEY')
    if not key:
        return False, 'No SENDGRID_API_KEY configured.'
    url = 'https://api.sendgrid.com/v3/mail/send'
    headers = {
        'Authorization': f'Bearer {key}',
        'Content-Type': 'application/json'
    }
    payload = {
        'personalizations': [{'to': [{'email': to_addr}]}],
        'from': {'email': from_addr},
        'subject': subject,
        'content': [{'type': 'text/plain', 'value': body}]
    }
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=15)
        if resp.status_code in (200, 202):
            return True, f'Sent via SendGrid ({resp.status_code})'
        return False, f'SendGrid returned {resp.status_code}: {resp.text}'
    except Exception as e:
        return False, f'SendGrid exception: {e}'


def send_via_smtp(to_addr, subject, body, from_addr):
    server = os.environ.get('SMTP_SERVER')
    port = int(os.environ.get('SMTP_PORT', 587))
    user = os.environ.get('SMTP_USER')
    pwd = os.environ.get('SMTP_PASS')
    if not server:
        return False, 'No SMTP_SERVER configured.'
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg.set_content(body)
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(server, port, timeout=15) as s:
            try:
                s.starttls(context=context)
                print('[SMTP] STARTTLS succeeded')
            except Exception as e:
                print('[SMTP] STARTTLS failed or not available:', e)
            if user and pwd:
                try:
                    s.login(user, pwd)
                    print(f'[SMTP] Authenticated as {user}')
                except Exception as e:
                    print('[SMTP] Login failed:', e)
            s.send_message(msg)
        return True, f'Sent via SMTP {server}:{port}'
    except Exception as e:
        return False, f'SMTP exception: {e}'


if __name__ == '__main__':
    print('Testing email send...')
    # Try SendGrid first
    ok, info = send_via_sendgrid(TO, SUBJECT, BODY, FROM)
    if ok:
        print('[OK]', info)
        exit(0)
    print('[SendGrid] Not sent or not configured:', info)
    # Fallback to SMTP
    ok2, info2 = send_via_smtp(TO, SUBJECT, BODY, FROM)
    if ok2:
        print('[OK]', info2)
        exit(0)
    print('[SMTP] Not sent:', info2)
    print('\nSummary:')
    print('SendGrid:', info)
    print('SMTP:', info2)
    print('\nPlease check credentials, ports, provider settings (Gmail may require app password), and sender address verification (SendGrid).')