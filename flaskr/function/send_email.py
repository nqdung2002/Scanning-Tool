from flaskr import mail
from flask import render_template
from flask_mail import Message

def send_mail(subject, recipients, template, **kwargs):
    html_content = render_template(template, **kwargs)
    body_text = render_template(template.replace('.html', '.txt'), **kwargs) if template.endswith('.html') else None
    msg = Message(
        subject=subject,
        recipients=recipients,
        body=body_text,
        html=html_content
    )
    mail.send(msg)
