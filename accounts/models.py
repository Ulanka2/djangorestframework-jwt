import jwt

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.template.loader import render_to_string
from django.conf import settings
from .managers import UserManager
from .agents import EmailAgent


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return f'{self.email}'

    def send_activation_message(self, host):
        code = jwt.encode({'id': self.id}, settings.SECRET_KEY, algorithm='HS256').decode("utf-8")
        context = {
            'email': self.email,
            'confirm_url': f'{host}/?activation={code}',
        }
        email_html_message = render_to_string('email/email_verification.html', context)
        agent = EmailAgent(
            from_email=settings.EMAIL_HOST_USER,
            to_emails=[self.email],
            subject='Email verification',
            html_content=email_html_message,
            message='test',
        )

        return agent.send_message()

    def save(self, *args, **kwargs):
        if not self.email:
            raise ValueError('User must have an email!')
        super(User, self).save(*args, **kwargs)





