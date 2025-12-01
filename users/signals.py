from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import UserStats
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token

User = get_user_model()


@receiver(post_save, sender=User)
def deactivate_user_token(sender, instance, **kwargs):
    if instance.pk and not instance.is_active:
        Token.objects.filter(user=instance).delete()


@receiver(post_save, sender=User)
def create_user_stats(sender, instance, created, **kwargs):
    if created:
        UserStats.objects.get_or_create(user=instance)
