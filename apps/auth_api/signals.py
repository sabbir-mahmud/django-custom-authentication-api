# imports
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import Profile

# profile signal

User = get_user_model()


@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(
            user=instance,
            display_name=f"{instance.first_name} {instance.last_name}",
        )
    else:
        Profile.objects.filter(user=instance).update(
            display_name=f"{instance.first_name} {instance.last_name}"
        )
