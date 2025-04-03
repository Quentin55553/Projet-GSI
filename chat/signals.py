from django.db.models.signals import post_save
from django.dispatch import receiver
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from .models import UserKeys
from django.contrib.auth.models import User
from .crypto import serialize

@receiver(post_save, sender=User)
def create_user_keys(sender, instance, created, **kwargs):
    """
    Cette fonction permet de créer les clés d'un nouvel utilisateur
    Elle est appelée dès qu'une inscription se fait (qu'un objet User est ajouté à la BDD) grâce à un signal
    """
    if created:
        ik = x25519.X25519PrivateKey.generate()
        sik = ed25519.Ed25519PrivateKey.generate()
        spk = x25519.X25519PrivateKey.generate()
        spk_bytes = spk.public_key().public_bytes_raw()
        spk_sig = sik.sign(spk_bytes)

        ik_private_base64 = serialize(ik.private_bytes_raw())
        sik_private_base64 = serialize(sik.private_bytes_raw())
        spk_private_base64 = serialize(spk.private_bytes_raw())
        ik_public_base64 = serialize(ik.public_key().public_bytes_raw())
        sik_public_base64 = serialize(sik.public_key().public_bytes_raw())
        spk_public_base64 = serialize(spk_bytes)
        spk_signature_base64 = serialize(spk_sig)

        UserKeys.objects.create(
            user=instance,
            ik_private=ik_private_base64,
            sik_private=sik_private_base64,
            spk_private=spk_private_base64,
            ik_public=ik_public_base64,
            sik_public=sik_public_base64,
            spk_public=spk_public_base64,
            spk_signature=spk_signature_base64
        )
