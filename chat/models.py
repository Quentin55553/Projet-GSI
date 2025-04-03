from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json
import base64
from django.http import JsonResponse


class UserRelation(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="user_relations"
    )
    friend = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="friend_relations", default=None
    )
    accepted = models.BooleanField(default=False)
    relation_key = models.CharField(max_length=255, blank=True, null=True)  # Add relation_key field
    def __str__(self):
        return f"{self.user.username} - {self.friend.username}"
    
class Messages(models.Model):
    description = models.TextField()
    sender_name = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="sender"
    )
    receiver_name = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="receiver"
    )
    time = models.TimeField(auto_now_add=True)
    seen = models.BooleanField(default=False)
    timestamp = models.DateTimeField(default=timezone.now, blank=True)

    class Meta:
        ordering = ("timestamp",)
    
class UserKeys(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="keys")
    ik_private = models.TextField()  # Clé privée d'identité (chiffrée)
    sik_private = models.TextField()  # Clé privée signée (chiffrée)
    spk_private = models.TextField()  # Clé privée pré-signée (chiffrée)
    ik_public = models.TextField()  # Clé publique IK
    sik_public = models.TextField() # Clé publique SIK
    spk_public = models.TextField()  # Clé publique SPK
    spk_signature = models.TextField()  # Signature de la clé SPK

    def __str__(self):
        return f"Clés de {self.user.username}"
    
    def bundle(self):
        return JsonResponse({
            "username": self.user.username,
            "ik_public": self.ik_public,
            "sik_public": self.sik_public,
            "spk_public": self.spk_public,
            "spk_signature": self.spk_signature,
         })

class UserSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_sessions")
    peer = models.TextField()
    ik = models.TextField()
    spk = models.TextField()

    def __str__(self):
        return f"Session {self.user.username} -> {self.peer}"
    
class X3DH_Session(models.Model):
    user_session = models.OneToOneField(UserSession, on_delete=models.CASCADE)
    sk = models.TextField()  # Clé secrète partagée
    spk = models.TextField()  # Clé publique de Bob
    epk = models.TextField()
    ad = models.TextField()  # Données supplémentaires associées

    def __str__(self):
        return f"X3DH Session {self.user_session.user.username} -> {self.user_session.peer}"


class RatchetSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    peer = models.ForeignKey(User, on_delete=models.CASCADE, related_name="peer_sessions")
    encrypted_data = models.TextField()  # Stocke la session chiffrée
    nonce = models.BinaryField()  # Stocke le nonce pour AES-GCM

    def encrypt_data(self, session, key):
        """ Chiffre l'état du Ratchet avec AES-GCM """
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit nonce
        encrypted = aesgcm.encrypt(nonce, json.dumps(session).encode(), None)
        
        self.encrypted_data = base64.b64encode(encrypted).decode()
        self.nonce = nonce
        self.save()

    def decrypt_data(self, key):
        """ Déchiffre l'état du Ratchet """
        if not self.encrypted_data:
            return {}

        aesgcm = AESGCM(key)
        encrypted = base64.b64decode(self.encrypted_data)
        decrypted = aesgcm.decrypt(self.nonce, encrypted, None)
        return json.loads(decrypted.decode())

class X3DHExchange(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_x3dh")
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name="received_x3dh")
    ik = models.TextField()  # Clé identité publique de l'expéditeur
    epk = models.TextField()  # Clé éphémère publique de l'expéditeur
    cipher_text = models.TextField()  # Message chiffré
    hmac = models.TextField()  # Code d'authentification

