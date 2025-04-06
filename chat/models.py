"""
Les models sont une partie importante de Django. 
Ils décrivent la structure des objets présents dans la base de données, qui est gérée automatiquement par Django quand des objets sont créés, modifiés 
ou supprimés dans le code.
"""
#--------------------------------------------------------------------------------------------------- Imports

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.http import JsonResponse

#--------------------------------------------------------------------------------------------------------- Models

class UserRelation(models.Model):
    """
    Un modèle utilisé dans l'application que nous avons reprise. Il représente une relation d'un utilisateur à un possible ami ("possible" car cet objet est
    créé au moment de l'envoi d'une demande d'ami, qui peut-être refusée).
    """
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
    """
    Ce modèle est particulièrement important et représente l'ensemble des clés d'un utilisateur (publiques comme privées)
    Les clés sont les suivantes :
    - ik_private : Clé privée d'identité (Identity Key - IK). Elle est unique et fixe pour l’utilisateur. Elle doit rester secrète.
    - sik_private : 
    - spk_private : 
    - ik_public : Clé publique d'identité. Partagée avec d'autres utilisateurs pour établir une communication sécurisée.
    - sik_public : 
    - spk_public : 
    - spk_signature : 

    Ces clés sont générées à partir de la courbe elliptique X25519.
    """
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
        """
        Méthode utilisée pour obtenir les clés publiques de l'utilisateur. 
        """
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

# ---------------------------------------------------------------------------------- X3DH 
class X3DH_Session(models.Model):
    user_session = models.OneToOneField(UserSession, on_delete=models.CASCADE)
    alice=models.TextField()
    bob=models.TextField()
    sk = models.TextField() 
    spk = models.TextField() 
    epk = models.TextField()
    ad = models.TextField()

    def __str__(self):
        return f"X3DH Session {self.user_session.user.username} -> {self.user_session.peer}"

class X3DH_Message(models.Model):
    """
    Ce modèle représente le message qu'envoie Alice à Bob lors du protocole X3DH. (voir crypto.py)
    Il contient les informations sur le destinataire et l'émetteur, la clé éphémère générée par l'émetteur et sa clé (publique) d'identité.
    Il contient aussi le message chiffré et sa signature numérique.
    """
    receiver = models.ForeignKey(User, on_delete=models.CASCADE)
    sender = models.TextField()
    ik = models.TextField()
    epk = models.TextField()
    cipher = models.TextField()
    hmac = models.TextField()

class Message(models.Model):
    """
    Ce modèle représente le message qu'envoie Alice à Bob lors du protocole X3DH. (voir crypto.py)
    Il contient les informations sur le destinataire et l'émetteur, la clé éphémère générée par l'émetteur et sa clé (publique) d'identité.
    Il contient aussi le message chiffré et sa signature numérique.
    """
    receiver = models.ForeignKey(User, on_delete=models.CASCADE)
    sender = models.TextField()
    cipher = models.TextField()
    hmac = models.TextField()