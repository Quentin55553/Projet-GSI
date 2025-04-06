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
    Un modèle utilisé dans l'application originelle associée à ce projet Django (inutilisé). 
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
    """
    Un modèle utilisé dans l'application originelle associée à ce projet Django (inutilisé). 
    """
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
    Notre implémentation théorique fait qu'il est stockée dans la base de données Django sur le serveur, mais en conditions réelles, il serait stocké en local.
    Les clés sont les suivantes :
    - ik_private : Clé privée d'identité (Identity Key - IK). Elle est unique et fixe pour l’utilisateur. Elle doit rester secrète.
    - sik_private : Clé de signature privée (Signing Identity Key - SIK). Elle sert à signer la pré clé SPK pour s'assurer que l'utilisateur est bien
    à l'origine de la communication. 
    - spk_private : Clé signée privée (Signed Prek Key - SPK). Clé à plus court terme que IK utilisée pour calculer des clés secrètes notamment.
    - ik_public : Clé publique d'identité. Partagée avec d'autres utilisateurs pour établir une communication sécurisée.
    - sik_public : Clé de signature publique. Elle est aussi partagée pour que d'autres utilisateurs puissent vérifier la signature faite à partir de la
    version privée de cette clé.
    - spk_public : Version publique de SPK
    - spk_signature : La signature de SPK faite avec SIK (privée). Vérifiable avec SIK (publique) 

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
    """
    Un modèle qui représente l'établissement d'une communication entre deux utilisateurs.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_sessions")
    peer = models.TextField()
    ik = models.TextField()
    spk = models.TextField()

# ---------------------------------------------------------------------------------- X3DH 

class X3DH_Session(models.Model):
    """
    Ce modèle représente les informations obtenues grâce au protocole X3DH.
    Notre implémentation théorique fait qu'il est stockée dans la base de données Django sur le serveur, mais en conditions réelles, il serait stocké en local.
    Il contient les informations sur les deux individus en communication mais aussi :
    - sk : clé secrète utilisée ici pour chiffrer et déchiffrer les messages. Elle est calculée grâce au protocole X3DH
    - spk : signed pre key du destinataire, utilisée calcul de SK (l'émetteur dispose de la version publique et le destinataire de la version privée)
    - epk : clé éphémère utilisée dans le calcul de SK (l'émetteur dispose de la version privée et le destinataire de la version publique)
    - L'associated data (ik_alice + ik_bob) permettant de vérifier que les messages reçus proviennent bien de cet échange et pas d'un autre (voir attaque replay) 
    """
    user_session = models.OneToOneField(UserSession, on_delete=models.CASCADE)
    alice=models.TextField()
    bob=models.TextField()
    sk = models.TextField() 
    spk = models.TextField() 
    epk = models.TextField()
    ad = models.TextField()

class X3DH_Message(models.Model):
    """
    Ce modèle représente le message qu'envoie Alice à Bob lors du protocole X3DH. (voir crypto.py)
    Il contient les informations sur le destinataire et l'émetteur, la clé éphémère (publique) générée par l'émetteur et sa clé (publique) d'identité.
    Il contient aussi le message chiffré et sa signature numérique (hmac).
    """
    receiver = models.ForeignKey(User, on_delete=models.CASCADE)
    sender = models.TextField()
    ik = models.TextField()
    epk = models.TextField()
    cipher = models.TextField()
    hmac = models.TextField()

class Message(models.Model):
    """
    Ce modèle représente le message envoyé après avoir effectué le protocole X3DH. (voir crypto.py)
    Il contient le message chiffré et sa signature numérique.
    Le destinataire le déchiffrera grâce à la clé SK contenue dans l'objet X3DH_Session stocké (en théorie) en local.
    """
    receiver = models.ForeignKey(User, on_delete=models.CASCADE)
    sender = models.TextField()
    cipher = models.TextField()
    hmac = models.TextField()