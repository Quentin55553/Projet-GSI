"""
Ce fichier de code regroupe toutes les fonctions cryptographiques utilisées pour garantir la sécurité des messages échangés 
et implémente une partie du Signal Protocol.

Cette implémentation reste très théorique et n'a qu'un rôle de simulation, elle ne peut pas être utilisée en l'état avec notre interface graphique
pour différentes raisons structurelles.

Les tests présents dans tests.py, exécutables avec 'python manage.py test', nous ont permis de vérifier que le code fonctionne. Ils simulent le protocole X3DH
entre deux utilisateurs ainsi que l'envoi d'un message chiffré, son déchiffrement par le destinataire.

Afin de produire le code, nous nous sommes aidés des deux sources suivantes :

1. La documentation de Signal
https://signal.org/docs/

Elle présente notamment le pseudo-code de certaines fonctions à utiliser et explique surtout en détail l'algorithmique du protocole.

2. Une implémentation existante du Signal Protocol en Python disponible sur Github
https://github.com/rohankalbag/cryptography-signal-protocol

Nous avons repris ce code, c'est pour cela qu'on peut trouver des similarités sur certaines fonctions du nôtre. 

En revanche, l'adapter à l'architecture Django a nécessité beaucoup de travail d'analyse, n'était pas trivial et a rendu obligatoire de comprendre en détail
le fonctionnement du code, que nous avons d'ailleurs commenté avec soin (le code présent sur ce dépôt est très peu commenté). 

Nous espérons que cette façon de procéder ne nous sera pas trop reprochée, il aurait été mieux pour nous de tout construire de zéro depuis la documentation
de Signal, mais le manque de temps et la charge de travail de ce deuxième semestre nous ont poussé à prendre cette décision. 
"""


#----------------------------------------------------------------------------------------------------------- Imports

import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from .models import User
from .models import UserSession
from .models import X3DH_Session
import json
import requests
import base64
from django.conf import settings


#######################################################################
#######################################################################
######################  FONCTIONS UTILITAIRES #########################
#######################################################################
#######################################################################

MAX_SKIP = 10

# Nous faisons tourner l'application en local, nous n'avons pas eu le temps de faire un déploiement concret.
SERVER_URL = "http://localhost:8000"

def serialize(val):
    """Utilisé pour encoder des octets en base 64 (pour stocker des clés dans la base de données notamment)"""
    return base64.standard_b64encode(val).decode('utf-8')

def deserialize(val):
    """Utilisé pour décoder des octets qui ont été encodés en base 64"""
    return base64.standard_b64decode(val.encode('utf-8'))

def GENERATE_DH():
    """
    Cette fonction génère aléatoirement une clé privée à partir de la cryptographie des courbes elliptiques (ECC). La courbe utilisée est X25519.
    Note : On peut extraire une clé publique de cette clé privée, c'est pour cela qu'on peut aussi dire que cette fonction génère une paire de clés DH.
    """
    sk = x25519.X25519PrivateKey.generate()
    return sk


################################################################
################################################################
########################  ECHANGE X3DH #########################
################################################################
################################################################

def request_user_prekey_bundle(self:User, username:str):
    """
    Cette fonction est utilisée pour obtenir les clés publiques d'un utilisateur (username). 
    Ces clés publiques sont utilisées par le protocole X3DH au moment d'un premier contact entre deux utilisateurs. 
    """
    user = User.objects.get(username=username)
    if(not user):
        raise Exception(f"User {username} not registered")
    data = json.loads(user.keys.bundle().content)
    ik_bytes = deserialize(data["ik_public"])
    sik_bytes = deserialize(data["sik_public"])
    spk_bytes = deserialize(data["spk_public"])
    spk_sig_bytes = deserialize(data["spk_signature"])
        
    ik = x25519.X25519PublicKey.from_public_bytes(ik_bytes)
    sik = ed25519.Ed25519PublicKey.from_public_bytes(sik_bytes)
    spk = x25519.X25519PublicKey.from_public_bytes(spk_bytes)

    # Vérification de la cohérence de la signature de la clé SPK du destinataire
    try:
        sik.verify(spk_sig_bytes, spk_bytes)
    except:
        raise Exception("SPK verification failed")

    # Création d'un objet UserSession qui permettra de commencer X3DH  
    session=UserSession.objects.create(
        user=self,
        peer=username,
        ik=serialize(ik.public_bytes_raw()),
        spk=serialize(spk.public_bytes_raw())
    )

def ENCRYPT_X3DH(SK, plaintext, associated_data):
    """
    Cette fonction sert à chiffrer un message en clair (plaintext) à l'aide de la clé SK déterminée par le processus X3DH (voir perform_x3dh()).
    Elle est utilisée par Alice (initiatrice de la communication entre elle et Bob)
    L'associated data ad est présente pour éviter certaines attaques (replay), c'est une variable contenant les clés d'identité d'Alice et de Bob.

    Une utilisation est faite de la fonction (de hachage) HKDF sur la clé partagée pour obtenir 80 octets qui correspondent à trois valeurs en sortie :
    - enc_key (32 octets) : Clé de chiffrement utilisée pour chiffrer le plaintext
    - auth_key (32 octets) : Clé correspondant à la signature numérique (HMAC).
    Celle-ci est utilisée pour signer la concaténation ciphertext + associated_data. Si le message est modifié par quelqu'un, on le verra grâce à la 
    vérification de la valeur HMAC.
    - iv (16 octets) : Cette valeur est une sorte de 'sel' qui permet d'empêcher que deux messages en clair identiques aient le même ciphertext. 
    Dans cette implémentation, elle est inutile car pas créée aléatoirement (faisant partie de la clé SK) ce qui fait que deux messages identiques vont
    effectivement être chiffrés de la même façon. C'est un point d'amélioration du code que nous avons identifié.

    En sortie, on retourne le message chiffré et sa signature.
    """
    # Utilisation de la HKDF pour obtenir les 3 valeurs
    zero_filled = b"\x00"*80
    info = b"X3DH"
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=zero_filled,
        info=info,
    )

    hkdf_out = hkdf.derive(SK)
    enc_key = hkdf_out[:32]
    auth_key = hkdf_out[32:64]
    iv = hkdf_out[64:]

    # Chiffrement du plaintext
    # Note : On ajoute du padding car AES fonctionne par blocs de 16 octets, il faut en mettre si le message en octets n'est pas un multiple de 16 
    cipher = Cipher(algorithms.AES256(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(256).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Signature numérique, sur le même principe que l'étape précédente
    padder = padding.PKCS7(256).padder()
    padded_assoc_data = padder.update(associated_data) + padder.finalize()
    h = hmac.HMAC(auth_key, hashes.SHA256())
    h.update(padded_assoc_data + ciphertext)
    h_out = h.finalize()
    return (ciphertext, h_out)


def DECRYPT_X3DH(SK, ciphertext, mac, associated_data):
    """
    Cette fonction est la suite de ENCRYPT_X3DH et sert à déchiffrer le message envoyé et vérifier la signature associée.
    Pour cela, elle utilise la clé secrète partagée (SK), le texte chiffré, le mac et l'associated data pour la vérification du contexte de l'échange.
    Mac correspond au h_out de ENCRYPT_X3DH(), la vérification se fait en comparant cette valeur à celle calculée localement.
    La structure est globalement similaire à celle d'ENCRYPT_X3DH.
    """
    # Utilisation de la HKDF pour obtenir les mêmes valeurs que dans ENCRYPT_X3DH()
    info = b"encrypt_info_kdf"
    zero_filled = b"\x00"*80
    info = b"X3DH"
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=zero_filled,
        info=info,
    )

    hkdf_out = hkdf.derive(SK)
    enc_key = hkdf_out[:32]
    auth_key = hkdf_out[32:64]
    iv = hkdf_out[64:]

    # Déchiffrement du message chiffré
    cipher = Cipher(algorithms.AES256(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Calcul de la signature numérique attendue
    h = hmac.HMAC(auth_key, hashes.SHA256())
    padder = padding.PKCS7(256).padder()
    padded_assoc_data = padder.update(associated_data) + padder.finalize()
    h.update(padded_assoc_data + ciphertext) 
    
    # Vérification de la signature
    try:
        h.verify(mac)
    except:
        return (False, "")

    unpadder = padding.PKCS7(256).unpadder()
    plaintext =  unpadder.update(plaintext) + unpadder.finalize()
    return (True, plaintext)
   

def perform_x3dh(self:User, peer:str,server_url=SERVER_URL):
    """
    Exécute l'échange X3DH d'Alice à Bob en envoyant les données au serveur

    I.
    Une première étape est de générer les 3 clés DH à partir du bundle de clés publiques de Bob et de la clé privée d'identité d'Alice
    Les trois clés DH sont obtenues à partir d'opérations d'échanges comme ceci :
    DH1 : Identité privée de Alice et clé publique signée de Bob
    DH2 : Clé éphémère privée de Alice et clé publique d'identité de Bob
    DH3 : Clé éphémère privée de Alice et clé publique signée de Bob
    De son côté, Bob fera les mêmes opérations en 'sens inversé', c'est à dire en utilisant la version privée des clés qui étaient publiques 
    (il peut car c'est bien lui!) et inversement avec les clés qui étaient privées chez Alice 
    Cela permettra de retrouver la même valeur pour SK, l'addition des 3 clés avec un sel

    II.
    Dans une deuxième étape, Alice calcule SK, la clé finale qui sera utilisée notamment comme base pour le Double Ratchet.
    Le calcul se fait comme ceci :
    - On concatène les 3 DHs (km), qui est une base secrète partagée entre Alice et Bob.
    - On ajoute à km un sel fixe qui permet d'augmenter un peu la sécurité du processus (fixe car Bob doit pouvoir faire le même calcul de son côté)
    - Cet ensemble passe dans la HKDF, fonction de dérivation de clé (hachage) qui produit une sortie plus sûre du point de vue cryptographique*. 

    III.
    Une fois SK déterminée, Alice l'utilise pour chiffrer le premier message (##CHAT_START##) qu'elle va envoyer à Bob. 
    Cela lui permettra de : 
    - Vérifier que le déchiffrage fonctionne
    - Connaître Alice pour demander ses clés publiques et calculer SK de son côté (en vérifiant que c'est la même que celle qu'a trouvé Alice)

    Le chiffrage est obtenu via ENCRYPT_X3DH().

    La fonction termine en enregistrant les informations sur l'échange et en effectuant la requête d'envoi du message X3DH au serveur.

    * Passer par un hash permet d'uniformiser (rendre plus aléatoire) la distribution des bits (les DHs peuvent avoir des valeurs biaisées 
    car elles proviennent d'échanges entre les mêmes clés). De plus, si on Alice et Bob démarrent plusieurs sessions, ils auront à chaque fois
    une clé SK très similaire sans hash (la seule différence entre les instances viendra de l'aléatoire de la clé ephémère epk d'Alice).
    """
        
    # Etape 1 : Génération des 3 DHs
    try:
        user_session = UserSession.objects.get(user=self, peer=peer)
    except UserSession.DoesNotExist:
        raise ValueError(f"Session not found for user {peer}!")
    
    alice = User.objects.get(username=self.username)
    alice_ik_bytes=deserialize(alice.keys.ik_private)
    alice_ik = x25519.X25519PrivateKey.from_private_bytes(alice_ik_bytes)
    bob_spk=x25519.X25519PublicKey.from_public_bytes(deserialize(user_session.spk))
    bob_ik=x25519.X25519PublicKey.from_public_bytes(deserialize(user_session.ik))
    alice_epk = GENERATE_DH()

    dh1 = alice_ik.exchange(bob_spk)
    dh2 = alice_epk.exchange(bob_ik)
    dh3 = alice_epk.exchange(bob_spk)

    # Etape 2 : Calcul de SK
    # Note : 32 bytes = clé de 256 bits
    # La fonction HKDF est mise en place et utilisée comme décrit
    # Les clés intermédiaires sont supprimées à la fin de ce processus
    info = b"extended_triple_diffie_hellman"
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"\x00"*32,
        info=info,
    )

    f = b"\xff" * 32
    km = dh1 + dh2 + dh3
    SK = hkdf.derive(f + km)

    alice_epk_pub = alice_epk.public_key()
    alice_epk_pub_bytes = alice_epk_pub.public_bytes_raw()
    alice_ik_bytes = alice_ik.public_key().public_bytes_raw()
    bob_ik_bytes = deserialize(user_session.ik)
    del alice_epk, dh1, dh2, dh3

    # Etape 3
    # Le premier message à faire passer est ##CHAT_START##
    # Note : ad est la concaténation des deux clés d'identité, c'est une valeur permettant de vérifier que ces informations concernent bien une session Alice/Bob
    # Son utilisation en paramètre de ENCRYPT_X3DH() permet d'éviter notamment des attaques par replay (voir annexes des slides de présentation)
    ad = serialize(alice_ik_bytes) + serialize(bob_ik_bytes)
    msg = "##CHAT_START##"
    ciphertext, hmac = ENCRYPT_X3DH(SK, msg.encode('utf-8'), ad.encode('utf-8'))

    # Création de l'objet X3DH_Session
    session=X3DH_Session.objects.create(
        user_session=user_session,
        alice=self.username,
        bob=peer,
        sk=serialize(SK),
        spk=user_session.spk,
        epk=serialize(alice_epk_pub_bytes),
        ad=ad
    )

    # Envoi de la requête avec le message chiffré vers le serveur pour qu'il le transmette à Bob
    url = server_url + "/x3dh_message/"
    response = requests.post(url, json={
        "username": peer,
        "from": self.username,
        "ik": self.keys.ik_public,
        "epk": session.epk,
        "cipher":serialize(ciphertext),
        "hmac": serialize(hmac)
    })
    
    if response.status_code == 200:
        #print("X3DH Message sent.")
        #InitRatchetAlice(self,peer)
        return True
    else:
        print("X3DH Failed!")
        return False


def receive_x3dh(self:User, username:str, data):
    """
    Cette fonction permet à Bob de recevoir le message X3DH d'Alice.

    La structure de la fonction est similaire à perform_x3dh() juste au-dessus. 
    I. Réception de data (contenant quelques informations d'Alice ainsi que le message chiffré) et calcul des 3 DHs
    II. Calcul de SK en utilisant les 3 DHs
    III. Déchiffrement du message en utilisant SK. 
    """
    # Etape 1
    #print(data)
    alice_ik_bytes = deserialize(data["ik"])
    epk_bytes = deserialize(data["epk"])
    cipher = deserialize(data["cipher"])
    hmac = deserialize(data["hmac"])

    alice_ik = x25519.X25519PublicKey.from_public_bytes(alice_ik_bytes)
    epk = x25519.X25519PublicKey.from_public_bytes(epk_bytes)
    bob_spk = x25519.X25519PrivateKey.from_private_bytes(deserialize(self.keys.spk_private))
    bob_ik = x25519.X25519PrivateKey.from_private_bytes(deserialize(self.keys.ik_private))

    dh1 = bob_spk.exchange(alice_ik)
    dh2 = bob_ik.exchange(epk)
    dh3 = bob_spk.exchange(epk)

    # Etape 2
    info = b"extended_triple_diffie_hellman"
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"\x00"*32,
        info=info,
    )
        
    f = b"\xff" * 32
    km = dh1 + dh2 + dh3
    SK = hkdf.derive(f + km)

    # Etape 3
    bob_ik_public=self.keys.ik_public
    ad  = serialize(alice_ik_bytes) +  bob_ik_public 
    res = DECRYPT_X3DH(SK, cipher, hmac, ad.encode('utf-8'))

    if(res[0]):
        #InitRatchetBob(self,username)
        pass
    else:
        print("DH Failed")
        return res
        
    return res
    
################################################################
################################################################
########################  MESSAGES #############################
################################################################
################################################################

def send_message(self:User, peer:str, msg:str,server_url=SERVER_URL):
    """
    Cette fonction permet à un utilisateur d'envoyer un message chiffré à un autre. Elle utilise la session X3DH 
    Sa structure est très similaire à celle de perform_x3dh(), les calculs de clés en moins car cette fois, la clé secrète SK a déjà été calculée et est
    disponible dans un objet X3DH_Session qui serait stocké en local en pratique.
    """
    # Session X3DH qui contient la clé secrète
    try:
        x3dh = X3DH_Session.objects.get(alice=self.username, bob=peer)
    except X3DH_Session.DoesNotExist:
        x3dh = X3DH_Session.objects.get(alice=peer, bob=self.username)

    ad=x3dh.ad
    SK=deserialize(x3dh.sk)
    ciphertext, hmac = ENCRYPT_X3DH(SK, msg.encode('utf-8'), ad.encode('utf-8'))

    # Envoi de la requête avec le message chiffré vers le serveur pour qu'il le transmette à Bob
    url = server_url + "/message/"
    response = requests.post(url, json={
        "username": peer,
        "from": self.username,
        "cipher":serialize(ciphertext),
        "hmac": serialize(hmac)
    })
    if response.status_code == 200:
        return True
    else:
        return False

def receive_message(self:User, peer:str, data):
    """
    Cette fonction permet à un destinataire de recevoir un message chiffré qu'il peut déchiffrer après avoir effectué X3DH avec l'émetteur
    De la même manière que la fonction précédentes, son fonctionnement se base beaucoup sur receive_x3dh()
    """
    cipher = deserialize(data["cipher"])
    hmac = deserialize(data["hmac"])
    # Session X3DH qui contient la clé secrète
    try:
        x3dh = X3DH_Session.objects.get(alice=self.username, bob=peer)
    except X3DH_Session.DoesNotExist:
        x3dh = X3DH_Session.objects.get(alice=peer, bob=self.username)
    ad=x3dh.ad
    SK=deserialize(x3dh.sk)
    res = DECRYPT_X3DH(SK, cipher, hmac, ad.encode('utf-8'))        
    return res

       