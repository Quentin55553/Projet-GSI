"""
Ce fichier de code peut-être considéré comme le coeur de notre projet (models.py est aussi assez important car il décrit les objets présents en BDD).
Il regroupe toutes les fonctions cryptographiques utilisées pour garantir la sécurité des messages échangés et implémente le Signal Protocol.

Afin de produire le code suivant, nous nous sommes aidés des deux sources suivantes :

1. La documentation de Signal
https://signal.org/docs/

Elle présente notamment le pseudo-code de certaines fonctions à utiliser et explique surtout en détail l'algorithmique du protocole.

2. Une implémentation existante du Signal Protocol en Python disponible sur Github
https://github.com/rohankalbag/cryptography-signal-protocol

Nous avons repris ce code, c'est pour cela qu'on peut trouver des similarités sur certaines fonctions du nôtre. 

En revanche, adapter le code à l'architecture Django a nécessité beaucoup de travail d'analyse, n'était pas trivial et a rendu obligatoire de comprendre en détail
le fonctionnement du code, que nous avons d'ailleurs commenté entièrement avec soin (le code présent sur ce dépôt est très peu commenté). Aucun de nous n'avait 
travaillé avec Django avant ce projet, ce qui a compliqué les choses et nous a demandé d'apprendre sur le tas, mais nous avons quand même décidé de nous en tenir
à ce que notre état de l'art des technologies nous avait appris (Django est l'un des meilleurs frameworks pour la sécurité générale d'une application). 

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
from .models import UserKeys
from .models import UserSession
from .models import X3DH_Session
from .models import RatchetSession
from .models import Conversation
from .models import Message
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

def DH(dh_pair, dh_pub):
    """
    Cette fonction est utilisée pour calculer l'échange entre la clé privée dh_pair et la clé publique dh_pub (voir schéma de fonctionnement du ratchet).
    
    Dans l'algorithme (plus précisément celui du ratchet DH, l'un des deux ratchets), à chaque étape, un parti :
    - Obtient la clé DH publique de l'émetteur (dh_pub)
    - Obtient le dh_out qu'a calculé l'émetteur de son côté (étape précédente)
    - Vérifie que la clé dh_pub associée à la clé DH privée qu'il a à cette étape produit le même dh_out.

    Cela est rendu possible par le fait que les clés DH privées des deux côtés proviennent d'une clé secrète 'SK' sur laquelle les deux partis
    se sont mis d'accord via X3DH   

    L'opération d'échange ou "association des clés" est réalisée par cette fonction, qui renvoie le résultat.
    """
    dh_out = dh_pair.exchange(dh_pub)
    return dh_out

def KDF_RK(rk, dh_out):
    # rk is hkdf salt, dh_out is hkdf input key material
    if isinstance(rk, x25519.X25519PublicKey):
        rk_bytes = rk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    elif isinstance(rk,str):
        rk_bytes=deserialize(rk)
    else:
        rk_bytes = rk

    info = b"kdf_rk_info"
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=rk_bytes,
        info=info,
    )
    
    h_out = hkdf.derive(dh_out)
    root_key = h_out[:32]
    chain_key = h_out[32:]

    return (root_key, chain_key)


def KDF_CK(ck):

    if isinstance(ck, x25519.X25519PublicKey):
        ck_bytes = ck.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    else:
        ck_bytes = ck

    h = hmac.HMAC(ck_bytes, hashes.SHA256())
    h.update(bytearray([0x01]))
    message_key = h.finalize()

    h = hmac.HMAC(ck_bytes, hashes.SHA256())
    h.update(bytearray([0x02]))
    next_ck = h.finalize()

    return (next_ck, message_key)

class Header:
    def __init__(self, dh, pn, n):
        self.dh = dh
        self.pn = pn
        self.n = n
    
    def serialize(self):
        #print(self.pn, self.n, "alpha")
        return {'dh': serialize(self.dh), 'pn': serialize(self.pn), 'n': serialize(self.n)}

    @staticmethod
    def deserialize(val):
        return Header(deserialize(val['dh']), deserialize(val['pn']), deserialize(val['n']))
    

def HEADER(dh_pair, pn, n):
    if isinstance(dh_pair,str):
        dh_pair=x25519.X25519PrivateKey.from_private_bytes(deserialize(dh_pair))
    pk = dh_pair.public_key()
    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return Header(pk_bytes, pn.to_bytes(pn.bit_length()), n.to_bytes(n.bit_length()))

def CONCAT(ad, header):
    return (ad, header)






#------------------------------------------------------------------------------------------------------------ Utilisateur du protocole

class SignalUser:
    def __init__(self, username):
        """
        Cette fonction est utilisée pour initialiser un objet utilisateur. Il peut déjà avoir un compte, dans ce cas les clés arriveront du serveur,
        sinon elles seront générées sur le moment.
        """
        self.username = username
        self.sessions = {}
        self.x3dh_session = {}
        self.ratchet_session = {}
        self.messages = {}
        self.get_keys()

    def get_keys(self, opk_size=10):
        self.ik = x25519.X25519PrivateKey.generate()
        self.sik = ed25519.Ed25519PrivateKey.generate()
        self.spk = x25519.X25519PrivateKey.generate()
        spk_bytes = self.spk.public_key().public_bytes_raw()
        self.spk_sig = self.sik.sign(spk_bytes)

    def serialize_user(self):
        
        ik_bytes = self.ik.public_key().public_bytes_raw()
        sik_bytes = self.sik.public_key().public_bytes_raw()
        spk_bytes = self.spk.public_key().public_bytes_raw()
        
        return {
            "username": self.username, 
            "ik": serialize(ik_bytes),
            "sik": serialize(sik_bytes),
            "spk": serialize(spk_bytes),
            "spk_sig": serialize(self.spk_sig)
        }
    

    
    


################################################################
################################################################
########################  ECHANGE X3DH #########################
################################################################
################################################################

def request_user_prekey_bundle(self:User, username:str):
    """
    Cette fonction est utilisée pour obtenir les clés publiques d'un utilisateur (username). 
    Ces clés publiques sont notamment utilisées par le protocole X3DH au moment d'un premier contact entre deux utilisateurs. 
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
    L'associated data est présente pour éviter certaines attaques (replay), elle contient les clés d'identité d'Alice et de Bob.

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
        InitRatchetAlice(self,peer)
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
        InitRatchetBob(self,username)
    else:
        print("DH Failed")
        return res
        
    return res
    

################################################################
################################################################
######################  DOUBLE RATCHET #########################
################################################################
################################################################

"""
Pour comprendre les fonctions suivantes, il est encore plus nécessaire qu'avec X3DH de se référer à la documentation technique fournie, surtout pour les schémas.
Nous décrivons quand même toutes les variables utilisées ainsi que les étapes de chaque fonction. 
"""

def InitRatchetAlice(self:User, peer:str):
    """
    Fonction d'initialisation de la session ratchet côté Alice.
    """

    x3dh = X3DH_Session.objects.get(alice=self.username, bob=peer)

    SK = x3dh.sk
    DHs=GENERATE_DH()
    DHr = x25519.X25519PublicKey.from_public_bytes(deserialize(x3dh.spk))
    RK,CKs=KDF_RK(SK, DH(DHs, DHr))
    RK = x25519.X25519PublicKey.from_public_bytes(RK)
    CKs = x25519.X25519PublicKey.from_public_bytes(CKs)

    json_fields = {
        "DHs": serialize(DHs.private_bytes_raw()),  
        "DHr": serialize(DHr.public_bytes_raw()),        
        "RK": serialize(RK.public_bytes_raw()),                
        "CKs": serialize(CKs.public_bytes_raw()),             
        "CKr": None,             
        "Ns": 0,                 
        "Nr": 0,                 
        "PN": 0,                 
        "MKSKIPPED": {}          
    }

    session = RatchetSession(
        username=self.username,
        peer=peer,
        session_data=json.dumps(json_fields)
    )
    session.save(
        #using="local_storage" # à commenter si on veut exécuter les tests
    )

def InitRatchetBob(self:User, peer:str):
    """
    Fonction d'initialisation de la session ratchet côté Bob. Elle fait directement suite au reçu de Bob du message X3DH d'Alice
    A ce stade, les deux viennent de se mettre d'accord sur une clé secrète partagée SK.
    Bob va créer un nouvel objet RatchetSession en local pour stocker les informations sur son échange avec Alice.

    Ces informations sont les suivantes :

    - Son propre nom d'utilisateur
    - Le nom d'utilisateur d'Alice (peer)
    - DHs : Une paire de clés (valeur privée) DH utilisée pour calculer DH_OUT
    - DHr : La clé publique utilisée dans le Ratchet DH (associée à la clé privée détenue pour obtenir DH_OUTPUT)
    - RK : Root Key. C'est SK, la clé secrète partagée qu'Alice et Bob ont déterminée ensemble. 
    Elle permet notamment de dériver les chain keys (CK) utilisées pour le chiffrement des messages.
    - CKs : La clé publique utilisée pour chiffrer les messages envoyés
    - CKr : La clé privée utilisée pour déchiffrer les messages reçus
    - Ns : Entier qui compte le nombre de message envoyés (sent)
    - Nr : Entier qui compte le nombre de message reçu (received)
    - PN : Le nombre de message dans une chaîne de messages précédente
    - MKSKIPPED : Un dictionnaire de clés à utiliser pour les messages qui n'ont pas été reçus (on peut le détecter quand on reçoit un numéro de message incohérent
    par rapport au précédent). Nous n'avons pas trop fait attention et géré ce système ici.
    """

    x3dh = X3DH_Session.objects.get(alice=peer, bob=self.username)

    SK = x3dh.sk
    recipient_dh_sk =x3dh.spk

    json_fields = {
        "DHs": recipient_dh_sk,  
        "DHr": None,        
        "RK": SK,                
        "CKs": None,             
        "CKr": None,             
        "Ns": 0,                 
        "Nr": 0,                
        "PN": 0,                 
        "MKSKIPPED": {}         
    }

    session = RatchetSession(
        username=self.username,
        peer=peer,
        session_data=json.dumps(json_fields)
    )
    session.save(
        #using="local_storage" # à commenter si on veut exécuter les tests
    )




#OK
def ENCRYPT_DOUB_RATCH(mk, plaintext, associated_data):
    info = b"encrypt_info_kdf"
    zero_filled = b"\x00"*80
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=zero_filled,
        info=info,
    )

    hkdf_out = hkdf.derive(mk)
    enc_key = hkdf_out[:32]
    auth_key = hkdf_out[32:64]
    iv = hkdf_out[64:]

    cipher = Cipher(algorithms.AES256(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(256).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    ad, header = associated_data
    pk, pn, n = header.dh, header.pn, header.n
    assoc_data = ad + pk + pn + n

    padder = padding.PKCS7(256).padder()
    padded_assoc_data = padder.update(assoc_data) + padder.finalize()

    h = hmac.HMAC(auth_key, hashes.SHA256())
    h.update(padded_assoc_data + ciphertext)
    h_out = h.finalize()
    return (ciphertext, h_out)


# OK
def DECRYPT_DOUB_RATCH(mk, cipherout, associated_data):
    
    ciphertext = cipherout[0]
    mac = cipherout[1]

    info = b"encrypt_info_kdf"
    zero_filled = b"\x00"*80
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=zero_filled,
        info=info,
    )

    hkdf_out = hkdf.derive(mk)
    enc_key = hkdf_out[:32]
    auth_key = hkdf_out[32:64]
    iv = hkdf_out[64:]

    cipher = Cipher(algorithms.AES256(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    h = hmac.HMAC(auth_key, hashes.SHA256())
    
    ad, header = associated_data
    pk, pn, n = header.dh, header.pn, header.n
    assoc_data = ad + pk + pn + n
    
    padder = padding.PKCS7(256).padder()
    padded_assoc_data = padder.update(assoc_data) + padder.finalize()

    h.update(padded_assoc_data + ciphertext) 
    
    try:
        h.verify(mac)
    except:
        raise Exception("MAC verification failed")

    return plaintext


def RatchetEncrypt(state: RatchetSession, plaintext, AD):
    data = json.loads(state.session_data) 
    data["CKs"], mk = KDF_CK(deserialize(data["CKs"]))
    header = HEADER(data["DHs"], data["PN"], data["Ns"])
    data["Ns"] += 1
    data["CKs"]=serialize(data["CKs"])
    state.session_data = json.dumps(data)
    state.save(
        #using="local_storage" # à commenter si on veut exécuter les tests
    )
    return header, ENCRYPT_DOUB_RATCH(mk, plaintext, CONCAT(AD, header))

def RatchetDecrypt(state, header, ciphertext, AD):
    plaintext = TrySkippedMessageKeys(state, header, ciphertext, AD)
    if plaintext != None:
        return plaintext
    if x25519.X25519PublicKey.from_public_bytes(header.dh) != state["DHr"]:                 
        SkipMessageKeys(state, int.from_bytes(header.pn))
        DHRatchet(state, header)
    SkipMessageKeys(state, int.from_bytes(header.n))             
    state["CKr"], mk = KDF_CK(state["CKr"])
    state["Nr"] += 1
    padded_plain_text = DECRYPT_DOUB_RATCH(mk, ciphertext, CONCAT(AD, header))
    unpadder = padding.PKCS7(256).unpadder()
    return unpadder.update(padded_plain_text) + unpadder.finalize()

def TrySkippedMessageKeys(state, header, ciphertext, AD):
    if (header.dh, int.from_bytes(header.n)) in state["MKSKIPPED"]:
        mk = state["MKSKIPPED"][header.dh, int.from_bytes(header.n)]
        del state["MKSKIPPED"][header.dh, int.from_bytes(header.n)]
        return DECRYPT_DOUB_RATCH(mk, ciphertext, CONCAT(AD, header))
    else:
        return None

def SkipMessageKeys(state, until):
    if state["Nr"] + MAX_SKIP < until:
        raise Exception("Too many skipped messages")
    if state["CKr"] != None:
        while state["Nr"] < until:
            state["CKr"], mk = KDF_CK(state["CKr"])
            DHr_bytes = state["DHr"].public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            state["MKSKIPPED"][DHr_bytes, state["Nr"]] = mk
            state["Nr"] += 1

def DHRatchet(state, header):
    state["PN"] = state["Ns"]                          
    state["Ns"] = 0
    state["Nr"] = 0
    state["DHr"] = x25519.X25519PublicKey.from_public_bytes(header.dh)
    state["RK"], state["CKr"] = KDF_RK(state["RK"], DH(state["DHs"], state["DHr"]))
    state["DHs"] = GENERATE_DH()
    state["RK"], state["CKs"] = KDF_RK(state["RK"], DH(state["DHs"], state["DHr"]))


def send_message(self:User, peer:str, msg:str,server_url=SERVER_URL):
    # Session X3DH
    try:
        x3hd = X3DH_Session.objects.get(alice=self.username, bob=peer)
    except X3DH_Session.DoesNotExist:
        x3hd = X3DH_Session.objects.get(alice=peer, bob=self.username)

    ad=x3hd.ad

    # Session ratchet
    self_ratch = RatchetSession.objects.get(username=self.username, peer=peer)

    header, ciphertext = RatchetEncrypt(self_ratch, msg.encode('utf-8'), ad.encode('utf-8'))
    ciphertext, mac = ciphertext
    
    # Récupère ou crée la conversation
    conversation, _ = Conversation.objects.get_or_create(username=self.username, peer=peer)

    # Crée le message
    Message.objects.create(conversation=conversation, sender=self.username, content=msg)

    # Envoi de la requête avec le message chiffré vers le serveur pour qu'il le transmette
    try:
        url = server_url + "/ratchet_message/"
        response = requests.post(url, json={
            "username": peer,
            "from": self.username,
            "cipher": serialize(ciphertext),
            "hmac": serialize(mac),
            "header":header.serialize(),
        })
        #print("Response status:", response.status_code)
        #print("Response text:", response.text)
    except requests.exceptions.RequestException as e:
        print("Erreur lors de la requête:", e)
    
    if response.status_code == 200:
        #print("Ratchet message sent.")
        return True
    else:
        print("Ratchet message failed")
        return False
    
    #return sio.call("ratchet_msg", {'username': username,'cipher': serialize(ciphertext), 'header': header.serialize(), 'hmac': serialize(mac), 'from': self.username})


def receive_message(self, username, msg):
    header = Header.deserialize(msg['header'])
    ciphertext = deserialize(msg['cipher'])
    hmac = deserialize(msg['hmac'])
    ad = self.x3dh_session[username]['ad']
    plaintext = RatchetDecrypt(self.ratchet_session[username], header, (ciphertext, hmac), ad.encode('utf-8'))
    print("recv:", plaintext)
    self.messages[username].append((username, plaintext.decode('utf-8') ))
    return plaintext.decode('utf-8')

       