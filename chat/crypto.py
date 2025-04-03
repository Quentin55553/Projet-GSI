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
import json
import requests
import base64
from django.conf import settings


#----------------------------------------------------------------------------------------------------------- Utilitaires

def serialize(val):
    """Utilisé pour encoder des octets en base 64 (pour stocker des clés dans la base de données notamment)"""
    return base64.standard_b64encode(val).decode('utf-8')

def deserialize(val):
    """Utilisé pour décoder des octets qui ont été encodés en base 64"""
    return base64.standard_b64decode(val.encode('utf-8'))


#------------------------------------------------------------------------------------------------------------ Utilitaires - Cryptographie

MAX_SKIP = 10

def GENERATE_DH():
    sk = x25519.X25519PrivateKey.generate()
    return sk

def DH(dh_pair, dh_pub):
    dh_out = dh_pair.exchange(dh_pub)
    return dh_out

def KDF_RK(rk, dh_out):
    # rk is hkdf salt, dh_out is hkdf input key material

    if isinstance(rk, x25519.X25519PublicKey):
        rk_bytes = rk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    else:
        rk_bytes = rk

    info = b"kdf_rk_info" # should be changed in other places HKDF() is used
    
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
        print(self.pn, self.n, "alpha")
        return {'dh': serialize(self.dh), 'pn': serialize(self.pn), 'n': serialize(self.n)}

    @staticmethod
    def deserialize(val):
        return Header(deserialize(val['dh']), deserialize(val['pn']), deserialize(val['n']))
    

def HEADER(dh_pair, pn, n):
    pk = dh_pair.public_key()
    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return Header(pk_bytes, pn.to_bytes(pn.bit_length()), n.to_bytes(n.bit_length()))

def CONCAT(ad, header):
    return (ad, header)

def RatchetEncrypt(state, plaintext, AD):
    state["CKs"], mk = KDF_CK(state["CKs"])
    header = HEADER(state["DHs"], state["PN"], state["Ns"])
    state["Ns"] += 1
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

def ENCRYPT_DOUB_RATCH(mk, plaintext, associated_data):
    info = b"encrypt_info_kdf" # should be changed in other places HKDF() is used
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


def DECRYPT_DOUB_RATCH(mk, cipherout, associated_data):
    
    ciphertext = cipherout[0]
    mac = cipherout[1]

    info = b"encrypt_info_kdf" # should be changed in other places HKDF() is used
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


def ENCRYPT_X3DH(mk, plaintext, associated_data):
    zero_filled = b"\x00"*80
    info = b"X3DH"
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

    padder = padding.PKCS7(256).padder()
    padded_assoc_data = padder.update(associated_data) + padder.finalize()

    h = hmac.HMAC(auth_key, hashes.SHA256())
    h.update(padded_assoc_data + ciphertext)
    h_out = h.finalize()
    return (ciphertext, h_out)

def DECRYPT_X3DH(mk, ciphertext, mac, associated_data):
    info = b"encrypt_info_kdf" # should be changed in other places HKDF() is used
    zero_filled = b"\x00"*80
    info = b"X3DH"
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
    
    padder = padding.PKCS7(256).padder()
    padded_assoc_data = padder.update(associated_data) + padder.finalize()

    h.update(padded_assoc_data + ciphertext) 
    
    try:
        h.verify(mac)
    except:
        return (False, "")

    unpadder = padding.PKCS7(256).unpadder()
    plaintext =  unpadder.update(plaintext) + unpadder.finalize()
    return (True, plaintext)

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

    def init_ratchet_transmission(self, username):
        """
        Fonction d'initialisation du ratchet côté Alice (voir la documentation de Signal : )
        """
        self.messages[username] = []
        SK = self.x3dh_session[username]['sk']
        self.ratchet_session[username] = {}
        recipient_dh_pk = self.x3dh_session[username]['spk']
        self.ratchet_session[username]["DHs"] = GENERATE_DH()
        self.ratchet_session[username]["DHr"] = recipient_dh_pk
        self.ratchet_session[username]["RK"], self.ratchet_session[username]["CKs"] = KDF_RK(SK, DH(self.ratchet_session[username]["DHs"], self.ratchet_session[username]["DHr"]))
        self.ratchet_session[username]["RK"] = x25519.X25519PublicKey.from_public_bytes(self.ratchet_session[username]["RK"])
        self.ratchet_session[username]["CKs"] = x25519.X25519PublicKey.from_public_bytes(self.ratchet_session[username]["CKs"])
        self.ratchet_session[username]["CKr"] = None
        self.ratchet_session[username]["Ns"] = 0
        self.ratchet_session[username]["Nr"] = 0
        self.ratchet_session[username]["PN"] = 0
        self.ratchet_session[username]["MKSKIPPED"] = {}
    
    def init_ratchet_receiver(self, username):
        """
        Fonction d'initialisation du ratchet côté Bob (voir la documentation de Signal : )
        """
        self.messages[username] = []
        SK = self.x3dh_session[username]['sk']
        recipient_dh_sk = self.x3dh_session[username]['spk']
        self.ratchet_session[username] = {}
        self.ratchet_session[username]["DHs"] = recipient_dh_sk
        self.ratchet_session[username]["DHr"] = None
        self.ratchet_session[username]["RK"] = SK
        self.ratchet_session[username]["CKs"] = None
        self.ratchet_session[username]["CKr"] = None
        self.ratchet_session[username]["Ns"] = 0
        self.ratchet_session[username]["Nr"] = 0
        self.ratchet_session[username]["PN"] = 0
        self.ratchet_session[username]["MKSKIPPED"] = {}
        pass

    def get_keys(self, opk_size=10):
        """
        
        """
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
    

    
    def send_message(self, username, msg):
        ad = self.x3dh_session[username]['ad']
        header, ciphertext = RatchetEncrypt(self.ratchet_session[username], msg.encode('utf-8'), ad.encode('utf-8'))
        ciphertext, mac = ciphertext
        self.messages[username].append((self.username, msg ))
        #return sio.call("ratchet_msg", {'username': username,'cipher': serialize(ciphertext), 'header': header.serialize(), 'hmac': serialize(mac), 'from': self.username})
        
    def is_connected(self, username):
        if username in self.x3dh_session:
            return True
        else:
            return False
        
    def receive_message(self, username, msg):
        header = Header.deserialize(msg['header'])
        ciphertext = deserialize(msg['cipher'])
        hmac = deserialize(msg['hmac'])
        ad = self.x3dh_session[username]['ad']
        plaintext = RatchetDecrypt(self.ratchet_session[username], header, (ciphertext, hmac), ad.encode('utf-8'))
        print("recv:", plaintext)
        self.messages[username].append((username, plaintext.decode('utf-8') ))
        return plaintext.decode('utf-8')

    def receive_x3dh(self, username, data):
        print(data)
        # {"username": username, "from": self.username, "ik": serialize(ik_bytes), "epk": serialize(epk_pub_bytes), "cipher": ciphertext, "nonce":nonce}
        ika_bytes = deserialize(data["ik"])
        epk_bytes = deserialize(data["epk"])
        cipher = deserialize(data["cipher"])
        hmac = deserialize(data["hmac"])
        ika = x25519.X25519PublicKey.from_public_bytes(ika_bytes)
        epk = x25519.X25519PublicKey.from_public_bytes(epk_bytes)
        dh1 = self.spk.exchange(ika)
        dh2 = self.ik.exchange(epk)
        dh3 = self.spk.exchange(epk)

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

        ad  = serialize(ika_bytes) +  serialize(self.ik.public_key().public_bytes_raw()) 
        res = DECRYPT_X3DH(SK, cipher, hmac, ad.encode('utf-8'))
        if(res[0]):
            self.x3dh_session[username] = {"sk" : SK, "spk": self.spk, "ad": ad}
            self.init_ratchet_reciever(username)
        else:
            print("DH Failed")
            return False
        
        return True
    
    

    """
    def perform_x3dh(self, username):
        if(not username in self.sessions):
            print("User key bundles not requested!")
        self.epk = x25519.X25519PrivateKey.generate()
        dh1 = self.ik.exchange(self.sessions[username]['spk'])
        dh2 = self.epk.exchange(self.sessions[username]['ik'])
        dh3 = self.epk.exchange(self.sessions[username]['spk'])

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

       
        self.epk_pub = self.epk.public_key()
        epk_pub_bytes = self.epk_pub.public_bytes_raw()
        ik_bytes = self.ik.public_key().public_bytes_raw()
        ik_b_bytes = self.sessions[username]['ik'].public_bytes_raw()
        del self.epk
        del dh1, dh2, dh3

        ad  = serialize(ik_bytes) + serialize(ik_b_bytes)
        msg = "##CHAT_START##"
        ciphertext, hmac = ENCRYPT_X3DH(SK, msg.encode('utf-8'), ad.encode('utf-8'))

        self.x3dh_session[username] = {"sk" : SK, "spk": self.sessions[username]['spk'], "ad": ad}
        res = sio.call("x3dh_message", {"username": username, "from": self.username, "ik": serialize(ik_bytes), "epk": serialize(epk_pub_bytes), "cipher": serialize(ciphertext), "hmac":serialize(hmac)})
        if res:
            self.init_ratchet_transmission(username)
        else:
            print("DH Failed!")
        return res
    """

def request_user_prekey_bundle(self:User, username:str):
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

    try:
        sik.verify(spk_sig_bytes, spk_bytes)
    except:
        raise Exception("SPK verification failed")

    session=UserSession.objects.create(
        user=self,
        peer=username,
        ik=serialize(ik.public_bytes_raw()),
        spk=serialize(spk.public_bytes_raw())
    )
   
def perform_x3dh(self:User, username:str):
    """Exécute l'échange X3DH d'Alice à Bob en envoyant les données via une requête Django"""
        
    # Une première étape est de générer les 3 clés DH à partir du bundle de clés publiques du destinataire et de la clé privée d'identité de l'émetteur
    try:
        # Session Alice -> Bob
        user_session = UserSession.objects.get(user=self, peer=username)
    except UserSession.DoesNotExist:
        raise ValueError(f"Session not found for user {username}!")
    
    alice = User.objects.get(username=self.username)
    alice_ik_bytes=deserialize(alice.keys.ik_private)
    alice_ik = x25519.X25519PrivateKey.from_private_bytes(alice_ik_bytes)
    bob_spk=x25519.X25519PublicKey.from_public_bytes(deserialize(user_session.spk))
    bob_ik=x25519.X25519PublicKey.from_public_bytes(deserialize(user_session.ik))
    alice_epk = x25519.X25519PrivateKey.generate()

    dh1 = alice_ik.exchange(bob_spk)
    dh2 = alice_epk.exchange(bob_ik)
    dh3 = alice_epk.exchange(bob_spk)

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

    ad = serialize(alice_ik_bytes) + serialize(bob_ik_bytes)
    msg = "##CHAT_START##"
    ciphertext, hmac = ENCRYPT_X3DH(SK, msg.encode('utf-8'), ad.encode('utf-8'))

    #self.x3dh_session[username] = {"sk": SK, "spk": self.sessions[username]['spk'], "ad": ad}
    # Création de l'objet X3DH_Session après l'échange
    X3DH_Session.objects.create(
        user_session=user_session,
        sk=SK,
        spk=user_session.spk,
        ad=ad
    )

    return
    """
        # Envoi de la requête avec le message chiffré vers Django pour qu'il le transmette au destinataire
        url = "localhost:8000/x3dh_message/"
        response = requests.post(url, json={
            "username": username,
            "from": self.username,
            "ik": serialize(ik_bytes),
            "epk": serialize(epk_pub_bytes),
            "cipher":serialize(ciphertext),
            "hmac": serialize(hmac)
        })

        if response.status_code == 200:
            self.init_ratchet_transmission(username)
            return True
        else:
            print("X3DH Failed!")
            return False
    """