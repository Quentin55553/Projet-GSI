from django.test import TestCase
from django.contrib.auth.models import User
from .models import UserKeys
from django.urls import reverse
from django.core.management import call_command
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import ed25519
from .crypto import serialize,deserialize
from .crypto import perform_x3dh
from .crypto import *
import json

class UserKeysTests(TestCase):

    def setUp(self):
        User.objects.all().delete()
        UserKeys.objects.all().delete()
        call_command('flush', '--no-input')

    def test_CREATION_USERS(self):
        print()
        # Création d'Alice
        alice = User.objects.create_user(username='alice', password='password')

        # Vérifier que les clés existent bien dans la base de données
        self.assertIsNotNone(UserKeys.objects.get(user=alice))

        # Vérifier que les clés sont bien créées pour Alice
        alice_keys = UserKeys.objects.get(user=alice)
        
        # Vérifier que l'utilisateur Alice a bien des clés associées
        self.assertEqual(alice_keys.user.username, 'alice')
        
        self.assertIsInstance(alice_keys.ik_private, str)
        self.assertIsInstance(alice_keys.sik_private, str)
        self.assertIsInstance(alice_keys.spk_private, str)
        self.assertIsInstance(alice_keys.ik_public, str)
        self.assertIsInstance(alice_keys.spk_public, str)
        self.assertIsInstance(alice_keys.spk_signature, str)
        
        print("Test réussi : Alice et ses clés ont bien été créés et sont dans la base de données.")


    def test_RECUP_BUNDLE(self):
        "Test de création d'utilisateurs, génération des clés et récupération des bundles"

        print()
        # Création des utilisateurs
        alice = User.objects.create(username="alice")
        bob = User.objects.create(username="bob")

        # Vérification que les clés sont bien créées
        self.assertIsNotNone(UserKeys.objects.get(user=alice))
        self.assertIsNotNone(UserKeys.objects.get(user=bob))

        alice_keys = UserKeys.objects.get(user=alice)
        bob_keys = UserKeys.objects.get(user=bob)    
        self.assertEqual(alice_keys.user.username, 'alice')
        self.assertEqual(bob_keys.user.username, 'bob')

        # Méthode 1
        username='alice'
        user = User.objects.get(username=username)
        keys = user.keys
        self.assertIsNotNone(keys)
        self.assertIsNotNone(user.keys.bundle().content)
        #print(json.loads(user.keys.bundle().content))
        
        # Méthode 2
        response_alice = self.client.get(reverse('get_user_bundle', args=["alice"]))
        response_bob = self.client.get(reverse('get_user_bundle', args=["bob"]))
        self.assertEqual(response_alice.status_code, 200)
        self.assertEqual(response_bob.status_code, 200)
        self.assertEqual(response_alice.json()["username"], "alice")
        self.assertEqual(response_bob.json()["username"], "bob")
        #print(response_alice.json())
        #print(response_bob.json())

        print("Test réussi : les utilisateurs et leurs clés sont bien créés et peuvent être récupérés avec user.keys.bundle().content.")
    
    def test_VERIF_SIGNATURE_SPK(self):
        "Test de vérification du bon fonctionnement de la signature de spk"
        print()
        alice = User.objects.create(username="alice")
        alice = User.objects.get(username="alice")
        data = json.loads(alice.keys.bundle().content)
        ik_bytes = deserialize(data["ik_public"])
        sik_bytes = deserialize(data["sik_public"])
        spk_bytes = deserialize(data["spk_public"])
        spk_sig_bytes = deserialize(data["spk_signature"])
        ik = x25519.X25519PublicKey.from_public_bytes(ik_bytes)
        sik = ed25519.Ed25519PublicKey.from_public_bytes(sik_bytes)
        spk = x25519.X25519PublicKey.from_public_bytes(spk_bytes)
        try:
            sik.verify(spk_sig_bytes, spk_bytes)
            self.assertTrue(True) 
        except:
            self.fail("SPK verification failed!")

        print("Test réussi : La vérification SPK fonctionne pour un utilisateur.")


class RatchetTests(TestCase):

    def setUp(self):
        User.objects.all().delete()
        UserKeys.objects.all().delete()
        call_command('flush', '--no-input')
        
#------------------------------------------------------------------------------------ Tests relatifs à l'échange X3DH

class X3DHTests(TestCase):
    def setUp(self):
        User.objects.all().delete()
        UserKeys.objects.all().delete()
        call_command('flush', '--no-input')
        # Alice et Bob
        self.alice = User.objects.create_user(username="alice", password="password")
        self.bob = User.objects.create_user(username="bob", password="password")
        # Vérifier que les clés ont bien été générées automatiquement
        self.assertIsNotNone(self.alice.keys)
        self.assertIsNotNone(self.bob.keys)

    def test_SESSION_CREATION(self):
        """Un objet UserSession est bien créé quand on appelle request_user_prekey_bundle()."""
        print()
        request_user_prekey_bundle(self.alice,"bob")

        user_session = UserSession.objects.filter(user=self.alice, peer="bob").first()
        self.assertIsNotNone(user_session, "La session entre Alice et Bob n'a pas été créée.")
        self.assertTrue(user_session.ik, "La clé ik n'est pas présente dans la session.")
        self.assertTrue(user_session.spk, "La clé spk n'est pas présente dans la session.")
        self.assertIsInstance(user_session.ik, str, "La clé ik n'est pas une chaîne de caractères.")
        self.assertIsInstance(user_session.spk, str, "La clé spk n'est pas une chaîne de caractères.")
    
        print("Test réussi : La session a bien été créée et les clés sont présentes.")

    
    def test_X3DH_KEY_EXCHANGE(self):
        "Test de l'échange de clés X3DH entre Alice et Bob"
        print()
        request_user_prekey_bundle(self.alice,"bob")

        alice_keys = self.alice.keys

        perform_x3dh(self.alice, "bob")
        try:
            session = X3DH_Session.objects.get(user_session__user=self.alice, user_session__peer="bob")
            self.assertIsNotNone(session)  
            self.assertEqual(session.user_session.user, self.alice)  
            self.assertEqual(session.user_session.peer, "bob")
        except X3DH_Session.DoesNotExist:
            self.fail("X3DH_Session not created after perform_x3dh")

        # Vérification de la structure du session key
        self.assertIsNotNone(session.sk)
        self.assertIsNotNone(session.spk)
        self.assertIsNotNone(session.ad)
        #print(session.sk)

        print("Test réussi : La session X3DH a bien été créée après perform_x3dh().")
    

    """
    def test_X3DH_ENCRYPTION_DECRYPTION(self):
        "Test du chiffrement et déchiffrement avec X3DH"
        session = perform_x3dh(self.alice, self.bob.keys)
        sk = session["sk"]
        ad = session["ad"]

        message = "Hello Bob!"
        ciphertext, hmac = ENCRYPT_X3DH(sk, message.encode("utf-8"), ad.encode("utf-8"))

        self.assertIsNotNone(ciphertext)
        self.assertIsNotNone(hmac)

        # Bob déchiffrerait le message avec Double Ratchet.
        print(f"Message chiffré : {ciphertext}")
        print(f"HMAC : {hmac}")

    def test_SEND_X3DH_MESSAGE(self):
        "Test de l'envoi d'un message via l'API"
        self.client.login(username="alice", password="password")

        response = self.client.post(
            reverse("send_x3dh_message"),
            {"username": "bob", "message": "Salut Bob !"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("success", response.json())"""