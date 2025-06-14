from django.test import TestCase
from django.test import LiveServerTestCase
import requests
from django.contrib.auth.models import User
from .models import UserKeys
from django.urls import reverse
from django.core.management import call_command
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import ed25519
from .crypto import serialize,deserialize
from .crypto import perform_x3dh
from .crypto import *
from chat.views.view_utils import *
import json

class A_UserKeysTests(TestCase):

    def setUp(self):
        User.objects.all().delete()
        UserKeys.objects.all().delete()
        call_command('flush', '--no-input')

    def test_CREATION_USERS(self):
        "Test de création d'utilisateurs"
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

        
#------------------------------------------------------------------------------------ Tests relatifs à l'échange X3DH

class B_X3DHTests(LiveServerTestCase):
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

    def test_X3DH_INIT_ALICE(self):
        "Test le démarrage de l'échange de clés X3DH entre Alice et Bob (côté Alice)"
        print()
        request_user_prekey_bundle(self.alice,"bob")

        perform_x3dh(self.alice, "bob",f"{self.live_server_url}")
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
    
    def test_X3DH_KEY_EXCHANGE(self):
        "Test de l'échange de clés X3DH entre Alice et Bob"
        print()
        request_user_prekey_bundle(self.alice,"bob")

        if(perform_x3dh(self.alice, "bob",f"{self.live_server_url}")):
            session = X3DH_Session.objects.get(user_session__user=self.alice, user_session__peer="bob")
        else:
            self.fail("Le X3DH n'a pas fonctionné (Alice)")

        data = get_x3dh_message("bob")
        if data is None:
            self.fail("Bob n'a pas reçu le message X3DH")

        res=receive_x3dh(self.bob,"alice",data)
        self.assertTrue(res[0])
        self.assertEqual(res[1].decode('utf-8'),"##CHAT_START##")
        #print(res[1].decode('utf-8'))

        print("Test réussi : L'échange de clés X3DH complet a réussi.")

    def test_MESSAGE_EXCHANGE(self):
        "Test de l'envoi et de la réception d'un message après avoir effectué l'échange X3DH"
        print()

        # X3DH
        request_user_prekey_bundle(self.alice,"bob")
        perform_x3dh(self.alice, "bob",f"{self.live_server_url}")
        data = get_x3dh_message("bob")
        res=receive_x3dh(self.bob,"alice",data)
        self.assertTrue(res[0])
        self.assertEqual(res[1].decode('utf-8'),"##CHAT_START##")

        # Message d'Alice à Bob
        send_message(self.alice,"bob","Bonjour Bob",f"{self.live_server_url}")
        data=get_message("bob")
        res=receive_message(self.bob,"alice",data)
        self.assertTrue(res[0])
        self.assertEqual(res[1].decode('utf-8'),"Bonjour Bob")

        # Message de Bob à Alice
        send_message(self.bob,"alice","Bonjour Alice",f"{self.live_server_url}")
        data=get_message("alice")
        res=receive_message(self.alice,"bob",data)
        self.assertTrue(res[0])
        self.assertEqual(res[1].decode('utf-8'),"Bonjour Alice")

        print("Test réussi : Un message chiffré peut être échangé entre Alice et Bob après X3DH.")
