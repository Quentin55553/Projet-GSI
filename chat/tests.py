from django.test import TestCase
from django.contrib.auth.models import User
from .models import UserKeys
from django.urls import reverse
import base64
from django.core.management import call_command
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import ed25519

class UserKeysTestCase(TestCase):

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
        # Étape 1 : Création des utilisateurs
        alice = User.objects.create(username="alice")
        bob = User.objects.create(username="bob")

        # Vérification que les clés sont bien créées
        self.assertIsNotNone(UserKeys.objects.get(user=alice))
        self.assertIsNotNone(UserKeys.objects.get(user=bob))

        alice_keys = UserKeys.objects.get(user=alice)
        bob_keys = UserKeys.objects.get(user=bob)    
        self.assertEqual(alice_keys.user.username, 'alice')
        self.assertEqual(bob_keys.user.username, 'bob')

        # Étape 3 : Récupération des bundles via une requête au serveur
        response_alice = self.client.get(reverse('get_user_bundle', args=["alice"]))
        response_bob = self.client.get(reverse('get_user_bundle', args=["bob"]))

        # Vérification que la requête est bien traitée (HTTP 200)
        self.assertEqual(response_alice.status_code, 200)
        self.assertEqual(response_bob.status_code, 200)

        # Vérification des données retournées
        self.assertEqual(response_alice.json()["username"], "alice")
        self.assertEqual(response_bob.json()["username"], "bob")

        print("Test réussi : les utilisateurs et leurs clés sont bien créés et récupérés par get_user_bundle.")
        