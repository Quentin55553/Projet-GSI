"""
import json
from channels.generic.websocket import AsyncWebsocketConsumer

from django.utils import timezone
from channels.db import database_sync_to_async

# Define an async function to save the message to the database
@database_sync_to_async
def save_message(sender_name, receiver_name, message):
    from django.contrib.auth.models import User
    from chat.models import Messages
    # Get User instances for sender and receiver
    sender = User.objects.get(username=sender_name)
    receiver = User.objects.get(username=receiver_name)

    # Create a new message
    new_message = Messages(
        description=message,
        sender_name=sender,
        receiver_name=receiver,
        time=timezone.now().time(),  # Store the current time
        timestamp=timezone.now(),   # Store the timestamp
        seen=True
    )
    new_message.save()
class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.room_group_name = f'chat_{self.room_name}'
        print(self.room_name, self.room_group_name)
        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    # Receive message from WebSocket
    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json['message']
        sender_name = text_data_json['sender_name']
        receiver_name = text_data_json['receiver_name']
        await save_message(sender_name, receiver_name, message)
        # Send message to room group
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': message,
                'sender': sender_name
            }
        )

    # Receive message from room group
    async def chat_message(self, event):
        message = event['message']
        sender = event['sender']

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message,
            'sender': sender
        }))
"""

import json
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth.models import User
from .models import RatchetSession, UserKeys
from .crypto import SignalUser

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope["user"]
        if self.user.is_authenticated:
            await self.accept()
        else:
            await self.close()

    async def receive(self, text_data):
        data = json.loads(text_data)
        recipient_username = data['username']
        message = data['message']

        recipient = User.objects.get(username=recipient_username)
        recipient_keys = UserKeys.objects.get(user=recipient)

        # Charger la session Double Ratchet
        sender_keys = UserKeys.objects.get(user=self.user)
        signal_user = SignalUser(self.user, sender_keys)

        ratchet_session, _ = RatchetSession.objects.get_or_create(user=self.user, peer=recipient)
        signal_user.ratchet_session[recipient_username] = ratchet_session.load_session()

        # Chiffrer le message
        encrypted_message = signal_user.encrypt_message(recipient_username, message)

        # Sauvegarder l'état du Ratchet
        ratchet_session.save_session(signal_user.ratchet_session[recipient_username])

        # Envoyer le message au destinataire
        await self.channel_layer.group_send(
            recipient_username,
            {
                "type": "chat.message",
                "sender": self.user.username,
                "message": encrypted_message
            }
        )

    async def chat_message(self, event):
        sender_username = event["sender"]
        encrypted_message = event["message"]

        sender = User.objects.get(username=sender_username)
        sender_keys = UserKeys.objects.get(user=sender)

        # Charger la session Double Ratchet
        receiver_keys = UserKeys.objects.get(user=self.user)
        signal_user = SignalUser(self.user, receiver_keys)

        ratchet_session, _ = RatchetSession.objects.get_or_create(user=self.user, peer=sender)
        signal_user.ratchet_session[sender_username] = ratchet_session.load_session()

        # Déchiffrer le message
        decrypted_message = signal_user.decrypt_message(sender_username, encrypted_message)

        # Sauvegarder l'état du Ratchet
        ratchet_session.save_session(signal_user.ratchet_session[sender_username])

        await self.send(text_data=json.dumps({
            "sender": sender_username,
            "message": decrypted_message
        }))
