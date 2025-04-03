from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from chat.models import UserKeys
from chat.models import User
from chat.models import X3DHExchange
from chat.serializers import UserKeysSerializer
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from rest_framework.decorators import api_view
from chat.crypto import perform_x3dh, serialize, ENCRYPT_X3DH
from django.views.decorators.csrf import csrf_exempt
import json
import base64

class GetPreKeyBundle(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, username):
        user = get_object_or_404(User, username=username)
        user_keys = get_object_or_404(UserKeys, user=user)
        serializer = UserKeysSerializer(user_keys)
        return Response(serializer.data)

def get_user_bundle(request, username):
    """Retourne le bundle de clés d'un utilisateur"""
    user_keys = get_object_or_404(UserKeys, user__username=username)
    return JsonResponse({
        "username": username,
        "ik_public": user_keys.ik_public,
        "sik_public":user_keys.sik_public,
        "spk_public": user_keys.spk_public,
        "spk_signature": user_keys.spk_signature,
    })


@csrf_exempt
def x3dh_message(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)

            sender = User.objects.get(username=data["from"])
            recipient = User.objects.get(username=data["username"])

            ik = base64.b64decode(data["ik"])
            epk = base64.b64decode(data["epk"])
            cipher_text = base64.b64decode(data["cipher"])
            hmac = base64.b64decode(data["hmac"])

            X3DHExchange.objects.create(
                sender=sender, 
                recipient=recipient, 
                ik=ik, 
                epk=epk, 
                cipher_text=cipher_text, 
                hmac=hmac
            )

            return JsonResponse({"status": "success"}, status=200)
        
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    
    return JsonResponse({"error": "Invalid request"}, status=405)

@api_view(['POST'])
def send_x3dh_message(request):
    """
    Vue Django pour envoyer un message en utilisant X3DH.
    """
    sender = request.user  # L'utilisateur qui envoie le message
    receiver_username = request.data.get("username")
    message = request.data.get("message", "##CHAT_START##")

    try:
        receiver = User.objects.get(username=receiver_username)
    except User.DoesNotExist:
        return Response({"error": "Utilisateur non trouvé"}, status=404)

    # Récupérer les clés du destinataire
    receiver_keys = receiver.keys

    # Exécuter X3DH pour établir une clé de session
    session = perform_x3dh(sender, receiver_keys)

    if not session:
        return Response({"error": "Échec de l'échange de clés"}, status=400)

    # Chiffrement du message
    ciphertext, hmac = ENCRYPT_X3DH(session["sk"], message.encode('utf-8'), session["ad"].encode('utf-8'))

    # Simuler l'envoi du message via Django Channels (WebSockets)
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync

    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f"user_{receiver.id}",  # Identifiant unique du destinataire
        {
            "type": "chat.message",
            "message": serialize(ciphertext),
            "hmac": serialize(hmac),
            "sender": sender.username,
        }
    )

    return Response({"success": "Message envoyé avec succès"})

