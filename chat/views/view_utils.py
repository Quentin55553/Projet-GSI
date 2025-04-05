#------------------------------------------------------------------------------------------ Imports

from chat.models import UserKeys
from chat.models import User
from chat.models import X3DH_Message
from chat.models import Ratchet_Message
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

#-------------------------------------------------------------------------------------------------- Server functions

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


###########################################
############### MESSAGES X3DH ############# 
###########################################

@csrf_exempt
def x3dh_message(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)

            username = data.get("username")
            sender = data.get("from")
            ik = data.get("ik")
            epk = data.get("epk")
            cipher = data.get("cipher")
            hmac = data.get("hmac")

            if not all([username, sender, ik, epk, cipher, hmac]):
                return JsonResponse({"error": "Missing parameters"}, status=400)

            #print(f"SERVEUR : Message X3DH envoyé de {sender} pour {username}")

            receiver = User.objects.get(username=username)

            X3DH_Message.objects.create(
                receiver=receiver,
                sender=sender,
                ik=ik,
                epk=epk,
                cipher=cipher,
                hmac=hmac
            )

            #print(f"SERVEUR : Message X3DH stocké de {sender} pour {username}")

            return JsonResponse({"status": "Message X3DH relayé avec succès"}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

    return JsonResponse({"error": "Invalid request method"}, status=405)

def get_x3dh_message(username: str):
    """Récupère le message X3DH stocké pour Bob"""
    try:
        msg = X3DH_Message.objects.get(receiver__username=username)
        return {
            "username": username,
            "from": msg.sender,
            "ik": msg.ik,
            "epk": msg.epk,
            "cipher": msg.cipher,
            "hmac": msg.hmac
        }
    except X3DH_Message.DoesNotExist:
        return None
    
###########################################
######### MESSAGES DOUBLE RATCHET ######### 
###########################################

@csrf_exempt
def ratchet_message(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)

            username = data.get("username")
            sender = data.get("from")
            header = data.get("header")
            cipher = data.get("cipher")
            hmac = data.get("hmac")

            if not all([username, sender, header, cipher, hmac]):
                return JsonResponse({"error": "Missing parameters"}, status=400)

            #print(f"SERVEUR : Message ratchet envoyé de {sender} pour {username}")

            receiver = User.objects.get(username=username)

            Ratchet_Message.objects.create(
                receiver=receiver,
                sender=sender,
                header=header,
                cipher=cipher,
                hmac=hmac
            )

            #print(f"SERVEUR : Message ratchet stocké de {sender} pour {username}")

            return JsonResponse({"status": "Message ratchet relayé avec succès"}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

    return JsonResponse({"error": "Invalid request method"}, status=405)

def get_ratchet_message(username: str):
    """Récupère le message double ratchet stocké pour Bob"""
    try:
        msg = Ratchet_Message.objects.get(receiver__username=username)
        return {
            "username": username,
            "from": msg.sender,
            "header": msg.header,
            "cipher": msg.cipher,
            "hmac": msg.hmac
        }
    except Ratchet_Message.DoesNotExist:
        return None

