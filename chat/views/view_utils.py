from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from chat.models import UserKeys
from chat.models import User
from chat.serializers import UserKeysSerializer
from django.shortcuts import get_object_or_404
from django.http import JsonResponse

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
        "spk_public": user_keys.spk_public,
        "spk_signature": user_keys.spk_signature,
    })
