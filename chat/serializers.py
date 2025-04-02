from .models import Messages
from django.contrib.auth.models import User
from rest_framework import serializers
from .models import UserKeys

class UserKeysSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserKeys
        fields = ['user', 'ik_public', 'spk_public', 'spk_signature']


class MessageSerializer(serializers.ModelSerializer):

    sender_name = serializers.SlugRelatedField(many=False, slug_field='username', queryset=User.objects.all())
    receiver_name = serializers.SlugRelatedField(many=False, slug_field='username', queryset=User.objects.all())

    class Meta:
        model = Messages
        fields = ['sender_name', 'receiver_name', 'description', 'time']
