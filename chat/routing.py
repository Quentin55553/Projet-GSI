from django.urls import path
from django.urls import re_path
from .consumers import ChatConsumer
from . import consumers

websocket_urlpatterns = [
    path('ws/chat/<str:room_name>/', consumers.ChatConsumer.as_asgi()),
    #re_path(r"ws/chat/$", ChatConsumer.as_asgi()),
]