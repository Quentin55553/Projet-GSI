from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from django.shortcuts import render

urlpatterns = [
    path('', views.accueil, name='accueil'),
    path('inscription/', views.inscription, name='inscription'),
    path('connexion/', auth_views.LoginView.as_view(template_name='connexion.html'), name='connexion'),
    path('deconnexion/', auth_views.LogoutView.as_view(next_page='accueil'), name='deconnexion'),
    path('dashboard/', views.tableau_de_bord, name='dashboard'),
    path('envoyer/', views.send_secure_message, name='envoyer_message'),
    path('envoye/', lambda request: render(request, 'message_sent.html'), name='message_envoye'),
    path('dashboard/<int:user_id>/', views.tableau_de_bord, name='discussion'),
    path('conversation/<int:user_id>/', views.conversation, name='conversation'),
]
