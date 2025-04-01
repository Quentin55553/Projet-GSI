from django.contrib.auth.forms import UserCreationForm, User
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from .models import SecureMessage
from django.db.models import Q
from django.db import models
from django.utils.timezone import localtime
from django.utils.timezone import make_aware
from datetime import datetime

def inscription(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('connexion')  
    else:
        form = UserCreationForm()
    return render(request, 'inscription.html', {'form': form})

def accueil(request):
    return render(request, 'accueil.html')

@login_required
def tableau_de_bord(request):
    user = request.user

    messages_envoyes = SecureMessage.objects.filter(sender=user).values_list('recipient_id', flat=True)
    messages_recus = SecureMessage.objects.filter(recipient=user).values_list('sender_id', flat=True)

    utilisateurs_ids = set(messages_envoyes) | set(messages_recus)
    utilisateurs = User.objects.filter(id__in=utilisateurs_ids).exclude(id=user.id)

    utilisateurs = list(utilisateurs)
    for u in utilisateurs:
        last_msg = SecureMessage.objects.filter(
            Q(sender=user, recipient=u) | Q(sender=u, recipient=user)
        ).order_by('-timestamp').first()
        u.last_message = last_msg

    utilisateurs.sort(
        key=lambda u: u.last_message.timestamp if u.last_message else timezone.make_aware(datetime.min),
        reverse=True
    )

    nouveaux_utilisateurs = User.objects.exclude(id__in=utilisateurs_ids).exclude(id=user.id)

    return render(request, 'messagerie.html', {
        'utilisateurs': utilisateurs,
        'nouveaux_utilisateurs': nouveaux_utilisateurs,
        'messages': [],
        'destinataire': None,
        'user': user
    })

@login_required
def send_secure_message(request):
    if request.method == 'POST':
        recipient_username = request.POST.get('recipient')
        content = request.POST.get('content')
        recipient = get_object_or_404(User, username=recipient_username)

        SecureMessage.objects.create(
            sender=request.user,
            recipient=recipient,
            encrypted_content=content,  
            timestamp=timezone.now()
        )
        return redirect('message_envoye')

    users = User.objects.exclude(id=request.user.id)
    return render(request, 'send_message2.html', {'users': users})


@login_required
def conversation(request, user_id=None):
    user = request.user

    messages_envoyes = SecureMessage.objects.filter(sender=user).values_list('recipient_id', flat=True)
    messages_recus = SecureMessage.objects.filter(recipient=user).values_list('sender_id', flat=True)
    utilisateurs_ids = set(messages_envoyes) | set(messages_recus)

    utilisateurs = User.objects.filter(id__in=utilisateurs_ids).exclude(id=user.id)

    destinataire = get_object_or_404(User, id=user_id)

    if request.method == 'POST':
        content = request.POST.get('content')
        if content:
            SecureMessage.objects.create(
                sender=user,
                recipient=destinataire,
                encrypted_content=content,
                timestamp=timezone.now()
            )
            return redirect('conversation', user_id=destinataire.id)

    messages = SecureMessage.objects.filter(
        Q(sender=user, recipient=destinataire) |
        Q(sender=destinataire, recipient=user)
    ).order_by('timestamp')

    utilisateurs = list(utilisateurs)
    for u in utilisateurs:
        last_msg = SecureMessage.objects.filter(
            Q(sender=user, recipient=u) | Q(sender=u, recipient=user)
        ).order_by('-timestamp').first()
        u.last_message = last_msg

    utilisateurs.sort(
        key=lambda u: u.last_message.timestamp if u.last_message else timezone.make_aware(datetime.min),
        reverse=True
    )

    if destinataire not in utilisateurs:
        utilisateurs.append(destinataire)

    last_msg = SecureMessage.objects.filter(
        Q(sender=user, recipient=destinataire) | Q(sender=destinataire, recipient=user)
    ).order_by('-timestamp').first()
    destinataire.last_message = last_msg

    nouveaux_utilisateurs = User.objects.exclude(id__in=utilisateurs_ids).exclude(id=user.id)

    return render(request, 'messagerie.html', {
        'utilisateurs': utilisateurs,
        'nouveaux_utilisateurs': nouveaux_utilisateurs,
        'messages': messages,
        'destinataire': destinataire,
        'user': user
    })


@login_required
@login_required
def messagerie(request, user_id=None):
    user = request.user

    utilisateurs = User.objects.filter(
        Q(sent_messages__recipient=user) | Q(received_messages__sender=user)
    ).exclude(id=user.id).distinct()

    utilisateurs_data = []

    if user_id:
        destinataire = get_object_or_404(User, id=user_id)
        if destinataire not in utilisateurs:
            utilisateurs = list(utilisateurs) + [destinataire]
    else:
        destinataire = None

    for u in utilisateurs:
        last_msg = SecureMessage.objects.filter(
            Q(sender=user, recipient=u) | Q(sender=u, recipient=user)
        ).order_by('-timestamp').first()

        if last_msg:
            time = localtime(last_msg.timestamp).strftime('%H:%M %d/%m')
            utilisateurs_data.append({
                'id': u.id,
                'username': u.username,
                'last_message': last_msg.encrypted_content,
                'last_time': time,
            })
        elif user_id and u.id == int(user_id):
            utilisateurs_data.append({
                'id': u.id,
                'username': u.username,
                'last_message': 'Aucun message',
                'last_time': '',
            })

    messages = []
    if destinataire:
        messages = SecureMessage.objects.filter(
            Q(sender=user, recipient=destinataire) |
            Q(sender=destinataire, recipient=user)
        ).order_by('timestamp')

    return render(request, 'messagerie.html', {
        'utilisateurs': utilisateurs_data,
        'destinataire': destinataire,
        'messages': messages,
        'user': user
    })