from django.contrib import admin
from chat.views import *
from django.urls import path
from django.conf import settings
from django.contrib.staticfiles.urls import static
from chat.views.view_utils import get_user_bundle
from chat.views.view_utils import x3dh_message
from chat.views.view_utils import message

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", LoginPage, name="login"),
    path("signup/", SignupPage, name="signup"),
    path("logout/", LogoutPage, name="logout"),
    path("user/", HomePage, name="home"),
    path("edit/", EditProfile, name="edit"),
    path("user/<str:username>/", userprofile, name="username"),
    path("add_friend/", add_friend, name="add_friend"),
    path("accept_request/", accept_request, name="accept_request"),
    path("delete_friend/", delete_friend, name="delete_friend"),
    path("search/", search, name="search"),
    path("chat/<str:username>/", chat, name="chat"),
    path('api/user_bundle/<str:username>/', get_user_bundle, name="get_user_bundle"),
    path("x3dh_message/", x3dh_message, name="x3dh_message"),
    path("message/", message, name="message"),
]


if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
