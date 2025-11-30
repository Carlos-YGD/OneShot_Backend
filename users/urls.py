from django.urls import path
from .views import RegisterView, LoginView, ProfileView, UserListView

urlpatterns = [
    path("", UserListView.as_view(), name="user-list"),
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("me/", ProfileView.as_view(), name="profile"),
]
