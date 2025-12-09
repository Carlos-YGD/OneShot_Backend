from django.urls import path
from .views import (
    UserListView,
    ProfileView,
    RegisterView,
    LoginView,
    UserDetailView,
    logout_view,
    delete_own_account,
    UserStatsView,
    ProfileEditView,
    UserStatsResetView
)

urlpatterns = [
    path("", UserListView.as_view(), name="user-list"),
    path("<int:pk>/", UserDetailView.as_view(), name="user-detail"),
    path("profile/", ProfileView.as_view(), name="profile"),
    path("profile/edit/", ProfileEditView.as_view(), name="profile-edit"),
    path("stats/", UserStatsView.as_view(), name="user-stats"),
    path("stats/reset/", UserStatsResetView.as_view(), name="user-stats-reset"),
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", logout_view, name="logout"),
    path("delete/", delete_own_account, name="delete-own-account"),
]
