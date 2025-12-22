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
    UserStatsResetView,
    refresh_access_token,
    AdminCheckView,
    UserStatsUpdateView
)

urlpatterns = [
    path("", UserListView.as_view(), name="user-list"),
    path("<int:pk>/", UserDetailView.as_view(), name="user-detail"),
    path("admin-check/", AdminCheckView.as_view(), name="admin-check"),
    path("profile/", ProfileView.as_view(), name="profile"),
    path("profile/edit/", ProfileEditView.as_view(), name="profile-edit"),
    path("stats/", UserStatsView.as_view(), name="user-stats"),
    path("stats/reset/", UserStatsResetView.as_view(), name="user-stats-reset"),
    path("stats/update/", UserStatsUpdateView.as_view(), name="user-stats-update"),
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", logout_view, name="logout"),
    path("delete/", delete_own_account, name="delete-own-account"),
    path("refresh/", refresh_access_token, name="token_refresh"),
]
