from rest_framework import generics, status, filters
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.decorators import api_view, permission_classes
from rest_framework.reverse import reverse
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django_filters.rest_framework import DjangoFilterBackend
from .authentication import CookieJWTAuthentication

from .models import User
from .serializers import (
    UserSerializer,
    UserStatsSerializer,
    RegisterSerializer,
    LoginSerializer,
    AdminUserSerializer,
    UserProfileUpdateSerializer,
)
from django.utils import timezone
from datetime import timedelta
from django.http import JsonResponse

MAX_FAILED_LOGINS = 5
LOCKOUT_TIME = timedelta(minutes=15)
COOKIE_DOMAIN = ".dyvr49stm9di1.cloudfront.net"  # Your CloudFront domain
COOKIE_PATH = "/"
COOKIE_MAX_AGE_ACCESS = 3600  # 1 hour
COOKIE_MAX_AGE_REFRESH = 7 * 24 * 3600  # 7 days

MAX_FAILED_LOGINS = 5
LOCKOUT_TIME = timedelta(minutes=15)


def health_check(request):
    return JsonResponse({"status": "ok"})


class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminUser]

    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["is_admin", "is_staff", "is_active"]
    search_fields = ["id", "username", "email"]
    ordering_fields = ["id", "username", "email"]
    ordering = ["id"]

    @swagger_auto_schema(
        operation_summary="List all users",
        operation_description="Returns a paginated list of all users. **Admin-only** endpoint.",
        tags=["Users"],
        responses={200: UserSerializer(many=True)},
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        return AdminUserSerializer if self.request.user.is_admin else UserSerializer

    def get_permissions(self):
        return [IsAuthenticated()]

    def get_object(self):
        return super().get_object() if self.request.user.is_admin else self.request.user

    @swagger_auto_schema(
        operation_summary="Partial update a user",
        operation_description="Partially update a specific user. **Admin-only** endpoint.",
        request_body=AdminUserSerializer,
        responses={200: AdminUserSerializer},
        tags=["Users"],
    )
    def patch(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="Retrieve a user",
        operation_description="Retrieve a specific user by their ID. **Admin-only** endpoint.",
        responses={200: AdminUserSerializer if True else UserSerializer},
        tags=["Users"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="Update a user",
        operation_description="Update a specific user's data. **Admin-only** endpoint.",
        request_body=AdminUserSerializer,
        responses={200: AdminUserSerializer},
        tags=["Users"],
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="Delete a user",
        operation_description="Delete a specific user's account. **Admin-only** endpoint.",
        responses={204: "No Content"},
        tags=["Users"],
    )
    def delete(self, request, *args, **kwargs):
        return super().delete(request, *args, **kwargs)


class AdminCheckView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Check admin and staff status",
        operation_description="Returns the admin and staff status of the authenticated user.",
        responses={200: openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "is_admin": openapi.Schema(type=openapi.TYPE_BOOLEAN),
                "is_staff": openapi.Schema(type=openapi.TYPE_BOOLEAN),
            }
        )},
        tags=["Users"],
    )
    def get(self, request):
        user = request.user
        return Response({
            "is_admin": user.is_admin,
            "is_staff": user.is_staff,
        })


class ProfileView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [CookieJWTAuthentication]

    def get_object(self):
        return self.request.user

    @swagger_auto_schema(
        operation_summary="Retrieve your profile",
        operation_description="Returns the logged-in user's profile.",
        responses={200: UserSerializer},
        tags=["Users"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class ProfileEditView(generics.UpdateAPIView):
    serializer_class = UserProfileUpdateSerializer
    permission_classes = [IsAuthenticated]
    throttle_scope = "profile_update"
    http_method_names = ["get", "patch", "head", "options"]

    def get_object(self):
        return self.request.user

    @swagger_auto_schema(
        operation_summary="Update username",
        operation_description="Allows the logged-in user to update only their username.",
        request_body=UserProfileUpdateSerializer,
        responses={200: UserProfileUpdateSerializer},
        tags=["Users"],
    )
    def patch(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]
    throttle_scope = "auth_register"

    @swagger_auto_schema(
        operation_summary="Register a new user",
        operation_description="Creates a new user account. Returns JWT tokens and sets HTTP-only cookies.",
        request_body=RegisterSerializer,
        tags=["Authentication"],
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        response = Response(
            {
                "user": UserSerializer(user).data,
            },
            status=201,
        )

        # Set cookies with proper domain/path for CloudFront
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=True,
            samesite="None",
            domain=COOKIE_DOMAIN,
            path=COOKIE_PATH,
            max_age=COOKIE_MAX_AGE_ACCESS,
        )
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite="None",
            domain=COOKIE_DOMAIN,
            path=COOKIE_PATH,
            max_age=COOKIE_MAX_AGE_REFRESH,
        )

        return response


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]
    throttle_scope = "auth_login"

    @swagger_auto_schema(
        operation_summary="User login",
        operation_description="Logs in a user and returns JWT tokens. Sets HTTP-only cookies.",
        request_body=LoginSerializer,
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "Invalid credentials"}, status=400)

        now = timezone.now()

        if user.locked_until and user.locked_until > now:
            return Response(
                {"error": f"Account temporarily locked until {user.locked_until}"},
                status=403,
            )

        user_auth = authenticate(request, email=email, password=password)
        if not user_auth:
            user.failed_logins += 1
            if user.failed_logins >= MAX_FAILED_LOGINS:
                user.locked_until = now + LOCKOUT_TIME
                user.failed_logins = 0
                user.save()
                return Response(
                    {"error": f"Account locked due to too many failed attempts. Try again at {user.locked_until}."},
                    status=403,
                )
            user.save()
            attempts_left = MAX_FAILED_LOGINS - user.failed_logins
            return Response(
                {"error": "Invalid credentials", "failed_attempts": user.failed_logins, "attempts_left": attempts_left},
                status=400,
            )

        user.failed_logins = 0
        user.locked_until = None
        user.save()

        refresh = RefreshToken.for_user(user_auth)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        response = Response(
            {
                "user": UserSerializer(user_auth).data,
            },
            status=200,
        )

        # Set cookies with proper domain/path for CloudFront
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=True,
            samesite="None",
            domain=COOKIE_DOMAIN,
            path=COOKIE_PATH,
            max_age=COOKIE_MAX_AGE_ACCESS,
        )
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite="None",
            domain=COOKIE_DOMAIN,
            path=COOKIE_PATH,
            max_age=COOKIE_MAX_AGE_REFRESH,
        )

        return response


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    refresh_token = request.COOKIES.get("refresh_token")

    if refresh_token:
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except Exception:
            pass

    response = Response({"detail": "Successfully logged out."}, status=200)

    # Delete cookies with same domain/path
    response.delete_cookie("access_token", domain=COOKIE_DOMAIN, path=COOKIE_PATH)
    response.delete_cookie("refresh_token", domain=COOKIE_DOMAIN, path=COOKIE_PATH)

    return response


@swagger_auto_schema(
    method="post",
    operation_summary="Refresh access token",
    operation_description="Uses refresh_token cookie to issue a new access token.",
    responses={200: openapi.Schema(type=openapi.TYPE_OBJECT, properties={"access": openapi.Schema(type=openapi.TYPE_STRING)})},
    tags=["Authentication"],
)
@api_view(["POST"])
@permission_classes([AllowAny])
def refresh_access_token(request):
    refresh_token = request.COOKIES.get("refresh_token")
    if not refresh_token:
        return Response({"detail": "No refresh token"}, status=401)

    try:
        token = RefreshToken(refresh_token)
        access_token = str(token.access_token)

        response = Response({"access": access_token})
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=True,
            samesite="None",
            domain=COOKIE_DOMAIN,
            path=COOKIE_PATH,
            max_age=COOKIE_MAX_AGE_ACCESS,
        )
        return response

    except TokenError:
        return Response({"detail": "Invalid refresh token"}, status=401)


class UserStatsView(generics.RetrieveAPIView):
    serializer_class = UserStatsSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user.userstats

    @swagger_auto_schema(
        operation_summary="Retrieve user stats",
        operation_description="Returns the game statistics of the logged-in user.",
        responses={200: UserStatsSerializer},
        tags=["Users"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class UserStatsResetView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user_stats = request.user.userstats
        for field in user_stats._meta.fields:
            if field.get_internal_type() in ["IntegerField", "FloatField"]:
                setattr(user_stats, field.name, 0)
        user_stats.save()
        return Response({"detail": "Your stats have been reset."}, status=status.HTTP_200_OK)


class UserStatsUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_stats = request.user.userstats
        data = request.data

        # Expected keys: winner, p1Lives, p2Lives
        winner = data.get("winner")

        # Update Versus stats
        if winner == "Player 1":
            user_stats.p1_wins += 1
            user_stats.p2_losses += 1
        elif winner == "Player 2":
            user_stats.p2_wins += 1
            user_stats.p1_losses += 1
        else:
            user_stats.draws += 1

        user_stats.versus_games_played += 1
        user_stats.total_games_played += 1
        user_stats.save()

        return Response(
            {"success": True, "stats": {
                "p1_wins": user_stats.p1_wins,
                "p1_losses": user_stats.p1_losses,
                "p2_wins": user_stats.p2_wins,
                "p2_losses": user_stats.p2_losses,
                "draws": user_stats.draws,
                "versus_games_played": user_stats.versus_games_played,
                "total_games_played": user_stats.total_games_played
            }},
            status=status.HTTP_200_OK
        )


@swagger_auto_schema(
    method="delete",
    operation_summary="Delete own account",
    operation_description="Allows a logged-in user to delete their own account. Deletes JWT cookies.",
    responses={204: "No Content"},
    tags=["Users"],
)
@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def delete_own_account(request):
    user = request.user
    user.delete()
    response = Response(
        {"detail": "Your account has been deleted."}, status=status.HTTP_204_NO_CONTENT
    )
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return response


@swagger_auto_schema(
    method="get",
    operation_summary="API root",
    operation_description="API root. Lists all available endpoints in the OneShot API for ease of access.",
    tags=["API"],
)
@api_view(["GET"])
@permission_classes([AllowAny])
def api_root(request):
    return Response(
        {
            "users": reverse("user-list", request=request),
            "profile": reverse("profile", request=request),
            "profile-edit": reverse("profile-edit", request=request),
            "user-stats": reverse("user-stats", request=request),
            "admin-check": reverse("admin-check", request=request),
            "user-stats-reset": reverse("user-stats-reset", request=request),
            "register": reverse("register", request=request),
            "login": reverse("login", request=request),
            "logout": reverse("logout", request=request),
            "delete_account": reverse("delete-own-account", request=request),
        }
    )