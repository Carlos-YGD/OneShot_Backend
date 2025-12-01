from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view, permission_classes
from rest_framework.reverse import reverse
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import User
from .serializers import (
    UserSerializer,
    UserStatsSerializer,
    RegisterSerializer,
    LoginSerializer,
    AdminUserSerializer,
    UserProfileUpdateSerializer
)


class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="List all users",
        operation_description="Returns a list of all users. **Admin-only** endpoint.",
        tags=["Users"],
        responses={200: UserSerializer(many=True)}
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
        tags=["Users"]
    )
    def patch(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="Retrieve a user",
        operation_description="Retrieve a specific user by their ID. **Admin-only** endpoint.",
        responses={200: AdminUserSerializer if True else UserSerializer},
        tags=["Users"]
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="Update a user",
        operation_description="Update a specific user's data. **Admin-only** endpoint.",
        request_body=AdminUserSerializer,
        responses={200: AdminUserSerializer},
        tags=["Users"]
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="Delete a user",
        operation_description="Delete a specific user's account. **Admin-only** endpoint.",
        responses={204: "No Content"},
        tags=["Users"]
    )
    def delete(self, request, *args, **kwargs):
        return super().delete(request, *args, **kwargs)


class ProfileView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    @swagger_auto_schema(
        operation_summary="Retrieve your profile",
        operation_description="Returns the logged-in user's profile.",
        responses={200: UserSerializer},
        tags=["Users"]
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class ProfileEditView(generics.UpdateAPIView):
    serializer_class = UserProfileUpdateSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ['get', 'patch', 'head', 'options']

    def get_object(self):
        return self.request.user

    @swagger_auto_schema(
        operation_summary="Update username",
        operation_description="Allows the logged-in user to update only their username.",
        request_body=UserProfileUpdateSerializer,
        responses={200: UserProfileUpdateSerializer},
        tags=["Users"]
    )
    def patch(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Register a new user",
        operation_description="Creates a new user account. Returns JWT tokens and sets HTTP-only cookies.",
        request_body=RegisterSerializer,
        tags=["Authentication"]
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        refresh = RefreshToken.for_user(user)

        response = Response({
            "user": UserSerializer(user).data,
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }, status=201)

        cookie_max_age = 3600
        response.set_cookie(
            key="access_token",
            value=str(refresh.access_token),
            httponly=True,
            max_age=cookie_max_age,
            samesite="Lax",
        )
        response.set_cookie(
            key="refresh_token",
            value=str(refresh),
            httponly=True,
            max_age=7*24*3600,
            samesite="Lax",
        )

        return response


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="User login",
        operation_description="Logs in a user and returns JWT tokens. Sets HTTP-only cookies.",
        request_body=LoginSerializer,
        tags=["Authentication"]
    )
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        user = authenticate(request, email=email, password=password)
        if not user:
            return Response({"error": "Invalid credentials"}, status=400)

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        response = Response({
            "user": UserSerializer(user).data,
            "refresh": refresh_token,
            "access": access_token,
        }, status=200)

        cookie_max_age = 3600
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            max_age=cookie_max_age,
            samesite="Lax",
        )
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            max_age=7*24*3600,
            samesite="Lax",
        )

        return response


@swagger_auto_schema(
    method='post',
    operation_summary="Logout",
    operation_description="Logs out the user by deleting JWT cookies.",
    responses={200: openapi.Schema(type=openapi.TYPE_OBJECT, properties={"detail": openapi.Schema(type=openapi.TYPE_STRING)})},
    tags=["Authentication"]
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    response = Response({"detail": "Successfully logged out."}, status=200)
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')
    return response


class UserStatsView(generics.RetrieveAPIView):
    serializer_class = UserStatsSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user.userstats

    @swagger_auto_schema(
        operation_summary="Retrieve user stats",
        operation_description="Returns the game statistics of the logged-in user.",
        responses={200: UserStatsSerializer},
        tags=["Users"]
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


@swagger_auto_schema(
    method='delete',
    operation_summary="Delete own account",
    operation_description="Allows a logged-in user to delete their own account. Deletes JWT cookies.",
    responses={204: "No Content"},
    tags=["Users"]
)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_own_account(request):
    user = request.user
    user.delete()
    response = Response({"detail": "Your account has been deleted."}, status=status.HTTP_204_NO_CONTENT)
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return response


@swagger_auto_schema(
    method='get',
    operation_summary="API root",
    operation_description="API root. Lists all available endpoints in the OneShot API for ease of access.",
    tags=["API"]
)
@api_view(['GET'])
@permission_classes([AllowAny])
def api_root(request):
    return Response({
        'users': reverse('user-list', request=request),
        'profile': reverse('profile', request=request),
        'profile-edit': reverse('profile-edit', request=request),
        'user-stats': reverse('user-stats', request=request),
        'register': reverse('register', request=request),
        'login': reverse('login', request=request),
        'logout': reverse('logout', request=request),
        'delete_account': reverse('delete-own-account', request=request),
    })
