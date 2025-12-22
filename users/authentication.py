from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed


class CookieJWTAuthentication(JWTAuthentication):

    def authenticate(self, request):
        raw_token = request.COOKIES.get("access_token")
        if not raw_token:
            return None
        try:
            validated_token = self.get_validated_token(raw_token)
        except Exception:
            return None
        user = self.get_user(validated_token)

        if not user.is_active:
            raise AuthenticationFailed("Account disabled")

        return (user, validated_token)
