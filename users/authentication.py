from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response


class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            raw_token = request.COOKIES.get("access_token")
            if raw_token is None:
                return None
        else:
            raw_token = self.get_raw_token(header)

        try:
            validated_token = self.get_validated_token(raw_token)
        except Exception:
            return None

        user = self.get_user(validated_token)

        if not user.is_active:
            response = Response({"error": "Account disabled"}, status=403)
            response.delete_cookie("access_token")
            response.delete_cookie("refresh_token")
            raise AuthenticationFailed("Account disabled")

        return (user, validated_token)
