from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import User, UserStats


class UserStatsSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserStats
        fields = "__all__"


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"}
    )

    class Meta:
        model = User
        fields = ["email", "username", "password"]

    def validate_password(self, password):
        try:
            validate_password(password)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return password

    def create(self, validated_data):
        user = User(
            email=validated_data["email"],
            username=validated_data["username"]
        )
        user.set_password(validated_data["password"])
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"}
    )


class UserSerializer(serializers.ModelSerializer):
    stats = UserStatsSerializer(read_only=True)

    class Meta:
        model = User
        fields = ["id", "email", "username", "is_active", "created_at", "stats"]
        read_only_fields = ("id", "created_at")
