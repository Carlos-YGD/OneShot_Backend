from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import User, UserStats, username_validator, email_validator


class UserStatsSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserStats
        exclude = ("user",)


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, required=True, style={"input_type": "password"}
    )
    username = serializers.CharField(validators=[username_validator])
    email = serializers.EmailField(validators=[email_validator])

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
        user = User(email=validated_data["email"], username=validated_data["username"])
        user.set_password(validated_data["password"])
        user.full_clean()
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, style={"input_type": "password"})


class UserSerializer(serializers.ModelSerializer):
    stats = UserStatsSerializer(read_only=True)

    class Meta:
        model = User
        fields = ["id", "email", "username", "created_at", "stats"]


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    username = serializers.CharField(validators=[username_validator])

    class Meta:
        model = User
        fields = ["username"]


class AdminUserSerializer(serializers.ModelSerializer):
    stats = UserStatsSerializer(source="userstats")

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "username",
            "is_active",
            "is_admin",
            "is_staff",
            "stats",
        ]
        read_only_fields = ("id", "created_at")

    def update(self, instance, validated_data):
        stats_data = validated_data.pop("userstats", None)
        instance = super().update(instance, validated_data)

        if stats_data:
            stats = instance.userstats
            for field, value in stats_data.items():
                setattr(stats, field, value)
            stats.save()

        return instance
