from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, UserStats


class UserStatsInline(admin.StackedInline):
    model = UserStats
    can_delete = False
    readonly_fields = ("updated_at",)
    fk_name = "user"


class UserAdmin(BaseUserAdmin):
    list_display = ("email", "username", "is_staff", "is_admin", "is_active")
    search_fields = ("email", "username")
    ordering = ("email",)

    readonly_fields = ("created_at", "last_login_at")

    fieldsets = (
        (None, {"fields": ("email", "username", "password")}),
        ("Permissions", {"fields": ("is_admin", "is_staff", "is_active", "is_superuser")}),
        ("Important Dates", {"fields": ("last_login_at", "created_at")}),
        ("Security", {"fields": ("failed_logins", "locked_until")}),
    )

    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "username", "password1", "password2")
        }),
    )

    inlines = (UserStatsInline,)


@admin.register(UserStats)
class UserStatsAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "total_games_played",
        "versus_games_played",
        "arcade_games_played",
        "updated_at",
    )

    search_fields = ("user__email", "user__username")

    readonly_fields = ("user", "updated_at")

    fieldsets = (
        ("User", {"fields": ("user",)}),
        ("Versus Mode Stats", {
            "fields": (
                "p1_wins", "p1_losses",
                "p2_wins", "p2_losses",
                "draws",
                "versus_games_played",
            )
        }),
        ("Arcade Mode Stats", {
            "fields": (
                "arcade_kills",
                "arcade_losses",
                "arcade_victories",
                "arcade_games_played",
            )
        }),
        ("Global Stats", {
            "fields": ("total_games_played", "updated_at")
        }),
    )


admin.site.register(User, UserAdmin)
