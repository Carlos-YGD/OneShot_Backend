from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, UserStats


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


admin.site.register(User, UserAdmin)
admin.site.register(UserStats)
