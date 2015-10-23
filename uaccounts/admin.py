from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin

from uaccounts.models import (EmailAddress,
                              VerificationCode, Avatar, UserProfile)


admin.site.register(EmailAddress)
admin.site.register(VerificationCode)
admin.site.register(Avatar)

User = get_user_model()

admin.site.unregister(User)


class UserProfileInline(admin.StackedInline):
    model = UserProfile
    max_num = 1
    can_delete = False


@admin.register(User)
class UserProfileAdmin(UserAdmin):
    inlines = [UserProfileInline]
