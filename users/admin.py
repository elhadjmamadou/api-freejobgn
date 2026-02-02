"""
Configuration admin pour les modèles utilisateurs.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _

from .models import (
    User,
    Skill,
    Speciality,
    ProviderProfile,
    FreelanceDetails,
    AgencyDetails,
    AgencyDocument,
    FreelanceDocument,
    ClientProfile,
    ClientIndividualDetails,
    ClientCompanyDetails,
    ClientCompanyDocument,
)


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin personnalisé pour le modèle User."""

    list_display = (
        "username",
        "email",
        "role",
        "provider_kind",
        "is_active",
        "is_staff",
        "date_joined",
    )
    list_filter = ("role", "provider_kind", "is_active", "is_staff", "date_joined")
    search_fields = ("username", "email")
    ordering = ("-date_joined",)

    fieldsets = (
        (None, {"fields": ("username", "password")}),
        (_("Informations personnelles"), {"fields": ("email",)}),
        (_("Rôle"), {"fields": ("role", "provider_kind")}),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        (_("Dates importantes"), {"fields": ("last_login", "date_joined")}),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "username",
                    "email",
                    "password1",
                    "password2",
                    "role",
                    "provider_kind",
                ),
            },
        ),
    )


@admin.register(Skill)
class SkillAdmin(admin.ModelAdmin):
    list_display = ("name", "is_active", "created_at")
    list_filter = ("is_active",)
    search_fields = ("name",)
    ordering = ("name",)


@admin.register(Speciality)
class SpecialityAdmin(admin.ModelAdmin):
    list_display = ("name", "is_active", "created_at")
    list_filter = ("is_active",)
    search_fields = ("name", "description")
    filter_horizontal = ("skills",)
    ordering = ("name",)


class FreelanceDetailsInline(admin.StackedInline):
    model = FreelanceDetails
    can_delete = False
    extra = 0


class AgencyDetailsInline(admin.StackedInline):
    model = AgencyDetails
    can_delete = False
    extra = 0


class FreelanceDocumentInline(admin.TabularInline):
    model = FreelanceDocument
    extra = 0


@admin.register(ProviderProfile)
class ProviderProfileAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "country",
        "city_or_region",
        "hourly_rate",
        "speciality",
        "created_at",
    )
    list_filter = ("country", "speciality")
    search_fields = ("user__username", "user__email", "city_or_region")
    raw_id_fields = ("user", "speciality")
    filter_horizontal = ("skills",)
    inlines = [FreelanceDetailsInline, AgencyDetailsInline, FreelanceDocumentInline]


@admin.register(FreelanceDetails)
class FreelanceDetailsAdmin(admin.ModelAdmin):
    list_display = ("provider_profile", "first_name", "last_name", "business_name")
    search_fields = ("first_name", "last_name", "business_name")
    raw_id_fields = ("provider_profile",)


class AgencyDocumentInline(admin.TabularInline):
    model = AgencyDocument
    extra = 0


@admin.register(AgencyDetails)
class AgencyDetailsAdmin(admin.ModelAdmin):
    list_display = ("agency_name", "provider_profile", "founded_at")
    search_fields = ("agency_name",)
    raw_id_fields = ("provider_profile",)
    inlines = [AgencyDocumentInline]


class ClientIndividualDetailsInline(admin.StackedInline):
    model = ClientIndividualDetails
    can_delete = False
    extra = 0


class ClientCompanyDetailsInline(admin.StackedInline):
    model = ClientCompanyDetails
    can_delete = False
    extra = 0


@admin.register(ClientProfile)
class ClientProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "client_type", "country", "city_or_region", "created_at")
    list_filter = ("client_type", "country")
    search_fields = ("user__username", "user__email", "city_or_region")
    raw_id_fields = ("user",)
    inlines = [ClientIndividualDetailsInline, ClientCompanyDetailsInline]


@admin.register(ClientIndividualDetails)
class ClientIndividualDetailsAdmin(admin.ModelAdmin):
    list_display = ("client_profile", "first_name", "last_name")
    search_fields = ("first_name", "last_name")
    raw_id_fields = ("client_profile",)


class ClientCompanyDocumentInline(admin.TabularInline):
    model = ClientCompanyDocument
    extra = 0


@admin.register(ClientCompanyDetails)
class ClientCompanyDetailsAdmin(admin.ModelAdmin):
    list_display = ("company_name", "client_profile")
    search_fields = ("company_name",)
    raw_id_fields = ("client_profile",)
    inlines = [ClientCompanyDocumentInline]
