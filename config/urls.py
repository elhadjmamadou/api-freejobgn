from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenVerifyView
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
    SpectacularRedocView,
)
from rest_framework.authentication import BasicAuthentication, SessionAuthentication

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from config.permissions import IsSuperUser

# Configuration commune pour les vues de documentation (superuser only)
docs_auth_classes = [BasicAuthentication, SessionAuthentication]
docs_permission_classes = [IsSuperUser]

urlpatterns = [
    path("admin/", admin.site.urls),
    # API Auth endpoints
    path("api/auth/", include("users.urls", namespace="users")),
    # OpenAPI schema (sécurisé - superuser only)
    path(
        "api/schema/",
        SpectacularAPIView.as_view(
            authentication_classes=docs_auth_classes,
            permission_classes=docs_permission_classes,
        ),
        name="schema",
    ),
    # Swagger UI (sécurisé - superuser only)
    path(
        "",
        SpectacularSwaggerView.as_view(
            url_name="schema",
            authentication_classes=docs_auth_classes,
            permission_classes=docs_permission_classes,
        ),
        name="swagger-ui",
    ),
    # Redoc (sécurisé - superuser only)
    path(
        "api/redoc/",
        SpectacularRedocView.as_view(
            url_name="schema",
            authentication_classes=docs_auth_classes,
            permission_classes=docs_permission_classes,
        ),
        name="redoc",
    ),

    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
]

# Servir les fichiers media en développement
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
