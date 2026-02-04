"""
URLs pour l'authentification.
"""

from django.urls import path

from .views import (
    RegisterView,
    ActivateView,
    ResendActivationView,
    LoginView,
    TokenRefreshView,
    LogoutView,
    MeView,
    RegistrationOptionsView,
    PublicStatsView,
    ClientProfileMeView,
    ClientProfileMeView,
    ClientCompanyDocumentListCreateView,
    ClientCompanyDocumentDetailView,
)

from .views import (
    FreelanceProfileInitView,
    FreelanceMeProfileView,
    FreelancePublicListView,
    FreelancePublicDetailView,
)

from .views import (
    FreelanceDocumentListCreateView,
    FreelanceDocumentDetailView,
)


from .views import (
    AgencyProfileInitView,
    AgencyMeProfileView,
    AgencyPublicListView,
    AgencyPublicDetailView,
    AgencyDocumentListCreateView,
    AgencyDocumentDetailView,
)

app_name = "users"

urlpatterns = [
    # Métadonnées publiques (stateless)
    path(
        "register/options/", RegistrationOptionsView.as_view(), name="register-options"
    ),
    path("public/stats/", PublicStatsView.as_view(), name="public-stats"),
    # Inscription et activation
    path("register/", RegisterView.as_view(), name="register"),
    path("activate/", ActivateView.as_view(), name="activate"),
    path(
        "resend-activation/", ResendActivationView.as_view(), name="resend-activation"
    ),
    # Authentification
    path("login/", LoginView.as_view(), name="login"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),
    # Utilisateur courant
    path("me/", MeView.as_view(), name="me"),
    
    # API Client Profile endpoint
    path("client/profile/", ClientProfileMeView.as_view(), name="client-profile"),
    # API Client Company Documents endpoints
    path(
        "client/company/documents/",
        ClientCompanyDocumentListCreateView.as_view(),
        name="client-company-documents-list",
    ),
    path(
        "client/company/documents/<int:pk>/",
        ClientCompanyDocumentDetailView.as_view(),
        name="client-company-documents-detail",
    ),

     path("freelance/profile/init/", FreelanceProfileInitView.as_view(), name="freelance-profile-init"),
    path("freelance/profile/", FreelanceMeProfileView.as_view(), name="freelance-profile-me"),

    # public
    path("freelancers/", FreelancePublicListView.as_view(), name="freelancers-public-list"),
    path("freelancers/<int:pk>/", FreelancePublicDetailView.as_view(), name="freelancers-public-detail"),

    path("freelance/documents/", FreelanceDocumentListCreateView.as_view(), name="freelance-documents"),
    path("freelance/documents/<int:pk>/", FreelanceDocumentDetailView.as_view(), name="freelance-document-detail"),

    # Agency profile
    path("agency/profile/init/", AgencyProfileInitView.as_view(), name="agency-profile-init"),
    path("agency/profile/", AgencyMeProfileView.as_view(), name="agency-profile-me"),

    # Public agencies
    path("agencies/", AgencyPublicListView.as_view(), name="agencies-public-list"),
    path("agencies/<int:pk>/", AgencyPublicDetailView.as_view(), name="agencies-public-detail"),

    # Agency documents
    path("agency/documents/", AgencyDocumentListCreateView.as_view(), name="agency-documents"),
    path("agency/documents/<int:pk>/", AgencyDocumentDetailView.as_view(), name="agency-document-detail"),

]
