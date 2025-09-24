# users/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (RegisterView, GroupViewSet, PermissionViewSet, 
                    TwoFactorSetupView, TwoFactorVerifyView, TokenVerify2FAView,
                    TwoFactorStatusView, TwoFactorDisableView)


router = DefaultRouter()
router.register(r'groups', GroupViewSet)
router.register(r'permissions', PermissionViewSet)

urlpatterns = [
    path("register/", RegisterView.as_view(), name="auth_register"),
    # The API URLs are now determined automatically by the router.
    path("2fa/setup/", TwoFactorSetupView.as_view(), name="2fa_setup"),
    path("2fa/verify/", TwoFactorVerifyView.as_view(), name="2fa_verify"),
    path("2fa/login-verify/", TokenVerify2FAView.as_view(), name="2fa_login_verify"),
    path("2fa/status/", TwoFactorStatusView.as_view(), name="2fa_status"), # <-- Add status
    path("2fa/disable/", TwoFactorDisableView.as_view(), name="2fa_disable"),
    path('', include(router.urls)),
]