from django.urls import re_path, include, path
from django.views.generic import TemplateView
from rest_auth.views import (
    LoginView, LogoutView, RegisterView, UserDetailsView, PasswordChangeView, VerifyEmailView,
    PasswordResetView, PasswordResetConfirmView
)

urlpatterns = [
    # URLs that do not require a session or valid token
    re_path(r'^password/reset/$', PasswordResetView.as_view(),
        name='rest_password_reset'),
    re_path(r'^password/reset/confirm/$', PasswordResetConfirmView.as_view(),
        name='rest_password_reset_confirm'),
    re_path(r'^login/$', LoginView.as_view(), name='rest_login'),
    # URLs that require a user to be logged in with a valid session / token.
    re_path(r'^logout/$', LogoutView.as_view(), name='rest_logout'),
    re_path(r'^user/$', UserDetailsView.as_view(), name='rest_user_details'),
    re_path(r'^password/change/$', PasswordChangeView.as_view(),
        name='rest_password_change'),
    re_path(r'^register/$', RegisterView.as_view(), name='rest_register'),
    re_path(r'^verify-email/$', VerifyEmailView.as_view(), name='rest_verify_email'),
    re_path(r'^account-confirm-email/(?P<key>[-:\w]+)/$', TemplateView.as_view(),
        name='account_confirm_email'),
]
