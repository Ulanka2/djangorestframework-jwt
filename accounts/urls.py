from django.urls import path
from .views import UserCreateView, EmailVerificationView, LoginView


urlpatterns = [

    path('sign-in/', UserCreateView.as_view(), name='sign-in'),
    path('email-verify', EmailVerificationView.as_view(), name='email-verify'),
    path('login', LoginView.as_view(), name='login'),


]