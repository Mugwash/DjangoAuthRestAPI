from django.urls import include, path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from . import views

urlpatterns = [
    #Authentication
    path('token/', views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('logout/', views.BlacklistRefreshView.as_view(), name='logout'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('otp-verification/', views.OTPVerificationView.as_view(), name='otp_verification'),
    path('otp-confirm/', views.OTPVerificationConfirmView.as_view(), name='otp_verification'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change_password'),
]