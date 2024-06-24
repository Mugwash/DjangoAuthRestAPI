import random
from tokenize import TokenError
from django.shortcuts import redirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from django.core.mail import send_mail
from Auth.models import *
from Auth.models import OTPVerification


class TokenObtainPairView(APIView):
    def post(self, request):
        username = request.data.get('email')
        password = request.data.get('password')

        # If authentication is successful, generate access and refresh tokens
        user = User.objects.get(username=username)
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        return Response({'access_token': access_token})

class TokenRefreshView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get('refresh_token')

        # Perform token validation here (e.g., check if refresh token is valid)

        # If token is valid, generate a new access token
        refresh = RefreshToken(refresh_token)
        access_token = str(refresh.access_token)

        return Response({'access_token': access_token})
    

class RegisterView(APIView):
    def post(self, request):
        # Get user data from request
        email = request.data.get('email')
        password = request.data.get('password')

        # Create user
        if User.objects.filter(username=email).exists():
            return Response({'message': 'User already exists'}, status=400)
        else:
            user = User.objects.create_user(username=email, password=password)

        return Response({'message': 'User created successfully'})
    
class OTPVerificationView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            otp = random.randint(100000, 999999)
            user = request.user
            email = user.username
            try:
                otp_instance, created = OTPVerification.objects.get_or_create(user=user)
                otp_instance.otp = otp
                otp_instance.is_verified = False
                otp_instance.save()
                # Other logic
            except Exception as e:
                print(f"Error creating OTPVerification: {e}")
            send_mail(
                "Welcome to MugStudios",
                "Your OTP is: " + str(otp),
                "do_not_reply@mugstudios.co.uk",
                [email],
                fail_silently=False,
            )
            return Response({'message': 'OTP sent successfully'})
        except Exception as e:
            return Response({'message': 'Failed to send OTP'}, status=500)
        

class OTPVerificationConfirmView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user = request.user
        otp = request.data.get('otp')
        otp_obj = OTPVerification.objects.get(user=user, otp=otp)
        if otp_obj:
            otp_obj.delete()
            return Response({'message': 'OTP verified successfully'})
        else:
            return Response({'message': 'Invalid OTP'}, status=400)

class BlacklistRefreshView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        refresh_token = request.data.get('refresh')
        token = RefreshToken(refresh_token)
        try:
            token.blacklist()
            return Response({"message": "Token blacklisted successfully"})
        except TokenError:
            return Response({"message": "Token is invalid or expired"}, status=400)

class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = User.objects.get(username=email)
        if user.check_password(password):
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            return Response({'access_token': access_token, 'refresh_token': str(refresh)})
        else:
            return Response({'message': 'Invalid credentials'}, status=400)
        
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user = request.user
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        if user.check_password(old_password):
            user.set_password(new_password)
            user.save()
            return Response({'message': 'Password changed successfully'})
        else:
            return Response({'message': 'Invalid password'}, status=400)