from datetime import timezone
from django.contrib.auth import get_user_model
from django.db import models

User = get_user_model()

class OTPVerification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=10)  # Adjust the max length as needed
    # Other fields if necessary
