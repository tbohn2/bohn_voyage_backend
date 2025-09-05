from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from django.conf import settings
from itsdangerous import URLSafeTimedSerializer
from rest_framework_simplejwt.tokens import AccessToken
from ..models import Customer
import time

JWT_SECRET = settings.SECRET_KEY  
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 15  
BASE_URL = settings.FRONTEND_URL

def create_magic_link(email: str) -> str:    
    serializer = URLSafeTimedSerializer(JWT_SECRET)

    token = serializer.dumps(email, salt="email-verification")
    encoded_token = quote(token)

    magic_url = f"{BASE_URL}/api/customer-login/?token={encoded_token}"
    
    return magic_url

def create_long_lasting_token(customer: Customer) -> str:
    access_token = AccessToken()
    
    access_token['id'] = str(customer.id)
    access_token['email'] = customer.email
    access_token.set_exp(from_time=None, lifetime=timedelta(days=30))
    
    return str(access_token)