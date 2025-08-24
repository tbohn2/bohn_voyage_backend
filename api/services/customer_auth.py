import jwt
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from django.conf import settings

JWT_SECRET = settings.SECRET_KEY  
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 15  
BASE_URL = settings.FRONTEND_URL

def create_magic_link(email: str) -> str:    
    exp = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXP_MINUTES)

    payload = {
        "email": email,
        "exp": exp.timestamp()
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    encoded_token = urlencode({"token": token})

    magic_url = f"{BASE_URL}/api/customer-login/?{encoded_token}"
    
    return magic_url

def create_long_lasting_token(email: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(days=30)

    payload = {
        "email": email,
        "exp": exp.timestamp()
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return token