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

    query = urlencode({"email": email, "token": token})
    magic_url = f"{BASE_URL}?{query}"

    return magic_url