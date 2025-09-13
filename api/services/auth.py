from rest_framework_simplejwt.authentication import JWTAuthentication
from ..models import Customer

class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        token = request.COOKIES.get("token")

        if token is None:
            return None
            
        try:
            validated_token = self.get_validated_token(token)
            user = self.get_user(validated_token)
            return (user, validated_token)
        except Exception as e:
            print("Exception: ", e)
            return None
    
    def get_user(self, validated_token):
        """
        Override to fetch Customer instead of User
        """
        try:
            customer_id = validated_token.get('id')
            if customer_id:
                customer = Customer.objects.get(id=customer_id)

                class CustomerUser:
                    def __init__(self, customer):
                        self.id = customer.id
                        self.email = customer.email
                        self.is_authenticated = True
                        self.is_anonymous = False
                        self.customer = customer
                
                return CustomerUser(customer)
            return None
        except Customer.DoesNotExist:
            return None