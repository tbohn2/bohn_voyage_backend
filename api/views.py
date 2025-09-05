from rest_framework import viewsets, mixins, permissions, status
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.contrib.auth.models import User
from django.conf import settings
import jwt
import stripe
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from .services.auth import CookieJWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from .models import Customer, Booking, Payment, TubeType, TubeBooking
from .serializers import (
    AdminSerializer, CustomerSerializer, CustomerCreateSerializer, CustomerUpdateSerializer,
    BookingSerializer, BookingCreateSerializer, BookingUpdateSerializer, CustomerWithBookingsSerializer,
    PaymentSerializer, PaymentCreateSerializer, PaymentUpdateSerializer, CustomerWithPaymentsSerializer,
    TubeTypeSerializer, TubeTypeCreateSerializer, TubeTypeUpdateSerializer,
    TubeBookingSerializer, TubeBookingCreateSerializer, TubeBookingUpdateSerializer
)
from .services.customer_auth import create_magic_link, create_long_lasting_token
from .services.utils import send_email

class AdminViewSet(mixins.CreateModelMixin,
                   mixins.UpdateModelMixin,
                   viewsets.GenericViewSet):
    """
    Provides Create, Update for Admin.    
    """
    queryset = User.objects.all()
    serializer_class = AdminSerializer
    permission_classes = [permissions.IsAdminUser]  # JWT-protected


class CustomerViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Customer model CRUD operations.
    """
    queryset = Customer.objects.all()
    permission_classes = [permissions.IsAdminUser]  # All operations require admin
    
    def get_serializer_class(self):
        if self.action == 'retrieve' and self.request.query_params.get('include_bookings'):
            return CustomerWithBookingsSerializer
        elif self.action == 'retrieve' and self.request.query_params.get('include_payments'):
            return CustomerWithPaymentsSerializer
        elif self.action == 'create':
            return CustomerCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return CustomerUpdateSerializer
        return CustomerSerializer


class PaymentViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Payment model CRUD operations.
    """
    queryset = Payment.objects.all()
    permission_classes = [permissions.IsAdminUser]  # All operations require admin
    
    def get_serializer_class(self):
        if self.action == 'create':
            return PaymentCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return PaymentUpdateSerializer
        return PaymentSerializer
    
    def get_queryset(self):
        queryset = Payment.objects.all()
        customer_id = self.request.query_params.get('customer_id', None)
        payment_status = self.request.query_params.get('payment_status', None)
        
        if customer_id:
            queryset = queryset.filter(customer_id=customer_id)
        if payment_status:
            queryset = queryset.filter(paymentStatus=payment_status)
        
        return queryset


class BookingViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Booking model CRUD operations.
    """
    queryset = Booking.objects.all()
    permission_classes = [permissions.IsAdminUser]  # All operations require admin
    
    def get_serializer_class(self):
        if self.action == 'create':
            return BookingCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return BookingUpdateSerializer
        return BookingSerializer
    
    def get_queryset(self):
        queryset = Booking.objects.all()
        customer_id = self.request.query_params.get('customer_id', None)
        if customer_id:
            queryset = queryset.filter(customer_id=customer_id)
        return queryset


class TubeTypeViewSet(viewsets.ModelViewSet):
    """
    ViewSet for TubeType model CRUD operations.
    """
    queryset = TubeType.objects.all()
    permission_classes = [permissions.IsAdminUser]  # All operations require admin
    
    def get_serializer_class(self):
        if self.action == 'create':
            return TubeTypeCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return TubeTypeUpdateSerializer
        return TubeTypeSerializer
    
    def get_queryset(self):
        queryset = TubeType.objects.all()
        size = self.request.query_params.get('size', None)
        if size:
            queryset = queryset.filter(size__icontains=size)
        return queryset


class TubeBookingViewSet(viewsets.ModelViewSet):
    """
    ViewSet for TubeBooking model CRUD operations.
    """
    queryset = TubeBooking.objects.all()
    permission_classes = [permissions.IsAdminUser]  # All operations require admin
    
    def get_serializer_class(self):
        if self.action == 'create':
            return TubeBookingCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return TubeBookingUpdateSerializer
        return TubeBookingSerializer
    
    def get_queryset(self):
        queryset = TubeBooking.objects.all()
        booking_id = self.request.query_params.get('booking_id', None)
        tube_type_id = self.request.query_params.get('tube_type_id', None)

        if booking_id:
            queryset = queryset.filter(booking_id=booking_id)
        if tube_type_id:
            queryset = queryset.filter(tubeType_id=tube_type_id)

        return queryset


class CustomerAuthViewSet(APIView):
    """
    ViewSet for Customer authentication.
    """
    def get(self, request):
        """
        Get customer authentication status. Used for polling customer authentication status.
        """
        token = request.COOKIES.get('token')
        if token:
            return Response({'authenticated': True}, status=status.HTTP_200_OK)
        return Response({'authenticated': False}, status=status.HTTP_200_OK)

    def post(self, request):
        """
        Is customer already logged in?
        """
        email = request.data.get('email')
        token = request.COOKIES.get('token')

        if token:
            jwt_auth = CookieJWTAuthentication()
            try:
                user, validated_token = jwt_auth.authenticate(request)
                if user and user.is_authenticated:
                    customer_id = validated_token.get('customer_id')
                    return Response({'authenticated': True, 'user_id': customer_id}, status=200)
            except (InvalidToken, TokenError):
                pass

        subject = "Verify link for booking"
        message = "Click the link to verify your email to proceed with booking:\n"
        magic_link = create_magic_link(email)
        send_email(email, subject, message + magic_link)
        return Response({'message': 'Magic link sent to email', 'authenticated': False}, status=200)
        

class CustomerLoginViewSet(APIView):
    """
    ViewSet for Customer login.
    """
    def get(self, request):
        """
        Get customer email from token in magic link url and issue long lasting http cookies only token
        """
        token = request.query_params.get('token')
        if not token:
            return Response({'error': 'No token provided'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            JWT_SECRET = settings.SECRET_KEY
            max_age_seconds = 3600
            serializer = URLSafeTimedSerializer(JWT_SECRET)         
            email = serializer.loads(token, salt="email-verification", max_age=max_age_seconds)
      
            if not email:
                return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
            
            customer, created = Customer.objects.get_or_create(email=email)

            message = "Customer created" if created else "Customer logged in"

            long_lasting_token = create_long_lasting_token(customer)
            response = Response({'message': message}, status=status.HTTP_200_OK)
            response.set_cookie('token', long_lasting_token, httponly=True)
            # response.set_cookie('token', long_lasting_token, httponly=True, secure=True, samesite='Strict')
            return response

        except (SignatureExpired, BadSignature):
            return Response({'error': 'Token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            print(token)
            return Response({'error': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'error': f'Authentication failed: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)


class CreatePaymentIntentView(APIView):
    """
    View for creating Stripe payment intents.
    """
    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """
        Create a Stripe payment intent.
        Expected payload:
        {
            "amount": 2000,  # Amount in cents
            "currency": "usd",
            "customer_email": "customer@example.com",  # Optional
            "metadata": {  # Optional
                "booking_id": "123",
                "description": "Tube rental payment"
            }
        }
        """
        try:
            stripe.api_key = settings.STRIPE_SECRET_KEY
            
            amount = request.data.get('amount')
            currency = request.data.get('currency', 'usd')
            customer_email = request.data.get('customer_email')
            metadata = request.data.get('metadata', {})
            
            if not amount:
                return Response(
                    {'error': 'Amount is required'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                amount = int(amount)
                if amount <= 0:
                    raise ValueError("Amount must be positive")
            except (ValueError, TypeError):
                return Response(
                    {'error': 'Amount must be a positive integer'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            intent_params = {
                'amount': amount,
                'currency': currency,
                'automatic_payment_methods': {
                    'enabled': True,
                },
                'metadata': metadata
            }
            
            if customer_email:
                intent_params['receipt_email'] = customer_email
            
            intent = stripe.PaymentIntent.create(**intent_params)
            
            return Response({
                'client_secret': intent.client_secret,
                'payment_intent_id': intent.id,
                'amount': intent.amount,
                'currency': intent.currency,
                'status': intent.status
            }, status=status.HTTP_201_CREATED)
            
        except stripe.error.StripeError as e:
            return Response(
                {'error': f'Stripe error: {str(e)}'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {'error': f'Server error: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

