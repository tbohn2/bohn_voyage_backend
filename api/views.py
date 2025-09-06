from rest_framework import viewsets, mixins, permissions, status
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
import stripe
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.conf import settings
import jwt
import stripe
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from .services.auth import CookieJWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from .models import Customer, Booking, TubeType, TubeBooking
from .serializers import (
    AdminSerializer, CustomerSerializer, CustomerCreateSerializer, CustomerUpdateSerializer,
    BookingSerializer, BookingCreateSerializer, BookingUpdateSerializer, CustomerWithBookingsSerializer,
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
        elif self.action == 'create':
            return CustomerCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return CustomerUpdateSerializer
        return CustomerSerializer


class BookingViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Booking model CRUD operations.
    """
    queryset = Booking.objects.all()

    def get_permissions(self):
        if self.action == 'create':
            return [permissions.IsAuthenticated()]
        return [permissions.IsAdminUser()]
    
    def get_serializer_class(self):
        if self.action == 'create':
            return BookingCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return BookingUpdateSerializer
        return BookingSerializer
    
    def get_queryset(self):
        queryset = Booking.objects.all()
        customer_id = self.request.query_params.get('customer_id', None)
        payment_status = self.request.query_params.get('payment_status', None)
        
        if customer_id:
            queryset = queryset.filter(customer_id=customer_id)
        if payment_status:
            queryset = queryset.filter(paymentStatus=payment_status)
        
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
        Create a booking and a Stripe payment intent.
        Request payload:
        {
            "amount": 2000,  # Amount in cents
            "currency": "usd",            
            "start_time": "2025-01-01T00:00:00Z",
            "end_time": "2025-01-01T00:00:00Z",
            "tube_types": [
                {
                    "tubeTypeId": "123", # Tube type id
                    "numOfTubesBooked": 1
                }
            ]
        }
        """
        try:
            stripe.api_key = settings.STRIPE_SECRET_KEY
            
            amount = request.data.get('amount')
            currency = request.data.get('currency', 'usd')
                        
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
                }
            }
            
            intent = stripe.PaymentIntent.create(**intent_params)      

            customer_id = request.user.id
            customer = Customer.objects.get(id=customer_id)

            start_time = request.data.get('start_time')
            end_time = request.data.get('end_time')

            booking = Booking.objects.create(
                customer=customer,
                amount=request.data.get('amount'),
                paymentStatus='pending',
                startTime=start_time,
                endTime=end_time
            )

            booking.stripePaymentIntentId = intent.id
            booking.save()

            for tube_type in request.data.get('tube_types', []):
                tube_type_obj = TubeType.objects.get(id=tube_type.get('tubeTypeId'))
                if not tube_type_obj:
                    return Response(
                        {'error': 'Tube type not found'}, 
                        status=status.HTTP_404_NOT_FOUND
                    )

                tube_booking = TubeBooking.objects.create(
                    booking=booking,
                    tubeType=tube_type_obj,
                    numOfTubesBooked=tube_type.get('numOfTubesBooked')
                )

                tube_booking.save()
                
            
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


@csrf_exempt
def stripe_webhook(request):
    """
    Stripe webhook handler - bypasses Django's authentication and CSRF
    """
    if request.method != 'POST':
        return HttpResponse(status=405)  # Method not allowed
    
    print("💰 Stripe webhook received")
    payload = request.body
    sig_header = request.META.get("HTTP_STRIPE_SIGNATURE")
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        print("❌ Invalid payload")
        return HttpResponse(status=400)
    except stripe.error.SignatureVerificationError:
        print("❌ Invalid signature")
        return HttpResponse(status=400)

    status = ''
    if event["type"] == "payment_intent.cancelled":
        status = 'cancelled'
    if event["type"] == "payment_intent.succeeded":
        status = 'succeeded'
    if event["type"] == "payment_intent.payment_failed":
        status = 'failed'
    
    payment_intent = event["data"]["object"]

    stripe_payment_intent_id = payment_intent.get("id")
    amount = payment_intent.get("amount_received") or payment_intent.get("amount")
    currency = payment_intent.get("currency")
    customer_email = payment_intent.get("receipt_email")

    # Update or create booking with payment information
    booking = Booking.objects.filter(stripePaymentIntentId=stripe_payment_intent_id).first()
    if booking:
        # Update existing booking with payment status
        booking.paymentStatus = status
        booking.amount = amount
        booking.currency = currency
        booking.save()
    else:
        # Create new booking if not found (this shouldn't happen in normal flow)
        # You might want to handle this case differently based on your business logic
        print(f"⚠️ No booking found for payment intent {stripe_payment_intent_id}")

    if event["type"] == "payment_intent.succeeded":
        payment_intent = event["data"]["object"]
        print("💰 Payment succeeded:", payment_intent["id"])
        # TODO: mark booking as paid, send confirmation email, etc.

    elif event["type"] == "payment_intent.payment_failed":
        payment_intent = event["data"]["object"]
        print("❌ Payment failed:", payment_intent["id"])
        # TODO: notify user or log

    # Always return 200 to acknowledge receipt
    return HttpResponse(status=200)
