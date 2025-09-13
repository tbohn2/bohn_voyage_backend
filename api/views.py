from rest_framework import viewsets, mixins, permissions, status
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
import stripe
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.conf import settings
from django.db import models
import jwt
import stripe
import openai
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
from datetime import datetime
import json

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
    
    def get_permissions(self):
        if self.action == 'list':
            return [permissions.AllowAny()]
        return [permissions.IsAdminUser()]
    
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
                'metadata': {
                    'client_email': request.user.email
                },
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


class TubeAvailabilityView(APIView):
    """
    View to get tube availability for a specific date range.
    """
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        """
        Get available tubes for each tube type within a date range.
        
        Query parameters:
        - start_date: Start date in ISO format (e.g., 2025-01-01T00:00:00Z)
        - end_date: End date in ISO format (e.g., 2025-01-01T23:59:59Z)
        """
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        
        if not start_date or not end_date:
            return Response(
                {'error': 'Both start_date and end_date are required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            from django.utils.dateparse import parse_datetime
            start_datetime = parse_datetime(start_date)
            end_datetime = parse_datetime(end_date)
            
            if not start_datetime or not end_datetime:
                return Response(
                    {'error': 'Invalid date format. Use ISO format (e.g., 2025-01-01T00:00:00Z)'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if start_datetime >= end_datetime:
                return Response(
                    {'error': 'start_date must be before end_date'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
        except Exception as e:
            return Response(
                {'error': f'Invalid date format: {str(e)}'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        tube_types = TubeType.objects.all()
        availability_data = []
        
        for tube_type in tube_types:
            # Find bookings that overlap with the requested time range
            # A booking overlaps if: booking.startTime < end_datetime AND booking.endTime > start_datetime
            overlapping_bookings = Booking.objects.filter(
                startTime__lt=end_datetime,
                endTime__gt=start_datetime,
                # paymentStatus='succeeded'
            )

            tube_bookings_count = TubeBooking.objects.filter(
                booking__in=overlapping_bookings,
                tubeType=tube_type
            ).aggregate(total_booked=models.Sum('numOfTubesBooked'))['total_booked'] or 0
            
            booked_tubes=tube_bookings_count
           
            available_tubes = tube_type.qty - booked_tubes
            
            availability_data.append({
                'tube_type_id': str(tube_type.id),
                'size': tube_type.size,
                'total_quantity': tube_type.qty,
                'booked_quantity': booked_tubes,
                'available_quantity': max(0, available_tubes),  # Ensure non-negative
                'price': tube_type.price,
                'description': tube_type.description
            })
        
        return Response({
            'date_range': {
                'start_date': start_date,
                'end_date': end_date
            },
            'availability': availability_data
        }, status=status.HTTP_200_OK)


class NLPViewSet(APIView):
    """
    View for NLP requests.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        """
        Create a NLP request.
        """
        tube_types = TubeType.objects.values_list('id', 'size', 'qty')
        tube_types = {size: (id, qty) for id, size, qty in tube_types}
        tube_type_sizes = {size for size in tube_types}
        inputText = request.data.get('inputText')
        today = datetime.now().strftime("%Y-%m-%d")
    
        client = openai.OpenAI(api_key=settings.OPEN_AI_KEY)

        output = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": f"""
                    You are extracting structured data from user requests.
                    Available tube types: {tube_type_sizes}
                    Today's date: {today}
                    Always return JSON with keys: start_time, tube_types (each with size and numOfTubesBooked).
                    """},
                {"role": "user", "content": inputText}
            ],
            response_format={"type": "json_schema", "json_schema": {
                "name": "booking_request",
                "schema": {
                    "type": "object",
                    "properties": {
                        "start_time": {"type": "string", "format": "date-time", "default": today},
                        "tube_types": {"type": "array", "items": {"type": "object", "properties": {
                            "tubeTypeSize": {"type": "string", "default": "Large"},
                            "numOfTubesBooked": {"type": "integer", "default": 1}
                        }}},
                    },
                    "required": ["start_time", "tube_types"]
                }
            }}
        )

        data = json.loads(output.choices[0].message.content)
    
        for tube_type in data.get('tube_types'):
            tube_type_obj = tube_types.get(tube_type.get('tubeTypeSize').lower())
            print("tube_type_obj", tube_type_obj)
            if tube_type_obj[1] < tube_type.get('numOfTubesBooked'):
                tube_type['numOfTubesBooked'] = tube_type_obj[1]
            tube_type['tubeTypeId'] = tube_type_obj[0]

    
        return Response({'data': data}, status=status.HTTP_200_OK)


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
    if event["type"] == "payment_intent.cancelled" or event["type"] == "payment_intent.canceled":
        status = 'cancelled'
    elif event["type"] == "payment_intent.succeeded":
        status = 'succeeded'
    elif event["type"] == "payment_intent.payment_failed":
        status = 'failed'
    else:
        print(f"⚠️ Unused event type: {event['type']}") 
        return HttpResponse(status=200)
        
    payment_intent = event["data"]["object"]

    stripe_payment_intent_id = payment_intent.get("id")

    try:
        booking = Booking.objects.get(stripePaymentIntentId=stripe_payment_intent_id)
        booking.paymentStatus = status
        booking.save()        
        booking.refresh_from_db()
        
        customer_email = booking.customer.email
        
        if event["type"] == "payment_intent.succeeded":
            print("💰 Payment succeeded")
            message = f"""
                Your trip has been booked successfully.
                Booking ID: {booking.id}
                Booking Date: {booking.startTime}
                Booking End Date: {booking.endTime}
                Booking Amount: {booking.amount}
            """
            send_email(customer_email, "Booked Successfully", message)

        elif event["type"] == "payment_intent.payment_failed":
            print("❌ Payment failed")
            message = f"""
                A payment has failed.
                Booking ID: {booking.id}
                Booking Date: {booking.startTime}
                Booking End Date: {booking.endTime}
                Booking Amount: {booking.amount}
            """
            send_email(settings.EMAIL_HOST_USER, "Payment failed", message)
            
    except Booking.DoesNotExist:
        print(f"⚠️ No booking found for payment intent")
        send_email(settings.EMAIL_HOST_USER, "Payment failed", "No booking found for payment intent " + stripe_payment_intent_id)
        return HttpResponse(status=404)

    return HttpResponse(status=200)