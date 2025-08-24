from rest_framework import viewsets, mixins, permissions, status
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
from urllib.parse import unquote
import jwt
from rest_framework_simplejwt.authentication import JWTAuthentication
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
        token = request.COOKIES.get('jwt')
        if token:
            return Response({'authenticated': True}, status=status.HTTP_200_OK)
        return Response({'authenticated': False}, status=status.HTTP_200_OK)

    def post(self, request):
        """
        Is customer already logged in?
        """
        email = request.data.get('email')
        token = request.COOKIES.get('jwt')
        
        jwt_auth = JWTAuthentication()

        subject = "Verify link for booking"
        message = "Click the link to verify your email to proceed with booking:\n"

        if token:
            try:
                validated_token = jwt_auth.get_validated_token(token)
                if validated_token:
                    return Response(
                        {'authenticated': True},
                        status=status.HTTP_200_OK
                    )

            except (InvalidToken, TokenError):
                magic_link = create_magic_link(email)
                send_email(email, subject, message + magic_link)
                return Response(
                    {'message': 'Invalid token. Magic link sent to email', 'authenticated': False},
                    status=status.HTTP_401_UNAUTHORIZED
                )

        # No token provided, send magic link
        magic_link = create_magic_link(email)
        send_email(email, subject, message + magic_link)
        return Response(
            {'message': 'Magic link sent to email', 'authenticated': False},
            status=status.HTTP_200_OK
        )
        

class CustomerLoginViewSet(APIView):
    """
    ViewSet for Customer login.
    """
    def get(self, request):
        """
        Get customer email from jwt token in url and issue long lasting http cookies only token
        """
        token = request.query_params.get('token')
        if not token:
            return Response({'error': 'No token provided'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            email = payload.get('email')
            if not email:
                return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                customer = Customer.objects.get(email=email)
            except Customer.DoesNotExist:
                customer = Customer.objects.create(email=email)

            email = customer.email
            long_lasting_token = create_long_lasting_token(email)
            response = Response({'message': 'Customer created'}, status=status.HTTP_200_OK)
            response.set_cookie('jwt', long_lasting_token, httponly=True, secure=True, samesite='Strict')
            return response

        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            print(token)
            return Response({'error': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'error': f'Authentication failed: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

