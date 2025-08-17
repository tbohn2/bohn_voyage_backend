from rest_framework import viewsets, mixins, permissions
from django.contrib.auth.models import User
from .models import Customer, Booking, Payment, TubeType, TubeBooking
from .serializers import (
    AdminSerializer, CustomerSerializer, CustomerCreateSerializer, CustomerUpdateSerializer,
    BookingSerializer, BookingCreateSerializer, BookingUpdateSerializer, CustomerWithBookingsSerializer,
    PaymentSerializer, PaymentCreateSerializer, PaymentUpdateSerializer, CustomerWithPaymentsSerializer,
    TubeTypeSerializer, TubeTypeCreateSerializer, TubeTypeUpdateSerializer,
    TubeBookingSerializer, TubeBookingCreateSerializer, TubeBookingUpdateSerializer
)


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
