from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Customer, Booking, TubeType, TubeBooking


class AdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username']


class CustomerSerializer(serializers.ModelSerializer):
    """
    Serializer for Customer model.
    """
    class Meta:
        model = Customer
        fields = ['id', 'name', 'phone_number', 'email', 'stripeCustomerId', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class CustomerCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating new Customer records.
    """
    class Meta:
        model = Customer
        fields = ['name', 'phone_number', 'email', 'stripeCustomerId']


class CustomerUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating Customer records.
    """
    class Meta:
        model = Customer
        fields = ['name', 'phone_number', 'email', 'stripeCustomerId']


class TubeTypeSerializer(serializers.ModelSerializer):
    """
    Serializer for TubeType model.
    """
    class Meta:
        model = TubeType
        fields = ['id', 'price', 'size', 'qty', 'length', 'width', 'description', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class TubeTypeCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating new TubeType records.
    """
    class Meta:
        model = TubeType
        fields = ['price', 'size', 'qty', 'length', 'width', 'description']
    
    def validate_price(self, value):
        if value <= 0:
            raise serializers.ValidationError("Price must be greater than zero.")
        return value
    
    def validate_qty(self, value):
        if value < 0:
            raise serializers.ValidationError("Quantity cannot be negative.")
        return value
    
    def validate_length(self, value):
        if value <= 0:
            raise serializers.ValidationError("Length must be greater than zero.")
        return value
    
    def validate_width(self, value):
        if value <= 0:
            raise serializers.ValidationError("Width must be greater than zero.")
        return value


class TubeTypeUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating TubeType records.
    """
    class Meta:
        model = TubeType
        fields = ['price', 'size', 'qty', 'length', 'width', 'description']
    
    def validate_price(self, value):
        if value <= 0:
            raise serializers.ValidationError("Price must be greater than zero.")
        return value
    
    def validate_qty(self, value):
        if value < 0:
            raise serializers.ValidationError("Quantity cannot be negative.")
        return value
    
    def validate_length(self, value):
        if value <= 0:
            raise serializers.ValidationError("Length must be greater than zero.")
        return value
    
    def validate_width(self, value):
        if value <= 0:
            raise serializers.ValidationError("Width must be greater than zero.")
        return value


class TubeBookingSerializer(serializers.ModelSerializer):
    """
    Serializer for TubeBooking model.
    """
    tube_type_size = serializers.CharField(source='tubeType.size', read_only=True)
    tube_type_price = serializers.FloatField(source='tubeType.price', read_only=True)
    tube_type_length = serializers.FloatField(source='tubeType.length', read_only=True)
    tube_type_width = serializers.FloatField(source='tubeType.width', read_only=True)
    booking_customer = serializers.CharField(source='booking.customer.name', read_only=True)
    
    class Meta:
        model = TubeBooking
        fields = ['id', 'tubeType', 'tube_type_size', 'tube_type_price', 'tube_type_length', 'tube_type_width', 'booking', 
                 'booking_customer', 'numOfTubesBooked', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class TubeBookingCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating new TubeBooking records.
    """
    class Meta:
        model = TubeBooking
        fields = ['tubeType', 'booking', 'numOfTubesBooked']
    
    def validate_numOfTubesBooked(self, value):
        if value <= 0:
            raise serializers.ValidationError("Number of tubes booked must be greater than zero.")
        return value
    
    def validate(self, attrs):
        tube_type = attrs.get('tubeType')
        num_booked = attrs.get('numOfTubesBooked')
        
        if tube_type and num_booked and num_booked > tube_type.qty:
            raise serializers.ValidationError(f"Not enough tubes available. Only {tube_type.qty} available.")
        
        return attrs


class TubeBookingUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating TubeBooking records.
    """
    class Meta:
        model = TubeBooking
        fields = ['tubeType', 'booking', 'numOfTubesBooked']
    
    def validate_numOfTubesBooked(self, value):
        if value <= 0:
            raise serializers.ValidationError("Number of tubes booked must be greater than zero.")
        return value
    
    def validate(self, attrs):
        tube_type = attrs.get('tubeType')
        num_booked = attrs.get('numOfTubesBooked')
        
        if tube_type and num_booked and num_booked > tube_type.qty:
            raise serializers.ValidationError(f"Not enough tubes available. Only {tube_type.qty} available.")
        
        return attrs


class BookingSerializer(serializers.ModelSerializer):
    """
    Serializer for Booking model.
    """
    customer_name = serializers.CharField(source='customer.name', read_only=True)
    customer_email = serializers.EmailField(source='customer.email', read_only=True)
    tube_bookings = TubeBookingSerializer(many=True, read_only=True)
    
    class Meta:
        model = Booking
        fields = ['id', 'startTime', 'endTime', 'customer', 'customer_name', 'customer_email', 
                 'stripePaymentIntentId', 'amount', 'paymentStatus', 'receipturl',
                 'tube_bookings', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class BookingCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating new Booking records.
    """
    class Meta:
        model = Booking
        fields = ['startTime', 'endTime', 'customer', 'stripePaymentIntentId', 'amount', 'paymentStatus']
    
    def validate(self, attrs):
        start_time = attrs.get('startTime')
        end_time = attrs.get('endTime')
        
        if start_time and end_time and start_time >= end_time:
            raise serializers.ValidationError("End time must be after start time.")
        
        return attrs


class BookingUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating Booking records.
    """
    class Meta:
        model = Booking
        fields = ['startTime', 'endTime', 'customer', 'stripePaymentIntentId', 'amount', 'paymentStatus']
    
    def validate(self, attrs):
        start_time = attrs.get('startTime')
        end_time = attrs.get('endTime')
        
        if start_time and end_time and start_time >= end_time:
            raise serializers.ValidationError("End time must be after start time.")
        
        return attrs




class CustomerWithBookingsSerializer(serializers.ModelSerializer):
    """
    Serializer for Customer model with nested bookings.
    """
    bookings = BookingSerializer(many=True, read_only=True)
    
    class Meta:
        model = Customer
        fields = ['id', 'name', 'phone_number', 'email', 'stripeCustomerId', 
                 'created_at', 'updated_at', 'bookings']
        read_only_fields = ['id', 'created_at', 'updated_at']