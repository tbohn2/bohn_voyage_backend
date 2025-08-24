from django.db import models
import uuid
from django.core.validators import RegexValidator
from decimal import Decimal

phone_regex = RegexValidator(
    regex=r'^\+?1?\d{9,15}$',
    message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
)

class Customer(models.Model):
    """
    Customer model with id, name, phone_number, email, and stripeCustomerId fields.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, blank=True, null=True)
    phone_number = models.CharField(validators=[phone_regex], max_length=17, blank=True, null=True)
    email = models.EmailField(unique=True)
    stripeCustomerId = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'customers'
        verbose_name = 'Customer'
        verbose_name_plural = 'Customers'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.email})"


class Payment(models.Model):
    """
    Payment model with id, stripPaymentId, amount, paymentStatus, paymentDate, customerId, receipturl, and currency fields.
    """
    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
        ('refunded', 'Refunded'),
    ]
    
    CURRENCY_CHOICES = [
        ('USD', 'US Dollar'),
        ('EUR', 'Euro'),
        ('GBP', 'British Pound'),
        ('CAD', 'Canadian Dollar'),
    ]
    
    id = models.AutoField(primary_key=True)
    stripPaymentId = models.CharField(max_length=255, unique=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    paymentStatus = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, default='pending')
    paymentDate = models.DateTimeField(auto_now_add=True)
    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,
        related_name='payments',
        db_column='customerId'
    )
    receipturl = models.URLField(max_length=500, blank=True, null=True)
    currency = models.CharField(max_length=3, choices=CURRENCY_CHOICES, default='USD')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'payments'
        verbose_name = 'Payment'
        verbose_name_plural = 'Payments'
        ordering = ['-paymentDate']
    
    def __str__(self):
        return f"Payment {self.id} - {self.customer.name} ({self.amount} {self.currency})"


class TubeType(models.Model):
    """
    TubeType model with id, price, size, and qty fields.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    price = models.FloatField()
    size = models.CharField(max_length=100)
    qty = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'tube_types'
        verbose_name = 'Tube Type'
        verbose_name_plural = 'Tube Types'
        ordering = ['size']
    
    def __str__(self):
        return f"{self.size} - ${self.price} (Qty: {self.qty})"


class Booking(models.Model):
    """
    Booking model with id, startTime, endTime, CustomerId, and paymentId fields.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    startTime = models.DateTimeField()
    endTime = models.DateTimeField()
    customer = models.ForeignKey(
        Customer, 
        on_delete=models.CASCADE, 
        related_name='bookings',
        db_column='CustomerId'
    )
    payment = models.OneToOneField(
        Payment,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='booking'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'bookings'
        verbose_name = 'Booking'
        verbose_name_plural = 'Bookings'
        ordering = ['-startTime']
    
    def __str__(self):
        return f"Booking {self.id} - {self.customer.name} ({self.startTime})"
    
    def clean(self):
        from django.core.exceptions import ValidationError
        if self.startTime and self.endTime and self.startTime >= self.endTime:
            raise ValidationError("End time must be after start time.")
    
    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)


class TubeBooking(models.Model):
    """
    TubeBooking model with tubeTypeId, bookingId, and numOfTubesBooked fields.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tubeType = models.ForeignKey(
        TubeType,
        on_delete=models.CASCADE,
        related_name='tube_bookings',
        db_column='tubeTypeId'
    )
    booking = models.ForeignKey(
        Booking,
        on_delete=models.CASCADE,
        related_name='tube_bookings',
        db_column='bookingId'
    )
    numOfTubesBooked = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'tube_bookings'
        verbose_name = 'Tube Booking'
        verbose_name_plural = 'Tube Bookings'
        ordering = ['-created_at']
        unique_together = ['tubeType', 'booking']
    
    def __str__(self):
        return f"{self.tubeType.size} x{self.numOfTubesBooked} for Booking {self.booking.id}"
    
    def clean(self):
        from django.core.exceptions import ValidationError
        if self.numOfTubesBooked <= 0:
            raise ValidationError("Number of tubes booked must be greater than zero.")
        if self.numOfTubesBooked > self.tubeType.qty:
            raise ValidationError(f"Not enough tubes available. Only {self.tubeType.qty} available.")
    
    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)


class NLPRequestLog(models.Model):
    """
    NLPRequestLog model for tracking NLP request inputs and outputs.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    inputText = models.TextField()
    output = models.TextField()
    createdAt = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'nlp_request_logs'
        verbose_name = 'NLP Request Log'
        verbose_name_plural = 'NLP Request Logs'
        ordering = ['-createdAt']
    
    def __str__(self):
        return f"NLP Request {self.id} - {self.createdAt}"