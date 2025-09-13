from django.contrib import admin
from .models import Customer, Booking, TubeType, TubeBooking


@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    """
    Admin interface for Customer model.
    """
    list_display = ('id', 'name', 'email', 'phone_number', 'stripeCustomerId', 'created_at')
    list_filter = ('created_at', 'updated_at')
    search_fields = ('name', 'email', 'phone_number')
    readonly_fields = ('id', 'created_at', 'updated_at', 'stripeCustomerId')
    ordering = ('-created_at',)
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'email', 'phone_number')
        }),
        ('Stripe Integration', {
            'fields': ('stripeCustomerId',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(TubeType)
class TubeTypeAdmin(admin.ModelAdmin):
    """
    Admin interface for TubeType model.
    """
    list_display = ('id', 'size', 'price', 'qty', 'length', 'width', 'created_at')
    list_filter = ('created_at', 'updated_at')
    search_fields = ('size', 'id')
    readonly_fields = ('id', 'created_at', 'updated_at')
    ordering = ('size',)
    
    fieldsets = (
        ('Tube Information', {
            'fields': ('size', 'price', 'qty', 'length', 'width', 'description')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Booking)
class BookingAdmin(admin.ModelAdmin):
    """
    Admin interface for Booking model.
    """
    list_display = ('id', 'customer', 'startTime', 'endTime', 'created_at')
    list_filter = ('startTime', 'endTime', 'created_at', 'updated_at', 'paymentStatus', 'stripePaymentIntentId')
    search_fields = ('customer__name', 'customer__email', 'id')
    readonly_fields = ('id', 'created_at', 'updated_at')
    ordering = ('-startTime',)
    
    fieldsets = (
        ('Booking Information', {
            'fields': ('customer', 'startTime', 'endTime', 'stripePaymentIntentId', 'paymentStatus')
        }),        
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(TubeBooking)
class TubeBookingAdmin(admin.ModelAdmin):
    """
    Admin interface for TubeBooking model.
    """
    list_display = ('id', 'tubeType', 'booking', 'numOfTubesBooked', 'created_at')
    list_filter = ('created_at', 'updated_at', 'tubeType')
    search_fields = ('tubeType__size', 'booking__id', 'id')
    readonly_fields = ('id', 'created_at', 'updated_at')
    ordering = ('-created_at',)
    
    fieldsets = (
        ('Tube Booking Information', {
            'fields': ('tubeType', 'booking', 'numOfTubesBooked')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def has_delete_permission(self, request, obj=None):
        return False
