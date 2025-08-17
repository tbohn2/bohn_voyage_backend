from django.contrib import admin
from .models import Customer


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
