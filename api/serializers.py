from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Customer


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
