from rest_framework import viewsets, mixins
from django.contrib.auth.models import User
from rest_framework.permissions import IsAdminUser
from .serializers import AdminSerializer

class AdminViewSet(mixins.CreateModelMixin,
                   mixins.UpdateModelMixin,
                   viewsets.GenericViewSet):
    """
    Provides Create, Update for Admin.    
    """
    queryset = User.objects.all()
    serializer_class = AdminSerializer
    permission_classes = [IsAdminUser]  # JWT-protected
