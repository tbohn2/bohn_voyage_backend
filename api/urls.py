from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import AdminViewSet, CustomerViewSet, BookingViewSet, TubeTypeViewSet, TubeBookingViewSet, CustomerAuthViewSet, CustomerLoginViewSet, CreatePaymentIntentView, stripe_webhook
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

router = DefaultRouter()
router.register(r'admins', AdminViewSet)
router.register(r'customers', CustomerViewSet)
router.register(r'bookings', BookingViewSet)
router.register(r'tube-types', TubeTypeViewSet)
router.register(r'tube-bookings', TubeBookingViewSet)

urlpatterns = [
    path('payments/stripe-webhook/', stripe_webhook, name='stripe-webhook'),
    path('', include(router.urls)),
    path('login/', TokenObtainPairView.as_view(), name='login'), # Admin login
    path('refresh/', TokenRefreshView.as_view(), name='refresh'), # Admin refresh
    path('customer-auth/', CustomerAuthViewSet.as_view(), name='customer-auth'),
    path('customer-login/', CustomerLoginViewSet.as_view(), name='customer-login'),
    path('create-payment-intent/', CreatePaymentIntentView.as_view(), name='create-payment-intent'),   
]
