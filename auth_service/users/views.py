# users/views.py

from rest_framework import generics
from rest_framework.permissions import AllowAny
from .serializers import RegisterSerializer , MyTokenObtainPairSerializer
from django.contrib.auth.models import User
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.models import Group, Permission
from rest_framework import viewsets, permissions as drf_permissions
from .serializers import GroupSerializer, PermissionSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from two_factor.utils import default_device
from django.contrib.auth import get_user_model
from rest_framework import status

User = get_user_model()

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,) # Allow any user (even unauthenticated) to access this view
    serializer_class = RegisterSerializer

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        
        try:
            serializer.is_valid(raise_exception=True)
        except AuthenticationFailed as e:
            return Response({'error': 'No active account found with the given credentials'}, status=401)
        
        user = serializer.user
        device = default_device(user)

        if device and device.confirmed:
            # If 2FA is enabled, do NOT return a JWT.
            # Return a response indicating that 2FA is required.
            return Response({
                'message': 'Two-factor authentication required.',
                'user_id': user.id # Send user_id for the next step
            }, status=200)

        # If 2FA is not enabled, proceed with the standard JWT response.
        return super().post(request, *args, **kwargs)

class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    permission_classes = [drf_permissions.IsAdminUser] # Only admins can manage roles

class PermissionViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows permissions to be viewed.
    """
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [drf_permissions.IsAdminUser]

class TwoFactorSetupView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """
        Generates a new TOTP device and returns its QR code URL.
        """
        user = request.user
        device = default_device(user)
        if not device:
            device = user.totpdevice_set.create(name='default')
        
        # The otpauth:// URL is what QR code generators use
        qr_code_url = device.config_url
        return Response({'qr_code_url': qr_code_url})

class TwoFactorVerifyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """
        Verifies a TOTP token to enable 2FA.
        """
        user = request.user
        token = request.data.get('token')
        device = default_device(user)

        if not device:
            return Response({'error': '2FA device not set up.'}, status=400)
        
        if device.verify_token(token):
            device.confirmed = True
            device.save()
            return Response({'success': '2FA has been enabled successfully.'})
        
        return Response({'error': 'Invalid 2FA token.'}, status=400)
    
class TokenVerify2FAView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        user_id = request.data.get('user_id')
        token = request.data.get('token')

        if not user_id or not token:
            return Response({'error': 'User ID and token are required.'}, status=400)
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=404)
        
        device = default_device(user)
        if not device or not device.confirmed:
            return Response({'error': '2FA is not enabled for this user.'}, status=400)

        if device.verify_token(token):
            # If the token is valid, generate the final JWT
            serializer = MyTokenObtainPairSerializer(data={})
            serializer.user = user
            token_data = serializer.get_token(user)
            
            return Response({
                    'refresh': str(token_data),
                    'access': str(token_data.access_token),
                })
        
        return Response({'error': 'Invalid 2FA token.'}, status=400)
    
class TwoFactorStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """
        Checks if 2FA is enabled for the current user.
        """
        user = request.user
        device = default_device(user)
        is_enabled = device is not None and device.confirmed
        return Response({'is_2fa_enabled': is_enabled})

class TwoFactorDisableView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """
        Disables 2FA for the current user.
        """
        user = request.user
        device = default_device(user)
        if device:
            device.delete()
            return Response({'success': '2FA has been disabled.'}, status=status.HTTP_200_OK)
        return Response({'error': '2FA is not enabled.'}, status=status.HTTP_400_BAD_REQUEST)