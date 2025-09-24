# users/serializers.py

from django.contrib.auth.models import User
from rest_framework import serializers, validators
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth.models import Group, Permission
from rest_framework_simplejwt.tokens import RefreshToken

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("username", "password", "email", "first_name", "last_name")
        extra_kwargs = {
            "password": {"write_only": True},
            "email": {
                "required": True,
                "allow_blank": False,
                "validators": [
                    validators.UniqueValidator(
                        User.objects.all(), "A user with that Email already exists."
                    )
                ],
            },
        }

    def create(self, validated_data):
        # Creates a new user with a hashed password
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
            first_name=validated_data.get("first_name", ""),
            last_name=validated_data.get("last_name", ""),
        )
        return user

def add_user_data_to_token(token: RefreshToken, user):
    """
    Helper function to add custom claims to a token.
    """
    token['username'] = user.username
    token['email'] = user.email
    permissions = list(user.get_all_permissions())
    token['permissions'] = permissions
    return token
    
class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        # This method is called when a token is created for a user
        token = super().get_token(user)

        # Add custom claims
        token['username'] = user.username
        token['email'] = user.email
        permissions = user.get_all_permissions() # e.g., {'users.add_user', 'workflows.view_workflow'}
        token['permissions'] = list(permissions)
        # ... you can add any other user data here

        return token
    
class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'name', 'codename']

class GroupSerializer(serializers.ModelSerializer):
    permissions = PermissionSerializer(many=True, read_only=True)

    class Meta:
        model = Group
        fields = ['id', 'name', 'permissions']