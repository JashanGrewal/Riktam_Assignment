from rest_framework import serializers
from django.contrib.auth.models import User


class UserSerializer(serializers.ModelSerializer):
    """
    This serializer class is created to handle the serialization of User objects
    """
    class Meta:
        model = User
        fields = ('id', 'username', 'password', 'is_staff')
        extra_kwargs = {
            'password': {'write_only': True},
        }

