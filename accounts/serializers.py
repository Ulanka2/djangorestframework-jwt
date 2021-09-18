from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True, validators=[UniqueValidator(queryset=User.objects.all())])
    password = serializers.CharField(min_length=8, write_only=True, label='Password', style={"input_type": "password"})

    class Meta:
        model = User
        fields = ('id', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(email=validated_data['email'], password=validated_data['password'])
        user.set_password(validated_data['password'])
        return user

    def validate_emal(self, value):
        email = value.strip().lower()
        if User.objects.filter(email=email):
            raise serializers.ValidationError('Пользователь с таким EMAIL уже существует')

        return email


class VerifyEmailSerializer(serializers.Serializer):
    key = serializers.CharField()
