import jwt

from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from rest_framework import generics
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import UserSerializer, VerifyEmailSerializer
from rest_framework_jwt.utils import jwt_payload_handler
from main import settings

User = get_user_model()


class UserCreateView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            if user:
                response_data = user.send_activation_message(request.get_host())
                return Response((serializer.data, response_data), status=status.HTTP_201_CREATED)
        return Response({"detail": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class EmailVerificationView(APIView):
    def post(self, request):
        serializer = VerifyEmailSerializer(data=request.data)
        if serializer.is_valid():
            decoded_jwt = jwt.decode(serializer.validated_data['key'], settings.SECRET_KEY, algorithms='HS256')
            if 'id' in decoded_jwt:
                user = User.objects.filter(id=decoded_jwt['id']).first()
                if user:
                    user.is_active = True
                    user.save()
                    serializer = UserSerializer(instance=user)
                    return Response(serializer.data, status=status.HTTP_200_OK)
            return Response({'key': 'Данный токен не валидный'}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'detail': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']
        user = authenticate(email=email, password=password)
        if user:
            payload = jwt_payload_handler(user)
            token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
            user_details = {'id': user.id, 'email': user.email,  'token': token}
            return Response(user_details, status=status.HTTP_200_OK)
        else:
            return Response({"detail": 'Не валидные данные'}, status=status.HTTP_403_FORBIDDEN)
