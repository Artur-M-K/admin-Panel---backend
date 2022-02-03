from asyncio import exceptions
from urllib import response
from rest_framework.decorators import api_view
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import exceptions, viewsets, status, generics, mixins
from rest_framework.views import APIView

from admin.pagination import CustomPagination
from .permissions import ViewPermissions

from .authentication import JWTAuthentication, generate_access_token

from .serializers import RoleSerializer, UserSerializer, PermissionSerializer
from .models import Permission, User, Role

@api_view(['POST'])
def register(request):
    data = request.data
    if data.get('password') != data.get('password_confirm'):
        raise exceptions.APIException('Passwords do not match!')

    serializer = UserSerializer(data=data)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response(serializer.data)

@api_view(['POST'])
def login(request):
    email = request.data.get('email')
    password = request.data.get('password')

    user = User.objects.filter(email=email).first()

    if user is None:
        raise exceptions.AuthenticationFailed('User not found!')

    if not user.check_password(password):
        raise exceptions.AuthenticationFailed('Incorrect password!')
    
    response = Response()

    token = generate_access_token(user)
    response.set_cookie(key='jwt', value=token, httponly=True)
    response.data = {
        'jwt': token
    }

    return response

@api_view(['POST'])
def logout(_):
    response = Response()
    response.delete_cookie(key='jwt')
    response.data = {
        'message': 'Success'
    }

    return response

class AuthenticatedUser(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        data = UserSerializer(request.user).data
        data['permissions'] = [p['name'] for p in data['role']['permissions']]

        return Response({
            'data': data
        })

class PermissionAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = PermissionSerializer(Permission.objects.all(), many=True)

        return Response({
            'data': serializer.data
        })

class RoleViewSet(viewsets.ModelViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated & ViewPermissions]
    permission_object = 'roles'
    serializer_class = RoleSerializer
    pagination_class = CustomPagination

    def list(self, request):
        queryset = Role.objects.all()
        pagination = CustomPagination()
        qs = pagination.paginate_queryset(queryset, request)
        # retrun all roles if endpoint dosn't include page parameter
        if 'page' not in request.query_params:
            serializer = RoleSerializer(queryset, many=True)
            return Response({
            'data': serializer.data
            })
        serializer = RoleSerializer(qs, many=True)
        return pagination.get_paginated_response(serializer.data)

    def create(self, request):
        serializer = RoleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            'data': serializer.data
        }, status=status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        role = Role.objects.get(id=pk)
        serializer = RoleSerializer(role)

        return Response({
            'data': serializer.data
        })

    def update(self, request, pk=None):
        role = Role.objects.get(id=pk)
        serializer = RoleSerializer(instance=role, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({
            'data': serializer.data
        }, status=status.HTTP_202_ACCEPTED)

    def destroy(self, request, pk=None):
        role = Role.objects.get(id=pk)
        role.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserGenericAPIView(generics.GenericAPIView, mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.CreateModelMixin, mixins.UpdateModelMixin, mixins.DestroyModelMixin):
        authentication_classes = [JWTAuthentication]
        permission_classes = [IsAuthenticated & ViewPermissions]
        permission_object = 'users'
        queryset = User.objects.all()
        serializer_class = UserSerializer
        pagination_class = CustomPagination

        def get(self, request, pk=None):
            if pk:
                return Response({
                   'data': self.retrieve(request, pk).data
                    })

            return self.list(request)

        def post(self, request):
            request.data.update({
                'password': 1234,
                'role': request.data.get('role_id')
            })
            return Response({
                'data': self.create(request).data
            })

        def patch(self, request, pk=None):
            
            if request.data.get('role_id'):
                request.data.update({
                'role': request.data.get('role_id')
            })

            return Response({
                'data': self.partial_update(request, pk).data
            })

        def delete(self, request, pk=None):
            return self.destroy(request, pk)

class ProfileInfoAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def put(self, request, pk=None):
        user = request.user
        serializer = UserSerializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

class ProfilePasswordAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def put(self, request, pk=None):
        user = request.user
        if request.data['password'] != request.data['password_confirm']:
            raise exceptions.ValidationError('Passwords do not match')

        user.set_password(request.data['password'])
        user.save()
        serializer = UserSerializer(user)
        return Response(serializer.data)