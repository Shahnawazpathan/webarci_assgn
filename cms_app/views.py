from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from .serializers import UserSerializer, contentserializer
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from django.core.exceptions import ObjectDoesNotExist
from .models import CustomUser, content_item, category
from django.db.models import Q

@api_view(['POST'])
def register_user(request):
    if request.method == 'POST':
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'success': 'Registration successfully done'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def user_login(request):
    if request.method == 'POST':
        username = request.data.get('username')
        password = request.data.get('password')

        user = None
        if '@' in username:
            try:
                user = CustomUser.objects.get(email=username)
            except ObjectDoesNotExist:
                pass

        if not user:
            user = authenticate(username=username, password=password)

        if user:
            token, _ = Token.objects.get_or_create(user=user)
            return Response({'token': token.key}, status=status.HTTP_200_OK)

        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def user_logout(request):
    if request.method == 'POST':
        try:
            request.user.auth_token.delete()
            return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_content(request):
    if request.method == "POST":
        serializer = contentserializer(data=request.data)
        if serializer.is_valid():
            serializer.validated_data['user'] = request.user
            serializer.save()
            return Response({'success': 'Content added successfully'}, status=status.HTTP_201_CREATED)
        else:
            return Response({'error': 'Invalid data', 'details': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST', 'GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def content_data(request, id=None):
    try:
        if id:
            if request.user.is_superuser:
                content = content_item.objects.get(id=id)
            else:
                try:
                    content = content_item.objects.get(id=id, user=request.user)
                except:
                    return Response({'error': 'Access denied. You do not have permission to perform this action.'})

            if request.method == 'GET':
                serializer = contentserializer(content)
                return Response(serializer.data)
            elif request.method == 'PUT':
                serializer = contentserializer(content, data=request.data)
                if serializer.is_valid():
                    serializer.save()
                    return Response({'message': 'Content updated successfully'})
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            elif request.method == 'DELETE':
                content.delete()
                return Response({'message': 'Content deleted successfully'})
        else:
            if request.user.is_superuser:
                content = content_item.objects.all()
            else:
                content = content_item.objects.filter(user=request.user)

            serializer = contentserializer(content, many=True)
            return Response(serializer.data)

    except content_item.DoesNotExist:
        return Response({'error': 'Content not found'}, status=status.HTTP_404_NOT_FOUND)

    return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def search_content(request):
    if request.method == 'GET':
        search_query = request.query_params.get('search', '')

        content = content_item.objects.filter(
            Q(title__icontains=search_query) |
            Q(description__icontains=search_query) |
            Q(summary__icontains=search_query) |
            Q(categories__name__icontains=search_query)
        )

        serializer = contentserializer(content, many=True)

        return Response(serializer.data)
