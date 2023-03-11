from django.shortcuts import get_object_or_404
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import generics, permissions, status
from django.contrib.auth.models import User
from .serializers import UserSerializer
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, login, logout
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from .models import Group, Member, Message, Like
from rest_framework.exceptions import PermissionDenied
from rest_framework.viewsets import ViewSet
from django.db import IntegrityError


@api_view(['POST'])
def generate_token(request):
    """
    This function is going to generate token for admin users only
    """
    username = request.data.get('username')
    password = request.data.get('password')

    user = authenticate(username=username, password=password)
    if user is not None and user.is_superuser:
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key})
    else:
        return Response({'error': 'Invalid credentials'})


class UserCreateAPIView(generics.CreateAPIView):
    """
    This function is used to create new user by admins only
    """
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAdminUser]

    def perform_create(self, serializer):
        # Hash the password before saving the user
        password = serializer.validated_data.get('password')
        hashed_password = make_password(password)
        serializer.save(password=hashed_password)


class UserUpdateAPIView(generics.UpdateAPIView):
    """
    This function is used to edit existing users by admins only
    """
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAdminUser]

    def get_object(self):
        queryset = User.objects.filter(pk=self.kwargs['pk'])
        obj = get_object_or_404(queryset)
        return obj

    def perform_update(self, serializer):
        if 'password' in serializer.validated_data:
            serializer.validated_data['password'] = make_password(serializer.validated_data['password'])
        serializer.save()

    def put(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            self.perform_update(serializer)
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(APIView):
    """
    This function is used to login existing users
    """
    def post(self, request):
        try:
            username = request.data.get('username')
            password = request.data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return Response({'message': 'Login successful.'})
            else:
                return Response({'message': 'Invalid username or password.'}, status=400)
        except Exception as e:
            return Response({'message': 'An error occurred while logging in: {}'.format(str(e))}, status=500)


class LogoutAPIView(APIView):
    """
    This function is used to logout and invalidate the session
    """
    def post(self, request):
        try:
            logout(request)
            request.session.flush()
            return Response({'message': 'Logout successful.'})
        except Exception as e:
            return Response({'message': 'An error occurred while logging out: {}'.format(str(e))}, status=500)



class GroupView(ViewSet):
    permission_classes = [IsAuthenticated]

    def create_group(self, request):
        """
        This function is used to create group if the user is logged in
        """
        name = request.data.get('name')
        description = request.data.get('description')
        owner = request.user

        try:
            group = Group.objects.create(name=name, description=description, owner=owner)
            member = Member.objects.create(user=owner, group=group)

            response_data = {
                'id': group.id,
                'name': group.name,
                'description': group.description,
            }
            return Response(response_data)

        except IntegrityError as e:
            error_response = {'error': str(e)}
            return Response(error_response, status=status.HTTP_400_BAD_REQUEST)

    def delete_group(self, request, group_id):
        """
        This function is used to delete group if user loggedin and
        user should be either owner of group or should have permissions to perform administrative tasks
        """
        group = get_object_or_404(Group, id=group_id)

        # Only the owner of the group or an admin can delete the group
        if request.user == group.owner or request.user.is_staff:
            group.delete()
            return Response({'message': 'Group deleted successfully.'})
        else:
            raise PermissionDenied(detail='You do not have permission to delete this group.')

    def search_and_add_member(self, request, group_id):
        """
        This function is used to search and add members in a group if user loggedin and
        user should be either owner of group or should have permissions to perform administrative tasks
        """
        # Get the group object, or raise 404 if not found
        group = get_object_or_404(Group, id=group_id)

        # Get the query parameter from the request
        query = request.query_params.get('search')

        # Search for users that match the query
        users = User.objects.filter(username__icontains=query)

        # Add each user to the group
        members_added = []
        for user in users:
            # Check if the user is already a member of the group
            if group.members.filter(user=user).exists():
                continue
            # Check if the current user is the owner of the group or an admin
            if not request.user.is_staff and group.owner != request.user:
                raise PermissionDenied(detail='You are not authorized to add members to this group.')

            # Add the user to the group
            member = Member.objects.create(user=user, group=group)
            group.members.add(member)

            members_added.append({
                'id': user.id,
                'username': user.username,
                'is_staff': user.is_staff
            })

        # Return the updated group information
        response_data = {
            'id': group.id,
            'name': group.name,
            'description': group.description,
            'members': [
                {
                    'id': m.user.id,
                    'username': m.user.username,
                    'is_staff': m.user.is_staff
                } for m in group.members.all()
            ]
        }

        if members_added:
            response_data['newly_added_members'] = members_added

        return Response(response_data)

    def send_message(self, request, group_id):
        """
        This function is used to send messages in a group if user loggedin and
        user should be a member of group
        """
        group = get_object_or_404(Group, id=group_id)
        user = request.user
        text = request.data.get('text')

        # Check if the user is a member of the group
        if not group.members.filter(user=user).exists():
            raise PermissionDenied(detail='You are not authorized to send messages in this group.')

        message = Message.objects.create(group=group, user=user, text=text)

        response_data = {
            'id': message.id,
            'group': message.group.id,
            'user': message.user.username,
            'text': message.text,
            'created_at': message.created_at
        }

        return Response(response_data)

    def like_message(self, request, group_id, message_id):
        """
        This function is used to like messages already send in a group if user loggedin and
        user should be a member of group
        """
        group = get_object_or_404(Group, id=group_id)
        message = get_object_or_404(Message, id=message_id, group=group)
        user = request.user

        # Check if the user has already liked the message
        if Like.objects.filter(user=user, message=message).exists():
            raise PermissionDenied(detail='You have already liked this message.')

        # Create the like
        like = Like.objects.create(user=user, message=message)

        response_data = {
            'id': like.id,
            'user': user.username,
            'message': message.text,
            'liked_at': like.liked_at,
        }

        return Response(response_data)