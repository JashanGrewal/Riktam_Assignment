from .views import generate_token, UserCreateAPIView, UserUpdateAPIView, \
    LoginAPIView, LogoutAPIView, GroupView
from django.urls import path


urlpatterns = [
    path('generate_token/', generate_token, name='generate-token'),
    path('users/create/', UserCreateAPIView.as_view(), name='user-create'),
    path('users/<int:pk>/update/', UserUpdateAPIView.as_view(), name='user-update'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('groups/', GroupView.as_view({'post': 'create_group',}), name='create_group'),
    path('groups/<int:group_id>/', GroupView.as_view({'delete': 'delete_group',}), name='delete_group'),
    path('groups/<int:group_id>/search_and_add_member/', GroupView.as_view({'post': 'search_and_add_member'}), name='search_and_add_member'),
    path('groups/<int:group_id>/messages/', GroupView.as_view({'post': 'send_message',}), name='send_message'),
    path('groups/<int:group_id>/messages/<int:message_id>/like/', GroupView.as_view({'post': 'like_message'}), name='like_message'),
]
