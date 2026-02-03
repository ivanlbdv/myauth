from auth_system import views as auth_views
from django.contrib import admin
from django.urls import path
from mock_app import views as mock_views
from rest_framework_simplejwt.views import (TokenObtainPairView,
                                            TokenRefreshView)

urlpatterns = [
    path(
        'api/token/',
        TokenObtainPairView.as_view(),
        name='token_obtain_pair'
    ),
    path(
        'api/token/refresh/',
        TokenRefreshView.as_view(),
        name='token_refresh'
    ),
    path(
        'admin/',
        admin.site.urls
    ),
    path(
        'api/auth/register/',
        auth_views.RegisterView.as_view(),
        name='register'
    ),
    path(
        'api/auth/login/',
        auth_views.LoginView.as_view(),
        name='login'
    ),
    path(
        'api/auth/logout/',
        auth_views.LogoutView.as_view(),
        name='logout'
    ),

    path(
        'api/users/<int:user_id>/',
        auth_views.UserUpdateView.as_view(),
        name='user-update'
    ),
    path(
        'api/users/<int:user_id>/delete/',
        auth_views.UserDeleteView.as_view(),
        name='user-delete'
    ),

    path(
        'api/roles/',
        auth_views.RoleListCreateView.as_view(),
        name='role-list'
    ),
    path(
        'api/roles/<int:role_id>/',
        auth_views.RoleDetailView.as_view(),
        name='role-detail'
    ),
    path(
        'api/permissions/',
        auth_views.PermissionListView.as_view(),
        name='permission-list'
    ),
    path(
        'api/access-rules/',
        auth_views.AccessRuleCreateView.as_view(),
        name='access-rule-create'
    ),
    path(
        'api/access-rules/<int:rule_id>/',
        auth_views.AccessRuleDetailView.as_view(),
        name='access-rule-detail'
    ),

    path(
        'api/posts/',
        mock_views.PostsListView.as_view(),
        name='posts-list'
    ),
    path(
        'api/comments/',
        mock_views.CommentsCreateView.as_view(),
        name='comments-create'
    ),
]
