"""
URL configuration for myauth project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from auth_system import views as auth_views
from django.urls import path
from mock_app import views as mock_views

urlpatterns = [
    # Аутентификация
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

    # Управление пользователями
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

    # Административные API
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

    # Моковые бизнес-объекты
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
