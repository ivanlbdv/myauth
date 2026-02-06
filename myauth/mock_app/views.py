from auth_system.mixins import PermissionContextMixin
from auth_system.permissions import HasPermission, IsAuthenticated
from django.shortcuts import get_object_or_404
from rest_framework import permissions, status
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Comment, Post
from .serializers import CommentSerializer, PostSerializer


class PostsListView(APIView, PermissionContextMixin):
    permission_classes = [IsAuthenticated, HasPermission]
    resource_code = 'posts'
    permission_code = 'view_posts'

    def check_permissions(self, request):
        if request.method == 'GET':
            self.permission_code = 'view_posts'
        elif request.method == 'POST':
            self.permission_code = 'create_posts'

        self.kwargs['resource_code'] = self.resource_code
        self.kwargs['permission_code'] = self.permission_code

        super().check_permissions(request)

    def get(self, request, **kwargs):
        self.kwargs['resource_code'] = 'posts'
        self.kwargs['permission_code'] = 'view_posts'

        try:
            posts = Post.objects.all()
        except Exception:
            return Response(
                {'error': 'Не удалось получить посты из базы'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        serializer = PostSerializer(posts, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        serializer = PostSerializer(
            data=request.data,
            context={'request': request}
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CommentsCreateView(APIView, PermissionContextMixin):
    permission_classes = [IsAuthenticated, HasPermission]
    resource_code = 'comments'
    permission_code = 'create_comments'

    def check_permissions(self, request):
        self.kwargs['resource_code'] = self.resource_code
        self.kwargs['permission_code'] = self.permission_code
        super().check_permissions(request)

    def post(self, request, **kwargs):
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Требуется аутентификация'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        data = request.data.copy()

        if 'post' not in data:
            post_id = kwargs.get('post_id')
            if not post_id:
                return Response(
                    {'post': ['Не указан ID поста']},
                    status=status.HTTP_400_BAD_REQUEST
                )
            data['post'] = post_id

        data['author'] = request.user.id

        serializer = CommentSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )


class PostDetailView(APIView, PermissionContextMixin):
    permission_classes = [IsAuthenticated, HasPermission]
    resource_code = 'posts'
    permission_code = 'view_posts'

    def check_permissions(self, request):
        if request.method == 'GET':
            self.permission_code = 'view_posts'
        elif request.method == 'PUT':
            self.permission_code = 'edit_posts'
        elif request.method == 'DELETE':
            self.permission_code = 'delete_posts'

        self.kwargs['resource_code'] = self.resource_code
        self.kwargs['permission_code'] = self.permission_code

        super().check_permissions(request)

    def get_object(self, post_id):
        return get_object_or_404(Post, id=post_id)

    def check_object_permissions(self, request, obj):
        if request.method in ['PUT', 'DELETE']:
            if request.user == obj.author:
                return True
            else:
                try:
                    self.check_permissions(request)
                    return True
                except PermissionDenied:
                    return False
        return True

    def get(self, request, post_id, **kwargs):
        post = self.get_object(post_id)
        serializer = PostSerializer(post)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, post_id, **kwargs):
        post = self.get_object(post_id)

        if not self.check_object_permissions(request, post):
            return Response(
                {'error': 'У вас нет прав на обновление этого поста'},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = PostSerializer(post, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, post_id, **kwargs):
        post = self.get_object(post_id)

        if not self.check_object_permissions(request, post):
            return Response(
                {'error': 'У вас нет прав на удаление этого поста'},
                status=status.HTTP_403_FORBIDDEN
            )

        post.delete()
        return Response(
            {'message': 'Пост успешно удален'},
            status=status.HTTP_204_NO_CONTENT
        )


class CommentDetailView(APIView, PermissionContextMixin):
    permission_classes = [IsAuthenticated, HasPermission]
    resource_code = 'comments'
    permission_code = 'view_comments'

    def check_permissions(self, request):
        if request.method == 'GET':
            self.permission_code = 'view_comments'
        elif request.method == 'PUT':
            self.permission_code = 'edit_comments'
        elif request.method == 'DELETE':
            self.permission_code = 'delete_comments'

        self.kwargs['resource_code'] = self.resource_code
        self.kwargs['permission_code'] = self.permission_code

        super().check_permissions(request)

    def get_object(self, comment_id):
        return get_object_or_404(Comment, id=comment_id)

    def check_object_permissions(self, request, obj):
        if request.method in ['PUT', 'DELETE']:
            if request.user == obj.author:
                return True
            else:
                try:
                    self.check_permissions(request)
                    return True
                except PermissionDenied:
                    return False
        return True

    def get(self, request, comment_id, **kwargs):
        comment = self.get_object(comment_id)
        serializer = CommentSerializer(comment)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, comment_id, **kwargs):
        comment = self.get_object(comment_id)

        if not self.check_object_permissions(request, comment):
            return Response(
                {'error': 'У вас нет прав на обновление этого комментария'},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = CommentSerializer(
            comment,
            data=request.data,
            partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, comment_id, **kwargs):
        comment = self.get_object(comment_id)

        if not self.check_object_permissions(request, comment):
            return Response(
                {'error': 'У вас нет прав на удаление этого комментария'},
                status=status.HTTP_403_FORBIDDEN
            )

        comment.delete()
        return Response(
            {'message': 'Комментарий успешно удален'},
            status=status.HTTP_204_NO_CONTENT
        )


class CommentsByPostView(APIView, PermissionContextMixin):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, post_id):
        post = get_object_or_404(Post, id=post_id)
        comments = Comment.objects.filter(post=post).order_by('-created_at')
        serializer = CommentSerializer(comments, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
