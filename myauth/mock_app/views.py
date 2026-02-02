from auth_system.permissions import HasPermission, IsAuthenticated
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView


class PostsListView(APIView):
    permission_classes = [IsAuthenticated, HasPermission]

    def get(self, request):
        self.kwargs['resource_code'] = 'posts'
        self.kwargs['permission_code'] = 'view_posts'
        mock_posts = [
            {'id': 1, 'title': 'Первый пост', 'content': 'Текст поста 1'},
            {'id': 2, 'title': 'Второй пост', 'content': 'Текст поста 2'}
        ]
        return Response(mock_posts, status=status.HTTP_200_OK)


class CommentsCreateView(APIView):
    permission_classes = [IsAuthenticated, HasPermission]

    def post(self, request):
        self.kwargs['resource_code'] = 'comments'
        self.kwargs['permission_code'] = 'create_comments'
        return Response(
            {'message': 'Комментарий создан'},
            status=status.HTTP_201_CREATED
        )
