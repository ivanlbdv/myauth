from auth_system.permissions import HasPermission, IsAuthenticated
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView


class PostsListView(APIView):
    permission_classes = [
        IsAuthenticated,
        HasPermission('posts', 'view_posts')
    ]

    def get(self, request):
        mock_posts = [
            {"id": 1, "title": "Первый пост", "content": "Текст поста 1"},
            {"id": 2, "title": "Второй пост", "content": "Текст поста 2"}
        ]
        return Response(mock_posts, status=status.HTTP_200_OK)


class CommentsCreateView(APIView):
    permission_classes = [
        IsAuthenticated,
        HasPermission('comments', 'create_comments')
    ]

    def post(self, request):
        return Response(
            {"message": "Комментарий создан"},
            status=status.HTTP_201_CREATED
        )
