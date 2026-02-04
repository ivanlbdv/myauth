from auth_system.models import User
from rest_framework import serializers

from .models import Comment, Post


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'email']


class PostSerializer(serializers.ModelSerializer):
    author = UserSerializer(read_only=True)
    comments_count = serializers.SerializerMethodField()

    def get_comments_count(self, obj):
        return obj.comments.count()

    class Meta:
        model = Post
        fields = [
            'id',
            'title',
            'content',
            'author',
            'created_at',
            'comments_count'
        ]
        read_only_fields = ['created_at']


class CommentSerializer(serializers.ModelSerializer):
    author = UserSerializer(read_only=True)
    post_title = serializers.CharField(source='post.title', read_only=True)

    class Meta:
        model = Comment
        fields = [
            'id',
            'post',
            'post_title',
            'content',
            'author',
            'created_at'
        ]
        read_only_fields = ['created_at', 'post', 'author']
