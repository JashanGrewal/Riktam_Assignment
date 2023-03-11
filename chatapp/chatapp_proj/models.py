from django.db import models
from django.contrib.auth.models import User


class Group(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_groups')

    def __str__(self):
        return self.name

    class Meta:
        # Add a unique_together constraint to ensure that the combination of
        # name and owner is unique.
        unique_together = ('name', 'owner')


class Member(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='memberships')
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='members')

    def __str__(self):
        return f'{self.user.username} in {self.group.name}'


class Message(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='messages')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.user.username} in {self.group.name}: {self.text}'


class Like(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='likes')
    liked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # Add a unique_together constraint to ensure that a user can only like a message once
        unique_together = ('user', 'message')
