from django.db import models
from django.utils import timezone

class CustomUser(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)  # Add this line

    class Meta:
        db_table = 'user'
        ordering = ['created_at']


class Role(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, unique=True)

    class Meta:
        db_table = 'role'


class Permission(models.Model):
    id = models.AutoField(primary_key=True)
    permission_name = models.CharField(max_length=100)
    permission_key = models.CharField(max_length=100, unique=True)

    class Meta:
        db_table = 'permission'


class RolePermission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='permissions')
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE, related_name='roles')

    class Meta:
        db_table = 'role_permission'
        unique_together = ('role', 'permission')


class UserRole(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='users')

    class Meta:
        db_table = 'user_role'
        unique_together = ('user', 'role')
